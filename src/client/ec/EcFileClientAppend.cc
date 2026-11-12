#include <algorithm>
#include <folly/CancellationToken.h>

#include "detail/EcFileClientCore.h"
namespace hf3fs::client::ec::detail {
CoTask<EcFileAppendOutcome> EcFileClientCore::appendOwned(std::shared_ptr<EcFileRunJournal> j,
                                                          EcFilePayload input,
                                                          EcStripeControl c) {
  uint64_t revalidated = 0;
  bool mutationInvoked = false, unknown = false;
  const auto finish = [&](std::optional<Status> error) {
    if (unknown && error && error->code() != StorageCode::kEcSealOutcomeUnknown)
      error = Status(StorageCode::kEcSealOutcomeUnknown);
    if (unknown && j->latest() && !j->poisoned()) {
      auto p = *j->latest();
      const auto index = p.confirmedStripes();
      if (index < j->record().count && p.appendStates[index] != EcFileAppendState::Aborted &&
          p.appendStates[index] != EcFileAppendState::NotStarted) {
        p.appendStates[index] = EcFileAppendState::Indeterminate;
        p.errorCode = StorageCode::kEcSealOutcomeUnknown;
        (void)j->append(std::move(p));
      }
    }
    auto saved = finishAttempt(*j, error);
    if (!error && !saved) error = std::move(saved.error());
    auto out = fileAppendOutcome(*j, std::move(error));
    out.revalidatedPrefixBytes = revalidated;
    out.complete = !out.failure && out.confirmedStripes == j->record().count && revalidated == j->record().length;
    return out;
  };
  auto check = validateRun(*j, EcFileRunKind::AppendAt);
  if (!check) co_return fileAppendOutcome(*j, std::move(check.error()));
  check = active(c);
  if (!check) co_return fileAppendOutcome(*j, std::move(check.error()));
  if (dataClosed || !budget->owns(input)) co_return fileAppendOutcome(*j, Status(StorageClientCode::kNotInitialized));
  check = validateFileInput(j->record(), input.bytes());
  if (!check) co_return fileAppendOutcome(*j, std::move(check.error()));
  check = beginAttempt(*j);
  if (!check) co_return fileAppendOutcome(*j, std::move(check.error()));
  CancellationSource combined;
  folly::CancellationCallback managerStop(stop.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback callerStop(c.cancellation, [&] { combined.requestCancellation(); });
  c.cancellation = combined.getToken();
  const auto &r = j->record();
  const size_t stripeBytes = size_t(r.shardBytes) * 10;
  std::optional<Status> exception;
  try {
    for (size_t i = 0; i != r.count; ++i) {
      check = active(c);
      if (!check) co_return finish(std::move(check.error()));
      const auto &slot = r.slots[i];
      auto state = j->latest()->appendStates[i];
      unknown = state == EcFileAppendState::Indeterminate ||
                (j->latest()->errorCode == StorageCode::kEcSealOutcomeUnknown && i == j->latest()->confirmedStripes());
      if (state != EcFileAppendState::NotStarted) {
        meta::QueryEcOwnedMutationV2Req get;
        request(get, slot.mutation.getRequest);
        get.object = r.object;
        get.operation = slot.mutation.operation;
        auto queried = co_await meta->queryEcOwnedMutationV2(std::move(get));
        if (queried) {
          check = validateFileOwnedObservation(r, i, *queried);
          if (!check) co_return finish(std::move(check.error()));
        }
        if (queried && queried->record.state == meta::EcOperationState::Published) {
          unknown = false;
          revalidated += stripeBytes;
          if (state != EcFileAppendState::Published) {
            auto p = *j->latest();
            p.appendStates[i] = EcFileAppendState::Published;
            p.errorCode = 0;
            check = j->append(std::move(p));
            if (!check) co_return finish(std::move(check.error()));
          }
          continue;
        }
        // A locally Published prefix may not be replaced by current EOF or a
        // bitmap. Missing, failed owner authentication, or contradictory state stops
        // this run before any later stripe's Begin.
        if (state == EcFileAppendState::Published)
          co_return finish(queried ? Status(StatusCode::kDataCorruption) : std::move(queried.error()));
        if (!queried && queried.error().code() != StatusCode::kKVStoreNotFound)
          co_return finish(std::move(queried.error()));
        if (queried && queried->record.state == meta::EcOperationState::Aborted) {
          unknown = false;
          auto p = *j->latest();
          p.appendStates[i] = EcFileAppendState::Aborted;
          p.errorCode = 0;
          check = j->append(std::move(p));
          if (!check) co_return finish(std::move(check.error()));
          co_return finish(Status(StatusCode::kTokenStale, "original append operation is aborted"));
        }
        // Preparing/missing do not confer write authority. The original
        // StripeClient Begin/Bind/Publish sequence still checks current WRITE;
        // its internal failure observations retain the existing RPC33 limits. Never
        // move the stripe to a newer EOF or mint another operation.
      } else {
        auto p = *j->latest();
        p.appendStates[i] = EcFileAppendState::Issued;
        p.errorCode = 0;
        check = j->append(std::move(p));
        if (!check) co_return finish(std::move(check.error()));
      }
      check = active(c);
      if (!check) co_return finish(std::move(check.error()));
      // Admission projection only. Describe does not supply creator/counters;
      // defaults below are never persisted as authoritative object metadata.
      EcStripeWrite write;
      write.object.object = r.object;
      write.object.shardBytes = r.shardBytes;
      write.object.epoch = r.epoch;
      write.stripe = slot.stripe;
      write.expectedRevision = 0;
      write.ids = slot.mutation;
      constexpr size_t lowerBudget = 64u << 20;
      if (stripeBytes + size_t(r.shardBytes) * 24 + 4 * storage::kEcIntegrityBlockBytes > lowerBudget)
        co_return finish(Status(StatusCode::kInvalidArg));
      // The exclusive lower manager has no previous active call/output. This
      // bounded handoff copy belongs to its 64 MiB partition, not a third one.
      write.logicalData.assign(reinterpret_cast<const char *>(input.bytes().data() + i * stripeBytes), stripeBytes);
      if (write.logicalData.capacity() + size_t(r.shardBytes) * 24 + 4 * storage::kEcIntegrityBlockBytes > lowerBudget)
        co_return finish(Status(StorageClientCode::kResourceBusy));
      mutationInvoked = true;
      auto result = co_await stripe->write(std::move(write), c);
      mutationInvoked = false;
      if (result.observation && result.observation->record.state == meta::EcOperationState::Published) {
        check = validateFilePublished(r, i, *result.observation);
        if (!check) {
          unknown = true;
          co_return finish(std::move(check.error()));
        }
        unknown = false;
        revalidated += stripeBytes;
        auto p = *j->latest();
        p.appendStates[i] = EcFileAppendState::Published;
        p.errorCode = 0;
        check = j->append(std::move(p));
        if (!check) co_return finish(std::move(check.error()));
        if (result.failure) co_return finish(std::move(result.failure));
        continue;
      }
      if (result.observation && result.observation->record.state == meta::EcOperationState::Aborted) {
        check = validateFileIntent(r, i, *result.observation);
        if (!check) co_return finish(std::move(check.error()));
        unknown = false;
        auto p = *j->latest();
        p.appendStates[i] = EcFileAppendState::Aborted;
        p.errorCode = 0;
        check = j->append(std::move(p));
        if (!check) co_return finish(std::move(check.error()));
        co_return finish(Status(StatusCode::kTokenStale, "original append operation is aborted"));
      }
      unknown = unknown || (result.failure && result.failure->code() == StorageCode::kEcSealOutcomeUnknown);
      auto p = *j->latest();
      // Only a fully checked Published result advances a prefix. Other native
      // results remain replayable with the same IDs; no remote state inferred.
      p.appendStates[i] = unknown ? EcFileAppendState::Indeterminate : EcFileAppendState::Issued;
      p.errorCode = result.failure ? result.failure->code() : StorageCode::kEcSealOutcomeUnknown;
      check = j->append(std::move(p));
      if (result.failure) co_return finish(std::move(result.failure));
      unknown = true;
      co_return finish(Status(StorageCode::kEcSealOutcomeUnknown));
    }
    co_return finish(std::nullopt);
  } catch (const std::bad_alloc &) {
    exception.emplace(StatusCode::kNotEnoughMemory);
  } catch (...) {
    exception.emplace(StatusCode::kIOError);
  }
  // A waiter exception after invoking a durable mutation must not release a
  // borrowed frame, nor downgrade unknown to a pure pre-dispatch OOM.
  if (mutationInvoked) {
    unknown = true;
    co_await folly::coro::co_withCancellation(CancellationToken{}, stripe->close());
    dataClosed = true;
  }
  co_return finish(std::move(exception));
}
}  // namespace hf3fs::client::ec::detail
