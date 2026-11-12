#include <algorithm>
#include <cstring>
#include <folly/CancellationToken.h>

#include "detail/EcFileClientCore.h"

namespace hf3fs::client::ec::detail {
namespace {
bool same(const auto &a, const auto &b) {
  const auto left = serde::serialize(a), right = serde::serialize(b);
  return std::string_view(left) == std::string_view(right);
}
Result<Void> validateTreeRun(const EcFileClientCore &core, const EcTreeReadJournal &j) {
  RETURN_ON_ERROR(j.record().validate());
  if (j.poisoned())
    return makeError(StatusCode::kIOError, "tree journal needs explicit resume after persistence failure");
  if (!same(j.record().intent.owner, core.owner))
    return makeError(MetaCode::kNoPermission, "tree range differs from actual authenticated owner");
  return Void{};
}
Result<Void> beginTreeAttempt(EcTreeReadJournal &j) {
  auto p = j.latest().value_or(EcTreeReadProgress{});
  if (j.latest()) {
    if (p.attempt == UINT64_MAX) return makeError(StatusCode::kInvalidArg);
    ++p.attempt;
  }
  p.localComplete = false;
  p.errorCode = 0;
  return j.append(std::move(p));
}
Result<Void> finishTreeAttempt(EcTreeReadJournal &j, const std::optional<Status> &error) {
  auto p = j.latest().value_or(EcTreeReadProgress{});
  p.localComplete = true;
  p.errorCode = error ? error->code() : 0;
  return j.append(std::move(p));
}
Result<meta::EcTreeReadRecord> rememberTree(EcTreeReadJournal &j, meta::EcTreeReadRecord record) {
  RETURN_ON_ERROR(validateEcTreeReadSnapshot(j.record(), record));
  auto p = j.latest().value_or(EcTreeReadProgress{});
  if (p.snapshot) RETURN_ON_ERROR(sameEcTreeReadSnapshot(*p.snapshot, record));
  p.snapshot = record;
  RETURN_ON_ERROR(j.append(std::move(p)));
  return record;
}
Result<Void> validateRead(const meta::EcTreeReadRecord &record, size_t index, const meta::AcquireEcReadV2Rsp &read) {
  if (index >= record.stripeCount) return makeError(StatusCode::kInvalidArg);
  const auto &s = record.stripes[index];
  if (s.slot.kind != meta::EcTreeSlotKind::Data || !s.snapshot || !same(read.snapshot, *s.snapshot) ||
      read.manifest.object != record.intent.selection.object || read.manifest.stripe != s.slot.stripe ||
      read.manifest.revision != s.slot.revision || read.manifest.generation != s.slot.generation ||
      read.manifest.logicalLength != s.slot.logicalLength || read.contentSha256 != s.slot.contentSha256)
    return makeError(StatusCode::kDataCorruption, "refreshed Data grant changed fixed tree snapshot");
  return Void{};
}
}  // namespace

CoTryTask<meta::EcTreeReadRecord> EcFileClientCore::treeRange(std::shared_ptr<EcTreeReadJournal> j,
                                                              bool mayCreate,
                                                              EcStripeControl control) {
  CO_RETURN_ON_ERROR(active(control));
  const auto &run = j->record();
  const bool issued = j->latest() && j->latest()->acquisitionIssued;
  if (issued || !mayCreate) {
    meta::QueryEcTreeReadReq request;
    this->request(request, run.queryRequest);
    request.intent = run.intent;
    auto result = co_await meta->queryEcTreeRead(std::move(request));
    CO_RETURN_ON_ERROR(result);
    if (result->read) co_return makeError(StatusCode::kDataCorruption, "query unexpectedly returned a bearer");
    // Missing after an issued call is unknown. Never create a new snapshot or
    // substitute new identities just because its original reply was lost.
    co_return rememberTree(*j, std::move(result->record));
  }
  auto p = j->latest().value_or(EcTreeReadProgress{});
  p.acquisitionIssued = true;
  CO_RETURN_ON_ERROR(j->append(std::move(p)));
  meta::AcquireEcTreeReadReq request;
  this->request(request, run.intent.request);
  request.intent = run.intent;
  auto result = co_await meta->acquireEcTreeRead(std::move(request));
  CO_RETURN_ON_ERROR(result);
  if (result->read) co_return makeError(StatusCode::kDataCorruption, "range creation unexpectedly returned a bearer");
  co_return rememberTree(*j, std::move(result->record));
}

CoTryTask<EcFileTreeReadOutput> EcFileClientCore::readTreeOwned(std::shared_ptr<EcTreeReadJournal> j,
                                                                EcStripeControl control) {
  CO_RETURN_ON_ERROR(validateTreeRun(*this, *j));
  CO_RETURN_ON_ERROR(active(control));
  if (dataClosed) co_return makeError(StorageClientCode::kNotInitialized, "file data manager closed");
  CO_RETURN_ON_ERROR(beginTreeAttempt(*j));
  CancellationSource combined;
  folly::CancellationCallback managerStop(stop.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback callerStop(control.cancellation, [&] { combined.requestCancellation(); });
  control.cancellation = combined.getToken();
  std::optional<Status> error;
  auto fixed = co_await treeRange(j, true, control);
  if (!fixed) {
    error = std::move(fixed.error());
    (void)finishTreeAttempt(*j, error);
    co_return makeError(std::move(*error));
  }
  if (fixed->state != meta::EcTreeReadState::Active) {
    error.emplace(StatusCode::kTokenStale, "tree range already closing/released; choose a new run for a new read");
    (void)finishTreeAttempt(*j, error);
    co_return makeError(std::move(*error));
  }
  EcFileTreeReadOutput output;
  output.snapshot = *fixed;
  auto payload = budget->allocate(fixed->readableLength);
  if (!payload)
    error = std::move(payload.error());
  else
    output.data = std::move(*payload);
  auto plan =
      planEcFileRead(j->record().shardBytes, j->record().intent.selection.offset, j->record().intent.selection.length);
  if (!plan) error = std::move(plan.error());
  auto clipped = plan ? clipEcFileRead(*plan, fixed->root.visibleLength)
                      : Result<EcFileExtentPlan>(makeError(StatusCode::kInvalidArg));
  if (!clipped) error = std::move(clipped.error());
  if (!error) std::fill(output.data.bytes().begin(), output.data.bytes().end(), 0);
  size_t copied = 0;
  for (size_t i = 0; !error && i < fixed->stripeCount; ++i) {
    auto check = active(control);
    if (!check) {
      error = std::move(check.error());
      break;
    }
    const auto &slice = clipped->slices[i];
    const auto &entry = fixed->stripes[i];
    if (slice.length > output.data.size() - copied) {
      error.emplace(StatusCode::kDataCorruption);
      break;
    }
    if (entry.slot.kind == meta::EcTreeSlotKind::Zero) {
      copied += slice.length;
      continue;
    }
    meta::AcquireEcTreeReadReq req;
    request(req, j->record().refreshRequests[i]);
    req.intent = j->record().intent;
    req.stripeIndex = i;
    auto refresh = co_await meta->acquireEcTreeRead(std::move(req));
    if (!refresh) {
      error = std::move(refresh.error());
      break;
    }
    check = validateEcTreeReadSnapshot(j->record(), refresh->record);
    if (check) check = sameEcTreeReadSnapshot(*fixed, refresh->record);
    if (check && refresh->record.state != meta::EcTreeReadState::Active) check = makeError(StatusCode::kTokenStale);
    if (check && !refresh->read) check = makeError(StatusCode::kDataCorruption, "Data refresh omitted its bearer");
    if (check) check = validateRead(*fixed, i, *refresh->read);
    if (!check) {
      error = std::move(check.error());
      break;
    }
    const auto &pin = j->record().intent.selection.pins[i];
    auto session = stripe->startPinnedRead(
        {j->record().session.object, pin.stripe, pin.pin, j->record().refreshRequests[i], j->record().releaseRequest},
        std::move(*refresh->read),
        control);
    if (!session) {
      error = std::move(session.error());
      break;
    }
    try {
      auto part = co_await session->takeReady();
      if (!part)
        error = std::move(part.error());
      else if (!same(part->pinned.snapshot, *entry.snapshot) || part->logicalData.size() != entry.slot.logicalLength ||
               part->contentSha256 != entry.slot.contentSha256)
        error.emplace(StatusCode::kDataCorruption, "decoded stripe differs from fixed tree slot");
      else {
        const auto available =
            slice.offsetInStripe < part->logicalData.size() ? part->logicalData.size() - slice.offsetInStripe : 0;
        const auto bytes = std::min<size_t>(slice.length, available);
        if (bytes)
          std::memcpy(output.data.bytes().data() + copied, part->logicalData.data() + slice.offsetInStripe, bytes);
        // Data's logical tail through the captured stripe/EOF is a hole.
        copied += slice.length;
      }
    } catch (const std::bad_alloc &) {
      error.emplace(StatusCode::kNotEnoughMemory);
    } catch (...) {
      error.emplace(StatusCode::kIOError);
    }
    if (error) session->cancel();
    co_await folly::coro::co_withCancellation(CancellationToken{}, session->waitLocalCleanup());
  }
  if (!error && copied != output.data.size()) error.emplace(StatusCode::kDataCorruption);
  if (!error) {
    auto check = active(control);
    if (!check) error = std::move(check.error());
  }
  if (!error) {
    auto p = *j->latest();
    p.dataReady = true;
    auto saved = j->append(std::move(p));
    if (!saved) error = std::move(saved.error());
  }
  auto saved = finishTreeAttempt(*j, error);
  if (!error && !saved) error = std::move(saved.error());
  if (error) co_return makeError(std::move(*error));
  co_return output;
}

CoTryTask<meta::EcTreeReadRecord> EcFileClientCore::releaseTreeOwned(std::shared_ptr<EcTreeReadJournal> j,
                                                                     EcStripeControl control) {
  CO_RETURN_ON_ERROR(validateTreeRun(*this, *j));
  CO_RETURN_ON_ERROR(active(control));
  CO_RETURN_ON_ERROR(beginTreeAttempt(*j));
  auto fixed = co_await treeRange(j, false, control);
  if (!fixed) {
    std::optional<Status> error = std::move(fixed.error());
    (void)finishTreeAttempt(*j, error);
    co_return makeError(std::move(*error));
  }
  if (fixed->state == meta::EcTreeReadState::Released) {
    CO_RETURN_ON_ERROR(finishTreeAttempt(*j, std::nullopt));
    co_return *fixed;
  }
  auto p = *j->latest();
  p.releaseIssued = true;
  CO_RETURN_ON_ERROR(j->append(std::move(p)));
  meta::ReleaseEcTreeReadReq req;
  request(req, j->record().releaseRequest);
  req.intent = j->record().intent;
  for (size_t i = 0; i < fixed->stripeCount; ++i)
    if (fixed->stripes[i].slot.kind == meta::EcTreeSlotKind::Data) req.revocations[i] = j->record().revocations[i];
  auto result = co_await meta->releaseEcTreeRead(std::move(req));
  if (!result) {
    std::optional<Status> error = std::move(result.error());
    (void)finishTreeAttempt(*j, error);
    co_return makeError(std::move(*error));
  }
  if (result->read) co_return makeError(StatusCode::kDataCorruption, "release unexpectedly returned a bearer");
  auto observed = rememberTree(*j, std::move(result->record));
  CO_RETURN_ON_ERROR(observed);
  if (observed->state != meta::EcTreeReadState::Released) {
    std::optional<Status> error = Status(StatusCode::kTokenStale, "range has not completed every remote source T2");
    (void)finishTreeAttempt(*j, error);
    co_return makeError(std::move(*error));
  }
  CO_RETURN_ON_ERROR(finishTreeAttempt(*j, std::nullopt));
  co_return *observed;
}
}  // namespace hf3fs::client::ec::detail
