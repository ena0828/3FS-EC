#include <algorithm>
#include <cstring>
#include <folly/CancellationToken.h>

#include "detail/EcFileClientCore.h"
namespace hf3fs::client::ec::detail {
CoTryTask<EcFileReadOutput> EcFileClientCore::readOwned(std::shared_ptr<EcFileRunJournal> j, EcStripeControl c) {
  auto check = validateRun(*j, EcFileRunKind::RangeRead);
  if (!check) co_return makeError(std::move(check.error()));
  check = active(c);
  if (!check) co_return makeError(std::move(check.error()));
  if (dataClosed)
    co_return makeError(StorageClientCode::kNotInitialized, "file data manager closed after prior exception");
  check = beginAttempt(*j);
  if (!check) co_return makeError(std::move(check.error()));
  CancellationSource combined;
  folly::CancellationCallback managerStop(stop.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback callerStop(c.cancellation, [&] { combined.requestCancellation(); });
  c.cancellation = combined.getToken();
  std::optional<Status> error;
  auto fixed = co_await range(j, true, c);
  if (!fixed) {
    error = std::move(fixed.error());
    auto saved = finishAttempt(*j, error);
    // A later local persistence error cannot erase unknown Acquire status.
    (void)saved;
    co_return makeError(std::move(*error));
  }
  EcFileReadOutput output;
  output.snapshot = std::move(*fixed);
  auto payload = budget->allocate(output.snapshot.readableLength);
  if (!payload)
    error = std::move(payload.error());
  else
    output.data = std::move(*payload);
  auto requested = planEcFileRead(j->record().shardBytes, j->record().offset, j->record().length);
  if (!requested) error = std::move(requested.error());
  auto clipped = requested ? clipEcFileRead(*requested, output.snapshot.file.length)
                           : Result<EcFileExtentPlan>(makeError(StatusCode::kInvalidArg));
  if (!clipped) error = std::move(clipped.error());
  size_t copied = 0;
  for (size_t i = 0; !error && i != output.snapshot.stripeCount; ++i) {
    check = active(c);
    if (!check) {
      error = std::move(check.error());
      break;
    }
    if (output.snapshot.stripes[i].state != meta::EcRangePinState::Active) {
      error.emplace(StatusCode::kTokenStale, "fixed range pin is already closing/released; it cannot be revived");
      break;
    }
    const auto &slot = j->record().slots[i];
    auto session =
        stripe->startRead({j->record().object, slot.stripe, slot.pin, slot.acquireRequest, slot.releaseRequest}, c);
    if (!session) {
      error = std::move(session.error());
      break;
    }
    try {
      auto part = co_await session->takeReady();
      if (!part)
        error = std::move(part.error());
      else {
        check = validateFileStripe(output.snapshot.stripes[i], *part);
        if (!check)
          error = std::move(check.error());
        else {
          const auto &slice = clipped->slices[i];
          if (slice.offsetInStripe > part->logicalData.size() ||
              slice.length > part->logicalData.size() - slice.offsetInStripe ||
              slice.length > output.data.size() - copied)
            error.emplace(StatusCode::kDataCorruption);
          else {
            std::memcpy(output.data.bytes().data() + copied,
                        part->logicalData.data() + slice.offsetInStripe,
                        slice.length);
            copied += slice.length;
          }
        }
      }
      // Destroy this lower-layer output/lease before the next stripe starts.
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
    check = active(c);
    if (!check) error = std::move(check.error());
  }
  if (!error) {
    auto progress = *j->latest();
    progress.dataReady = true;
    check = j->append(std::move(progress));
    if (!check) error = std::move(check.error());
  }
  auto saved = finishAttempt(*j, error);
  if (!error && !saved) error = std::move(saved.error());
  if (error) co_return makeError(std::move(*error));
  // All local decoders/late requests are joined; zero remote pins were
  // automatically released. A complete output is not a ReadReleased proof.
  co_return output;
}
CoTask<EcFileReleaseOutcome> EcFileClientCore::releaseOwned(std::shared_ptr<EcFileRunJournal> j, EcStripeControl c) {
  EcFileReleaseOutcome out;
  auto check = validateRun(*j, EcFileRunKind::RangeRead);
  if (!check) {
    out.failure = std::move(check.error());
    co_return out;
  }
  check = beginAttempt(*j);
  if (!check) {
    out.failure = std::move(check.error());
    co_return out;
  }
  auto fixed = co_await range(j, false, c);
  if (!fixed) {
    out.failure = std::move(fixed.error());
    (void)finishAttempt(*j, out.failure);
    co_return out;
  }
  out.expectedPins = fixed->stripeCount;
  // Even never-read pins are present in the one atomic range snapshot.
  for (size_t i = 0; i != fixed->stripeCount; ++i) {
    if (fixed->stripes[i].state == meta::EcRangePinState::Released) continue;
    check = active(c);
    if (!check) {
      if (!out.failure) out.failure = std::move(check.error());
      break;
    }
    const auto &slot = j->record().slots[i];
    meta::ReleaseEcReadV2Req req;
    request(req, slot.releaseRequest);
    req.object = j->record().object;
    req.stripe = slot.stripe;
    req.pin = slot.pin;
    auto result = co_await meta->releaseEcReadV2(std::move(req));
    if (!result) {
      if (!out.failure) out.failure = std::move(result.error());
      continue;
    }
    const auto &drain = result->drain;
    if (result->pin != slot.pin || drain.revocation.is_nil() || drain.expectedEndpoints != 12 ||
        drain.acknowledgedEndpoints > 12 ||
        (drain.state != meta::EcV2DrainState::Closing && drain.state != meta::EcV2DrainState::ReadReleased) ||
        (drain.state == meta::EcV2DrainState::ReadReleased && drain.acknowledgedEndpoints != 12)) {
      if (!out.failure) out.failure.emplace(StatusCode::kDataCorruption);
      continue;
    }
    if (drain.state == meta::EcV2DrainState::ReadReleased) {
      auto p = *j->latest();
      p.releasedMask |= uint16_t(1u << i);
      check = j->append(std::move(p));
      if (!check) {
        if (!out.failure) out.failure = std::move(check.error());
        break;
      }
    }
  }
  check = finishAttempt(*j, out.failure);
  if (!check && !out.failure) out.failure = std::move(check.error());
  if (j->latest()) out.releasedMask = j->latest()->releasedMask;
  out.allReleased = !out.failure && j->latest() && j->latest()->allPinsReleased();
  co_return out;
}
}  // namespace hf3fs::client::ec::detail
