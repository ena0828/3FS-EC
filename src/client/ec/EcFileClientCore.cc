#include "detail/EcFileClientCore.h"

#include <algorithm>
#include <limits>
namespace hf3fs::client::ec::detail {
Result<Void> EcFileClientCore::active(const EcStripeControl &c) const {
  if (stop.isCancellationRequested() || c.cancellation.isCancellationRequested())
    return makeError(StorageClientCode::kRequestCanceled);
  const auto now = std::chrono::steady_clock::now();
  if (c.deadline <= now) return makeError(StorageClientCode::kTimeout);
  if (c.deadline - now > maximumTime)
    return makeError(StatusCode::kInvalidArg, "file deadline exceeds finite manager limit");
  return Void{};
}
void EcFileClientCore::request(meta::ReqBase &req, const Uuid &id) const {
  req.user = credentials;
  req.client = ClientId(owner.client);
  req.uuid = id;
}
Result<Void> EcFileClientCore::validateRun(const EcFileRunJournal &j, EcFileRunKind kind) const {
  RETURN_ON_ERROR(j.record().validate());
  if (j.poisoned()) return makeError(StatusCode::kIOError, "journal must be reopened after persistence failure");
  if (j.record().kind != kind || j.record().owner.uid != owner.uid || j.record().owner.client != owner.client)
    return makeError(StatusCode::kTokenMismatch,
                     "run differs from authenticated effective UID/actual client namespace");
  return Void{};
}
Result<Void> EcFileClientCore::beginAttempt(EcFileRunJournal &j) {
  auto p = j.latest().value_or(EcFileRunProgress{});
  if (j.latest()) {
    if (p.localAttempt == UINT64_MAX) return makeError(StatusCode::kInvalidArg);
    ++p.localAttempt;
  }
  p.localComplete = false;
  p.errorCode = 0;
  return j.append(std::move(p));
}
Result<Void> EcFileClientCore::finishAttempt(EcFileRunJournal &j, const std::optional<Status> &error) {
  auto p = j.latest().value_or(EcFileRunProgress{});
  p.localComplete = true;
  p.errorCode = error ? error->code() : 0;
  return j.append(std::move(p));
}
Result<meta::EcRangeSnapshot> EcFileClientCore::rememberRange(EcFileRunJournal &j, meta::EcRangeSnapshot s) {
  RETURN_ON_ERROR(validateFileSnapshot(j.record(), s));
  auto p = j.latest().value_or(EcFileRunProgress{});
  if (p.snapshotObserved) {
    meta::EcRangeSnapshot original;
    RETURN_ON_ERROR(serde::deserialize(original, p.snapshotBytes));
    RETURN_ON_ERROR(validateFileSnapshot(j.record(), original));
    RETURN_ON_ERROR(validateSameFileSnapshot(original, s));
  } else {
    // Store the first complete response, never just its apparent pin count.
    p.snapshotBytes = serde::serialize(s);
    if (p.snapshotBytes.size() > meta::kEcFileRangeMaxRecordBytes) return makeError(StatusCode::kDataCorruption);
    p.snapshotObserved = true;
    p.actualPins = s.stripeCount;
  }
  for (size_t i = 0; i != s.stripeCount; ++i) {
    const bool wasReleased = p.releasedMask & (1u << i);
    if (wasReleased && s.stripes[i].state != meta::EcRangePinState::Released)
      return makeError(StatusCode::kDataCorruption, "terminal range pin regressed");
    if (s.stripes[i].state == meta::EcRangePinState::Released) p.releasedMask |= uint16_t(1u << i);
  }
  RETURN_ON_ERROR(j.append(std::move(p)));
  return s;
}
CoTryTask<meta::EcRangeSnapshot> EcFileClientCore::range(std::shared_ptr<EcFileRunJournal> j,
                                                         bool mayAcquire,
                                                         EcStripeControl c) {
  auto check = active(c);
  if (!check) co_return makeError(std::move(check.error()));
  const auto &r = j->record();
  const bool issued = j->latest() && j->latest()->acquisitionIssued;
  if (issued || !mayAcquire) {
    meta::QueryEcRangeV2Req query;
    request(query, r.rangeRequest);
    query.rangeId = r.rangeId;
    query.selection = fileSelection(r);
    auto result = co_await meta->queryEcRangeV2(std::move(query));
    if (result) co_return rememberRange(*j, std::move(result->snapshot));
    if (result.error().code() == StatusCode::kKVStoreNotFound && j->latest() && j->latest()->snapshotObserved)
      co_return makeError(StatusCode::kDataCorruption,
                          "previously observed permanent range disappeared; do not reacquire");
    if (!mayAcquire || result.error().code() != StatusCode::kKVStoreNotFound)
      co_return makeError(std::move(result.error()));
    // Missing is not proof that a previous Acquire failed. Only a same-ID
    // Acquire can recover/create that exact permanent transaction identity.
  }
  check = active(c);
  if (!check) co_return makeError(std::move(check.error()));
  auto p = j->latest().value_or(EcFileRunProgress{});
  p.acquisitionIssued = true;
  auto persisted = j->append(std::move(p));
  if (!persisted) co_return makeError(std::move(persisted.error()));
  meta::AcquireEcRangeV2Req req;
  request(req, r.rangeRequest);
  req.rangeId = r.rangeId;
  req.selection = fileSelection(r);
  auto result = co_await meta->acquireEcRangeV2(std::move(req));
  if (!result) co_return makeError(std::move(result.error()));
  co_return rememberRange(*j, std::move(result->snapshot));
}
CoTryTask<meta::EcFileState> EcFileClientCore::describeOwned(meta::EcObjectRef object,
                                                             Uuid id,
                                                             meta::AccessType access,
                                                             EcStripeControl c) {
  auto check = active(c);
  if (!check) co_return makeError(std::move(check.error()));
  meta::DescribeEcFileV2Req req;
  request(req, id);
  req.object = object;
  req.access = access;
  check = req.valid();
  if (!check) co_return makeError(std::move(check.error()));
  auto result = co_await meta->describeEcFileV2(std::move(req));
  if (!result) co_return makeError(std::move(result.error()));
  check = result->file.layout.valid();
  if (!check) co_return makeError(std::move(check.error()));
  if (result->file.object != object || result->file.layout.incarnation != object.incarnation || !result->file.epoch)
    co_return makeError(StatusCode::kDataCorruption);
  co_return std::move(result->file);
}
CoTask<void> EcFileClientCore::closeStripe(std::shared_ptr<EcFileClientCore> core) {
  if (core->stripeJoined) co_return;
  if (core->stripeJoinStarted) {
    // The prior await failed after entry. Do not re-enter a possibly completed
    // AsyncScope join, or mistake its missing completion for no work.
    if (core->stripeJoinError) std::rethrow_exception(core->stripeJoinError);
    throw std::bad_alloc{};  // Unconfirmed entry has no successful join evidence.
  }
  // Construct the lower task before marking entry. A factory bad_alloc means
  // the task never started and a later explicit close may retry this stage.
  auto task = core->stripeCloseFactoryForTest
                  ? core->stripeCloseFactoryForTest(core->stripeCloseFactoryContextForTest, *core->stripe)
                  : core->stripe->close();
  core->stripeJoinStarted = true;
  try {
    co_await folly::coro::co_withCancellation(CancellationToken{}, std::move(task));
    core->stripeJoined = true;
  } catch (...) {
    core->stripeJoinError = std::current_exception();
    throw;
  }
}
CoTask<void> EcFileClientCore::close(std::shared_ptr<EcFileClientCore> core) {
  std::shared_ptr<EcFileCloseAttempt> attempt;
  bool first;
  {
    std::lock_guard lock(core->mutex);
    core->closing = true;
    if (core->closeComplete) co_return;
    first = !core->closeAttempt;
    if (first) core->closeAttempt = std::make_shared<EcFileCloseAttempt>();
    attempt = core->closeAttempt;
  }
  if (!first) {
    co_await folly::coro::co_withCancellation(CancellationToken{}, attempt->ready);
    if (attempt->error) std::rethrow_exception(attempt->error);
    co_return;
  }
  // Every elected attempt notifies its own waiters on either outcome. A
  // failure leaves admission closed, never posts a global false-success bit.
  try {
    core->stop.requestCancellation();
    if (!core->tasksJoined) {
      if (core->tasksJoinStarted) {
        if (core->tasksJoinError) std::rethrow_exception(core->tasksJoinError);
        throw std::bad_alloc{};
      }
      auto task = core->tasks.joinAsync();
      core->tasksJoinStarted = true;
      try {
        co_await folly::coro::co_withCancellation(CancellationToken{}, std::move(task));
        core->tasksJoined = true;
      } catch (...) {
        core->tasksJoinError = std::current_exception();
        throw;
      }
    }
    co_await folly::coro::co_withCancellation(CancellationToken{}, closeStripe(core));
    {
      std::lock_guard lock(core->mutex);
      core->closeComplete = true;
      core->unconfirmedJoinLease.reset();
      core->localJoinUnconfirmed.store(false);
    }
  } catch (...) {
    attempt->error = std::current_exception();
    std::lock_guard lock(core->mutex);
    core->unconfirmedJoinLease = core;
    core->localJoinUnconfirmed.store(true);
  }
  {
    std::lock_guard lock(core->mutex);
    core->closeAttempt.reset();
  }
  attempt->ready.post();
  if (attempt->error) std::rethrow_exception(attempt->error);
}
EcFileAppendOutcome fileAppendOutcome(const EcFileRunJournal &j, std::optional<Status> error) {
  EcFileAppendOutcome out;
  if (j.latest()) {
    out.confirmedStripes = j.latest()->confirmedStripes();
    out.confirmedPrefixBytes = j.latest()->confirmedPrefixBytes(j.record());
    out.firstUnconfirmedIndex = out.confirmedStripes;
    if (out.firstUnconfirmedIndex < j.record().count)
      out.firstUnconfirmedState = j.latest()->appendStates[out.firstUnconfirmedIndex];
  }
  out.failure = std::move(error);
  return out;
}
}  // namespace hf3fs::client::ec::detail
