#include "detail/EcReadDispatcherCore.h"

#include "detail/EcReadSpoolArchive.h"

namespace hf3fs::client::ec::detail {
Result<Void> EcReadDispatcherCore::active(const EcStripeControl &c) const {
  RETURN_ON_ERROR(validateEcStorageTransport(c.transport));
  if (cancellation.isCancellationRequested() || c.cancellation.isCancellationRequested())
    return makeError(StorageClientCode::kRequestCanceled);
  const auto now = std::chrono::steady_clock::now();
  if (c.deadline <= now) return makeError(StorageClientCode::kTimeout);
  if (c.deadline - now > limits.maximumOperationTime)
    return makeError(StatusCode::kInvalidArg, "read dispatcher deadline exceeds finite limit");
  return Void{};
}
size_t EcReadDispatcherCore::heldOutputs() {
  std::lock_guard lock(mutex);
  return outputLeases;
}
CoTryTask<flat::UserInfo> EcReadDispatcherCore::authenticate(flat::UserInfo user, EcStripeControl c) {
  auto check = active(c);
  CO_RETURN_ON_ERROR(check);
  auto authenticated = co_await meta->authenticate(user);
  CO_RETURN_ON_ERROR(authenticated);
  check = active(c);
  CO_RETURN_ON_ERROR(check);
  // UserStore decides valid root proxy/effective UID. Neither a supplied UID
  // nor namespace is authentication; retain the actual token for later RPCs.
  auto token = std::move(user.token);
  user = std::move(*authenticated);
  user.token = std::move(token);
  co_return user;
}
void EcReadDispatcherCore::request(meta::ReqBase &req, const flat::UserInfo &user, const Uuid &id) const {
  req.user = user;
  req.client = ClientId(spool->clientNamespace());
  req.uuid = id;
}
CoTryTask<Void> EcReadDispatcherCore::manager(const flat::UserInfo &user, EcStripeControl c) {
  auto check = active(c);
  CO_RETURN_ON_ERROR(check);
  if (file && serde::serialize(fileCredentials) == serde::serialize(user)) co_return Void{};
  if (heldOutputs())
    co_return makeError(StorageClientCode::kResourceBusy,
                        "held read output prevents replacing the shared budget/credentials");
  if (file) {
    co_await file->close();
    file.reset();
  }
  auto connected = co_await EcFileClient::connect(meta,
                                                  storage,
                                                  mgmtd,
                                                  user,
                                                  spool->clientNamespace(),
                                                  pool,
                                                  limits.maximumOperationTime);
  CO_RETURN_ON_ERROR(connected);
  file = std::move(*connected);
  fileCredentials = user;
  check = active(c);
  CO_RETURN_ON_ERROR(check);
  co_return Void{};
}
CoTryTask<EcReadHandle> EcReadDispatcherCore::openOwned(meta::EcObjectRef object,
                                                        flat::UserInfo user,
                                                        EcStripeControl c) {
  auto authenticated = co_await authenticate(std::move(user), c);
  CO_RETURN_ON_ERROR(authenticated);
  meta::DescribeEcFileV2Req req;
  const auto id = Uuid::random();
  request(req, *authenticated, id);
  req.object = object;
  req.access = meta::AccessType::READ;
  auto check = req.valid();
  CO_RETURN_ON_ERROR(check);
  auto response = co_await meta->describeEcFileV2(std::move(req));
  CO_RETURN_ON_ERROR(response);
  check = response->file.layout.valid();
  CO_RETURN_ON_ERROR(check);
  if (response->file.object != object || response->file.layout.incarnation != object.incarnation ||
      !response->file.epoch)
    co_return makeError(StatusCode::kDataCorruption);
  check = active(c);
  CO_RETURN_ON_ERROR(check);
  EcReadHandle handle;
  handle.file_ = std::move(response->file);
  handle.dispatcher_ = instance;
  handle.describeRequest_ = id;
  co_return handle;
}
CoTryTask<EcReadSpoolSnapshot> EcReadDispatcherCore::inspectOwned() { co_return spool->inspect(); }
CoTryTask<EcReadReceiptObservation> EcReadDispatcherCore::receiptOwned(EcReadReceipt receipt) {
  auto check = spool->validReceipt(receipt);
  CO_RETURN_ON_ERROR(check);
  auto snapshot = spool->inspect();
  CO_RETURN_ON_ERROR(snapshot);
  EcReadReceiptObservation out;
  for (auto &record : snapshot->records) {
    if (record.receipt.sequence != receipt.sequence) continue;
    if (!sameReadReceipt(record.receipt, receipt)) co_return makeError(StatusCode::kTokenMismatch);
    out.evidence = record.retirementPending ? EcReadLocalEvidence::RetirementPending : EcReadLocalEvidence::Retained;
    out.record = std::move(record);
    break;
  }
  // Missing is purely local NoRetainedEvidence. This method performs no RPC.
  co_return out;
}
CoTask<EcReadShutdownReport> EcReadDispatcherCore::finishStop(std::shared_ptr<EcReadDispatcherCore> core) {
  // Elect per-attempt leadership only when this task actually starts. Failed
  // attempts have their own settled report/baton; a later stop may try the same
  // lower instance again under F3's monotonic retryable-close contract.
  std::shared_ptr<EcReadStopCall> attempt;
  bool leader = false;
  try {
    std::lock_guard lock(core->mutex);
    if (core->stopAttempt && (!core->stopAttempt->done || core->stopped))
      attempt = core->stopAttempt;
    else {
      attempt = std::make_shared<EcReadStopCall>();
      attempt->report.joinFailure.emplace(StatusCode::kIOError);
      core->stopAttempt = attempt;
      leader = true;
    }
  } catch (...) {
    core->retainUnconfirmedJoin();
    EcReadShutdownReport out;
    out.joinFailure.emplace(StatusCode::kNotEnoughMemory);
    co_return out;
  }
  if (!leader) {
    co_await attempt->ready;
    co_return attempt->report;
  }
  {
    auto notify = folly::makeGuard([&] {
      {
        std::lock_guard lock(core->mutex);
        attempt->done = true;
      }
      attempt->ready.post();
    });
    try {
      if (!core->tasksJoined) {
        if (core->tasksJoinStarted) {
          // No proof that this AsyncScope join finished: never perform it a
          // second time, nor destroy it. This is a finite sticky failure.
          core->retainUnconfirmedJoin();
          attempt->report.joinFailure.emplace(StatusCode::kIOError);
        } else {
          core->tasksJoinStarted = true;
          co_await folly::coro::co_withCancellation(CancellationToken{}, core->tasks.joinAsync());
          core->tasksJoined = true;
        }
      }
      attempt->report.dispatcherTasksJoined = core->tasksJoined;
      if (core->tasksJoined) {
        if (core->file) {
          // New F3 close reports each failed attempt and never repeats an
          // already-entered uncertain join. Keep this exact instance on error.
          co_await folly::coro::co_withCancellation(CancellationToken{}, core->lowerClose());
          core->file.reset();
        }
        core->lowerJoinUnconfirmed = false;
        attempt->report.lowerJoinConfirmed = true;
        attempt->report.localJoined = true;
        attempt->report.joinFailure.reset();
        // Outputs may outlive stop, but may not retain executor shutdown debt.
        core->executor.reset();
        attempt->report.retainedOutputLeases = core->heldOutputs();
        auto snapshot = core->spool->inspect();
        if (snapshot) {
          attempt->report.spool = std::move(*snapshot);
          attempt->report.inventoryVerified = true;
        } else
          attempt->report.observationFailure = std::move(snapshot.error());
        {
          std::lock_guard lock(core->mutex);
          core->stopped = true;
          core->retainedAfterJoinFailure.reset();
        }
      }
    } catch (...) {
      // A report is always published, including close factory/body failure.
      // Retain all uncertain lower resources and executor leases until a later
      // successful explicit stop. External clients must remain alive meanwhile.
      core->retainUnconfirmedJoin();
      attempt->report.dispatcherTasksJoined = core->tasksJoined;
      attempt->report.localJoined = false;
      attempt->report.lowerJoinConfirmed = false;
      attempt->report.inventoryVerified = false;
      attempt->report.spool = {};
      attempt->report.joinFailure.emplace(StatusCode::kIOError);
    }
    attempt->report.retainedOutputLeases = core->heldOutputs();
  }
  co_return attempt->report;
}
}  // namespace hf3fs::client::ec::detail
