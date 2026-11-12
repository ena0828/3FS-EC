#include "EcReadDispatcher.h"

#include "detail/EcReadDispatcherCore.h"

namespace hf3fs::client::ec {
using Core = detail::EcReadDispatcherCore;
EcDispatchedRead::EcDispatchedRead(EcDispatchedRead &&other) noexcept
    : lease_(std::move(other.lease_)),
      output_(std::move(other.output_)) {}
EcDispatchedRead &EcDispatchedRead::operator=(EcDispatchedRead &&other) noexcept {
  if (this != &other) {
    // Destroy the old payload charge before releasing its global lease. Then
    // move the new lease first, so both payloads always have a live owner.
    output_ = EcFileReadOutput{};
    lease_.reset();
    lease_ = std::move(other.lease_);
    output_ = std::move(other.output_);
  }
  return *this;
}
EcReadDispatcher::~EcReadDispatcher() = default;
Result<std::shared_ptr<EcReadDispatcher>> EcReadDispatcher::connect(
    std::shared_ptr<EcReadSpool> spool,
    std::shared_ptr<meta::client::MetaClient> metadata,
    std::shared_ptr<storage::client::StorageClient> storage,
    std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd,
    folly::CPUThreadPoolExecutor &pool,
    Limits limits) {
  if (!spool || !metadata || !storage || !mgmtd || spool->poisoned() ||
      metadata->clientId().uuid != spool->clientNamespace() ||
      limits.maximumOperationTime <= std::chrono::seconds::zero() ||
      limits.maximumOperationTime > std::chrono::hours(1) ||
      limits.cleanupAttemptTime <= std::chrono::seconds::zero() ||
      limits.cleanupAttemptTime > limits.maximumOperationTime)
    return makeError(StatusCode::kInvalidArg, "invalid read dispatcher bounds or actual persistent Meta namespace");
  bool unattached = false;
  if (!spool->attached_.compare_exchange_strong(unattached, true))
    return makeError(StorageClientCode::kResourceBusy, "spool already has a dispatcher or retained output lease");
  bool transferred = false;
  try {
    auto core = std::make_shared<Core>(spool, std::move(metadata), std::move(storage), std::move(mgmtd), pool, limits);
    transferred = true;
    return std::shared_ptr<EcReadDispatcher>(new EcReadDispatcher(std::move(core)));
  } catch (const std::bad_alloc &) {
    if (!transferred) spool->attached_.store(false);
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
CoTryTask<EcReadHandle> EcReadDispatcher::openRead(meta::EcObjectRef object, flat::UserInfo user, EcStripeControl c) {
  return core_->launch<Result<EcReadHandle>>(
      [core = core_, object, user = std::move(user), c]() mutable {
        return core->openOwned(object, std::move(user), c);
      },
      [](Status e) -> Result<EcReadHandle> { return makeError(std::move(e)); });
}
CoTryTask<EcDispatchReadOutcome> EcReadDispatcher::read(EcReadHandle handle,
                                                        flat::UserInfo user,
                                                        uint64_t offset,
                                                        uint64_t length,
                                                        EcStripeControl c) {
  return core_->launch<Result<EcDispatchReadOutcome>>(
      [core = core_, handle = std::move(handle), user = std::move(user), offset, length, c]() mutable {
        return core->newReadOwned(std::move(handle), std::move(user), offset, length, c);
      },
      [](Status e) -> Result<EcDispatchReadOutcome> { return makeError(std::move(e)); });
}
CoTryTask<EcDispatchReadOutcome> EcReadDispatcher::resumeRead(EcReadReceipt receipt,
                                                              flat::UserInfo user,
                                                              EcStripeControl c) {
  return core_->launch<Result<EcDispatchReadOutcome>>(
      [core = core_, receipt, user = std::move(user), c]() mutable {
        return core->resumeOwned(receipt, std::move(user), c);
      },
      [](Status e) -> Result<EcDispatchReadOutcome> { return makeError(std::move(e)); });
}
CoTask<EcDispatchCleanupOutcome> EcReadDispatcher::retryCleanup(EcReadReceipt receipt,
                                                                flat::UserInfo user,
                                                                EcStripeControl c) {
  return core_->launch<EcDispatchCleanupOutcome>(
      [core = core_, receipt, user = std::move(user), c]() mutable {
        return core->cleanupOwned(receipt, std::move(user), c);
      },
      [](Status e) {
        EcDispatchCleanupOutcome out;
        out.failure = std::move(e);
        return out;
      });
}
CoTryTask<EcReadRetirementOutcome> EcReadDispatcher::retire(EcReadReceipt receipt,
                                                            flat::UserInfo user,
                                                            std::filesystem::path archive,
                                                            EcStripeControl c) {
  return core_->launch<Result<EcReadRetirementOutcome>>(
      [core = core_, receipt, user = std::move(user), archive = std::move(archive), c]() mutable {
        return core->retireOwned(receipt, std::move(user), std::move(archive), c);
      },
      [](Status e) -> Result<EcReadRetirementOutcome> { return makeError(std::move(e)); });
}
CoTryTask<EcReadSpoolSnapshot> EcReadDispatcher::inspect() {
  return core_->launch<Result<EcReadSpoolSnapshot>>(
      [core = core_] { return core->inspectOwned(); },
      [](Status e) -> Result<EcReadSpoolSnapshot> { return makeError(std::move(e)); });
}
CoTryTask<EcReadReceiptObservation> EcReadDispatcher::inspectReceipt(EcReadReceipt receipt) {
  return core_->launch<Result<EcReadReceiptObservation>>(
      [core = core_, receipt] { return core->receiptOwned(receipt); },
      [](Status e) -> Result<EcReadReceiptObservation> { return makeError(std::move(e)); });
}
CoTask<EcReadShutdownReport> EcReadDispatcher::stop() {
  // Close admission synchronously, even if the returned task has not yet been
  // awaited. The owner must still await it before destroying clients/executor.
  {
    std::lock_guard lock(core_->mutex);
    core_->closing = true;
    if (!core_->stopped) core_->retainedAfterJoinFailure = core_;
  }
  core_->cancellation.requestCancellation();
  return Core::finishStop(core_);
}
}  // namespace hf3fs::client::ec
