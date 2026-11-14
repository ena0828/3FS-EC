#include <folly/CancellationToken.h>

#include "EcFileRunFactory.h"
#include "detail/EcReadDispatcherCore.h"

namespace hf3fs::client::ec::detail {
CoTryTask<EcDispatchReadOutcome> EcReadDispatcherCore::newReadOwned(EcReadHandle handle,
                                                                    flat::UserInfo user,
                                                                    uint64_t offset,
                                                                    uint64_t length,
                                                                    EcStripeControl c) {
  if (handle.dispatcher_ != instance || handle.describeRequest_.is_nil())
    co_return makeError(StatusCode::kTokenMismatch, "read handle belongs to another dispatcher lifetime");
  if (heldOutputs())
    co_return makeError(StorageClientCode::kResourceBusy, "release the held output before admitting another data read");
  auto authenticated = co_await authenticate(std::move(user), c);
  CO_RETURN_ON_ERROR(authenticated);
  auto connected = co_await manager(*authenticated, c);
  CO_RETURN_ON_ERROR(connected);
  // A handle is immutable object/layout information, never an ACL bypass.
  // Acquire43 below performs current access checks in the real Meta service.
  auto prepared =
      prepareEcFileRead(handle.file_, file->owner(), spool->cluster(), offset, length, handle.describeRequest_);
  CO_RETURN_ON_ERROR(prepared);
  auto run = spool->prepare(std::move(*prepared));
  CO_RETURN_ON_ERROR(run);
  activeReceipt = run->receipt;
  co_return co_await readRun(std::move(*run), c);
}
CoTryTask<EcDispatchReadOutcome> EcReadDispatcherCore::resumeOwned(EcReadReceipt receipt,
                                                                   flat::UserInfo user,
                                                                   EcStripeControl c) {
  if (heldOutputs()) co_return makeError(StorageClientCode::kResourceBusy, "held output prevents another data read");
  auto authenticated = co_await authenticate(std::move(user), c);
  CO_RETURN_ON_ERROR(authenticated);
  if (authenticated->uid.toUnderType() != receipt.ownerUid) co_return makeError(StatusCode::kTokenMismatch);
  auto run = spool->resume(receipt);
  CO_RETURN_ON_ERROR(run);
  activeReceipt = receipt;
  auto connected = co_await manager(*authenticated, c);
  if (!connected) co_return failedRead(std::move(connected.error()));
  co_return co_await readRun(std::move(*run), c);
}
CoTryTask<EcDispatchReadOutcome> EcReadDispatcherCore::readRun(EcReadSpool::Run run, EcStripeControl c) {
  EcDispatchReadOutcome out;
  out.receipt = run.receipt;
  auto reserved = spool->reserveAttempt(run);
  if (!reserved) {
    out.localJoined = out.cleanup.localJoined = true;
    out.readFailure = reserved.error();
    out.cleanup.failure = std::move(reserved.error());
    co_return out;
  }
  CancellationSource combined;
  folly::CancellationCallback stopped(cancellation.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback caller(c.cancellation, [&] { combined.requestCancellation(); });
  c.cancellation = combined.getToken();
  auto read = co_await file->read(run.journal, c);
  if (!read) out.readFailure = std::move(read.error());
  if (file->localJoinUnconfirmed()) {
    retainUnconfirmedJoin();
    if (!out.readFailure) out.readFailure.emplace(StatusCode::kIOError);
    out.cleanup.failure.emplace(StatusCode::kIOError);
    co_return out;
  }
  // One bounded cleanup attempt is independent of a canceled data waiter. It
  // never invents another range; F3 cleanup uses Query44 and original Release36.
  EcStripeControl cleanup;
  cleanup.transport = c.transport;
  cleanup.deadline = std::chrono::steady_clock::now() + limits.cleanupAttemptTime;
  auto released = co_await file->releaseRead(run.journal, cleanup);
  const bool joined = !file->localJoinUnconfirmed();
  out.cleanup = EcDispatchCleanupOutcome{std::move(released), joined};
  if (!joined) {
    retainUnconfirmedJoin();
    out.cleanup.allReleased = false;
    if (!out.cleanup.failure) out.cleanup.failure.emplace(StatusCode::kIOError);
    if (!out.readFailure) out.readFailure.emplace(StatusCode::kIOError);
    co_return out;
  }
  out.localJoined = true;
  if (read) {
    EcDispatchedRead output;
    output.lease_ = std::make_shared<EcReadOutputLease>(shared_from_this());
    output.output_ = std::move(*read);
    out.data.emplace(std::move(output));
  }
  co_return out;
}
CoTask<EcDispatchCleanupOutcome> EcReadDispatcherCore::cleanupOwned(EcReadReceipt receipt,
                                                                    flat::UserInfo user,
                                                                    EcStripeControl c) {
  const auto failure = [](Status e) {
    EcDispatchCleanupOutcome out;
    out.failure = std::move(e);
    return out;
  };
  auto authenticated = co_await authenticate(std::move(user), c);
  if (!authenticated) co_return failure(std::move(authenticated.error()));
  if (authenticated->uid.toUnderType() != receipt.ownerUid) co_return failure(Status(StatusCode::kTokenMismatch));
  auto run = spool->resume(receipt);
  if (!run) co_return failure(std::move(run.error()));
  activeReceipt = receipt;
  auto reserved = spool->reserveAttempt(*run);
  if (!reserved) co_return failure(std::move(reserved.error()));
  auto connected = co_await manager(*authenticated, c);
  if (!connected) co_return failure(std::move(connected.error()));
  CancellationSource combined;
  folly::CancellationCallback stopped(cancellation.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback caller(c.cancellation, [&] { combined.requestCancellation(); });
  c.cancellation = combined.getToken();
  auto released = co_await file->releaseRead(run->journal, c);
  const bool joined = !file->localJoinUnconfirmed();
  EcDispatchCleanupOutcome out{std::move(released), joined};
  if (!joined) {
    retainUnconfirmedJoin();
    out.allReleased = false;
    if (!out.failure) out.failure.emplace(StatusCode::kIOError);
  }
  co_return out;
}
}  // namespace hf3fs::client::ec::detail
