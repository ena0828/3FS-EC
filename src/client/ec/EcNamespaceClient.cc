#include "EcNamespaceClient.h"

#include <fcntl.h>
#include <folly/experimental/coro/BlockingWait.h>

namespace hf3fs::client::ec {
Result<std::unique_ptr<EcNamespaceClient>> EcNamespaceClient::connect(
    std::shared_ptr<meta::client::MetaClient> meta, flat::UserInfo credentials, Uuid expected) {
  if (!meta || expected.is_nil() || meta->clientId().uuid != expected) return makeError(StatusCode::kInvalidArg);
  try {
    auto authenticated = folly::coro::blockingWait(meta->authenticate(credentials));
    if (!authenticated) return makeError(std::move(authenticated.error()));
    auto token = std::move(credentials.token);
    credentials = std::move(*authenticated);
    credentials.token = std::move(token);
    return std::unique_ptr<EcNamespaceClient>(new EcNamespaceClient(std::move(meta), std::move(credentials)));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}
EcNamespaceOutcome EcNamespaceClient::unlink(EcNamespaceJournal &journal, EcStripeControl control) {
  EcNamespaceOutcome out;
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) {
    out.failure = Status(StorageClientCode::kResourceBusy);
    return out;
  }
  out.acknowledged = journal.latest() && journal.latest()->acknowledged;
  bool invoked = false;
  try {
    auto call = [&]() -> Result<Void> {
      RETURN_ON_ERROR(journal.record().validate());
      const auto &r = journal.record();
      const auto &i = r.session.intent;
      if (journal.poisoned() || i.owner.uid != owner_.uid || i.owner.client != owner_.client)
        return makeError(StatusCode::kTokenMismatch);
      // This policy does not choose the Meta control transport. Reject malformed
      // public control values but never start a data-plane device for unlink.
      RETURN_ON_ERROR(validateEcStorageTransport(control.transport));
      const auto now = std::chrono::steady_clock::now();
      if (control.deadline - now > std::chrono::hours(1)) return makeError(StatusCode::kInvalidArg);
      if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
      if (now >= control.deadline) return makeError(StorageClientCode::kTimeout);
      if (journal.remainingStates() < 2) return makeError(StatusCode::kInvalidArg, "unlink observation limit");
      meta::RemoveReq request;
      request.user = credentials_;
      request.client = ClientId(owner_.client);
      request.uuid = r.request;
      request.path = meta::PathAt(meta::InodeId::root(), Path(r.path));
      request.atFlags = meta::AtFlags(AT_SYMLINK_NOFOLLOW);
      request.recursive = false;
      request.checkType = true;
      request.inodeId = i.object.inode;
      RETURN_ON_ERROR(request.valid());
      auto state = journal.latest().value_or(EcNamespaceJournalState{});
      state.issued = true;
      RETURN_ON_ERROR(journal.append(state));  // Durable intent before dispatch, including retry.
      invoked = true;
      auto reply = folly::coro::blockingWait(meta_->unlinkWithIdentity(std::move(request)));
      if (!reply) return makeError(std::move(reply.error()));  // Missing never means success.
      state.acknowledged = true;
      RETURN_ON_ERROR(journal.append(state));
      return Void{};
    };
    auto result = call();
    out.acknowledged = journal.latest() && journal.latest()->acknowledged;
    if (!result) out.failure = std::move(result.error());
    else out.revalidated = true;
  } catch (const std::bad_alloc &) {
    out.failure = Status(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    out.failure = Status(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
  return out;
}
}  // namespace hf3fs::client::ec
