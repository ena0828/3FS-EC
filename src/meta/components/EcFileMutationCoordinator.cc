#include "EcFileMutationCoordinator.h"

#include <atomic>
#include <stdexcept>

#include "core/user/UserStoreEx.h"

namespace hf3fs::meta::server {
struct EcFileMutationCoordinator::State {
  explicit State(std::shared_ptr<kv::IKVEngine> value)
      : engine(std::move(value)),
        users(*engine, retry, cache) {}
  std::shared_ptr<kv::IKVEngine> engine;
  kv::TransactionRetry retry;
  core::UserCache::Config cache;
  core::UserStoreEx users;
  std::atomic<bool> closing{false};
};
EcFileMutationCoordinator::EcFileMutationCoordinator(std::shared_ptr<kv::IKVEngine> engine) {
  if (!engine) throw std::invalid_argument("file mutation coordinator requires a KV engine");
  state_ = std::make_shared<State>(std::move(engine));
}
void EcFileMutationCoordinator::closeAdmission() noexcept { state_->closing.store(true); }
template <typename R, typename Fn>
CoTryTask<R> EcFileMutationCoordinator::executeOwned(std::shared_ptr<State> state,
                                                     flat::UserInfo user,
                                                     EcOwner owner,
                                                     Fn fn) {
  if (state->closing.load()) co_return makeError(StorageClientCode::kResourceBusy, "file coordinator admission closed");
  CO_RETURN_ON_ERROR(co_await state->users.authenticate(user));
  if (owner.client.is_nil() || owner.uid != user.uid) co_return makeError(MetaCode::kNoPermission);
  auto inner = state->engine->createReadWriteTransaction();
  EcFileTreeTxnBudget txn(*inner);
  // Fn and its copied fixed request remain in this owned frame while its
  // coroutine runs. No automatic retry or new identity follows commit-unknown.
  auto result = co_await fn(txn, user);
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(co_await txn.commit());
  co_return std::move(*result);
}
CoTryTask<EcFileSessionRecord> EcFileMutationCoordinator::open(flat::UserInfo user, EcFileOpenIntent intent) const {
  auto owner = intent.owner;
  return executeOwned<EcFileSessionRecord>(state_,
                                           std::move(user),
                                           owner,
                                           [intent = std::move(intent)](auto &txn, const auto &authenticated) {
                                             return EcFileSessionCatalog::open(txn, authenticated, intent);
                                           });
}
CoTryTask<EcFileSessionRecord> EcFileMutationCoordinator::closeSession(flat::UserInfo user,
                                                                       EcObjectRef object,
                                                                       Uuid session,
                                                                       EcOwner owner) const {
  return executeOwned<EcFileSessionRecord>(state_, std::move(user), owner, [=](auto &txn, const auto &) {
    return EcFileSessionCatalog::close(txn, object, session, owner);
  });
}
CoTryTask<EcFileMutationRecord> EcFileMutationCoordinator::begin(flat::UserInfo user, EcFilePwriteIntent intent) const {
  auto owner = intent.owner;
  return executeOwned<EcFileMutationRecord>(
      state_,
      std::move(user),
      owner,
      [intent = std::move(intent)](auto &txn, const auto &) { return EcFileMutationCatalog::begin(txn, intent); });
}
CoTryTask<std::optional<EcFileMutationRecord>> EcFileMutationCoordinator::query(flat::UserInfo user,
                                                                                EcObjectRef object,
                                                                                Uuid parent,
                                                                                EcOwner owner) const {
  return executeOwned<std::optional<EcFileMutationRecord>>(
      state_,
      std::move(user),
      owner,
      [=](auto &txn, const auto &) { return EcFileMutationCatalog::query(txn, object, parent, owner); });
}
CoTryTask<EcFileChildRecord> EcFileMutationCoordinator::planChild(flat::UserInfo user,
                                                                  EcOwner owner,
                                                                  EcFileChildIntent intent) const {
  return executeOwned<EcFileChildRecord>(state_,
                                         std::move(user),
                                         owner,
                                         [intent = std::move(intent), owner](auto &txn, const auto &) {
                                           return EcFileMutationCatalog::planChild(txn, owner, intent);
                                         });
}
CoTryTask<std::optional<EcFileChildRecord>> EcFileMutationCoordinator::queryChild(flat::UserInfo user,
                                                                                  EcObjectRef object,
                                                                                  Uuid child,
                                                                                  EcOwner owner) const {
  return executeOwned<std::optional<EcFileChildRecord>>(state_, std::move(user), owner, [=](auto &txn, const auto &) {
    return EcFileMutationCatalog::queryChild(txn, object, child, owner);
  });
}
CoTryTask<EcFileMutationRecord> EcFileMutationCoordinator::sealPrefix(flat::UserInfo user,
                                                                      EcObjectRef object,
                                                                      Uuid parent,
                                                                      EcOwner owner) const {
  return executeOwned<EcFileMutationRecord>(state_, std::move(user), owner, [=](auto &txn, const auto &) {
    return EcFileMutationCatalog::sealPrefix(txn, object, parent, owner);
  });
}
}  // namespace hf3fs::meta::server
