#pragma once

#include <memory>

#include "common/kv/IKVEngine.h"
#include "meta/store/EcFileMutationCatalog.h"

namespace hf3fs::meta::server {
// Internal, owning, single-transaction API. Public Meta methods authenticate
// through MetaOperator and combine these same catalogs with the W1 verifier.
// Every call authenticates the supplied token through UserStoreEx. No caller
// bool or asserted UID can bypass authentication. Commit errors retain their
// original status: callers must Query the SAME request/session/child IDs.
class EcFileMutationCoordinator {
 public:
  explicit EcFileMutationCoordinator(std::shared_ptr<kv::IKVEngine>);
  void closeAdmission() noexcept;
  CoTryTask<EcFileSessionRecord> open(flat::UserInfo, EcFileOpenIntent) const;
  CoTryTask<EcFileSessionRecord> closeSession(flat::UserInfo, EcObjectRef, Uuid, EcOwner) const;
  CoTryTask<EcFileMutationRecord> begin(flat::UserInfo, EcFilePwriteIntent) const;
  CoTryTask<std::optional<EcFileMutationRecord>> query(flat::UserInfo, EcObjectRef, Uuid, EcOwner) const;
  CoTryTask<EcFileChildRecord> planChild(flat::UserInfo, EcOwner, EcFileChildIntent) const;
  CoTryTask<std::optional<EcFileChildRecord>> queryChild(flat::UserInfo, EcObjectRef, Uuid, EcOwner) const;
  CoTryTask<EcFileMutationRecord> sealPrefix(flat::UserInfo, EcObjectRef, Uuid, EcOwner) const;
  // Publication belongs to MetaOperator's actual W1 verifier + trusted Data
  // installer path, never a caller-built receipt in this metadata-only helper.
 private:
  struct State;
  template <typename R, typename Fn>
  static CoTryTask<R> executeOwned(std::shared_ptr<State>, flat::UserInfo, EcOwner, Fn);
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
