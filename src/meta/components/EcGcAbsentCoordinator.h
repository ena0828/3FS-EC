#pragma once

#include "meta/components/EcGcCoordinator.h"
#include "meta/store/EcGcAbsentCompletionCatalog.h"

namespace hf3fs::meta::server {
class EcGcAbsentTransport {
 public:
  virtual ~EcGcAbsentTransport() = default;
  virtual CoTryTask<storage::EcGcAbsentAck> exchange(storage::EcGcAbsentRequest owned,
                                                   storage::client::EcRequestControl) = 0;
};
class EcGcAbsentCoordinator {
 public:
  using Config = EcGcCoordinator::Config;
  static Result<std::unique_ptr<EcGcAbsentCoordinator>> create(Config, std::shared_ptr<kv::IKVEngine>,
      std::shared_ptr<const storage::EcScopeControlKey>, std::shared_ptr<const storage::EcGcKey>,
      std::shared_ptr<EcGcAbsentTransport>);
  CoTryTask<EcGcAbsentCompletion> confirm(EcObjectRef, storage::EcFragmentIdentity, Uuid claimId,
                                         storage::client::EcRequestControl) const;
  // Query may persist the first authenticated existing Storage fact in Meta;
  // it never creates a claim, local fence or Storage absence ledger.
  CoTryTask<EcGcAbsentCompletion> query(EcObjectRef, storage::EcFragmentIdentity, Uuid claimId,
                                       storage::client::EcRequestControl) const;

 private:
  struct State;
  explicit EcGcAbsentCoordinator(std::shared_ptr<State> state) : state_(std::move(state)) {}
  static CoTryTask<EcGcAbsentCompletion> executeOwned(std::shared_ptr<State>, EcObjectRef,
      storage::EcFragmentIdentity, Uuid, storage::EcGcAbsentAction, storage::client::EcRequestControl);
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
