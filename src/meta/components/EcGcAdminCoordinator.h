#pragma once

#include "meta/components/EcCoordinator.h"
#include "meta/components/EcV2Coordinator.h"
#include "meta/components/NativeEcGcTransport.h"

namespace hf3fs::meta::server {
// Service-owned runtime. Authorization is performed by MetaOperator before
// calling this internal entry point. No candidate scan or implicit retire.
class EcGcAdminCoordinator {
 public:
  EcGcAdminCoordinator(const Config &,
                       std::shared_ptr<kv::IKVEngine>,
                       std::shared_ptr<storage::client::StorageClient>,
                       const EcCoordinator &,
                       const EcV2Coordinator &);
  Result<Void> checkEnabled() const;
  void close();
  CoTryTask<EcGcAdminRsp> collect(EcGcAdminReq) const;
  CoTryTask<EcGcAdminRsp> query(EcGcAdminReq) const;

 private:
  struct State;
  static CoTryTask<EcGcAdminRsp> executeOwned(std::shared_ptr<State>, EcGcAdminReq, storage::EcGcAction);
  const Config &config_;
  std::optional<Status> initializationError_;
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
