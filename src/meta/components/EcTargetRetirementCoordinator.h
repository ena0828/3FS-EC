#pragma once

#include "common/kv/IKVEngine.h"
#include "meta/components/EcV2Coordinator.h"

namespace hf3fs::meta::server {
// Owns all state and request bytes across each awaited controlled exchange.
// Authorization is performed by MetaOperator; no detached task or auto retry.
// The service owner must join requests before destroying Config/MetaOperator.
// close() denies new work; it is not itself a join or distributed drain.
class EcTargetRetirementCoordinator {
 public:
  EcTargetRetirementCoordinator(const Config &,
                                 std::shared_ptr<kv::IKVEngine>,
                                 std::shared_ptr<storage::client::StorageClient>,
                                 const EcV2Coordinator &);
  Result<Void> checkEnabled() const;
  void close();
  CoTryTask<EcTargetRetirementRsp> prepare(EcTargetRetirementReq) const;
  CoTryTask<EcTargetRetirementRsp> query(EcTargetRetirementReq) const;

 private:
  struct State;
  static CoTryTask<EcTargetRetirementRsp> executeOwned(std::shared_ptr<State>,
                                                      EcTargetRetirementReq,
                                                      storage::EcTargetRetirementAction);
  const Config &config_;
  std::optional<Status> initializationError_;
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
