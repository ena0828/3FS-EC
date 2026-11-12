#pragma once

#include <atomic>

#include "EcRmwPlanIssuer.h"
#include "EcRmwPublicationProof.h"
#include "client/storage/EcRequestControl.h"
#include "client/storage/StorageClient.h"

namespace hf3fs::meta::server {
class EcRmwPublicationVerifier final {
 public:
  struct Config {
    Uuid authority = Uuid::zero();
    std::function<uint64_t()> now;
    std::function<Result<storage::VersionedChainId>(const EcV2PhysicalEndpoint &)> route;
  };
  static Result<std::shared_ptr<EcRmwPublicationVerifier>> create(Config,
                                                                  std::shared_ptr<kv::IKVEngine>,
                                                                  std::shared_ptr<EcRmwPlanIssuer>,
                                                                  std::shared_ptr<storage::client::StorageClient>,
                                                                  std::shared_ptr<const storage::EcScopeControlKey>);
  // Actual network validation + committed T0/T1/T2, never a receipt-only
  // constructor. The returned proof is safe to consume only inside W2's fresh
  // root/epoch/child CAS transaction. It does NOT itself install a Data leaf.
  CoTryTask<std::shared_ptr<const EcRmwPublicationProof>> verify(EcObjectRef,
                                                                 EcOwner,
                                                                 Uuid child,
                                                                 storage::client::EcRequestControl) const;

 private:
  struct State;
  explicit EcRmwPublicationVerifier(std::shared_ptr<State> state)
      : state_(std::move(state)) {}
  static CoTryTask<std::shared_ptr<const EcRmwPublicationProof>> run(std::shared_ptr<State>,
                                                                     EcObjectRef,
                                                                     EcOwner,
                                                                     Uuid,
                                                                     storage::client::EcRequestControl);
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
