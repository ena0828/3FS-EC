#pragma once

#include "common/kv/IKVEngine.h"
#include "meta/store/EcFileExecutionCatalog.h"

namespace hf3fs::meta::server {
// Internal issuance envelope. Never return this from ordinary user methods:
// it contains original plaintext-read authority for the trusted worker only.
struct EcRmwIssuedExecution {
  EcFileExecutionObservation observed;
  storage::EcRmwGrant install;
  storage::EcRmwGrant client;
  std::optional<std::array<storage::EcCapabilityV2, 12>> reads;
  std::optional<std::array<storage::EcCapabilityV2, 12>> writes;
  // Only the selected ten repair helpers receive output-scope read authority.
  std::optional<std::array<storage::EcCapabilityV2, 10>> repairReads;
  // Issued only for a committed HelperChainDirect record, in selected target order.
  std::optional<std::array<storage::EcCapabilityV2, 2>> repairAppends;
  std::optional<std::array<storage::EcCapabilityV2, 2>> repairQueries;
};
class EcRmwPlanIssuer final {
 public:
  struct Config {
    Uuid authority = Uuid::zero();
    uint64_t ttlSeconds = 60;
    std::function<uint64_t()> now;
  };
  static Result<std::shared_ptr<EcRmwPlanIssuer>> create(Config,
                                                         std::shared_ptr<kv::IKVEngine>,
                                                         std::shared_ptr<const storage::EcRmwKey>,
                                                         std::shared_ptr<const storage::EcCapabilityKey>);
  // Owns a fresh transaction, including W2 session/parent/child and source-pin
  // issuance conflict writes. No signing occurs after MaybeCommitted/error.
  CoTryTask<EcRmwIssuedExecution> issue(EcObjectRef, EcOwner, Uuid child) const;
  // Internal Meta52 worker path: actual RMW Execute MAC AND computed MAC must
  // match the permanent plan; first binding + issuance commit precedes grants.
  CoTryTask<EcRmwIssuedExecution> bind(EcObjectRef,
                                       EcOwner,
                                       Uuid child,
                                       storage::EcRmwGrant,
                                       storage::EcRmwComputedCommitment) const;

 private:
  EcRmwPlanIssuer(Config c,
                  std::shared_ptr<kv::IKVEngine> db,
                  std::shared_ptr<const storage::EcRmwKey> rmw,
                  std::shared_ptr<const storage::EcCapabilityKey> data)
      : config_(std::move(c)),
        db_(std::move(db)),
        rmw_(std::move(rmw)),
        data_(std::move(data)) {}
  Result<EcRmwIssuedExecution> sign(EcFileExecutionObservation, uint16_t directMask = 0) const;
  Result<storage::EcCapabilityV2> dataGrant(const storage::EcRepairFragment &,
                                            const storage::EcRmwPlan &,
                                            storage::EcGrantScope,
                                            const Uuid &,
                                            uint16_t,
                                            uint64_t) const;
  Config config_;
  std::shared_ptr<kv::IKVEngine> db_;
  std::shared_ptr<const storage::EcRmwKey> rmw_;
  std::shared_ptr<const storage::EcCapabilityKey> data_;
};
}  // namespace hf3fs::meta::server
