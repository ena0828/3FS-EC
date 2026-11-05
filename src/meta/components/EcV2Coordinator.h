#pragma once

#include <folly/fibers/Semaphore.h>
#include <memory>

#include "client/mgmtd/ICommonMgmtdClient.h"
#include "client/storage/StorageClient.h"
#include "fbs/meta/Service.h"
#include "meta/base/Config.h"
#include "meta/components/EcV2RepairIssuer.h"
#include "meta/store/EcV2DrainCatalog.h"

namespace hf3fs::meta::server {
class EcV2Coordinator {
 public:
  EcV2Coordinator(const Config &,
                  std::shared_ptr<client::ICommonMgmtdClient>,
                  std::shared_ptr<storage::client::StorageClient>);
  Result<Void> checkEnabled() const;
  Result<EcV2ReservationCatalog::PhysicalPool> configuredPool() const;
  Result<EcV2ReservationCatalog::PhysicalPool> pool(uint16_t replacementMask = kEcAllShards) const;
  Result<storage::VersionedChainId> route(const EcV2PhysicalEndpoint &) const;
  const Uuid &authority() const { return authority_; }
  const storage::EcScopeControlKey &controlKey() const { return *controlKey_; }
  std::shared_ptr<const storage::EcScopeControlKey> sharedControlKey() const { return controlKey_; }
  Result<std::vector<storage::EcKeyFileIdentity>> loadedKeyFileIdentities() const;

  // Caller must first commit checkIssuanceOpen in the same transaction that
  // checked owner/ACL and loaded these fixed records. Late delivery after T0
  // cannot reopen the corresponding irreversible Storage deny.
  Result<Void> addMutationGrants(EcV2MutationRsp &) const;
  Result<Void> addReadGrants(AcquireEcReadV2Rsp &) const;
  Result<std::optional<std::array<storage::EcHelperCapability, 10>>> issueRepairHelpers(
      const EcV2RepairPlanRecord &) const;
  CoTryTask<std::shared_ptr<const EcV2PublishEvidence>> verifyForPublish(const EcV2MutationRsp &);
  CoTryTask<std::optional<EcVerifiedDrainAck>> observeDrain(const EcV2DrainRecord &,
                                                            size_t index,
                                                            storage::EcScopeControlAction);

 private:
  Result<storage::EcCapabilityV2> issueGrant(const EcV2AllocationBinding &,
                                             const EcOwner &,
                                             storage::EcGrantScope,
                                             const Uuid &,
                                             uint16_t rights) const;
  const Config &config_;
  std::shared_ptr<client::ICommonMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClient> storage_;
  folly::fibers::Semaphore verifying_;
  std::shared_ptr<const storage::EcCapabilityKey> dataKey_;
  std::shared_ptr<const storage::EcScopeControlKey> controlKey_;
  std::shared_ptr<const storage::EcHelperKey> helperKey_;
  Uuid authority_ = Uuid::zero();
  std::optional<Status> initializationError_;
};
}  // namespace hf3fs::meta::server
