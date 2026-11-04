#pragma once

#include <folly/fibers/Semaphore.h>
#include <memory>

#include "client/mgmtd/ICommonMgmtdClient.h"
#include "client/storage/StorageClient.h"
#include "fbs/meta/Service.h"
#include "meta/base/Config.h"
#include "meta/store/EcCatalog.h"

namespace hf3fs::meta::server {

// Not a wire type. Only this coordinator creates evidence after real storage
// reads, codec/digest verification, and twelve durability reconciliations.
class EcPublishEvidence {
 public:
  const EcOperationRecord &snapshot() const { return snapshot_; }
  const EcVerifiedManifest &verified() const { return verified_; }

 private:
  friend class EcCoordinator;
  EcPublishEvidence(EcOperationRecord snapshot, EcVerifiedManifest verified)
      : snapshot_(std::move(snapshot)),
        verified_(std::move(verified)) {}
  EcOperationRecord snapshot_;
  EcVerifiedManifest verified_;
};

class EcCoordinator {
 public:
  EcCoordinator(const Config &config,
                std::shared_ptr<client::ICommonMgmtdClient> mgmtd,
                std::shared_ptr<storage::client::StorageClient> storage);

  Result<Void> checkEnabled() const;
  Result<std::array<EcPlacement, 12>> placements() const;
  Result<storage::VersionedChainId> route(const EcPlacement &) const;
  Result<Void> validatePlacements(const EcOperationRecord &) const;
  CoTryTask<std::shared_ptr<const EcPublishEvidence>> verifyForPublish(const PublishEcMutationReq &,
                                                                       const EcOperationRsp &snapshot);

  // Capability issuance does not prove storage read-session drain. A live pin
  // cannot be released through client booleans, UUID knowledge, or expiry.
  Result<storage::EcCapability> issueCreateGrant(const EcFragment &,
                                                 const EcOwner &,
                                                 const Uuid &operation,
                                                 uint32_t length,
                                                 uint32_t crc) const;
  Result<storage::EcCapability> issueReadGrant(const EcFragment &, const EcOwner &, const Uuid &pin) const;
  Result<Void> addCreateGrants(EcOperationRsp &) const;
  Result<Void> addReadGrants(AcquireEcReadRsp &, const EcOwner &) const;
  Result<Void> confirmReadDrained(const EcPinRecord &) const;

 private:
  const Config &config_;
  std::shared_ptr<client::ICommonMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClient> storage_;
  folly::fibers::Semaphore verifying_;
  std::shared_ptr<const storage::EcCapabilityKey> key_;
  std::optional<Status> keyError_;
  Result<storage::EcCapability> issueGrant(const EcFragment &,
                                           const EcOwner &,
                                           storage::EcGrantScope,
                                           const Uuid &scopeId,
                                           uint8_t rights,
                                           uint32_t length,
                                           uint32_t crc) const;
};
}  // namespace hf3fs::meta::server
