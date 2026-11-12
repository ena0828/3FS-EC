#pragma once

#include "meta/store/EcV2ReservationCatalog.h"

namespace hf3fs::meta::server {
class EcV2Coordinator;

// Only the coordinator may construct this after real V2 block reads, full
// descriptor/parity/logical SHA verification and twelve seal barriers.
// This cannot be deserialized or created through a caller-supplied callback.
class EcV2PublishEvidence {
 public:
  const EcOperationRecord &operation() const { return operation_; }
  const EcManifest &manifest() const { return manifest_; }
  const storage::EcSha256 &contentSha256() const { return contentSha256_; }

 private:
  friend class EcV2Coordinator;
  EcV2PublishEvidence(EcOperationRecord operation, EcManifest manifest, storage::EcSha256 content)
      : operation_(std::move(operation)),
        manifest_(std::move(manifest)),
        contentSha256_(content) {}
  EcOperationRecord operation_;
  EcManifest manifest_;
  storage::EcSha256 contentSha256_;
};

class EcVerifiedDrainAck {
 public:
  EcVerifiedDrainAck(const EcVerifiedDrainAck &) = default;
  EcVerifiedDrainAck &operator=(const EcVerifiedDrainAck &) = default;
  static Result<EcVerifiedDrainAck> verify(const storage::EcScopeControlKey &,
                                           const EcV2DrainRecord &,
                                           size_t index,
                                           const storage::EcScopeControlRequest &issued,
                                           const storage::EcScopeControlAck &observed);

 private:
  friend class EcV2DrainCatalog;
  friend class EcFileTreeReadCatalog;
  EcVerifiedDrainAck(EcV2DrainIdentity identity, size_t index, EcV2DrainObservation observation)
      : identity_(std::move(identity)),
        index_(index),
        observation_(std::move(observation)) {}
  EcV2DrainIdentity identity_;
  size_t index_;
  EcV2DrainObservation observation_;
};

// T0: close issuance + persist fixed scope/instances and optional publication
// proof. T1: store individually authenticated drained ACKs. T2: reverify all
// persisted ACKs and release exactly the recorded historical reference.
// Callers commit between phases and do all Storage control RPCs outside txn.
// Current inode permission/epoch checks for startPublish/finishPublish belong
// in the same caller txn; releasing/cancelling one's old scope does not need
// current READ permission. No timeouts, quorum or caller booleans bypass T2.
class EcV2DrainCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  // Pure signing helper outside the transaction; retries can use a fresh
  // nonce/time without changing the durable revocation or endpoint set.
  static Result<storage::EcScopeControlRequest> makeRequest(const EcV2DrainRecord &,
                                                            size_t index,
                                                            storage::EcScopeControlAction,
                                                            const storage::EcScopeControlKey &,
                                                            uint64_t nowSeconds,
                                                            uint64_t ttlSeconds = 60);
  static CoTryTask<std::optional<EcV2DrainRecord>> get(Transaction &,
                                                       const EcObjectRef &,
                                                       storage::EcGrantScope,
                                                       const Uuid &,
                                                       const EcOwner &);
  static CoTryTask<EcV2DrainRecord> startRead(Transaction &,
                                              const EcObjectRef &,
                                              const Uuid &pin,
                                              const EcOwner &,
                                              const Uuid &authority,
                                              const Uuid &revocation);
  static CoTryTask<EcV2DrainRecord> startCancel(Transaction &,
                                                const EcObjectRef &,
                                                const Uuid &operation,
                                                const EcOwner &,
                                                const Uuid &authority,
                                                const Uuid &revocation);
  static CoTryTask<EcV2DrainRecord> startPublish(Transaction &,
                                                 const EcV2PublishEvidence &,
                                                 const EcOwner &,
                                                 const Uuid &authority,
                                                 const Uuid &revocation);
  static CoTryTask<EcV2DrainRecord> recordAck(Transaction &, const EcVerifiedDrainAck &);
  static CoTryTask<EcPinRecord> finishRead(Transaction &,
                                           const EcObjectRef &,
                                           const Uuid &pin,
                                           const EcOwner &,
                                           const storage::EcScopeControlKey &);
  static CoTryTask<EcOperationRecord> finishCancel(Transaction &,
                                                   const EcObjectRef &,
                                                   const Uuid &operation,
                                                   const EcOwner &,
                                                   const storage::EcScopeControlKey &);
  static CoTryTask<EcOperationRecord> finishPublish(Transaction &,
                                                    const EcObjectRef &,
                                                    const Uuid &operation,
                                                    const EcOwner &,
                                                    const storage::EcScopeControlKey &);
};
}  // namespace hf3fs::meta::server
