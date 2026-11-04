#pragma once

#include "common/kv/ITransaction.h"
#include "fbs/meta/Ec.h"

namespace hf3fs::meta::server {

// Deliberately not serializable. The caller must obtain these responses from
// authenticated storage and validate its current routing outside the database
// transaction. This checks bytes and seals, not whether an untrusted client
// encoded correct parity: encoding remains the trusted coordinator's duty.
class EcVerifiedManifest {
 public:
  static Result<EcVerifiedManifest> fromStorageResponses(EcManifest manifest,
                                                         const std::array<storage::EcReadResult, 12> &reads,
                                                         const std::array<storage::EcFragmentReceipt, 12> &reconciled);
  const EcManifest &manifest() const { return manifest_; }

 private:
  explicit EcVerifiedManifest(EcManifest manifest)
      : manifest_(std::move(manifest)) {}
  EcManifest manifest_;
};

// Internal transaction primitives. The service must check inode permissions,
// incarnation, storage placement and capabilities before invoking these APIs.
// No method commits or retries. On any error the caller must discard/reset its
// transaction. A commit with unknown outcome is reconciled through operation
// records; it is never permission to remove a fragment.
class EcCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  static CoTryTask<EcObjectRecord> createObject(Transaction &,
                                                const EcObjectRef &,
                                                uint32_t shardBytes,
                                                bool allowColocated = false,
                                                const EcOwner &creator = {},
                                                const Uuid &createRequest = Uuid::zero());
  static CoTryTask<EcObjectRecord> getObject(Transaction &, const EcObjectRef &);
  static CoTryTask<EcOperationRecord> begin(Transaction &, const EcMutationIntent &, const EcOwner &owner = {});
  static CoTryTask<EcOperationRecord> getOperation(Transaction &, const EcObjectRef &, const Uuid &operation);
  static CoTryTask<EcOperationRecord> publish(Transaction &,
                                              const EcObjectRef &,
                                              const Uuid &operation,
                                              const EcVerifiedManifest &);
  static CoTryTask<EcOperationRecord> cancel(Transaction &, const EcObjectRef &, const Uuid &operation);
  static CoTryTask<EcManifest> acquireRead(Transaction &,
                                           const EcObjectRef &,
                                           uint64_t stripe,
                                           const Uuid &pin,
                                           const EcOwner &owner = {});
  static CoTryTask<EcPinRecord> getPin(Transaction &, const EcObjectRef &, const Uuid &pin);
  // The service may release a pin only after all its admitted reads have drained.
  // There is intentionally no expiry-based or administrative forced release.
  static CoTryTask<Void> releaseRead(Transaction &, const EcObjectRef &, const Uuid &pin);
  static CoTryTask<Void> retireRevision(Transaction &, const EcObjectRef &, uint64_t stripe, uint64_t revision);
  static CoTryTask<EcFragmentRefRecord> getFragmentRef(Transaction &, const storage::EcFragmentIdentity &);
};

}  // namespace hf3fs::meta::server
