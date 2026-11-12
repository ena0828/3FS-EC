#pragma once

#include "EcFileMutationCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "storage/ec_rmw/EcRmwComputation.h"

namespace hf3fs::meta::server {
class EcRmwPublicationVerifier;
class EcRmwPublicationProof;
class EcFileDataInstaller;
class EcFileTruncateCatalog;
enum class EcFileExecutionOwner : uint8_t { Pwrite = 1, TruncateTail = 2, Repair = 3 };
enum class EcFileExecutionState : uint8_t {
  Reserved = 1,
  Bound = 2,
  Closing = 3,
  Drained = 4,
  Published = 5,
  Aborted = 6
};
// Meta-internal only: WRITE-only clients never receive sources or read grants.
struct EcFileExecutionRecord {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(child, EcFileChildRecord{});
  SERDE_STRUCT_FIELD(ownerKind, EcFileExecutionOwner::Pwrite);
  SERDE_STRUCT_FIELD(state, EcFileExecutionState::Reserved);
  SERDE_STRUCT_FIELD(candidates, (std::array<EcV2ReservedAllocation, 12>{}));
  SERDE_STRUCT_FIELD(endpoints, EcV2OperationEndpoints{});
  SERDE_STRUCT_FIELD(workerIndex, uint8_t{});
  SERDE_STRUCT_FIELD(planDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(issuanceSequence, uint64_t{});
  SERDE_STRUCT_FIELD(allocations, (std::optional<EcV2AllocationBindings>{}));
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(drain, (std::optional<EcV2DrainRecord>{}));
};
struct EcFileExecutionAllocation {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(allocation, EcV2ReservedAllocation{});
  SERDE_STRUCT_FIELD(active, true);
};
struct EcFileExecutionObservation {
  EcFileExecutionRecord record;
  std::shared_ptr<const storage::EcRmwPlan> plan;
};
class EcFileExecutionCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  using TrustedPool = std::array<EcV2PhysicalEndpoint, 12>;
  // Internal server configuration only. A public request cannot provide pool,
  // worker, allocation IDs or a purported source manifest. Existing records
  // keep their original instances even if the current configuration changes.
  static CoTryTask<EcFileExecutionObservation> reserveExecution(Tx &,
                                                                const EcOwner &,
                                                                const EcObjectRef &,
                                                                const Uuid &child,
                                                                const TrustedPool &,
                                                                uint8_t workerIndex,
                                                                EcFileExecutionOwner = EcFileExecutionOwner::Pwrite);
  static CoTryTask<EcFileExecutionObservation> get(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &child);
  // Real ECFE increment conflicts with Closing; source ECSP issuance is also
  // incremented in this transaction. Commit MUST succeed before any signing.
  // Repair binds the exact captured immutable descriptors; no caller or worker
  // can substitute bytes. Actual verifier remains required before publication.
  static CoTryTask<EcFileExecutionObservation> bindRepairOutput(Tx &,
                                                                const EcOwner &,
                                                                const EcObjectRef &,
                                                                const Uuid &child);
  static CoTryTask<EcFileExecutionObservation> reserveIssuance(Tx &,
                                                               const EcOwner &,
                                                               const EcObjectRef &,
                                                               const Uuid &child);
  static CoTryTask<EcFileExecutionObservation> bindOutput(Tx &,
                                                          const EcOwner &,
                                                          const EcObjectRef &,
                                                          const Uuid &child,
                                                          const storage::VerifiedEcRmwComputation &);
  static CoTryTask<EcV2DrainRecord> startCancelClosing(Tx &,
                                                       const EcOwner &,
                                                       const EcObjectRef &,
                                                       const Uuid &child,
                                                       const Uuid &authority,
                                                       const Uuid &revocation);
  static CoTryTask<EcV2DrainRecord> recordAck(Tx &,
                                              const EcOwner &,
                                              const EcObjectRef &,
                                              const Uuid &child,
                                              size_t index,
                                              const storage::EcScopeControlKey &,
                                              const storage::EcScopeControlRequest &,
                                              const storage::EcScopeControlAck &);
  static CoTryTask<EcFileExecutionObservation> finishDrain(Tx &,
                                                           const EcOwner &,
                                                           const EcObjectRef &,
                                                           const Uuid &child,
                                                           const storage::EcScopeControlKey &);
  static CoTryTask<Void> requireUnheld(kv::IReadWriteTransaction &,
                                       const EcObjectRef &,
                                       const storage::EcFragmentIdentity &);

 private:
  friend class EcRmwPublicationVerifier;
  friend class EcFileDataInstaller;
  friend class EcFileTruncateCatalog;
  friend class EcFileRepairCatalog;
  // Only the three closed compound publication functions may hold this
  // validation. It must not escape, cross a transaction boundary, or surround
  // callbacks/parallel work. Between prepare and finish they may write new
  // manifest/tree/typed-operation/session state, but never the checked ECFE,
  // ECFX, ECVA, source pin/accounting/manifest or immutable birth/mode records.
  // Tx/attempt checks reject stale handles; they are NOT mutation tracking.
  class PublicationValidation final {
   public:
    PublicationValidation(PublicationValidation &&) noexcept;
    PublicationValidation(const PublicationValidation &) = delete;
    PublicationValidation &operator=(const PublicationValidation &) = delete;
    PublicationValidation &operator=(PublicationValidation &&) = delete;
    ~PublicationValidation() = default;
    const EcFileExecutionRecord &record() const { return observed_.record; }
    const storage::EcRmwPlan &plan() const { return *observed_.plan; }
    bool validFor(const Tx &txn) const {
      return txn_ == &txn && attempt_ == txn.attempt() && !txn.poisoned() && !consumed_;
    }

   private:
    friend class EcFileExecutionCatalog;
    PublicationValidation(Tx &, const EcOwner &, EcFileExecutionObservation);
    Tx *txn_;
    uint64_t attempt_;
    EcOwner owner_;
    EcFileExecutionObservation observed_;
    bool consumed_ = false;
  };
  static CoTryTask<PublicationValidation> preparePublicationValidation(Tx &,
                                                                       const EcOwner &,
                                                                       const EcRmwPublicationProof &,
                                                                       EcFileExecutionOwner);
  static CoTryTask<Void> finishValidatedPublication(Tx &, PublicationValidation &&, const EcTreeRoot &);
  // Only the actual data verifier can persist pre-T0 verified bytes. Ordinary
  // caller receipts/worker MACs cannot enter this path.
  static CoTryTask<EcV2DrainRecord> startPublishClosing(Tx &,
                                                        const EcOwner &,
                                                        const EcObjectRef &,
                                                        const Uuid &child,
                                                        const EcManifest &,
                                                        const storage::EcSha256 &,
                                                        const Uuid &authority,
                                                        const Uuid &revocation);
};
}  // namespace hf3fs::meta::server
