#pragma once

#include "meta/store/EcFileTreeCatalog.h"
#include "meta/store/EcV2DrainCatalog.h"

namespace hf3fs::meta::server {

// Internal metadata only. Never place this source snapshot or its eventual
// ReadBlock bearer in a WRITE-only caller's response.
struct EcTreeSourcePinIntent {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(parent, Uuid::zero());
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(pin, Uuid::zero());
  SERDE_STRUCT_FIELD(root, Uuid::zero());
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
  SERDE_STRUCT_FIELD(lengthAtPlan, uint64_t{});
  SERDE_STRUCT_FIELD(slot, EcTreeSlot{});
};
enum class EcTreeSourcePinState : uint8_t { Active = 1, Closing = 2, Released = 3 };
struct EcTreeSourcePinRecord {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(intent, EcTreeSourcePinIntent{});
  SERDE_STRUCT_FIELD(manifest, EcManifest{});
  SERDE_STRUCT_FIELD(allocations, EcV2AllocationBindings{});
  SERDE_STRUCT_FIELD(endpoints, EcV2OperationEndpoints{});
  SERDE_STRUCT_FIELD(state, EcTreeSourcePinState::Active);
  SERDE_STRUCT_FIELD(issuanceSequence, uint64_t{});
  SERDE_STRUCT_FIELD(drain, (std::optional<EcV2DrainRecord>{}));
};
struct EcTreeSourceAllocationRecord {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(registered, uint64_t{});
  SERDE_STRUCT_FIELD(released, uint64_t{});
  SERDE_STRUCT_FIELD(active, uint64_t{});
};

// Proves a checked metadata observation in the supplied transaction, NOT that
// it has committed, nor a data seal/permission. The trusted W2 owner checks the
// WRITE session/child in this same txn. The internal issuer must commit its
// reserveIssuance transaction successfully before signing any worker bearer.
class EcTreeSourcePinEvidence final {
 public:
  const EcTreeSourcePinRecord &record() const { return record_; }

 private:
  friend class EcTreeSourcePinCatalog;
  explicit EcTreeSourcePinEvidence(EcTreeSourcePinRecord record)
      : record_(std::move(record)) {}
  EcTreeSourcePinRecord record_;
};
class EcTreeSourcePinCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  // Reopen and read W0 inside this exact txn; never accept a context from a
  // different txn. Fresh Data pin only; Zero must not call this factory.
  static CoTryTask<EcTreeSourcePinEvidence> pinExactSource(Tx &, const EcTreeSourcePinIntent &);
  static CoTryTask<EcTreeSourcePinRecord> query(Tx &, const EcTreeSourcePinIntent &);
  static CoTryTask<EcTreeSourcePinEvidence> reserveIssuance(Tx &, const EcTreeSourcePinIntent &);
  // Commit T0 before issuing controls; do every Storage call outside txn.
  // Any semantic error requires discarding the complete caller transaction.
  static CoTryTask<EcV2DrainRecord> startClosing(Tx &,
                                                 const EcTreeSourcePinIntent &,
                                                 const Uuid &authority,
                                                 const Uuid &revocation);
  static CoTryTask<EcV2DrainRecord> recordAck(Tx &,
                                              const EcTreeSourcePinIntent &,
                                              size_t index,
                                              const storage::EcScopeControlKey &,
                                              const storage::EcScopeControlRequest &,
                                              const storage::EcScopeControlAck &);
  static CoTryTask<EcV2DrainRecord> recordRetirement(Tx &, const EcTreeSourcePinIntent &, size_t index,
                                                     const storage::EcScopeControlKey &);
  static CoTryTask<EcTreeSourcePinRecord> finishRelease(Tx &,
                                                        const EcTreeSourcePinIntent &,
                                                        const storage::EcScopeControlKey &);
  // Additional normal conflict read in the physical claim gate. It does not
  // enroll mode4 in mode3 GC; it forbids ignoring a retained source scope.
  static CoTryTask<Void> requireUnheld(kv::IReadWriteTransaction &,
                                       const EcObjectRef &,
                                       const storage::EcFragmentIdentity &);
};
}  // namespace hf3fs::meta::server
