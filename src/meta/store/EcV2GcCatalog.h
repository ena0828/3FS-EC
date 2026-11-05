#pragma once

#include "fbs/meta/EcV2Gc.h"
#include "meta/store/EcV2DrainCatalog.h"

namespace hf3fs::meta::server {

// Internal transaction core. Every read is a conflict read. The caller discards
// the transaction on error and commits with fixed IDs; MaybeCommitted never
// authorizes removal. Only mode-3 objects tracked from their creation qualify.
// This API neither authenticates a remote caller nor sends Storage deletion RPCs.
class EcV2GcCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  static CoTryTask<Void> validateEnrollment(Transaction &, const EcV2ObjectMode &);
  static CoTryTask<Void> protectOperation(Transaction &, const EcV2Reservation &);
  static CoTryTask<Void> protectRead(Transaction &, const EcV2PinSnapshot &);
  static CoTryTask<Void> requireProtectedScope(Transaction &,
                                               const EcObjectRef &,
                                               storage::EcGrantScope,
                                               const Uuid &,
                                               const EcOwner &);
  // Called in the same T2 transaction after the legacy reference and ECVD state
  // changed. Independently rechecks every signed ACK and durable terminal state.
  static CoTryTask<Void> finishScope(Transaction &,
                                     const EcObjectRef &,
                                     storage::EcGrantScope,
                                     const Uuid &,
                                     const EcOwner &,
                                     const storage::EcScopeControlKey &);
  static CoTryTask<EcGcClaim> claim(Transaction &,
                                    const EcObjectRef &,
                                    const storage::EcFragmentIdentity &,
                                    const Uuid &claimId,
                                    const storage::EcScopeControlKey &);
  static CoTryTask<std::optional<EcGcClaim>> getClaim(Transaction &,
                                                      const EcObjectRef &,
                                                      const storage::EcFragmentIdentity &);
  static CoTryTask<EcGcAllocationRecord> getAllocation(Transaction &,
                                                       const EcObjectRef &,
                                                       const storage::EcFragmentIdentity &);

 private:
  friend class EcV2BindingCatalog;
  // Not a migration API: caller has just established that object and mode were
  // absent, and writes object, mode and enrollment in this same transaction.
  static CoTryTask<Void> enrollBirth(Transaction &, const EcV2ObjectMode &);
};
}  // namespace hf3fs::meta::server
