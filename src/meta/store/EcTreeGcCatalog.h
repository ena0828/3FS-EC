#pragma once
#include "EcFileLifecycleCatalog.h"
#include "EcV2GcCatalog.h"
#include "EcTargetRetirementCatalog.h"
#include "fbs/meta/EcTreeGc.h"
#include "fbs/meta/Service.h"
namespace hf3fs::meta::server {
struct EcTreeReclaimObservation {
  AdvanceEcTreeReclaimRsp response;
  bool needsCommit = false;
};
// Internal-only full terminal source for a new local absence witness. Nothing
// here authorizes a Storage mutation until a fresh committed read is signed.
struct EcGcBoundClosure {
  EcGcClaim claim;
  EcV2DrainRecord drain;
  uint16_t endpointIndex = 0;
  std::optional<EcTargetRetirementCompletion> retirement;
};
// Mode4 only. No old object enrollment, implicit retirement, TTL release, or
// snapshot CAS. Every write and its permanent evidence commits atomically.
class EcTreeGcCatalog {
 public:
  using Tx = kv::IReadWriteTransaction;
  static CoTryTask<bool> isTree(Tx &, const EcObjectRef &);
  static CoTryTask<EcRevisionRetirementRsp> retire(Tx &, const EcRevisionRetirementReq &, bool query = false);
  static CoTryTask<EcTreeReclaimProgress> reclaim(Tx &, const EcObjectRef &, const Uuid &node);
  // Same transaction accounts the permanent request lookup, bounded core work,
  // complete public identity hints and result write. Authentication stays at RPC.
  static CoTryTask<EcTreeReclaimObservation> reclaimRequest(Tx &, const AdvanceEcTreeReclaimReq &, bool readonly);
  static CoTryTask<std::optional<EcGcClaim>> getClaim(Tx &, const EcObjectRef &, const storage::EcFragmentIdentity &);
  static CoTryTask<EcGcClaim> claim(Tx &,
                                    const EcObjectRef &,
                                    const storage::EcFragmentIdentity &,
                                    const Uuid &,
                                    const storage::EcScopeControlKey &);
  static CoTryTask<EcGcBoundClosure> closureForClaim(Tx &, const EcObjectRef &,
                                                    const storage::EcFragmentIdentity &, const Uuid &claimId,
                                                    const storage::EcScopeControlKey &);
};
}  // namespace hf3fs::meta::server
