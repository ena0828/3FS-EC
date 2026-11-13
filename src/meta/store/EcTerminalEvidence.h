#pragma once

#include "meta/store/EcTargetRetirementCatalog.h"
#include "meta/store/EcV2DrainCatalog.h"

namespace hf3fs::meta::server {
enum class EcTerminalPurpose { Publication, ReadRelease, FencedAbort };
inline bool ecTerminalAt(const EcV2DrainRecord &r, size_t i) {
  return r.observations[i].has_value() || r.retirements[i].has_value();
}
inline bool ecAllTerminal(const EcV2DrainRecord &r) {
  for (size_t i = 0; i < r.identity.endpoints.count; ++i)
    if (!ecTerminalAt(r, i)) return false;
  return true;
}
// These functions use the caller's raw/budget transaction. No private cache or
// additional transaction is permitted. Callers establish the actual read T0 or
// typed abort fence before attaching; this union can never authorize publish.
// Historical integrity only: the immutable completion was authenticated before
// T1 and its complete digest is pinned. This is not a fresh/offline MAC check.
CoTryTask<Void> verifyEcStoredRetirementReferences(kv::IReadWriteTransaction &, const EcV2DrainRecord &);
CoTryTask<Void> verifyEcRetirementReferences(kv::IReadWriteTransaction &,
                                            const EcV2DrainRecord &,
                                            const storage::EcScopeControlKey &);
CoTryTask<Void> verifyEcTerminalEvidence(kv::IReadWriteTransaction &,
                                       const EcV2DrainRecord &,
                                       const storage::EcScopeControlKey &,
                                       EcTerminalPurpose);
CoTryTask<bool> attachEcCompletedRetirement(kv::IReadWriteTransaction &,
                                          EcV2DrainRecord &,
                                          size_t index,
                                          EcV2DrainUse,
                                          const storage::EcScopeControlKey &);
}  // namespace hf3fs::meta::server
