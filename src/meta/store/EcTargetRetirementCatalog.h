#pragma once

#include "common/kv/ITransaction.h"
#include "fbs/meta/EcTargetRetirement.h"

namespace hf3fs::meta::server {
struct EcTargetRetirementCompletion {
  SERDE_STRUCT_FIELD(request, storage::EcTargetRetirementRequest{});
  SERDE_STRUCT_FIELD(observation, storage::EcTargetRetirementObservation{});
  SERDE_STRUCT_FIELD(digest, storage::EcSha256{});
};
struct EcTargetRetirementRecord {
  SERDE_STRUCT_FIELD(version, kEcTargetRetirementCatalogVersion);
  SERDE_STRUCT_FIELD(intent, EcTargetRetirementIntent{});
  SERDE_STRUCT_FIELD(completion, (std::optional<EcTargetRetirementCompletion>{}));
};

// No network, retry, cache or commit: use the caller's single transaction and
// budget. Every lookup is a normal conflict read, including absence. The first
// accepted intent permanently closes future output/helper assignment; the first
// complete exchange is immutable and reverified whenever referenced.
class EcTargetRetirementCatalog {
 public:
  static constexpr size_t kMaximumRecordBytes = 2048;
  static Result<Void> validIntent(const EcTargetRetirementIntent &);
  static CoTryTask<EcTargetRetirementRecord> prepare(kv::IReadWriteTransaction &, const EcTargetRetirementIntent &);
  static CoTryTask<EcTargetRetirementRecord> get(kv::IReadWriteTransaction &, const EcTargetRetirementIntent &);
  static CoTryTask<EcTargetRetirementRecord> recordCompletion(kv::IReadWriteTransaction &,
                                                            const EcTargetRetirementIntent &,
                                                            const storage::EcTargetRetirementRequest &,
                                                            const storage::EcTargetRetirementObservation &,
                                                            const storage::EcScopeControlKey &);
  static CoTryTask<Void> requireAssignable(kv::IReadWriteTransaction &, const EcV2PhysicalEndpoint &);
  static CoTryTask<std::optional<EcTargetRetirementRef>> findCompleted(kv::IReadWriteTransaction &,
                                                                    const EcV2PhysicalEndpoint &,
                                                                    const Uuid &authority,
                                                                    const storage::EcScopeControlKey &);
  // Integrity-only historical lookup for callers without a control key. This
  // does not admit a new completion or authorize a release: admission/T2/claim
  // must separately use verifyReference with the trusted control key. This relies
  // on recordCompletion as the only trusted-store writer and a previously
  // pinned digest; it is not independent authentication of a new exchange.
  static CoTryTask<Void> verifyStoredReference(kv::IReadWriteTransaction &,
                                              const EcV2PhysicalEndpoint &,
                                              const Uuid &authority,
                                              const EcTargetRetirementRef &);
  static CoTryTask<Void> verifyReference(kv::IReadWriteTransaction &,
                                        const EcV2PhysicalEndpoint &,
                                        const Uuid &authority,
                                        const EcTargetRetirementRef &,
                                        const storage::EcScopeControlKey &);
  // Return the original, fully verified exchange for this exact retained ref.
  // Never substitute a later target/retirement or reconstruct a new C request.
  static CoTryTask<EcTargetRetirementCompletion> getVerifiedCompletion(kv::IReadWriteTransaction &,
                                                                      const EcV2PhysicalEndpoint &,
                                                                      const Uuid &authority,
                                                                      const EcTargetRetirementRef &,
                                                                      const storage::EcScopeControlKey &);
};
}  // namespace hf3fs::meta::server
