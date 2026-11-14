#pragma once

#include <string_view>

#include "fbs/meta/EcFileOutput.h"
#include "fbs/meta/EcFileTree.h"

namespace hf3fs::meta {
enum class EcFileOutputResolutionKind : uint8_t {
  NoIssuanceAfterClose = 1,
  NeverBoundAfterClose = 2,
};

// A permanent Meta qualification for these exact original reservations. It is
// neither a Storage absent-stage receipt nor evidence of an application ledger
// debit. Both kinds retain the original output T2 and source closure contract.
struct EcFileOutputResolution {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(identity, EcFileOutputIdentity{});
  SERDE_STRUCT_FIELD(resolutionId, Uuid::zero());
  SERDE_STRUCT_FIELD(confirmingClientNamespace, Uuid::zero());
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(childEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(issuanceSequence, uint64_t{});
  SERDE_STRUCT_FIELD(kind, EcFileOutputResolutionKind::NoIssuanceAfterClose);
  SERDE_STRUCT_FIELD(candidates, (std::array<EcV2ReservedAllocation, 12>{}));
  SERDE_STRUCT_FIELD(candidateDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(executionDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(outputClosureDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(sourceClosureDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(outputClosure, EcFileOutputDrain{});
  SERDE_STRUCT_FIELD(sourceKind, EcTreeSlotKind::Zero);
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceClosure, (std::optional<EcFileOutputDrain>{}));
  SERDE_STRUCT_FIELD(candidateReservationsReleaseEligible, false);
  SERDE_STRUCT_FIELD(collected, false);
  SERDE_STRUCT_FIELD(physicalReclamationConfirmed, false);

 public:
  Result<Void> valid() const;
};

// Canonical, domain-separated digests; no signature or bearer authority.
Result<storage::EcSha256> ecFileOutputResolutionDigest(std::string_view domain, std::string_view bytes);
Result<storage::EcSha256> ecFileOutputCandidateDigest(const std::array<EcV2ReservedAllocation, 12> &);
Result<storage::EcSha256> ecFileOutputZeroSourceDigest(const EcFileOutputIdentity &, const Uuid &birth,
                                                    uint64_t epoch);
}  // namespace hf3fs::meta
