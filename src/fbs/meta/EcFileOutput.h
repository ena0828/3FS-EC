#pragma once

#include "fbs/meta/EcV2Lifecycle.h"

namespace hf3fs::meta {
enum class EcFileOutputOwner : uint8_t { Pwrite = 1, TruncateTail = 2, Repair = 3 };
enum class EcFileOutputState : uint8_t { Reserved = 1, Bound = 2, Closing = 3, Drained = 4, Published = 5, Aborted = 6 };

struct EcFileOutputIdentity {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(parent, Uuid::zero());
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(ownerKind, EcFileOutputOwner::Pwrite);

 public:
  Result<Void> valid() const {
    if (!object.inode.u64() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        object.incarnation.is_nil() || owner.client.is_nil() || parent.is_nil() || child.is_nil() ||
        (ownerKind != EcFileOutputOwner::Pwrite && ownerKind != EcFileOutputOwner::TruncateTail &&
         ownerKind != EcFileOutputOwner::Repair))
      return makeError(StatusCode::kInvalidArg, "fixed file output identity is required");
    return Void{};
  }
};

// Metadata projection only. Never serialize the stored signed requests/ACKs,
// capability envelopes, source manifests, or keys into this public response.
struct EcFileOutputDrain {
  SERDE_STRUCT_FIELD(version, uint16_t{});
  SERDE_STRUCT_FIELD(identity, EcV2DrainIdentity{});
  SERDE_STRUCT_FIELD(state, EcV2DrainState::Closing);
  SERDE_STRUCT_FIELD(terminalUse, EcV2DrainUse::AckOnly);
  SERDE_STRUCT_FIELD(ackMask, uint32_t{});
  SERDE_STRUCT_FIELD(retirements, (std::array<std::optional<EcTargetRetirementRef>, 24>{}));
  SERDE_STRUCT_FIELD(recordDigest, storage::EcSha256{});
};

struct EcFileOutputObservation {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(identity, EcFileOutputIdentity{});
  SERDE_STRUCT_FIELD(state, EcFileOutputState::Reserved);
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(plan, Uuid::zero());
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(planDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(issuanceSequence, uint64_t{});
  SERDE_STRUCT_FIELD(candidates, (std::array<EcV2ReservedAllocation, 12>{}));
  SERDE_STRUCT_FIELD(allocations, (std::optional<EcV2AllocationBindings>{}));
  SERDE_STRUCT_FIELD(endpoints, EcV2OperationEndpoints{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(drain, (std::optional<EcFileOutputDrain>{}));
  SERDE_STRUCT_FIELD(recordDigest, storage::EcSha256{});
  // Confirms only the stored output-scope T2. It says nothing about whether a
  // candidate ever materialized, source debt, or physical deletion/reclamation.
  SERDE_STRUCT_FIELD(outputT2Confirmed, false);
  SERDE_STRUCT_FIELD(physicalReclamationConfirmed, false);
};
}  // namespace hf3fs::meta
