#pragma once

#include "fbs/meta/EcV2Lifecycle.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcGcCatalogVersion = 1;
inline constexpr uint16_t kEcGcTrackedObjectMode = 3;

// Enrollment is written only in the transaction which first creates the object.
// An existing mode-2 object can never acquire an empty protection history.
struct EcGcEnrollment {
  SERDE_STRUCT_FIELD(version, kEcGcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(creator, EcOwner{});
  SERDE_STRUCT_FIELD(createRequest, Uuid::zero());
};

struct EcGcProtectionSlot {
  SERDE_STRUCT_FIELD(allocation, EcV2ReservedAllocation{});
};
}  // namespace hf3fs::meta

template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::meta::EcGcProtectionSlot, 24>> {
  static void serialize(const std::array<meta::EcGcProtectionSlot, 24> &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(24);
  }
  static Result<Void> deserialize(std::array<meta::EcGcProtectionSlot, 24> &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 24) return makeError(StatusCode::kInvalidFormat, "invalid fixed GC protection extent");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 24) return makeError(StatusCode::kInvalidFormat, "invalid fixed GC protection extent");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
enum class EcGcScopeState : uint8_t { Active = 1, Released = 2 };

struct EcGcScopeRecord {
  SERDE_STRUCT_FIELD(version, kEcGcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(kind, storage::EcGrantScope::ReadPin);
  SERDE_STRUCT_FIELD(scopeId, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(endpoints, EcV2OperationEndpoints{});
  SERDE_STRUCT_FIELD(count, uint16_t{});
  SERDE_STRUCT_FIELD(slots, (std::array<EcGcProtectionSlot, 24>{}));
  SERDE_STRUCT_FIELD(state, EcGcScopeState::Active);
  // Hash of the full persisted, authenticated terminal ECVD record.
  SERDE_STRUCT_FIELD(releaseEvidence, storage::EcSha256{});
};

struct EcGcAllocationRecord {
  SERDE_STRUCT_FIELD(version, kEcGcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(allocation, EcV2ReservedAllocation{});
  SERDE_STRUCT_FIELD(registered, uint64_t{});
  SERDE_STRUCT_FIELD(released, uint64_t{});
  SERDE_STRUCT_FIELD(active, uint64_t{});
  // Ordered SHA256 history accumulator; permanent ECGP/ECGS remain available.
  SERDE_STRUCT_FIELD(releaseHistory, storage::EcSha256{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
};

struct EcGcMembership {
  SERDE_STRUCT_FIELD(version, kEcGcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(kind, storage::EcGrantScope::ReadPin);
  SERDE_STRUCT_FIELD(scopeId, Uuid::zero());
  SERDE_STRUCT_FIELD(state, EcGcScopeState::Active);
  SERDE_STRUCT_FIELD(releaseEvidence, storage::EcSha256{});
};

// A committed Meta claim is an irreversible eligibility decision, not a Storage
// deletion receipt or a bearer capability. The first implementation never turns
// Missing into Deleted and never deletes these records or the source evidence.
struct EcGcClaim {
  SERDE_STRUCT_FIELD(version, kEcGcCatalogVersion);
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(enrollment, EcGcEnrollment{});
  SERDE_STRUCT_FIELD(allocation, EcV2AllocationBinding{});
  SERDE_STRUCT_FIELD(registeredScopes, uint64_t{});
  SERDE_STRUCT_FIELD(releasedScopes, uint64_t{});
  SERDE_STRUCT_FIELD(releaseHistory, storage::EcSha256{});
  SERDE_STRUCT_FIELD(originDrainEvidence, storage::EcSha256{});
  SERDE_STRUCT_FIELD(eligibilityDigest, storage::EcSha256{});
};
}  // namespace hf3fs::meta
