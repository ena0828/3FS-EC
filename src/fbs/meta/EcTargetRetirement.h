#pragma once

#include "fbs/meta/EcV2.h"
#include "fbs/storage/EcTargetRetirementControl.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcTargetRetirementCatalogVersion = 1;

// An immutable completion reference, not a bearer capability or a scope ACK.
struct EcTargetRetirementRef {
  SERDE_STRUCT_FIELD(retirementId, Uuid::zero());
  SERDE_STRUCT_FIELD(completionDigest, storage::EcSha256{});

 public:
  bool operator==(const EcTargetRetirementRef &) const = default;
};

struct EcTargetRetirementIntent {
  SERDE_STRUCT_FIELD(version, kEcTargetRetirementCatalogVersion);
  SERDE_STRUCT_FIELD(endpoint, EcV2PhysicalEndpoint{});
  SERDE_STRUCT_FIELD(authority, Uuid::zero());
  SERDE_STRUCT_FIELD(retirementId, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
};

enum class EcTargetRetirementStage : uint8_t { Prepared = 1, Completed = 2 };
}  // namespace hf3fs::meta
