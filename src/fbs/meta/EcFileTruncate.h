#pragma once

#include "fbs/meta/EcFileMutation.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcFileTruncateVersion = 1;
enum class EcFileStructuralAction : uint8_t { Truncate = 1 };
enum class EcFileTruncateState : uint8_t { Planned = 1, Published = 2, Aborted = 3 };
// All UUIDs are fixed before the first request, including an unknown commit.
struct EcFileTruncateIntent {
  SERDE_STRUCT_FIELD(version, kEcFileTruncateVersion);
  SERDE_STRUCT_FIELD(action, EcFileStructuralAction::Truncate);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedRoot, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedSequence, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(expectedLength, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(plan, Uuid::zero());
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(nodeIds, (std::array<Uuid, 16>{}));
};
struct EcFileTruncateRecord {
  SERDE_STRUCT_FIELD(version, kEcFileTruncateVersion);
  SERDE_STRUCT_FIELD(intent, EcFileTruncateIntent{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(state, EcFileTruncateState::Planned);
  // B0 has already fenced old writers, but has not changed visible EOF/data.
  SERDE_STRUCT_FIELD(fencedRoot, EcTreeRoot{});
  SERDE_STRUCT_FIELD(tail, (std::optional<EcFileChildRecord>{}));
  SERDE_STRUCT_FIELD(publishedRoot, (std::optional<EcTreeRoot>{}));
};
struct EcFileStructuralGate {
  SERDE_STRUCT_FIELD(version, kEcFileTruncateVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
  SERDE_STRUCT_FIELD(active, true);
};
struct EcFileTruncateChildIndex {
  SERDE_STRUCT_FIELD(version, kEcFileTruncateVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
};
}  // namespace hf3fs::meta
