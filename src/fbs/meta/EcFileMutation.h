#pragma once

#include "fbs/meta/EcFileTree.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcFileMutationVersion = 1;
inline constexpr uint8_t kEcSessionRead = 1;
inline constexpr uint8_t kEcSessionWrite = 2;
inline constexpr uint64_t kEcPwriteMaxBytes = 32u << 20;

enum class EcFileSessionState : uint8_t { Open = 1, Closing = 2, Closed = 3 };
enum class EcFileMutationState : uint8_t { Open = 1, ClosedLogical = 2 };
enum class EcFileChildState : uint8_t { Planned = 1, Published = 2, Fenced = 3 };

struct EcFileOpenIntent {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(openRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(rights, uint8_t{});
};
struct EcFileSessionRecord {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(intent, EcFileOpenIntent{});
  SERDE_STRUCT_FIELD(state, EcFileSessionState::Open);
  SERDE_STRUCT_FIELD(acceptedSequence, uint64_t{});
  SERDE_STRUCT_FIELD(activeParent, Uuid::zero());
  SERDE_STRUCT_FIELD(activeReadRanges, uint64_t{});
  SERDE_STRUCT_FIELD(activeStructural, Uuid::zero());
};
struct EcFileSessionIndex {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(openCount, uint64_t{});
};
struct EcFilePwriteIntent {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(offset, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(inputSha256, storage::EcSha256{});
};
struct EcFileMutationRecord {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(intent, EcFilePwriteIntent{});
  SERDE_STRUCT_FIELD(state, EcFileMutationState::Open);
  SERDE_STRUCT_FIELD(sessionSequence, uint64_t{});
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
  SERDE_STRUCT_FIELD(confirmedPrefix, uint64_t{});
  SERDE_STRUCT_FIELD(activeChild, Uuid::zero());
  // A logical fence is not a physical abort, release, or allocation GC proof.
  SERDE_STRUCT_FIELD(fencedChild, Uuid::zero());
};
struct EcFileChildIntent {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(parent, Uuid::zero());
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(plan, Uuid::zero());
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedPrefix, uint64_t{});
  SERDE_STRUCT_FIELD(patchSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(nodeIds, (std::array<Uuid, 16>{}));
};
struct EcFileChildRecord {
  SERDE_STRUCT_FIELD(version, kEcFileMutationVersion);
  SERDE_STRUCT_FIELD(intent, EcFileChildIntent{});
  SERDE_STRUCT_FIELD(state, EcFileChildState::Planned);
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRoot, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceSequence, uint64_t{});
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
  SERDE_STRUCT_FIELD(lengthAtPlan, uint64_t{});
  SERDE_STRUCT_FIELD(source, EcTreeSlot{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(patchOffset, uint32_t{});
  SERDE_STRUCT_FIELD(patchLength, uint32_t{});
  SERDE_STRUCT_FIELD(targetLogicalLength, uint32_t{});
  SERDE_STRUCT_FIELD(targetGeneration, uint64_t{});
  SERDE_STRUCT_FIELD(targetRevision, uint64_t{});
  SERDE_STRUCT_FIELD(publishedRoot, (std::optional<EcTreeRoot>{}));
};
}  // namespace hf3fs::meta
