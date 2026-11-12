#pragma once

#include <limits>
#include <set>

#include "fbs/meta/EcFileTruncate.h"

namespace hf3fs::meta {
// Never expose EcFileTruncateRecord::tail to a WRITE-only caller: that internal
// record contains the captured source SHA and exact source selection.
struct EcFileTruncateObservation {
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(state, EcFileTruncateState::Planned);
  SERDE_STRUCT_FIELD(fencedRoot, EcTreeRoot{});
  SERDE_STRUCT_FIELD(tailRequired, false);
  SERDE_STRUCT_FIELD(publishedRoot, (std::optional<EcTreeRoot>{}));
  SERDE_STRUCT_FIELD(outputDrained, false);
  SERDE_STRUCT_FIELD(sourceReleased, false);
};
struct EcFileTruncateProgress {
  SERDE_STRUCT_FIELD(intent, EcFileTruncateIntent{});
  // Absence is an observation, not proof that a previous Begin did not commit.
  SERDE_STRUCT_FIELD(observed, (std::optional<EcFileTruncateObservation>{}));
};
inline Result<Void> validateEcFileTruncateIntent(const EcFileTruncateIntent &i) {
  if (i.version != kEcFileTruncateVersion || i.action != EcFileStructuralAction::Truncate ||
      i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() || i.object.inode > InodeId::normalMax() ||
      i.owner.client.is_nil() || i.session.is_nil() || i.operation.is_nil() || i.child.is_nil() || i.plan.is_nil() ||
      i.sourcePin.is_nil() || !i.expectedSequence || i.expectedSequence >= std::numeric_limits<uint64_t>::max() - 1 ||
      !i.expectedEpoch || i.expectedEpoch == std::numeric_limits<uint64_t>::max())
    return makeError(StatusCode::kInvalidArg, "invalid fixed truncate identity/CAS");
  std::set<Uuid> ids{i.operation, i.child, i.plan, i.sourcePin};
  if (ids.size() != 4) return makeError(StatusCode::kInvalidArg, "truncate protocol IDs overlap");
  for (const auto &id : i.nodeIds)
    if (id.is_nil() || !ids.insert(id).second) return makeError(StatusCode::kInvalidArg, "truncate node IDs overlap");
  return Void{};
}
}  // namespace hf3fs::meta
