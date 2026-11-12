#pragma once

#include "fbs/meta/EcFileMutation.h"
#include "storage/ec_rmw/EcRmwWire.h"

namespace hf3fs::meta {
// Public progress deliberately omits the old source manifest, old SHA and all
// source ReadBlock capabilities. WRITE-only callers upload only their patch.
struct EcFileChildProgress {
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(plan, Uuid::zero());
  SERDE_STRUCT_FIELD(state, EcFileChildState::Planned);
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(patchOffset, uint32_t{});
  SERDE_STRUCT_FIELD(patchLength, uint32_t{});
  SERDE_STRUCT_FIELD(targetLogicalLength, uint64_t{});
};
struct EcFileWorkerAccess {
  SERDE_STRUCT_FIELD(worker, EcV2PhysicalEndpoint{});
  SERDE_STRUCT_FIELD(planDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(grant, storage::EcRmwGrant{});
};
enum class EcFileAdvanceAction : uint8_t { Plan = 1, Publish = 2, SealPrefix = 3, CleanupChild = 4 };
// ClosedLogical only fixes the acknowledged prefix. It does not imply that
// the independent output/source drain debts have been released.
struct EcFilePwriteProgress {
  SERDE_STRUCT_FIELD(parent, (std::optional<EcFileMutationRecord>{}));
  SERDE_STRUCT_FIELD(child, (std::optional<EcFileChildProgress>{}));
  SERDE_STRUCT_FIELD(outputDrained, false);
  SERDE_STRUCT_FIELD(sourceReleased, false);
  SERDE_STRUCT_FIELD(worker, (std::optional<EcFileWorkerAccess>{}));
};
}  // namespace hf3fs::meta
