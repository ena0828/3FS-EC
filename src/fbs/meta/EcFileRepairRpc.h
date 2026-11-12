#pragma once
#include "EcFileRepair.h"
#include "fbs/storage/EcRmwRpc.h"

namespace hf3fs::meta {
enum class EcFileRepairAdvance : uint8_t { Prepare = 1, Publish = 2 };
struct EcFileRepairAccess {
  SERDE_STRUCT_FIELD(plan, storage::EcRepairPlanInput{});
  SERDE_STRUCT_FIELD(sources, EcV2AllocationBindings{});
  SERDE_STRUCT_FIELD(targets, EcV2AllocationBindings{});
  SERDE_STRUCT_FIELD(reads, (std::array<storage::EcCapabilityV2, 12>{}));
  SERDE_STRUCT_FIELD(pipelineReads, (std::array<storage::EcCapabilityV2, 10>{}));
  SERDE_STRUCT_FIELD(writes, (std::array<storage::EcCapabilityV2, 12>{}));
  SERDE_STRUCT_FIELD(helpers, (std::optional<std::array<storage::EcHelperCapability, 10>>{}));
};
struct EcFileRepairProgress {
  SERDE_STRUCT_FIELD(record, (std::optional<EcFileRepairRecord>{}));
  SERDE_STRUCT_FIELD(outputDrained, false);
  SERDE_STRUCT_FIELD(outputClosing, false);
  SERDE_STRUCT_FIELD(sourceReleased, false);
};
}  // namespace hf3fs::meta
