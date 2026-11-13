#pragma once
#include "fbs/meta/EcFileMutation.h"
#include "fbs/meta/EcV2Repair.h"

namespace hf3fs::meta {
enum class EcFileRepairMode : uint8_t { CentralSerial = 1, ClientPipeline = 2, HelperChain = 3, HelperChainDirect = 4 };
enum class EcFileRepairState : uint8_t { Planned = 1, Published = 2, Aborted = 3 };
struct EcFileRepairIntent {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedRoot, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedSequence, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(replacementMask, uint16_t{});
  SERDE_STRUCT_FIELD(mode, EcFileRepairMode::CentralSerial);
  SERDE_STRUCT_FIELD(selection, EcV2RepairSelection{});
  SERDE_STRUCT_FIELD(nodeIds, (std::array<Uuid, 16>{}));
};
struct EcFileRepairRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(intent, EcFileRepairIntent{});
  SERDE_STRUCT_FIELD(state, EcFileRepairState::Planned);
  SERDE_STRUCT_FIELD(child, EcFileChildRecord{});
};
struct EcFileRepairChildIndex {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
};
Result<Void> validateEcFileRepairIntent(const EcFileRepairIntent &);
}  // namespace hf3fs::meta
