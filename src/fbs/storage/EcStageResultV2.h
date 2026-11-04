#pragma once

#include "fbs/storage/EcAuthorizedV2.h"

namespace hf3fs::storage {

// Response identity only. Transport and server trust remain prerequisites;
// neither this value nor an expired data grant is a GC or drain certificate.
struct EcFragmentReceiptV2 {
  SERDE_STRUCT_FIELD(version, kEcGrantVersionV2);
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(engineUuid, Uuid::zero());
  SERDE_STRUCT_FIELD(targetIncarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(length, uint32_t{});
  SERDE_STRUCT_FIELD(crc32c, uint32_t{});
  SERDE_STRUCT_FIELD(integrityRoot, EcSha256{});
};

struct EcStageStateV2 {
  SERDE_STRUCT_FIELD(receipt, EcFragmentReceiptV2{});
  // 1 Active, 2 Sealed, 3 Aborted. Query alone never confirms persistence.
  SERDE_STRUCT_FIELD(state, uint8_t{});
  SERDE_STRUCT_FIELD(prefixBytes, uint32_t{});
  SERDE_STRUCT_FIELD(pendingBlock, false);
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(needsReconcile, true);
};

struct EcReadBlockResultV2 {
  SERDE_STRUCT_FIELD(receipt, EcFragmentReceiptV2{});
  SERDE_STRUCT_FIELD(blockIndex, uint32_t{});
  SERDE_STRUCT_FIELD(payload, EcSlicePayloadV2{});
};
struct EcReadBlockV2Rsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(result, (Result<EcReadBlockResultV2>{makeError(StorageClientCode::kNotInitialized)}));
};
struct EcStageV2Rsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(result, (Result<EcStageStateV2>{makeError(StorageClientCode::kNotInitialized)}));
};
struct EcSealStageV2Rsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  // Success is a fresh seal barrier plus trusted-descriptor verification.
  SERDE_STRUCT_FIELD(result, (Result<EcFragmentReceiptV2>{makeError(StorageClientCode::kNotInitialized)}));
};

static_assert(serde::Serializable<EcFragmentReceiptV2>);
static_assert(serde::Serializable<EcStageStateV2>);
static_assert(serde::Serializable<EcReadBlockV2Rsp>);
static_assert(serde::Serializable<EcStageV2Rsp>);
static_assert(serde::Serializable<EcSealStageV2Rsp>);
}  // namespace hf3fs::storage
