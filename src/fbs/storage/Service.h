#pragma once

#include "common/serde/Service.h"
#include "fbs/storage/Common.h"
#include "fbs/storage/Ec.h"
#include "fbs/storage/EcAuthorized.h"
#include "fbs/storage/EcScopeControl.h"
#include "fbs/storage/EcStageResultV2.h"

namespace hf3fs::storage {

SERDE_SERVICE(StorageSerde, 3) {
  SERDE_SERVICE_METHOD(batchRead, 1, BatchReadReq, BatchReadRsp);
  SERDE_SERVICE_METHOD(write, 2, WriteReq, WriteRsp);
  SERDE_SERVICE_METHOD(update, 3, UpdateReq, UpdateRsp);
  SERDE_SERVICE_METHOD(queryLastChunk, 5, QueryLastChunkReq, QueryLastChunkRsp);
  SERDE_SERVICE_METHOD(truncateChunks, 6, TruncateChunksReq, TruncateChunksRsp);
  SERDE_SERVICE_METHOD(removeChunks, 7, RemoveChunksReq, RemoveChunksRsp);
  SERDE_SERVICE_METHOD(syncStart, 8, SyncStartReq, TargetSyncInfo);
  SERDE_SERVICE_METHOD(syncDone, 9, SyncDoneReq, SyncDoneRsp);
  SERDE_SERVICE_METHOD(spaceInfo, 10, SpaceInfoReq, SpaceInfoRsp);
  SERDE_SERVICE_METHOD(createTarget, 11, CreateTargetReq, CreateTargetRsp);
  SERDE_SERVICE_METHOD(queryChunk, 12, QueryChunkReq, QueryChunkRsp);
  SERDE_SERVICE_METHOD(getAllChunkMetadata, 13, GetAllChunkMetadataReq, GetAllChunkMetadataRsp);
  SERDE_SERVICE_METHOD(offlineTarget, 16, OfflineTargetReq, OfflineTargetRsp);
  SERDE_SERVICE_METHOD(removeTarget, 17, RemoveTargetReq, RemoveTargetRsp);
  SERDE_SERVICE_METHOD(createEcTarget, 18, EcCreateTargetReq, EcCreateTargetRsp);
  SERDE_SERVICE_METHOD(createEcFragment, 19, EcCreateReq, EcCreateRsp);
  SERDE_SERVICE_METHOD(readEcFragment, 20, EcReadReq, EcReadRsp);
  SERDE_SERVICE_METHOD(reconcileEcFragment, 21, EcReconcileReq, EcReconcileRsp);
  SERDE_SERVICE_METHOD(authorizedCreateEcFragment, 22, EcAuthorizedCreateReq, EcCreateRsp);
  SERDE_SERVICE_METHOD(authorizedReadEcFragment, 23, EcAuthorizedReadReq, EcReadRsp);
  SERDE_SERVICE_METHOD(authorizedReconcileEcFragment, 24, EcAuthorizedReconcileReq, EcReconcileRsp);
  SERDE_SERVICE_METHOD(revokeEcScope, 25, EcScopeControlRequest, EcScopeControlRsp);
  SERDE_SERVICE_METHOD(queryEcScopeDrain, 26, EcScopeControlRequest, EcScopeControlRsp);
  SERDE_SERVICE_METHOD(readEcBlockV2, 40, EcReadBlockV2Req, EcReadBlockV2Rsp);
  SERDE_SERVICE_METHOD(beginEcStageV2, 41, EcBeginStageV2Req, EcStageV2Rsp);
  SERDE_SERVICE_METHOD(appendEcStageV2, 42, EcAppendStageV2Req, EcStageV2Rsp);
  SERDE_SERVICE_METHOD(queryEcStageV2, 43, EcQueryStageV2Req, EcStageV2Rsp);
  SERDE_SERVICE_METHOD(reconcileEcStageV2, 44, EcReconcileStageV2Req, EcStageV2Rsp);
  SERDE_SERVICE_METHOD(sealEcStageV2, 45, EcSealStageV2Req, EcSealStageV2Rsp);
};

}  // namespace hf3fs::storage
