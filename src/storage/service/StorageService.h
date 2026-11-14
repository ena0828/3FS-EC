#pragma once

#include "common/serde/CallContext.h"
#include "fbs/storage/Service.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {

class StorageService : public serde::ServiceWrapper<StorageService, storage::StorageSerde> {
 public:
  StorageService(StorageOperator &storageOperator)
      : storageOperator_(storageOperator) {}

  CoTryTask<BatchReadRsp> batchRead(serde::CallContext &ctx, const BatchReadReq &req) {
    reportReadQueueLatency(ctx);
    if (UNLIKELY(req.payloads.empty())) co_return BatchReadRsp{.tag = req.tag};
    ServiceRequestContext requestCtx{"batchRead", req.tag, req.retryCount, req.userInfo, req.debugFlags};
    co_return co_await storageOperator_.batchRead(requestCtx, req, ctx);
  }

  CoTryTask<WriteRsp> write(serde::CallContext &ctx, const WriteReq &req) {
    reportUpdateQueueLatency(ctx);
    ServiceRequestContext requestCtx{"write", req.tag, req.retryCount, req.userInfo, req.debugFlags};
    co_return co_await storageOperator_.write(requestCtx, req, ctx.transport()->ibSocket());
  }

  CoTryTask<UpdateRsp> update(serde::CallContext &ctx, const UpdateReq &req) {
    reportUpdateQueueLatency(ctx);
    ServiceRequestContext requestCtx{"update", req.tag, req.retryCount, req.userInfo, req.debugFlags};
    co_return co_await storageOperator_.update(requestCtx, req, ctx.transport()->ibSocket());
  }

  CoTryTask<QueryLastChunkRsp> queryLastChunk(serde::CallContext &ctx, const QueryLastChunkReq &req) {
    reportDefaultQueueLatency(ctx);
    if (UNLIKELY(req.payloads.empty())) co_return QueryLastChunkRsp{};
    ServiceRequestContext requestCtx{"queryLastChunk", req.tag, req.retryCount, req.userInfo, req.debugFlags};
    co_return co_await storageOperator_.queryLastChunk(requestCtx, req);
  }

  CoTryTask<TruncateChunksRsp> truncateChunks(serde::CallContext &ctx, const TruncateChunksReq &req) {
    reportDefaultQueueLatency(ctx);
    if (UNLIKELY(req.payloads.empty())) co_return TruncateChunksRsp{};
    ServiceRequestContext requestCtx{"truncateChunks",
                                     req.payloads.front().tag,
                                     req.payloads.front().retryCount,
                                     req.userInfo,
                                     req.debugFlags};
    co_return co_await storageOperator_.truncateChunks(requestCtx, req);
  }

  CoTryTask<RemoveChunksRsp> removeChunks(serde::CallContext &ctx, const RemoveChunksReq &req) {
    reportDefaultQueueLatency(ctx);
    if (UNLIKELY(req.payloads.empty())) co_return RemoveChunksRsp{};
    ServiceRequestContext requestCtx{"removeChunks",
                                     req.payloads.front().tag,
                                     req.payloads.front().retryCount,
                                     req.userInfo,
                                     req.debugFlags};
    co_return co_await storageOperator_.removeChunks(requestCtx, req);
  }

  CoTryTask<TargetSyncInfo> syncStart(serde::CallContext &ctx, const SyncStartReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.syncStart(req);
  }

  CoTryTask<SyncDoneRsp> syncDone(serde::CallContext &ctx, const SyncDoneReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.syncDone(req);
  }

  CoTryTask<SpaceInfoRsp> spaceInfo(serde::CallContext &ctx, const SpaceInfoReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.spaceInfo(req);
  }

  CoTryTask<CreateTargetRsp> createTarget(serde::CallContext &ctx, const CreateTargetReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.createTarget(req);
  }

  CoTryTask<EcCreateTargetRsp> createEcTarget(serde::CallContext &ctx, const EcCreateTargetReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.createEcTarget(req);
  }

  CoTryTask<EcCreateRsp> createEcFragment(serde::CallContext &ctx, const EcCreateReq &req) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.createEcFragment(req);
  }

  CoTryTask<EcReadRsp> readEcFragment(serde::CallContext &ctx, const EcReadReq &req) {
    reportReadQueueLatency(ctx);
    return storageOperator_.readEcFragment(req);
  }

  CoTryTask<EcReconcileRsp> reconcileEcFragment(serde::CallContext &ctx, const EcReconcileReq &req) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.reconcileEcFragment(req);
  }

  CoTryTask<EcCreateRsp> authorizedCreateEcFragment(serde::CallContext &ctx, const EcAuthorizedCreateReq &req) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.authorizedCreateEcFragment(req);
  }

  CoTryTask<EcReadRsp> authorizedReadEcFragment(serde::CallContext &ctx, const EcAuthorizedReadReq &req) {
    reportReadQueueLatency(ctx);
    return storageOperator_.authorizedReadEcFragment(req);
  }

  CoTryTask<EcReconcileRsp> authorizedReconcileEcFragment(serde::CallContext &ctx,
                                                          const EcAuthorizedReconcileReq &req) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.authorizedReconcileEcFragment(req);
  }

  CoTryTask<EcGcAbsentRsp> exchangeEcGcAbsent(serde::CallContext &ctx, const EcGcAbsentRequest &request) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.exchangeEcGcAbsent(request);
  }
  CoTryTask<EcGcAbsentDiscoveryRsp> getEcGcAbsentCapability(serde::CallContext &ctx, const EcGcAbsentDiscoveryRequest &request) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.getEcGcAbsentCapability(request);
  }
  CoTryTask<EcGcRsp> exchangeEcGc(serde::CallContext &ctx, const EcGcRequest &request) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.exchangeEcGc(request);
  }

  CoTryTask<EcGcDiscoveryRsp> getEcGcCapability(serde::CallContext &ctx, const EcGcDiscoveryRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.getEcGcCapability(req);
  }

  CoTryTask<EcTargetDiscoveryRsp> getEcTargetIdentity(serde::CallContext &ctx, const EcTargetDiscoveryRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.getEcTargetIdentity(req);
  }

  CoTryTask<EcTargetRetirementRsp> prepareEcTargetRetirement(serde::CallContext &ctx, const EcTargetRetirementRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.prepareEcTargetRetirement(req);
  }
  CoTryTask<EcTargetRetirementRsp> queryEcTargetRetirement(serde::CallContext &ctx, const EcTargetRetirementRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.queryEcTargetRetirement(req);
  }
  CoTryTask<EcScopeControlRsp> revokeEcScope(serde::CallContext &ctx, const EcScopeControlRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.revokeEcScope(req);
  }
  CoTryTask<EcScopeControlRsp> queryEcScopeDrain(serde::CallContext &ctx, const EcScopeControlRequest &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.queryEcScopeDrain(req);
  }

  CoTryTask<EcReadBlockV2Rsp> readEcBlockV2(serde::CallContext &ctx, const EcReadBlockV2Req &request) {
    reportReadQueueLatency(ctx);
    return storageOperator_.readEcBlockV2(request);
  }

  CoTryTask<EcStageV2Rsp> beginEcStageV2(serde::CallContext &ctx, const EcBeginStageV2Req &request) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.beginEcStageV2(request);
  }

  CoTryTask<EcStageV2Rsp> appendEcStageV2(serde::CallContext &ctx, const EcAppendStageV2Req &request) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.appendEcStageV2(request);
  }

  CoTryTask<EcStageV2Rsp> queryEcStageV2(serde::CallContext &ctx, const EcQueryStageV2Req &request) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.queryEcStageV2(request);
  }

  CoTryTask<EcStageV2Rsp> reconcileEcStageV2(serde::CallContext &ctx, const EcReconcileStageV2Req &request) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.reconcileEcStageV2(request);
  }

  CoTryTask<EcHelperHopRsp> executeEcHelper(serde::CallContext &ctx, const EcHelperHopReq &request) {
    reportDefaultQueueLatency(ctx);
    // Copy ingress identity before returning the task; never retain CallContext/Transport.
    const auto transportType = ctx.transport() ? ctx.transport()->serverAddr().type : net::Address::LOCAL;
    return storageOperator_.executeEcHelper(request, transportType);
  }

  CoTryTask<EcHelperDirectHopRsp> executeEcHelperDirect(serde::CallContext &ctx,
                                                     const EcHelperDirectHopReq &request) {
    reportDefaultQueueLatency(ctx);
    // Copy ingress identity before returning the task; never retain CallContext/Transport.
    const auto transportType = ctx.transport() ? ctx.transport()->serverAddr().type : net::Address::LOCAL;
    return storageOperator_.executeEcHelperDirect(request, transportType);
  }

  CoTryTask<EcRmwStatusRsp> installEcRmw(serde::CallContext &ctx, const EcRmwInstallReq &request) {
    reportDefaultQueueLatency(ctx);
    const auto transportType = ctx.transport() ? ctx.transport()->serverAddr().type : net::Address::LOCAL;
    return storageOperator_.installEcRmw(request, transportType);
  }
  CoTryTask<EcRmwStatusRsp> putEcRmw(serde::CallContext &ctx, const EcRmwPutReq &request) {
    reportDefaultQueueLatency(ctx);
    const auto transportType = ctx.transport() ? ctx.transport()->serverAddr().type : net::Address::LOCAL;
    return storageOperator_.putEcRmw(request, transportType);
  }
  CoTryTask<EcRmwStatusRsp> actionEcRmw(serde::CallContext &ctx, const EcRmwActionReq &request) {
    reportDefaultQueueLatency(ctx);
    const auto transportType = ctx.transport() ? ctx.transport()->serverAddr().type : net::Address::LOCAL;
    return storageOperator_.actionEcRmw(request, transportType);
  }

  CoTryTask<EcSealStageV2Rsp> sealEcStageV2(serde::CallContext &ctx, const EcSealStageV2Req &request) {
    reportUpdateQueueLatency(ctx);
    return storageOperator_.sealEcStageV2(request);
  }

  CoTryTask<OfflineTargetRsp> offlineTarget(serde::CallContext &ctx, const OfflineTargetReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.offlineTarget(req);
  }

  CoTryTask<RemoveTargetRsp> removeTarget(serde::CallContext &ctx, const RemoveTargetReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.removeTarget(req);
  }

  CoTryTask<QueryChunkRsp> queryChunk(serde::CallContext &ctx, const QueryChunkReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.queryChunk(req);
  }

  CoTryTask<GetAllChunkMetadataRsp> getAllChunkMetadata(serde::CallContext &ctx, const GetAllChunkMetadataReq &req) {
    reportDefaultQueueLatency(ctx);
    return storageOperator_.getAllChunkMetadata(req);
  }

 private:
  void reportReadQueueLatency(serde::CallContext &ctx);
  void reportUpdateQueueLatency(serde::CallContext &ctx);
  void reportDefaultQueueLatency(serde::CallContext &ctx);

 private:
  StorageOperator &storageOperator_;
};

}  // namespace hf3fs::storage
