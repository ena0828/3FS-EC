#include "StorageMessenger.h"

#include <boost/core/ignore_unused.hpp>

#include "common/serde/ClientContext.h"
#include "common/serde/Service.h"
#include "fbs/storage/Service.h"

namespace hf3fs::storage::client {

StorageMessenger::StorageMessenger(const hf3fs::net::Client::Config &config)
    : client_(config) {}

template <typename Req, typename Rsp, auto rpcMethod>
CoTryTask<Rsp> callSerdeRpcMethod(hf3fs::net::Client &client,
                                  const hf3fs::net::Address &address,
                                  const Req &request,
                                  const net::UserRequestOptions *options,
                                  serde::Timestamp *timestamp) {
  auto clientCtx = client.serdeCtx(address);

  auto packedRsp = co_await rpcMethod(clientCtx, request, options, timestamp);

  if (!packedRsp) {
    auto timeout = options && options->timeout ? options->timeout.value() : client.options()->timeout;
    XLOGF(ERR,
          "RPC communication error: {}, request: {}, timeout: {}, peer address: {}",
          packedRsp.error(),
          fmt::ptr(&request),
          timeout,
          address);
    co_return makeError(packedRsp.error());
  }

  co_return packedRsp;
}

CoTryTask<BatchReadRsp> StorageMessenger::batchRead(const hf3fs::net::Address &address,
                                                    const BatchReadReq &request,
                                                    const net::UserRequestOptions *options,
                                                    serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<BatchReadReq,
                                        BatchReadRsp,
                                        hf3fs::storage::StorageSerde<>::batchRead<serde::ClientContext>>(client_,
                                                                                                         address,
                                                                                                         request,
                                                                                                         options,
                                                                                                         timestamp);
}

CoTryTask<WriteRsp> StorageMessenger::write(const hf3fs::net::Address &address,
                                            const WriteReq &request,
                                            const net::UserRequestOptions *options,
                                            serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<WriteReq,
                                        WriteRsp,
                                        hf3fs::storage::StorageSerde<>::write<serde::ClientContext>>(client_,
                                                                                                     address,
                                                                                                     request,
                                                                                                     options,
                                                                                                     timestamp);
}

CoTryTask<UpdateRsp> StorageMessenger::update(const hf3fs::net::Address &address,
                                              const UpdateReq &request,
                                              const net::UserRequestOptions *options,
                                              serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<UpdateReq,
                                        UpdateRsp,
                                        hf3fs::storage::StorageSerde<>::update<serde::ClientContext>>(client_,
                                                                                                      address,
                                                                                                      request,
                                                                                                      options,
                                                                                                      timestamp);
}

CoTryTask<QueryLastChunkRsp> StorageMessenger::queryLastChunk(const hf3fs::net::Address &address,
                                                              const QueryLastChunkReq &request,
                                                              const net::UserRequestOptions *options,
                                                              serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<QueryLastChunkReq,
                                        QueryLastChunkRsp,
                                        hf3fs::storage::StorageSerde<>::queryLastChunk<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<RemoveChunksRsp> StorageMessenger::removeChunks(const hf3fs::net::Address &address,
                                                          const RemoveChunksReq &request,
                                                          const net::UserRequestOptions *options,
                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<RemoveChunksReq,
                                        RemoveChunksRsp,
                                        hf3fs::storage::StorageSerde<>::removeChunks<serde::ClientContext>>(client_,
                                                                                                            address,
                                                                                                            request,
                                                                                                            options,
                                                                                                            timestamp);
}

CoTryTask<TruncateChunksRsp> StorageMessenger::truncateChunks(const hf3fs::net::Address &address,
                                                              const TruncateChunksReq &request,
                                                              const net::UserRequestOptions *options,
                                                              serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<TruncateChunksReq,
                                        TruncateChunksRsp,
                                        hf3fs::storage::StorageSerde<>::truncateChunks<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<SpaceInfoRsp> StorageMessenger::querySpaceInfo(const hf3fs::net::Address &address,
                                                         const SpaceInfoReq &request,
                                                         const net::UserRequestOptions *options,
                                                         serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<SpaceInfoReq,
                                        SpaceInfoRsp,
                                        hf3fs::storage::StorageSerde<>::spaceInfo<serde::ClientContext>>(client_,
                                                                                                         address,
                                                                                                         request,
                                                                                                         options,
                                                                                                         timestamp);
}

CoTryTask<TargetSyncInfo> StorageMessenger::syncStart(const hf3fs::net::Address &address,
                                                      const SyncStartReq &request,
                                                      const net::UserRequestOptions *options,
                                                      serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<SyncStartReq,
                                        TargetSyncInfo,
                                        hf3fs::storage::StorageSerde<>::syncStart<serde::ClientContext>>(client_,
                                                                                                         address,
                                                                                                         request,
                                                                                                         options,
                                                                                                         timestamp);
}

CoTryTask<SyncDoneRsp> StorageMessenger::syncDone(const hf3fs::net::Address &address,
                                                  const SyncDoneReq &request,
                                                  const net::UserRequestOptions *options,
                                                  serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<SyncDoneReq,
                                        SyncDoneRsp,
                                        hf3fs::storage::StorageSerde<>::syncDone<serde::ClientContext>>(client_,
                                                                                                        address,
                                                                                                        request,
                                                                                                        options,
                                                                                                        timestamp);
}

CoTryTask<CreateTargetRsp> StorageMessenger::createTarget(const hf3fs::net::Address &address,
                                                          const CreateTargetReq &request,
                                                          const net::UserRequestOptions *options,
                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<CreateTargetReq,
                                        CreateTargetRsp,
                                        hf3fs::storage::StorageSerde<>::createTarget<serde::ClientContext>>(client_,
                                                                                                            address,
                                                                                                            request,
                                                                                                            options,
                                                                                                            timestamp);
}

CoTryTask<EcCreateTargetRsp> StorageMessenger::createEcTarget(const hf3fs::net::Address &address,
                                                              const EcCreateTargetReq &request,
                                                              const net::UserRequestOptions *options,
                                                              serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcCreateTargetReq,
                                        EcCreateTargetRsp,
                                        hf3fs::storage::StorageSerde<>::createEcTarget<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcCreateRsp> StorageMessenger::createEcFragment(const hf3fs::net::Address &address,
                                                          const EcCreateReq &request,
                                                          const net::UserRequestOptions *options,
                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcCreateReq,
                                        EcCreateRsp,
                                        hf3fs::storage::StorageSerde<>::createEcFragment<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcReadRsp> StorageMessenger::readEcFragment(const hf3fs::net::Address &address,
                                                      const EcReadReq &request,
                                                      const net::UserRequestOptions *options,
                                                      serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcReadReq,
                                        EcReadRsp,
                                        hf3fs::storage::StorageSerde<>::readEcFragment<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcReconcileRsp> StorageMessenger::reconcileEcFragment(const hf3fs::net::Address &address,
                                                                const EcReconcileReq &request,
                                                                const net::UserRequestOptions *options,
                                                                serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcReconcileReq,
                                        EcReconcileRsp,
                                        hf3fs::storage::StorageSerde<>::reconcileEcFragment<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcCreateRsp> StorageMessenger::authorizedCreateEcFragment(const net::Address &address,
                                                                    const EcAuthorizedCreateReq &request,
                                                                    const net::UserRequestOptions *options,
                                                                    serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcAuthorizedCreateReq,
                                        EcCreateRsp,
                                        StorageSerde<>::authorizedCreateEcFragment<serde::ClientContext>>(client_,
                                                                                                          address,
                                                                                                          request,
                                                                                                          options,
                                                                                                          timestamp);
}

CoTryTask<EcReadRsp> StorageMessenger::authorizedReadEcFragment(const net::Address &address,
                                                                const EcAuthorizedReadReq &request,
                                                                const net::UserRequestOptions *options,
                                                                serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcAuthorizedReadReq,
                                        EcReadRsp,
                                        StorageSerde<>::authorizedReadEcFragment<serde::ClientContext>>(client_,
                                                                                                        address,
                                                                                                        request,
                                                                                                        options,
                                                                                                        timestamp);
}

CoTryTask<EcReconcileRsp> StorageMessenger::authorizedReconcileEcFragment(const net::Address &address,
                                                                          const EcAuthorizedReconcileReq &request,
                                                                          const net::UserRequestOptions *options,
                                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcAuthorizedReconcileReq,
                                        EcReconcileRsp,
                                        StorageSerde<>::authorizedReconcileEcFragment<serde::ClientContext>>(client_,
                                                                                                             address,
                                                                                                             request,
                                                                                                             options,
                                                                                                             timestamp);
}

CoTryTask<OfflineTargetRsp> StorageMessenger::offlineTarget(const hf3fs::net::Address &address,
                                                            const OfflineTargetReq &request,
                                                            const net::UserRequestOptions *options,
                                                            serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<OfflineTargetReq,
                                        OfflineTargetRsp,
                                        hf3fs::storage::StorageSerde<>::offlineTarget<serde::ClientContext>>(client_,
                                                                                                             address,
                                                                                                             request,
                                                                                                             options,
                                                                                                             timestamp);
}

CoTryTask<RemoveTargetRsp> StorageMessenger::removeTarget(const hf3fs::net::Address &address,
                                                          const RemoveTargetReq &request,
                                                          const net::UserRequestOptions *options,
                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<RemoveTargetReq,
                                        RemoveTargetRsp,
                                        hf3fs::storage::StorageSerde<>::removeTarget<serde::ClientContext>>(client_,
                                                                                                            address,
                                                                                                            request,
                                                                                                            options,
                                                                                                            timestamp);
}

CoTryTask<QueryChunkRsp> StorageMessenger::queryChunk(const hf3fs::net::Address &address,
                                                      const QueryChunkReq &request,
                                                      const net::UserRequestOptions *options,
                                                      serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<QueryChunkReq,
                                        QueryChunkRsp,
                                        hf3fs::storage::StorageSerde<>::queryChunk<serde::ClientContext>>(client_,
                                                                                                          address,
                                                                                                          request,
                                                                                                          options,
                                                                                                          timestamp);
}

CoTryTask<GetAllChunkMetadataRsp> StorageMessenger::getAllChunkMetadata(const hf3fs::net::Address &address,
                                                                        const GetAllChunkMetadataReq &request,
                                                                        const net::UserRequestOptions *options,
                                                                        serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<GetAllChunkMetadataReq,
                                        GetAllChunkMetadataRsp,
                                        hf3fs::storage::StorageSerde<>::getAllChunkMetadata<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcGcRsp> StorageMessenger::exchangeEcGc(const net::Address &address,
                                                  const EcGcRequest &request,
                                                  const net::UserRequestOptions *options,
                                                  serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcGcRequest, EcGcRsp, StorageSerde<>::exchangeEcGc<serde::ClientContext>>(
      client_,
      address,
      request,
      options,
      timestamp);
}

CoTryTask<EcTargetDiscoveryRsp> StorageMessenger::getEcTargetIdentity(const net::Address &address,
                                                                      const EcTargetDiscoveryRequest &request,
                                                                      const net::UserRequestOptions *options,
                                                                      serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcTargetDiscoveryRequest,
                                        EcTargetDiscoveryRsp,
                                        StorageSerde<>::getEcTargetIdentity<serde::ClientContext>>(client_,
                                                                                                   address,
                                                                                                   request,
                                                                                                   options,
                                                                                                   timestamp);
}

CoTryTask<EcGcDiscoveryRsp> StorageMessenger::getEcGcCapability(const net::Address &address,
                                                                const EcGcDiscoveryRequest &request,
                                                                const net::UserRequestOptions *options,
                                                                serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcGcDiscoveryRequest,
                                        EcGcDiscoveryRsp,
                                        StorageSerde<>::getEcGcCapability<serde::ClientContext>>(client_,
                                                                                                 address,
                                                                                                 request,
                                                                                                 options,
                                                                                                 timestamp);
}

CoTryTask<EcTargetRetirementRsp> StorageMessenger::prepareEcTargetRetirement(
    const net::Address &address, const EcTargetRetirementRequest &request,
    const net::UserRequestOptions *options, serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcTargetRetirementRequest, EcTargetRetirementRsp,
      StorageSerde<>::prepareEcTargetRetirement<serde::ClientContext>>(client_, address, request, options, timestamp);
}

CoTryTask<EcTargetRetirementRsp> StorageMessenger::queryEcTargetRetirement(
    const net::Address &address, const EcTargetRetirementRequest &request,
    const net::UserRequestOptions *options, serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcTargetRetirementRequest, EcTargetRetirementRsp,
      StorageSerde<>::queryEcTargetRetirement<serde::ClientContext>>(client_, address, request, options, timestamp);
}

CoTryTask<EcScopeControlRsp> StorageMessenger::revokeEcScope(const net::Address &address,
                                                             const EcScopeControlRequest &request,
                                                             const net::UserRequestOptions *options,
                                                             serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcScopeControlRequest,
                                        EcScopeControlRsp,
                                        StorageSerde<>::revokeEcScope<serde::ClientContext>>(client_,
                                                                                             address,
                                                                                             request,
                                                                                             options,
                                                                                             timestamp);
}

CoTryTask<EcScopeControlRsp> StorageMessenger::queryEcScopeDrain(const net::Address &address,
                                                                 const EcScopeControlRequest &request,
                                                                 const net::UserRequestOptions *options,
                                                                 serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcScopeControlRequest,
                                        EcScopeControlRsp,
                                        StorageSerde<>::queryEcScopeDrain<serde::ClientContext>>(client_,
                                                                                                 address,
                                                                                                 request,
                                                                                                 options,
                                                                                                 timestamp);
}

CoTryTask<EcReadBlockV2Rsp> StorageMessenger::readEcBlockV2(const net::Address &address,
                                                            const EcReadBlockV2Req &request,
                                                            const net::UserRequestOptions *options,
                                                            serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcReadBlockV2Req,
                                        EcReadBlockV2Rsp,
                                        StorageSerde<>::readEcBlockV2<serde::ClientContext>>(client_,
                                                                                             address,
                                                                                             request,
                                                                                             options,
                                                                                             timestamp);
}

CoTryTask<EcStageV2Rsp> StorageMessenger::beginEcStageV2(const net::Address &address,
                                                         const EcBeginStageV2Req &request,
                                                         const net::UserRequestOptions *options,
                                                         serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcBeginStageV2Req,
                                        EcStageV2Rsp,
                                        StorageSerde<>::beginEcStageV2<serde::ClientContext>>(client_,
                                                                                              address,
                                                                                              request,
                                                                                              options,
                                                                                              timestamp);
}

CoTryTask<EcStageV2Rsp> StorageMessenger::appendEcStageV2(const net::Address &address,
                                                          const EcAppendStageV2Req &request,
                                                          const net::UserRequestOptions *options,
                                                          serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcAppendStageV2Req,
                                        EcStageV2Rsp,
                                        StorageSerde<>::appendEcStageV2<serde::ClientContext>>(client_,
                                                                                               address,
                                                                                               request,
                                                                                               options,
                                                                                               timestamp);
}

CoTryTask<EcStageV2Rsp> StorageMessenger::queryEcStageV2(const net::Address &address,
                                                         const EcQueryStageV2Req &request,
                                                         const net::UserRequestOptions *options,
                                                         serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcQueryStageV2Req,
                                        EcStageV2Rsp,
                                        StorageSerde<>::queryEcStageV2<serde::ClientContext>>(client_,
                                                                                              address,
                                                                                              request,
                                                                                              options,
                                                                                              timestamp);
}

CoTryTask<EcStageV2Rsp> StorageMessenger::reconcileEcStageV2(const net::Address &address,
                                                             const EcReconcileStageV2Req &request,
                                                             const net::UserRequestOptions *options,
                                                             serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcReconcileStageV2Req,
                                        EcStageV2Rsp,
                                        StorageSerde<>::reconcileEcStageV2<serde::ClientContext>>(client_,
                                                                                                  address,
                                                                                                  request,
                                                                                                  options,
                                                                                                  timestamp);
}

CoTryTask<EcSealStageV2Rsp> StorageMessenger::sealEcStageV2(const net::Address &address,
                                                            const EcSealStageV2Req &request,
                                                            const net::UserRequestOptions *options,
                                                            serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcSealStageV2Req,
                                        EcSealStageV2Rsp,
                                        StorageSerde<>::sealEcStageV2<serde::ClientContext>>(client_,
                                                                                             address,
                                                                                             request,
                                                                                             options,
                                                                                             timestamp);
}

CoTryTask<EcHelperHopRsp> StorageMessenger::executeEcHelper(const net::Address &address,
                                                            const EcHelperHopReq &request,
                                                            const net::UserRequestOptions *options,
                                                            serde::Timestamp *timestamp) {
  co_return co_await callSerdeRpcMethod<EcHelperHopReq,
                                        EcHelperHopRsp,
                                        StorageSerde<>::executeEcHelper<serde::ClientContext>>(client_,
                                                                                               address,
                                                                                               request,
                                                                                               options,
                                                                                               timestamp);
}

}  // namespace hf3fs::storage::client
