#pragma once

#include <span>
#include <vector>

#include "common/net/Client.h"
#include "common/serde/MessagePacket.h"
#include "common/serde/RpcCallSizes.h"
#include "common/utils/Address.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Result.h"
#include "fbs/storage/Common.h"
#include "fbs/storage/Ec.h"
#include "fbs/storage/EcAuthorized.h"
#include "fbs/storage/EcGcDiscovery.h"
#include "fbs/storage/EcGcRpc.h"
#include "fbs/storage/EcHelper.h"
#include "fbs/storage/EcHelperDirect.h"
#include "fbs/storage/EcScopeControl.h"
#include "fbs/storage/EcStageResultV2.h"
#include "fbs/storage/EcTargetDiscovery.h"
#include "fbs/storage/EcTargetRetirementControl.h"

namespace hf3fs::storage::client {

class StorageMessenger {
 public:
  StorageMessenger(const hf3fs::net::Client::Config &config);

  Result<Void> start(const std::string &name = "StorageMsgr") { return client_.start(name); }

  void stopAndJoin() { client_.stopAndJoin(); }

  CoTryTask<BatchReadRsp> batchRead(const hf3fs::net::Address &address,
                                    const BatchReadReq &request,
                                    const net::UserRequestOptions *options = nullptr,
                                    serde::Timestamp *timestamp = nullptr);

  CoTryTask<WriteRsp> write(const hf3fs::net::Address &address,
                            const WriteReq &request,
                            const net::UserRequestOptions *options = nullptr,
                            serde::Timestamp *timestamp = nullptr);

  CoTryTask<UpdateRsp> update(const hf3fs::net::Address &address,
                              const UpdateReq &request,
                              const net::UserRequestOptions *options = nullptr,
                              serde::Timestamp *timestamp = nullptr);

  CoTryTask<QueryLastChunkRsp> queryLastChunk(const hf3fs::net::Address &address,
                                              const QueryLastChunkReq &request,
                                              const net::UserRequestOptions *options = nullptr,
                                              serde::Timestamp *timestamp = nullptr);

  CoTryTask<RemoveChunksRsp> removeChunks(const hf3fs::net::Address &address,
                                          const RemoveChunksReq &request,
                                          const net::UserRequestOptions *options = nullptr,
                                          serde::Timestamp *timestamp = nullptr);

  CoTryTask<TruncateChunksRsp> truncateChunks(const hf3fs::net::Address &address,
                                              const TruncateChunksReq &request,
                                              const net::UserRequestOptions *options = nullptr,
                                              serde::Timestamp *timestamp = nullptr);

  CoTryTask<SpaceInfoRsp> querySpaceInfo(const hf3fs::net::Address &address,
                                         const SpaceInfoReq &request,
                                         const net::UserRequestOptions *options = nullptr,
                                         serde::Timestamp *timestamp = nullptr);

  CoTryTask<TargetSyncInfo> syncStart(const hf3fs::net::Address &address,
                                      const SyncStartReq &request,
                                      const net::UserRequestOptions *options = nullptr,
                                      serde::Timestamp *timestamp = nullptr);

  CoTryTask<SyncDoneRsp> syncDone(const hf3fs::net::Address &address,
                                  const SyncDoneReq &request,
                                  const net::UserRequestOptions *options = nullptr,
                                  serde::Timestamp *timestamp = nullptr);

  CoTryTask<CreateTargetRsp> createTarget(const hf3fs::net::Address &address,
                                          const CreateTargetReq &request,
                                          const net::UserRequestOptions *options = nullptr,
                                          serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcCreateTargetRsp> createEcTarget(const hf3fs::net::Address &address,
                                              const EcCreateTargetReq &request,
                                              const net::UserRequestOptions *options = nullptr,
                                              serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcCreateRsp> createEcFragment(const hf3fs::net::Address &address,
                                          const EcCreateReq &request,
                                          const net::UserRequestOptions *options = nullptr,
                                          serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcReadRsp> readEcFragment(const hf3fs::net::Address &address,
                                      const EcReadReq &request,
                                      const net::UserRequestOptions *options = nullptr,
                                      serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcReconcileRsp> reconcileEcFragment(const hf3fs::net::Address &address,
                                                const EcReconcileReq &request,
                                                const net::UserRequestOptions *options = nullptr,
                                                serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcCreateRsp> authorizedCreateEcFragment(const net::Address &address,
                                                    const EcAuthorizedCreateReq &request,
                                                    const net::UserRequestOptions *options = nullptr,
                                                    serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcReadRsp> authorizedReadEcFragment(const net::Address &address,
                                                const EcAuthorizedReadReq &request,
                                                const net::UserRequestOptions *options = nullptr,
                                                serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcReconcileRsp> authorizedReconcileEcFragment(const net::Address &address,
                                                          const EcAuthorizedReconcileReq &request,
                                                          const net::UserRequestOptions *options = nullptr,
                                                          serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcGcRsp> exchangeEcGc(const net::Address &address,
                                  const EcGcRequest &request,
                                  const net::UserRequestOptions *options = nullptr,
                                  serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcTargetDiscoveryRsp> getEcTargetIdentity(const net::Address &address,
                                                      const EcTargetDiscoveryRequest &request,
                                                      const net::UserRequestOptions *options = nullptr,
                                                      serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcGcDiscoveryRsp> getEcGcCapability(const net::Address &address,
                                                const EcGcDiscoveryRequest &request,
                                                const net::UserRequestOptions *options = nullptr,
                                                serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcTargetRetirementRsp> prepareEcTargetRetirement(const net::Address &address,
      const EcTargetRetirementRequest &request,
      const net::UserRequestOptions *options = nullptr,
      serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcTargetRetirementRsp> queryEcTargetRetirement(const net::Address &address,
      const EcTargetRetirementRequest &request,
      const net::UserRequestOptions *options = nullptr,
      serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcScopeControlRsp> revokeEcScope(const net::Address &address,
                                             const EcScopeControlRequest &request,
                                             const net::UserRequestOptions *options = nullptr,
                                             serde::Timestamp *timestamp = nullptr);
  CoTryTask<EcScopeControlRsp> queryEcScopeDrain(const net::Address &address,
                                                 const EcScopeControlRequest &request,
                                                 const net::UserRequestOptions *options = nullptr,
                                                 serde::Timestamp *timestamp = nullptr);

  CoTryTask<EcHelperHopRsp> executeEcHelper(const net::Address &address,
                                            const EcHelperHopReq &request,
                                            const net::UserRequestOptions *options = nullptr,
                                            serde::Timestamp *timestamp = nullptr,
                                            serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcReadBlockV2Rsp> readEcBlockV2(const net::Address &address,
                                            const EcReadBlockV2Req &request,
                                            const net::UserRequestOptions *options = nullptr,
                                            serde::Timestamp *timestamp = nullptr,
                                            serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcHelperDirectHopRsp> executeEcHelperDirect(const net::Address &address,
                                                      const EcHelperDirectHopReq &request,
                                                      const net::UserRequestOptions *options = nullptr,
                                                      serde::Timestamp *timestamp = nullptr,
                                                      serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcStageV2Rsp> beginEcStageV2(const net::Address &address,
                                         const EcBeginStageV2Req &request,
                                         const net::UserRequestOptions *options = nullptr,
                                         serde::Timestamp *timestamp = nullptr,
                                         serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcStageV2Rsp> appendEcStageV2(const net::Address &address,
                                          const EcAppendStageV2Req &request,
                                          const net::UserRequestOptions *options = nullptr,
                                          serde::Timestamp *timestamp = nullptr,
                                          serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcStageV2Rsp> queryEcStageV2(const net::Address &address,
                                         const EcQueryStageV2Req &request,
                                         const net::UserRequestOptions *options = nullptr,
                                         serde::Timestamp *timestamp = nullptr,
                                         serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcStageV2Rsp> reconcileEcStageV2(const net::Address &address,
                                             const EcReconcileStageV2Req &request,
                                             const net::UserRequestOptions *options = nullptr,
                                             serde::Timestamp *timestamp = nullptr,
                                             serde::RpcCallSizes *sizes = nullptr);
  CoTryTask<EcSealStageV2Rsp> sealEcStageV2(const net::Address &address,
                                            const EcSealStageV2Req &request,
                                            const net::UserRequestOptions *options = nullptr,
                                            serde::Timestamp *timestamp = nullptr,
                                            serde::RpcCallSizes *sizes = nullptr);

  CoTryTask<OfflineTargetRsp> offlineTarget(const hf3fs::net::Address &address,
                                            const OfflineTargetReq &request,
                                            const net::UserRequestOptions *options = nullptr,
                                            serde::Timestamp *timestamp = nullptr);

  CoTryTask<RemoveTargetRsp> removeTarget(const hf3fs::net::Address &address,
                                          const RemoveTargetReq &request,
                                          const net::UserRequestOptions *options = nullptr,
                                          serde::Timestamp *timestamp = nullptr);

  CoTryTask<QueryChunkRsp> queryChunk(const hf3fs::net::Address &address,
                                      const QueryChunkReq &request,
                                      const net::UserRequestOptions *options = nullptr,
                                      serde::Timestamp *timestamp = nullptr);

  CoTryTask<GetAllChunkMetadataRsp> getAllChunkMetadata(const hf3fs::net::Address &address,
                                                        const GetAllChunkMetadataReq &request,
                                                        const net::UserRequestOptions *options = nullptr,
                                                        serde::Timestamp *timestamp = nullptr);

 private:
  hf3fs::net::Client client_;
};

}  // namespace hf3fs::storage::client
