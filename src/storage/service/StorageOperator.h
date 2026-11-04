#pragma once

#include <chrono>
#include <folly/concurrency/ConcurrentHashMap.h>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <functional>

#include "analytics/StructuredTraceLog.h"
#include "client/mgmtd/IMgmtdClientForServer.h"
#include "client/mgmtd/RoutingInfo.h"
#include "client/storage/StorageMessenger.h"
#include "common/net/Server.h"
#include "common/net/Transport.h"
#include "common/net/ib/IBSocket.h"
#include "common/net/ib/RDMABuf.h"
#include "common/utils/Address.h"
#include "common/utils/ConfigBase.h"
#include "common/utils/Coroutine.h"
#include "common/utils/LockManager.h"
#include "common/utils/Semaphore.h"
#include "fbs/storage/Ec.h"
#include "fbs/storage/EcAuthorized.h"
#include "fbs/storage/EcStageResultV2.h"
#include "storage/aio/AioReadWorker.h"
#include "storage/ec_helper/EcHelperRuntime.h"
#include "storage/ec_scope/EcScopeControlExecutor.h"
#include "storage/service/BufferPool.h"
#include "storage/service/ReliableForwarding.h"
#include "storage/service/ReliableUpdate.h"
#include "storage/store/StorageTargets.h"
#include "storage/update/UpdateWorker.h"

namespace hf3fs::storage {

struct Components;

class StorageOperator {
 public:
  class Config : public ConfigBase<Config> {
    CONFIG_OBJ(write_worker, UpdateWorker::Config);
    CONFIG_OBJ(event_trace_log, analytics::StructuredTraceLog<StorageEventTrace>::Config);
    CONFIG_HOT_UPDATED_ITEM(max_num_results_per_query, uint32_t{100});
    CONFIG_HOT_UPDATED_ITEM(batch_read_job_split_size, uint32_t{1024});
    CONFIG_HOT_UPDATED_ITEM(post_buffer_per_bytes, 64_KB);
    CONFIG_HOT_UPDATED_ITEM(batch_read_ignore_chain_version, false);
    CONFIG_HOT_UPDATED_ITEM(max_concurrent_rdma_writes, 256U);
    CONFIG_HOT_UPDATED_ITEM(max_concurrent_rdma_reads, 256U);
    CONFIG_HOT_UPDATED_ITEM(read_only, false);
    CONFIG_HOT_UPDATED_ITEM(rdma_transmission_req_timeout, 0_ms);
    CONFIG_HOT_UPDATED_ITEM(apply_transmission_before_getting_semaphore, true);
    CONFIG_ITEM(enable_ec_fragments, false);
    CONFIG_ITEM(allow_unsafe_ec_fragment_rpc_for_testing, false);
    CONFIG_ITEM(ec_capability_key_file, Path{});
    CONFIG_ITEM(enable_ec_helpers, false);
    CONFIG_ITEM(ec_helper_key_file, Path{});
    CONFIG_ITEM(enable_ec_scope_control, false);
    CONFIG_ITEM(ec_scope_control_key_file, Path{});
    CONFIG_ITEM(ec_scope_control_authority, std::string{});
    CONFIG_ITEM(max_concurrent_ec_requests, 8u, [](auto value) { return value > 0 && value <= 64; });
    CONFIG_ITEM(ec_scope_load_wait_ms, 250u, [](auto value) { return value <= 1000; });
  };

  StorageOperator(const Config &config, Components &components)
      : config_(config),
        components_(components),
        updateWorker_(config_.write_worker()),
        storageEventTrace_(config.event_trace_log()) {
    for (const auto &ibdev : net::IBDevice::all()) {
      concurrentRdmaWriteSemaphore_.emplace(ibdev->id(), config.max_concurrent_rdma_writes());
      concurrentRdmaReadSemaphore_.emplace(ibdev->id(), config.max_concurrent_rdma_reads());
    }

    onConfigUpdated_ = config_.addCallbackGuard([this]() {
      for (auto &[_, semaphore] : concurrentRdmaWriteSemaphore_) {
        semaphore.changeUsableTokens(config_.max_concurrent_rdma_writes());
      }
      for (auto &[_, semaphore] : concurrentRdmaReadSemaphore_) {
        semaphore.changeUsableTokens(config_.max_concurrent_rdma_reads());
      }
    });
  }

  Result<Void> init(uint32_t numberOfDisks);

  Result<Void> stopAndJoin();

  CoTryTask<BatchReadRsp> batchRead(ServiceRequestContext &requestCtx,
                                    const BatchReadReq &req,
                                    serde::CallContext &ctx);

  CoTryTask<WriteRsp> write(ServiceRequestContext &requestCtx, const WriteReq &req, net::IBSocket *ibSocket);

  CoTryTask<UpdateRsp> update(ServiceRequestContext &requestCtx, const UpdateReq &req, net::IBSocket *ibSocket);

  CoTryTask<QueryLastChunkRsp> queryLastChunk(ServiceRequestContext &requestCtx, const QueryLastChunkReq &req);

  CoTryTask<TruncateChunksRsp> truncateChunks(ServiceRequestContext &requestCtx, const TruncateChunksReq &req);

  CoTryTask<RemoveChunksRsp> removeChunks(ServiceRequestContext &requestCtx, const RemoveChunksReq &req);

  CoTryTask<TargetSyncInfo> syncStart(const SyncStartReq &req);

  CoTryTask<SyncDoneRsp> syncDone(const SyncDoneReq &req);

  CoTryTask<SpaceInfoRsp> spaceInfo(const SpaceInfoReq &req);

  CoTryTask<CreateTargetRsp> createTarget(const CreateTargetReq &req);

  CoTryTask<EcCreateTargetRsp> createEcTarget(const EcCreateTargetReq &req);
  CoTryTask<EcCreateRsp> createEcFragment(const EcCreateReq &req);
  CoTryTask<EcReadRsp> readEcFragment(const EcReadReq &req);
  CoTryTask<EcReconcileRsp> reconcileEcFragment(const EcReconcileReq &req);
  CoTryTask<EcCreateRsp> authorizedCreateEcFragment(const EcAuthorizedCreateReq &req);
  CoTryTask<EcReadRsp> authorizedReadEcFragment(const EcAuthorizedReadReq &req);
  CoTryTask<EcReconcileRsp> authorizedReconcileEcFragment(const EcAuthorizedReconcileReq &req);

  CoTryTask<EcHelperHopRsp> executeEcHelper(const EcHelperHopReq &request);
  CoTryTask<EcScopeControlRsp> revokeEcScope(const EcScopeControlRequest &req);
  CoTryTask<EcScopeControlRsp> queryEcScopeDrain(const EcScopeControlRequest &req);

  CoTryTask<EcReadBlockV2Rsp> readEcBlockV2(const EcReadBlockV2Req &request);
  CoTryTask<EcStageV2Rsp> beginEcStageV2(const EcBeginStageV2Req &request);
  CoTryTask<EcStageV2Rsp> appendEcStageV2(const EcAppendStageV2Req &request);
  CoTryTask<EcStageV2Rsp> queryEcStageV2(const EcQueryStageV2Req &request);
  CoTryTask<EcStageV2Rsp> reconcileEcStageV2(const EcReconcileStageV2Req &request);
  CoTryTask<EcSealStageV2Rsp> sealEcStageV2(const EcSealStageV2Req &request);

  CoTryTask<OfflineTargetRsp> offlineTarget(const OfflineTargetReq &req);

  CoTryTask<RemoveTargetRsp> removeTarget(const RemoveTargetReq &req);

  CoTryTask<QueryChunkRsp> queryChunk(const QueryChunkReq &req);

  CoTryTask<GetAllChunkMetadataRsp> getAllChunkMetadata(const GetAllChunkMetadataReq &req);

 protected:
  using ChunkMetadataProcessor = std::function<CoTryTask<void>(const ChunkId &, const ChunkMetadata &)>;

  CoTask<IOResult> handleUpdate(ServiceRequestContext &requestCtx,
                                UpdateReq &req,
                                net::IBSocket *ibSocket,
                                TargetPtr &target);

  CoTask<IOResult> doUpdate(ServiceRequestContext &requestCtx,
                            const UpdateIO &updateIO,
                            const UpdateOptions &updateOptions,
                            uint32_t featureFlags,
                            const std::shared_ptr<StorageTarget> &target,
                            net::IBSocket *ibSocket,
                            BufferPool::Buffer &buffer,
                            net::RDMARemoteBuf &remoteBuf,
                            ChunkEngineUpdateJob &chunkEngineJob,
                            bool allowToAllocate);

  CoTask<IOResult> doCommit(ServiceRequestContext &requestCtx,
                            const CommitIO &commitIO,
                            const UpdateOptions &updateOptions,
                            ChunkEngineUpdateJob &chunkEngineJob,
                            uint32_t featureFlags,
                            const std::shared_ptr<StorageTarget> &target);

  Result<std::vector<std::pair<ChunkId, ChunkMetadata>>> doQuery(ServiceRequestContext &requestCtx,
                                                                 const VersionedChainId &vChainId,
                                                                 const ChunkIdRange &chunkIdRange);

  CoTryTask<uint32_t> processQueryResults(ServiceRequestContext &requestCtx,
                                          const VersionedChainId &vChainId,
                                          const ChunkIdRange &chunkIdRanges,
                                          ChunkMetadataProcessor processor,
                                          bool &moreChunksInRange);

  CoTask<IOResult> doTruncate(ServiceRequestContext &requestCtx,
                              const TruncateChunkOp &op,
                              flat::UserInfo userInfo,
                              uint32_t featureFlags);

  CoTask<IOResult> doRemove(ServiceRequestContext &requestCtx,
                            const RemoveChunksOp &op,
                            flat::UserInfo userInfo,
                            uint32_t featureFlags);

 private:
  friend class ReliableUpdate;
  friend class StorageEcAuthorizationTestAccess;
  friend class StorageEcStageAuthorizationTestAccess;

  Result<Void> initEcHelpers();
  CoTryTask<EcHelperHopResult> executeEcHelperOwned(EcHelperHopReq, std::chrono::steady_clock::time_point receivedAt);
  std::unique_ptr<EcHelperRuntime> ecHelpers_;

  Result<Void> initEcScopeControl();
  CoTryTask<EcScopeControlRsp> controlEcScope(const EcScopeControlRequest &, EcScopeControlAction);
  std::unique_ptr<EcScopeControlExecutor> ecScopeControl_;

  using EcStageExecution = std::pair<EcStageResult, EcScopeTargetIdentity>;
  template <typename Request>
  CoTryTask<EcStageExecution> executeEcStageV2(const Request &, EcStageOperation);
  template <typename Request>
  CoTryTask<EcStageV2Rsp> stageStateV2(const Request &, EcStageOperation);

  Result<TargetPtr> ecTarget(VersionedChainId chain, TargetId targetId, bool writing) const;
  Result<Void> validateEcTarget(const TargetPtr &expected, bool writing) const;
  using EcValidation = std::function<Result<Void>()>;
  Result<Void> validateUnsafeEcAccess() const;
  EcValidation ecAuthorization(const EcCapability &grant, EcGrantBinding expected, EcGrantRight right) const;
  CoTryTask<EcCreateRsp> createEcFragmentImpl(const EcCreateReq &req, EcValidation authorization);
  CoTryTask<EcReadRsp> readEcFragmentImpl(const EcReadReq &req, EcValidation authorization);
  CoTryTask<EcReconcileRsp> reconcileEcFragmentImpl(const EcReconcileReq &req, EcValidation authorization);
  std::function<uint64_t()> ecAuthorizationNow_ = [] {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  };

  ConstructLog<"storage::StorageOperator"> constructLog_;
  const Config &config_;
  Components &components_;
  UpdateWorker updateWorker_;
  analytics::StructuredTraceLog<StorageEventTrace> storageEventTrace_;
  std::unique_ptr<ConfigCallbackGuard> onConfigUpdated_;
  std::map<uint8_t, hf3fs::Semaphore> concurrentRdmaWriteSemaphore_;
  std::map<uint8_t, hf3fs::Semaphore> concurrentRdmaReadSemaphore_;
  std::atomic<uint64_t> totalReadBytes_{};
  std::atomic<uint64_t> totalReadIOs_{};
  Semaphore ecFragmentSemaphore_{config_.max_concurrent_ec_requests(), 64};
};

}  // namespace hf3fs::storage
