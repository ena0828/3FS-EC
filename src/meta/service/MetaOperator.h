#pragma once

#include <arrow/util/macros.h>
#include <atomic>
#include <folly/Likely.h>
#include <folly/Utility.h>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/functional/Invoke.h>
#include <folly/logging/xlog.h>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "client/mgmtd/ICommonMgmtdClient.h"
#include "client/mgmtd/IMgmtdClientForServer.h"
#include "client/storage/EcRmwTransport.h"
#include "client/storage/StorageClient.h"
#include "common/kv/IKVEngine.h"
#include "common/kv/ITransaction.h"
#include "common/kv/WithTransaction.h"
#include "common/utils/BackgroundRunner.h"
#include "common/utils/CPUExecutorGroup.h"
#include "common/utils/Coroutine.h"
#include "common/utils/CoroutinesPool.h"
#include "common/utils/Result.h"
#include "core/user/UserStoreEx.h"
#include "fbs/meta/Common.h"
#include "fbs/meta/Service.h"
#include "fdb/FDBRetryStrategy.h"
#include "meta/base/Config.h"
#include "meta/components/ChainAllocator.h"
#include "meta/components/Distributor.h"
#include "meta/components/EcCoordinator.h"
#include "meta/components/EcGcAdminCoordinator.h"
#include "meta/components/EcTargetRetirementCoordinator.h"
#include "meta/components/EcRmwPlanIssuer.h"
#include "meta/components/EcRmwPublicationVerifier.h"
#include "meta/components/EcV2Coordinator.h"
#include "meta/components/FileHelper.h"
#include "meta/components/Forward.h"
#include "meta/components/GcManager.h"
#include "meta/components/SessionManager.h"
#include "meta/store/Inode.h"
#include "meta/store/MetaStore.h"
#include "meta/store/ops/BatchOperation.h"

namespace hf3fs::meta::server {

class BatchedOp;

class MetaOperator : public folly::NonCopyableNonMovable {
 public:
  MetaOperator(const Config &cfg,
               flat::NodeId nodeId,
               std::shared_ptr<kv::IKVEngine> kvEngine,
               std::shared_ptr<client::ICommonMgmtdClient> mgmtdClient,
               std::shared_ptr<storage::client::StorageClient> storageClient,
               std::unique_ptr<Forward> forward);

  CoTryTask<void> init(std::optional<Layout> rootLayout);

  void start(CPUExecutorGroup &exec);
  void beforeStop();
  void afterStop();

  CoTryTask<AuthRsp> authenticate(AuthReq req);
  CoTryTask<BindEcRmwOutputRsp> bindEcRmwOutput(BindEcRmwOutputReq req);

  CoTryTask<StatFsRsp> statFs(StatFsReq req);

  CoTryTask<StatRsp> stat(StatReq req);

  CoTryTask<GetRealPathRsp> getRealPath(GetRealPathReq req);

  CoTryTask<OpenRsp> open(OpenReq req);

  CoTryTask<CloseRsp> close(CloseReq req);

  CoTryTask<CreateRsp> create(CreateReq req);
  CoTryTask<CreateEcFileRsp> createEcFile(CreateEcFileReq req);
  CoTryTask<EcOperationRsp> beginEcMutation(BeginEcMutationReq req);
  CoTryTask<EcOperationRsp> publishEcMutation(PublishEcMutationReq req);
  CoTryTask<EcOperationRsp> getEcOperation(GetEcOperationReq req);
  CoTryTask<EcOperationRsp> cancelEcMutation(CancelEcMutationReq req);
  CoTryTask<AcquireEcReadRsp> acquireEcRead(AcquireEcReadReq req);
  CoTryTask<ReleaseEcReadRsp> releaseEcRead(ReleaseEcReadReq req);
  CoTryTask<CreateEcFileRsp> createEcFileV2(CreateEcFileV2Req req);
  CoTryTask<EcV2MutationRsp> beginEcMutationV2(BeginEcMutationV2Req req);
  CoTryTask<EcV2MutationRsp> bindEcMutationV2(BindEcMutationV2Req req);
  CoTryTask<EcV2MutationRsp> publishEcMutationV2(PublishEcMutationV2Req req);
  CoTryTask<EcV2MutationRsp> getEcOperationV2(GetEcOperationV2Req req);
  CoTryTask<EcV2MutationRsp> cancelEcMutationV2(CancelEcMutationV2Req req);
  CoTryTask<AcquireEcReadV2Rsp> acquireEcReadV2(AcquireEcReadV2Req req);
  CoTryTask<ReleaseEcReadV2Rsp> releaseEcReadV2(ReleaseEcReadV2Req req);
  CoTryTask<PrepareEcRepairV2Rsp> prepareEcRepairV2(PrepareEcRepairV2Req req);
  CoTryTask<EcGcAdminRsp> collectEcFragmentV2(CollectEcFragmentV2Req req);
  CoTryTask<EcGcAdminRsp> queryEcFragmentGcV2(QueryEcFragmentGcV2Req req);
  CoTryTask<EcRevisionRetirementRsp> retireEcRevisionV2(RetireEcRevisionV2Req req);
  CoTryTask<EcRevisionRetirementRsp> queryEcRevisionRetirementV2(QueryEcRevisionRetirementV2Req req);
  CoTryTask<EcTargetRetirementRsp> prepareEcTargetRetirement(PrepareEcTargetRetirementReq req);
  CoTryTask<EcTargetRetirementRsp> queryEcTargetRetirement(QueryEcTargetRetirementReq req);
  CoTryTask<DescribeEcFileV2Rsp> describeEcFileV2(DescribeEcFileV2Req req);
  CoTryTask<EcRangeRsp> acquireEcRangeV2(AcquireEcRangeV2Req req);
  CoTryTask<EcRangeRsp> queryEcRangeV2(QueryEcRangeV2Req req);
  CoTryTask<EcOwnedMutationRsp> queryEcOwnedMutationV2(QueryEcOwnedMutationV2Req req);
  CoTryTask<OpenEcFileSessionRsp> openEcFileSession(OpenEcFileSessionReq req);
  CoTryTask<EcFilePwriteRsp> beginEcFilePwrite(BeginEcFilePwriteReq req);
  CoTryTask<EcFilePwriteRsp> queryEcFilePwrite(QueryEcFilePwriteReq req);
  CoTryTask<EcFilePwriteRsp> advanceEcFilePwrite(AdvanceEcFilePwriteReq req);
  CoTryTask<CloseEcFileSessionRsp> closeEcFileSession(CloseEcFileSessionReq req);
  CoTryTask<EcTreeReadRsp> acquireEcTreeRead(AcquireEcTreeReadReq req);
  CoTryTask<EcTreeReadRsp> queryEcTreeRead(QueryEcTreeReadReq req);
  CoTryTask<EcTreeReadRsp> releaseEcTreeRead(ReleaseEcTreeReadReq req);
  CoTryTask<AdvanceEcTreeReclaimRsp> advanceEcTreeReclaim(AdvanceEcTreeReclaimReq req);
  CoTryTask<EcFileTruncateRsp> beginEcFileTruncate(BeginEcFileTruncateReq req);
  CoTryTask<EcFileTruncateRsp> queryEcFileTruncate(QueryEcFileTruncateReq req);
  CoTryTask<EcFileTruncateRsp> advanceEcFileTruncate(AdvanceEcFileTruncateReq req);
  CoTryTask<EcFileTruncateRsp> closeEcFileTruncateDebt(CloseEcFileTruncateDebtReq req);
  CoTryTask<EcFileAppendRsp> beginEcFileAppend(BeginEcFileAppendReq req);
  CoTryTask<EcFileAppendRsp> queryEcFileAppend(QueryEcFileAppendReq req);
  CoTryTask<SyncEcFileSessionRsp> syncEcFileSession(SyncEcFileSessionReq req);
  CoTryTask<EcFileRepairRsp> beginEcFileRepair(BeginEcFileRepairReq req);
  CoTryTask<EcFileRepairRsp> queryEcFileRepair(QueryEcFileRepairReq req);
  CoTryTask<EcFileRepairRsp> advanceEcFileRepair(AdvanceEcFileRepairReq req);
  CoTryTask<EcFileRepairRsp> closeEcFileRepairDebt(CloseEcFileRepairDebtReq req);

  CoTryTask<MkdirsRsp> mkdirs(MkdirsReq req);

  CoTryTask<SymlinkRsp> symlink(SymlinkReq req);

  CoTryTask<RemoveRsp> remove(RemoveReq req);

  CoTryTask<RenameRsp> rename(RenameReq req);

  CoTryTask<ListRsp> list(ListReq req);

  CoTryTask<TruncateRsp> truncate(TruncateReq req);

  CoTryTask<SyncRsp> sync(SyncReq req);

  CoTryTask<HardLinkRsp> hardLink(HardLinkReq req);

  CoTryTask<SetAttrRsp> setAttr(SetAttrReq req);

  CoTryTask<PruneSessionRsp> pruneSession(PruneSessionReq req);

  CoTryTask<DropUserCacheRsp> dropUserCache(DropUserCacheReq req);

  CoTryTask<LockDirectoryRsp> lockDirectory(LockDirectoryReq req);

  CoTryTask<TestRpcRsp> testRpc(TestRpcReq req);

  CoTryTask<BatchStatRsp> batchStat(BatchStatReq req);

  CoTryTask<BatchStatByPathRsp> batchStatByPath(BatchStatByPathReq req);

 private:
  friend class MockMeta;

  template <typename>
  FRIEND_TEST(TestBatchOp, batch);

  template <typename>
  FRIEND_TEST(TestCreate, batch);

  class Batch {
   public:
    void setNext(BatchedOp *op, folly::coro::Baton *baton) {
      next = op;
      nextBaton = baton;
    }

    bool wakeupNext() {
      if (!next) {
        return false;
      }
      nextBaton->post();
      next = nullptr;
      nextBaton = nullptr;
      return true;
    }

    BatchedOp *getNext() const { return next; }

   private:
    BatchedOp *next = nullptr;
    folly::coro::Baton *nextBaton = nullptr;
  };

  Result<Void> initEcRmw();
  kv::FDBRetryStrategy::Config createRetryConfig() const;
  kv::FDBRetryStrategy createRetryStrategy() const { return kv::FDBRetryStrategy(createRetryConfig()); }

  template <typename Func, typename Arg>
  auto runOp(Func &&func, Arg &&arg)
      -> CoTryTask<typename std::invoke_result_t<Func, MetaStore, Arg &&>::element_type::RspT>;

  template <typename Req, typename Rsp>
  std::unique_ptr<BatchedOp> addBatchReq(InodeId inodeId, BatchedOp::Waiter<Req, Rsp> &waiter) {
    auto func = [&](auto &map) {
      auto [iter, inserted] = map.try_emplace(inodeId);
      auto &batch = iter->second;
      if (inserted) {
        assert(!batch.getNext());
        auto op = std::make_unique<BatchedOp>(*metaStore_, inodeId);
        op->add(waiter);
        waiter.baton.post();
        return op;
      } else if (!batch.getNext()) {
        auto op = std::make_unique<BatchedOp>(*metaStore_, inodeId);
        op->add(waiter);
        batch.setNext(op.get(), &waiter.baton);
        return op;
      } else {
        auto next = batch.getNext();
        auto num_reqs = next->numReqs();
        if (UNLIKELY(config_.max_batch_operations() != 0 && num_reqs >= config_.max_batch_operations())) {
          auto msg = fmt::format("too many batch operations on {}", inodeId);
          XLOG(WARN, msg);
          waiter.result = makeError(MetaCode::kBusy, std::move(msg));
          waiter.baton.post();
        } else {
          if (num_reqs && num_reqs % 1024 == 0) {
            XLOGF(WARN, "{} batch operations on {}", num_reqs, inodeId);
          }
          next->add(waiter);
        }
        return std::unique_ptr<BatchedOp>();
      }
    };
    return batches_.withLock(func, inodeId);
  }

  CoTryTask<Inode> runBatch(InodeId inodeId,
                            std::unique_ptr<BatchedOp> op,
                            std::optional<SteadyTime> deadline = std::nullopt);

  template <typename Req, typename Rsp>
  CoTryTask<Rsp> runInBatch(InodeId inodeId, Req req);

  CoTryTask<void> authenticate(UserInfo &userInfo);
  CoTryTask<void> authenticateEc(ReqBase &req);
  CoTryTask<void> authenticateEcV2(ReqBase &req);
  CoTryTask<void> authenticateEcGcAdmin(ReqBase &req);
  CoTryTask<void> authenticateEcRevisionRetirement(EcRevisionRetirementReq &req);
  CoTryTask<void> authenticateEcTargetRetirement(EcTargetRetirementReq &req);
  CoTryTask<void> authenticateEcFileRange(ReqBase &req);
  CoTryTask<void> authenticateEcFileSession(ReqBase &req);
  CoTryTask<EcV2DrainRecord> advanceEcV2Drain(const EcOperationReq &, EcV2DrainRecord);

  const Config &config_;
  flat::NodeId nodeId_;
  analytics::StructuredTraceLog<MetaEventTrace> metaEventTraceLog_;
  std::shared_ptr<kv::IKVEngine> kvEngine_;
  std::shared_ptr<client::ICommonMgmtdClient> mgmtd_;
  std::shared_ptr<Distributor> distributor_;
  std::shared_ptr<core::UserStoreEx> userStore_;
  std::shared_ptr<InodeIdAllocator> inodeIdAlloc_;
  std::shared_ptr<ChainAllocator> chainAlloc_;
  std::shared_ptr<FileHelper> fileHelper_;
  std::shared_ptr<SessionManager> sessionManager_;
  std::shared_ptr<GcManager> gcManager_;
  std::unique_ptr<Forward> forward_;

  std::unique_ptr<MetaStore> metaStore_;
  std::unique_ptr<EcCoordinator> ecCoordinator_;
  std::unique_ptr<EcV2Coordinator> ecV2Coordinator_;
  std::unique_ptr<EcGcAdminCoordinator> ecGcAdmin_;
  std::unique_ptr<EcTargetRetirementCoordinator> ecTargetRetirement_;
  std::shared_ptr<storage::client::StorageClient> ecRmwStorage_;
  std::shared_ptr<storage::client::EcRmwTransport> ecRmwTransport_;
  std::shared_ptr<EcRmwPlanIssuer> ecRmwIssuer_;
  std::shared_ptr<EcRmwPublicationVerifier> ecRmwVerifier_;

  Shards<std::map<InodeId, Batch>, 63> batches_;

  std::atomic_bool stop_{false};
  std::unique_ptr<BackgroundRunner> bgRunner_;
};
}  // namespace hf3fs::meta::server
