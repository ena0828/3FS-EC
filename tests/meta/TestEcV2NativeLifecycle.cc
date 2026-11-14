#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <folly/Random.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Collect.h>
#include <folly/experimental/coro/Sleep.h>
#include <fstream>
#include <linux/magic.h>
#include <mutex>
#include <optional>
#include <bit>
#include <condition_variable>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "client/bin/EcRepairMetricsJson.h"
#include "client/ec/EcFileAppendClient.h"
#include "client/ec/EcFileRepairClient.h"
#include "client/ec/EcFileRunFactory.h"
#include "client/ec/EcReadDispatcher.h"
#include "client/ec/EcStripeClient.h"
#include "client/ec/EcStripeRecoveryWrite.h"
#include "client/ec/EcTruncateJournal.h"
#include "client/meta/MetaClient.h"
#include "client/storage/EcRmwTransport.h"
#include "common/kv/KeyPrefix.h"
#include "common/net/Client.h"
#include "common/net/Server.h"
#include "common/utils/SerDeser.h"
#include "core/user/UserStore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/storage/EcAuthorizedV2.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "fdb/FDBKVEngine.h"
#include "fuse/EcFileMount.h"
#include "meta/components/NativeEcGcTransport.h"
#include "meta/service/MetaSerdeService.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/EcFileExecutionCatalog.h"
#include "meta/store/EcFileTruncateCatalog.h"
#include "meta/store/EcNamespaceGuard.h"
#include "meta/store/EcOwnedMutationCatalog.h"
#include "meta/store/EcRangeCatalog.h"
#include "meta/store/EcRevisionRetirementCatalog.h"
#include "meta/store/EcTargetRetirementCatalog.h"
#include "meta/store/EcTerminalEvidence.h"
#include "meta/store/EcV2GcCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "meta/store/EcV2RepairPlanCatalog.h"
#include "meta/store/EcV2PublishedCatalog.h"
#include "meta/store/Inode.h"
#include "meta/store/detail/EcFileTreeKeys.h"
#include "storage/ec_codec/EcCodec.h"
#include "storage/ec_repair/EcHelperDirectAuthorization.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"
#include "tests/lib/UnitTestFabric.h"
#include "tests/meta/EcNativeTxnObservation.h"
#include "tests/meta/EcPendingWriteFault.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;

void smallThreads(net::ThreadPoolGroup::Config &config) {
  config.set_num_proc_threads(2);
  config.set_num_io_threads(1);
  config.set_num_bg_threads(1);
  config.set_num_connect_threads(1);
}

void smallClient(net::Client::Config &config) {
  smallThreads(config.thread_pool());
  config.processor().set_max_processing_requests_num(16);
  config.processor().set_max_coroutines_num(16);
  config.processor().set_response_compression_level(0);
  config.set_default_timeout(20_s);
}

struct PublishReplyDrop {
  std::shared_ptr<detail::EcMountedTruncateFault> mountedTruncate;
  bool mountedDropBegin = false;
  size_t mountedBeginDrops = 0;
  int mountedShutdownResult = -1;
  bool mountedShutdownFinished = false;
  std::condition_variable mountedChanged;
  struct State {
    size_t calls = 0;
    std::optional<EcOperationRecord> committed;
  };
  void arm(const Uuid &operation) {
    std::lock_guard lock(mutex);
    armed = operation;
    state = {};
  }
  State snapshot() const {
    std::lock_guard lock(mutex);
    return state;
  }
  mutable std::mutex mutex;
  Uuid armed = Uuid::zero();
  State state;
  Uuid retirementArmed = Uuid::zero();
  size_t retirementCalls = 0;
  std::optional<EcRevisionRetirementRsp> retirementCommitted;
  Uuid rangeArmed = Uuid::zero();
  size_t rangeCalls = 0;
  std::optional<EcRangeRsp> rangeCommitted;
  Uuid ownerBeginArmed = Uuid::zero(), ownerQueryArmed = Uuid::zero();
  size_t ownerBeginCalls = 0, ownerQueryCalls = 0;
  std::optional<EcV2MutationRsp> ownerBeginCommitted;
  // File-client recovery seam: lose a bounded number of actual committed
  // replies, including retries of that same operation. Never fabricate state.
  Uuid fileBeginDropOperation = Uuid::zero(), filePublishDropOperation = Uuid::zero();
  Uuid fileTreePublishDropChild = Uuid::zero();
  size_t fileTreeRepliesDropped = 0;
  Uuid truncateDropOperation = Uuid::zero();
  size_t truncateRepliesDropped = 0;
  size_t fileBeginRepliesToDrop = 0, filePublishRepliesToDrop = 0;
  Uuid directPrepareDropOperation = Uuid::zero();
  size_t directPrepareRepliesDropped = 0;
  int directShutdownResult = -1;
  bool directShutdownObserved = false;
  std::condition_variable directChanged;
  std::optional<EcFileRepairDirectRsp> directPrepared;
  Uuid flatDirectDropOperation = Uuid::zero();
  size_t flatDirectDrops = 0;
  int flatDirectShutdown = -1;
  bool flatDirectFinished = false;
  std::optional<PrepareEcRepairDirectV2Rsp> flatDirectPrepared;
};

// The real operator has returned from its FDB commit before this one-shot
// connection fault. No fabricated success, receipt or transaction is supplied.
class DropPublishMetaService : public MetaSerdeService {
 public:
  DropPublishMetaService(MetaOperator &meta, PublishReplyDrop &fault)
      : MetaSerdeService(meta),
        fault_(fault) {}

  CoTryTask<EcFileTruncateRsp> queryEcFileTruncate(serde::CallContext &ctx, const QueryEcFileTruncateReq &req) {
    const auto trace = fault_.mountedTruncate;
    const auto event = trace ? trace->enter(detail::EcMountedTruncateFault::Method::Query, req.intent, req.uuid)
                             : detail::EcMountedTruncateFault::kIgnored;
    auto response = co_await MetaSerdeService::queryEcFileTruncate(ctx, req);
    if (trace) trace->finish(event, response ? StatusCode::kOK : response.error().code());
    co_return response;
  }
  CoTryTask<EcFileTruncateRsp> beginEcFileTruncate(serde::CallContext &ctx, const BeginEcFileTruncateReq &req) {
    const auto trace = fault_.mountedTruncate;
    const auto event = trace ? trace->enter(detail::EcMountedTruncateFault::Method::Begin, req.intent, req.uuid)
                             : detail::EcMountedTruncateFault::kIgnored;
    auto response = co_await MetaSerdeService::beginEcFileTruncate(ctx, req);
    if (trace) trace->finish(event, response ? StatusCode::kOK : response.error().code());
    bool drop = false;
    if (response && response->progress.observed && event != detail::EcMountedTruncateFault::kIgnored) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.mountedDropBegin) {
        fault_.mountedDropBegin = false;
        drop = true;
        ++fault_.mountedBeginDrops;
      }
    }
    if (drop) {
      const auto transport = ctx.transport();
      int result = -1;
      if (transport->isTCP()) {
        const auto &handler = static_cast<const net::EventLoop::EventHandler &>(*transport);
        result = ::shutdown(handler.fd(), SHUT_RDWR);
      }
      transport->invalidate(false);
      {
        std::lock_guard lock(fault_.mutex);
        fault_.mountedShutdownResult = result;
        fault_.mountedShutdownFinished = true;
      }
      fault_.mountedChanged.notify_all();
    }
    co_return response;
  }
  CoTryTask<EcFileTruncateRsp> closeEcFileTruncateDebt(serde::CallContext &ctx,
                                                     const CloseEcFileTruncateDebtReq &req) {
    const auto trace = fault_.mountedTruncate;
    const auto event = trace ? trace->enter(detail::EcMountedTruncateFault::Method::Close, req.intent, req.uuid)
                             : detail::EcMountedTruncateFault::kIgnored;
    auto response = co_await MetaSerdeService::closeEcFileTruncateDebt(ctx, req);
    if (trace) trace->finish(event, response ? StatusCode::kOK : response.error().code());
    co_return response;
  }

  CoTryTask<EcFileRepairDirectRsp> prepareEcFileRepairDirect(
      serde::CallContext &ctx, const PrepareEcFileRepairDirectReq &req) {
    auto response = co_await MetaSerdeService::prepareEcFileRepairDirect(ctx, req);
    bool drop = false;
    if (response && response->access && response->progress.record) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.directPrepareDropOperation == req.intent.operation) {
        fault_.directPrepareDropOperation = Uuid::zero();
        ++fault_.directPrepareRepliesDropped;
        fault_.directPrepared = *response;
        drop = true;
      }
    }
    if (drop) {
      // The real Prepare returned its committed issuance. End this actual TCP
      // connection before a response can be sent, without inventing an error.
      const auto transport = ctx.transport();
      int result = -1;
      if (transport->isTCP()) {
        const auto &handler = static_cast<const net::EventLoop::EventHandler &>(*transport);
        result = ::shutdown(handler.fd(), SHUT_RDWR);
      }
      transport->invalidate(false);
      {
        std::lock_guard lock(fault_.mutex);
        fault_.directShutdownResult = result;
        fault_.directShutdownObserved = true;
      }
      fault_.directChanged.notify_all();
    }
    co_return response;
  }

  CoTryTask<EcFileTruncateRsp> advanceEcFileTruncate(serde::CallContext &ctx, const AdvanceEcFileTruncateReq &req) {
    const auto trace = fault_.mountedTruncate;
    const auto event = trace ? trace->enter(detail::EcMountedTruncateFault::Method::Advance, req.intent, req.uuid)
                             : detail::EcMountedTruncateFault::kIgnored;
    auto response = co_await MetaSerdeService::advanceEcFileTruncate(ctx, req);
    if (trace) trace->finish(event, response ? StatusCode::kOK : response.error().code());
    bool drop = false;
    if (response && response->progress.observed &&
        response->progress.observed->state == EcFileTruncateState::Published) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.truncateDropOperation == req.intent.operation) {
        fault_.truncateDropOperation = Uuid::zero();
        ++fault_.truncateRepliesDropped;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<EcFilePwriteRsp> advanceEcFilePwrite(serde::CallContext &ctx, const AdvanceEcFilePwriteReq &req) {
    auto response = co_await MetaSerdeService::advanceEcFilePwrite(ctx, req);
    bool drop = false;
    if (response && req.action == EcFileAdvanceAction::Publish && response->progress.child &&
        response->progress.child->state == EcFileChildState::Published) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.fileTreePublishDropChild == req.child) {
        fault_.fileTreePublishDropChild = Uuid::zero();
        ++fault_.fileTreeRepliesDropped;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<EcV2MutationRsp> publishEcMutationV2(serde::CallContext &ctx, const PublishEcMutationV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.calls;
    }
    auto response = co_await MetaSerdeService::publishEcMutationV2(ctx, req);
    bool drop = false;
    if (response && response->record.state == EcOperationState::Published) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.armed == req.operation) {
        fault_.armed = Uuid::zero();
        fault_.state.committed = response->record;
        drop = true;
      }
      if (fault_.filePublishDropOperation == req.operation && fault_.filePublishRepliesToDrop) {
        --fault_.filePublishRepliesToDrop;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<PrepareEcRepairDirectV2Rsp> prepareEcRepairDirectV2(
      serde::CallContext &ctx, const PrepareEcRepairDirectV2Req &req) {
    auto response = co_await MetaSerdeService::prepareEcRepairDirectV2(ctx, req);
    bool drop = false;
    if (response && response->delegation) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.flatDirectDropOperation == req.operation) {
        fault_.flatDirectDropOperation = Uuid::zero();
        fault_.flatDirectPrepared = *response;
        ++fault_.flatDirectDrops;
        drop = true;
      }
    }
    if (drop) {
      const auto transport = ctx.transport();
      int result = -1;
      if (transport->isTCP()) {
        const auto &handler = static_cast<const net::EventLoop::EventHandler &>(*transport);
        result = ::shutdown(handler.fd(), SHUT_RDWR);
      }
      transport->invalidate(false);
      {
        std::lock_guard lock(fault_.mutex);
        fault_.flatDirectShutdown = result;
        fault_.flatDirectFinished = true;
      }
      fault_.directChanged.notify_all();
    }
    co_return response;
  }

  CoTryTask<PrepareEcRepairV2Rsp> prepareEcRepairV2(serde::CallContext &ctx, const PrepareEcRepairV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.calls;
    }
    auto response = co_await MetaSerdeService::prepareEcRepairV2(ctx, req);
    bool drop = false;
    if (response) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.armed == req.operation) {
        fault_.armed = Uuid::zero();
        fault_.state.committed = response->mutation.record;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<EcRevisionRetirementRsp> retireEcRevisionV2(serde::CallContext &ctx, const RetireEcRevisionV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.retirementCalls;
    }
    auto response = co_await MetaSerdeService::retireEcRevisionV2(ctx, req);
    bool drop = false;
    if (response) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.retirementArmed == req.uuid) {
        fault_.retirementArmed = Uuid::zero();
        fault_.retirementCommitted = *response;
        drop = true;
      }
    }
    // Real FDB retirement committed before this one-shot lost RPC response.
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<EcV2MutationRsp> beginEcMutationV2(serde::CallContext &ctx, const BeginEcMutationV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.ownerBeginCalls;
    }
    auto response = co_await MetaSerdeService::beginEcMutationV2(ctx, req);
    bool drop = false;
    if (response) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.ownerBeginArmed == req.operation) {
        fault_.ownerBeginArmed = Uuid::zero();
        fault_.ownerBeginCommitted = *response;
        drop = true;
      }
      if (fault_.fileBeginDropOperation == req.operation && fault_.fileBeginRepliesToDrop) {
        --fault_.fileBeginRepliesToDrop;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }
  CoTryTask<EcOwnedMutationRsp> queryEcOwnedMutationV2(serde::CallContext &ctx, const QueryEcOwnedMutationV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.ownerQueryCalls;
    }
    auto response = co_await MetaSerdeService::queryEcOwnedMutationV2(ctx, req);
    bool drop = false;
    if (response) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.ownerQueryArmed == req.uuid) {
        fault_.ownerQueryArmed = Uuid::zero();
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

  CoTryTask<EcRangeRsp> acquireEcRangeV2(serde::CallContext &ctx, const AcquireEcRangeV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.rangeCalls;
    }
    auto response = co_await MetaSerdeService::acquireEcRangeV2(ctx, req);
    bool drop = false;
    if (response) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.rangeArmed == req.uuid) {
        fault_.rangeArmed = Uuid::zero();
        fault_.rangeCommitted = *response;
        drop = true;
      }
    }
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = DropPublishMetaService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<MetaSerde<U>>;

 private:
  PublishReplyDrop &fault_;
};

struct ControlFailure {
  std::mutex mutex;
  Uuid scope = Uuid::zero();
  bool fail = false;
  size_t actualRevokes = 0;
  Uuid observedRepair = Uuid::zero();
  std::array<size_t, 12> actualPartialReconciles{};
  std::array<uint16_t, 10> actualHelperBlocks{};
  Uuid dropGcCollectReply = Uuid::zero();
  size_t actualGcCollects = 0;
  size_t actualGcQueries = 0;
  std::optional<storage::EcGcAck> observedGcCollect;
};
// Only replaces a real, already durable control response with an error. It
// cannot fabricate a positive ACK, and does not skip the actual revoke.
// Stage/helper overrides only observe successful real handlers.
class ControlFailureStorageService : public storage::StorageService {
 public:
  ControlFailureStorageService(storage::StorageOperator &op, ControlFailure &fault)
      : StorageService(op),
        fault_(fault) {}
  CoTryTask<storage::EcScopeControlRsp> revokeEcScope(serde::CallContext &ctx,
                                                      const storage::EcScopeControlRequest &req) {
    auto response = co_await storage::StorageService::revokeEcScope(ctx, req);
    if (response && response->result) {
      std::lock_guard lock(fault_.mutex);
      ++fault_.actualRevokes;
      if (fault_.fail && fault_.scope == req.claims.scopeId)
        co_return makeError(StatusCode::kNotImplemented, "test fault after actual durable revoke");
    }
    co_return response;
  }
  CoTryTask<storage::EcGcRsp> exchangeEcGc(serde::CallContext &ctx, const storage::EcGcRequest &req) {
    auto response = co_await storage::StorageService::exchangeEcGc(ctx, req);
    bool drop = false;
    if (response && response->result) {
      std::lock_guard lock(fault_.mutex);
      if (req.claims.action == storage::EcGcAction::Collect) {
        ++fault_.actualGcCollects;
        fault_.observedGcCollect = *response->result;
        if (fault_.dropGcCollectReply == req.claims.certificate.claimId) {
          fault_.dropGcCollectReply = Uuid::zero();
          drop = true;
        }
      } else {
        ++fault_.actualGcQueries;
      }
    }
    // Same connection-loss seam as Publish above: the real authenticated
    // handler and Rust/WAL confirmation finish before the reply is lost.
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }
  CoTryTask<storage::EcStageV2Rsp> reconcileEcStageV2(serde::CallContext &ctx,
                                                      const storage::EcReconcileStageV2Req &req) {
    auto response = co_await storage::StorageService::reconcileEcStageV2(ctx, req);
    if (response && response->result && response->result->state == 1 &&
        response->result->prefixBytes == storage::kEcIntegrityBlockBytes && !response->result->needsReconcile) {
      std::lock_guard lock(fault_.mutex);
      if (req.request.operationId == fault_.observedRepair && req.request.identity.shard < 12)
        ++fault_.actualPartialReconciles[req.request.identity.shard];
    }
    co_return response;
  }
  CoTryTask<storage::EcHelperHopRsp> executeEcHelper(serde::CallContext &ctx, const storage::EcHelperHopReq &req) {
    auto response = co_await storage::StorageService::executeEcHelper(ctx, req);
    if (response && response->result) {
      std::lock_guard lock(fault_.mutex);
      if (req.plan.operationId == fault_.observedRepair && req.packet.nextHelper < 10 && req.packet.blockIndex < 16)
        fault_.actualHelperBlocks[req.packet.nextHelper] |= uint16_t(1u << req.packet.blockIndex);
    }
    co_return response;
  }

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = ControlFailureStorageService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<storage::StorageSerde<U>>;

 private:
  ControlFailure &fault_;
};

// Functional integration, not a durability/power-loss or throughput benchmark.
// Meta and Storage use real TCP Serde clients/services, actual private FDB and
// one actual Rust Engine. Only the mgmtd routing provider is a test double.
// Twelve targets/chains share one process, disk and failure domain; this is
// explicitly permitted by ec_allow_colocated_test_targets, not production
// placement. An Engine is opened per disk path, not per logical target.
class TestEcV2NativeLifecycle : public hf3fs::testing::SetupFDB {
 protected:
  static constexpr uint32_t kShardBytes = 4096;
  virtual uint32_t ecAdmissionLimit() const { return 2; }
  virtual bool enableHelperIssuance() const { return false; }
  virtual bool enableExactGc() const { return false; }
  virtual bool enableMetaGcAdmin() const { return false; }
  virtual bool enableTargetRetirement() const { return false; }
  virtual bool enableFileRmw() const { return false; }
  virtual bool enableMountedTruncateFault() const { return false; }
  struct Mutation {
    std::string logical;
    storage::EcCodec::Shards shards;
    BeginEcMutationV2Req begin;
    EcV2MutationRsp reservation;
    PublishEcMutationV2Req publish;
    BindEcMutationV2Req bind;
  };

  void SetUp() override {
    const char *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
    if (!cluster || !*cluster) GTEST_SKIP() << "Requires a runner-owned private EC_CATALOG_TEST_CLUSTER";
    ASSERT_NO_FATAL_FAILURE(validatePrivateCluster(cluster));
    struct statfs fs {};
    ASSERT_EQ(::statfs(data_.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, EXT4_SUPER_MAGIC) << "Set TMPDIR to local ext4 for the Rust Engine";
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    const auto initialFds = openFds();
    ASSERT_GE(limit.rlim_cur, 16384u) << "Set the test process soft nofile limit to at least 16384";
    ASSERT_GE(limit.rlim_cur, initialFds + 8192u) << "Insufficient descriptor headroom for one Engine";
    RecordProperty("nofile_soft", std::to_string(limit.rlim_cur));
    RecordProperty("fds_before_engine", std::to_string(initialFds));
    RecordProperty("physical_storage_processes", "1");
    RecordProperty("physical_disk_paths", "1");
    RecordProperty("logical_ec_targets", "12");
    RecordProperty("routing_provider", "FakeMgmtdClient; no mgmtd control-plane acceptance");
    RecordProperty("transport", "MetaSerde TCP and StorageSerde TCP");

    kv::fdb::DB db(privateCluster_.string(), false);
    ASSERT_FALSE(db.error());
    kv_ = std::make_shared<kv::FDBKVEngine>(std::move(db));
    // Namespace rejection tests deliberately leave corrupt root counters in
    // this runner's database. Reset only after the strict private-cluster
    // checks above, using the same real transaction path as KvTestBase<FDB>.
    // A unique file name/incarnation alone cannot isolate root ancestor keys.
    auto reset = kv_->createReadWriteTransaction();
    ASSERT_NE(reset, nullptr);
    auto *fdb = dynamic_cast<kv::FDBTransaction *>(reset.get());
    ASSERT_NE(fdb, nullptr);
    ASSERT_OK(blockingWait(fdb->clearRange("", "\xff")));
    ASSERT_OK(blockingWait(reset->commit()));
    reset.reset();
    RecordProperty("private_fdb_reset", "user keys [empty, 0xff), before Meta initialization");
    if (enableFileRmw()) {
      txnObservation_ = std::make_shared<detail::EcNativeTxnObservation>();
      if (enableMountedTruncateFault()) replyDrop_.mountedTruncate = std::make_shared<detail::EcMountedTruncateFault>();
      kv_ = std::make_shared<detail::EcObservedNativeEngine>(kv_, txnObservation_, replyDrop_.mountedTruncate);
    }
    ASSERT_NO_FATAL_FAILURE(writeKey());
    ASSERT_NO_FATAL_FAILURE(startStorage());
    RecordProperty("fds_with_engine", std::to_string(openFds()));
    ASSERT_NO_FATAL_FAILURE(startMeta());
  }

  void TearDown() override {
    if (metaClient_) metaClient_->stop();
    if (metaServer_) metaServer_->stopAndJoin();
    if (metaNet_) metaNet_->stopAndJoin();
    metaClient_.reset();
    metaNet_.reset();
    metaServer_.reset();
    if (meta_ && metaInitialized_) {
      meta_->beforeStop();
      meta_->afterStop();
    }
    meta_.reset();
    if (storageClient_) storageClient_->stop();
    if (storageServer_) storageServer_->stopAndJoin();
    if (components_ && storageInitialized_) {
      auto stopped = components_->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped) << stopped.error().describe();
    }
    storageClient_.reset();
    storageServer_.reset();
    if (components_) {
      auto map = components_->targetMap.release();
      if (map) {
        for (const auto &[id, target] : map->getTargets()) {
          if (target.storageTarget) {
            auto released = target.storageTarget->release();
            EXPECT_TRUE(released) << released.error().describe();
          }
        }
      }
      map.reset();
      auto cleared = components_->storageTargets.globalFileStore().clear(loader_);
      EXPECT_TRUE(cleared) << cleared.error().describe();
      components_.reset();
    }
    // All service workers have joined before reading the fixed observation
    // array. This includes callbacks from real worker Bind and verifier RPCs.
    if (txnObservation_) txnObservation_->report(!HasFatalFailure());
    // Private database ownership and cleanup belong to the runner. Live pins
    // remain live; this fixture does not invent a drain or physical GC proof.
  }

  static size_t openFds() {
    return std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{});
  }

  void validatePrivateCluster(const char *cluster) {
    // This test resets user keys, so the normal explicit EC environment alone
    // is insufficient. Require the private runner's three matching variables,
    // owner-only temporary root and generated loopback connection identifier.
    // These checks prevent accidental use of a conventional/default cluster;
    // callers must still use a dedicated test instance, never a shared service.
    const char *unittest = std::getenv("FDB_UNITTEST_CLUSTER");
    const char *defaultCluster = std::getenv("FDB_CLUSTER_FILE");
    const char *tmpdir = std::getenv("TMPDIR");
    ASSERT_NE(unittest, nullptr) << "Use scripts/ec/test-meta-catalog.py with its private FDB";
    ASSERT_NE(defaultCluster, nullptr);
    ASSERT_NE(tmpdir, nullptr);
    ASSERT_NE(*unittest, '\0');
    ASSERT_NE(*defaultCluster, '\0');
    ASSERT_NE(*tmpdir, '\0');
    std::error_code error;
    privateCluster_ = std::filesystem::canonical(cluster, error);
    ASSERT_FALSE(error) << error.message();
    const auto unitPath = std::filesystem::canonical(unittest, error);
    ASSERT_FALSE(error) << error.message();
    ASSERT_EQ(privateCluster_, unitPath);
    const auto defaultPath = std::filesystem::canonical(defaultCluster, error);
    ASSERT_FALSE(error) << error.message();
    ASSERT_EQ(privateCluster_, defaultPath);
    const auto temporary = std::filesystem::canonical(tmpdir, error);
    ASSERT_FALSE(error) << error.message();
    ASSERT_EQ(privateCluster_.parent_path(), temporary);
    ASSERT_EQ(privateCluster_.filename(), "fdb.cluster");
    ASSERT_TRUE(temporary.filename().string().starts_with("ec-meta-"));
    struct stat rootStat {
    }, fileStat{};
    ASSERT_EQ(::lstat(temporary.c_str(), &rootStat), 0);
    ASSERT_TRUE(S_ISDIR(rootStat.st_mode));
    ASSERT_EQ(rootStat.st_uid, ::geteuid());
    ASSERT_EQ(rootStat.st_mode & 0077, 0);
    ASSERT_EQ(::lstat(privateCluster_.c_str(), &fileStat), 0);
    ASSERT_TRUE(S_ISREG(fileStat.st_mode));
    ASSERT_EQ(fileStat.st_uid, ::geteuid());
    ASSERT_GT(fileStat.st_size, 0);
    ASSERT_LE(fileStat.st_size, 128);
    std::ifstream input(privateCluster_);
    ASSERT_TRUE(input.is_open());
    std::string line;
    ASSERT_TRUE(static_cast<bool>(std::getline(input, line)));
    ASSERT_EQ(input.peek(), std::char_traits<char>::eof());
    constexpr std::string_view prefix = "ec_catalog_test:";
    constexpr std::string_view address = "@127.0.0.1:";
    ASSERT_TRUE(line.starts_with(prefix));
    ASSERT_GT(line.size(), prefix.size() + 32 + address.size());
    const std::string_view connection(line);
    const auto identifier = connection.substr(prefix.size(), 32);
    ASSERT_TRUE(std::all_of(identifier.begin(), identifier.end(), [](char ch) {
      return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }));
    ASSERT_EQ(connection.substr(prefix.size() + 32, address.size()), address);
    const auto port = connection.substr(prefix.size() + 32 + address.size());
    ASSERT_LE(port.size(), 5);
    ASSERT_TRUE(std::all_of(port.begin(), port.end(), [](char ch) { return ch >= '0' && ch <= '9'; }));
    const auto portNumber = std::stoul(std::string(port));
    ASSERT_GT(portNumber, 0u);
    ASSERT_LE(portNumber, 65535u);
    RecordProperty("private_fdb_cluster", privateCluster_.string());
  }

  void writeKey() {
    // Fixed test-only key, confined to a newly created 0700 temporary directory.
    // The production Meta and Storage loaders both open the same 0600 file.
    keyPath_ = traces_.path() / "native-publication.key";
    ASSERT_EQ(::chmod(traces_.path().c_str(), 0700), 0);
    std::array<uint8_t, 32> key;
    for (size_t i = 0; i != key.size(); ++i) key[i] = static_cast<uint8_t>(i + 1);
    const auto fd = ::open(keyPath_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    const auto written = ::write(fd, key.data(), key.size());
    const auto closed = ::close(fd);
    ASSERT_EQ(written, static_cast<ssize_t>(key.size()));
    ASSERT_EQ(closed, 0);
    struct stat st {};
    ASSERT_EQ(::stat(keyPath_.c_str(), &st), 0);
    ASSERT_EQ(st.st_mode & 0777, 0600);
    controlKeyPath_ = traces_.path() / "native-control.key";
    if (enableFileRmw()) {
      rmwKeyPath_ = traces_.path() / "native-rmw.key";
      std::ofstream rmw(rmwKeyPath_.string(), std::ios::binary | std::ios::trunc);
      const std::string material(32, 'R');
      rmw.write(material.data(), material.size());
      rmw.close();
      ASSERT_TRUE(rmw.good());
      ASSERT_EQ(::chmod(rmwKeyPath_.c_str(), 0600), 0);
    }
    std::ofstream control(controlKeyPath_.string(), std::ios::binary | std::ios::trunc);
    const std::string material(32, 'C');
    control.write(material.data(), material.size());
    control.close();
    ASSERT_TRUE(control.good());
    ASSERT_EQ(::chmod(controlKeyPath_.c_str(), 0600), 0);
    if (enableExactGc()) {
      gcKeyPath_ = traces_.path() / "native-gc.key";
      std::ofstream gc(gcKeyPath_.string(), std::ios::binary | std::ios::trunc);
      const std::string gcMaterial(32, 'G');
      gc.write(gcMaterial.data(), gcMaterial.size());
      gc.close();
      ASSERT_TRUE(gc.good());
      ASSERT_EQ(::chmod(gcKeyPath_.c_str(), 0600), 0);
    }
    if (enableHelperIssuance()) {
      helperKeyPath_ = traces_.path() / "native-helper.key";
      std::ofstream helper(helperKeyPath_.string(), std::ios::binary | std::ios::trunc);
      const std::string helperMaterial(32, 'H');
      helper.write(helperMaterial.data(), helperMaterial.size());
      helper.close();
      ASSERT_TRUE(helper.good());
      ASSERT_EQ(::chmod(helperKeyPath_.c_str(), 0600), 0);
    }
  }

  template <typename Service>
  void startServer(net::Server::Config &config,
                   std::unique_ptr<net::Server> &server,
                   std::unique_ptr<Service> service,
                   flat::NodeId node,
                   flat::NodeType type,
                   const std::string &name) {
    smallThreads(config.thread_pool());
    smallThreads(config.independent_thread_pool());
    config.set_groups_length(1);
    auto &group = config.groups(0);
    group.set_network_type(net::Address::TCP);
    group.set_services({name});
    group.listener().set_listen_port(0);
    group.listener().set_filter_list({"lo"});
    group.listener().set_custom_tcp_nic_prefix("lo");
    group.processor().set_max_processing_requests_num(enableHelperIssuance() ? 128 : 16);
    group.processor().set_max_coroutines_num(enableHelperIssuance() ? 128 : 16);
    group.processor().set_response_compression_level(0);
    server = std::make_unique<net::Server>(config);
    ASSERT_OK(server->addSerdeService(std::move(service), true));
    ASSERT_OK(server->setup());
    flat::AppInfo app;
    app.nodeId = node;
    ASSERT_OK(server->start(app));
    auto groups = server->getServiceGroupInfos();
    ASSERT_EQ(groups.size(), 1);
    ASSERT_TRUE(groups.front().services.contains(name));
    auto &endpoints = groups.front().endpoints;
    const auto found = std::find_if(endpoints.begin(), endpoints.end(), [](const auto &endpoint) {
      return endpoint.type == net::Address::TCP && endpoint.ipStr() == "127.0.0.1" && endpoint.port != 0;
    });
    ASSERT_NE(found, endpoints.end());
    const auto address = *found;
    endpoints.assign(1, address);
    flat::NodeInfo info;
    info.app.nodeId = node;
    info.app.serviceGroups = std::move(groups);
    info.type = type;
    info.status = flat::NodeStatus::HEARTBEAT_CONNECTED;
    routing_->nodes[node] = std::move(info);
    RecordProperty(name + "_endpoint", fmt::format("{}", address));
  }

  void startStorage() {
    storageConfig_.targets().set_target_paths({data_.path()});
    storageConfig_.targets().set_ec_only(true);
    storageConfig_.targets().set_ec_staging_v2(true);
    storageConfig_.targets().set_ec_exact_gc(enableExactGc());
    storageConfig_.targets().set_allow_disk_without_uuid(true);
    storageConfig_.targets().set_collect_all_fds(false);
    auto &storage = storageConfig_.storage();
    storage.set_enable_ec_fragments(true);
    storage.set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    storage.set_ec_capability_key_file(keyPath_);
    storage.set_enable_ec_scope_control(true);
    storage.set_enable_ec_target_retirement(enableTargetRetirement());
    storage.set_ec_scope_control_key_file(controlKeyPath_);
    storage.set_ec_scope_control_authority(authority_.toHexString());
    if (enableFileRmw()) {
      storage.set_enable_ec_rmw(true);
      storage.set_ec_rmw_key_file(rmwKeyPath_);
      storage.set_ec_rmw_authority(authority_.toHexString());
      smallClient(storage.ec_rmw_transport());
      storage.ec_rmw_client().set_implementation_type(storage::client::StorageClient::ImplementationType::RPC);
    }
    if (enableExactGc()) {
      storage.set_enable_ec_gc(true);
      storage.set_ec_gc_key_file(gcKeyPath_);
      storage.set_ec_gc_key_id(gcKeyId_.toHexString());
      storage.set_ec_gc_authority(authority_.toHexString());
    }
    if (enableHelperIssuance()) {
      storage.set_enable_ec_helpers(true);
      storage.set_ec_helper_key_file(helperKeyPath_);
    }
    storage.set_max_concurrent_ec_requests(ecAdmissionLimit());
    storage.write_worker().set_num_threads(2);
    storage.write_worker().set_bg_num_threads(1);
    storage.write_worker().set_queue_size(8);
    storage.event_trace_log().set_enabled(false);
    storage.event_trace_log().set_trace_file_dir(traces_.path());
    storageConfig_.aio_read_worker().set_num_threads(1);
    storageConfig_.aio_read_worker().set_queue_size(8);
    storageConfig_.sync_worker().set_num_threads(2);
    for (auto *pool : {&storageConfig_.coroutines_pool_read(),
                       &storageConfig_.coroutines_pool_update(),
                       &storageConfig_.coroutines_pool_sync(),
                       &storageConfig_.coroutines_pool_default()}) {
      pool->set_threads_num(1);
      pool->set_coroutines_num(2);
      pool->set_queue_size(8);
    }
    smallClient(storageConfig_.forward_client());
    smallClient(storageConfig_.client());
    components_ = std::make_unique<storage::Components>(storageConfig_);
    components_->appInfo.nodeId = storageNode_;
    if (enableFileRmw()) {
      routing_ = std::make_shared<flat::RoutingInfo>();
      routing_->routingInfoVersion = flat::RoutingInfoVersion{1};
      fakeMgmtd_ = std::make_shared<hf3fs::test::FakeMgmtdClient>(routing_);
      components_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(fakeMgmtd_));
    }
    // No Components::start: avoid unrelated allocator, RDMA/AIO, resync and
    // telemetry background workers. The actual EC update worker starts in init.
    ASSERT_OK(components_->storageTargets.load(loader_));
    ASSERT_OK(components_->storageOperator.init(1));
    storageInitialized_ = true;
    if (!routing_) routing_ = std::make_shared<flat::RoutingInfo>();
    routing_->routingInfoVersion = flat::RoutingInfoVersion{1};
    ASSERT_NO_FATAL_FAILURE(
        startServer(storageServerConfig_,
                    storageServer_,
                    std::make_unique<ControlFailureStorageService>(components_->storageOperator, controlFault_),
                    storageNode_,
                    flat::NodeType::STORAGE,
                    "StorageSerde"));
    if (!fakeMgmtd_) fakeMgmtd_ = std::make_shared<hf3fs::test::FakeMgmtdClient>(routing_);
    // Components::start is intentionally absent in this fixture. Helper
    // forwarding still needs the server-side routing provider, not only the
    // client's provider and targetMap snapshot.
    components_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(fakeMgmtd_));
    mgmtd_ = std::shared_ptr<hf3fs::client::ICommonMgmtdClient>(fakeMgmtd_, fakeMgmtd_->asCommon());
    storageClientConfig_.set_implementation_type(storage::client::StorageClient::ImplementationType::RPC);
    storageClientConfig_.retry().set_max_wait_time(20_s);
    storageClientConfig_.traffic_control().read().set_max_concurrent_requests(2);
    storageClientConfig_.traffic_control().read().set_max_concurrent_requests_per_server(2);
    storageClientConfig_.traffic_control().write().set_max_concurrent_requests(2);
    storageClientConfig_.traffic_control().write().set_max_concurrent_requests_per_server(2);
    smallClient(storageClientConfig_.net_client());
    smallClient(storageClientConfig_.net_client_for_updates());
    storageClient_ = storage::client::StorageClient::create(storageClientId_, storageClientConfig_, *mgmtd_);
    ASSERT_NE(storageClient_, nullptr);
    auto next = std::make_shared<flat::RoutingInfo>(*routing_);
    for (size_t i = 0; i != 12; ++i) {
      const auto targetId = storage::TargetId{2000 + i};
      const auto chainId = storage::ChainId{static_cast<uint32_t>(1000 + i)};
      storage::EcCreateTargetReq create;
      create.settings.targetId = targetId;
      create.settings.chainId = chainId;
      create.settings.diskIndex = 0;
      create.settings.onlyChunkEngine = true;
      create.settings.allowExistingTarget = false;
      auto created = blockingWait(storageClient_->createEcTarget(storageNode_, create));
      ASSERT_OK(created);
      ASSERT_EQ(created->targetId, targetId);
      flat::TargetInfo target;
      target.targetId = targetId;
      target.chainId = chainId;
      target.nodeId = storageNode_;
      target.diskIndex = 0;
      target.publicState = flat::PublicTargetState::SERVING;
      target.localState = flat::LocalTargetState::UPTODATE;
      next->targets[targetId] = target;
      flat::ChainInfo chain;
      chain.chainId = chainId;
      chain.chainVersion = storage::ChainVer{1};
      flat::ChainTargetInfo member;
      member.targetId = targetId;
      member.publicState = flat::PublicTargetState::SERVING;
      chain.targets.push_back(member);
      next->chains[chainId] = std::move(chain);
    }
    next->routingInfoVersion = flat::RoutingInfoVersion{2};
    routing_ = std::move(next);
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_OK(components_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
  }

  void startMeta() {
    metaConfig_.set_enable_ec_catalog(true);
    metaConfig_.set_enable_ec_v2(true);
    metaConfig_.set_enable_ec_target_retirement(enableTargetRetirement());
    if (enableFileRmw()) {
      metaConfig_.set_enable_ec_rmw(true);
      metaConfig_.set_ec_rmw_key_file(rmwKeyPath_);
      metaConfig_.set_enable_ec_file_ranges(true);
      metaConfig_.set_ec_rmw_authority(authority_.toHexString());
      smallClient(metaConfig_.ec_rmw_transport());
    }
    if (enableMetaGcAdmin()) {
      metaConfig_.set_enable_ec_exact_gc(true);
      metaConfig_.set_ec_gc_key_file(gcKeyPath_);
      metaConfig_.set_ec_gc_key_id(gcKeyId_.toHexString());
      metaConfig_.set_ec_gc_authority(authority_.toHexString());
    }
    if (enableHelperIssuance()) metaConfig_.set_ec_v2_helper_key_file(helperKeyPath_);
    metaConfig_.set_ec_v2_control_key_file(controlKeyPath_);
    metaConfig_.set_ec_v2_control_authority(authority_.toHexString());
    metaConfig_.set_authenticate(true);
    metaConfig_.set_ec_allow_colocated_test_targets(true);
    metaConfig_.set_ec_allow_unauthorized_storage_for_tests(false);
    metaConfig_.set_ec_capability_key_file(keyPath_);
    metaConfig_.set_ec_max_verifying_stripes(2);
    metaConfig_.set_ec_targets_length(12);
    metaConfig_.gc().set_enable(false);
    metaConfig_.session_manager().set_enable(false);
    metaConfig_.event_trace_log().set_enabled(false);
    metaConfig_.event_trace_log().set_trace_file_dir(traces_.path());
    for (size_t i = 0; i != 12; ++i) {
      metaConfig_.ec_targets(i).set_chain(1000 + i);
      metaConfig_.ec_targets(i).set_target(2000 + i);
      metaConfig_.ec_targets(i).set_node(storageNode_.toUnderType());
      auto target = components_->targetMap.getByTargetId(storage::TargetId{2000 + i});
      ASSERT_OK(target);
      auto state = (*target)->storageTarget->ecScopeState();
      ASSERT_OK(state);
      Uuid engine, incarnation;
      std::copy(state->second.engine.begin(), state->second.engine.end(), std::begin(engine.data));
      std::copy(state->second.incarnation.begin(), state->second.incarnation.end(), std::begin(incarnation.data));
      metaConfig_.ec_targets(i).set_engine_uuid(engine.toHexString());
      metaConfig_.ec_targets(i).set_target_incarnation(incarnation.toHexString());
    }
    meta_ = std::make_unique<MetaOperator>(metaConfig_, metaNode_, kv_, mgmtd_, storageClient_, nullptr);
    ASSERT_OK(blockingWait(meta_->init(Layout::newEmpty(flat::ChainTableId{1}, kShardBytes, 12))));
    metaInitialized_ = true;
    auto txn = kv_->createReadWriteTransaction();
    core::UserStore users;
    auto existingAdmin = blockingWait(users.getUser(*txn, flat::Uid{0}));
    ASSERT_OK(existingAdmin);
    flat::UserAttr admin;
    if (*existingAdmin) {
      admin = **existingAdmin;
    } else {
      auto addedAdmin = blockingWait(users.addUser(*txn, flat::Uid{0}, "root", {}, true));
      ASSERT_OK(addedAdmin);
      admin = *addedAdmin;
    }
    const UserInfo administrator{admin.uid, admin.gid, admin.token};
    const auto uid = flat::Uid{100000 + folly::Random::rand32(1000000000)};
    auto added = blockingWait(users.addUser(*txn, uid, fmt::format("ec-native-{}", Uuid::random()), {}, false));
    ASSERT_OK(added);
    user_ = UserInfo{added->uid, added->gid, added->token};
    ASSERT_FALSE(user_.token.empty());
    ASSERT_NE(user_.uid, flat::Uid{0});
    ASSERT_OK(blockingWait(txn->commit()));
    // Publish a new immutable routing snapshot after adding the Meta endpoint.
    routing_ = std::make_shared<flat::RoutingInfo>(*routing_);
    ASSERT_NO_FATAL_FAILURE(startServer(metaServerConfig_,
                                        metaServer_,
                                        std::make_unique<DropPublishMetaService>(*meta_, replyDrop_),
                                        metaNode_,
                                        flat::NodeType::META,
                                        "MetaSerde"));
    routing_->routingInfoVersion = flat::RoutingInfoVersion{3};
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_OK(components_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
    metaClientConfig_.set_network_type(net::Address::TCP);
    metaClientConfig_.set_max_concurrent_requests(4);
    metaClientConfig_.retry_default().set_rpc_timeout(20_s);
    metaClientConfig_.retry_default().set_retry_total_time(30_s);
    // Persist the client UUID used for operation ownership before Begin. The
    // hostname is descriptive and MetaClient refreshes it in its constructor.
    std::ofstream identity((traces_.path() / "client.uuid").string(), std::ios::binary);
    ASSERT_TRUE(identity.is_open());
    identity << metaClientId_.uuid.toHexString();
    identity.close();
    ASSERT_TRUE(identity.good());
    ASSERT_NO_FATAL_FAILURE(startMetaClient(metaClientId_));
    // Intentionally distinct: bearer identity is not the storage transport tag.
    ASSERT_NE(metaClientId_.uuid, storageClientId_.uuid);
    auto authenticated = blockingWait(metaClient_->authenticate(user_));
    ASSERT_OK(authenticated);
    ASSERT_EQ(authenticated->uid, user_.uid);
    // Authenticate a genuine root token only to create a fresh writable test
    // directory. All EC requests below use the separate unprivileged user.
    auto parent = blockingWait(metaClient_->mkdirs(administrator,
                                                   InodeId::root(),
                                                   Path(fmt::format("ec-native-{}", Uuid::random())),
                                                   Permission{0777},
                                                   false));
    ASSERT_OK(parent);
    parent_ = parent->id;
  }

  void startMetaClient(const ClientId &identity) {
    smallClient(metaNetConfig_);
    metaNet_ = std::make_unique<net::Client>(metaNetConfig_, "EcNativeMeta");
    ASSERT_OK(metaNet_->start("EcNativeMeta"));
    auto factory = std::make_unique<meta::client::MetaClient::StubFactory>(
        [this](net::Address address) { return metaNet_->serdeCtx(address); });
    metaClient_ = std::make_unique<meta::client::MetaClient>(identity,
                                                             metaClientConfig_,
                                                             std::move(factory),
                                                             mgmtd_,
                                                             storageClient_,
                                                             false);
  }

  void reconstructMetaClient() {
    metaClient_->stop();
    metaClient_.reset();
    metaNet_->stopAndJoin();
    metaNet_.reset();
    std::ifstream identity((traces_.path() / "client.uuid").string(), std::ios::binary);
    ASSERT_TRUE(identity.is_open());
    std::string saved;
    ASSERT_TRUE(static_cast<bool>(std::getline(identity, saved)));
    ASSERT_EQ(identity.peek(), std::char_traits<char>::eof());
    auto uuid = Uuid::fromHexString(saved);
    ASSERT_OK(uuid);
    ASSERT_EQ(*uuid, metaClientId_.uuid);
    ASSERT_NO_FATAL_FAILURE(startMetaClient(ClientId(*uuid)));
  }

  template <typename Req>
  Req request() const {
    Req req;
    req.user = user_;
    req.client = metaClientId_;
    req.uuid = Uuid::random();
    return req;
  }

  static std::string bytes(size_t length, uint32_t seed) {
    std::string data(length, '\0');
    for (size_t i = 0; i != length; ++i) data[i] = static_cast<char>((i * 37 + (i >> 3) + seed) & 255);
    return data;
  }

  void prepare(Mutation &out,
               const EcObjectRef &object,
               uint64_t revision,
               uint32_t seed,
               bool badParity = false,
               uint64_t stripe = 0,
               size_t logicalLength = 10 * kShardBytes - 37) {
    out.logical = bytes(logicalLength, seed);
    auto encoded = storage::EcCodec::encode(out.logical, kShardBytes);
    ASSERT_OK(encoded);
    out.shards = std::move(*encoded);
    if (badParity) out.shards[11][17] ^= 0x53;
    out.begin = request<BeginEcMutationV2Req>();
    out.begin.object = object;
    out.begin.stripe = stripe;
    out.begin.operation = Uuid::random();
    out.begin.expectedEpoch = 1;
    out.begin.expectedRevision = revision;
    out.begin.logicalLength = out.logical.size();
    std::array<std::string_view, 10> logical;
    for (size_t i = 0; i != 10; ++i) logical[i] = out.shards[i];
    auto sha = computeEcLogicalSha256(logical, out.logical.size());
    ASSERT_OK(sha);
    out.begin.contentSha256 = *sha;
    for (size_t i = 0; i != 12; ++i) {
      const auto crc = storage::ChecksumInfo::create(storage::ChecksumType::CRC32C,
                                                     reinterpret_cast<const uint8_t *>(out.shards[i].data()),
                                                     out.shards[i].size());
      out.begin.fragmentCrc32c[i] = ~crc.value;
    }
    auto begun = blockingWait(metaClient_->beginEcMutationV2(out.begin));
    ASSERT_OK(begun);
    ASSERT_TRUE(begun->reservation);
    for (const auto &grant : begun->grants) ASSERT_FALSE(grant);
    out.bind = request<BindEcMutationV2Req>();
    out.bind.object = object;
    out.bind.operation = out.begin.operation;
    for (size_t i = 0; i != 12; ++i) {
      auto descriptor = storage::computeEcIntegrity(begun->record.candidate.fragments[i].identity, out.shards[i]);
      ASSERT_OK(descriptor);
      out.bind.descriptors[i] = *descriptor;
    }
    auto bound = blockingWait(metaClient_->bindEcMutationV2(out.bind));
    ASSERT_OK(bound);
    ASSERT_TRUE(bound->allocations);
    out.reservation = std::move(*bound);
    out.publish = request<PublishEcMutationV2Req>();
    out.publish.object = object;
    out.publish.operation = out.begin.operation;
    for (size_t i = 0; i != 12; ++i) {
      ASSERT_TRUE(out.reservation.grants[i]);
      const auto &claims = out.reservation.grants[i]->claims;
      ASSERT_EQ(claims.ownerUid, user_.uid);
      ASSERT_EQ(claims.clientNamespace, metaClient_->clientId().uuid);
      ASSERT_NE(claims.clientNamespace, storageClientId_.uuid);
      ASSERT_EQ(claims.engineUuid, out.reservation.reservation->candidates[i].endpoint.engineUuid);
    }
  }
  storage::client::EcRequestControl control() const {
    storage::client::EcRequestControl value;
    value.deadline = SteadyClock::now() + 20_s;
    return value;
  }
  storage::EcFragmentAccessV2 access(const EcV2AllocationBinding &allocation) const {
    storage::EcFragmentAccessV2 value;
    value.identity = allocation.fragment.identity;
    value.operationId = allocation.fragment.operation;
    value.vChainId = {allocation.fragment.placement.chain, storage::ChainVer{1}};
    value.targetId = allocation.fragment.placement.target;
    value.integrity = allocation.fragment.integrity;
    return value;
  }
  void writeFragments(const Mutation &mutation) {
    ASSERT_TRUE(mutation.reservation.allocations);
    for (size_t i = 0; i != 12; ++i) {
      if (!(mutation.begin.replacementMask & (1u << i))) continue;
      ASSERT_TRUE(mutation.reservation.grants[i]);
      storage::EcBeginStageV2Req begin;
      begin.request = access((*mutation.reservation.allocations)[i]);
      begin.grant = *mutation.reservation.grants[i];
      ASSERT_OK(blockingWait(storageClient_->beginEcStageV2Controlled(begin, control())));
      storage::EcAppendStageV2Req append;
      append.request = begin.request;
      append.grant = begin.grant;
      append.payload.data = mutation.shards[i];
      ASSERT_OK(blockingWait(storageClient_->appendEcStageV2Controlled(append, control())));
      storage::EcSealStageV2Req seal;
      seal.request = begin.request;
      seal.grant = begin.grant;
      auto receipt = blockingWait(storageClient_->sealEcStageV2Controlled(seal, control()));
      ASSERT_OK(receipt);
      ASSERT_OK(storage::validateEcReceiptV2(*receipt, seal.request, seal.grant.claims));
    }
  }
  AcquireEcReadV2Req readRequest(const EcObjectRef &object) const {
    auto req = request<AcquireEcReadV2Req>();
    req.object = object;
    req.pin = Uuid::random();
    return req;
  }
  Result<storage::EcReadBlockResultV2> readOne(const AcquireEcReadV2Rsp &pin, size_t index) {
    if (!pin.readGrants[index]) return makeError(StatusCode::kInvalidArg);
    EcV2AllocationBinding allocation;
    allocation.fragment = pin.manifest.fragments[index];
    storage::EcReadBlockV2Req read;
    read.request = access(allocation);
    read.grant = *pin.readGrants[index];
    return blockingWait(storageClient_->readEcBlockV2Controlled(read, control()));
  }
  void repair(Mutation &out, const AcquireEcReadV2Rsp &base, uint16_t mask) {
    out.begin = request<BeginEcMutationV2Req>();
    out.begin.object = base.manifest.object;
    out.begin.operation = Uuid::random();
    out.begin.expectedEpoch = 1;
    out.begin.expectedRevision = base.manifest.revision;
    out.begin.logicalLength = base.manifest.logicalLength;
    out.begin.kind = EcMutationKind::Repair;
    out.begin.replacementMask = mask;
    out.begin.contentSha256 = base.contentSha256;
    for (size_t i = 0; i != 12; ++i) out.begin.fragmentCrc32c[i] = base.manifest.fragments[i].integrity.wholeCrc32c;
    auto begun = blockingWait(metaClient_->beginEcMutationV2(out.begin));
    ASSERT_OK(begun);
    ASSERT_EQ(begun->record.candidate.generation, base.manifest.generation);
    out.bind = request<BindEcMutationV2Req>();
    out.bind.object = out.begin.object;
    out.bind.operation = out.begin.operation;
    // Same generation and logical contents: descriptors are reused before any
    // data read. They do not include the newly allocated physical UUID.
    for (size_t i = 0; i != 12; ++i) out.bind.descriptors[i] = base.manifest.fragments[i].integrity;
    auto bound = blockingWait(metaClient_->bindEcMutationV2(out.bind));
    ASSERT_OK(bound);
    out.reservation = std::move(*bound);
    storage::EcCodec::Shards received;
    std::array<storage::EcCodecShardView, 10> sources;
    size_t count = 0;
    for (size_t i = 0; i != 12 && count != sources.size(); ++i) {
      if (mask & (1u << i)) continue;
      auto read = readOne(base, i);
      ASSERT_OK(read);
      received[i] = std::move(read->payload.data);
      sources[count++] = {static_cast<uint16_t>(i), received[i]};
    }
    ASSERT_EQ(count, 10);
    auto decoded = storage::EcCodec::recover(sources, base.manifest.logicalLength, kShardBytes);
    ASSERT_OK(decoded);
    out.shards = std::move(*decoded);
    for (size_t i = 0; i != 10; ++i) out.logical += out.shards[i];
    out.logical.resize(base.manifest.logicalLength);
    out.publish = request<PublishEcMutationV2Req>();
    out.publish.object = out.begin.object;
    out.publish.operation = out.begin.operation;
  }
  void prepareRepairMetadata(Mutation &out, const AcquireEcReadV2Rsp &base, uint16_t mask) {
    out.begin = request<BeginEcMutationV2Req>();
    out.begin.object = base.manifest.object;
    out.begin.operation = Uuid::random();
    out.begin.expectedEpoch = 1;
    out.begin.expectedRevision = base.manifest.revision;
    out.begin.logicalLength = base.manifest.logicalLength;
    out.begin.kind = EcMutationKind::Repair;
    out.begin.replacementMask = mask;
    out.begin.contentSha256 = base.contentSha256;
    for (size_t i = 0; i != 12; ++i) out.begin.fragmentCrc32c[i] = base.manifest.fragments[i].integrity.wholeCrc32c;
    auto begun = blockingWait(metaClient_->beginEcMutationV2(out.begin));
    ASSERT_OK(begun);
    out.bind = request<BindEcMutationV2Req>();
    out.bind.object = out.begin.object;
    out.bind.operation = out.begin.operation;
    for (size_t i = 0; i != 12; ++i) out.bind.descriptors[i] = base.manifest.fragments[i].integrity;
    auto bound = blockingWait(metaClient_->bindEcMutationV2(out.bind));
    ASSERT_OK(bound);
    out.reservation = std::move(*bound);
    out.publish = request<PublishEcMutationV2Req>();
    out.publish.object = out.begin.object;
    out.publish.operation = out.begin.operation;
    // No data reads, encoding or recovery are performed by this plan setup.
  }
  PrepareEcRepairV2Req planRequest(const Mutation &mutation) const {
    auto req = request<PrepareEcRepairV2Req>();
    req.object = mutation.begin.object;
    req.operation = mutation.begin.operation;
    req.planId = Uuid::random();
    size_t index = 0;
    for (uint8_t shard = 0; shard != 12 && index != req.sourceOrder.size(); ++shard)
      if (!(mutation.begin.replacementMask & (1u << shard))) req.sourceOrder[index++] = shard;
    return req;
  }
  void restartCoordinator() {
    metaClient_->stop();
    metaClient_.reset();
    metaNet_->stopAndJoin();
    metaNet_.reset();
    metaServer_->stopAndJoin();
    metaServer_.reset();
    meta_->beforeStop();
    meta_->afterStop();
    meta_.reset();
    metaInitialized_ = false;
    meta_ = std::make_unique<MetaOperator>(metaConfig_, metaNode_, kv_, mgmtd_, storageClient_, nullptr);
    ASSERT_OK(blockingWait(meta_->init(std::nullopt)));
    metaInitialized_ = true;
    routing_ = std::make_shared<flat::RoutingInfo>(*routing_);
    ASSERT_NO_FATAL_FAILURE(startServer(metaServerConfig_,
                                        metaServer_,
                                        std::make_unique<DropPublishMetaService>(*meta_, replyDrop_),
                                        metaNode_,
                                        flat::NodeType::META,
                                        "MetaSerde"));
    routing_->routingInfoVersion = flat::RoutingInfoVersion(routing_->routingInfoVersion.toUnderType() + 1);
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_NO_FATAL_FAILURE(startMetaClient(metaClientId_));
    RecordProperty("coordinator_recovery",
                   "destroyed/reconstructed MetaOperator and TCP service; same real FDB and Storage");
  }
  void reopenStorageKeepingMeta() {
    // The caller first joins every manager task and awaits every direct RPC.
    // Meta/FDB and both real clients remain live but issue no requests here.
    // No target, scope registry or Engine lease is retained across reset.
    ASSERT_TRUE(storageInitialized_);
    ASSERT_NE(storageServer_, nullptr);
    storageServer_->stopAndJoin();
    storageServer_.reset();
    ASSERT_OK(components_->storageOperator.stopAndJoin());
    storageInitialized_ = false;
    {
      auto map = components_->targetMap.release();
      ASSERT_NE(map, nullptr);
      for (const auto &[id, target] : map->getTargets()) {
        if (target.storageTarget) ASSERT_OK(target.storageTarget->release());
      }
    }
    ASSERT_OK(components_->storageTargets.globalFileStore().clear(loader_));
    components_.reset();

    // AtomicallyTargetMap::release consumes its old map. Reconstruct the
    // owning Components rather than attempting to reuse that released map.
    components_ = std::make_unique<storage::Components>(storageConfig_);
    components_->appInfo.nodeId = storageNode_;
    ASSERT_OK(components_->storageTargets.load(loader_));
    components_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(fakeMgmtd_));
    ASSERT_OK(components_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
    ASSERT_OK(components_->storageOperator.init(1));
    storageInitialized_ = true;
    routing_ = std::make_shared<flat::RoutingInfo>(*routing_);
    ASSERT_NO_FATAL_FAILURE(
        startServer(storageServerConfig_,
                    storageServer_,
                    std::make_unique<ControlFailureStorageService>(components_->storageOperator, controlFault_),
                    storageNode_,
                    flat::NodeType::STORAGE,
                    "StorageSerde"));
    routing_->routingInfoVersion = flat::RoutingInfoVersion(routing_->routingInfoVersion.toUnderType() + 1);
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_OK(components_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
    for (size_t i = 0; i != 12; ++i) {
      const auto &fixed = metaConfig_.ec_targets(i);
      auto loaded = components_->targetMap.getByTargetId(storage::TargetId(fixed.target()));
      ASSERT_OK(loaded);
      auto state = (*loaded)->storageTarget->ecScopeState();
      ASSERT_OK(state);
      Uuid engine = Uuid::zero(), incarnation = Uuid::zero();
      std::copy(state->second.engine.begin(), state->second.engine.end(), std::begin(engine.data));
      std::copy(state->second.incarnation.begin(), state->second.incarnation.end(), std::begin(incarnation.data));
      ASSERT_EQ(engine.toHexString(), fixed.engine_uuid());
      ASSERT_EQ(incarnation.toHexString(), fixed.target_incarnation());
    }
    RecordProperty("storage_recovery", "normal close/reopen of actual Rust Engine and TCP service; same Meta/FDB");
  }
  template <typename F>
  void alterInode(const EcObjectRef &object, F change) {
    auto txn = kv_->createReadWriteTransaction();
    auto inode = blockingWait(Inode::load(*txn, object.inode));
    ASSERT_OK(inode);
    ASSERT_TRUE(*inode);
    change(**inode);
    ASSERT_OK(blockingWait((**inode).store(*txn)));
    ASSERT_OK(blockingWait(txn->commit()));
  }
  void checkPin(const EcObjectRef &object, const Uuid &pin, bool released) {
    auto txn = kv_->createReadWriteTransaction();
    auto record = blockingWait(EcCatalog::getPin(*txn, object, pin));
    ASSERT_OK(record);
    ASSERT_EQ(record->released, released);
  }
  const flat::NodeId storageNode_{61};
  const flat::NodeId metaNode_{62};
  const ClientId metaClientId_ = ClientId::random();
  const ClientId storageClientId_ = ClientId::random();
  folly::test::TemporaryDirectory data_;
  folly::test::TemporaryDirectory traces_;
  Path keyPath_;
  std::filesystem::path privateCluster_;
  CPUExecutorGroup loader_{1, "EcNativeDisk"};
  std::shared_ptr<kv::IKVEngine> kv_;
  std::shared_ptr<detail::EcNativeTxnObservation> txnObservation_;
  std::shared_ptr<flat::RoutingInfo> routing_;
  std::shared_ptr<hf3fs::test::FakeMgmtdClient> fakeMgmtd_;
  std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd_;
  storage::Components::Config storageConfig_;
  std::unique_ptr<storage::Components> components_;
  bool storageInitialized_ = false;
  net::Server::Config storageServerConfig_;
  std::unique_ptr<net::Server> storageServer_;
  storage::client::StorageClient::Config storageClientConfig_;
  std::shared_ptr<storage::client::StorageClient> storageClient_;
  Config metaConfig_;
  std::unique_ptr<MetaOperator> meta_;
  bool metaInitialized_ = false;
  UserInfo user_;
  InodeId parent_;
  PublishReplyDrop replyDrop_;
  ControlFailure controlFault_;
  Path controlKeyPath_;
  Path helperKeyPath_;
  Path rmwKeyPath_;
  Path gcKeyPath_;
  const Uuid gcKeyId_ = Uuid::random();
  const Uuid authority_ = Uuid::random();
  net::Server::Config metaServerConfig_;
  std::unique_ptr<net::Server> metaServer_;
  net::Client::Config metaNetConfig_;
  std::unique_ptr<net::Client> metaNet_;
  meta::client::MetaClient::Config metaClientConfig_;
  std::unique_ptr<meta::client::MetaClient> metaClient_;
};

class TestEcV2NativeHelperPlan : public TestEcV2NativeLifecycle {
 protected:
  bool enableHelperIssuance() const override { return true; }
};

// clang-format off
// The following fragments require TestEcFileNativeWrite to be defined first.
#include "EcFileNativeWriteTests.inc"
#include "EcFileRepairNativeTests.inc"
#include "EcFileHelperDirectNativeTests.inc"
#include "EcFileRepairPendingNativeTests.inc"
#include "EcFileAppendNativeTests.inc"
#include "EcFileTruncateNativeTests.inc"
#include "EcMountedTruncateNativeTests.inc"
// clang-format on

TEST_F(TestEcV2NativeLifecycle, PublicCreateTracksNewObjectsAndLegacyCreateReplayDoesNotUpgrade) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "gc-tracked-birth");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  auto txn = kv_->createReadWriteTransaction();
  auto mode = blockingWait(EcV2BindingCatalog::requireV2Mode(*txn, object));
  ASSERT_OK(mode);
  EXPECT_EQ(mode->mode, kEcGcTrackedObjectMode);
  ASSERT_OK(blockingWait(EcV2GcCatalog::validateEnrollment(*txn, *mode)));
  txn.reset();
  ASSERT_OK(blockingWait(metaClient_->createEcFileV2(create)));

  // Build a pre-tracking on-disk fixture before any mutation/issuance exists.
  // This raw test-only rewrite is not an offered downgrade/migration API.
  // The permanent Create result and its UUID are identical to the old format.
  txn = kv_->createReadWriteTransaction();
  mode = blockingWait(EcV2BindingCatalog::requireV2Mode(*txn, object));
  ASSERT_OK(mode);
  mode->mode = 2;
  std::string modeKey(kv::toStr(kv::KeyPrefix::EcV2ObjectMode));
  modeKey.append(object.incarnation.asStringView());
  const auto bytes = serde::serialize(*mode);
  ASSERT_OK(blockingWait(txn->set(modeKey, bytes)));
  std::string birthKey(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  birthKey.append(object.incarnation.asStringView());
  ASSERT_OK(blockingWait(txn->clear(birthKey)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  auto replay = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(replay);
  EXPECT_EQ(replay->object.object, object);
  txn = kv_->createReadWriteTransaction();
  mode = blockingWait(EcV2BindingCatalog::requireV2Mode(*txn, object));
  ASSERT_OK(mode);
  EXPECT_EQ(mode->mode, 2);
  auto enrollment = blockingWait(txn->get(birthKey));
  ASSERT_OK(enrollment);
  EXPECT_FALSE(*enrollment);
}

TEST_F(TestEcV2NativeLifecycle, PublicationReplayModeGuardsAndReleaseAfterAclRevocation) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "native-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  auto wrongToken = create;
  wrongToken.uuid = Uuid::random();
  wrongToken.path = PathAt(parent_, "forged");
  wrongToken.user.token = "invalid-token";
  ASSERT_FALSE(blockingWait(metaClient_->createEcFileV2(wrongToken)));
  ASSERT_OK(blockingWait(metaClient_->createEcFileV2(create)));
  CreateEcFileReq oldCreate = static_cast<const CreateEcFileReq &>(create);
  ASSERT_ERROR(blockingWait(metaClient_->createEcFile(oldCreate)), StatusCode::kNotImplemented);
  auto v1 = request<CreateEcFileReq>();
  v1.path = PathAt(parent_, "legacy-v1");
  v1.shardBytes = kShardBytes;
  ASSERT_OK(blockingWait(metaClient_->createEcFile(v1)));
  CreateEcFileV2Req upgrade;
  static_cast<CreateEcFileReq &>(upgrade) = v1;
  ASSERT_ERROR(blockingWait(metaClient_->createEcFileV2(upgrade)), StatusCode::kNotImplemented);

  Mutation mutation;
  ASSERT_NO_FATAL_FAILURE(prepare(mutation, object, 0, 17));
  auto changed = mutation.bind;
  changed.descriptors[0].root[0] ^= 1;
  ASSERT_FALSE(blockingWait(metaClient_->bindEcMutationV2(changed)));
  ASSERT_NO_FATAL_FAILURE(writeFragments(mutation));
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &inode) {
    inode.acl.uid = flat::Uid{999};
    inode.acl.perm = Permission{07777};
  }));
  replyDrop_.arm(mutation.begin.operation);
  auto published = blockingWait(metaClient_->publishEcMutationV2(mutation.publish));
  ASSERT_OK(published);
  ASSERT_TRUE(published->drain);
  EXPECT_EQ(published->drain->state, EcV2DrainState::Published);
  EXPECT_EQ(published->drain->acknowledgedEndpoints, 12);
  EXPECT_TRUE(replyDrop_.snapshot().committed);
  EXPECT_GE(replyDrop_.snapshot().calls, 2u);
  const auto manifest = published->record.candidate;
  auto txn = kv_->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, object.inode));
  ASSERT_OK(inode);
  ASSERT_TRUE(*inode);
  EXPECT_EQ((**inode).acl.perm & (S_ISUID | S_ISGID | S_ISVTX), 0);
  txn.reset();
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0444}; }));
  ASSERT_ERROR(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) {
    value.acl.perm = Permission{0666};
    value.acl.iflags |= FS_IMMUTABLE_FL;
  }));
  ASSERT_ERROR(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.iflags &= ~FS_IMMUTABLE_FL; }));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)));
  txn = kv_->createReadWriteTransaction();
  for (const auto &fragment : manifest.fragments) {
    auto ref = blockingWait(EcCatalog::getFragmentRef(*txn, fragment.identity));
    ASSERT_OK(ref);
    EXPECT_EQ(ref->references, 1);
  }
  txn.reset();
  ASSERT_ERROR(blockingWait(metaClient_->bindEcMutationV2(mutation.bind)), StatusCode::kTokenStale);

  auto pinReq = readRequest(object);
  auto pinned = blockingWait(metaClient_->acquireEcReadV2(pinReq));
  ASSERT_OK(pinned);
  EXPECT_EQ(pinned->contentSha256, mutation.begin.contentSha256);
  for (size_t i = 0; i != 12; ++i) {
    auto read = readOne(*pinned, i);
    ASSERT_OK(read);
    EXPECT_EQ(read->payload.data, mutation.shards[i]);
  }
  // Every legacy metadata path rejects V2 mode, including old Cancel and old
  // Release, which otherwise could reach legacy reference accounting directly.
  BeginEcMutationReq oldBegin = mutation.begin;
  ASSERT_ERROR(blockingWait(metaClient_->beginEcMutation(oldBegin)), StatusCode::kNotImplemented);
  auto oldPublish = request<PublishEcMutationReq>();
  oldPublish.object = object;
  oldPublish.operation = mutation.begin.operation;
  ASSERT_ERROR(blockingWait(metaClient_->publishEcMutation(oldPublish)), StatusCode::kNotImplemented);
  auto oldGet = request<GetEcOperationReq>();
  oldGet.object = object;
  oldGet.operation = mutation.begin.operation;
  ASSERT_ERROR(blockingWait(metaClient_->getEcOperation(oldGet)), StatusCode::kNotImplemented);
  auto oldCancel = request<CancelEcMutationReq>();
  oldCancel.object = object;
  oldCancel.operation = mutation.begin.operation;
  ASSERT_ERROR(blockingWait(metaClient_->cancelEcMutation(oldCancel)), StatusCode::kNotImplemented);
  AcquireEcReadReq oldAcquire = pinReq;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRead(oldAcquire)), StatusCode::kNotImplemented);
  auto oldRelease = request<ReleaseEcReadReq>();
  oldRelease.object = object;
  oldRelease.pin = pinReq.pin;
  ASSERT_ERROR(blockingWait(metaClient_->releaseEcRead(oldRelease)), StatusCode::kNotImplemented);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0000}; }));
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcReadV2(pinReq)), MetaCode::kNoPermission);
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = pinReq.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(released);
  EXPECT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
  EXPECT_EQ(released->drain.acknowledgedEndpoints, 12);
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  ASSERT_NO_FATAL_FAILURE(checkPin(object, pinReq.pin, true));
  ASSERT_FALSE(readOne(*pinned, 0));
}

TEST_F(TestEcV2NativeLifecycle, DurableProofResumesAfterActualRevokeAndCoordinatorReconstruction) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "resume-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation mutation;
  ASSERT_NO_FATAL_FAILURE(prepare(mutation, object, 0, 31));
  ASSERT_NO_FATAL_FAILURE(writeFragments(mutation));
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.scope = mutation.begin.operation;
    controlFault_.fail = true;
  }
  ASSERT_ERROR(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)), StatusCode::kNotImplemented);
  auto get = request<GetEcOperationV2Req>();
  get.object = object;
  get.operation = mutation.begin.operation;
  auto closing = blockingWait(metaClient_->getEcOperationV2(get));
  ASSERT_OK(closing);
  ASSERT_TRUE(closing->drain);
  EXPECT_EQ(closing->drain->state, EcV2DrainState::Closing);
  EXPECT_EQ(closing->record.state, EcOperationState::Preparing);
  ASSERT_ERROR(blockingWait(metaClient_->bindEcMutationV2(mutation.bind)), StatusCode::kTokenStale);
  {
    auto txn = kv_->createReadWriteTransaction();
    EcOwner owner{user_.uid, metaClientId_.uuid};
    auto record = blockingWait(
        EcV2DrainCatalog::get(*txn, object, storage::EcGrantScope::WriteOperation, mutation.begin.operation, owner));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    ASSERT_TRUE((**record).verifiedManifest);
    EXPECT_EQ((**record).verifiedContentSha256, mutation.begin.contentSha256);
  }
  {
    std::lock_guard lock(controlFault_.mutex);
    EXPECT_GE(controlFault_.actualRevokes, 1u);
    controlFault_.fail = false;
  }
  // The first target now denies the WriteOperation data scope. Re-reading it
  // would fail; reconstruction must resume from the durable T0 proof instead.
  storage::EcReadBlockV2Req stale;
  stale.request = access((*mutation.reservation.allocations)[0]);
  stale.grant = *mutation.reservation.grants[0];
  ASSERT_FALSE(blockingWait(storageClient_->readEcBlockV2Controlled(stale, control())));
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  auto published = blockingWait(metaClient_->publishEcMutationV2(mutation.publish));
  ASSERT_OK(published);
  EXPECT_EQ(published->record.state, EcOperationState::Published);
  EXPECT_EQ(published->drain->acknowledgedEndpoints, 12);
  auto acquired = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(acquired);
  EXPECT_EQ(acquired->contentSha256, mutation.begin.contentSha256);
  auto actual = readOne(*acquired, 0);
  ASSERT_OK(actual);
  EXPECT_EQ(actual->payload.data, mutation.shards[0]);
}

TEST_F(TestEcV2NativeLifecycle, SingleAndDoubleRepairReuseDescriptorsAndPreserveHistoricalPins) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "repair-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 49));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto first = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(first);
  std::vector<AcquireEcReadV2Rsp> history{*first};
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{07600}; }));
  auto inodeTxn = kv_->createReadWriteTransaction();
  auto before = blockingWait(Inode::load(*inodeTxn, object.inode));
  ASSERT_OK(before);
  ASSERT_TRUE(*before);
  const auto preserved = **before;
  inodeTxn.reset();
  for (const uint16_t mask : {uint16_t{1}, uint16_t{3}}) {
    Mutation repaired;
    ASSERT_NO_FATAL_FAILURE(repair(repaired, history.back(), mask));
    EXPECT_EQ(repaired.logical, original.logical);
    ASSERT_NO_FATAL_FAILURE(writeFragments(repaired));
    auto published = blockingWait(metaClient_->publishEcMutationV2(repaired.publish));
    ASSERT_OK(published);
    EXPECT_EQ(published->record.candidate.generation, first->manifest.generation);
    auto next = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
    ASSERT_OK(next);
    EXPECT_EQ(next->contentSha256, original.begin.contentSha256);
    for (size_t i = 0; i != 12; ++i) {
      const auto &old = history.back().manifest.fragments[i];
      const auto &now = next->manifest.fragments[i];
      EXPECT_EQ(old.integrity, now.integrity);
      EXPECT_EQ(old.identity.allocation == now.identity.allocation, !(mask & (1u << i)));
    }
    history.push_back(*next);
    inodeTxn = kv_->createReadWriteTransaction();
    auto after = blockingWait(Inode::load(*inodeTxn, object.inode));
    ASSERT_OK(after);
    ASSERT_TRUE(*after);
    EXPECT_EQ((**after).mtime, preserved.mtime);
    EXPECT_EQ((**after).ctime, preserved.ctime);
    EXPECT_EQ((**after).acl.perm, preserved.acl.perm);
    inodeTxn.reset();
    // Old read scopes stay valid; only the repair WriteOperation was drained.
    for (const auto &pin : history) {
      auto read = readOne(pin, 0);
      ASSERT_OK(read);
      EXPECT_EQ(read->payload.data, original.shards[0]);
    }
  }
  auto txn = kv_->createReadWriteTransaction();
  for (const auto &pin : history) {
    for (const auto &fragment : pin.manifest.fragments) {
      uint64_t references = 0;
      for (const auto &revision : history)
        for (const auto &candidate : revision.manifest.fragments)
          references += serde::equals(candidate.identity, fragment.identity);
      auto actual = blockingWait(EcCatalog::getFragmentRef(*txn, fragment.identity));
      ASSERT_OK(actual);
      EXPECT_EQ(actual->references, references);
    }
  }
  txn.reset();
  // Metadata-only GC eligibility follows real Publish/Release TCP calls.
  // No Storage deletion is invoked, and current/shared shards stay readable.
  auto gcKey = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
  ASSERT_OK(gcKey);
  txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(EcCatalog::retireRevision(*txn, object, 0, history.front().manifest.revision)),
               StatusCode::kTokenStale);
  txn.reset();
  for (size_t old = 0; old + 1 < history.size(); ++old) {
    auto release = request<ReleaseEcReadV2Req>();
    release.object = object;
    release.pin = history[old].snapshot.pin;
    auto released = blockingWait(metaClient_->releaseEcReadV2(release));
    ASSERT_OK(released);
    EXPECT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
    txn = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(EcCatalog::retireRevision(*txn, object, 0, history[old].manifest.revision)));
    ASSERT_OK(blockingWait(txn->commit()));
    txn.reset();
  }
  const auto claimId = Uuid::random();
  txn = kv_->createReadWriteTransaction();
  auto gcClaim = blockingWait(
      EcV2GcCatalog::claim(*txn, object, history.front().manifest.fragments[0].identity, claimId, **gcKey));
  ASSERT_OK(gcClaim);
  EXPECT_EQ(gcClaim->allocation.fragment.operation, original.begin.operation);
  EXPECT_EQ(gcClaim->allocation.fragment.integrity, history.front().manifest.fragments[0].integrity);
  EXPECT_EQ(gcClaim->registeredScopes, gcClaim->releasedScopes);
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(
      blockingWait(
          EcV2GcCatalog::claim(*txn, object, history.back().manifest.fragments[11].identity, Uuid::random(), **gcKey)),
      StatusCode::kTokenStale);
  txn.reset();
  auto stillReadable = readOne(history.back(), 11);
  ASSERT_OK(stillReadable);
  EXPECT_EQ(stillReadable->payload.data, original.shards[11]);
  auto forgedRepair = request<BeginEcMutationV2Req>();
  forgedRepair.object = object;
  forgedRepair.operation = Uuid::random();
  forgedRepair.expectedEpoch = 1;
  forgedRepair.expectedRevision = history.back().manifest.revision;
  forgedRepair.kind = EcMutationKind::Repair;
  forgedRepair.replacementMask = kEcAllShards;
  forgedRepair.logicalLength = original.logical.size();
  forgedRepair.contentSha256 = original.begin.contentSha256;
  forgedRepair.contentSha256[0] ^= 1;
  for (size_t i = 0; i != 12; ++i) forgedRepair.fragmentCrc32c[i] = original.begin.fragmentCrc32c[i];
  ASSERT_ERROR(blockingWait(metaClient_->beginEcMutationV2(forgedRepair)), StatusCode::kTokenMismatch);
}

TEST_F(TestEcV2NativeLifecycle, BadParityCannotPublishAndUnavailableHistoricalTargetsDoNotBlockAcquire) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "degraded-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation bad;
  ASSERT_NO_FATAL_FAILURE(prepare(bad, object, 0, 73, true));
  ASSERT_NO_FATAL_FAILURE(writeFragments(bad));
  ASSERT_FALSE(blockingWait(metaClient_->publishEcMutationV2(bad.publish)));
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = bad.begin.operation;
  auto cancelled = blockingWait(metaClient_->cancelEcMutationV2(cancel));
  ASSERT_OK(cancelled);
  EXPECT_EQ(cancelled->record.state, EcOperationState::Aborted);
  EXPECT_EQ(cancelled->drain->acknowledgedEndpoints, 12);
  ASSERT_ERROR(blockingWait(metaClient_->bindEcMutationV2(bad.bind)), StatusCode::kTokenStale);
  Mutation good;
  ASSERT_NO_FATAL_FAILURE(prepare(good, object, 0, 79));
  ASSERT_NO_FATAL_FAILURE(writeFragments(good));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(good.publish)));
  for (size_t failures : {size_t{1}, size_t{2}}) {
    auto degraded = std::make_shared<flat::RoutingInfo>(*routing_);
    for (size_t i = 0; i != failures; ++i) degraded->targets.erase(storage::TargetId{2000 + i});
    degraded->routingInfoVersion = flat::RoutingInfoVersion{static_cast<uint64_t>(10 + failures)};
    fakeMgmtd_->setRoutingInfo(degraded);
    // Storage's physical targets remain real and unchanged. Actual client
    // routing lacks one/two targets, rather than a fabricated MAC rejection.
    auto pinned = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
    ASSERT_OK(pinned);
    EXPECT_EQ(pinned->contentSha256, good.begin.contentSha256);
    for (size_t i = 0; i != failures; ++i) ASSERT_FALSE(readOne(*pinned, i));
    storage::EcCodec::Shards received;
    std::array<storage::EcCodecShardView, 10> inputs;
    for (size_t slot = 0; slot != 10; ++slot) {
      const auto i = slot + failures;
      auto read = readOne(*pinned, i);
      ASSERT_OK(read);
      received[i] = std::move(read->payload.data);
      inputs[slot] = {static_cast<uint16_t>(i), received[i]};
    }
    auto recovered = storage::EcCodec::recover(inputs, good.logical.size(), kShardBytes);
    ASSERT_OK(recovered);
    EXPECT_EQ(*recovered, good.shards);
    RecordProperty(fmt::format("actual_missing_route_targets_{}", failures),
                   "Acquire succeeded; ten actual TCP blocks decoded");
  }
  fakeMgmtd_->setRoutingInfo(routing_);
}
TEST_F(TestEcV2NativeLifecycle, PendingActualScopeCannotReleasePinAndBindingRetainsOriginalInstance) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "pending-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation mutation;
  ASSERT_NO_FATAL_FAILURE(prepare(mutation, object, 0, 87));
  const auto originalEngine = mutation.reservation.grants[0]->claims.engineUuid;
  const auto configuredEngine = metaConfig_.ec_targets(0).engine_uuid();
  metaConfig_.ec_targets(0).set_engine_uuid(Uuid::random().toHexString());
  auto rebound = blockingWait(metaClient_->bindEcMutationV2(mutation.bind));
  ASSERT_OK(rebound);
  ASSERT_TRUE(rebound->grants[0]);
  EXPECT_EQ(rebound->grants[0]->claims.engineUuid, originalEngine);
  auto replay = blockingWait(metaClient_->beginEcMutationV2(mutation.begin));
  ASSERT_OK(replay);
  EXPECT_EQ(replay->reservation->candidates[0].endpoint.engineUuid, originalEngine);
  metaConfig_.ec_targets(0).set_engine_uuid(configuredEngine);
  ASSERT_NO_FATAL_FAILURE(writeFragments(mutation));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)));
  auto pinReq = readRequest(object);
  auto pin = blockingWait(metaClient_->acquireEcReadV2(pinReq));
  ASSERT_OK(pin);
  ASSERT_OK(readOne(*pin, 0));
  auto target = components_->targetMap.getByTargetId(pin->manifest.fragments[0].placement.target);
  ASSERT_OK(target);
  auto state = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(state);
  storage::EcScopeBinding binding{};
  binding.target = state->second;
  binding.kind = static_cast<uint8_t>(storage::EcGrantScope::ReadPin);
  binding.owner_uid = user_.uid.toUnderType();
  std::copy(std::begin(object.incarnation.data), std::end(object.incarnation.data), binding.object.begin());
  std::copy(std::begin(pinReq.pin.data), std::end(pinReq.pin.data), binding.scope.begin());
  std::copy(std::begin(metaClientId_.uuid.data), std::end(metaClientId_.uuid.data), binding.client_namespace.begin());
  auto admitted = state->first->tryAdmit(binding);
  ASSERT_OK(admitted);
  std::optional<storage::EcScopeTicket> ticket(std::move(*admitted));
  // This held real registry ticket models unfinished admitted work. It is not
  // described as an actual delayed disk job. Control transport/deny/ACKs and
  // Meta pin accounting remain the production implementations.
  metaConfig_.set_ec_v2_drain_timeout(100_ms);
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = pinReq.pin;
  ASSERT_ERROR(blockingWait(meta_->releaseEcReadV2(release)), MetaCode::kOperationTimeout);
  ASSERT_NO_FATAL_FAILURE(checkPin(object, pinReq.pin, false));
  ASSERT_FALSE(state->first->tryAdmit(binding));
  auto txn = kv_->createReadWriteTransaction();
  EcOwner owner{user_.uid, metaClientId_.uuid};
  auto closing = blockingWait(EcV2DrainCatalog::get(*txn, object, storage::EcGrantScope::ReadPin, pinReq.pin, owner));
  ASSERT_OK(closing);
  ASSERT_TRUE(*closing);
  EXPECT_EQ((**closing).state, EcV2DrainState::Closing);
  txn.reset();
  ticket.reset();
  metaConfig_.set_ec_v2_drain_timeout(60_s);
  auto done = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(done);
  EXPECT_EQ(done->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_NO_FATAL_FAILURE(checkPin(object, pinReq.pin, true));
}

TEST_F(TestEcV2NativeHelperPlan, CommittedPlanRenewalRetainsSelectionAndClosingStopsEveryGrant) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "helper-plan-v2");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 93));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto base = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(base);
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(prepareRepairMetadata(replacement, *base, 3));
  auto planReq = planRequest(replacement);
  auto denied = planReq;
  denied.user.uid = flat::Uid{99999999};
  ASSERT_FALSE(blockingWait(metaClient_->prepareEcRepairV2(denied)));
  denied = planReq;
  denied.client = ClientId::random();
  ASSERT_ERROR(blockingWait(meta_->prepareEcRepairV2(denied)), MetaCode::kNoPermission);
  replyDrop_.arm(replacement.begin.operation);
  auto prepared = blockingWait(metaClient_->prepareEcRepairV2(planReq));
  ASSERT_OK(prepared);
  EXPECT_GE(replyDrop_.snapshot().calls, 2u);
  ASSERT_TRUE(replyDrop_.snapshot().committed);
  ASSERT_TRUE(prepared->helpers);
  ASSERT_TRUE(prepared->mutation.reservation);
  auto plan = storage::EcRepairPlan::create(prepared->plan);
  ASSERT_OK(plan);
  auto key = storage::EcHelperKey::loadFile(helperKeyPath_.string());
  ASSERT_OK(key);
  const uint64_t now =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  for (size_t i = 0; i != 10; ++i) {
    const auto shard = planReq.sourceOrder[i];
    EXPECT_TRUE(serde::equals(prepared->plan.sources[i].identity, base->manifest.fragments[shard].identity));
    EXPECT_EQ(prepared->plan.sources[i].operationId, base->manifest.fragments[shard].operation);
    EXPECT_EQ(prepared->plan.sources[i].writerNamespace, original.reservation.record.owner.client);
    ASSERT_OK(storage::verifyEcHelperGrant(**key,
                                           (*prepared->helpers)[i],
                                           **plan,
                                           prepared->plan.sources[i].endpoint,
                                           static_cast<uint8_t>(i),
                                           0,
                                           now));
    EXPECT_EQ((*prepared->helpers)[i].claims.planDigest, (*plan)->digest());
    ASSERT_TRUE(prepared->mutation.grants[shard]);
    EXPECT_EQ(prepared->mutation.grants[shard]->claims.scopeId, replacement.begin.operation);
  }
  auto renewed = blockingWait(metaClient_->prepareEcRepairV2(planReq));
  ASSERT_OK(renewed);
  EXPECT_EQ(serde::serialize(renewed->plan), serde::serialize(prepared->plan));
  ASSERT_TRUE(renewed->helpers);
  EXPECT_NE((*renewed->helpers)[0].claims.grantId, (*prepared->helpers)[0].claims.grantId);
  auto changed = planReq;
  std::swap(changed.sourceOrder[0], changed.sourceOrder[1]);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(changed)), StatusCode::kTokenMismatch);
  changed = planReq;
  changed.planId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(changed)), StatusCode::kTokenMismatch);
  changed = planReq;
  changed.maxBlocksInFlight = 2;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(changed)), StatusCode::kTokenMismatch);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0400}; }));
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(planReq)), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0600}; }));
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = replacement.begin.operation;
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.scope = replacement.begin.operation;
    controlFault_.fail = true;
  }
  ASSERT_ERROR(blockingWait(metaClient_->cancelEcMutationV2(cancel)), StatusCode::kNotImplemented);
  auto get = request<GetEcOperationV2Req>();
  get.object = object;
  get.operation = replacement.begin.operation;
  auto closing = blockingWait(metaClient_->getEcOperationV2(get));
  ASSERT_OK(closing);
  ASSERT_TRUE(closing->drain);
  EXPECT_EQ(closing->record.state, EcOperationState::Preparing);
  EXPECT_EQ(closing->drain->state, EcV2DrainState::Closing);
  auto historyTxn = kv_->createReadWriteTransaction();
  auto beforeHistory = blockingWait(ec_v2_lifecycle::readIssuanceSequence(
      *historyTxn, object, storage::EcGrantScope::WriteOperation, replacement.begin.operation));
  ASSERT_OK(beforeHistory);
  historyTxn.reset();
  auto history = blockingWait(metaClient_->prepareEcRepairV2(planReq));
  ASSERT_OK(history);
  EXPECT_FALSE(history->helpers);
  for (const auto &grant : history->mutation.grants) EXPECT_FALSE(grant);
  historyTxn = kv_->createReadWriteTransaction();
  auto afterHistory = blockingWait(ec_v2_lifecycle::readIssuanceSequence(
      *historyTxn, object, storage::EcGrantScope::WriteOperation, replacement.begin.operation));
  ASSERT_OK(afterHistory);
  EXPECT_EQ(*beforeHistory, *afterHistory);
  historyTxn.reset();
  {
    std::lock_guard lock(controlFault_.mutex);
    EXPECT_GE(controlFault_.actualRevokes, 1u);
    controlFault_.fail = false;
  }
  ASSERT_OK(blockingWait(metaClient_->cancelEcMutationV2(cancel)));
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(planReq)), StatusCode::kTokenStale);
  // Cancellation drained the repair scope but did not retire the reader's
  // original pin or reinterpret token expiry as physical deletion authority.
  auto actual = readOne(*base, 0);
  ASSERT_OK(actual);
  EXPECT_EQ(actual->payload.data, original.shards[0]);
}

TEST_F(TestEcV2NativeLifecycle, MissingHelperKeyKeepsNativePlanButCannotIssueHelperAuthority) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "without-helper-key");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, created->object.object, 0, 101));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto base = blockingWait(metaClient_->acquireEcReadV2(readRequest(created->object.object)));
  ASSERT_OK(base);
  Mutation repaired;
  ASSERT_NO_FATAL_FAILURE(prepareRepairMetadata(repaired, *base, 1));
  auto prepared = blockingWait(metaClient_->prepareEcRepairV2(planRequest(repaired)));
  ASSERT_OK(prepared);
  EXPECT_FALSE(prepared->helpers);
  ASSERT_OK(storage::EcRepairPlan::create(prepared->plan));
  EXPECT_EQ(prepared->plan.logicalSha256, base->contentSha256);
}

TEST_F(TestEcV2NativeHelperPlan, KeyFileAliasesAreRejectedAtCoordinatorInitialization) {
  const auto alias = traces_.path() / "same-material-hardlink.key";
  std::error_code error;
  std::filesystem::create_hard_link(std::filesystem::path(keyPath_.string()),
                                    std::filesystem::path(alias.string()),
                                    error);
  ASSERT_FALSE(error) << error.message();
  const auto originalControl = metaConfig_.ec_v2_control_key_file();
  metaConfig_.set_ec_v2_control_key_file(alias);
  EcV2Coordinator dataAlias(metaConfig_, mgmtd_, storageClient_);
  ASSERT_ERROR(dataAlias.checkEnabled(), StatusCode::kInvalidConfig);
  metaConfig_.set_ec_v2_control_key_file(originalControl);
  const auto originalHelper = metaConfig_.ec_v2_helper_key_file();
  metaConfig_.set_ec_v2_helper_key_file(alias);
  EcV2Coordinator helperAlias(metaConfig_, mgmtd_, storageClient_);
  ASSERT_ERROR(helperAlias.checkEnabled(), StatusCode::kInvalidConfig);
  metaConfig_.set_ec_v2_helper_key_file(originalHelper);
}

TEST_F(TestEcV2NativeLifecycle, StripeManagerCreateUsesConnectedIdentityBeforeValidatingCallerRequest) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor pool(2);
  auto borrowedMeta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected =
      blockingWait(EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, pool, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT { blockingWait(manager->close()); };
  auto control = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; };
  CreateEcFileV2Req create;
  // Default production requests have no client identity. Clear it explicitly
  // because ReqBase can inherit a test-global client ID in this fixture.
  create.client = ClientId{Uuid::zero()};
  create.path = PathAt(parent_, "stripe-manager-default-create");
  create.shardBytes = 65543;
  ASSERT_ERROR(blockingWait(manager->createFile(create, control())), StatusCode::kInvalidArg);
  create.uuid = Uuid::random();
  const auto originalRequest = create.uuid;
  auto created = blockingWait(manager->createFile(create, control()));
  ASSERT_OK(created);
  EXPECT_EQ(created->object.creator.uid, user_.uid);
  EXPECT_EQ(created->object.creator.client, metaClientId_.uuid);
  EXPECT_EQ(created->object.createRequest, originalRequest);

  // A caller cannot select a different owner by filling the wire DTO. Replay
  // still uses the same authenticated manager, original UUID and object.
  create.client = ClientId::random();
  create.user = flat::UserInfo{};
  create.user.uid = flat::Uid(0);
  auto replayed = blockingWait(manager->createFile(create, control()));
  ASSERT_OK(replayed);
  EXPECT_EQ(replayed->object.object, created->object.object);
  EXPECT_EQ(replayed->object.creator.uid, created->object.creator.uid);
  EXPECT_EQ(replayed->object.creator.client, created->object.creator.client);
  EXPECT_EQ(replayed->object.createRequest, originalRequest);
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
}

TEST_F(TestEcV2NativeLifecycle, StripeManagerOwnsWriteAndReadsThroughTwoMissingRoutes) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor pool(4);
  // Fixture owns this client until after the manager's explicit close/join.
  auto borrowedMeta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected =
      blockingWait(EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, pool, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT { blockingWait(manager->close()); };
  auto control = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}}; };
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "stripe-manager");
  create.shardBytes = 65543;  // two integrity blocks, with a seven-byte final block
  auto created = blockingWait(manager->createFile(create, control()));
  ASSERT_OK(created);
  EcStripeWrite write;
  write.object = created->object;
  write.ids = {Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random()};
  write.logicalData = bytes(10 * create.shardBytes - 37, 101);
  replyDrop_.arm(write.ids.operation);
  {
    // Starting is synchronous: dropping an un-awaited waiter does not drop
    // input/codeword or cancel the real managed Meta/Storage operation.
    auto abandoned = manager->write(write, control());
  }
  auto query = request<GetEcOperationV2Req>();
  query.object = write.object.object;
  query.operation = write.ids.operation;
  bool published = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
  while (std::chrono::steady_clock::now() < deadline) {
    auto observed = blockingWait(metaClient_->getEcOperationV2(query));
    if (observed && observed->record.state == EcOperationState::Published) {
      published = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  ASSERT_TRUE(published);
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  ASSERT_TRUE(replyDrop_.snapshot().committed);
  connected =
      blockingWait(EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, pool, {}));
  ASSERT_OK(connected);
  manager = *connected;
  auto replayed = blockingWait(manager->write(write, control()));
  ASSERT_TRUE(replayed.published()) << (replayed.failure ? replayed.failure->describe() : "not published");
  for (size_t missing : {size_t{0}, size_t{1}, size_t{2}}) {
    auto routes = std::make_shared<flat::RoutingInfo>(*routing_);
    for (size_t i = 0; i != missing; ++i) routes->targets.erase(storage::TargetId{2000 + i});
    routes->routingInfoVersion = flat::RoutingInfoVersion{30 + missing};
    fakeMgmtd_->setRoutingInfo(routes);
    EcStripePinIds pin{write.object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
    auto session = manager->startRead(pin, control());
    ASSERT_OK(session);
    auto output = blockingWait(session->takeReady());
    ASSERT_OK(output);
    EXPECT_EQ(output->logicalData, write.logicalData);
    blockingWait(session->waitLocalCleanup());
    EXPECT_EQ(manager->snapshot().activeOperations, 0);
    EXPECT_EQ(manager->snapshot().reservedApplicationBytes, output->logicalData.capacity());
    // Restore routing before the all-endpoint remote drain, which deliberately
    // requires all twelve actual instances rather than a ten-shard quorum.
    fakeMgmtd_->setRoutingInfo(routing_);
    auto released = blockingWait(manager->release(*session, control()));
    ASSERT_OK(released);
    EXPECT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
    EXPECT_EQ(released->drain.acknowledgedEndpoints, released->drain.expectedEndpoints);
    output = makeError(StatusCode::kInterrupted);
    EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  }
  auto changed = write;
  changed.logicalData[0] ^= 1;
  auto mismatch = blockingWait(manager->write(std::move(changed), control()));
  ASSERT_TRUE(mismatch.failure);
  EXPECT_EQ(mismatch.failure->code(), StatusCode::kTokenMismatch);
  RecordProperty("stripe_manager_logical_bytes", std::to_string(write.logicalData.size()));
  RecordProperty("stripe_manager_shard_bytes", std::to_string(create.shardBytes));
  RecordProperty("stripe_manager_blocks_per_shard", "2");
  RecordProperty("actual_missing_route_candidates", "0,1,2; all decoded through real Storage TCP");
}

// Inspect the final sample from real Meta/FDB + Storage TCP work. Flat repair
// has no healthy-copy phase: all first-hop samples belong to selected repair.
void expectFlatRepairMetrics(
    const hf3fs::client::ec::EcRepairSample &metrics,
    const std::array<uint64_t, size_t(storage::client::EcRpcMethod::Count)> &expectedCalls) {
  using namespace hf3fs::client::ec;
  using storage::client::EcRpcMethodSample;
  ASSERT_TRUE(metrics.available);
  EXPECT_EQ(metrics.action, 1);
  EXPECT_FALSE(metrics.overflow);
  EXPECT_FALSE(metrics.clockAnomaly);
  EXPECT_FALSE(metrics.journalStateObserved);  // The manager does not own the CLI's journal.
  for (const auto &point : metrics.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.finished, point.entered);
  }
  for (const auto point : {EcRepairPoint::HealthyCopy, EcRepairPoint::CopyRead, EcRepairPoint::CopyBegin,
                           EcRepairPoint::CopyReconcile, EcRepairPoint::CopyAppend, EcRepairPoint::CopySeal})
    EXPECT_EQ(metrics.at(point).entered, 0);
  EXPECT_FALSE(metrics.storageRpc.overflow);
  EXPECT_FALSE(metrics.selectedRepairRpc.overflow);
  EXPECT_FALSE(metrics.healthyCopyRpc.overflow);
  const auto json = folly::parseJson(repairMetricsJson(metrics));
  EXPECT_EQ(json["schema"].asInt(), 1);
  EXPECT_EQ(json["scope"].asString(), "this_call");
  EXPECT_TRUE(json["wire_bytes"].isNull());
  EXPECT_TRUE(json["transport_retry_attempts"].isNull());
  EXPECT_TRUE(json["helper_server_compute"].isNull());
  const auto &rpcJson = json["storage_rpc"];
  EXPECT_EQ(rpcJson["coverage"].asString(), "controlled_client_to_storage_first_hop");
  EXPECT_TRUE(rpcJson["helper_downstream_bytes"].isNull());
  EXPECT_TRUE(rpcJson["complete_server_queue"].isNull());
  for (size_t i = 0; i != expectedCalls.size(); ++i) {
    SCOPED_TRACE(storage::client::kEcRpcMethodNames[i]);
    const auto &total = metrics.storageRpc.methods[i];
    const auto &selected = metrics.selectedRepairRpc.methods[i];
    const auto &copy = metrics.healthyCopyRpc.methods[i];
    EXPECT_EQ(total.entered, expectedCalls[i]);
    EXPECT_EQ(total.finished, total.entered);
    EXPECT_EQ(total.active, 0);
    EXPECT_EQ(total.outerOk, total.entered);
    EXPECT_EQ(total.outerError, 0);
    EXPECT_EQ(total.withoutResult, 0);
    EXPECT_EQ(total.messengerInvocations, total.entered);
    EXPECT_EQ(total.withoutMessenger, 0);
    EXPECT_EQ(total.observedEncodedRequestFrames, total.entered);
    EXPECT_EQ(total.observedEncodedResponseFrames, total.entered);
    EXPECT_EQ(total.missingEncodedRequestFrames, 0);
    EXPECT_EQ(total.missingEncodedResponseFrames, 0);
    EXPECT_GE(total.requestFrameBytes, total.entered * uint64_t{8});
    EXPECT_GE(total.responseFrameBytes, total.entered * uint64_t{8});
    // Finished local scopes permit additive comparisons. Peaks are deliberately
    // not added: these counters are not a globally atomic concurrent snapshot.
    for (auto field : {&EcRpcMethodSample::entered, &EcRpcMethodSample::finished, &EcRpcMethodSample::active,
                       &EcRpcMethodSample::outerOk, &EcRpcMethodSample::outerError, &EcRpcMethodSample::withoutResult,
                       &EcRpcMethodSample::messengerInvocations, &EcRpcMethodSample::withoutMessenger,
                       &EcRpcMethodSample::observedEncodedRequestFrames, &EcRpcMethodSample::requestFrameBytes,
                       &EcRpcMethodSample::missingEncodedRequestFrames, &EcRpcMethodSample::compressedRequestFrames,
                       &EcRpcMethodSample::observedEncodedResponseFrames, &EcRpcMethodSample::responseFrameBytes,
                       &EcRpcMethodSample::missingEncodedResponseFrames, &EcRpcMethodSample::compressedResponseFrames}) {
      EXPECT_EQ(total.*field, selected.*field);
      EXPECT_EQ(copy.*field, 0);
      if (!expectedCalls[i]) EXPECT_EQ(total.*field, 0);
    }
    for (const auto &limiter : total.limiters) {
      EXPECT_EQ(limiter.active, 0);
      EXPECT_EQ(limiter.entered, limiter.finished);
    }
    const auto *name = storage::client::kEcRpcMethodNames[i];
    const auto &methodJson = rpcJson["methods"][name];
    EXPECT_EQ(methodJson["frame_entered_decimal"].asString(), std::to_string(expectedCalls[i]));
    EXPECT_EQ(methodJson["request_frame_bytes_decimal"].asString(), std::to_string(total.requestFrameBytes));
    EXPECT_EQ(methodJson["response_frame_bytes_decimal"].asString(), std::to_string(total.responseFrameBytes));
    EXPECT_EQ(rpcJson["by_phase"]["selected_repair"]["methods"][name]["frame_entered_decimal"].asString(),
              std::to_string(expectedCalls[i]));
    EXPECT_EQ(rpcJson["by_phase"]["healthy_copy"]["methods"][name]["frame_entered_decimal"].asString(), "0");
  }
}

TEST_F(TestEcV2NativeHelperPlan, StripeManagerRunsAllExplicitRepairStrategiesThroughMetaIssuedPlan) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor pool(4);
  auto borrowedMeta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected =
      blockingWait(EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, pool, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT { blockingWait(manager->close()); };
  auto control = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}}; };
  auto ids = [] {
    return EcStripeMutationIds{Uuid::random(),
                               Uuid::random(),
                               Uuid::random(),
                               Uuid::random(),
                               Uuid::random(),
                               Uuid::random()};
  };
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "stripe-manager-three-modes");
  create.shardBytes = 65543;
  auto created = blockingWait(manager->createFile(create, control()));
  ASSERT_OK(created);
  EcStripeWrite write;
  write.object = created->object;
  write.ids = ids();
  write.logicalData = bytes(10 * create.shardBytes - 37, 131);
  auto written = blockingWait(manager->write(write, control()));
  ASSERT_TRUE(written.published()) << (written.failure ? written.failure->describe() : "not published");
  auto object = written.observation->object;
  auto revision = written.observation->record.candidate.revision;
  const std::array<EcRepairMode, 3> modes{EcRepairMode::CentralSerial,
                                          EcRepairMode::ClientPipeline,
                                          EcRepairMode::HelperChain};
  const std::array<uint16_t, 3> masks{1, 6, 24};
  for (size_t round = 0; round != modes.size(); ++round) {
    EcStripeRepair repair;
    repair.object = object;
    repair.expectedRevision = revision;
    repair.ids = ids();
    repair.baseRead = {object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
    repair.planId = Uuid::random();
    repair.replacementMask = masks[round];
    repair.blockWindow = 2;
    repair.mode = modes[round];
    repair.collectMetrics = true;
    size_t source = 0;
    for (uint16_t i = 0; i != 12 && source != 10; ++i)
      if (!(repair.replacementMask & (1u << i))) repair.sources[source++] = i;
    // The first round gets an injected error after real durable revoke during
    // Publish. The data path completed; retrying the fixed operation only finishes
    // its existing Closing drain and must not inherit those data samples.
    size_t revokeBaseline = 0;
    if (round == 0) {
      std::lock_guard lock(controlFault_.mutex);
      revokeBaseline = controlFault_.actualRevokes;
      controlFault_.scope = repair.ids.operation;
      controlFault_.fail = true;
    }
    auto repaired = blockingWait(manager->repair(repair, control()));
    const auto dataMetrics = repaired.repairMetrics;
    ASSERT_TRUE(repaired.repairDataPhaseEntered);
    const uint64_t targets = std::popcount(repair.replacementMask);
    const bool helper = repair.mode == EcRepairMode::HelperChain;
    ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(
        dataMetrics, {helper ? 0ULL : 20ULL, targets, 2 * targets, 0, 0, targets, helper ? 2ULL : 0ULL, 0}));
    EXPECT_EQ(dataMetrics.configuredWindow, repair.blockWindow);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::Query).entered, 1);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::Query).succeeded, 0);  // Fresh operation does not exist yet.
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::Begin).succeeded, 1);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::Prepare).succeeded, 3);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::SelectedRepair).succeeded, 1);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::NativeAppend).submittedPayloadBytes, targets * create.shardBytes);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::NativeSeal).succeeded, targets);
    EXPECT_EQ(dataMetrics.blockActorsApplicable, repair.mode != EcRepairMode::CentralSerial);
    EXPECT_LE(dataMetrics.at(EcRepairPoint::BlockActor).peakActive, repair.blockWindow);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::CentralCodecRecover).entered,
              repair.mode == EcRepairMode::CentralSerial ? 1 : 0);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::ClientBlockAdvance).entered,
              repair.mode == EcRepairMode::ClientPipeline ? 20 : 0);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::NativeRead).validatedReturnedPayloadBytes,
              helper ? 0 : 10ULL * create.shardBytes);
    EXPECT_EQ(dataMetrics.at(EcRepairPoint::NativeHelper).validatedReturnedPayloadBytes,
              helper ? targets * create.shardBytes : 0);
    if (round == 0) {
      ASSERT_TRUE(repaired.failure);
      EXPECT_EQ(repaired.failure->code(), StorageCode::kEcSealOutcomeUnknown);
      EXPECT_EQ(repaired.phase, EcStripePhase::Publish);
      EXPECT_EQ(dataMetrics.at(EcRepairPoint::Publish).entered, 1);
      // publish() resolves its failed RPC attempts through Get and returns the
      // real Closing record. Result success does not mean business Published.
      EXPECT_EQ(dataMetrics.at(EcRepairPoint::Publish).succeeded, 1);
      {
        std::lock_guard lock(controlFault_.mutex);
        EXPECT_GT(controlFault_.actualRevokes, revokeBaseline);
        controlFault_.fail = false;
      }
      auto get = request<GetEcOperationV2Req>();
      get.object = repair.object.object;
      get.operation = repair.ids.operation;
      auto closing = blockingWait(metaClient_->getEcOperationV2(get));
      ASSERT_OK(closing);
      ASSERT_TRUE(closing->drain);
      EXPECT_EQ(closing->drain->state, EcV2DrainState::Closing);
      repaired = blockingWait(manager->repair(repair, control()));
      EXPECT_FALSE(repaired.repairDataPhaseEntered);
      ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(repaired.repairMetrics, {}));
      EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::Query).succeeded, 1);
      EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::Prepare).succeeded, 1);
      EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::Publish).succeeded, 1);
      EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::SelectedRepair).entered, 0);
    } else {
      EXPECT_EQ(dataMetrics.at(EcRepairPoint::Publish).succeeded, 1);
    }
    ASSERT_TRUE(repaired.published()) << (repaired.failure ? repaired.failure->describe() : "not published");
    EXPECT_EQ(repaired.observation->record.candidate.generation, written.observation->record.candidate.generation);
    object = repaired.observation->object;
    revision = repaired.observation->record.candidate.revision;
    EcStripePinIds pin{object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
    auto read = manager->startRead(pin, control());
    ASSERT_OK(read);
    auto output = blockingWait(read->takeReady());
    ASSERT_OK(output);
    EXPECT_EQ(output->logicalData, write.logicalData);
    EXPECT_EQ(output->pinned.manifest.revision, revision);
    blockingWait(read->waitLocalCleanup());
    auto readReleased = blockingWait(manager->release(*read, control()));
    ASSERT_OK(readReleased);
    EXPECT_EQ(readReleased->drain.state, EcV2DrainState::ReadReleased);
    auto baseReleased = blockingWait(manager->release(repair.baseRead, control()));
    ASSERT_OK(baseReleased);
    EXPECT_EQ(baseReleased->drain.state, EcV2DrainState::ReadReleased);
    // Resume after the auxiliary base pin has already been released: Get of
    // the same durable operation must recover Published before another Acquire.
    auto replay = blockingWait(manager->repair(repair, control()));
    ASSERT_TRUE(replay.published()) << (replay.failure ? replay.failure->describe() : "not published");
    EXPECT_EQ(replay.observation->record.candidate.revision, revision);
    EXPECT_FALSE(replay.repairDataPhaseEntered);
    ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(replay.repairMetrics, {}));
    EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Query).succeeded, 1);
    EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Prepare).succeeded, 1);
    EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::SelectedRepair).entered, 0);
    EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Publish).entered, 0);
    auto disabled = repair;
    disabled.collectMetrics = false;
    auto unobserved = blockingWait(manager->repair(disabled, control()));
    ASSERT_TRUE(unobserved.published());
    EXPECT_FALSE(unobserved.repairMetrics.available);
    EXPECT_EQ(unobserved.repairMetrics.elapsedNs, 0);
    for (const auto &point : unobserved.repairMetrics.points) EXPECT_EQ(point.entered, 0);
    for (const auto &method : unobserved.repairMetrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
    PrepareEcRepairDirectV2Req wrongDelivery;
    static_cast<PrepareEcRepairV2Req &>(wrongDelivery) = request<PrepareEcRepairV2Req>();
    wrongDelivery.object = repair.object.object;
    wrongDelivery.operation = repair.ids.operation;
    wrongDelivery.planId = repair.planId;
    wrongDelivery.maxBlocksInFlight = repair.blockWindow;
    for (size_t i = 0; i != repair.sources.size(); ++i) wrongDelivery.sourceOrder[i] = repair.sources[i];
    ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(wrongDelivery)), StatusCode::kTokenMismatch);
    RecordProperty(fmt::format("native_strategy_{}", round), static_cast<int>(modes[round]));
  }
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  RecordProperty("flat_metrics", "real first-hop encoded frames; selected only; Closing/Published are per-call");
  RecordProperty("trusted_plan_issuance", "real Meta37 with independent helper signing key");
  RecordProperty("physical_failure_domains", "one process/disk; not a multi-node benchmark");
}

TEST_F(TestEcV2NativeHelperPlan, PartialRepairSurvivesStorageReopenAndPublishesThroughOriginalMetaPlan) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(4);
  auto borrowedMeta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected = blockingWait(
      EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, executor, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT {
    if (manager) blockingWait(manager->close());
  };
  auto managerControl = [] {
    return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}};
  };
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "partial-repair-storage-reopen");
  create.shardBytes = storage::kEcIntegrityBlockBytes + 7;
  auto created = blockingWait(manager->createFile(create, managerControl()));
  ASSERT_OK(created);
  EcStripeWrite write;
  write.object = created->object;
  write.ids = {Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random()};
  write.logicalData = bytes(10 * create.shardBytes - 37, 197);
  auto written = blockingWait(manager->write(write, managerControl()));
  ASSERT_TRUE(written.published()) << (written.failure ? written.failure->describe() : "not published");
  ASSERT_TRUE(written.observation);
  const auto baseObject = written.observation->object;

  // Freeze real Meta intent/descriptor/plan records before creating a partial
  // stage. Only the first block bytes come from the known original input;
  // the subsequent recovery reads healthy fragments through actual TCP RPCs.
  auto acquire = readRequest(baseObject.object);
  auto base = blockingWait(metaClient_->acquireEcReadV2(acquire));
  ASSERT_OK(base);
  Mutation replacement;
  constexpr uint16_t mask = (1u << 0) | (1u << 11);
  ASSERT_NO_FATAL_FAILURE(prepareRepairMetadata(replacement, *base, mask));
  auto planReq = planRequest(replacement);
  planReq.maxBlocksInFlight = 1;
  auto issued = blockingWait(metaClient_->prepareEcRepairV2(planReq));
  ASSERT_OK(issued);
  ASSERT_TRUE(issued->helpers);
  ASSERT_TRUE(issued->mutation.allocations);
  auto originalPlan = storage::EcRepairPlan::create(issued->plan);
  ASSERT_OK(originalPlan);
  ASSERT_EQ((*originalPlan)->blockCount(), 2);
  ASSERT_EQ((*originalPlan)->input().targetCount, 2);
  const auto planDigest = (*originalPlan)->digest();
  const auto fixedCandidate = issued->mutation.record.candidate;
  auto originalShards = storage::EcCodec::encode(write.logicalData, create.shardBytes);
  ASSERT_OK(originalShards);
  for (const auto shard : {uint16_t{0}, uint16_t{11}}) {
    ASSERT_TRUE(issued->mutation.grants[shard]);
    storage::EcBeginStageV2Req begin;
    begin.request = access((*issued->mutation.allocations)[shard]);
    begin.grant = *issued->mutation.grants[shard];
    ASSERT_OK(blockingWait(storageClient_->beginEcStageV2Controlled(begin, control())));
    storage::EcAppendStageV2Req append;
    append.request = begin.request;
    append.grant = begin.grant;
    append.blockIndex = 0;
    append.payload.data = (*originalShards)[shard].substr(0, storage::kEcIntegrityBlockBytes);
    auto progress = blockingWait(storageClient_->appendEcStageV2Controlled(std::move(append), control()));
    ASSERT_OK(progress);
    ASSERT_EQ(progress->state, 1);
    ASSERT_EQ(progress->prefixBytes, storage::kEcIntegrityBlockBytes);
    ASSERT_FALSE(progress->needsReconcile);
  }

  // No detached waiter, manager operation, or direct RPC remains in flight.
  // The authenticated Meta endpoint and FDB database are intentionally kept.
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  manager.reset();
  const auto *sameMeta = meta_.get();
  const auto *sameMetaServer = metaServer_.get();
  const auto *sameFdb = kv_.get();
  ASSERT_NO_FATAL_FAILURE(reopenStorageKeepingMeta());
  EXPECT_EQ(meta_.get(), sameMeta);
  EXPECT_EQ(metaServer_.get(), sameMetaServer);
  EXPECT_EQ(kv_.get(), sameFdb);

  for (const auto shard : {uint16_t{0}, uint16_t{11}}) {
    storage::EcQueryStageV2Req query;
    query.request = access((*issued->mutation.allocations)[shard]);
    query.grant = *issued->mutation.grants[shard];
    auto restored = blockingWait(storageClient_->queryEcStageV2Controlled(std::move(query), control()));
    ASSERT_OK(restored);
    ASSERT_EQ(restored->state, 1);
    ASSERT_EQ(restored->prefixBytes, storage::kEcIntegrityBlockBytes);
    ASSERT_TRUE(restored->needsReconcile);
  }
  auto renewed = blockingWait(metaClient_->prepareEcRepairV2(planReq));
  ASSERT_OK(renewed);
  ASSERT_EQ(renewed->mutation.record.state, EcOperationState::Preparing);
  ASSERT_FALSE(renewed->mutation.drain);
  auto restoredPlan = storage::EcRepairPlan::create(renewed->plan);
  ASSERT_OK(restoredPlan);
  EXPECT_EQ((*restoredPlan)->digest(), planDigest);
  EXPECT_EQ(renewed->plan.planId, planReq.planId);
  EXPECT_EQ(renewed->plan.operationId, replacement.begin.operation);
  for (size_t i = 0; i != 12; ++i) {
    EXPECT_TRUE(
        serde::equals(renewed->mutation.record.candidate.fragments[i].identity, fixedCandidate.fragments[i].identity));
    EXPECT_EQ(renewed->mutation.record.candidate.fragments[i].operation, fixedCandidate.fragments[i].operation);
  }

  connected = blockingWait(
      EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, executor, {}));
  ASSERT_OK(connected);
  manager = *connected;
  EcStripeRepair resume;
  resume.object = baseObject;
  resume.expectedRevision = base->manifest.revision;
  resume.ids = {replacement.begin.operation,
                replacement.begin.uuid,
                replacement.bind.uuid,
                replacement.publish.uuid,
                Uuid::random(),
                planReq.uuid};
  resume.baseRead = {baseObject.object, acquire.stripe, acquire.pin, acquire.uuid, Uuid::random()};
  resume.planId = planReq.planId;
  resume.replacementMask = mask;
  resume.blockWindow = planReq.maxBlocksInFlight;
  resume.mode = EcRepairMode::HelperChain;
  std::copy(planReq.sourceOrder.begin(), planReq.sourceOrder.end(), resume.sources.begin());
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.observedRepair = replacement.begin.operation;
    controlFault_.actualPartialReconciles.fill(0);
    controlFault_.actualHelperBlocks.fill(0);
  }
  // This path must reconcile the actual restored partial stages, use the
  // original Meta37 plan, complete the authenticated helper chain, and then
  // execute Meta's full verification/revoke/ACK/publication sequence.
  auto repaired = blockingWait(manager->repair(resume, managerControl()));
  ASSERT_TRUE(repaired.published()) << (repaired.failure ? repaired.failure->describe() : "not published");
  ASSERT_TRUE(repaired.observation);
  {
    std::lock_guard lock(controlFault_.mutex);
    EXPECT_GE(controlFault_.actualPartialReconciles[0], 1u);
    EXPECT_GE(controlFault_.actualPartialReconciles[11], 1u);
    for (const auto blocks : controlFault_.actualHelperBlocks) EXPECT_EQ(blocks, 3u);
  }
  EXPECT_EQ(repaired.operation, replacement.begin.operation);
  EXPECT_EQ(repaired.observation->record.candidate.generation, base->manifest.generation);
  EXPECT_EQ(repaired.observation->record.candidate.revision, fixedCandidate.revision);
  for (size_t i = 0; i != 12; ++i) {
    EXPECT_TRUE(serde::equals(repaired.observation->record.candidate.fragments[i].identity,
                              fixedCandidate.fragments[i].identity));
    EXPECT_EQ(repaired.observation->record.candidate.fragments[i].operation, fixedCandidate.fragments[i].operation);
  }
  ASSERT_TRUE(repaired.observation->drain);
  EXPECT_EQ(repaired.observation->drain->state, EcV2DrainState::Published);
  ASSERT_GT(repaired.observation->drain->expectedEndpoints, 0);
  EXPECT_EQ(repaired.observation->drain->acknowledgedEndpoints, repaired.observation->drain->expectedEndpoints);
  {
    // The public response exposes progress only. Read and verify the complete
    // persisted evidence through the same real FDB instance after publication.
    auto txn = kv_->createReadWriteTransaction();
    auto record = blockingWait(EcV2DrainCatalog::get(*txn,
                                                     baseObject.object,
                                                     storage::EcGrantScope::WriteOperation,
                                                     replacement.begin.operation,
                                                     manager->owner()));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    EXPECT_EQ((**record).state, EcV2DrainState::Published);
    ASSERT_EQ((**record).identity.endpoints.count, repaired.observation->drain->expectedEndpoints);
    auto key = storage::EcScopeControlKey::loadFile(controlKeyPath_.string());
    ASSERT_OK(key);
    for (size_t i = 0; i != (**record).identity.endpoints.count; ++i) {
      ASSERT_TRUE((**record).observations[i]);
      const auto &observed = *(**record).observations[i];
      ASSERT_OK(EcVerifiedDrainAck::verify(**key, **record, i, observed.request, observed.ack));
    }
  }

  EcStripePinIds finalPin{baseObject.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
  auto read = manager->startRead(finalPin, managerControl());
  ASSERT_OK(read);
  {
    auto output = blockingWait(read->takeReady());
    ASSERT_OK(output);
    EXPECT_EQ(output->logicalData, write.logicalData);
    EXPECT_EQ(output->pinned.manifest.revision, fixedCandidate.revision);
    EXPECT_EQ(output->contentSha256, base->contentSha256);
  }
  blockingWait(read->waitLocalCleanup());
  auto finalReleased = blockingWait(manager->release(*read, managerControl()));
  ASSERT_OK(finalReleased);
  EXPECT_EQ(finalReleased->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_NO_FATAL_FAILURE(checkPin(baseObject.object, acquire.pin, false));
  auto baseReleased = blockingWait(manager->release(resume.baseRead, managerControl()));
  ASSERT_OK(baseReleased);
  EXPECT_EQ(baseReleased->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_NO_FATAL_FAILURE(checkPin(baseObject.object, acquire.pin, true));
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  RecordProperty("recovered_stage_prefix_bytes", std::to_string(storage::kEcIntegrityBlockBytes));
  RecordProperty("recovered_replacement_shards", "0,11");
  RecordProperty("recovery_boundary", "normal Storage Engine reopen, same live Meta/FDB; no power-loss claim");
}

class TestEcV2NativeExactGc : public TestEcV2NativeLifecycle {
 protected:
  bool enableExactGc() const override { return true; }

  void makeGc(std::shared_ptr<const storage::EcGcKey> &key,
              std::shared_ptr<NativeEcGcTransport> &transport,
              std::unique_ptr<EcGcCoordinator> &coordinator,
              const EcV2AllocationBindings &allocations) {
    auto data = storage::EcCapabilityKey::loadFile(std::filesystem::path(keyPath_.string()));
    auto control = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
    ASSERT_OK(data);
    ASSERT_OK(control);
    ASSERT_TRUE((*data)->fileIdentity());
    ASSERT_TRUE((*control)->fileIdentity());
    const auto &dataIdentity = *(*data)->fileIdentity();
    const auto &controlIdentity = *(*control)->fileIdentity();
    const std::array<storage::EcGcRoleFileIdentity, 2> roles{
        {{dataIdentity.device, dataIdentity.inode}, {controlIdentity.device, controlIdentity.inode}}};
    auto loaded = storage::EcGcKey::loadFile(std::filesystem::path(gcKeyPath_.string()), gcKeyId_, roles);
    ASSERT_OK(loaded);
    key = std::shared_ptr<const storage::EcGcKey>(std::move(*loaded));
    auto native = NativeEcGcTransport::create(storageClient_, key);
    ASSERT_OK(native);
    transport = *native;
    EcGcCoordinator::Config config;
    config.authority = authority_;
    // This is explicit fixture inventory, not a discovery inference. Storage
    // opened exact format3 before any request; every instance came from real
    // Meta reservations and is rechecked by the actual executor.
    for (const auto &allocation : allocations)
      config.targets.push_back({allocation.endpoint().controlEndpoint(), 2, 3, 1, true});
    auto built = EcGcCoordinator::create(config, kv_, key, transport);
    ASSERT_OK(built);
    coordinator = std::move(*built);
  }

  Result<storage::EcStageResult> observeStage(const EcV2AllocationBinding &allocation,
                                              storage::EcStageOperation operation) {
    CHECK_RESULT(found, components_->targetMap.getByTargetId(allocation.fragment.placement.target));
    storage::EcStageRequest request;
    request.operation = operation;
    request.identity = allocation.fragment.identity;
    request.operationId = allocation.fragment.operation;
    request.writerNamespace = allocation.writer.client;
    request.targetId = allocation.fragment.placement.target;
    request.vChainId = {allocation.fragment.placement.chain, storage::ChainVer{1}};
    request.integrity = allocation.fragment.integrity;
    // Read-only local observation bypasses revoked network read credentials;
    // no delete, receipt fabrication or stage mutation occurs here.
    return found->storageTarget->executeEcStage(request);
  }

  // MetaStore add_mut/remove_mut account pos.chunk_size(), not payload bytes.
  // This fixture's 4096-byte shards use CHUNK_SIZE_SMALL (64 KiB), defined in
  // chunk_engine/src/types/constants.rs and selected by Allocators::select_by_size.
  static constexpr uint64_t kCommittedAllocationClassBytes = 64 * 1024;
  static_assert(kShardBytes > 0 && kShardBytes <= kCommittedAllocationClassBytes);

  Result<uint64_t> committedAllocationClassBytes(const EcV2AllocationBinding &allocation) {
    CHECK_RESULT(found, components_->targetMap.getByTargetId(allocation.fragment.placement.target));
    return found->storageTarget->usedSize();
  }

  void verifySealedSurvivors(const EcV2AllocationBindings &allocations,
                             const storage::EcCodec::Shards &expected,
                             uint16_t omittedMask = 0) {
    for (size_t shard = 0; shard != allocations.size(); ++shard) {
      if (omittedMask & (uint16_t{1} << shard)) continue;
      const auto &allocation = allocations[shard];
      // These fixed 4 KiB shards fit in one actual ReadBlock response.
      ASSERT_EQ(allocation.fragment.integrity.wholeLength, kShardBytes);
      auto state = observeStage(allocation, storage::EcStageOperation::Query);
      ASSERT_OK(state);
      ASSERT_TRUE(state->state);
      ASSERT_EQ(state->state->state, 2);
      auto read = observeStage(allocation, storage::EcStageOperation::ReadBlock);
      ASSERT_OK(read);
      ASSERT_EQ(read->data, expected[shard]);
    }
  }

  void verifyFormatMarker() {
    std::ifstream input((data_.path() / "engine").string(), std::ios::binary);
    ASSERT_TRUE(input.is_open());
    const std::string marker((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    ASSERT_EQ(marker, "3FS_EC_ENGINE_ROOT_V3_GC\n");
  }

  void verifyCurrent(const AcquireEcReadV2Rsp &pin, const Mutation &original) {
    storage::EcCodec::Shards actual;
    std::array<storage::EcCodecShardView, 12> views;
    for (size_t i = 0; i != 12; ++i) {
      auto block = readOne(pin, i);
      ASSERT_OK(block);
      actual[i] = std::move(block->payload.data);
      ASSERT_EQ(actual[i], original.shards[i]);
      views[i] = {static_cast<uint16_t>(i), actual[i]};
    }
    ASSERT_OK(storage::EcCodec::verify(views, pin.manifest.logicalLength, kShardBytes));
    std::array<std::string_view, 10> logical;
    std::string joined;
    for (size_t i = 0; i != 10; ++i) {
      logical[i] = actual[i];
      joined += actual[i];
    }
    joined.resize(pin.manifest.logicalLength);
    ASSERT_EQ(joined, original.logical);
    auto sha = computeEcLogicalSha256(logical, pin.manifest.logicalLength);
    ASSERT_OK(sha);
    ASSERT_EQ(*sha, original.begin.contentSha256);
    ASSERT_EQ(*sha, pin.contentSha256);
  }

  void verifyDrain(const EcObjectRef &object,
                   storage::EcGrantScope kind,
                   const Uuid &scope,
                   const EcV2DrainProgress &progress,
                   EcV2DrainState expected) {
    ASSERT_EQ(progress.state, expected);
    ASSERT_GT(progress.expectedEndpoints, 0);
    ASSERT_EQ(progress.acknowledgedEndpoints, progress.expectedEndpoints);
    auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
    ASSERT_OK(key);
    auto txn = kv_->createReadWriteTransaction();
    auto record =
        blockingWait(EcV2DrainCatalog::get(*txn, object, kind, scope, EcOwner{user_.uid, metaClientId_.uuid}));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    ASSERT_EQ((**record).state, expected);
    ASSERT_EQ((**record).identity.endpoints.count, progress.expectedEndpoints);
    for (size_t i = 0; i != (**record).identity.endpoints.count; ++i) {
      ASSERT_TRUE((**record).observations[i]);
      const auto &observed = *(**record).observations[i];
      ASSERT_OK(EcVerifiedDrainAck::verify(**key, **record, i, observed.request, observed.ack));
    }
  }
};

TEST_F(TestEcV2NativeExactGc, RealQualificationLostCollectReplyAndReopenQueryCommitPermanentCompletion) {
  ASSERT_NO_FATAL_FAILURE(verifyFormatMarker());
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "exact-gc-fdb-native");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  {
    auto txn = kv_->createReadWriteTransaction();
    auto mode = blockingWait(EcV2BindingCatalog::requireV2Mode(*txn, object));
    ASSERT_OK(mode);
    ASSERT_EQ(mode->mode, kEcGcTrackedObjectMode);
    ASSERT_OK(blockingWait(EcV2GcCatalog::validateEnrollment(*txn, *mode)));
  }
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 211));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  auto initial = blockingWait(metaClient_->publishEcMutationV2(original.publish));
  ASSERT_OK(initial);
  ASSERT_TRUE(initial->drain);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                      storage::EcGrantScope::WriteOperation,
                                      original.begin.operation,
                                      *initial->drain,
                                      EcV2DrainState::Published));
  auto oldPin = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(oldPin);
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(repair(replacement, *oldPin, uint16_t{1}));
  ASSERT_NO_FATAL_FAILURE(writeFragments(replacement));
  auto published = blockingWait(metaClient_->publishEcMutationV2(replacement.publish));
  ASSERT_OK(published);
  ASSERT_TRUE(published->drain);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                      storage::EcGrantScope::WriteOperation,
                                      replacement.begin.operation,
                                      *published->drain,
                                      EcV2DrainState::Published));
  auto current = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(current);
  ASSERT_NO_FATAL_FAILURE(verifyCurrent(*current, original));
  ASSERT_TRUE(original.reservation.allocations);
  const auto oldAllocation = (*original.reservation.allocations)[0];
  const auto oldIdentity = oldAllocation.fragment.identity;
  ASSERT_NE(current->manifest.fragments[0].identity.allocation, oldIdentity.allocation);
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_ERROR(blockingWait(EcCatalog::retireRevision(*txn, object, 0, oldPin->manifest.revision)),
                 StatusCode::kTokenStale);
  }
  // Both read sessions complete the actual authenticated all-endpoint T0/T1/T2
  // path. The current-head rejection below must not depend only on a live pin.
  for (const auto *pin : {&*oldPin, &*current}) {
    auto release = request<ReleaseEcReadV2Req>();
    release.object = object;
    release.pin = pin->snapshot.pin;
    auto released = blockingWait(metaClient_->releaseEcReadV2(release));
    ASSERT_OK(released);
    ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                        storage::EcGrantScope::ReadPin,
                                        release.pin,
                                        released->drain,
                                        EcV2DrainState::ReadReleased));
    ASSERT_NO_FATAL_FAILURE(checkPin(object, release.pin, true));
  }
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(EcCatalog::retireRevision(*txn, object, 0, oldPin->manifest.revision)));
    ASSERT_OK(blockingWait(txn->commit()));
  }
  auto controlKey = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
  ASSERT_OK(controlKey);
  const Uuid claimId = Uuid::random();
  EcGcClaim committedClaim;
  {
    auto txn = kv_->createReadWriteTransaction();
    auto refs = blockingWait(EcCatalog::getFragmentRef(*txn, oldIdentity));
    ASSERT_OK(refs);
    ASSERT_EQ(refs->references, 0);
    ASSERT_TRUE(refs->owner.is_nil());
    ASSERT_TRUE(refs->gcCandidate);
    auto protection = blockingWait(EcV2GcCatalog::getAllocation(*txn, object, oldIdentity));
    ASSERT_OK(protection);
    ASSERT_EQ(protection->active, 0);
    ASSERT_EQ(protection->registered, protection->released);
    // Real G0 invokes all immutable reference, birth, membership, T2 and ACK
    // validation against this same private FoundationDB; no raw ledger writes.
    auto qualified = blockingWait(EcV2GcCatalog::claim(*txn, object, oldIdentity, claimId, **controlKey));
    ASSERT_OK(qualified);
    committedClaim = *qualified;
    ASSERT_TRUE(serde::equals(committedClaim.allocation, oldAllocation));
    ASSERT_EQ(committedClaim.registeredScopes, committedClaim.releasedScopes);
    ASSERT_OK(blockingWait(txn->commit()));
  }
  // G0 is committed and its transaction destroyed before any G request exists.
  {
    auto txn = kv_->createReadWriteTransaction();
    auto durable = blockingWait(EcV2GcCatalog::getClaim(*txn, object, oldIdentity));
    ASSERT_OK(durable);
    ASSERT_TRUE(*durable);
    ASSERT_TRUE(serde::equals(**durable, committedClaim));
    ASSERT_ERROR(blockingWait(EcCatalog::retireRevision(*txn, object, 0, current->manifest.revision)),
                 StatusCode::kTokenStale);
  }
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_ERROR(
        blockingWait(
            EcV2GcCatalog::claim(*txn, object, current->manifest.fragments[0].identity, Uuid::random(), **controlKey)),
        StatusCode::kTokenStale);
  }
  auto physicalBefore = observeStage(oldAllocation, storage::EcStageOperation::Query);
  ASSERT_OK(physicalBefore);
  ASSERT_TRUE(physicalBefore->state);
  ASSERT_EQ(physicalBefore->state->state, 2);  // Actual Sealed record.
  auto oldRead = observeStage(oldAllocation, storage::EcStageOperation::ReadBlock);
  ASSERT_OK(oldRead);
  ASSERT_EQ(oldRead->data, original.shards[0]);
  auto beforeBytes = committedAllocationClassBytes(oldAllocation);
  ASSERT_OK(beforeBytes);
  ASSERT_EQ(oldAllocation.fragment.integrity.wholeLength, kShardBytes);
  ASSERT_GE(*beforeBytes, kCommittedAllocationClassBytes);
  std::shared_ptr<const storage::EcGcKey> gcKey;
  std::shared_ptr<NativeEcGcTransport> transport;
  std::unique_ptr<EcGcCoordinator> gc;
  ASSERT_NO_FATAL_FAILURE(makeGc(gcKey, transport, gc, *original.reservation.allocations));
  ASSERT_ERROR(blockingWait(gc->query(object, oldIdentity, claimId, control())), StorageCode::kChunkMetadataNotFound);
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.dropGcCollectReply = claimId;
  }
  ASSERT_ERROR(blockingWait(gc->collect(object, oldIdentity, claimId, control())), StorageCode::kEcSealOutcomeUnknown);
  storage::EcGcAck actualLostAck;
  {
    std::lock_guard lock(controlFault_.mutex);
    ASSERT_EQ(controlFault_.actualGcCollects, 1);
    ASSERT_TRUE(controlFault_.observedGcCollect);
    actualLostAck = *controlFault_.observedGcCollect;
    ASSERT_TRUE(controlFault_.dropGcCollectReply.is_nil());
  }
  auto absent = blockingWait(gc->getCompletion(object, oldIdentity, claimId));
  ASSERT_OK(absent);
  ASSERT_FALSE(*absent);
  auto physicalAfter = observeStage(oldAllocation, storage::EcStageOperation::Query);
  ASSERT_OK(physicalAfter);
  ASSERT_TRUE(physicalAfter->state);
  ASSERT_EQ(physicalAfter->state->state, 3);  // Actual permanent Aborted stage + GC ledger.
  ASSERT_FALSE(observeStage(oldAllocation, storage::EcStageOperation::ReadBlock));
  auto afterBytes = committedAllocationClassBytes(oldAllocation);
  ASSERT_OK(afterBytes);
  ASSERT_EQ(*afterBytes, *beforeBytes - kCommittedAllocationClassBytes);
  ASSERT_TRUE(replacement.reservation.allocations);
  // The new shard 0 and the eleven shared allocations must remain Sealed and
  // byte-identical; the accounting correction cannot hide another deletion.
  for (size_t shard = 1; shard != 12; ++shard)
    ASSERT_TRUE(
        serde::equals((*replacement.reservation.allocations)[shard], (*original.reservation.allocations)[shard]));
  ASSERT_NO_FATAL_FAILURE(verifySealedSurvivors(*replacement.reservation.allocations, original.shards));
  gc.reset();
  transport.reset();
  gcKey.reset();
  const auto *sameFdb = kv_.get();
  const auto *sameMeta = meta_.get();
  // No target/Engine leases, in-flight RPCs or synthetic storage state survive
  // this normal close/reopen. The helper verifies all twelve durable instances.
  ASSERT_NO_FATAL_FAILURE(reopenStorageKeepingMeta());
  ASSERT_EQ(kv_.get(), sameFdb);
  ASSERT_EQ(meta_.get(), sameMeta);
  ASSERT_NO_FATAL_FAILURE(verifyFormatMarker());
  ASSERT_NO_FATAL_FAILURE(makeGc(gcKey, transport, gc, *original.reservation.allocations));
  auto completed = blockingWait(gc->query(object, oldIdentity, claimId, control()));
  ASSERT_OK(completed);
  ASSERT_EQ(completed->request.claims.action, storage::EcGcAction::Query);
  ASSERT_OK(storage::ec_gc_control_detail::Codec::verifyAck(*gcKey, completed->ack, completed->request));
  ASSERT_EQ(completed->ack.claims.ledgerSha256, actualLostAck.claims.ledgerSha256);
  ASSERT_EQ(completed->ack.claims.terminalRevision, actualLostAck.claims.terminalRevision);
  ASSERT_NE(completed->ack.claims.bootNonce, actualLostAck.claims.bootNonce);
  ASSERT_EQ(completed->ack.claims.endpoint.engineUuid, oldAllocation.engineUuid);
  ASSERT_EQ(completed->ack.claims.endpoint.targetIncarnation, oldAllocation.targetIncarnation);
  {
    std::lock_guard lock(controlFault_.mutex);
    ASSERT_EQ(controlFault_.actualGcQueries, 1);
  }
  {
    auto txn = kv_->createReadWriteTransaction();
    auto saved = blockingWait(EcGcCompletionCatalog::get(*txn, object, oldIdentity, claimId, *gcKey, authority_));
    ASSERT_OK(saved);
    ASSERT_TRUE(*saved);
    // Binary Serde includes the opaque request and ACK signatures.
    ASSERT_TRUE(serde::serialize(**saved) == serde::serialize(*completed));
    auto replayClaim = blockingWait(EcV2GcCatalog::claim(*txn, object, oldIdentity, claimId, **controlKey));
    ASSERT_OK(replayClaim);
    ASSERT_TRUE(serde::equals(*replayClaim, committedClaim));
    ASSERT_OK(blockingWait(txn->commit()));
  }
  auto replay = blockingWait(gc->collect(object, oldIdentity, claimId, control()));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::serialize(*replay) == serde::serialize(*completed));
  auto finalBytes = committedAllocationClassBytes(oldAllocation);
  ASSERT_OK(finalBytes);
  ASSERT_EQ(*finalBytes, *afterBytes);
  {
    std::lock_guard lock(controlFault_.mutex);
    ASSERT_EQ(controlFault_.actualGcCollects, 1);  // G2 replay does not delete twice.
    ASSERT_EQ(controlFault_.actualGcQueries, 1);
  }
  auto finalPin = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(finalPin);
  ASSERT_EQ(finalPin->manifest.revision, current->manifest.revision);
  ASSERT_NO_FATAL_FAILURE(verifyCurrent(*finalPin, original));
  auto finalRelease = request<ReleaseEcReadV2Req>();
  finalRelease.object = object;
  finalRelease.pin = finalPin->snapshot.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(finalRelease));
  ASSERT_OK(released);
  ASSERT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_ERROR(
        blockingWait(
            EcV2GcCatalog::claim(*txn, object, finalPin->manifest.fragments[0].identity, Uuid::random(), **controlKey)),
        StatusCode::kTokenStale);
  }
  RecordProperty("gc_qualification", "actual FDB birth/protection/T2/retire/claim, independent G0 commit");
  RecordProperty("gc_transport", "actual native RPC28; reply dropped only after actual Rust/WAL confirmation");
  RecordProperty("gc_recovery", "normal same-format3 Storage reopen; actual Query ACK then permanent FDB G2");
  RecordProperty("gc_limit", "one Engine/failure domain; no process-kill, power-loss or throughput claim");
}

// Unlike the earlier internal coordinator test, these cases use the production
// Meta38/39 methods. G0, capability discovery29, RPC28 and G2 are service-owned.
class TestEcV2NativeGcAdmin : public TestEcV2NativeExactGc {
 protected:
  bool enableMetaGcAdmin() const override { return true; }
  Result<UserInfo> rootUser() {
    auto txn = kv_->createReadWriteTransaction();
    core::UserStore store;
    auto root = blockingWait(store.getUser(*txn, flat::Uid{0}));
    RETURN_ON_ERROR(root);
    if (!*root) return makeError(StatusCode::kAuthenticationFail);
    return UserInfo{(**root).uid, (**root).gid, (**root).token};
  }
  Result<std::shared_ptr<const storage::EcGcKey>> verificationKey() {
    auto data = storage::EcCapabilityKey::loadFile(keyPath_.string());
    auto control = storage::EcScopeControlKey::loadFile(controlKeyPath_.string());
    RETURN_ON_ERROR(data);
    RETURN_ON_ERROR(control);
    if (!(*data)->fileIdentity() || !(*control)->fileIdentity()) return makeError(StatusCode::kInvalidConfig);
    const auto &d = *(*data)->fileIdentity();
    const auto &c = *(*control)->fileIdentity();
    const std::array<storage::EcGcRoleFileIdentity, 2> roles{{{d.device, d.inode}, {c.device, c.inode}}};
    auto key = storage::EcGcKey::loadFile(gcKeyPath_.string(), gcKeyId_, roles);
    RETURN_ON_ERROR(key);
    return std::shared_ptr<const storage::EcGcKey>(std::move(*key));
  }
};

TEST_F(TestEcV2NativeGcAdmin, RootServiceCommitsEligibilityDiscoversDeletesAndRecoversTheSameClaim) {
  // Overall GC may exceed the independent <=60s discovery request budget.
  metaConfig_.set_ec_gc_timeout(120_s);
  auto root = rootUser();
  ASSERT_OK(root);
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "admin-gc-native");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 221));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  auto published = blockingWait(metaClient_->publishEcMutationV2(original.publish));
  ASSERT_OK(published);
  auto current = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(current);
  auto currentRelease = request<ReleaseEcReadV2Req>();
  currentRelease.object = object;
  currentRelease.pin = current->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(currentRelease)));
  auto head = request<CollectEcFragmentV2Req>();
  head.user = *root;
  head.object = object;
  head.identity = current->manifest.fragments[0].identity;
  head.claimId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(head)), StatusCode::kTokenStale);

  Mutation abandoned;
  ASSERT_NO_FATAL_FAILURE(prepare(abandoned, object, current->manifest.revision, 229));
  ASSERT_NO_FATAL_FAILURE(writeFragments(abandoned));
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = abandoned.begin.operation;
  auto cancelled = blockingWait(metaClient_->cancelEcMutationV2(cancel));
  ASSERT_OK(cancelled);
  ASSERT_TRUE(cancelled->drain);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                      storage::EcGrantScope::WriteOperation,
                                      cancel.operation,
                                      *cancelled->drain,
                                      EcV2DrainState::Aborted));
  ASSERT_TRUE(abandoned.reservation.allocations);
  const auto &allocation = (*abandoned.reservation.allocations)[0];
  auto collect = request<CollectEcFragmentV2Req>();
  collect.object = object;
  collect.identity = allocation.fragment.identity;
  collect.claimId = Uuid::random();
  // A real ordinary token and a forged effective root UID both fail before G0.
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(collect)), MetaCode::kNoPermission);
  collect.user.uid = flat::Uid{0};
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(collect)), StatusCode::kAuthenticationFail);
  collect.user = *root;
  auto query = request<QueryEcFragmentGcV2Req>();
  static_cast<EcGcAdminReq &>(query) = collect;
  ASSERT_ERROR(blockingWait(metaClient_->queryEcFragmentGcV2(query)), StatusCode::kTokenStale);
  metaConfig_.set_readonly(true);
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(collect)), StatusCode::kReadOnlyMode);
  metaConfig_.set_readonly(false);
  {
    auto txn = kv_->createReadWriteTransaction();
    auto absent = blockingWait(EcV2GcCatalog::getClaim(*txn, object, collect.identity));
    ASSERT_OK(absent);
    ASSERT_FALSE(*absent);
  }
  auto before = committedAllocationClassBytes(allocation);
  ASSERT_OK(before);
  ASSERT_EQ(allocation.fragment.integrity.wholeLength, kShardBytes);
  ASSERT_GE(*before, kCommittedAllocationClassBytes);
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.dropGcCollectReply = collect.claimId;
  }
  auto lost = blockingWait(metaClient_->collectEcFragmentV2(collect));
  ASSERT_ERROR(lost, StorageCode::kEcSealOutcomeUnknown);
  auto key = verificationKey();
  ASSERT_OK(key);
  {
    auto txn = kv_->createReadWriteTransaction();
    auto committed = blockingWait(EcV2GcCatalog::getClaim(*txn, object, collect.identity));
    ASSERT_OK(committed);
    ASSERT_TRUE(*committed);
    ASSERT_EQ((**committed).claimId, collect.claimId);
    ASSERT_TRUE(serde::equals((**committed).allocation, allocation));
    auto completion =
        blockingWait(EcGcCompletionCatalog::get(*txn, object, collect.identity, collect.claimId, **key, authority_));
    ASSERT_OK(completion);
    ASSERT_FALSE(*completion);
  }
  auto physical = observeStage(allocation, storage::EcStageOperation::Query);
  ASSERT_OK(physical);
  ASSERT_TRUE(physical->state);
  ASSERT_EQ(physical->state->state, 3);
  auto after = committedAllocationClassBytes(allocation);
  ASSERT_OK(after);
  ASSERT_EQ(*after, *before - kCommittedAllocationClassBytes);
  ASSERT_TRUE(original.reservation.allocations);
  ASSERT_NO_FATAL_FAILURE(verifySealedSurvivors(*original.reservation.allocations, original.shards));
  ASSERT_NO_FATAL_FAILURE(verifySealedSurvivors(*abandoned.reservation.allocations, abandoned.shards, uint16_t{1}));
  // A reconstructed production Meta runtime loads its own real G authority.
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  metaConfig_.set_readonly(true);
  storageConfig_.storage().set_read_only(true);
  auto completed = blockingWait(metaClient_->queryEcFragmentGcV2(query));
  ASSERT_OK(completed);
  ASSERT_EQ(completed->claimId, collect.claimId);
  ASSERT_GT(completed->terminalRevision, 0);
  ASSERT_NE(completed->ledgerSha256, storage::EcSha256{});
  {
    auto txn = kv_->createReadWriteTransaction();
    auto record =
        blockingWait(EcGcCompletionCatalog::get(*txn, object, collect.identity, collect.claimId, **key, authority_));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    ASSERT_EQ((**record).ack.claims.ledgerSha256, completed->ledgerSha256);
    ASSERT_EQ((**record).request.claims.action, storage::EcGcAction::Query);
  }
  metaConfig_.set_readonly(false);
  storageConfig_.storage().set_read_only(false);
  // Remove the actual Storage route: permanent authenticated ECGD replay does
  // not require a fresh discovery exchange or a new physical delete.
  auto unavailable = std::make_shared<flat::RoutingInfo>(*routing_);
  unavailable->nodes.erase(storageNode_);
  unavailable->routingInfoVersion = flat::RoutingInfoVersion{100};
  fakeMgmtd_->setRoutingInfo(unavailable);
  auto replay = blockingWait(metaClient_->collectEcFragmentV2(collect));
  fakeMgmtd_->setRoutingInfo(routing_);
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*replay, *completed));
  auto changed = collect;
  changed.claimId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(changed)), StatusCode::kTokenMismatch);
  {
    std::lock_guard lock(controlFault_.mutex);
    ASSERT_EQ(controlFault_.actualGcCollects, 1);
    ASSERT_EQ(controlFault_.actualGcQueries, 1);
  }
  auto final = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(final);
  ASSERT_EQ(final->manifest.revision, current->manifest.revision);
  ASSERT_NO_FATAL_FAILURE(verifyCurrent(*final, original));
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = final->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  RecordProperty("gc_entry", "actual authenticated Meta38/39, FDB G0, signed discovery29, native28, FDB G2");
  RecordProperty("gc_scope", "explicit bound cancelled allocation; no scan, migration, retire or current-head removal");
}

TEST_F(TestEcV2NativeGcAdmin, LoadedFileRoleAliasesAndAuthenticationDisableFailClosed) {
  const auto original = metaConfig_.ec_gc_key_file();
  const Path alias = traces_.path() / "gc-role-alias.key";
  ASSERT_EQ(::link(keyPath_.c_str(), alias.c_str()), 0);
  metaConfig_.set_ec_gc_key_file(alias);
  EcCoordinator data(metaConfig_, mgmtd_, storageClient_);
  EcV2Coordinator v2(metaConfig_, mgmtd_, storageClient_);
  EcGcAdminCoordinator invalid(metaConfig_, kv_, storageClient_, data, v2);
  ASSERT_ERROR(invalid.checkEnabled(), StatusCode::kInvalidConfig);
  metaConfig_.set_ec_gc_key_file(original);
  auto root = rootUser();
  ASSERT_OK(root);
  auto req = request<QueryEcFragmentGcV2Req>();
  req.user = *root;
  req.object = {InodeId{12345}, Uuid::random()};
  req.identity.object = req.object.incarnation;
  req.identity.generation = 1;
  req.identity.allocation = Uuid::random();
  req.claimId = Uuid::random();
  metaConfig_.set_authenticate(false);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcFragmentGcV2(req)), StatusCode::kAuthenticationFail);
  metaConfig_.set_authenticate(true);
}

TEST_F(TestEcV2NativeLifecycle, ExactGcAdminIsDisabledByDefault) {
  auto req = request<CollectEcFragmentV2Req>();
  req.object = {InodeId{12345}, Uuid::random()};
  req.identity.object = req.object.incarnation;
  req.identity.generation = 1;
  req.identity.allocation = Uuid::random();
  req.claimId = Uuid::random();
  ASSERT_FALSE(metaConfig_.enable_ec_exact_gc());
  ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(req)), StatusCode::kNotImplemented);
  auto query = request<QueryEcFragmentGcV2Req>();
  static_cast<EcGcAdminReq &>(query) = req;
  ASSERT_ERROR(blockingWait(metaClient_->queryEcFragmentGcV2(query)), StatusCode::kNotImplemented);
}

class TestEcV2NativeRetirement : public TestEcV2NativeGcAdmin {
 protected:
  void SetUp() override {
    TestEcV2NativeGcAdmin::SetUp();
    if (HasFatalFailure()) return;
    metaConfig_.set_enable_ec_revision_retirement(true);
  }
  void replaceClientIdentity(const ClientId &identity) {
    metaClient_->stop();
    metaClient_.reset();
    metaNet_->stopAndJoin();
    metaNet_.reset();
    ASSERT_NO_FATAL_FAILURE(startMetaClient(identity));
  }
  RetireEcRevisionV2Req retirement(const EcObjectRef &object, uint64_t revision, const UserInfo &user) {
    auto req = request<RetireEcRevisionV2Req>();
    req.user = user;
    req.object = object;
    req.revision = revision;
    return req;
  }
  QueryEcRevisionRetirementV2Req query(const RetireEcRevisionV2Req &retire) {
    QueryEcRevisionRetirementV2Req req;
    static_cast<EcRevisionRetirementReq &>(req) = retire;
    return req;
  }
};

TEST_F(TestEcV2NativeRetirement, PinBlocksRetirementThenLostReplyReplaysWithoutReleasingSharedFragments) {
  auto root = rootUser();
  ASSERT_OK(root);
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "retirement-native");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 241));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto oldPin = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(oldPin);
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(repair(replacement, *oldPin, uint16_t{1}));
  ASSERT_NO_FATAL_FAILURE(writeFragments(replacement));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(replacement.publish)));
  auto retire = retirement(object, oldPin->manifest.revision, *root);
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(retire)), StatusCode::kTokenStale);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(retire))), StatusCode::kKVStoreNotFound);
  {
    auto txn = kv_->createReadWriteTransaction();
    auto shared = blockingWait(EcCatalog::getFragmentRef(*txn, oldPin->manifest.fragments[1].identity));
    ASSERT_OK(shared);
    ASSERT_EQ(shared->references, 2);
  }
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = oldPin->snapshot.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(released);
  ASSERT_NO_FATAL_FAILURE(
      verifyDrain(object, storage::EcGrantScope::ReadPin, release.pin, released->drain, EcV2DrainState::ReadReleased));
  size_t callsBefore = 0;
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.retirementArmed = retire.uuid;
    callsBefore = replyDrop_.retirementCalls;
  }
  auto lost = blockingWait(metaClient_->retireEcRevisionV2(retire));
  ASSERT_TRUE(lost.hasError());
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.retirementCalls, callsBefore + 1);
    ASSERT_TRUE(replyDrop_.retirementCommitted);
    ASSERT_TRUE(replyDrop_.retirementCommitted->referencesReleased);
  }
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  metaConfig_.set_readonly(true);
  auto observed = blockingWait(metaClient_->queryEcRevisionRetirementV2(query(retire)));
  ASSERT_OK(observed);
  ASSERT_EQ(observed->object, object);
  ASSERT_EQ(observed->revision, retire.revision);
  ASSERT_EQ(observed->requestId, retire.uuid);
  ASSERT_EQ(observed->clientNamespace, metaClientId_.uuid);
  ASSERT_TRUE(observed->referencesReleased);
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  auto reconstructed = blockingWait(metaClient_->queryEcRevisionRetirementV2(query(retire)));
  ASSERT_OK(reconstructed);
  ASSERT_TRUE(serde::equals(*observed, *reconstructed));
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(ClientId::random()));
  // retry overwrites the supplied req.client with the actual client identity.
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(retire))), StatusCode::kKVStoreNotFound);
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(metaClientId_));
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(retire)), StatusCode::kReadOnlyMode);
  metaConfig_.set_readonly(false);
  auto replay = blockingWait(metaClient_->retireEcRevisionV2(retire));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*observed, *replay));
  for (int field = 0; field != 4; ++field) {
    SCOPED_TRACE(field);
    auto changed = retire;
    if (field == 0) ++changed.stripe;
    if (field == 1) ++changed.revision;
    if (field == 2) changed.object.incarnation = Uuid::random();
    if (field == 3) changed.object.inode = InodeId(object.inode.u64() + 1);
    ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(changed)), StatusCode::kTokenMismatch);
    ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(changed))), StatusCode::kTokenMismatch);
  }
  {
    auto txn = kv_->createReadWriteTransaction();
    auto replaced = blockingWait(EcCatalog::getFragmentRef(*txn, oldPin->manifest.fragments[0].identity));
    auto shared = blockingWait(EcCatalog::getFragmentRef(*txn, oldPin->manifest.fragments[1].identity));
    ASSERT_OK(replaced);
    ASSERT_OK(shared);
    ASSERT_EQ(replaced->references, 0);
    ASSERT_TRUE(replaced->gcCandidate);
    ASSERT_EQ(shared->references, 1);
    ASSERT_FALSE(shared->gcCandidate);
  }
  auto current = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(current);
  ASSERT_NO_FATAL_FAILURE(verifyCurrent(*current, original));
  auto currentRelease = request<ReleaseEcReadV2Req>();
  currentRelease.object = object;
  currentRelease.pin = current->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(currentRelease)));
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(retirement(object, current->manifest.revision, *root))),
               StatusCode::kTokenStale);
  {
    std::lock_guard lock(controlFault_.mutex);
    ASSERT_EQ(controlFault_.actualGcCollects, 0);
    ASSERT_EQ(controlFault_.actualGcQueries, 0);
  }
  RecordProperty("retirement_path", "actual authenticated Meta40/41, FDB reference transaction, lost RPC reply");
  RecordProperty("retirement_limit", "metadata references only; no physical deletion or automatic scanner");
}

TEST_F(TestEcV2NativeRetirement, ActualCommittedButUnknownAcknowledgementCanBeQueriedWithoutDoubleDecrement) {
  auto root = rootUser();
  ASSERT_OK(root);
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "retirement-unknown-fdb");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 243));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto old = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(old);
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(prepare(replacement, object, old->manifest.revision, 247));
  ASSERT_NO_FATAL_FAILURE(writeFragments(replacement));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(replacement.publish)));
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = old->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  auto req = retirement(object, old->manifest.revision, *root);
  auto unknown = [&]() -> CoTryTask<Void> {
    auto txn = kv_->createReadWriteTransaction();
    CO_RETURN_ON_ERROR(co_await EcRevisionRetirementCatalog::retire(*txn, req));
    CO_RETURN_ON_ERROR(co_await txn->commit());
    // Actual FDB commit succeeds; model losing just its acknowledgement.
    // This is not a FoundationDB server/network fault-injection claim.
    co_return makeError(TransactionCode::kMaybeCommitted, "lost ACK after actual FDB retirement commit");
  };
  ASSERT_ERROR(blockingWait(unknown()), TransactionCode::kMaybeCommitted);
  auto observed = blockingWait(metaClient_->queryEcRevisionRetirementV2(query(req)));
  ASSERT_OK(observed);
  auto replay = blockingWait(metaClient_->retireEcRevisionV2(req));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*observed, *replay));
  for (const auto &fragment : old->manifest.fragments) {
    auto txn = kv_->createReadWriteTransaction();
    auto ref = blockingWait(EcCatalog::getFragmentRef(*txn, fragment.identity));
    ASSERT_OK(ref);
    ASSERT_EQ(ref->references, 0);
    ASSERT_TRUE(ref->gcCandidate);
  }
}

TEST_F(TestEcV2NativeRetirement, AuthenticationModeAndDefaultGateCannotBeBypassed) {
  auto root = rootUser();
  ASSERT_OK(root);
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "retirement-auth");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  auto req = retirement(created->object.object, 1, user_);
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(req)), MetaCode::kNoPermission);
  req.user.uid = flat::Uid{0};
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(req)), StatusCode::kAuthenticationFail);
  req.user = *root;
  metaConfig_.set_authenticate(false);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(req))), StatusCode::kAuthenticationFail);
  metaConfig_.set_authenticate(true);
  metaConfig_.set_enable_ec_revision_retirement(false);
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(req)), StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(req))), StatusCode::kNotImplemented);
  metaConfig_.set_enable_ec_revision_retirement(true);
  const EcObjectRef legacy{InodeId{500123}, Uuid::random()};
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(EcV2BindingCatalog::createV2Object(*txn,
                                                              legacy,
                                                              kShardBytes,
                                                              true,
                                                              EcOwner{user_.uid, metaClientId_.uuid},
                                                              Uuid::random())));
    ASSERT_OK(blockingWait(txn->commit()));
  }
  auto legacyReq = retirement(legacy, 1, *root);
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(legacyReq)), StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(legacyReq))), StatusCode::kNotImplemented);
  auto empty = req;
  empty.uuid = Uuid::zero();
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(empty)), StatusCode::kInvalidArg);
  ASSERT_FALSE(Config{}.enable_ec_revision_retirement());
}

TEST_F(TestEcV2NativeRetirement, MissingOrMismatchedBirthEnrollmentNeverCreatesCompletion) {
  auto root = rootUser();
  ASSERT_OK(root);
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "retirement-enrollment");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  auto req = retirement(created->object.object, 1, *root);
  std::string enrollmentKey(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  enrollmentKey.append(req.object.incarnation.asStringView());
  const auto completedKey = Serializer::serRawArgs(kv::KeyPrefix::EcRevisionRetirement, req.uuid, req.client.uuid);
  String original;
  EcGcEnrollment enrollment;
  {
    auto txn = kv_->createReadWriteTransaction();
    auto bytes = blockingWait(txn->get(enrollmentKey));
    ASSERT_OK(bytes);
    ASSERT_TRUE(*bytes);
    original = **bytes;
    ASSERT_OK(serde::deserialize(enrollment, original));
  }
  for (int corrupt = 0; corrupt != 2; ++corrupt) {
    {
      auto txn = kv_->createReadWriteTransaction();
      if (corrupt == 0) {
        ASSERT_OK(blockingWait(txn->clear(enrollmentKey)));
      } else {
        auto forged = enrollment;
        forged.createRequest = Uuid::random();
        ASSERT_OK(blockingWait(txn->set(enrollmentKey, serde::serialize(forged))));
      }
      ASSERT_OK(blockingWait(txn->commit()));
    }
    ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(req)), StatusCode::kDataCorruption);
    ASSERT_ERROR(blockingWait(metaClient_->queryEcRevisionRetirementV2(query(req))), StatusCode::kDataCorruption);
    {
      auto txn = kv_->createReadWriteTransaction();
      auto complete = blockingWait(txn->get(completedKey));
      ASSERT_OK(complete);
      ASSERT_FALSE(*complete);
      ASSERT_OK(blockingWait(txn->set(enrollmentKey, original)));
      ASSERT_OK(blockingWait(txn->commit()));
    }
  }
}

// A delegating observer: every operation, including conflicts and commit,
// reaches the actual FDB transaction. It supplies no fabricated read or ACK.
class RangeCountingTransaction : public kv::IReadWriteTransaction {
 public:
  explicit RangeCountingTransaction(kv::IReadWriteTransaction &inner)
      : inner_(inner) {}
  void setReadVersion(int64_t v) override { inner_.setReadVersion(v); }
  CoTryTask<std::optional<String>> snapshotGet(std::string_view k) override {
    co_return co_await inner_.snapshotGet(k);
  }
  CoTryTask<std::optional<String>> get(std::string_view k) override { co_return co_await inner_.get(k); }
  CoTryTask<GetRangeResult> snapshotGetRange(const KeySelector &a, const KeySelector &b, int32_t n) override {
    co_return co_await inner_.snapshotGetRange(a, b, n);
  }
  CoTryTask<GetRangeResult> getRange(const KeySelector &a, const KeySelector &b, int32_t n) override {
    co_return co_await inner_.getRange(a, b, n);
  }
  CoTryTask<void> cancel() override { co_return co_await inner_.cancel(); }
  void reset() override { inner_.reset(); }
  CoTryTask<void> addReadConflict(std::string_view k) override { co_return co_await inner_.addReadConflict(k); }
  CoTryTask<void> addReadConflictRange(std::string_view a, std::string_view b) override {
    co_return co_await inner_.addReadConflictRange(a, b);
  }
  CoTryTask<void> set(std::string_view k, std::string_view v) override {
    ++sets;
    setBytes += k.size() + v.size();
    maximumValue = std::max(maximumValue, v.size());
    co_return co_await inner_.set(k, v);
  }
  CoTryTask<void> clear(std::string_view k) override {
    ++clears;
    co_return co_await inner_.clear(k);
  }
  CoTryTask<void> setVersionstampedKey(std::string_view k, uint32_t o, std::string_view v) override {
    co_return co_await inner_.setVersionstampedKey(k, o, v);
  }
  CoTryTask<void> setVersionstampedValue(std::string_view k, std::string_view v, uint32_t o) override {
    co_return co_await inner_.setVersionstampedValue(k, v, o);
  }
  CoTryTask<void> commit() override { co_return co_await inner_.commit(); }
  int64_t getCommittedVersion() override { return inner_.getCommittedVersion(); }
  size_t sets = 0, clears = 0, setBytes = 0, maximumValue = 0;

 private:
  kv::IReadWriteTransaction &inner_;
};

class TestEcV2NativeFileRange : public TestEcV2NativeRetirement {
 protected:
  static constexpr uint64_t kStripeBytes = uint64_t{kShardBytes} * 10;
  void SetUp() override {
    TestEcV2NativeRetirement::SetUp();
    if (HasFatalFailure()) return;
    metaConfig_.set_enable_ec_file_ranges(true);
  }
  void createFile(EcObjectRef &object, std::string name) {
    auto req = request<CreateEcFileV2Req>();
    req.path = PathAt(parent_, std::move(name));
    req.shardBytes = kShardBytes;
    auto result = blockingWait(metaClient_->createEcFileV2(req));
    ASSERT_OK(result);
    object = result->object.object;
  }
  void appendStripe(const EcObjectRef &object, uint64_t stripe, Mutation &mutation, size_t length = kStripeBytes) {
    ASSERT_NO_FATAL_FAILURE(prepare(mutation, object, 0, static_cast<uint32_t>(313 + stripe), false, stripe, length));
    ASSERT_NO_FATAL_FAILURE(writeFragments(mutation));
    ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(mutation.publish)));
  }
  AcquireEcRangeV2Req range(const EcObjectRef &object, uint64_t offset, uint64_t length) const {
    auto req = request<AcquireEcRangeV2Req>();
    req.rangeId = Uuid::random();
    req.selection.object = object;
    req.selection.offset = offset;
    req.selection.length = length;
    const auto first = offset / kStripeBytes;
    const auto count = length ? (offset + length - 1) / kStripeBytes - first + 1 : 0;
    req.selection.pinCount = count;
    for (size_t i = 0; i < std::min<uint64_t>(count, 8); ++i) {
      req.selection.pins[i].stripe = first + i;
      req.selection.pins[i].pin = Uuid::random();
    }
    return req;
  }
  QueryEcRangeV2Req rangeQuery(const EcRangeReq &source) const {
    QueryEcRangeV2Req req;
    static_cast<EcRangeReq &>(req) = source;
    return req;
  }
  void releaseRange(const EcRangeRsp &rsp) {
    for (size_t i = 0; i != rsp.snapshot.stripeCount; ++i) {
      auto req = request<ReleaseEcReadV2Req>();
      req.object = rsp.snapshot.selection.object;
      req.stripe = rsp.snapshot.stripes[i].snapshot.stripe;
      req.pin = rsp.snapshot.stripes[i].snapshot.pin;
      auto released = blockingWait(metaClient_->releaseEcReadV2(req));
      ASSERT_OK(released);
      ASSERT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
    }
  }
  void assertNoPin(const AcquireEcRangeV2Req &req) {
    auto txn = kv_->createReadWriteTransaction();
    for (size_t i = 0; i != req.selection.pinCount; ++i)
      ASSERT_ERROR(blockingWait(EcCatalog::getPin(*txn, req.selection.object, req.selection.pins[i].pin)),
                   StatusCode::kKVStoreNotFound);
  }
};

TEST_F(TestEcV2NativeFileRange, DescribeRequiresActualCredentialsGateAclAndTrackedBirth) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-describe"));
  auto req = request<DescribeEcFileV2Req>();
  req.object = object;
  auto described = blockingWait(metaClient_->describeEcFileV2(req));
  ASSERT_OK(described);
  ASSERT_EQ(described->file.object, object);
  ASSERT_EQ(described->file.length, 0);
  ASSERT_EQ(described->file.layout.shardBytes, kShardBytes);
  ASSERT_EQ(described->file.epoch, 1);
  req.access = AccessType::WRITE;
  ASSERT_OK(blockingWait(metaClient_->describeEcFileV2(req)));
  req.access = static_cast<AccessType>(255);
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kInvalidArg);
  req.access = AccessType::READ;
  req.user.uid = flat::Uid{0};
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kAuthenticationFail);
  req.user = user_;
  req.user.token.clear();
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kAuthenticationFail);
  req.user = user_;
  Config defaults;
  ASSERT_FALSE(defaults.enable_ec_file_ranges());
  metaConfig_.set_enable_ec_file_ranges(false);
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kNotImplemented);
  metaConfig_.set_enable_ec_file_ranges(true);
  metaConfig_.set_authenticate(false);
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kAuthenticationFail);
  metaConfig_.set_authenticate(true);
  auto root = rootUser();
  ASSERT_OK(root);
  req.user = *root;
  req.user.uid = user_.uid;
  req.user.gid = user_.gid;
  ASSERT_OK(blockingWait(metaClient_->describeEcFileV2(req)));  // actual root delegation is preserved
  req.user = user_;
  auto txn = kv_->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, object.inode));
  ASSERT_OK(inode);
  ASSERT_TRUE(*inode);
  (**inode).acl.perm = Permission{0200};
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), MetaCode::kNoPermission);
  req.access = AccessType::WRITE;
  ASSERT_OK(blockingWait(metaClient_->describeEcFileV2(req)));
  EcObjectRef legacy;
  legacy.inode = InodeId{object.inode.u64() + 1000000};
  legacy.incarnation = Uuid::random();
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcV2BindingCatalog::createV2Object(*txn,
                                                            legacy,
                                                            kShardBytes,
                                                            true,
                                                            EcOwner{user_.uid, metaClientId_.uuid},
                                                            Uuid::random())));
  ASSERT_OK(blockingWait(txn->commit()));
  txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(requireTrackedEcFile(*txn, legacy)), StatusCode::kNotImplemented);
  std::string enrollment(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  enrollment += object.incarnation.asStringView();
  txn = kv_->createReadWriteTransaction();
  auto original = blockingWait(txn->get(enrollment));
  ASSERT_OK(original);
  ASSERT_TRUE(*original);
  ASSERT_OK(blockingWait(txn->clear(enrollment)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->describeEcFileV2(req)), StatusCode::kDataCorruption);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(enrollment, **original)));
  ASSERT_OK(blockingWait(txn->commit()));
}

TEST_F(TestEcV2NativeFileRange, CrossStripeSnapshotPinsHistoricalRevisionsAndConflictsWithPublish) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-cross-stripe"));
  Mutation first, second, tail;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 1, second));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 2, tail, 137));
  auto req = range(object, kStripeBytes - 31, kStripeBytes + 500);
  auto acquired = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(acquired);
  ASSERT_EQ(acquired->snapshot.stripeCount, 3);
  ASSERT_EQ(acquired->snapshot.file.length, 2 * kStripeBytes + 137);
  ASSERT_EQ(acquired->snapshot.readableLength, kStripeBytes + 168);
  ASSERT_EQ(acquired->snapshot.stripes[2].logicalLength, 137);
  for (size_t i = 0; i != 3; ++i) {
    auto read = readRequest(object);
    read.stripe = i;
    read.pin = acquired->snapshot.stripes[i].snapshot.pin;
    auto pinned = blockingWait(metaClient_->acquireEcReadV2(read));
    ASSERT_OK(pinned);
    ASSERT_TRUE(serde::equals(pinned->snapshot, acquired->snapshot.stripes[i].snapshot));
    ASSERT_EQ(pinned->contentSha256, acquired->snapshot.stripes[i].contentSha256);
    ASSERT_NO_FATAL_FAILURE(verifyCurrent(*pinned, i == 0 ? first : (i == 1 ? second : tail)));
  }
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(
      prepare(replacement, object, acquired->snapshot.stripes[0].snapshot.revision, 411, false, 0, kStripeBytes));
  ASSERT_NO_FATAL_FAILURE(writeFragments(replacement));
  auto competing = range(object, 0, 2 * kStripeBytes);
  auto txn = kv_->createReadWriteTransaction();
  auto provisional = blockingWait(EcRangeCatalog::acquire(*txn, competing));
  ASSERT_OK(provisional);
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(replacement.publish)));
  ASSERT_ERROR(blockingWait(txn->commit()), TransactionCode::kConflict);
  ASSERT_NO_FATAL_FAILURE(assertNoPin(competing));
  auto replay = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*replay, *acquired));
  auto root = rootUser();
  ASSERT_OK(root);
  auto retire = retirement(object, acquired->snapshot.stripes[0].snapshot.revision, *root);
  ASSERT_ERROR(blockingWait(metaClient_->retireEcRevisionV2(retire)), StatusCode::kTokenStale);
  ASSERT_NO_FATAL_FAILURE(releaseRange(*acquired));
  ASSERT_OK(blockingWait(metaClient_->retireEcRevisionV2(retire)));
  auto query = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req)));
  ASSERT_OK(query);
  for (size_t i = 0; i != 3; ++i) ASSERT_EQ(query->snapshot.stripes[i].state, EcRangePinState::Released);
}

TEST_F(TestEcV2NativeFileRange, FailureAfterFirstPinRollsBackEveryPinGcCountAndRangeRecord) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-atomic-failure"));
  Mutation first, second;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 1, second));
  auto req = range(object, 0, 2 * kStripeBytes);
  auto txn = kv_->createReadWriteTransaction();
  const auto revision = second.reservation.record.candidate.revision;
  std::string key(kv::toStr(kv::KeyPrefix::EcV2PublishedContent));
  key += object.incarnation.asStringView();
  for (uint64_t n : {uint64_t{1}, revision})
    for (int shift = 56; shift >= 0; shift -= 8) key.push_back(static_cast<char>(n >> shift));
  auto saved = blockingWait(txn->get(key));
  ASSERT_OK(saved);
  ASSERT_TRUE(*saved);
  auto before = blockingWait(
      EcV2GcCatalog::getAllocation(*txn, object, first.reservation.record.candidate.fragments[0].identity));
  ASSERT_OK(before);
  ASSERT_OK(blockingWait(txn->clear(key)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(req)), StatusCode::kNotImplemented);
  ASSERT_NO_FATAL_FAILURE(assertNoPin(req));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req))), StatusCode::kKVStoreNotFound);
  txn = kv_->createReadWriteTransaction();
  auto after = blockingWait(
      EcV2GcCatalog::getAllocation(*txn, object, first.reservation.record.candidate.fragments[0].identity));
  ASSERT_OK(after);
  ASSERT_TRUE(serde::equals(*before, *after));
  auto manifest = blockingWait(EcCatalog::getManifest(*txn, object, 0, first.reservation.record.candidate.revision));
  ASSERT_OK(manifest);
  ASSERT_EQ(manifest->pins, 0);
  ASSERT_OK(blockingWait(txn->set(key, **saved)));
  ASSERT_OK(blockingWait(txn->commit()));
  auto retry = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(retry);
  ASSERT_NO_FATAL_FAILURE(releaseRange(*retry));
}

TEST_F(TestEcV2NativeFileRange, CompleteBodyOwnerAliasAndPreexistingPinsCannotBeRebound) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-identity"));
  Mutation first;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  auto req = range(object, 0, 19);
  auto result = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(result);
  auto changed = req;
  changed.selection.length++;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(changed)), StatusCode::kTokenMismatch);
  changed = req;
  changed.selection.pins[0].pin = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(changed))), StatusCode::kTokenMismatch);
  changed = req;
  changed.uuid = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(changed))), StatusCode::kTokenMismatch);
  changed = req;
  changed.rangeId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(changed)), StatusCode::kTokenMismatch);
  auto root = rootUser();
  ASSERT_OK(root);
  changed = req;
  changed.user = *root;
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(changed))), MetaCode::kNoPermission);
  auto existing = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(existing);
  auto collision = range(object, 0, 23);
  collision.selection.pins[0].pin = existing->snapshot.pin;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(collision)), StatusCode::kTokenDuplicated);
  collision = range(object, 0, kStripeBytes + 1);
  collision.selection.pins[1].pin = collision.selection.pins[0].pin;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(collision)), StatusCode::kInvalidArg);
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = existing->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  ASSERT_NO_FATAL_FAILURE(releaseRange(*result));
}

TEST_F(TestEcV2NativeFileRange, ClosingReleasedAndRevokedAclRemainObservableWithoutResurrection) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-cleanup"));
  Mutation first;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  auto req = range(object, 0, 19);
  auto result = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(result);
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = result->snapshot.stripes[0].snapshot.pin;
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.scope = release.pin;
    controlFault_.fail = true;
  }
  auto failed = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_FALSE(failed);
  auto closing = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req)));
  ASSERT_OK(closing);
  ASSERT_EQ(closing->snapshot.stripes[0].state, EcRangePinState::Closing);
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(req)), StatusCode::kTokenStale);
  // Inject one missing ECPN row while preserving real ECVP/Closing/GC state.
  // A new range must refuse adoption and leave the old closed scope unchanged.
  std::string pinKey(kv::toStr(kv::KeyPrefix::EcPin));
  pinKey += object.incarnation.asStringView();
  pinKey += release.pin.asStringView();
  auto faultTxn = kv_->createReadWriteTransaction();
  auto savedPin = blockingWait(faultTxn->get(pinKey));
  ASSERT_OK(savedPin);
  ASSERT_TRUE(*savedPin);
  ASSERT_OK(blockingWait(faultTxn->clear(pinKey)));
  ASSERT_OK(blockingWait(faultTxn->commit()));
  auto orphan = range(object, 0, 19);
  orphan.selection.pins[0].pin = release.pin;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(orphan)), StatusCode::kTokenDuplicated);
  faultTxn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(faultTxn->set(pinKey, **savedPin)));
  ASSERT_OK(blockingWait(faultTxn->commit()));
  for (const auto prefix :
       {kv::KeyPrefix::EcV2Pin, kv::KeyPrefix::EcV2Drain, kv::KeyPrefix::EcGcScope, kv::KeyPrefix::EcV2Issuance}) {
    auto isolated = range(object, 0, 19);
    std::string side(kv::toStr(prefix));
    side += object.incarnation.asStringView();
    if (prefix != kv::KeyPrefix::EcV2Pin) side.push_back(static_cast<char>(storage::EcGrantScope::ReadPin));
    side += isolated.selection.pins[0].pin.asStringView();
    auto corrupt = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(corrupt->set(side, "fixture-only-orphan")));
    ASSERT_OK(blockingWait(corrupt->commit()));
    ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(isolated)), StatusCode::kTokenDuplicated);
    ASSERT_NO_FATAL_FAILURE(assertNoPin(isolated));
    ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(isolated))), StatusCode::kKVStoreNotFound);
    corrupt = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(corrupt->clear(side)));
    ASSERT_OK(blockingWait(corrupt->commit()));
  }
  auto txn = kv_->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, object.inode));
  ASSERT_OK(inode);
  ASSERT_TRUE(*inode);
  const auto original = **inode;
  (**inode).acl.perm = Permission{0};
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(req)), MetaCode::kNoPermission);
  ASSERT_OK(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req))));
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.fail = false;
  }
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  auto released = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req)));
  ASSERT_OK(released);
  ASSERT_EQ(released->snapshot.stripes[0].state, EcRangePinState::Released);
  txn = kv_->createReadWriteTransaction();
  auto unlinked = original;
  unlinked.nlink = 0;
  ASSERT_OK(blockingWait(unlinked.store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  // This fixture-only liveness fault is not an implementation of unlink.
  ASSERT_OK(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req))));
  txn = kv_->createReadWriteTransaction();
  auto restored = original;
  ASSERT_OK(blockingWait(restored.store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(req)), StatusCode::kTokenStale);
  auto observeTxn = kv_->createReadWriteTransaction();
  RangeCountingTransaction observer(*observeTxn);
  ASSERT_OK(blockingWait(EcRangeCatalog::query(observer, req)));
  ASSERT_EQ(observer.sets, 0);
  ASSERT_EQ(observer.clears, 0);
}

TEST_F(TestEcV2NativeFileRange, LostTcpReplyAndUnknownCommitRecoverWithSameDurableIdentity) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-unknown"));
  Mutation first;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  auto req = range(object, 0, 29);
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.rangeArmed = req.uuid;
    replyDrop_.rangeCalls = 0;
  }
  auto lost = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_FALSE(lost);
  EcRangeRsp committed;
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.rangeCalls, 1);
    ASSERT_TRUE(replyDrop_.rangeCommitted);
    committed = *replyDrop_.rangeCommitted;
  }
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  auto query = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req)));
  ASSERT_OK(query);
  ASSERT_TRUE(serde::equals(*query, committed));
  auto replay = blockingWait(metaClient_->acquireEcRangeV2(req));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*replay, committed));
  auto txn = kv_->createReadWriteTransaction();
  auto manifest =
      blockingWait(EcCatalog::getManifest(*txn, object, 0, committed.snapshot.stripes[0].snapshot.revision));
  ASSERT_OK(manifest);
  ASSERT_EQ(manifest->pins, 1);
  auto unknownReq = range(object, 0, 31);
  auto unknown = [&]() -> CoTryTask<Void> {
    auto transaction = kv_->createReadWriteTransaction();
    CO_RETURN_ON_ERROR(co_await EcRangeCatalog::acquire(*transaction, unknownReq));
    CO_RETURN_ON_ERROR(co_await transaction->commit());
    // Actual commit followed by a modeled lost acknowledgement. This does not
    // claim an FDB server/network fault injection.
    co_return makeError(TransactionCode::kMaybeCommitted);
  };
  ASSERT_ERROR(blockingWait(unknown()), TransactionCode::kMaybeCommitted);
  auto recovered = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(unknownReq)));
  ASSERT_OK(recovered);
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(ClientId::random()));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(req))), StatusCode::kKVStoreNotFound);
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(metaClientId_));
  ASSERT_NO_FATAL_FAILURE(releaseRange(committed));
  ASSERT_NO_FATAL_FAILURE(releaseRange(*recovered));
}

TEST_F(TestEcV2NativeFileRange, EmptyRangesPersistEofAndUnusedMappingsWithoutCreatingPins) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-empty"));
  auto empty = range(object, 0, 0);
  auto captured = blockingWait(metaClient_->acquireEcRangeV2(empty));
  ASSERT_OK(captured);
  auto beyond = range(object, 2 * kStripeBytes + 1, 8 * kStripeBytes - 1);
  auto outside = blockingWait(metaClient_->acquireEcRangeV2(beyond));
  ASSERT_OK(outside);
  ASSERT_EQ(outside->snapshot.stripeCount, 0);
  ASSERT_EQ(outside->snapshot.selection.pinCount, 8);
  ASSERT_NO_FATAL_FAILURE(assertNoPin(beyond));
  Mutation first;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  auto replay = blockingWait(metaClient_->acquireEcRangeV2(empty));
  ASSERT_OK(replay);
  ASSERT_EQ(replay->snapshot.file.length, 0);
  ASSERT_EQ(replay->snapshot.stripeCount, 0);
  ASSERT_TRUE(serde::equals(*replay, *captured));
  auto wrong = range(object, 0, 0);
  wrong.selection.pins[7].pin = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(wrong)), StatusCode::kInvalidArg);
  wrong = range(object, 0, 1);
  wrong.selection.offset = std::numeric_limits<uint64_t>::max();
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(wrong)), StatusCode::kInvalidArg);
  wrong = range(object, 0, 1);
  wrong.selection.length = kEcFileRangeMaxBytes + 1;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(wrong)), StatusCode::kInvalidArg);
  wrong = range(object, 0, 8 * kStripeBytes);
  wrong.selection.offset = 1;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(wrong)), StatusCode::kInvalidArg);
  wrong = range(object, 0, 1);
  wrong.selection.pins[0].stripe = 1;
  ASSERT_ERROR(blockingWait(metaClient_->acquireEcRangeV2(wrong)), StatusCode::kInvalidArg);
  auto missing = range(object, 0, 1);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcRangeV2(rangeQuery(missing))), StatusCode::kKVStoreNotFound);
  ASSERT_OK(blockingWait(metaClient_->acquireEcRangeV2(missing)));  // missing was not cancellation
  auto recovered = blockingWait(metaClient_->queryEcRangeV2(rangeQuery(missing)));
  ASSERT_OK(recovered);
  ASSERT_NO_FATAL_FAILURE(releaseRange(*recovered));
}

TEST_F(TestEcV2NativeFileRange, EightStripeActualFdbTransactionAndWireSizeRemainBounded) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "range-eight"));
  for (size_t i = 0; i != 8; ++i) {
    Mutation stripe;
    ASSERT_NO_FATAL_FAILURE(appendStripe(object, i, stripe));
  }
  auto req = range(object, 0, 8 * kStripeBytes);
  auto txn = kv_->createReadWriteTransaction();
  RangeCountingTransaction counted(*txn);
  auto result = blockingWait(EcRangeCatalog::acquire(counted, req));
  ASSERT_OK(result);
  ASSERT_EQ(result->snapshot.stripeCount, 8);
  ASSERT_LE(counted.maximumValue, kEcFileRangeMaxRecordBytes);
  ASSERT_LT(counted.setBytes, 1u << 20);
  ASSERT_LE(counted.sets, 256);
  ASSERT_OK(blockingWait(counted.commit()));
  auto bytes = serde::serialize(result->snapshot);
  ASSERT_LE(bytes.size(), kEcFileRangeMaxRecordBytes);
  EcRangeSnapshot decoded;
  ASSERT_OK(serde::deserialize(decoded, bytes));
  ASSERT_TRUE(serde::equals(decoded, result->snapshot));
  auto queryTxn = kv_->createReadWriteTransaction();
  RangeCountingTransaction queryCounted(*queryTxn);
  ASSERT_OK(blockingWait(EcRangeCatalog::query(queryCounted, req)));
  ASSERT_EQ(queryCounted.sets, 0);
  ASSERT_EQ(queryCounted.clears, 0);
  // Fixed eight-slot decoder rejects the wire count before decoding elements.
  auto pins = serde::serialize(req.selection.pins);
  ASSERT_FALSE(pins.empty());
  pins[0] = static_cast<char>(9);
  std::array<EcRangePin, 8> malformed;
  ASSERT_ERROR(serde::deserialize(malformed, pins), StatusCode::kInvalidFormat);
  EcRangeSelection maximum;
  maximum.object = object;
  maximum.length = kEcFileRangeMaxBytes;
  maximum.pinCount = 4;
  for (size_t i = 0; i != 4; ++i) maximum.pins[i] = EcRangePin{uint64_t{i}, Uuid::random()};
  EcManifestLayoutV1 layout;
  layout.incarnation = object.incarnation;
  layout.shardBytes = 1u << 20;
  ASSERT_OK(maximum.matchesLayout(layout));
  ASSERT_NO_FATAL_FAILURE(releaseRange(*result));
}

class TestEcV2NativeOwnedMutation : public TestEcV2NativeFileRange {
 protected:
  QueryEcOwnedMutationV2Req ownedQuery(const EcObjectRef &object, const Uuid &operation) {
    auto req = request<QueryEcOwnedMutationV2Req>();
    req.object = object;
    req.operation = operation;
    return req;
  }
  void makeBegin(BeginEcMutationV2Req &req, const EcObjectRef &object) {
    const auto logical = bytes(kStripeBytes, 701);
    auto encoded = storage::EcCodec::encode(logical, kShardBytes);
    ASSERT_OK(encoded);
    req = request<BeginEcMutationV2Req>();
    req.object = object;
    req.operation = Uuid::random();
    req.expectedEpoch = 1;
    req.logicalLength = logical.size();
    std::array<std::string_view, 10> data;
    for (size_t i = 0; i != 10; ++i) data[i] = (*encoded)[i];
    auto digest = computeEcLogicalSha256(data, logical.size());
    ASSERT_OK(digest);
    req.contentSha256 = *digest;
    for (size_t i = 0; i != 12; ++i) {
      auto crc = storage::ChecksumInfo::create(storage::ChecksumType::CRC32C,
                                               reinterpret_cast<const uint8_t *>((*encoded)[i].data()),
                                               (*encoded)[i].size());
      req.fragmentCrc32c[i] = ~crc.value;
    }
  }
  std::string idKey(kv::KeyPrefix prefix, const EcObjectRef &object, const Uuid &id, bool scope = false) {
    std::string key(kv::toStr(prefix));
    key += object.incarnation.asStringView();
    if (scope) key.push_back(static_cast<char>(storage::EcGrantScope::WriteOperation));
    key += id.asStringView();
    return key;
  }
};

TEST_F(TestEcV2NativeOwnedMutation, RealOwnerCanObserveAfterReadAclRevocationUnlinkAndDeletingWithoutWrites) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "owner-query-acl"));
  Mutation mutation;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, mutation));
  auto req = ownedQuery(object, mutation.begin.operation);
  auto initial = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(initial);
  ASSERT_TRUE(initial->publishedContentConfirmed);
  ASSERT_EQ(initial->contentSha256, mutation.begin.contentSha256);
  ASSERT_EQ(initial->requestId, req.uuid);
  ASSERT_EQ(initial->clientNamespace, metaClientId_.uuid);
  ASSERT_TRUE(initial->drain);
  ASSERT_EQ(initial->drain->state, EcV2DrainState::Published);
  ASSERT_EQ(initial->drain->acknowledgedEndpoints, initial->drain->expectedEndpoints);
  auto txn = kv_->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, object.inode));
  ASSERT_OK(inode);
  ASSERT_TRUE(*inode);
  const auto originalInode = **inode;
  (**inode).acl.perm = Permission{0200};
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  auto ordinary = request<GetEcOperationV2Req>();
  ordinary.object = object;
  ordinary.operation = req.operation;
  ASSERT_ERROR(blockingWait(metaClient_->getEcOperationV2(ordinary)), MetaCode::kNoPermission);
  auto writeOnly = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(writeOnly);
  ASSERT_EQ(serde::serialize(*initial), serde::serialize(*writeOnly));
  txn = kv_->createReadWriteTransaction();
  auto removed = originalInode;
  removed.nlink = 0;
  removed.acl.perm = Permission{0};
  ASSERT_OK(blockingWait(removed.store(*txn)));
  auto catalog = blockingWait(EcCatalog::getObject(*txn, object));
  ASSERT_OK(catalog);
  const auto originalObject = *catalog;
  catalog->deleting = true;
  ++catalog->epoch;
  std::string objectKey(kv::toStr(kv::KeyPrefix::EcObject));
  objectKey += object.incarnation.asStringView();
  ASSERT_OK(blockingWait(txn->set(objectKey, serde::serialize(*catalog))));
  ASSERT_OK(blockingWait(txn->commit()));
  // Fixture-only tombstone simulation; ordinary unlink/truncate remain blocked.
  metaConfig_.set_readonly(true);
  const auto savedEngine = metaConfig_.ec_targets(0).engine_uuid();
  metaConfig_.ec_targets(0).set_engine_uuid("not-a-current-pool");
  auto retained = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(retained);
  ASSERT_EQ(serde::serialize(*initial), serde::serialize(*retained));
  metaConfig_.ec_targets(0).set_engine_uuid(savedEngine);
  metaConfig_.set_readonly(false);
  auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
  ASSERT_OK(key);
  auto readTxn = kv_->createReadWriteTransaction();
  RangeCountingTransaction count(*readTxn);
  ASSERT_OK(blockingWait(EcOwnedMutationCatalog::query(count, req, **key)));
  ASSERT_EQ(count.sets, 0);
  ASSERT_EQ(count.clears, 0);
  auto root = rootUser();
  ASSERT_OK(root);
  auto changed = req;
  changed.user = *root;
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(changed)), MetaCode::kNoPermission);
  changed.user.uid = user_.uid;
  changed.user.gid = user_.gid;
  ASSERT_OK(blockingWait(metaClient_->queryEcOwnedMutationV2(changed)));  // genuine root delegation
  changed = req;
  changed.user.uid = flat::Uid{0};
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(changed)), StatusCode::kAuthenticationFail);
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(ClientId::random()));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(replaceClientIdentity(metaClientId_));
  changed = req;
  changed.uuid = Uuid::zero();
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(changed)), StatusCode::kInvalidArg);
  metaConfig_.set_enable_ec_file_ranges(false);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), StatusCode::kNotImplemented);
  metaConfig_.set_enable_ec_file_ranges(true);
  txn = kv_->createReadWriteTransaction();
  auto restored = originalInode;
  ASSERT_OK(blockingWait(restored.store(*txn)));
  ASSERT_OK(blockingWait(txn->set(objectKey, serde::serialize(originalObject))));
  ASSERT_OK(blockingWait(txn->commit()));
}

TEST_F(TestEcV2NativeOwnedMutation, MissingLostBeginAndLostQueryReplyPreserveIdentityAndObserveAbort) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "owner-query-unknown"));
  BeginEcMutationV2Req begin;
  ASSERT_NO_FATAL_FAILURE(makeBegin(begin, object));
  auto req = ownedQuery(object, begin.operation);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), StatusCode::kKVStoreNotFound);
  const auto wait = metaClientConfig_.retry_default().retry_init_wait();
  metaClientConfig_.retry_default().set_retry_init_wait(0_ms);
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.ownerBeginArmed = begin.operation;
    replyDrop_.ownerBeginCalls = 0;
  }
  auto lostBegin = blockingWait(metaClient_->beginEcMutationV2(begin));
  ASSERT_FALSE(lostBegin);
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.ownerBeginCalls, 1);
    ASSERT_TRUE(replyDrop_.ownerBeginCommitted);
  }
  metaClientConfig_.retry_default().set_retry_init_wait(wait);
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.ownerQueryArmed = req.uuid;
    replyDrop_.ownerQueryCalls = 0;
  }
  auto lostQuery = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_FALSE(lostQuery);
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.ownerQueryCalls, 1);
  }
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  auto preparing = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(preparing);
  ASSERT_EQ(preparing->record.state, EcOperationState::Preparing);
  ASSERT_FALSE(preparing->drain);
  ASSERT_FALSE(preparing->publishedContentConfirmed);
  ASSERT_EQ(preparing->contentSha256, begin.contentSha256);
  ASSERT_EQ(preparing->record.intent.operation, begin.operation);
  ASSERT_EQ(preparing->requestId, req.uuid);
  // Persist a real T0 through the production catalog, intentionally without
  // dispatching T1. This is an actual FDB Closing state, not a mocked reply.
  auto closingTxn = kv_->createReadWriteTransaction();
  auto closingRecord = blockingWait(EcV2DrainCatalog::startCancel(*closingTxn,
                                                                  object,
                                                                  begin.operation,
                                                                  EcOwner{user_.uid, metaClientId_.uuid},
                                                                  authority_,
                                                                  Uuid::random()));
  ASSERT_OK(closingRecord);
  ASSERT_OK(blockingWait(closingTxn->commit()));
  auto closing = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(closing);
  ASSERT_EQ(closing->record.state, EcOperationState::Preparing);
  ASSERT_TRUE(closing->drain);
  ASSERT_EQ(closing->drain->state, EcV2DrainState::Closing);
  ASSERT_EQ(closing->drain->acknowledgedEndpoints, 0);
  ASSERT_FALSE(closing->publishedContentConfirmed);
  ASSERT_EQ(closing->requestId, req.uuid);
  auto cancelled = request<CancelEcMutationV2Req>();
  cancelled.object = object;
  cancelled.operation = begin.operation;
  ASSERT_OK(blockingWait(metaClient_->cancelEcMutationV2(cancelled)));
  auto terminal = blockingWait(metaClient_->queryEcOwnedMutationV2(req));
  ASSERT_OK(terminal);
  ASSERT_EQ(terminal->record.state, EcOperationState::Aborted);
  ASSERT_FALSE(terminal->publishedContentConfirmed);
  ASSERT_TRUE(terminal->drain);
  ASSERT_EQ(terminal->drain->state, EcV2DrainState::Aborted);
  ASSERT_EQ(terminal->drain->acknowledgedEndpoints, terminal->drain->expectedEndpoints);
  ASSERT_EQ(terminal->requestId, req.uuid);  // same query identity, newer observation
}

TEST_F(TestEcV2NativeOwnedMutation, RepairAndRetiredHistoricalPublicationDoNotDependOnTheCurrentHead) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "owner-query-history"));
  Mutation first;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  auto old = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(old);
  Mutation repaired;
  ASSERT_NO_FATAL_FAILURE(repair(repaired, *old, uint16_t{1}));
  ASSERT_NO_FATAL_FAILURE(writeFragments(repaired));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(repaired.publish)));
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = old->snapshot.pin;
  ASSERT_OK(blockingWait(metaClient_->releaseEcReadV2(release)));
  auto root = rootUser();
  ASSERT_OK(root);
  ASSERT_OK(blockingWait(metaClient_->retireEcRevisionV2(retirement(object, old->manifest.revision, *root))));
  auto historical = blockingWait(metaClient_->queryEcOwnedMutationV2(ownedQuery(object, first.begin.operation)));
  ASSERT_OK(historical);
  auto replacement = blockingWait(metaClient_->queryEcOwnedMutationV2(ownedQuery(object, repaired.begin.operation)));
  ASSERT_OK(replacement);
  ASSERT_TRUE(historical->publishedContentConfirmed);
  ASSERT_TRUE(replacement->publishedContentConfirmed);
  ASSERT_EQ(historical->record.candidate.revision, old->manifest.revision);
  ASSERT_NE(replacement->record.candidate.revision, historical->record.candidate.revision);
  ASSERT_EQ(replacement->record.intent.kind, EcMutationKind::Repair);
  ASSERT_EQ(replacement->record.candidate.fragments[1], historical->record.candidate.fragments[1]);
  auto txn = kv_->createReadWriteTransaction();
  auto retired = blockingWait(EcCatalog::getManifest(*txn, object, 0, old->manifest.revision));
  ASSERT_OK(retired);
  ASSERT_TRUE(retired->referencesReleased);
  ASSERT_EQ(retired->pins, 0);
}

TEST_F(TestEcV2NativeOwnedMutation, MissingBirthTamperedHistoricalProofAndWrongControlKeyFailClosed) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "owner-query-proof"));
  Mutation mutation;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, mutation));
  auto req = ownedQuery(object, mutation.begin.operation);
  auto txn = kv_->createReadWriteTransaction();
  std::string enrollment(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  enrollment += object.incarnation.asStringView();
  auto birth = blockingWait(txn->get(enrollment));
  ASSERT_OK(birth);
  ASSERT_TRUE(*birth);
  ASSERT_OK(blockingWait(txn->clear(enrollment)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), StatusCode::kDataCorruption);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(enrollment, **birth)));
  ASSERT_OK(blockingWait(txn->commit()));
  const auto key = idKey(kv::KeyPrefix::EcV2Drain, object, req.operation, true);
  txn = kv_->createReadWriteTransaction();
  auto saved = blockingWait(txn->get(key));
  ASSERT_OK(saved);
  ASSERT_TRUE(*saved);
  EcV2DrainRecord record;
  ASSERT_OK(serde::deserialize(record, **saved));
  ASSERT_TRUE(record.observations[0]);
  auto incomplete = record;
  incomplete.observations[0].reset();
  ASSERT_OK(blockingWait(txn->set(key, serde::serialize(incomplete))));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), StatusCode::kDataCorruption);
  auto changed = record;
  ++changed.observations[0]->ack.claims.inflight;
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(key, serde::serialize(changed))));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_FALSE(blockingWait(metaClient_->queryEcOwnedMutationV2(req)));
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(key, **saved)));
  ASSERT_OK(blockingWait(txn->commit()));
  auto wrong = storage::EcScopeControlKey::loadFile(std::filesystem::path(keyPath_.string()));
  ASSERT_OK(wrong);
  txn = kv_->createReadWriteTransaction();
  RangeCountingTransaction readOnly(*txn);
  ASSERT_FALSE(blockingWait(EcOwnedMutationCatalog::query(readOnly, req, **wrong)));
  ASSERT_EQ(readOnly.sets, 0);
  ASSERT_EQ(readOnly.clears, 0);
  ASSERT_OK(blockingWait(metaClient_->queryEcOwnedMutationV2(req)));
  std::string content(kv::toStr(kv::KeyPrefix::EcV2PublishedContent));
  content += object.incarnation.asStringView();
  for (uint64_t n : {uint64_t{0}, mutation.reservation.record.candidate.revision})
    for (int shift = 56; shift >= 0; shift -= 8) content.push_back(static_cast<char>(n >> shift));
  txn = kv_->createReadWriteTransaction();
  auto provenance = blockingWait(txn->get(content));
  ASSERT_OK(provenance);
  ASSERT_TRUE(*provenance);
  ASSERT_OK(blockingWait(txn->clear(content)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(req)), StatusCode::kDataCorruption);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(content, **provenance)));
  ASSERT_OK(blockingWait(txn->commit()));

  // A real Preparing+Bound operation retains the original zero-descriptor
  // candidate. Missing ECVA must not be mistaken for ECVO not yet existing.
  Mutation preparing;
  ASSERT_NO_FATAL_FAILURE(prepare(preparing, object, 0, 719, false, 1, kStripeBytes));
  auto preparingReq = ownedQuery(object, preparing.begin.operation);
  ASSERT_OK(blockingWait(metaClient_->queryEcOwnedMutationV2(preparingReq)));
  const auto &allocation = (*preparing.reservation.allocations)[0];
  auto chunk = allocation.fragment.identity.chunkId();
  ASSERT_OK(chunk);
  std::string allocationKey(kv::toStr(kv::KeyPrefix::EcV2Allocation));
  allocationKey += chunk->data();
  txn = kv_->createReadWriteTransaction();
  auto allocationBytes = blockingWait(txn->get(allocationKey));
  ASSERT_OK(allocationBytes);
  ASSERT_TRUE(*allocationBytes);
  ASSERT_OK(blockingWait(txn->clear(allocationKey)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(EcV2BindingCatalog::getOperationBinding(*txn,
                                                                    object,
                                                                    preparing.begin.operation,
                                                                    EcOwner{user_.uid, metaClientId_.uuid})),
               StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(preparingReq)), StatusCode::kDataCorruption);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(allocationKey, **allocationBytes)));
  ASSERT_OK(blockingWait(txn->commit()));

  // Individually valid ECVO can contain an extra endpoint with a recomputed
  // digest. It must still exactly match the original reservation's set.
  const auto operationKey = idKey(kv::KeyPrefix::EcV2Operation, object, preparing.begin.operation);
  txn = kv_->createReadWriteTransaction();
  auto operationBytes = blockingWait(txn->get(operationKey));
  ASSERT_OK(operationBytes);
  ASSERT_TRUE(*operationBytes);
  EcV2OperationBinding binding;
  ASSERT_OK(serde::deserialize(binding, **operationBytes));
  ASSERT_EQ(binding.operationEndpoints.count, 12);
  auto &set = binding.operationEndpoints;
  set.endpoints[12] = set.endpoints[0];
  set.endpoints[12].engineUuid = Uuid::random();
  set.count = 13;
  std::array<storage::EcScopeEndpoint, 13> endpoints;
  for (size_t i = 0; i != endpoints.size(); ++i) endpoints[i] = set.endpoints[i].controlEndpoint();
  auto extraDigest = storage::computeEcScopeEndpointDigest(endpoints);
  ASSERT_OK(extraDigest);
  set.digest = *extraDigest;
  ASSERT_OK(blockingWait(txn->set(operationKey, serde::serialize(binding))));
  ASSERT_OK(blockingWait(txn->commit()));
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcV2BindingCatalog::getOperationBinding(*txn,
                                                                 object,
                                                                 preparing.begin.operation,
                                                                 EcOwner{user_.uid, metaClientId_.uuid})));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(preparingReq)), StatusCode::kDataCorruption);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(operationKey, **operationBytes)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_OK(blockingWait(metaClient_->queryEcOwnedMutationV2(preparingReq)));
}

#include "EcFlatDirectNativeTests.inc"
#include "EcTargetRetirementNativeTests.inc"
#include "EcFileClientNativeTests.inc"
#include "EcReadDispatcherNativeTests.inc"
#include "EcRecoveryWriteNativeTests.inc"

}  // namespace
}  // namespace hf3fs::meta::server
