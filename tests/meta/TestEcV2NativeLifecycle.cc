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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "client/ec/EcStripeClient.h"
#include "client/meta/MetaClient.h"
#include "common/net/Client.h"
#include "common/net/Server.h"
#include "core/user/UserStore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/storage/EcAuthorizedV2.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "fdb/FDBKVEngine.h"
#include "meta/service/MetaSerdeService.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/EcV2PublishedCatalog.h"
#include "meta/store/Inode.h"
#include "storage/ec_codec/EcCodec.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"
#include "tests/lib/UnitTestFabric.h"

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
};

// The real operator has returned from its FDB commit before this one-shot
// connection fault. No fabricated success, receipt or transaction is supplied.
class DropPublishMetaService : public MetaSerdeService {
 public:
  DropPublishMetaService(MetaOperator &meta, PublishReplyDrop &fault)
      : MetaSerdeService(meta),
        fault_(fault) {}

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
    }
    if (drop) ctx.transport()->invalidate(false);
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
    std::ofstream control(controlKeyPath_.string(), std::ios::binary | std::ios::trunc);
    const std::string material(32, 'C');
    control.write(material.data(), material.size());
    control.close();
    ASSERT_TRUE(control.good());
    ASSERT_EQ(::chmod(controlKeyPath_.c_str(), 0600), 0);
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
    storageConfig_.targets().set_allow_disk_without_uuid(true);
    storageConfig_.targets().set_collect_all_fds(false);
    auto &storage = storageConfig_.storage();
    storage.set_enable_ec_fragments(true);
    storage.set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    storage.set_ec_capability_key_file(keyPath_);
    storage.set_enable_ec_scope_control(true);
    storage.set_ec_scope_control_key_file(controlKeyPath_);
    storage.set_ec_scope_control_authority(authority_.toHexString());
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
    // No Components::start: avoid unrelated allocator, RDMA/AIO, resync and
    // telemetry background workers. The actual EC update worker starts in init.
    ASSERT_OK(components_->storageTargets.load(loader_));
    ASSERT_OK(components_->storageOperator.init(1));
    storageInitialized_ = true;
    routing_ = std::make_shared<flat::RoutingInfo>();
    routing_->routingInfoVersion = flat::RoutingInfoVersion{1};
    ASSERT_NO_FATAL_FAILURE(
        startServer(storageServerConfig_,
                    storageServer_,
                    std::make_unique<ControlFailureStorageService>(components_->storageOperator, controlFault_),
                    storageNode_,
                    flat::NodeType::STORAGE,
                    "StorageSerde"));
    fakeMgmtd_ = std::make_shared<hf3fs::test::FakeMgmtdClient>(routing_);
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

  void prepare(Mutation &out, const EcObjectRef &object, uint64_t revision, uint32_t seed, bool badParity = false) {
    out.logical = bytes(10 * kShardBytes - 37, seed);
    auto encoded = storage::EcCodec::encode(out.logical, kShardBytes);
    ASSERT_OK(encoded);
    out.shards = std::move(*encoded);
    if (badParity) out.shards[11][17] ^= 0x53;
    out.begin = request<BeginEcMutationV2Req>();
    out.begin.object = object;
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
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(planReq)), StatusCode::kTokenStale);
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
    size_t source = 0;
    for (uint16_t i = 0; i != 12 && source != 10; ++i)
      if (!(repair.replacementMask & (1u << i))) repair.sources[source++] = i;
    auto repaired = blockingWait(manager->repair(repair, control()));
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
    RecordProperty(fmt::format("native_strategy_{}", round), static_cast<int>(modes[round]));
  }
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
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

}  // namespace
}  // namespace hf3fs::meta::server
