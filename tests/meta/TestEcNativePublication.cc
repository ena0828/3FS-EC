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
#include <unistd.h>
#include <vector>

#include "client/ec/NativeEcReadTransport.h"
#include "client/meta/MetaClient.h"
#include "common/net/Client.h"
#include "common/net/Server.h"
#include "core/user/UserStore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/storage/EcAuthorized.h"
#include "fdb/FDBKVEngine.h"
#include "meta/service/MetaSerdeService.h"
#include "meta/store/EcCatalog.h"
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

  CoTryTask<EcOperationRsp> publishEcMutation(serde::CallContext &ctx, const PublishEcMutationReq &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.calls;
    }
    auto response = co_await MetaSerdeService::publishEcMutation(ctx, req);
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

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = DropPublishMetaService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<MetaSerde<U>>;

 private:
  PublishReplyDrop &fault_;
};

// A bounded test-only barrier after actual authorization and disk completion,
// before serialization of the real TCP reply. No result/receipt is fabricated.
// It proves a local request can outlive the ten-result quorum; it does not
// claim that the disk worker is still running or that remote scopes drained.
struct ReadResponseGate {
  using Clock = std::chrono::steady_clock;
  struct State {
    uint16_t arrived = 0;
    uint16_t authenticationFailures = 0;
    std::array<uint16_t, 12> resultCodes{};
    bool released = false;
    bool timedOut = false;
  };
  void arm(const Uuid &scope) {
    std::lock_guard lock(mutex);
    armed = scope;
    state = {};
    deadline = Clock::now() + std::chrono::seconds(10);
  }
  void release() {
    std::lock_guard lock(mutex);
    state.released = true;
  }
  State snapshot() const {
    std::lock_guard lock(mutex);
    return state;
  }
  CoTask<void> afterRead(Uuid scope, uint16_t shard, uint16_t resultCode) {
    {
      std::lock_guard lock(mutex);
      if (armed.is_nil() || scope != armed || shard >= 12) co_return;
      state.arrived |= uint16_t(1u << shard);
      state.resultCodes[shard] = resultCode;
      if (resultCode == StatusCode::kAuthenticationFail) state.authenticationFailures |= uint16_t(1u << shard);
    }
    while (true) {
      {
        std::lock_guard lock(mutex);
        if (scope != armed || state.released) co_return;
        if (Clock::now() >= deadline) {
          state.timedOut = true;
          state.released = true;
          co_return;
        }
        // Wait until every one of the initial eleven real requests reached
        // the server, so client cancellation cannot prevent shard 10 dispatch.
        if ((state.arrived & 0x7ff) == 0x7ff && shard != 10) co_return;
      }
      co_await folly::coro::sleep(std::chrono::milliseconds(1));
    }
  }
  mutable std::mutex mutex;
  Uuid armed = Uuid::zero();
  Clock::time_point deadline;
  State state;
};

class GatedReadStorageService : public storage::StorageService {
 public:
  GatedReadStorageService(storage::StorageOperator &storage, ReadResponseGate &gate)
      : storage::StorageService(storage),
        gate_(gate) {}

  CoTryTask<storage::EcReadRsp> authorizedReadEcFragment(serde::CallContext &ctx,
                                                         const storage::EcAuthorizedReadReq &req) {
    auto response = co_await storage::StorageService::authorizedReadEcFragment(ctx, req);
    // Record the actual service result before the response barrier. Numeric
    // codes distinguish admission, authorization and disk errors without
    // writing a capability, request body or payload into the test evidence.
    const uint16_t resultCode = !response           ? response.error().code()
                                : !response->result ? response->result.error().code()
                                                    : 0;
    co_await gate_.afterRead(req.grant.claims.scopeId, req.request.identity.shard, resultCode);
    co_return response;
  }

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = GatedReadStorageService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<storage::StorageSerde<U>>;

 private:
  ReadResponseGate &gate_;
};

// Functional integration, not a durability/power-loss or throughput benchmark.
// Meta and Storage use real TCP Serde clients/services, actual private FDB and
// one actual Rust Engine. Only the mgmtd routing provider is a test double.
// Twelve targets/chains share one process, disk and failure domain; this is
// explicitly permitted by ec_allow_colocated_test_targets, not production
// placement. An Engine is opened per disk path, not per logical target.
class TestEcNativePublication : public hf3fs::testing::SetupFDB {
 protected:
  static constexpr uint32_t kShardBytes = 4096;
  virtual uint32_t ecAdmissionLimit() const { return 2; }
  virtual uint32_t ecUpdateQueueSize() const { return 8; }
  struct Mutation {
    std::string logical;
    storage::EcCodec::Shards shards;
    BeginEcMutationReq begin;
    EcOperationRsp reservation;
    PublishEcMutationReq publish;
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
    readGate_.release();
    if (selectorClient_) selectorClient_->stop();
    selectorClient_.reset();
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
    group.processor().set_max_processing_requests_num(16);
    group.processor().set_max_coroutines_num(16);
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
    storageConfig_.targets().set_allow_disk_without_uuid(true);
    storageConfig_.targets().set_collect_all_fds(false);
    auto &storage = storageConfig_.storage();
    storage.set_enable_ec_fragments(true);
    storage.set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    storage.set_ec_capability_key_file(keyPath_);
    storage.set_max_concurrent_ec_requests(ecAdmissionLimit());
    storage.write_worker().set_num_threads(2);
    storage.write_worker().set_bg_num_threads(1);
    storage.write_worker().set_queue_size(ecUpdateQueueSize());
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
                    std::make_unique<GatedReadStorageService>(components_->storageOperator, readGate_),
                    storageNode_,
                    flat::NodeType::STORAGE,
                    "StorageSerde"));
    fakeMgmtd_ = std::make_shared<hf3fs::test::FakeMgmtdClient>(routing_);
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

  void prepare(Mutation &out, const EcObjectRef &object, uint64_t base, uint32_t seed, bool badParity = false) {
    out.logical = bytes(10 * kShardBytes - 37, seed);
    auto encoded = storage::EcCodec::encode(out.logical, kShardBytes);
    ASSERT_OK(encoded);
    out.shards = std::move(*encoded);
    if (badParity) out.shards[11][17] ^= 0x53;
    out.begin = request<BeginEcMutationReq>();
    out.begin.object = object;
    out.begin.operation = Uuid::random();
    out.begin.expectedEpoch = 1;
    out.begin.expectedRevision = base;
    out.begin.logicalLength = out.logical.size();
    std::array<std::string_view, 10> logical;
    for (size_t i = 0; i != 10; ++i) logical[i] = out.shards[i];
    auto digest = computeEcLogicalSha256(logical, out.logical.size());
    ASSERT_OK(digest);
    out.begin.contentSha256 = *digest;
    for (size_t i = 0; i != 12; ++i) {
      const auto checksum = storage::ChecksumInfo::create(storage::ChecksumType::CRC32C,
                                                          reinterpret_cast<const uint8_t *>(out.shards[i].data()),
                                                          out.shards[i].size());
      out.begin.fragmentCrc32c[i] = ~checksum.value;
    }
    auto reserved = blockingWait(metaClient_->beginEcMutation(out.begin));
    ASSERT_OK(reserved);
    ASSERT_EQ(reserved->record.state, EcOperationState::Preparing);
    out.reservation = std::move(*reserved);
    out.publish = request<PublishEcMutationReq>();
    out.publish.object = object;
    out.publish.operation = out.begin.operation;
    for (size_t i = 0; i != 12; ++i) {
      const auto &fragment = out.reservation.record.candidate.fragments[i];
      auto descriptor = storage::computeEcIntegrity(fragment.identity, out.shards[i]);
      ASSERT_OK(descriptor);
      ASSERT_EQ(descriptor->wholeCrc32c, out.begin.fragmentCrc32c[i]);
      out.publish.descriptors[i] = *descriptor;
      ASSERT_TRUE(out.reservation.createGrants[i].has_value());
      const auto &binding = out.reservation.createGrants[i]->claims;
      ASSERT_EQ(binding.ownerUid, user_.uid);
      ASSERT_EQ(binding.clientUuid, metaClientId_.uuid);
      ASSERT_NE(binding.clientUuid, storageClientId_.uuid);
      ASSERT_EQ(binding.fragmentOperationId, fragment.operation);
    }
  }

  void writeFragments(const Mutation &mutation, size_t count = 12) {
    for (size_t i = 0; i != count; ++i) {
      if (!(mutation.begin.replacementMask & (1u << i))) continue;
      SCOPED_TRACE(fmt::format("write shard {}", i));
      const auto &fragment = mutation.reservation.record.candidate.fragments[i];
      storage::EcAuthorizedCreateReq authorized;
      auto &req = authorized.request;
      req.identity = fragment.identity;
      req.operationId = fragment.operation;
      req.vChainId = {fragment.placement.chain, storage::ChainVer{1}};
      req.targetId = fragment.placement.target;
      req.payload.data = mutation.shards[i];
      req.checksum.type = storage::ChecksumType::CRC32C;
      req.checksum.value = ~mutation.publish.descriptors[i].wholeCrc32c;
      authorized.grant = *mutation.reservation.createGrants[i];
      auto created = blockingWait(storageClient_->authorizedCreateEcFragment(authorized));
      ASSERT_OK(created);
      ASSERT_TRUE(serde::equals(created->identity, fragment.identity));
      ASSERT_EQ(created->operationId, fragment.operation);
      ASSERT_EQ(created->length, kShardBytes);
    }
  }

  AcquireEcReadReq readRequest(const EcObjectRef &object) const {
    auto req = request<AcquireEcReadReq>();
    req.object = object;
    req.pin = Uuid::random();
    return req;
  }

  void recoverHealthy(storage::EcCodec::Shards &recovered, const AcquireEcReadRsp &base, uint16_t replacementMask) {
    storage::EcCodec::Shards received;
    std::array<storage::EcCodecShardView, 10> sources;
    size_t count = 0;
    // Read exactly ten real healthy sources, including parity where available.
    // Omitted shards model erasures at the recovery input; their old physical
    // allocations remain intact so existing pins can still read that revision.
    for (size_t position = 12; position != 0 && count != sources.size(); --position) {
      const auto i = position - 1;
      if (replacementMask & (1u << i)) continue;
      SCOPED_TRACE(fmt::format("recover from healthy shard {}", i));
      const auto &fragment = base.manifest.fragments[i];
      ASSERT_TRUE(base.readGrants[i].has_value());
      storage::EcAuthorizedReadReq authorized;
      auto &req = authorized.request;
      req.identity = fragment.identity;
      req.operationId = fragment.operation;
      req.vChainId = {fragment.placement.chain, storage::ChainVer{1}};
      req.targetId = fragment.placement.target;
      req.expectedLength = fragment.integrity.wholeLength;
      req.checksum = {storage::ChecksumType::CRC32C, ~fragment.integrity.wholeCrc32c};
      authorized.grant = *base.readGrants[i];
      auto read = blockingWait(storageClient_->authorizedReadEcFragment(authorized));
      ASSERT_OK(read);
      ASSERT_TRUE(serde::equals(read->receipt.identity, fragment.identity));
      ASSERT_EQ(read->receipt.operationId, fragment.operation);
      received[i] = std::move(read->payload.data);
      auto integrity = storage::computeEcIntegrity(fragment.identity, received[i]);
      ASSERT_OK(integrity);
      ASSERT_TRUE(serde::equals(*integrity, fragment.integrity));
      sources[count++] = {static_cast<uint16_t>(i), received[i]};
    }
    ASSERT_EQ(count, sources.size());
    auto result = storage::EcCodec::recover(sources, base.manifest.logicalLength, kShardBytes);
    ASSERT_OK(result);
    recovered = std::move(*result);
  }

  void verifyRead(const AcquireEcReadRsp &pinned, const Mutation &expected) {
    storage::EcCodec::Shards received;
    std::array<storage::EcCodecShardView, 12> views;
    for (size_t i = 0; i != 12; ++i) {
      SCOPED_TRACE(fmt::format("read shard {}", i));
      const auto &fragment = pinned.manifest.fragments[i];
      ASSERT_TRUE(pinned.readGrants[i].has_value());
      ASSERT_EQ(pinned.readGrants[i]->claims.fragmentOperationId, fragment.operation);
      ASSERT_EQ(pinned.readGrants[i]->claims.scopeKind, storage::EcGrantScope::ReadPin);
      storage::EcAuthorizedReadReq authorized;
      auto &req = authorized.request;
      req.identity = fragment.identity;
      req.operationId = fragment.operation;
      req.vChainId = {fragment.placement.chain, storage::ChainVer{1}};
      req.targetId = fragment.placement.target;
      req.expectedLength = fragment.integrity.wholeLength;
      req.checksum.type = storage::ChecksumType::CRC32C;
      req.checksum.value = ~fragment.integrity.wholeCrc32c;
      authorized.grant = *pinned.readGrants[i];
      auto read = blockingWait(storageClient_->authorizedReadEcFragment(authorized));
      ASSERT_OK(read);
      ASSERT_TRUE(serde::equals(read->receipt.identity, fragment.identity));
      ASSERT_EQ(read->receipt.operationId, fragment.operation);
      received[i] = std::move(read->payload.data);
      ASSERT_EQ(received[i], expected.shards[i]);
      auto integrity = storage::computeEcIntegrity(fragment.identity, received[i]);
      ASSERT_OK(integrity);
      ASSERT_TRUE(serde::equals(*integrity, fragment.integrity));
      views[i] = {static_cast<uint16_t>(i), received[i]};
    }
    ASSERT_OK(storage::EcCodec::verify(views, pinned.manifest.logicalLength, kShardBytes));
    std::string reconstructed;
    for (size_t i = 0; i != 10; ++i) reconstructed += received[i];
    reconstructed.resize(pinned.manifest.logicalLength);
    ASSERT_EQ(reconstructed, expected.logical);
  }

  void startSelectorClient() {
    // A separate client keeps the existing fixture's two-permit settings.
    // The real response barrier needs room for all eleven dispatched requests.
    selectorClientConfig_.set_implementation_type(storage::client::StorageClient::ImplementationType::RPC);
    selectorClientConfig_.retry().set_max_wait_time(20_s);
    selectorClientConfig_.traffic_control().read().set_max_concurrent_requests(12);
    selectorClientConfig_.traffic_control().read().set_max_concurrent_requests_per_server(12);
    smallClient(selectorClientConfig_.net_client());
    smallClient(selectorClientConfig_.net_client_for_updates());
    selectorClient_ = storage::client::StorageClient::create(ClientId::random(), selectorClientConfig_, *mgmtd_);
    ASSERT_NE(selectorClient_, nullptr);
  }

  void selectAndRecover(const AcquireEcReadRsp &pinned, const Mutation &expected, bool badMac) {
    ::hf3fs::client::ec::EcStripeReadInput input;
    input.manifest = pinned.manifest;
    for (size_t i = 0; i != input.requests.size(); ++i) {
      ASSERT_TRUE(pinned.readGrants[i].has_value());
      const auto &fragment = pinned.manifest.fragments[i];
      auto &authorized = input.requests[i];
      auto &req = authorized.request;
      req.identity = fragment.identity;
      req.operationId = fragment.operation;
      req.vChainId = {fragment.placement.chain, storage::ChainVer{1}};
      req.targetId = fragment.placement.target;
      req.expectedLength = fragment.integrity.wholeLength;
      req.checksum = {storage::ChecksumType::CRC32C, ~fragment.integrity.wholeCrc32c};
      authorized.grant = *pinned.readGrants[i];
    }
    if (badMac) {
      // Preserve a valid schema and request binding, but invalidate the actual
      // MAC by changing the signed grant UUID. Storage must reject it itself.
      input.requests[0].grant.claims.grantId = Uuid::random();
    }
    readGate_.arm(input.requests[10].grant.claims.scopeId);
    folly::CPUThreadPoolExecutor executor(2);
    auto transport = std::make_shared<::hf3fs::client::ec::NativeEcReadTransport>(selectorClient_);
    ::hf3fs::client::ec::EcStripeRead reader(transport, executor, {});
    SCOPE_EXIT {
      readGate_.release();
      blockingWait(reader.close());
    };
    ::hf3fs::client::ec::EcStripeReadOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    // Exclude timing-based hedging from this deterministic test. A rejected
    // response still launches the twelfth request immediately.
    options.hedgeAfter = std::chrono::seconds(30);
    auto started = reader.start(std::move(input), options);
    ASSERT_OK(started);
    auto handle = std::move(*started);
    {
      auto selected = blockingWait(handle.takeReady());
      ASSERT_OK(selected);
      EXPECT_EQ(selected->attempted, badMac ? 12u : 11u);
      EXPECT_EQ(selected->rejected, badMac ? 1u : 0u);
      const auto gate = readGate_.snapshot();
      EXPECT_EQ(gate.arrived & 0x7ff, 0x7ff);
      EXPECT_EQ(gate.authenticationFailures, badMac ? 1u : 0u);
      std::string serviceCodes;
      for (size_t index = 0; index != gate.resultCodes.size(); ++index) {
        if (!(gate.arrived & (1u << index))) continue;
        const auto expectedCode = badMac && index == 0 ? StatusCode::kAuthenticationFail : 0;
        EXPECT_EQ(gate.resultCodes[index], expectedCode) << "actual service result, shard " << index;
        serviceCodes += fmt::format("{}{}:{}", serviceCodes.empty() ? "" : ",", index, gate.resultCodes[index]);
      }
      RecordProperty(badMac ? "selector_bad_mac_service_codes" : "selector_valid_service_codes", serviceCodes);
      EXPECT_FALSE(gate.timedOut);
      EXPECT_FALSE(gate.released);
      EXPECT_FALSE(handle.localCleanupComplete());
      EXPECT_EQ(reader.snapshot().activeOperations, 1u);
      EXPECT_GE(reader.snapshot().activeRequests, 1u);
      std::array<storage::EcCodecShardView, 10> sources;
      bool usedTwelfth = false;
      for (size_t i = 0; i != selected->shards.size(); ++i) {
        const auto &shard = selected->shards[i];
        EXPECT_NE(shard.index, 10);
        if (badMac) EXPECT_NE(shard.index, 0);
        usedTwelfth |= shard.index == 11;
        EXPECT_EQ(shard.result.payload.data, expected.shards[shard.index]);
        sources[i] = {shard.index, shard.result.payload.data};
      }
      EXPECT_EQ(usedTwelfth, badMac);
      auto recovered = storage::EcCodec::recover(sources, pinned.manifest.logicalLength, kShardBytes);
      ASSERT_OK(recovered);
      EXPECT_EQ(*recovered, expected.shards);
      std::string logical;
      for (size_t i = 0; i != 10; ++i) logical += (*recovered)[i];
      logical.resize(pinned.manifest.logicalLength);
      EXPECT_EQ(logical, expected.logical);
      // Neither reaching quorum nor recovering bytes releases the last TCP
      // request. The server still owns its real response at the explicit gate.
      EXPECT_FALSE(handle.localCleanupComplete());
      readGate_.release();
      blockingWait(handle.waitLocalCleanup());
      EXPECT_TRUE(handle.localCleanupComplete());
      EXPECT_EQ(reader.snapshot().activeOperations, 0u);
      EXPECT_EQ(reader.snapshot().activeRequests, 0u);
      EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12u * kShardBytes);
    }
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0u);
    EXPECT_FALSE(readGate_.snapshot().timedOut);
  }

  void expectHead(const EcObjectRef &object, uint64_t revision) {
    auto head = blockingWait(metaClient_->acquireEcRead(readRequest(object)));
    ASSERT_OK(head);
    ASSERT_EQ(head->manifest.revision, revision);
  }

  void expectReferences(const EcManifest &manifest, uint64_t count) {
    // Observational reads from the same private FDB, not a substituted backend.
    auto txn = kv_->createReadWriteTransaction();
    for (const auto &fragment : manifest.fragments) {
      auto reference = blockingWait(EcCatalog::getFragmentRef(*txn, fragment.identity));
      ASSERT_OK(reference);
      ASSERT_EQ(reference->references, count);
    }
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
  ReadResponseGate readGate_;
  storage::client::StorageClient::Config selectorClientConfig_;
  std::shared_ptr<storage::client::StorageClient> selectorClient_;
  net::Server::Config metaServerConfig_;
  std::unique_ptr<net::Server> metaServer_;
  net::Client::Config metaNetConfig_;
  std::unique_ptr<net::Client> metaNet_;
  meta::client::MetaClient::Config metaClientConfig_;
  std::unique_ptr<meta::client::MetaClient> metaClient_;
};

TEST_F(TestEcNativePublication, AuthenticatedPublicationAndFailureBoundaries) {
  auto create = request<CreateEcFileReq>();
  create.path = PathAt(parent_, fmt::format("ec-native-{}", Uuid::random()));
  create.shardBytes = kShardBytes;
  auto unauthorized = create;
  unauthorized.user.token = "not-a-valid-user-token";
  ASSERT_FALSE(blockingWait(metaClient_->createEcFile(unauthorized)));
  auto created = blockingWait(metaClient_->createEcFile(create));
  ASSERT_OK(created);
  ASSERT_TRUE(created->object.allowColocated);
  const auto object = created->object.object;
  {
    // Set up a root-owned, writable set-ID file in the private real database.
    // The writer remains the authenticated nonroot user. This tests that
    // successful EC publication applies the same special-bit policy as write.
    auto txn = kv_->createReadWriteTransaction();
    auto inode = blockingWait(Inode::load(*txn, object.inode));
    ASSERT_OK(inode);
    ASSERT_TRUE(inode->has_value());
    (**inode).acl.uid = flat::Uid{0};
    (**inode).acl.perm = Permission{06777};
    ASSERT_OK(blockingWait((**inode).store(*txn)));
    ASSERT_OK(blockingWait(txn->commit()));
  }

  Mutation initial;
  ASSERT_NO_FATAL_FAILURE(prepare(initial, object, 0, 1));
  ASSERT_NO_FATAL_FAILURE(writeFragments(initial));
  replyDrop_.arm(initial.begin.operation);
  auto published = blockingWait(metaClient_->publishEcMutation(initial.publish));
  ASSERT_OK(published);
  ASSERT_EQ(published->record.state, EcOperationState::Published);
  const auto fault = replyDrop_.snapshot();
  ASSERT_TRUE(fault.committed.has_value());
  ASSERT_GE(fault.calls, 2u) << "The committed reply must actually be lost and retried through TCP";
  ASSERT_EQ(fault.committed->candidate.revision, published->record.candidate.revision);
  ASSERT_EQ(fault.committed->intent.operation, initial.begin.operation);
  std::optional<Inode> writable;
  {
    auto txn = kv_->createReadWriteTransaction();
    auto inode = blockingWait(Inode::load(*txn, object.inode));
    ASSERT_OK(inode);
    ASSERT_TRUE(inode->has_value());
    ASSERT_EQ((**inode).acl.uid, flat::Uid{0});
    ASSERT_EQ((**inode).acl.perm, Permission{0777});
    writable = **inode;
  }
  for (bool immutable : {false, true}) {
    SCOPED_TRACE(immutable ? "published replay on immutable inode" : "published replay without WRITE");
    auto restricted = *writable;
    restricted.acl.perm = immutable ? Permission{0777} : Permission{0555};
    if (immutable) restricted.acl.iflags = IFlags(restricted.acl.iflags | FS_IMMUTABLE_FL);
    {
      auto txn = kv_->createReadWriteTransaction();
      ASSERT_OK(blockingWait(restricted.store(*txn)));
      ASSERT_OK(blockingWait(txn->commit()));
    }
    ASSERT_ERROR(blockingWait(metaClient_->publishEcMutation(initial.publish)), MetaCode::kNoPermission);
    ASSERT_NO_FATAL_FAILURE(expectReferences(published->record.candidate, 1));
    auto txn = kv_->createReadWriteTransaction();
    auto inode = blockingWait(Inode::load(*txn, object.inode));
    ASSERT_OK(inode);
    ASSERT_TRUE(inode->has_value());
    ASSERT_EQ(**inode, restricted);
  }
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(writable->store(*txn)));
    ASSERT_OK(blockingWait(txn->commit()));
  }
  // Separately destroy both client and transport, reconstruct the ownership
  // UUID from the saved file, then recover through real RPC. This is a clean
  // object reconstruction; neither the server process nor FDB is restarted.
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  auto repeated = blockingWait(metaClient_->publishEcMutation(initial.publish));
  ASSERT_OK(repeated);
  ASSERT_TRUE(serde::equals(repeated->record, published->record));
  auto get = request<GetEcOperationReq>();
  get.object = object;
  get.operation = initial.begin.operation;
  auto persisted = blockingWait(metaClient_->getEcOperation(get));
  ASSERT_OK(persisted);
  ASSERT_TRUE(serde::equals(persisted->record, published->record));
  ASSERT_NO_FATAL_FAILURE(expectReferences(published->record.candidate, 1));
  const auto baseRevision = published->record.candidate.revision;
  const auto originalPin = readRequest(object);
  auto pinned = blockingWait(metaClient_->acquireEcRead(originalPin));
  ASSERT_OK(pinned);
  ASSERT_NO_FATAL_FAILURE(verifyRead(*pinned, initial));

  auto changed = initial.begin;
  changed.contentSha256[0] ^= 1;
  auto reused = blockingWait(metaClient_->beginEcMutation(changed));
  ASSERT_FALSE(reused);
  ASSERT_EQ(reused.error().code(), StatusCode::kTokenMismatch);
  ASSERT_NO_FATAL_FAILURE(expectHead(object, baseRevision));

  Mutation missing;
  ASSERT_NO_FATAL_FAILURE(prepare(missing, object, baseRevision, 2));
  ASSERT_NO_FATAL_FAILURE(writeFragments(missing, 11));
  auto rejectedMissing = blockingWait(metaClient_->publishEcMutation(missing.publish));
  ASSERT_FALSE(rejectedMissing);
  ASSERT_NO_FATAL_FAILURE(expectHead(object, baseRevision));
  ASSERT_NO_FATAL_FAILURE(expectReferences(missing.reservation.record.candidate, 0));
  auto cancel = request<CancelEcMutationReq>();
  cancel.object = object;
  cancel.operation = missing.begin.operation;
  auto canceled = blockingWait(metaClient_->cancelEcMutation(cancel));
  ASSERT_OK(canceled);
  ASSERT_EQ(canceled->record.state, EcOperationState::Aborted);
  auto canceledRetry = blockingWait(metaClient_->cancelEcMutation(cancel));
  ASSERT_OK(canceledRetry);
  ASSERT_TRUE(serde::equals(canceledRetry->record, canceled->record));
  ASSERT_NO_FATAL_FAILURE(expectHead(object, baseRevision));

  Mutation wrongParity;
  ASSERT_NO_FATAL_FAILURE(prepare(wrongParity, object, baseRevision, 3, true));
  // Every stored shard has its correct CRC and descriptor, including the bad
  // parity bytes. Only the codeword verification should reject publication.
  ASSERT_NO_FATAL_FAILURE(writeFragments(wrongParity));
  auto rejectedParity = blockingWait(metaClient_->publishEcMutation(wrongParity.publish));
  ASSERT_FALSE(rejectedParity);
  ASSERT_EQ(rejectedParity.error().code(), StatusCode::kDataCorruption);
  ASSERT_NO_FATAL_FAILURE(expectHead(object, baseRevision));
  ASSERT_NO_FATAL_FAILURE(expectReferences(wrongParity.reservation.record.candidate, 0));

  Mutation writerA, writerB;
  ASSERT_NO_FATAL_FAILURE(prepare(writerA, object, baseRevision, 4));
  ASSERT_NO_FATAL_FAILURE(prepare(writerB, object, baseRevision, 5));
  ASSERT_NO_FATAL_FAILURE(writeFragments(writerA));
  ASSERT_NO_FATAL_FAILURE(writeFragments(writerB));
  auto [resultA, resultB] = blockingWait(folly::coro::collectAll(metaClient_->publishEcMutation(writerA.publish),
                                                                 metaClient_->publishEcMutation(writerB.publish)));
  ASSERT_NE(resultA.hasValue(), resultB.hasValue());
  const auto &winner = resultA ? writerA : writerB;
  const auto &loser = resultA ? writerB : writerA;
  const auto &failure = resultA ? resultB : resultA;
  ASSERT_EQ(failure.error().code(), StatusCode::kTokenStale);
  auto latest = blockingWait(metaClient_->acquireEcRead(readRequest(object)));
  ASSERT_OK(latest);
  ASSERT_EQ(latest->manifest.revision, winner.reservation.record.candidate.revision);
  ASSERT_NO_FATAL_FAILURE(verifyRead(*latest, winner));
  ASSERT_NO_FATAL_FAILURE(expectReferences(latest->manifest, 1));
  ASSERT_NO_FATAL_FAILURE(expectReferences(loser.reservation.record.candidate, 0));

  // A live pin remains attached to the old immutable revision after head CAS.
  auto old = blockingWait(metaClient_->acquireEcRead(originalPin));
  ASSERT_OK(old);
  ASSERT_EQ(old->manifest.revision, baseRevision);
  ASSERT_NO_FATAL_FAILURE(verifyRead(*old, initial));
  ASSERT_NO_FATAL_FAILURE(expectReferences(old->manifest, 1));
  ReleaseEcReadReq release;
  static_cast<AcquireEcReadReq &>(release) = originalPin;
  auto releaseResult = blockingWait(metaClient_->releaseEcRead(release));
  ASSERT_FALSE(releaseResult);
  ASSERT_EQ(releaseResult.error().code(), StatusCode::kNotImplemented)
      << "Without distributed admission/drain, an active pin must not be released";
  auto retained = blockingWait(metaClient_->acquireEcRead(originalPin));
  ASSERT_OK(retained);
  ASSERT_EQ(retained->manifest.revision, baseRevision);
  RecordProperty("committed_publish_reply_dropped", "1");
  RecordProperty("client_and_transport_reconstructed", "1; saved UUID; no server/process restart");
  RecordProperty("initial_publish_handler_calls", std::to_string(fault.calls));
  RecordProperty("verified_shards_per_read", "12");
  RecordProperty("power_loss_test", "false");
}

TEST_F(TestEcNativePublication, RepairsOneAndTwoAllocationsFromTenActualHealthyReads) {
  auto create = request<CreateEcFileReq>();
  create.path = PathAt(parent_, fmt::format("ec-repair-{}", Uuid::random()));
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFile(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation initial;
  ASSERT_NO_FATAL_FAILURE(prepare(initial, object, 0, 71));
  ASSERT_NO_FATAL_FAILURE(writeFragments(initial));
  auto published = blockingWait(metaClient_->publishEcMutation(initial.publish));
  ASSERT_OK(published);
  auto firstPin = blockingWait(metaClient_->acquireEcRead(readRequest(object)));
  ASSERT_OK(firstPin);
  ASSERT_NO_FATAL_FAILURE(verifyRead(*firstPin, initial));
  ASSERT_NO_FATAL_FAILURE(expectReferences(firstPin->manifest, 1));
  std::vector<AcquireEcReadRsp> pins{*firstPin};
  std::vector<EcManifest> history{firstPin->manifest};
  std::optional<Inode> preserved;
  {
    auto txn = kv_->createReadWriteTransaction();
    auto inode = blockingWait(Inode::load(*txn, object.inode));
    ASSERT_OK(inode);
    ASSERT_TRUE(inode->has_value());
    (**inode).acl.uid = flat::Uid{0};
    (**inode).acl.perm = Permission{06777};
    // Fixed old values make accidental timestamp updates observable even when
    // the repair completes within the configured one-second granularity.
    (**inode).mtime = UtcTime::fromMicroseconds(123456000000);
    (**inode).ctime = UtcTime::fromMicroseconds(234567000000);
    ASSERT_OK(blockingWait((**inode).store(*txn)));
    ASSERT_OK(blockingWait(txn->commit()));
    preserved = **inode;
  }

  for (uint16_t mask : {uint16_t{1u << 0}, uint16_t{(1u << 3) | (1u << 11)}}) {
    SCOPED_TRACE(fmt::format("repair replacement mask {}", mask));
    const auto base = pins.back();
    Mutation repair;
    ASSERT_NO_FATAL_FAILURE(recoverHealthy(repair.shards, base, mask));
    // The original data is only an oracle after recovery, never a source.
    ASSERT_EQ(repair.shards, initial.shards);
    for (size_t i = 0; i != 10; ++i) repair.logical += repair.shards[i];
    repair.logical.resize(base.manifest.logicalLength);
    ASSERT_EQ(repair.logical, initial.logical);
    repair.begin = request<BeginEcMutationReq>();
    repair.begin.object = object;
    repair.begin.operation = Uuid::random();
    repair.begin.expectedEpoch = 1;
    repair.begin.expectedRevision = base.manifest.revision;
    repair.begin.logicalLength = base.manifest.logicalLength;
    repair.begin.kind = EcMutationKind::Repair;
    repair.begin.replacementMask = mask;
    std::array<std::string_view, 10> logical;
    for (size_t i = 0; i != 10; ++i) logical[i] = repair.shards[i];
    auto digest = computeEcLogicalSha256(logical, repair.logical.size());
    ASSERT_OK(digest);
    repair.begin.contentSha256 = *digest;
    for (size_t i = 0; i != 12; ++i) {
      auto integrity = storage::computeEcIntegrity(base.manifest.fragments[i].identity, repair.shards[i]);
      ASSERT_OK(integrity);
      ASSERT_TRUE(serde::equals(*integrity, base.manifest.fragments[i].integrity));
      repair.begin.fragmentCrc32c[i] = integrity->wholeCrc32c;
    }
    auto reserved = blockingWait(metaClient_->beginEcMutation(repair.begin));
    ASSERT_OK(reserved);
    ASSERT_EQ(reserved->record.state, EcOperationState::Preparing);
    ASSERT_EQ(reserved->record.candidate.generation, base.manifest.generation);
    ASSERT_NE(reserved->record.candidate.revision, base.manifest.revision);
    repair.reservation = *reserved;
    repair.publish = request<PublishEcMutationReq>();
    repair.publish.object = object;
    repair.publish.operation = repair.begin.operation;
    for (size_t i = 0; i != 12; ++i) {
      const auto &fragment = reserved->record.candidate.fragments[i];
      const auto &old = base.manifest.fragments[i];
      const bool replacement = (mask & (1u << i)) != 0;
      ASSERT_EQ(reserved->createGrants[i].has_value(), replacement);
      if (replacement) {
        ASSERT_NE(fragment.identity.allocation, old.identity.allocation);
        ASSERT_EQ(fragment.operation, repair.begin.operation);
        ASSERT_EQ(reserved->createGrants[i]->claims.fragmentOperationId, repair.begin.operation);
      } else {
        ASSERT_TRUE(serde::equals(fragment, old));
      }
      auto integrity = storage::computeEcIntegrity(fragment.identity, repair.shards[i]);
      ASSERT_OK(integrity);
      ASSERT_TRUE(serde::equals(*integrity, old.integrity));
      repair.publish.descriptors[i] = *integrity;
    }
    // This helper submits only mask-selected creates. All healthy allocations
    // remain the exact old identities and are shared by the new manifest.
    ASSERT_NO_FATAL_FAILURE(writeFragments(repair));
    auto result = blockingWait(metaClient_->publishEcMutation(repair.publish));
    ASSERT_OK(result);
    ASSERT_EQ(result->record.state, EcOperationState::Published);
    history.push_back(result->record.candidate);
    auto repeated = blockingWait(metaClient_->publishEcMutation(repair.publish));
    ASSERT_OK(repeated);
    ASSERT_TRUE(serde::equals(repeated->record, result->record));
    {
      auto txn = kv_->createReadWriteTransaction();
      auto inode = blockingWait(Inode::load(*txn, object.inode));
      ASSERT_OK(inode);
      ASSERT_TRUE(inode->has_value());
      ASSERT_EQ(**inode, *preserved);
      // Every retained revision contributes one reference. Neither the old
      // read pins nor replaying Publish contributes additional fragment refs.
      for (const auto &manifest : history) {
        for (const auto &fragment : manifest.fragments) {
          uint64_t expected = 0;
          for (const auto &other : history) {
            if (serde::equals(other.fragments[fragment.identity.shard].identity, fragment.identity)) ++expected;
          }
          auto reference = blockingWait(EcCatalog::getFragmentRef(*txn, fragment.identity));
          ASSERT_OK(reference);
          ASSERT_EQ(reference->references, expected);
          ASSERT_TRUE(reference->owner.is_nil());
          ASSERT_FALSE(reference->gcCandidate);
        }
      }
    }
    auto latest = blockingWait(metaClient_->acquireEcRead(readRequest(object)));
    ASSERT_OK(latest);
    ASSERT_EQ(latest->manifest.revision, result->record.candidate.revision);
    ASSERT_NO_FATAL_FAILURE(verifyRead(*latest, initial));
    for (const auto &old : pins) ASSERT_NO_FATAL_FAILURE(verifyRead(old, initial));
    pins.push_back(std::move(*latest));
  }
  RecordProperty("repair_replacement_counts", "1,2");
  RecordProperty("actual_healthy_reads_per_recovery", "10");
  RecordProperty("repair_erasure_model", "source omission; old physical allocations retained for pinned reads");
  RecordProperty("physical_fragment_deletion", "false");
}

// This fixture launches eleven requests together and may add the twelfth.
// Non-waiting EC queues must fit that declared burst even before workers run.
// Other fixtures retain their two-request admission and eight-entry queue.
class TestEcNativeReadSelector : public TestEcNativePublication {
 protected:
  uint32_t ecAdmissionLimit() const override { return 12; }
  uint32_t ecUpdateQueueSize() const override { return 12; }
};

TEST_F(TestEcNativeReadSelector, QuorumPrecedesTcpCleanupAndRejectsBadGrant) {
  auto create = request<CreateEcFileReq>();
  create.path = PathAt(parent_, fmt::format("ec-select-{}", Uuid::random()));
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFile(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation initial;
  ASSERT_NO_FATAL_FAILURE(prepare(initial, object, 0, 67));
  ASSERT_NO_FATAL_FAILURE(writeFragments(initial));
  auto published = blockingWait(metaClient_->publishEcMutation(initial.publish));
  ASSERT_OK(published);
  ASSERT_EQ(published->record.state, EcOperationState::Published);
  ASSERT_NO_FATAL_FAILURE(startSelectorClient());
  for (bool badMac : {false, true}) {
    SCOPED_TRACE(badMac ? "actual Storage authentication failure and twelfth source" : "eleven real TCP candidates");
    const auto acquire = readRequest(object);
    auto pinned = blockingWait(metaClient_->acquireEcRead(acquire));
    ASSERT_OK(pinned);
    ASSERT_EQ(pinned->manifest.revision, 1u);
    ASSERT_NO_FATAL_FAILURE(selectAndRecover(*pinned, initial, badMac));
    // Local cleanup proves only local buffers and request frames have ended.
    // The unfinished authenticated remote-drain protocol remains fail-closed.
    auto release = request<ReleaseEcReadReq>();
    static_cast<AcquireEcReadReq &>(release) = acquire;
    ASSERT_ERROR(blockingWait(metaClient_->releaseEcRead(release)), StatusCode::kNotImplemented);
    auto retained = blockingWait(metaClient_->acquireEcRead(acquire));
    ASSERT_OK(retained);
    EXPECT_EQ(retained->manifest.revision, pinned->manifest.revision);
  }
  ASSERT_NO_FATAL_FAILURE(expectReferences(published->record.candidate, 1));
  RecordProperty("selector_transport", "native controlled StorageClient TCP, real capability verification");
  RecordProperty("selector_quorum", "11 initial candidates, 10 actual validated responses before local cleanup");
  RecordProperty("selector_failure", "one invalid MAC at real service; shard 12 replaces rejected candidate");
  RecordProperty("selector_gate",
                 "after actual service completion, before TCP response serialization; not remote drain");
  RecordProperty("selector_decode", "EcCodec recover from selected actual bytes equals original logical data");
}

}  // namespace
}  // namespace hf3fs::meta::server
