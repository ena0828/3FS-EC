#include <algorithm>
#include <chrono>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <linux/magic.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "client/storage/StorageClient.h"
#include "common/net/Server.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::storage {
namespace {
using folly::coro::blockingWait;
void smallDiscoveryThreads(net::ThreadPoolGroup::Config &config) {
  config.set_num_proc_threads(2);
  config.set_num_io_threads(1);
  config.set_num_bg_threads(1);
  config.set_num_connect_threads(1);
}
void smallDiscoveryClient(net::Client::Config &config) {
  smallDiscoveryThreads(config.thread_pool());
  config.processor().set_max_processing_requests_num(16);
  config.processor().set_max_coroutines_num(16);
  config.processor().set_response_compression_level(0);
  config.set_default_timeout(10_s);
}
Uuid fromBytes(const std::array<uint8_t, 16> &bytes) {
  Uuid value;
  std::copy(bytes.begin(), bytes.end(), std::begin(value.data));
  return value;
}
class TestEcGcDiscoveryService : public ::testing::Test {
 protected:
  virtual bool enableGc() const { return true; }
  void SetUp() override {
    struct statfs fs {};
    ASSERT_EQ(::statfs(directory.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, EXT4_SUPER_MAGIC) << "native V2 control requires local ext4 TMPDIR";
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_cur, 8192u);
    const auto path = keys.path() / "gc.key";
    std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
    const std::string bytes(32, 'G');
    output.write(bytes.data(), bytes.size());
    output.close();
    ASSERT_TRUE(output.good());
    ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
    auto loaded = EcGcKey::loadFile(std::filesystem::path(path.string()), keyId, {});
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcGcKey>(std::move(*loaded));
    const auto dataPath = keys.path() / "data.key";
    std::ofstream dataOutput(dataPath.string(), std::ios::binary | std::ios::trunc);
    const std::string dataBytes(32, 'D');
    dataOutput.write(dataBytes.data(), dataBytes.size());
    dataOutput.close();
    ASSERT_TRUE(dataOutput.good());
    ASSERT_EQ(::chmod(dataPath.c_str(), 0600), 0);
    config.set_speed_up_quit(false);
    config.targets().set_target_paths({directory.path()});
    config.targets().set_ec_only(true);
    config.targets().set_ec_staging_v2(true);
    config.targets().set_ec_exact_gc(true);
    config.targets().set_allow_disk_without_uuid(true);
    config.targets().set_collect_all_fds(false);
    config.storage().set_enable_ec_fragments(true);
    config.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    config.storage().set_ec_capability_key_file(dataPath);
    config.storage().set_enable_ec_gc(enableGc());
    config.storage().set_ec_gc_key_file(path);
    config.storage().set_ec_gc_key_id(fmt::to_string(keyId));
    config.storage().set_ec_gc_authority(fmt::to_string(authority));
    config.storage().write_worker().set_num_threads(1);
    config.storage().write_worker().set_bg_num_threads(1);
    config.storage().write_worker().set_queue_size(1);
    config.storage().event_trace_log().set_enabled(false);
    config.storage().event_trace_log().set_trace_file_dir(traces.path());
    config.aio_read_worker().set_num_threads(1);
    config.aio_read_worker().set_queue_size(8);
    config.sync_worker().set_num_threads(2);
    for (auto *pool : {&config.coroutines_pool_read(),
                       &config.coroutines_pool_update(),
                       &config.coroutines_pool_sync(),
                       &config.coroutines_pool_default()}) {
      pool->set_threads_num(1);
      pool->set_coroutines_num(2);
      pool->set_queue_size(8);
    }
    smallDiscoveryClient(config.client());
    smallDiscoveryClient(config.forward_client());
    components = std::make_unique<Components>(config);
    components->appInfo.nodeId = nodeId;
    ASSERT_OK(components->storageTargets.load(loader));
    ASSERT_OK(components->storageOperator.init(1));
    initialized = true;
    CreateTargetReq create;
    create.chainId = chainId;
    create.targetId = targetId;
    create.onlyChunkEngine = true;
    EcCreateTargetReq createRequest;
    createRequest.settings = create;
    ASSERT_OK(blockingWait(components->storageOperator.createEcTarget(createRequest)));
    auto found = components->targetMap.getByTargetId(targetId);
    ASSERT_OK(found);
    auto state = (*found)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    scope = state->first;
    identity = state->second;

    smallDiscoveryThreads(serverConfig.thread_pool());
    smallDiscoveryThreads(serverConfig.independent_thread_pool());
    serverConfig.set_groups_length(1);
    auto &group = serverConfig.groups(0);
    group.set_network_type(net::Address::TCP);
    group.set_services({"StorageSerde"});
    group.listener().set_listen_port(0);
    group.listener().set_filter_list({"lo"});
    group.listener().set_custom_tcp_nic_prefix("lo");
    group.processor().set_max_processing_requests_num(16);
    group.processor().set_max_coroutines_num(16);
    group.processor().set_response_compression_level(0);
    server = std::make_unique<net::Server>(serverConfig);
    ASSERT_OK(server->addSerdeService(std::make_unique<StorageService>(components->storageOperator), true));
    ASSERT_OK(server->setup());
    flat::AppInfo app;
    app.nodeId = nodeId;
    ASSERT_OK(server->start(app));
    auto groups = server->getServiceGroupInfos();
    ASSERT_EQ(groups.size(), 1);
    auto endpoint = std::find_if(groups[0].endpoints.begin(), groups[0].endpoints.end(), [](const auto &value) {
      return value.type == net::Address::TCP && value.ipStr() == "127.0.0.1";
    });
    ASSERT_NE(endpoint, groups[0].endpoints.end());
    const auto address = *endpoint;
    groups[0].endpoints.assign(1, address);
    auto routing = std::make_shared<flat::RoutingInfo>();
    routing->routingInfoVersion = flat::RoutingInfoVersion(1);
    flat::NodeInfo node;
    node.app.nodeId = nodeId;
    node.app.serviceGroups = std::move(groups);
    node.type = flat::NodeType::STORAGE;
    // Control must reach a retained physical instance without a serving chain
    // and without requiring the node's heartbeat state to still be connected.
    node.status = flat::NodeStatus::HEARTBEAT_FAILED;
    routing->nodes.emplace(nodeId, std::move(node));
    mgmtd = std::make_unique<hf3fs::test::FakeMgmtdClient>(routing);
    clientConfig.set_implementation_type(client::StorageClient::ImplementationType::RPC);
    clientConfig.retry().set_max_wait_time(10_s);
    smallDiscoveryClient(clientConfig.net_client());
    smallDiscoveryClient(clientConfig.net_client_for_updates());
    storageClient = client::StorageClient::create(ClientId::random(), clientConfig, *mgmtd->asCommon());
    ASSERT_NE(storageClient, nullptr);
  }
  void TearDown() override {
    if (storageClient) storageClient->stop();
    if (server) server->stopAndJoin();
    if (components && initialized) {
      auto stopped = components->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped);
    }
    storageClient.reset();
    server.reset();
    scope.reset();
    if (components) {
      auto map = components->targetMap.release();
      if (map)
        for (const auto &[id, target] : map->getTargets())
          if (target.storageTarget) EXPECT_TRUE(target.storageTarget->release());
      map.reset();
      EXPECT_TRUE(components->storageTargets.globalFileStore().clear(loader));
      components.reset();
    }
  }
  EcGcDiscoveryClaims claims() const {
    EcGcDiscoveryClaims value;
    value.keyId = keyId;
    value.authority = authority;
    value.nodeId = nodeId;
    value.chainId = chainId;
    value.targetId = targetId;
    value.nonce = Uuid::random();
    value.issuedAtSeconds = now();
    value.expiresAtSeconds = value.issuedAtSeconds + 30;
    return value;
  }
  static uint64_t now() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
  }
  client::EcRequestControl control() const {
    client::EcRequestControl value;
    value.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    return value;
  }
  const NodeId nodeId{61};
  const ChainId chainId{81};
  const TargetId targetId{71};
  const Uuid authority = Uuid::from(201, 202);
  const Uuid keyId = Uuid::from(203, 204);
  folly::test::TemporaryDirectory directory, keys, traces;
  Components::Config config;
  CPUExecutorGroup loader{1, "EcDiscoveryRpc"};
  std::unique_ptr<Components> components;
  bool initialized = false;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity identity{};
  std::shared_ptr<const EcGcKey> key;
  net::Server::Config serverConfig;
  std::unique_ptr<net::Server> server;
  client::StorageClient::Config clientConfig;
  std::unique_ptr<hf3fs::test::FakeMgmtdClient> mgmtd;
  std::shared_ptr<client::StorageClient> storageClient;
};

class TestEcGcDiscoveryDisabled : public TestEcGcDiscoveryService {
 protected:
  bool enableGc() const override { return false; }
};
TEST_F(TestEcGcDiscoveryDisabled, DiskFormat3DoesNotImplyInitializedGcAuthority) {
  auto request = signEcGcDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  ASSERT_ERROR(blockingWait(storageClient->getEcGcCapabilityControlled(*request, key, control())),
               StatusCode::kAuthenticationFail);
}
TEST_F(TestEcGcDiscoveryService, RealTcpReturnsActualInstanceAndCurrentReadOnlyMask) {
  auto request = signEcGcDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  auto observed = blockingWait(storageClient->getEcGcCapabilityControlled(*request, key, control()));
  ASSERT_OK(observed);
  ASSERT_OK(verifyEcGcDiscoveryObservation(*key, *observed, *request, now()));
  EXPECT_EQ(observed->claims.endpoint.engineUuid, fromBytes(identity.engine));
  EXPECT_EQ(observed->claims.endpoint.targetIncarnation, fromBytes(identity.incarnation));
  EXPECT_EQ(observed->claims.endpoint.nodeId, nodeId);
  EXPECT_EQ(observed->claims.keyId, keyId);
  EXPECT_EQ(observed->claims.authority, authority);
  EXPECT_EQ(observed->claims.dataProtocol, 2);
  EXPECT_EQ(observed->claims.diskFormat, 3);
  EXPECT_EQ(observed->claims.gcProtocol, 1);
  EXPECT_EQ(observed->claims.capabilities, kEcGcDiscoveryCollectQuery);
  EXPECT_FALSE(observed->claims.bootNonce.is_nil());
  config.storage().set_read_only(true);
  auto next = signEcGcDiscovery(*key, claims(), now());
  ASSERT_OK(next);
  auto readOnly = blockingWait(storageClient->getEcGcCapabilityControlled(*next, key, control()));
  ASSERT_OK(readOnly);
  EXPECT_EQ(readOnly->claims.capabilities, kEcGcDiscoveryQueryOnly);
  EXPECT_EQ(readOnly->claims.bootNonce, observed->claims.bootNonce);
  // Both observations are point-in-time statements, not authority to Collect.
  EXPECT_FALSE(verifyEcGcDiscoveryObservation(*key, *readOnly, *request, now()));
}
TEST_F(TestEcGcDiscoveryService, ServerRejectsTamperMissingTargetAndExpiredRequest) {
  auto request = signEcGcDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  auto forged = *request;
  forged.claims.nonce.data[0] ^= 1;
  auto rejected = blockingWait(components->storageOperator.getEcGcCapability(forged));
  ASSERT_OK(rejected);
  ASSERT_ERROR(rejected->result, StatusCode::kAuthenticationFail);
  auto missing = claims();
  missing.targetId = TargetId{999};
  auto signedMissing = signEcGcDiscovery(*key, missing, now());
  ASSERT_OK(signedMissing);
  ASSERT_ERROR(blockingWait(storageClient->getEcGcCapabilityControlled(*signedMissing, key, control())),
               StorageCode::kTargetStateInvalid);
  auto stale = claims();
  stale.issuedAtSeconds -= 100;
  stale.expiresAtSeconds -= 100;
  auto signedStale = signEcGcDiscovery(*key, stale, stale.issuedAtSeconds);
  ASSERT_OK(signedStale);
  rejected = blockingWait(components->storageOperator.getEcGcCapability(*signedStale));
  ASSERT_OK(rejected);
  ASSERT_ERROR(rejected->result, StatusCode::kAuthenticationFail);
}
TEST_F(TestEcGcDiscoveryService, StoppedRuntimeDoesNotAdvertiseViaNonNullOwner) {
  auto request = signEcGcDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  ASSERT_OK(components->storageOperator.stopAndJoin());
  // The network server and target map remain alive; ecGc_ still exists but its
  // lifecycle gate is closed. Successful prior observations cannot reopen it.
  ASSERT_ERROR(blockingWait(storageClient->getEcGcCapabilityControlled(*request, key, control())),
               StorageClientCode::kResourceBusy);
}
}  // namespace
}  // namespace hf3fs::storage
