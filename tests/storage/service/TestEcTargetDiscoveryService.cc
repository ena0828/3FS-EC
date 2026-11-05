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
class TestEcTargetDiscoveryService : public ::testing::Test {
 protected:
  virtual bool enableDiscovery() const { return true; }
  void SetUp() override {
    struct statfs fs {};
    ASSERT_EQ(::statfs(directory.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, EXT4_SUPER_MAGIC) << "native V2 control requires local ext4 TMPDIR";
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_cur, 8192u);
    const auto path = keys.path() / "control.key";
    std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
    const std::string bytes(32, 'C');
    output.write(bytes.data(), bytes.size());
    output.close();
    ASSERT_TRUE(output.good());
    ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
    auto loaded = EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
    config.set_speed_up_quit(false);
    config.targets().set_target_paths({directory.path()});
    config.targets().set_ec_only(true);
    config.targets().set_ec_staging_v2(true);
    config.targets().set_allow_disk_without_uuid(true);
    config.targets().set_collect_all_fds(false);
    config.storage().set_enable_ec_fragments(true);
    config.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    config.storage().set_enable_ec_scope_control(enableDiscovery());
    config.storage().set_ec_scope_control_key_file(path);
    config.storage().set_ec_scope_control_authority(fmt::to_string(authority));
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
  EcTargetDiscoveryClaims claims() const {
    EcTargetDiscoveryClaims value;
    value.clusterAuthority = authority;
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
  folly::test::TemporaryDirectory directory, keys, traces;
  Components::Config config;
  CPUExecutorGroup loader{1, "EcDiscoveryRpc"};
  std::unique_ptr<Components> components;
  bool initialized = false;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity identity{};
  std::shared_ptr<const EcScopeControlKey> key;
  net::Server::Config serverConfig;
  std::unique_ptr<net::Server> server;
  client::StorageClient::Config clientConfig;
  std::unique_ptr<hf3fs::test::FakeMgmtdClient> mgmtd;
  std::shared_ptr<client::StorageClient> storageClient;
};

class TestEcTargetDiscoveryDisabled : public TestEcTargetDiscoveryService {
 protected:
  bool enableDiscovery() const override { return false; }
};
TEST_F(TestEcTargetDiscoveryDisabled, ServerNeverFallsBackWhenControlAuthorityIsDisabled) {
  auto request = signEcTargetDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*request, key, control())),
               StatusCode::kAuthenticationFail);
}
TEST_F(TestEcTargetDiscoveryService, ActualLoadedInstanceCanBeDiscoveredWithoutServingRoute) {
  auto request = signEcTargetDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  auto observed = blockingWait(storageClient->getEcTargetIdentityControlled(*request, key, control()));
  ASSERT_OK(observed);
  ASSERT_OK(verifyEcTargetDiscoveryObservation(*key, *observed, *request, now()));
  EXPECT_EQ(observed->claims.endpoint.engineUuid, fromBytes(identity.engine));
  EXPECT_EQ(observed->claims.endpoint.targetIncarnation, fromBytes(identity.incarnation));
  EXPECT_EQ(observed->claims.endpoint.nodeId, nodeId);
  auto another = signEcTargetDiscovery(*key, claims(), now());
  ASSERT_OK(another);
  ASSERT_ERROR(verifyEcTargetDiscoveryObservation(*key, *observed, *another, now()), StatusCode::kAuthenticationFail);
  auto changed = *observed;
  changed.claims.endpoint.engineUuid.data[0] ^= 1;
  ASSERT_ERROR(verifyEcTargetDiscoveryObservation(*key, changed, *request, now()), StatusCode::kAuthenticationFail);
  EcCreateTargetReq existing;
  existing.settings.chainId = chainId;
  existing.settings.targetId = targetId;
  existing.settings.onlyChunkEngine = true;
  existing.settings.allowExistingTarget = true;
  // Discovery reaches retained instances after heartbeat failure; creation
  // still requires a connected node. Neither operation needs a serving chain.
  ASSERT_ERROR(blockingWait(storageClient->createEcTarget(nodeId, existing)), StorageClientCode::kNotAvailable);
  auto connected = std::make_shared<flat::RoutingInfo>(*mgmtd->getRoutingInfo()->raw());
  connected->routingInfoVersion = flat::RoutingInfoVersion(2);
  connected->nodes.at(nodeId).status = flat::NodeStatus::HEARTBEAT_CONNECTED;
  mgmtd->setRoutingInfo(connected);
  ASSERT_OK(blockingWait(storageClient->createEcTarget(nodeId, existing)));
  auto disconnected = std::make_shared<flat::RoutingInfo>(*connected);
  disconnected->routingInfoVersion = flat::RoutingInfoVersion(3);
  disconnected->nodes.at(nodeId).status = flat::NodeStatus::HEARTBEAT_FAILED;
  mgmtd->setRoutingInfo(disconnected);
  auto repeated = blockingWait(storageClient->getEcTargetIdentityControlled(*another, key, control()));
  ASSERT_OK(repeated);
  EXPECT_EQ(repeated->claims.endpoint.engineUuid, observed->claims.endpoint.engineUuid);
  EXPECT_EQ(repeated->claims.endpoint.targetIncarnation, observed->claims.endpoint.targetIncarnation);
}
TEST_F(TestEcTargetDiscoveryService, ServerRejectsForgeryExpiryAndMissingTargetsWithoutRegistering) {
  auto request = signEcTargetDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  auto changed = *request;
  changed.claims.nonce.data[0] ^= 1;
  auto raw = blockingWait(components->storageOperator.getEcTargetIdentity(changed));
  ASSERT_OK(raw);
  ASSERT_ERROR(raw->result, StatusCode::kAuthenticationFail);
  auto intent = claims();
  intent.clusterAuthority = Uuid::random();
  auto wrongAuthority = signEcTargetDiscovery(*key, intent, now());
  ASSERT_OK(wrongAuthority);
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*wrongAuthority, key, control())),
               StatusCode::kAuthenticationFail);
  intent = claims();
  intent.nodeId = NodeId(999);
  auto wrongNode = signEcTargetDiscovery(*key, intent, now());
  ASSERT_OK(wrongNode);
  raw = blockingWait(components->storageOperator.getEcTargetIdentity(*wrongNode));
  ASSERT_OK(raw);
  ASSERT_ERROR(raw->result, StatusCode::kAuthenticationFail);
  intent = claims();
  intent.issuedAtSeconds = now() - 60;
  intent.expiresAtSeconds = now() - 30;
  auto expired = signEcTargetDiscovery(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(expired);
  raw = blockingWait(components->storageOperator.getEcTargetIdentity(*expired));
  ASSERT_OK(raw);
  ASSERT_ERROR(raw->result, StatusCode::kAuthenticationFail);
  intent = claims();
  intent.targetId = TargetId(999);
  auto missing = signEcTargetDiscovery(*key, intent, now());
  ASSERT_OK(missing);
  ASSERT_FALSE(scope->loadTarget(chainId.toUnderType(), 999));
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*missing, key, control())),
               StorageCode::kTargetStateInvalid);
  ASSERT_FALSE(scope->loadTarget(chainId.toUnderType(), 999));
  intent = claims();
  intent.chainId = ChainId(999);
  auto wrongChain = signEcTargetDiscovery(*key, intent, now());
  ASSERT_OK(wrongChain);
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*wrongChain, key, control())),
               StatusCode::kTokenMismatch);
}
TEST_F(TestEcTargetDiscoveryService, ControlledClientRejectsMissingKeyCancellationAndUnboundedDeadline) {
  auto request = signEcTargetDiscovery(*key, claims(), now());
  ASSERT_OK(request);
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*request, {}, control())),
               StatusCode::kAuthenticationFail);
  auto expired = control();
  expired.deadline = std::chrono::steady_clock::now();
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*request, key, expired)),
               StorageClientCode::kTimeout);
  auto tooLong = control();
  tooLong.deadline += std::chrono::minutes(2);
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*request, key, tooLong)),
               StatusCode::kInvalidArg);
  CancellationSource cancellation;
  cancellation.requestCancellation();
  auto stopped = control();
  stopped.cancellation = cancellation.getToken();
  ASSERT_ERROR(blockingWait(storageClient->getEcTargetIdentityControlled(*request, key, stopped)),
               StorageClientCode::kRequestCanceled);
}
}  // namespace
}  // namespace hf3fs::storage
