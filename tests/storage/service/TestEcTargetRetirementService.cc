#include <algorithm>
#include <chrono>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <linux/magic.h>
#include <mutex>
#include <optional>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "client/storage/StorageClient.h"
#include "client/storage/StorageMessenger.h"
#include "common/net/Server.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::storage {
namespace {
using folly::coro::blockingWait;
void smallControlThreads(net::ThreadPoolGroup::Config &config) {
  config.set_num_proc_threads(2);
  config.set_num_io_threads(1);
  config.set_num_bg_threads(1);
  config.set_num_connect_threads(1);
}
void smallControlClient(net::Client::Config &config) {
  smallControlThreads(config.thread_pool());
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
struct RetirementReplyDrop {
  struct Snapshot {
    size_t prepareCalls = 0;
    size_t durableRepliesDropped = 0;
    std::optional<EcTargetRetirementObservation> dropped;
  };
  void arm() {
    std::lock_guard lock(mutex);
    armed = true;
    state = {};
  }
  Snapshot snapshot() const {
    std::lock_guard lock(mutex);
    return state;
  }
  mutable std::mutex mutex;
  bool armed = false;
  Snapshot state;
};
// Rebind only the test service reflection, exactly as the existing native seal
// reply-loss fixture. The real handler completes before the TCP invalidation.
class RetirementReplyDropService : public StorageService {
 public:
  RetirementReplyDropService(StorageOperator &storageOperator, RetirementReplyDrop &fault)
      : StorageService(storageOperator), fault_(fault) {}
  CoTryTask<EcTargetRetirementRsp> prepareEcTargetRetirement(serde::CallContext &ctx,
                                                             const EcTargetRetirementRequest &request) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.prepareCalls;
    }
    auto response = co_await StorageService::prepareEcTargetRetirement(ctx, request);
    bool drop = false;
    if (response && response->result && response->result->claims.durable) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.armed) {
        fault_.armed = false;
        fault_.state.dropped = *response->result;
        ++fault_.state.durableRepliesDropped;
        drop = true;
      }
    }
    // Prevent the actual successful response from being queued on this socket.
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }
 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = RetirementReplyDropService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<StorageSerde<U>>;
 private:
  RetirementReplyDrop &fault_;
};
class TestEcTargetRetirementService : public ::testing::Test {
 protected:
  virtual bool retirementEnabled() const { return true; }
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
    key = std::move(*loaded);
    config.set_speed_up_quit(false);
    config.targets().set_target_paths({directory.path()});
    config.targets().set_ec_only(true);
    config.targets().set_ec_staging_v2(true);
    config.targets().set_allow_disk_without_uuid(true);
    config.targets().set_collect_all_fds(false);
    config.storage().set_enable_ec_fragments(true);
    config.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    config.storage().set_enable_ec_scope_control(true);
    config.storage().set_enable_ec_target_retirement(retirementEnabled());
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
    smallControlClient(config.client());
    smallControlClient(config.forward_client());
    components = std::make_unique<Components>(config);
    components->appInfo.nodeId = nodeId;
    ASSERT_OK(components->storageTargets.load(loader));
    ASSERT_OK(components->storageOperator.init(1));
    initialized = true;
    CreateTargetReq create;
    create.chainId = chainId;
    create.targetId = targetId;
    create.onlyChunkEngine = true;
    ASSERT_OK(components->storageTargets.create(create, true));
    auto found = components->targetMap.getByTargetId(targetId);
    ASSERT_OK(found);
    auto state = (*found)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    scope = state->first;
    identity = state->second;

    smallControlThreads(serverConfig.thread_pool());
    smallControlThreads(serverConfig.independent_thread_pool());
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
    ASSERT_OK(server->addSerdeService(std::make_unique<RetirementReplyDropService>(components->storageOperator, replyDrop), true));
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
    address = *endpoint;
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
    smallControlClient(clientConfig.net_client());
    smallControlClient(clientConfig.net_client_for_updates());
    storageClient = client::StorageClient::create(ClientId::random(), clientConfig, *mgmtd->asCommon());
    ASSERT_NE(storageClient, nullptr);
    messenger = std::make_unique<client::StorageMessenger>(clientConfig.net_client());
    ASSERT_OK(messenger->start("RetirementRawTest"));
  }
  void TearDown() override {
    if (messenger) messenger->stopAndJoin();
    if (storageClient) storageClient->stop();
    if (server) server->stopAndJoin();
    if (components && initialized) {
      auto stopped = components->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped);
    }
    messenger.reset();
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
  EcTargetRetirementClaims claims() const {
    EcTargetRetirementClaims value;
    value.clusterAuthority = authority;
    value.nodeId = nodeId;
    value.chainId = chainId;
    value.targetId = targetId;
    value.engineUuid = fromBytes(identity.engine);
    value.targetIncarnation = fromBytes(identity.incarnation);
    value.retirementId = Uuid::from(107, 108);
    value.nonce = Uuid::random();
    value.issuedAtSeconds =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    value.expiresAtSeconds = value.issuedAtSeconds + 120;
    return value;
  }
  EcScopeBinding binding() const {
    EcScopeBinding result{};
    result.target = identity;
    result.kind = 1;
    result.object.fill(101);
    result.scope.fill(103);
    result.owner_uid = 1000;
    result.client_namespace.fill(105);
    return result;
  }
  client::EcRequestControl requestControl() const {
    client::EcRequestControl result;
    result.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    result.transport = client::EcRequestControl::TransportPolicy::TcpOnly;
    return result;
  }
  Result<EcTargetRetirementRsp> rawPrepare(const EcTargetRetirementRequest &request) {
    net::UserRequestOptions options;
    options.timeout = 10_s;
    options.sendRetryTimes = 0;
    return blockingWait(messenger->prepareEcTargetRetirement(address, request, &options));
  }
  const NodeId nodeId{61};
  const ChainId chainId{81};
  const TargetId targetId{71};
  const Uuid authority = Uuid::from(201, 202);
  folly::test::TemporaryDirectory directory, keys, traces;
  Components::Config config;
  CPUExecutorGroup loader{1, "EcControlRpc"};
  std::unique_ptr<Components> components;
  bool initialized = false;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity identity{};
  std::shared_ptr<const EcScopeControlKey> key;
  net::Address address;
  std::unique_ptr<client::StorageMessenger> messenger;
  RetirementReplyDrop replyDrop;
  net::Server::Config serverConfig;
  std::unique_ptr<net::Server> server;
  client::StorageClient::Config clientConfig;
  std::unique_ptr<hf3fs::test::FakeMgmtdClient> mgmtd;
  std::shared_ptr<client::StorageClient> storageClient;
};

TEST_F(TestEcTargetRetirementService, RealClientPrepareQueryAndReplayBindExactObservation) {
  auto intent = claims();
  auto scopeBinding = binding();
  auto request = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(request);
  ASSERT_OK(scope->prepare(scopeBinding));
  {
    auto ticket = scope->tryAdmit(scopeBinding);
    ASSERT_OK(ticket);
    replyDrop.arm();
    ASSERT_ERROR(blockingWait(storageClient->prepareEcTargetRetirement(*request, key, requestControl())),
                 StorageCode::kEcSealOutcomeUnknown);
    const auto dropped = replyDrop.snapshot();
    ASSERT_EQ(dropped.durableRepliesDropped, 1u);
    ASSERT_EQ(dropped.prepareCalls, 1u);  // No automatic resend after dispatch.
    ASSERT_TRUE(dropped.dropped);
    ASSERT_OK(verifyEcTargetRetirementObservation(*key, *dropped.dropped, *request));
    EXPECT_EQ(dropped.dropped->claims.state, EcTargetRetirementState::Pending);
    EXPECT_TRUE(dropped.dropped->claims.durable);
    EXPECT_EQ(dropped.dropped->claims.inflight, 1);
    auto pendingIntent = intent;
    pendingIntent.action = EcTargetRetirementAction::Query;
    pendingIntent.nonce = Uuid::random();
    auto pendingQuery = signEcTargetRetirement(*key, pendingIntent, pendingIntent.issuedAtSeconds);
    ASSERT_OK(pendingQuery);
    auto pending = blockingWait(storageClient->queryEcTargetRetirement(*pendingQuery, key, requestControl()));
    ASSERT_OK(pending);
    ASSERT_OK(verifyEcTargetRetirementObservation(*key, *pending, *pendingQuery));
    EXPECT_EQ(pending->claims.state, EcTargetRetirementState::Pending);
    EXPECT_EQ(pending->claims.inflight, 1);
    EXPECT_EQ(pending->claims.retirementDigest, dropped.dropped->claims.retirementDigest);
    EXPECT_EQ(replyDrop.snapshot().prepareCalls, 1u);
    ASSERT_ERROR(ticket->checkExecution(), StatusCode::kTokenStale);
    ASSERT_ERROR(scope->tryAdmit(scopeBinding), StatusCode::kTokenStale);
  }
  intent.action = EcTargetRetirementAction::Query;
  intent.nonce = Uuid::random();
  auto query = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(query);
  auto result = blockingWait(storageClient->queryEcTargetRetirement(*query, key, requestControl()));
  ASSERT_OK(result);
  ASSERT_OK(verifyEcTargetRetirementObservation(*key, *result, *query));
  EXPECT_EQ(result->claims.state, EcTargetRetirementState::LocalDataDrained);
  EXPECT_TRUE(result->claims.durable);
  EXPECT_EQ(result->claims.inflight, 0);
  EXPECT_FALSE(verifyEcTargetRetirementObservation(*key, *result, *request));
  // Replay the original Prepare without changing its target or retirement ID.
  auto replay = blockingWait(storageClient->prepareEcTargetRetirement(*request, key, requestControl()));
  ASSERT_OK(replay);
  EXPECT_EQ(replay->claims.retirementDigest, result->claims.retirementDigest);
  EXPECT_EQ(replyDrop.snapshot().durableRepliesDropped, 1u);
  intent.action = EcTargetRetirementAction::Prepare;
  intent.retirementId.data[0] ^= 1;
  auto changed = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(changed);
  ASSERT_ERROR(blockingWait(storageClient->prepareEcTargetRetirement(*changed, key, requestControl())),
               StatusCode::kTokenMismatch);
  ASSERT_ERROR(scope->prepare(scopeBinding), StatusCode::kTokenStale);
}

TEST_F(TestEcTargetRetirementService, ChangedAuthorityIdentityAndTamperedRequestHaveNoEffect) {
  const auto initial = claims();
  for (unsigned variant = 0; variant != 5; ++variant) {
    auto intent = initial;
    if (variant == 0) intent.clusterAuthority.data[0] ^= 1;
    if (variant == 1) intent.targetIncarnation.data[0] ^= 1;
    if (variant == 2) intent.action = EcTargetRetirementAction::Query;
    if (variant == 3) {
      intent.issuedAtSeconds -= 300;
      intent.expiresAtSeconds -= 300;
    }
    auto request = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
    ASSERT_OK(request);
    if (variant == 4) request->claims.nonce.data[0] ^= 1;
    // Bypass the local client validator to exercise the real service MAC,
    // authority/action/time and loaded-identity rejection over TCP.
    auto response = rawPrepare(*request);
    ASSERT_OK(response);
    EXPECT_FALSE(response->result);
    ASSERT_OK(scope->prepare(binding()));
    ASSERT_OK(scope->tryAdmit(binding()));
  }
  auto intent = initial;
  intent.action = EcTargetRetirementAction::Query;
  auto query = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(query);
  ASSERT_FALSE(blockingWait(storageClient->queryEcTargetRetirement(*query, key, requestControl())));
}

class TestEcTargetRetirementDisabledService : public TestEcTargetRetirementService {
 protected:
  bool retirementEnabled() const override { return false; }
};
TEST_F(TestEcTargetRetirementDisabledService, DisabledRequestsHaveNoPersistentEffects) {
  auto intent = claims();
  auto request = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(request);
  auto response = rawPrepare(*request);
  ASSERT_OK(response);
  ASSERT_ERROR(response->result, StatusCode::kAuthenticationFail);
  intent.action = EcTargetRetirementAction::Query;
  auto query = signEcTargetRetirement(*key, intent, intent.issuedAtSeconds);
  ASSERT_OK(query);
  ASSERT_ERROR(blockingWait(storageClient->queryEcTargetRetirement(*query, key, requestControl())),
               StatusCode::kAuthenticationFail);
  ASSERT_OK(scope->prepare(binding()));
  ASSERT_OK(scope->tryAdmit(binding()));
  EcTargetRetirement raw{};
  raw.target = identity;
  std::copy(std::begin(intent.retirementId.data), std::end(intent.retirementId.data), raw.id.begin());
  ASSERT_ERROR(scope->queryTargetRetirement(raw), StorageClientCode::kResourceBusy);
}
}  // namespace
}  // namespace hf3fs::storage
