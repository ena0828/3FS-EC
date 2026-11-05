#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <linux/magic.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <utility>

#include "client/storage/StorageClient.h"
#include "common/kv/mem/MemKVEngine.h"
#include "common/net/Server.h"
#include "meta/components/NativeEcGcTransport.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::storage {
// Same existing test-access seam as TestEcStageService; no production hook.
class StorageEcStageAuthorizationTestAccess {
 public:
  static void clock(StorageOperator &op, std::function<uint64_t()> now) { op.ecAuthorizationNow_ = std::move(now); }
};
namespace {
using namespace meta::server;
using Codec = ec_gc_control_detail::Codec;
using folly::coro::blockingWait;
void smallGcThreads(net::ThreadPoolGroup::Config &config) {
  config.set_num_proc_threads(2);
  config.set_num_io_threads(1);
  config.set_num_bg_threads(1);
  config.set_num_connect_threads(1);
}
void smallGcClient(net::Client::Config &config) {
  smallGcThreads(config.thread_pool());
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
class TestEcGcRpc : public ::testing::Test {
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
    for (const auto &[name, byte] : {std::pair{"gc.key", 'G'}, std::pair{"data.key", 'D'}}) {
      std::ofstream output((keys.path() / name).string(), std::ios::binary | std::ios::trunc);
      const std::string bytes(32, byte);
      output.write(bytes.data(), bytes.size());
      output.close();
      ASSERT_TRUE(output.good());
      ASSERT_EQ(::chmod((keys.path() / name).c_str(), 0600), 0);
    }
    auto loaded = EcGcKey::loadFile(std::filesystem::path(path.string()), keyId, {});
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcGcKey>(std::move(*loaded));
    config.set_speed_up_quit(false);
    config.targets().set_target_paths({directory.path()});
    config.targets().set_ec_only(true);
    config.targets().set_ec_staging_v2(true);
    config.targets().set_ec_exact_gc(true);
    config.targets().set_allow_disk_without_uuid(true);
    config.targets().set_collect_all_fds(false);
    config.storage().set_enable_ec_fragments(true);
    config.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    config.storage().set_ec_capability_key_file(keys.path() / "data.key");
    config.storage().set_enable_ec_scope_control(false);
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
    smallGcClient(config.client());
    smallGcClient(config.forward_client());
    components = std::make_unique<Components>(config);
    components->appInfo.nodeId = nodeId;
    auto heldClock = clock;
    StorageEcStageAuthorizationTestAccess::clock(components->storageOperator, [heldClock] {
      if (heldClock->pause.exchange(false)) {
        heldClock->entered.store(true);
        heldClock->entered.notify_all();
        while (!heldClock->released.load()) heldClock->released.wait(false);
      }
      return now();
    });
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
    target = (*found)->storageTarget;
    scope = state->first;
    identity = state->second;

    smallGcThreads(serverConfig.thread_pool());
    smallGcThreads(serverConfig.independent_thread_pool());
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
    smallGcClient(clientConfig.net_client());
    smallGcClient(clientConfig.net_client_for_updates());
    storageClient = client::StorageClient::create(ClientId::random(), clientConfig, *mgmtd->asCommon());
    ASSERT_NE(storageClient, nullptr);
    ASSERT_NO_FATAL_FAILURE(prepareClaim());
  }
  void TearDown() override {
    coordinator.reset();
    transport.reset();
    if (storageClient) storageClient->stop();
    if (server) server->stopAndJoin();
    if (components && initialized) {
      auto stopped = components->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped);
    }
    storageClient.reset();
    server.reset();
    scope.reset();
    target.reset();
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
  static EcSha256 hash(std::string_view bytes) {
    EcSha256 out{};
    unsigned int length = 0;
    if (!EVP_Digest(bytes.data(), bytes.size(), out.data(), &length, EVP_sha256(), nullptr) || length != out.size())
      throw std::runtime_error("fixture SHA256 failed");
    return out;
  }
  static std::string allocationKey(kv::KeyPrefix prefix, const EcFragmentIdentity &identity) {
    auto chunk = identity.chunkId();
    if (!chunk) throw std::runtime_error("fixture identity invalid");
    return std::string(kv::toStr(prefix)) + chunk->data();
  }
  void prepareClaim() {
    metadata = std::make_shared<kv::MemKVEngine>();
    const meta::EcObjectRef object{meta::InodeId(1234), Uuid::random()};
    const meta::EcOwner owner{flat::Uid(101), Uuid::random()};
    stage.identity.object = object.incarnation;
    stage.identity.generation = 1;
    stage.identity.allocation = Uuid::random();
    stage.operationId = Uuid::random();
    stage.writerNamespace = owner.client;
    stage.vChainId = {chainId, ChainVer(1)};
    stage.targetId = targetId;
    data.resize(kEcIntegrityBlockBytes + 17);
    for (size_t i = 0; i != data.size(); ++i) data[i] = static_cast<char>((i * 19 + 31) & 255);
    auto integrity = computeEcIntegrity(stage.identity, data);
    ASSERT_OK(integrity);
    stage.integrity = *integrity;
    claim.claimId = Uuid::random();
    claim.enrollment.object = object;
    claim.enrollment.creator = owner;
    claim.enrollment.createRequest = Uuid::random();
    claim.allocation.object = object;
    claim.allocation.fragment.identity = stage.identity;
    claim.allocation.fragment.operation = stage.operationId;
    claim.allocation.fragment.placement = {chainId, targetId, nodeId};
    claim.allocation.fragment.integrity = stage.integrity;
    claim.allocation.writer = owner;
    claim.allocation.engineUuid = fromBytes(identity.engine);
    claim.allocation.targetIncarnation = fromBytes(identity.incarnation);
    claim.registeredScopes = claim.releasedScopes = 2;
    claim.releaseHistory = hash("synthetic-qualified-Meta-G0-history");
    claim.originDrainEvidence = hash("synthetic-qualified-Meta-G0-origin-T2");
    claim.eligibilityDigest = hash(std::string("3FSECGC-CLAIM-v1") + std::string(serde::serialize(claim)));
    auto txn = metadata->createReadWriteTransaction();
    ASSERT_OK(blockingWait(meta::server::EcV2BindingCatalog::createTrackedV2Object(*txn,
                                                                                   object,
                                                                                   data.size(),
                                                                                   true,
                                                                                   owner,
                                                                                   claim.enrollment.createRequest)));
    // Qualification is a synthetic metadata fixture. Actual G0 eligibility,
    // all-scope drain and private FDB are tested separately; do not claim them
    // from this RPC test. G1/G2 use the real catalog and a committed DB record.
    meta::EcGcAllocationRecord allocation;
    allocation.object = object;
    allocation.allocation = {stage.identity, stage.operationId, claim.allocation.endpoint(), owner};
    allocation.registered = allocation.released = 2;
    allocation.releaseHistory = claim.releaseHistory;
    allocation.claimId = claim.claimId;
    ASSERT_OK(blockingWait(
        txn->set(allocationKey(kv::KeyPrefix::EcV2Allocation, stage.identity), serde::serialize(claim.allocation))));
    ASSERT_OK(blockingWait(
        txn->set(allocationKey(kv::KeyPrefix::EcGcAllocation, stage.identity), serde::serialize(allocation))));
    ASSERT_OK(blockingWait(txn->set(allocationKey(kv::KeyPrefix::EcGcClaim, stage.identity), serde::serialize(claim))));
    ASSERT_OK(blockingWait(txn->commit()));
    auto native = meta::server::NativeEcGcTransport::create(storageClient, key);
    ASSERT_OK(native);
    transport = *native;
    meta::server::EcGcCoordinator::Config gc;
    gc.authority = authority;
    gc.targets = {{claim.allocation.endpoint().controlEndpoint(), 2, 3, 1, true}};
    auto built = meta::server::EcGcCoordinator::create(gc, metadata, key, transport);
    ASSERT_OK(built);
    coordinator = std::move(*built);
  }
  EcStageRequest op(EcStageOperation kind) const {
    auto result = stage;
    result.operation = kind;
    return result;
  }
  void seal() {
    ASSERT_OK(target->executeEcStage(op(EcStageOperation::Begin)));
    for (uint32_t i = 0; i != stage.integrity.blockCount; ++i) {
      auto append = op(EcStageOperation::Append);
      append.blockIndex = i;
      append.payload = data.substr(size_t(i) * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
      ASSERT_OK(target->executeEcStage(append));
    }
    ASSERT_OK(target->executeEcStage(op(EcStageOperation::Seal)));
  }
  EcGcRequest sign(EcGcRequestClaims claims) {
    const auto body = Codec::encode(claims);
    const std::string raw(32, 'G');
    EcSha256 mac{};
    unsigned int length = 0;
    if (!HMAC(EVP_sha256(), raw.data(), raw.size(), body.data(), body.size(), mac.data(), &length) ||
        length != mac.size())
      throw std::runtime_error("fixture HMAC failed");
    auto decoded = Codec::decodeRequest({reinterpret_cast<const char *>(body.data()), body.size()},
                                        {reinterpret_cast<const char *>(mac.data()), mac.size()});
    if (!decoded) throw std::runtime_error("fixture request failed");
    return std::move(*decoded);
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
  const Uuid keyId = Uuid::from(211, 212);
  folly::test::TemporaryDirectory directory, keys, traces;
  Components::Config config;
  CPUExecutorGroup loader{1, "EcDiscoveryRpc"};
  std::unique_ptr<Components> components;
  bool initialized = false;
  std::shared_ptr<StorageTarget> target;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity identity{};
  std::shared_ptr<const EcGcKey> key;
  net::Server::Config serverConfig;
  std::unique_ptr<net::Server> server;
  client::StorageClient::Config clientConfig;
  struct ClockBarrier {
    std::atomic<bool> pause{false}, entered{false}, released{false};
    void release() {
      released.store(true);
      released.notify_all();
    }
  };
  std::shared_ptr<ClockBarrier> clock = std::make_shared<ClockBarrier>();
  std::shared_ptr<kv::MemKVEngine> metadata;
  meta::EcGcClaim claim;
  EcStageRequest stage;
  std::string data;
  std::shared_ptr<meta::server::NativeEcGcTransport> transport;
  std::unique_ptr<meta::server::EcGcCoordinator> coordinator;
  std::unique_ptr<hf3fs::test::FakeMgmtdClient> mgmtd;
  std::shared_ptr<client::StorageClient> storageClient;
};

TEST_F(TestEcGcRpc, NativeMetaTransportReachesActualGcLedgerAndCommitsCompletion) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto object = claim.enrollment.object;
  const auto before = target->usedSize();
  ASSERT_GT(before, 0);
  ASSERT_ERROR(blockingWait(coordinator->query(object, stage.identity, claim.claimId, control())),
               StorageCode::kChunkMetadataNotFound);
  EXPECT_EQ(target->usedSize(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  auto absent = blockingWait(coordinator->getCompletion(object, stage.identity, claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  auto completed = blockingWait(coordinator->collect(object, stage.identity, claim.claimId, control()));
  ASSERT_OK(completed);
  EXPECT_EQ(target->usedSize(), 0);
  ASSERT_OK(Codec::verifyAck(*key, completed->ack, completed->request));
  auto persisted = blockingWait(coordinator->getCompletion(object, stage.identity, claim.claimId));
  ASSERT_OK(persisted);
  ASSERT_TRUE(*persisted);
  EXPECT_EQ(Codec::frame((**persisted).ack), Codec::frame(completed->ack));
  // Force an actual second network exchange, rather than coordinator's local
  // completion fast path. The old ledger is reconfirmed by Rust Query/WAL.
  auto renewed = completed->request.claims;
  renewed.action = EcGcAction::Query;
  renewed.nonce = Uuid::random();
  renewed.issuedAtSeconds = now();
  renewed.expiresAtSeconds = renewed.issuedAtSeconds + 60;
  auto request = sign(renewed);
  auto observed = blockingWait(storageClient->exchangeEcGcControlled(request, key, control()));
  ASSERT_OK(observed);
  EXPECT_EQ(observed->claims.ledgerSha256, completed->ack.claims.ledgerSha256);
  EXPECT_EQ(observed->claims.terminalRevision, completed->ack.claims.terminalRevision);
  auto txn = metadata->createReadWriteTransaction();
  auto replay = blockingWait(
      EcGcCompletionCatalog::record(*txn, object, stage.identity, claim.claimId, request, *observed, *key, authority));
  ASSERT_OK(replay);
  ASSERT_OK(blockingWait(txn->commit()));
  EXPECT_EQ(Codec::frame(replay->ack), Codec::frame(completed->ack));
  EXPECT_EQ(target->usedSize(), 0);
}

TEST_F(TestEcGcRpc, AuthenticatedWrongInstanceCannotDeleteActualTarget) {
  ASSERT_NO_FATAL_FAILURE(seal());
  auto projected = EcGcCompletionCatalog::project(claim);
  ASSERT_OK(projected);
  EcGcRequestClaims claims;
  claims.keyId = keyId;
  claims.authority = authority;
  claims.nonce = Uuid::random();
  claims.issuedAtSeconds = now();
  claims.expiresAtSeconds = claims.issuedAtSeconds + 60;
  claims.certificate = *projected;
  claims.certificate.endpoint.targetIncarnation = Uuid::random();
  const auto before = target->usedSize();
  ASSERT_ERROR(blockingWait(storageClient->exchangeEcGcControlled(sign(claims), key, control())),
               StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(target->usedSize(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  auto absent = blockingWait(coordinator->getCompletion(claim.enrollment.object, stage.identity, claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
}

class TestEcGcRpcDisabled : public TestEcGcRpc {
 protected:
  bool enableGc() const override { return false; }
};
TEST_F(TestEcGcRpcDisabled, DefaultOffServerCannotFallBackToOrdinaryDelete) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = target->usedSize();
  ASSERT_ERROR(blockingWait(coordinator->query(claim.enrollment.object, stage.identity, claim.claimId, control())),
               StatusCode::kAuthenticationFail);
  EXPECT_EQ(target->usedSize(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  // Collect has actually crossed RPC28. The client conservatively preserves
  // its dispatched outcome as unknown, while the disabled server must leave
  // both the physical data and the permanent completion absent/unmodified.
  ASSERT_ERROR(blockingWait(coordinator->collect(claim.enrollment.object, stage.identity, claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(target->usedSize(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  auto absent = blockingWait(coordinator->getCompletion(claim.enrollment.object, stage.identity, claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
}

TEST_F(TestEcGcRpc, NativeWaiterTimeoutRetainsUnknownWhileActualServerCanFinishLater) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto object = claim.enrollment.object;
  clock->pause.store(true);
  SCOPE_EXIT { clock->release(); };
  auto shortControl = control();
  shortControl.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
  auto lost = blockingWait(coordinator->collect(object, stage.identity, claim.claimId, shortControl));
  ASSERT_ERROR(lost, StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(clock->entered.load()) << "timeout must follow real server admission, not local rejection";
  auto pending = blockingWait(coordinator->getCompletion(object, stage.identity, claim.claimId));
  ASSERT_OK(pending);
  EXPECT_FALSE(*pending);
  clock->release();
  // Separate server/client thread pools: the synchronous test clock never
  // blocks its client's timer. Join the actual handler before inspecting disk.
  server->stopAndJoin();
  server.reset();
  EXPECT_EQ(target->usedSize(), 0);
  auto stillUnconfirmed = blockingWait(coordinator->getCompletion(object, stage.identity, claim.claimId));
  ASSERT_OK(stillUnconfirmed);
  EXPECT_FALSE(*stillUnconfirmed);
}

TEST(TestEcGcConfiguration, SameLoadedDataFileAndHardLinkCannotBecomeGRole) {
  folly::test::TemporaryDirectory files;
  const auto data = files.path() / "data.key";
  const auto alias = files.path() / "alias.key";
  std::ofstream output(data.string(), std::ios::binary);
  output << std::string(32, 'A');
  output.close();
  ASSERT_TRUE(output.good());
  ASSERT_EQ(::chmod(data.c_str(), 0600), 0);
  std::filesystem::create_hard_link(std::filesystem::path(data.string()), std::filesystem::path(alias.string()));
  Components::Config config;
  config.targets().set_ec_only(true);
  config.targets().set_ec_staging_v2(true);
  config.targets().set_ec_exact_gc(true);
  config.storage().set_enable_ec_fragments(true);
  config.storage().set_ec_capability_key_file(data);
  config.storage().set_enable_ec_gc(true);
  config.storage().set_ec_gc_key_id(fmt::to_string(Uuid::random()));
  config.storage().set_ec_gc_authority(fmt::to_string(Uuid::random()));
  config.storage().event_trace_log().set_enabled(false);
  for (const auto &path : {data, alias}) {
    config.storage().set_ec_gc_key_file(path);
    Components components(config);
    components.appInfo.nodeId = NodeId(12);
    // Fails at G loading, before UpdateWorker starts or any target is opened.
    ASSERT_ERROR(components.storageOperator.init(1), StatusCode::kInvalidConfig);
  }
}

TEST_F(TestEcGcRpc, ReadOnlyCollectCannotDeleteAndQueryRemainsUsable) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto object = claim.enrollment.object;
  const auto before = target->usedSize();
  config.storage().set_read_only(true);
  ASSERT_ERROR(blockingWait(coordinator->collect(object, stage.identity, claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(target->usedSize(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  auto absent = blockingWait(coordinator->getCompletion(object, stage.identity, claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  ASSERT_ERROR(blockingWait(coordinator->query(object, stage.identity, claim.claimId, control())),
               StorageCode::kChunkMetadataNotFound);
  config.storage().set_read_only(false);
  auto collected = blockingWait(coordinator->collect(object, stage.identity, claim.claimId, control()));
  ASSERT_OK(collected);
  config.storage().set_read_only(true);
  // Force an actual Query RPC; the coordinator's cached completion would not
  // exercise the server's read-only branch or its ledger/WAL confirmation.
  auto renewal = collected->request.claims;
  renewal.action = EcGcAction::Query;
  renewal.nonce = Uuid::random();
  renewal.issuedAtSeconds = now();
  renewal.expiresAtSeconds = renewal.issuedAtSeconds + 60;
  auto queried = blockingWait(storageClient->exchangeEcGcControlled(sign(renewal), key, control()));
  ASSERT_OK(queried);
  EXPECT_EQ(queried->claims.ledgerSha256, collected->ack.claims.ledgerSha256);
  EXPECT_EQ(target->usedSize(), 0);
}

}  // namespace
}  // namespace hf3fs::storage
