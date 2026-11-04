#include <algorithm>
#include <atomic>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
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

// A private, local-only clock seam makes admission/worker/completion expiry
// tests deterministic without sleeping or introducing a configurable bypass.
class StorageEcAuthorizationTestAccess {
 public:
  static void clock(StorageOperator &op, std::function<uint64_t()> now) { op.ecAuthorizationNow_ = std::move(now); }
};

namespace {

using folly::coro::blockingWait;

void smallThreadPool(net::ThreadPoolGroup::Config &config) {
  config.set_num_proc_threads(2);
  config.set_num_io_threads(1);
  config.set_num_bg_threads(1);
  config.set_num_connect_threads(1);
}

void smallClient(net::Client::Config &config) {
  smallThreadPool(config.thread_pool());
  config.processor().set_max_processing_requests_num(16);
  config.processor().set_max_coroutines_num(16);
  config.processor().set_response_compression_level(0);
  config.set_default_timeout(10_s);
}

EcReadReq readFor(const EcCreateReq &create) {
  EcReadReq read;
  read.identity = create.identity;
  read.vChainId = create.vChainId;
  read.targetId = create.targetId;
  read.operationId = create.operationId;
  read.expectedLength = static_cast<uint32_t>(create.payload.data.size());
  read.checksum = create.checksum;
  read.tag = create.tag;
  return read;
}

EcReconcileReq reconcileFor(const EcCreateReq &create) {
  EcReconcileReq request;
  request.identity = create.identity;
  request.vChainId = create.vChainId;
  request.targetId = create.targetId;
  request.operationId = create.operationId;
  request.expectedLength = static_cast<uint32_t>(create.payload.data.size());
  request.checksum = create.checksum;
  request.tag = create.tag;
  return request;
}

struct ReplyDropState {
  struct Snapshot {
    size_t createCalls = 0;
    std::optional<EcFragmentReceipt> droppedReceipt;
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

// Every handler still executes the real StorageService. Rebind the serde
// reflection to this derived type so only this post-success fault intercepts
// createEcFragment; no synthetic storage result is supplied to the client.
class ReplyDropStorageService : public StorageService {
 public:
  ReplyDropStorageService(StorageOperator &storageOperator, ReplyDropState &fault)
      : StorageService(storageOperator),
        fault_(fault) {}

  CoTryTask<EcCreateRsp> createEcFragment(serde::CallContext &ctx, const EcCreateReq &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.createCalls;
    }
    auto response = co_await StorageService::createEcFragment(ctx, req);
    bool drop = false;
    if (response && response->result) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.armed) {
        fault_.armed = false;
        fault_.state.droppedReceipt = *response->result;
        drop = true;
      }
    }
    // invalidate() is thread-safe and marks the connection invalid before
    // CallContext::makeResponse can enqueue the otherwise successful reply.
    if (drop) ctx.transport()->invalidate(false);
    co_return response;
  }

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = ReplyDropStorageService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<StorageSerde<U>>;

 private:
  ReplyDropState &fault_;
};

class TestEcService : public ::testing::Test {
 protected:
  virtual void configureEcAuthorization() { config_.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(true); }

  void SetUp() override {
    // The Rust engine uses direct I/O. Keep its real files on local ext4;
    // TMPDIR may select the test location, but a DrvFS path is not equivalent.
    struct statfs fs {};
    ASSERT_EQ(::statfs(directory_.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, EXT4_SUPER_MAGIC) << "Set TMPDIR to local ext4 for the native EC RPC test";
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_cur, 8192u) << "One real Engine requires more than 5,632 chunk-file descriptors";

    config_.targets().set_target_paths({directory_.path()});
    config_.targets().set_ec_only(true);
    config_.targets().set_allow_disk_without_uuid(true);
    config_.targets().set_collect_all_fds(false);
    config_.storage().set_enable_ec_fragments(true);
    configureEcAuthorization();
    config_.storage().set_max_concurrent_ec_requests(2);
    config_.storage().write_worker().set_num_threads(2);
    config_.storage().write_worker().set_bg_num_threads(1);
    config_.storage().write_worker().set_queue_size(8);
    config_.storage().event_trace_log().set_enabled(false);
    config_.storage().event_trace_log().set_trace_file_dir(traces_.path());
    config_.aio_read_worker().set_num_threads(1);
    config_.aio_read_worker().set_queue_size(8);
    config_.sync_worker().set_num_threads(2);
    for (auto *pool : {&config_.coroutines_pool_read(),
                       &config_.coroutines_pool_update(),
                       &config_.coroutines_pool_sync(),
                       &config_.coroutines_pool_default()}) {
      pool->set_threads_num(1);
      pool->set_coroutines_num(2);
      pool->set_queue_size(8);
    }
    smallClient(config_.forward_client());
    smallClient(config_.client());
    components_ = std::make_unique<Components>(config_);
    components_->appInfo.nodeId = nodeId_;
    // Deliberately do not call Components::start: no allocator workers,
    // RDMA buffers, AIO readers, resync loops or fabricated data backend.
    ASSERT_OK(components_->storageTargets.load(loader_));
    ASSERT_OK(components_->storageOperator.init(1));
    operatorInitialized_ = true;

    smallThreadPool(serverConfig_.thread_pool());
    smallThreadPool(serverConfig_.independent_thread_pool());
    serverConfig_.set_groups_length(2);
    for (size_t index = 0; index != 2; ++index) {
      auto &group = serverConfig_.groups(index);
      group.set_network_type(net::Address::TCP);
      // An earlier Core endpoint must never receive an EC storage request.
      // Only the second group registers the real StorageService.
      group.set_services({index == 0 ? "Core" : "StorageSerde"});
      group.listener().set_listen_port(0);
      group.listener().set_filter_list({"lo"});
      group.listener().set_custom_tcp_nic_prefix("lo");
      group.processor().set_max_processing_requests_num(16);
      group.processor().set_max_coroutines_num(16);
      group.processor().set_response_compression_level(0);
    }
    server_ = std::make_unique<net::Server>(serverConfig_);
    ASSERT_OK(
        server_->addSerdeService(std::make_unique<ReplyDropStorageService>(components_->storageOperator, replyDrop_),
                                 true));
    ASSERT_OK(server_->setup());
    flat::AppInfo app;
    app.nodeId = nodeId_;
    ASSERT_OK(server_->start(app));
    auto groups = server_->getServiceGroupInfos();
    ASSERT_EQ(groups.size(), 2);
    ASSERT_EQ(groups.front().services.size(), 1);
    ASSERT_EQ(groups.back().services.size(), 1);
    ASSERT_TRUE(groups.front().services.contains("Core"));
    ASSERT_TRUE(groups.back().services.contains("StorageSerde"));
    for (auto &group : groups) {
      ASSERT_FALSE(group.endpoints.empty());
      for (const auto &endpoint : group.endpoints) {
        ASSERT_EQ(endpoint.type, net::Address::TCP);
        ASSERT_NE(endpoint.port, 0);
      }
      // A NIC can own several IPv4 addresses (including WSL's extra lo
      // address). Advertise one actual loopback listener per service group
      // so neither interface enumeration nor address fallback hides a wrong
      // choice of Core instead of StorageSerde.
      const auto loopback = std::find_if(group.endpoints.begin(), group.endpoints.end(), [](const auto &endpoint) {
        return endpoint.ipStr() == "127.0.0.1";
      });
      ASSERT_NE(loopback, group.endpoints.end()) << "the TCP fixture requires a 127.0.0.1 listener";
      const auto endpoint = *loopback;
      group.endpoints.assign(1, endpoint);
    }
    address_ = groups.back().endpoints.front();
    ASSERT_EQ(address_.type, net::Address::TCP);
    ASSERT_NE(address_.port, 0);
    ASSERT_NE(address_.port, groups.front().endpoints.front().port);

    routing_ = std::make_shared<flat::RoutingInfo>();
    routing_->routingInfoVersion = flat::RoutingInfoVersion{1};
    flat::NodeInfo node;
    node.app.nodeId = nodeId_;
    node.app.serviceGroups = std::move(groups);
    node.type = flat::NodeType::STORAGE;
    node.status = flat::NodeStatus::HEARTBEAT_CONNECTED;
    routing_->nodes.emplace(nodeId_, std::move(node));
    mgmtd_ = std::make_unique<hf3fs::test::FakeMgmtdClient>(routing_);
    clientConfig_.set_implementation_type(client::StorageClient::ImplementationType::RPC);
    clientConfig_.retry().set_max_wait_time(10_s);
    clientConfig_.traffic_control().read().set_max_concurrent_requests(2);
    clientConfig_.traffic_control().read().set_max_concurrent_requests_per_server(2);
    clientConfig_.traffic_control().write().set_max_concurrent_requests(2);
    clientConfig_.traffic_control().write().set_max_concurrent_requests_per_server(2);
    smallClient(clientConfig_.net_client());
    smallClient(clientConfig_.net_client_for_updates());
    client_ = client::StorageClient::create(ClientId::random(), clientConfig_, *mgmtd_->asCommon());
    ASSERT_NE(client_, nullptr);
    smallClient(messengerConfig_);
    messenger_ = std::make_unique<client::StorageMessenger>(messengerConfig_);
    ASSERT_OK(messenger_->start("EcRpcProbe"));
    options_.timeout = 10_s;
    options_.sendRetryTimes = 0;

    EcCreateTargetReq createTarget;
    createTarget.settings.targetId = targetId_;
    createTarget.settings.chainId = chainId_;
    createTarget.settings.onlyChunkEngine = true;
    createTarget.settings.allowExistingTarget = false;
    auto created = blockingWait(client_->createEcTarget(nodeId_, createTarget));
    ASSERT_OK(created);
    ASSERT_EQ(created->targetId, targetId_);
    ASSERT_EQ(created->version, kEcFragmentProtocolVersion);
    ASSERT_NO_FATAL_FAILURE(publishRouting(false));
  }

  void TearDown() override {
    if (client_) client_->stop();
    if (messenger_) messenger_->stopAndJoin();
    // Drain real RPC handlers before stopping their borrowed disk jobs.
    if (server_) server_->stopAndJoin();
    if (components_ && operatorInitialized_) {
      auto stopped = components_->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped) << stopped.error().describe();
    }
    client_.reset();
    messenger_.reset();
    server_.reset();
    if (components_) {
      // StorageTarget contains a borrowed Engine pointer. Release all targets
      // while StorageTargets still owns its engine, then destroy Components.
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
  }

  void publishRouting(bool multipleMembers) {
    auto next = std::make_shared<flat::RoutingInfo>(*routing_);
    next->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
    flat::TargetInfo target;
    target.targetId = targetId_;
    target.chainId = chainId_;
    target.nodeId = nodeId_;
    target.diskIndex = 0;
    target.publicState = flat::PublicTargetState::SERVING;
    target.localState = flat::LocalTargetState::UPTODATE;
    next->targets[targetId_] = target;
    flat::ChainInfo chain;
    chain.chainId = chainId_;
    chain.chainVersion = ChainVer{1};
    flat::ChainTargetInfo member;
    member.targetId = targetId_;
    member.publicState = flat::PublicTargetState::SERVING;
    chain.targets.push_back(member);
    if (multipleMembers) {
      target.targetId = TargetId{72};
      next->targets[target.targetId] = target;
      member.targetId = target.targetId;
      chain.targets.push_back(member);
    } else {
      next->targets.erase(TargetId{72});
    }
    next->chains[chainId_] = std::move(chain);
    routing_ = std::move(next);
    mgmtd_->setRoutingInfo(routing_);
    ASSERT_OK(components_->targetMap.updateRouting(mgmtd_->getRoutingInfo()));
  }

  EcCreateReq createRequest(size_t length, uint64_t index) const {
    EcCreateReq request;
    request.identity.object = Uuid::from(1, 2);
    request.identity.allocation = Uuid::from(index, 3);
    request.identity.generation = 1;
    request.identity.stripe = index;
    request.identity.shard = index % 12;
    request.vChainId = VersionedChainId{chainId_, ChainVer{1}};
    request.targetId = targetId_;
    request.operationId = Uuid::from(index, 4);
    request.tag = MessageTag(ClientId::random(), RequestId{index});
    request.payload.data.resize(length);
    for (size_t i = 0; i < length; ++i) request.payload.data[i] = static_cast<char>((i * 37 + (i >> 3) + index) & 255);
    request.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                            reinterpret_cast<const uint8_t *>(request.payload.data.data()),
                                            length);
    return request;
  }

  const NodeId nodeId_{61};
  const TargetId targetId_{71};
  const ChainId chainId_{81};
  folly::test::TemporaryDirectory directory_;
  folly::test::TemporaryDirectory traces_;
  Components::Config config_;
  CPUExecutorGroup loader_{1, "EcRpcDisk"};
  std::unique_ptr<Components> components_;
  bool operatorInitialized_ = false;
  ReplyDropState replyDrop_;
  net::Server::Config serverConfig_;
  std::unique_ptr<net::Server> server_;
  client::StorageClient::Config clientConfig_;
  std::shared_ptr<flat::RoutingInfo> routing_;
  uint64_t routingVersion_ = 1;
  std::unique_ptr<hf3fs::test::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<client::StorageClient> client_;
  net::Client::Config messengerConfig_;
  std::unique_ptr<client::StorageMessenger> messenger_;
  net::Address address_;
  net::UserRequestOptions options_;
};

class TestEcAuthorizedService : public TestEcService {
 protected:
  virtual bool provisionKey() const { return true; }

  void configureEcAuthorization() override {
    config_.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    for (size_t i = 0; i != keyBytes_.size(); ++i) keyBytes_[i] = static_cast<uint8_t>(i + 1);
    if (!provisionKey()) return;
    const auto path = traces_.path() / "ec-capability.key";
    auto fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    const auto written = ::write(fd, keyBytes_.data(), keyBytes_.size());
    const auto closed = ::close(fd);
    ASSERT_EQ(written, static_cast<ssize_t>(keyBytes_.size()));
    ASSERT_EQ(closed, 0);
    config_.storage().set_ec_capability_key_file(path);
  }

  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(TestEcService::SetUp());
    signingKey_ = std::make_unique<EcCapabilityKey>(std::span<const uint8_t, 32>(keyBytes_));
    StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  }

  EcCapability grantFor(const EcCreateReq &request, uint8_t rights = 7, uint64_t expiry = 1100) {
    EcGrantClaims claims;
    claims.identity = request.identity;
    claims.fragmentOperationId = request.operationId;
    claims.chainId = request.vChainId.chainId;
    claims.targetId = request.targetId;
    claims.nodeId = nodeId_;
    claims.expectedLength = static_cast<uint32_t>(request.payload.data.size());
    claims.expectedCrc32c = ~request.checksum.value;
    claims.ownerUid = flat::Uid(1234);
    claims.clientUuid = Uuid::from(55, 66);
    claims.scopeObject = request.identity.object;
    claims.scopeKind = EcGrantScope::WriteOperation;
    claims.scopeId = Uuid::from(77, 88);
    claims.rights = rights;
    claims.grantId = Uuid::random();
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = expiry;
    auto signedGrant = signEcGrant(*signingKey_, claims, 1000, kEcGrantMaxTtlSeconds);
    EXPECT_TRUE(signedGrant.hasValue());
    return signedGrant.value();
  }

  void expireOnValidation(size_t firstExpiredCall) {
    auto calls = std::make_shared<std::atomic<size_t>>(0);
    StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [calls, firstExpiredCall] {
      return ++*calls >= firstExpiredCall ? uint64_t{1100} : uint64_t{1000};
    });
  }

  std::array<uint8_t, 32> keyBytes_{};
  std::unique_ptr<EcCapabilityKey> signingKey_;
};

class TestEcAuthorizedNoKeyService : public TestEcAuthorizedService {
 protected:
  bool provisionKey() const override { return false; }
  void configureEcAuthorization() override {
    TestEcAuthorizedService::configureEcAuthorization();
    // Even explicit experimental access cannot become an authorization fallback.
    config_.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(true);
  }
};

TEST_F(TestEcAuthorizedService, NativeAuthorizedRoundtripRejectsUncredentialedMethods) {
  for (auto length : {size_t{0}, size_t{257}, kEcFragmentRpcMaxBytes}) {
    const auto create = createRequest(length, length + 100);
    const auto grant = grantFor(create);
    ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({create, grant})));
    auto read = blockingWait(client_->authorizedReadEcFragment({readFor(create), grant}));
    ASSERT_OK(read);
    ASSERT_EQ(read->payload.data, create.payload.data);
    ASSERT_OK(blockingWait(client_->authorizedReconcileEcFragment({reconcileFor(create), grant})));
    ASSERT_ERROR(blockingWait(client_->createEcFragment(create)), StatusCode::kAuthenticationFail);
    ASSERT_ERROR(blockingWait(client_->readEcFragment(readFor(create))), StatusCode::kAuthenticationFail);
    ASSERT_ERROR(blockingWait(client_->reconcileEcFragment(reconcileFor(create))), StatusCode::kAuthenticationFail);
  }
  auto create = createRequest(17, 199);
  auto grant = grantFor(create);
  ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({create, grant})));
  auto readClaims = grant.claims;
  readClaims.scopeKind = EcGrantScope::ReadPin;
  readClaims.scopeId = Uuid::random();
  readClaims.rights = static_cast<uint8_t>(EcGrantRight::Read);
  auto readGrant = signEcGrant(*signingKey_, readClaims, 1000);
  ASSERT_OK(readGrant);
  auto readReq = readFor(create);
  readReq.userInfo.uid = flat::Uid(9999);  // userInfo is not used as proof of the bearer's identity.
  ASSERT_OK(blockingWait(client_->authorizedReadEcFragment({readReq, *readGrant})));
  ASSERT_ERROR(blockingWait(client_->authorizedReconcileEcFragment({reconcileFor(create), *readGrant})),
               StatusCode::kAuthenticationFail);
  auto longLived = createRequest(17, 200);
  ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({longLived, grantFor(longLived, 7, 1600)})));
}

TEST_F(TestEcAuthorizedService, ControlledTcpReadKeepsAuthorizationAndFiniteQueueDeadline) {
  const auto create = createRequest(257, 9090);
  const auto grant = grantFor(create);
  ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({create, grant})));
  client::EcRequestControl control;
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  auto result = blockingWait(client_->authorizedReadEcFragmentControlled({readFor(create), grant}, control));
  ASSERT_OK(result);
  EXPECT_EQ(result->payload.data, create.payload.data);

  auto wrong = grantFor(create, static_cast<uint8_t>(EcGrantRight::Create));
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragmentControlled({readFor(create), wrong}, control)),
               StatusCode::kAuthenticationFail);
  control.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragmentControlled({readFor(create), grant}, control)),
               StorageClientCode::kTimeout);
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  CancellationSource cancelled;
  cancelled.requestCancellation();
  control.cancellation = cancelled.getToken();
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragmentControlled({readFor(create), grant}, control)),
               StorageClientCode::kRequestCanceled);

  // A real RPC client's zero-capacity global admission queue must be released
  // by the deadline token. This is not a fake transport or a remote drain ACK.
  client::StorageClient::Config queuedConfig;
  queuedConfig.set_implementation_type(client::StorageClient::ImplementationType::RPC);
  queuedConfig.traffic_control().read().set_max_concurrent_requests(0);
  queuedConfig.traffic_control().read().set_max_concurrent_requests_per_server(2);
  smallClient(queuedConfig.net_client());
  smallClient(queuedConfig.net_client_for_updates());
  auto queued = client::StorageClient::create(ClientId::random(), queuedConfig, *mgmtd_->asCommon());
  ASSERT_NE(queued, nullptr);
  auto stop = folly::makeGuard([&] { queued->stop(); });
  control.cancellation = {};
  control.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  ASSERT_ERROR(blockingWait(queued->authorizedReadEcFragmentControlled({readFor(create), grant}, control)),
               StorageClientCode::kTimeout);
}

TEST_F(TestEcAuthorizedService, RejectsMacBindingRightsExpiryAndPayloadMismatch) {
  const auto create = createRequest(513, 201);
  const auto grant = grantFor(create);
  for (unsigned scenario = 0; scenario != 7; ++scenario) {
    SCOPED_TRACE(scenario);
    EcAuthorizedCreateReq request{create, grant};
    if (scenario == 0) request.grant.claims.grantId = Uuid::random();  // Wrong MAC, otherwise valid schema.
    if (scenario == 1) request.request.targetId = TargetId{999};
    if (scenario == 2) request.request.operationId = Uuid::random();
    if (scenario == 3) request.request.identity.allocation = Uuid::random();
    if (scenario == 4) request.request.payload.data.push_back('x');
    if (scenario == 5) request.request.checksum.value ^= 1;
    if (scenario == 6) request.grant = grantFor(create, static_cast<uint8_t>(EcGrantRight::Read));
    auto result = blockingWait(messenger_->authorizedCreateEcFragment(address_, request, &options_));
    ASSERT_OK(result);
    ASSERT_ERROR(result->result, StatusCode::kAuthenticationFail);
  }
  auto wrongNode = grant.claims;
  wrongNode.nodeId = NodeId{62};
  auto signedWrongNode = signEcGrant(*signingKey_, wrongNode, 1000);
  ASSERT_OK(signedWrongNode);
  ASSERT_ERROR(blockingWait(client_->authorizedCreateEcFragment({create, *signedWrongNode})),
               StatusCode::kAuthenticationFail);

  StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1100}; });
  ASSERT_ERROR(blockingWait(client_->authorizedCreateEcFragment({create, grant})), StatusCode::kAuthenticationFail);
  StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  auto corrupt = create;
  corrupt.payload.data.front() ^= 1;
  auto server = blockingWait(messenger_->authorizedCreateEcFragment(address_, {corrupt, grant}, &options_));
  ASSERT_OK(server);
  ASSERT_ERROR(server->result, StorageCode::kChecksumMismatch);
  auto stale = create;
  stale.vChainId.chainVer = ChainVer{2};
  auto staleResponse = blockingWait(messenger_->authorizedCreateEcFragment(address_, {stale, grant}, &options_));
  ASSERT_OK(staleResponse);
  // The messenger sends directly to StorageSerde. Its server-side TargetMap
  // uses the shared routing error code before any immutable fragment I/O.
  ASSERT_ERROR(staleResponse->result, StorageClientCode::kRoutingVersionMismatch);
  auto directResponse = blockingWait(components_->storageOperator.authorizedCreateEcFragment({stale, grant}));
  ASSERT_OK(directResponse);
  ASSERT_ERROR(directResponse->result, StorageClientCode::kRoutingVersionMismatch);
  // Earlier rejections never created the fragment; the first valid create succeeds.
  ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({create, grant})));
}

TEST_F(TestEcAuthorizedNoKeyService, MissingKeyNeverFallsBackToUncredentialedIo) {
  auto create = createRequest(257, 301);
  auto grant = grantFor(create);
  ASSERT_ERROR(blockingWait(client_->authorizedCreateEcFragment({create, grant})), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragment({readFor(create), grant})),
               StatusCode::kAuthenticationFail);
  ASSERT_ERROR(blockingWait(client_->authorizedReconcileEcFragment({reconcileFor(create), grant})),
               StatusCode::kAuthenticationFail);
  ASSERT_OK(blockingWait(client_->createEcFragment(create)));
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragment({readFor(create), grant})),
               StatusCode::kAuthenticationFail);
}

TEST(TestEcCapabilityComponents, InvalidConfiguredKeyFailsBeforeStartingWorkers) {
  folly::test::TemporaryDirectory directory;
  Components::Config config;
  config.targets().set_target_paths({directory.path()});
  config.storage().set_ec_capability_key_file(directory.path() / "missing-key");
  config.storage().event_trace_log().set_enabled(false);
  Components components(config);
  ASSERT_ERROR(components.storageOperator.init(1), StatusCode::kIOError);
}

TEST_F(TestEcAuthorizedService, WorkerExpiryRejectsBeforeIoAndCompletionExpiryRetainsCommittedData) {
  const auto rejected = createRequest(257, 401);
  const auto rejectedGrant = grantFor(rejected);
  // Calls 1/2 admit and validate after the chunk lock; call 3 runs on the disk worker.
  expireOnValidation(3);
  ASSERT_ERROR(blockingWait(client_->authorizedCreateEcFragment({rejected, rejectedGrant})),
               StatusCode::kAuthenticationFail);
  StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  ASSERT_OK(blockingWait(client_->authorizedCreateEcFragment({rejected, rejectedGrant})));

  const auto committed = createRequest(4097, 402);
  const auto committedGrant = grantFor(committed);
  // The fourth validation follows the real Engine commit and worker drain.
  expireOnValidation(4);
  ASSERT_ERROR(blockingWait(client_->authorizedCreateEcFragment({committed, committedGrant})),
               StorageCode::kEcSealOutcomeUnknown);
  StorageEcAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  auto read = blockingWait(client_->authorizedReadEcFragment({readFor(committed), grantFor(committed)}));
  ASSERT_OK(read);
  ASSERT_EQ(read->payload.data, committed.payload.data);
  ASSERT_OK(blockingWait(client_->authorizedReconcileEcFragment({reconcileFor(committed), grantFor(committed)})));
  expireOnValidation(4);
  ASSERT_ERROR(blockingWait(client_->authorizedReconcileEcFragment({reconcileFor(committed), committedGrant})),
               StorageCode::kEcSealOutcomeUnknown);
  // Read has admission/worker/completion checks; it must not return bytes after expiry.
  expireOnValidation(3);
  ASSERT_ERROR(blockingWait(client_->authorizedReadEcFragment({readFor(committed), committedGrant})),
               StatusCode::kAuthenticationFail);
}

TEST_F(TestEcService, TcpNativeRoundtripAndGuards) {
  uint64_t index = 10;
  for (size_t length : {size_t{0}, size_t{1}, size_t{257}, size_t{4097}, kEcFragmentRpcMaxBytes}) {
    SCOPED_TRACE(fmt::format("roundtrip length={}", length));
    auto create = createRequest(length, index++);
    auto receipt = blockingWait(client_->createEcFragment(create));
    ASSERT_OK(receipt);
    ASSERT_EQ(receipt->length, length);
    ASSERT_EQ(receipt->operationId, create.operationId);
    ASSERT_EQ(receipt->checksum, create.checksum);
    auto read = blockingWait(client_->readEcFragment(readFor(create)));
    ASSERT_OK(read);
    ASSERT_EQ(read->payload.data, create.payload.data);
    ASSERT_ERROR(blockingWait(client_->createEcFragment(create)), StorageCode::kChunkAlreadyExists);
    auto reconciled = blockingWait(client_->reconcileEcFragment(reconcileFor(create)));
    ASSERT_OK(reconciled);
    ASSERT_EQ(reconciled->operationId, create.operationId);
    ASSERT_EQ(reconciled->checksum, create.checksum);
    ASSERT_EQ(reconciled->length, length);
    ASSERT_OK(blockingWait(client_->reconcileEcFragment(reconcileFor(create))));
  }

  auto create = createRequest(257, 30);
  ASSERT_OK(blockingWait(client_->createEcFragment(create)));
  auto read = readFor(create);
  {
    SCOPED_TRACE("invalid expected metadata and payload");
    auto wrong = read;
    wrong.expectedLength++;
    ASSERT_ERROR(blockingWait(client_->readEcFragment(wrong)), StorageCode::kChunkSizeMismatch);
    wrong = read;
    wrong.checksum.value ^= 1;
    ASSERT_ERROR(blockingWait(client_->readEcFragment(wrong)), StorageCode::kChecksumMismatch);
    wrong = read;
    wrong.operationId = Uuid::from(90, 91);
    ASSERT_ERROR(blockingWait(client_->readEcFragment(wrong)), StorageCode::kChunkETagMismatch);
    auto wrongReconcile = reconcileFor(create);
    wrongReconcile.operationId = wrong.operationId;
    ASSERT_ERROR(blockingWait(client_->reconcileEcFragment(wrongReconcile)), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcileFor(create);
    wrongReconcile.identity.allocation = Uuid::from(90, 92);
    ASSERT_ERROR(blockingWait(client_->reconcileEcFragment(wrongReconcile)), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcileFor(create);
    ++wrongReconcile.expectedLength;
    ASSERT_ERROR(blockingWait(client_->reconcileEcFragment(wrongReconcile)), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcileFor(create);
    wrongReconcile.checksum.value ^= 1;
    ASSERT_ERROR(blockingWait(client_->reconcileEcFragment(wrongReconcile)), StorageCode::kEcSealOutcomeUnknown);

    auto badCreate = createRequest(31, 40);
    badCreate.checksum.value ^= 1;
    ASSERT_ERROR(blockingWait(client_->createEcFragment(badCreate)), StorageClientCode::kChecksumMismatch);
    auto serverRejected = blockingWait(messenger_->createEcFragment(address_, badCreate, &options_));
    ASSERT_OK(serverRejected);
    ASSERT_ERROR(serverRejected->result, StorageCode::kChecksumMismatch);
    auto oversized = createRequest(kEcFragmentRpcMaxBytes + 1, 41);
    ASSERT_ERROR(blockingWait(client_->createEcFragment(oversized)), StatusCode::kInvalidArg);
  }
  {
    SCOPED_TRACE("stale versions rejected by client and real server");
    auto staleCreate = createRequest(33, 50);
    staleCreate.vChainId.chainVer = ChainVer{0};
    ASSERT_ERROR(blockingWait(client_->createEcFragment(staleCreate)), StorageClientCode::kRoutingVersionMismatch);
    auto serverCreate = blockingWait(messenger_->createEcFragment(address_, staleCreate, &options_));
    ASSERT_OK(serverCreate);
    ASSERT_ERROR(serverCreate->result, StorageClientCode::kRoutingVersionMismatch);
    auto staleRead = read;
    staleRead.vChainId.chainVer = ChainVer{0};
    ASSERT_ERROR(blockingWait(client_->readEcFragment(staleRead)), StorageClientCode::kRoutingVersionMismatch);
    auto serverRead = blockingWait(messenger_->readEcFragment(address_, staleRead, &options_));
    ASSERT_OK(serverRead);
    ASSERT_ERROR(serverRead->result, StorageClientCode::kRoutingVersionMismatch);
  }
  {
    SCOPED_TRACE("multi-member chains rejected by client and real server");
    ASSERT_NO_FATAL_FAILURE(publishRouting(true));
    auto fresh = createRequest(33, 51);
    ASSERT_ERROR(blockingWait(client_->createEcFragment(fresh)), StorageClientCode::kRoutingError);
    auto serverCreate = blockingWait(messenger_->createEcFragment(address_, fresh, &options_));
    ASSERT_OK(serverCreate);
    ASSERT_ERROR(serverCreate->result, StorageClientCode::kRoutingError);
    ASSERT_ERROR(blockingWait(client_->readEcFragment(read)), StorageClientCode::kRoutingError);
    auto serverRead = blockingWait(messenger_->readEcFragment(address_, read, &options_));
    ASSERT_OK(serverRead);
    ASSERT_ERROR(serverRead->result, StorageClientCode::kRoutingError);
    ASSERT_NO_FATAL_FAILURE(publishRouting(false));
  }
  {
    SCOPED_TRACE("offline owner rejected before dispatch");
    auto offline = std::make_shared<flat::RoutingInfo>(*routing_);
    offline->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
    offline->nodes.at(nodeId_).status = flat::NodeStatus::HEARTBEAT_FAILED;
    mgmtd_->setRoutingInfo(offline);
    ASSERT_ERROR(blockingWait(client_->createEcFragment(createRequest(1, 52))), StorageClientCode::kNotAvailable);
    ASSERT_ERROR(blockingWait(client_->readEcFragment(read)), StorageClientCode::kNotAvailable);
    ASSERT_NO_FATAL_FAILURE(publishRouting(false));
  }
  {
    SCOPED_TRACE("legacy RPCs cannot access immutable EC allocations");
    auto key = create.identity.chunkId();
    ASSERT_OK(key);
    BatchReadReq legacyRead;
    legacyRead.payloads.push_back(ReadIO{.length = 1, .key = {create.vChainId, *key}});
    ASSERT_ERROR(blockingWait(messenger_->batchRead(address_, legacyRead, &options_)),
                 StorageCode::kTargetStateInvalid);
    UpdateReq update;
    update.payload.key = {create.vChainId, *key};
    update.payload.updateType = UpdateType::REMOVE;
    auto updated = blockingWait(messenger_->update(address_, update, &options_));
    ASSERT_OK(updated);
    ASSERT_ERROR(updated->result.lengthInfo, StorageCode::kTargetStateInvalid);
    RemoveChunksReq remove;
    RemoveChunksOp op;
    op.vChainId = create.vChainId;
    op.chunkIdRange = {*key, key->nextChunkId(), 1};
    remove.payloads.push_back(op);
    auto removed = blockingWait(messenger_->removeChunks(address_, remove, &options_));
    ASSERT_OK(removed);
    ASSERT_EQ(removed->results.size(), 1);
    ASSERT_ERROR(removed->results.front().statusCode, StorageCode::kTargetStateInvalid);
    ASSERT_ERROR(blockingWait(messenger_->removeTarget(address_, RemoveTargetReq{.targetId = targetId_}, &options_)),
                 StorageCode::kTargetStateInvalid);
    ASSERT_ERROR(blockingWait(messenger_->syncStart(address_, SyncStartReq{.vChainId = create.vChainId}, &options_)),
                 StorageCode::kTargetStateInvalid);
    ASSERT_ERROR(blockingWait(messenger_->syncDone(address_, SyncDoneReq{.vChainId = create.vChainId}, &options_)),
                 StorageCode::kTargetStateInvalid);
  }
  {
    SCOPED_TRACE("readonly retains read access");
    config_.storage().set_read_only(true);
    ASSERT_ERROR(blockingWait(client_->createEcFragment(createRequest(1, 60))), StatusCode::kReadOnlyMode);
    auto retained = blockingWait(client_->readEcFragment(read));
    ASSERT_OK(retained);
    ASSERT_EQ(retained->payload.data, create.payload.data);
    ASSERT_OK(blockingWait(client_->reconcileEcFragment(reconcileFor(create))));
    config_.storage().set_read_only(false);
  }
  // Failed legacy mutation attempts must leave the sealed bytes unchanged.
  auto retained = blockingWait(client_->readEcFragment(read));
  ASSERT_OK(retained);
  ASSERT_EQ(retained->payload.data, create.payload.data);
}

TEST_F(TestEcService, LostCreateReplyRequiresExplicitReconciliation) {
  auto create = createRequest(4097, 70);
  replyDrop_.arm();
  auto uncertain = blockingWait(client_->createEcFragment(create));
  ASSERT_ERROR(uncertain, StorageCode::kEcSealOutcomeUnknown);

  // The fixture captured the real create handler's successful receipt before
  // dropping the reply. This observation is not available to the caller.
  auto observed = replyDrop_.snapshot();
  ASSERT_EQ(observed.createCalls, 1) << "the client must not automatically replay an uncertain create";
  ASSERT_TRUE(observed.droppedReceipt.has_value());
  ASSERT_EQ(observed.droppedReceipt->operationId, create.operationId);
  ASSERT_EQ(observed.droppedReceipt->length, create.payload.data.size());
  ASSERT_EQ(observed.droppedReceipt->checksum, create.checksum);

  ASSERT_ERROR(blockingWait(client_->createEcFragment(create)), StorageCode::kChunkAlreadyExists);
  ASSERT_EQ(replyDrop_.snapshot().createCalls, 2);
  auto overwrite = create;
  overwrite.operationId = Uuid::from(71, 4);
  overwrite.payload.data.front() ^= 1;
  overwrite.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                            reinterpret_cast<const uint8_t *>(overwrite.payload.data.data()),
                                            overwrite.payload.data.size());
  ASSERT_ERROR(blockingWait(client_->createEcFragment(overwrite)), StorageCode::kChunkAlreadyExists);
  ASSERT_EQ(replyDrop_.snapshot().createCalls, 3);

  // A read verifies only content retention. It is deliberately not used as
  // the durability acknowledgement for the original uncertain operation.
  auto retained = blockingWait(client_->readEcFragment(readFor(create)));
  ASSERT_OK(retained);
  ASSERT_EQ(retained->payload.data, create.payload.data);
  auto reconciled = blockingWait(client_->reconcileEcFragment(reconcileFor(create)));
  ASSERT_OK(reconciled);
  ASSERT_EQ(reconciled->operationId, create.operationId);
  ASSERT_EQ(reconciled->checksum, create.checksum);
  ASSERT_OK(blockingWait(client_->reconcileEcFragment(reconcileFor(create))));
  ASSERT_EQ(replyDrop_.snapshot().createCalls, 3) << "reconciliation must never create or overwrite a fragment";
}

TEST(TestEcServiceWithoutEngine, InMemExplicitlyUnsupported) {
  auto routing = std::make_shared<flat::RoutingInfo>();
  hf3fs::test::FakeMgmtdClient mgmtd(routing);
  client::StorageClient::Config config;
  config.set_implementation_type(client::StorageClient::ImplementationType::InMem);
  auto storage = client::StorageClient::create(ClientId::random(), config, *mgmtd.asCommon());
  ASSERT_NE(storage, nullptr);
  ASSERT_ERROR(blockingWait(storage->createEcTarget(NodeId{1}, EcCreateTargetReq{})), StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(storage->createEcFragment(EcCreateReq{})), StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(storage->readEcFragment(EcReadReq{})), StatusCode::kNotImplemented);
  ASSERT_ERROR(blockingWait(storage->reconcileEcFragment(EcReconcileReq{})), StatusCode::kNotImplemented);
}

}  // namespace
}  // namespace hf3fs::storage
