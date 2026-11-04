#include <algorithm>
#include <atomic>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <future>
#include <linux/magic.h>
#include <mutex>
#include <optional>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "client/storage/StorageClient.h"
#include "client/storage/StorageMessenger.h"
#include "common/net/Server.h"
#include "fbs/storage/EcStageResultV2.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::storage {
class StorageEcStageAuthorizationTestAccess {
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

struct StageReplyDropState {
  struct ReadDelay {
    std::promise<void> entered;
    std::promise<void> release;
    std::shared_future<void> resume = release.get_future().share();
    std::atomic<bool> resumed{false};
    void unblock() {
      if (!resumed.exchange(true)) release.set_value();
    }
    ~ReadDelay() { unblock(); }
  };
  struct Snapshot {
    size_t sealCalls = 0;
    std::optional<EcFragmentReceiptV2> droppedReceipt;
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
  std::shared_ptr<ReadDelay> delayedRead;
};

// Every handler still executes the real StorageService. Rebind the serde
// reflection to this derived type so only this post-success fault intercepts
// sealEcStageV2; no synthetic storage result is supplied to the client.
class StageReplyDropStorageService : public StorageService {
 public:
  StageReplyDropStorageService(StorageOperator &storageOperator, StageReplyDropState &fault)
      : StorageService(storageOperator),
        fault_(fault) {}

  CoTryTask<EcReadBlockV2Rsp> readEcBlockV2(serde::CallContext &ctx, const EcReadBlockV2Req &req) {
    std::shared_ptr<StageReplyDropState::ReadDelay> delay;
    {
      std::lock_guard lock(fault_.mutex);
      delay = std::move(fault_.delayedRead);
    }
    if (delay) {
      delay->entered.set_value();
      delay->resume.wait();
    }
    // Delay the real server handler; never supply synthetic successful data.
    co_return co_await StorageService::readEcBlockV2(ctx, req);
  }

  CoTryTask<EcSealStageV2Rsp> sealEcStageV2(serde::CallContext &ctx, const EcSealStageV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.sealCalls;
    }
    auto response = co_await StorageService::sealEcStageV2(ctx, req);
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
  template <class U = StageReplyDropStorageService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<StorageSerde<U>>;

 private:
  StageReplyDropState &fault_;
};

class TestEcStageService : public ::testing::Test {
 protected:
  void configureEcAuthorization() {
    config_.storage().set_allow_unsafe_ec_fragment_rpc_for_testing(false);
    for (size_t i = 0; i != keyBytes_.size(); ++i) keyBytes_[i] = static_cast<uint8_t>(i + 41);
    const auto path = traces_.path() / "v2-data.key";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    const auto written = ::write(fd, keyBytes_.data(), keyBytes_.size());
    const int closed = ::close(fd);
    ASSERT_EQ(written, static_cast<ssize_t>(keyBytes_.size()));
    ASSERT_EQ(closed, 0);
    config_.storage().set_ec_capability_key_file(path);
  }

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
    config_.targets().set_ec_staging_v2(true);
    config_.targets().set_allow_disk_without_uuid(true);
    config_.targets().set_collect_all_fds(false);
    config_.storage().set_enable_ec_fragments(true);
    ASSERT_NO_FATAL_FAILURE(configureEcAuthorization());
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
    ASSERT_OK(server_->addSerdeService(
        std::make_unique<StageReplyDropStorageService>(components_->storageOperator, replyDrop_),
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
    auto target = components_->targetMap.getByTargetId(targetId_);
    ASSERT_OK(target);
    ASSERT_TRUE((*target)->storageTarget->usesEcStagingEngine());
    auto state = (*target)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    instance_ = state->second;
    signingKey_ = std::make_unique<EcCapabilityKey>(std::span<const uint8_t, 32>(keyBytes_));
    StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
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

  EcFragmentAccessV2 access(size_t length, uint64_t index, std::string &data) const {
    EcFragmentAccessV2 request;
    request.identity.object = Uuid::from(11, 12);
    request.identity.allocation = Uuid::from(index, 13);
    request.identity.generation = 1;
    request.identity.stripe = index;
    request.identity.shard = index % 12;
    request.vChainId = VersionedChainId{chainId_, ChainVer{1}};
    request.targetId = targetId_;
    request.operationId = Uuid::from(index, 14);
    request.tag = MessageTag(ClientId::random(), RequestId{index});
    data.resize(length);
    for (size_t i = 0; i != length; ++i) data[i] = static_cast<char>((i * 37 + index) & 255);
    auto descriptor = computeEcIntegrity(request.identity, data);
    EXPECT_TRUE(descriptor.hasValue());
    request.integrity = descriptor.value();
    return request;
  }
  EcCapabilityV2 grant(const EcFragmentAccessV2 &request,
                       uint16_t rights = kEcGrantAllRightsV2,
                       bool readPin = false,
                       uint64_t expires = 1100) const {
    EcGrantClaimsV2 claims;
    std::copy(instance_.engine.begin(), instance_.engine.end(), std::begin(claims.engineUuid.data));
    std::copy(instance_.incarnation.begin(), instance_.incarnation.end(), std::begin(claims.targetIncarnation.data));
    claims.identity = request.identity;
    claims.fragmentOperationId = request.operationId;
    claims.chainId = request.vChainId.chainId;
    claims.targetId = request.targetId;
    claims.nodeId = nodeId_;
    claims.expectedLength = request.integrity.wholeLength;
    claims.expectedCrc32c = request.integrity.wholeCrc32c;
    auto digest = digestEcIntegrityV2(request.identity, request.integrity);
    EXPECT_TRUE(digest.hasValue());
    claims.integrityDigest = digest.value();
    claims.ownerUid = flat::Uid{1234};
    claims.clientNamespace = Uuid::from(readPin ? 99 : 55, 66);
    claims.scopeObject = request.identity.object;
    claims.scopeKind = readPin ? EcGrantScope::ReadPin : EcGrantScope::WriteOperation;
    claims.scopeId = Uuid::from(readPin ? 100 : 77, 88);
    claims.rights = rights;
    claims.grantId = Uuid::random();
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = expires;
    auto result = signEcGrantV2(*signingKey_, claims, 1000, kEcGrantMaxTtlSeconds);
    EXPECT_TRUE(result.hasValue());
    return result.value();
  }
  void appendAll(const EcFragmentAccessV2 &request, const EcCapabilityV2 &token, const std::string &data) {
    for (uint32_t block = 0; block != request.integrity.blockCount; ++block) {
      EcAppendStageV2Req append;
      append.request = request;
      append.grant = token;
      append.blockIndex = block;
      append.payload.data = data.substr(size_t(block) * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
      ASSERT_OK(blockingWait(client_->appendEcStageV2(append)));
    }
  }
  std::array<uint8_t, 32> keyBytes_{};
  std::unique_ptr<EcCapabilityKey> signingKey_;
  EcScopeTargetIdentity instance_{};

  const NodeId nodeId_{61};
  const TargetId targetId_{71};
  const ChainId chainId_{81};
  folly::test::TemporaryDirectory directory_;
  folly::test::TemporaryDirectory traces_;
  Components::Config config_;
  CPUExecutorGroup loader_{1, "EcRpcDisk"};
  std::unique_ptr<Components> components_;
  bool operatorInitialized_ = false;
  StageReplyDropState replyDrop_;
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

TEST_F(TestEcStageService, AuthorizedTcpSlicesRoundtripThroughRealEngine) {
  uint64_t index = 10;
  for (size_t length : {size_t{0}, size_t{1}, size_t{65543}, size_t{1u << 20}}) {
    SCOPED_TRACE(length);
    std::string original;
    auto request = access(length, index++, original);
    auto token = grant(request);
    auto begin = blockingWait(client_->beginEcStageV2({request, token}));
    ASSERT_OK(begin);
    EXPECT_EQ(begin->state, 1);
    EXPECT_EQ(begin->prefixBytes, 0);
    ASSERT_NO_FATAL_FAILURE(appendAll(request, token, original));
    auto seal = blockingWait(client_->sealEcStageV2({request, token}));
    ASSERT_OK(seal);
    EXPECT_EQ(seal->length, original.size());
    EXPECT_EQ(seal->operationId, request.operationId);
    auto observed = blockingWait(client_->queryEcStageV2({request, token}));
    ASSERT_OK(observed);
    EXPECT_EQ(observed->state, 2);
    EXPECT_FALSE(observed->needsReconcile);
    ASSERT_OK(blockingWait(client_->reconcileEcStageV2({request, token})));
    auto readToken = grant(request, static_cast<uint16_t>(EcGrantRightV2::ReadBlock), true);
    std::string restored;
    for (uint32_t block = 0; block != request.integrity.blockCount; ++block) {
      EcReadBlockV2Req read;
      read.request = request;
      read.request.userInfo.uid = flat::Uid{9999};  // Diagnostic input is not bearer authentication.
      read.blockIndex = block;
      read.grant = readToken;
      auto result = blockingWait(client_->readEcBlockV2(read));
      ASSERT_OK(result);
      EXPECT_EQ(result->blockIndex, block);
      EXPECT_LE(result->payload.data.size(), kEcIntegrityBlockBytes);
      restored += result->payload.data;
    }
    EXPECT_EQ(restored, original);
  }
}

TEST_F(TestEcStageService, BindingMacRightsAndExactTailRejectBeforeMutation) {
  std::string original;
  auto request = access(65543, 40, original);
  auto token = grant(request);
  auto wrongMac = token;
  wrongMac.claims.grantId = Uuid::random();
  ASSERT_ERROR(blockingWait(client_->beginEcStageV2({request, wrongMac})), StatusCode::kAuthenticationFail);
  auto wrongInstance = token.claims;
  wrongInstance.engineUuid = Uuid::random();
  auto signedWrongInstance = signEcGrantV2(*signingKey_, wrongInstance, 1000);
  ASSERT_OK(signedWrongInstance);
  ASSERT_ERROR(blockingWait(client_->beginEcStageV2({request, *signedWrongInstance})), StatusCode::kAuthenticationFail);
  auto readOnly = grant(request, static_cast<uint16_t>(EcGrantRightV2::ReadBlock), true);
  ASSERT_ERROR(blockingWait(client_->beginEcStageV2({request, readOnly})), StatusCode::kAuthenticationFail);
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
  EcAppendStageV2Req append;
  append.request = request;
  append.grant = token;
  append.blockIndex = 0;
  append.payload.data = original.substr(0, 65536);
  append.payload.data[17] ^= 1;
  // Raw Messenger exercises server verification instead of client prechecks.
  auto rejected = blockingWait(messenger_->appendEcStageV2(address_, append, &options_));
  ASSERT_OK(rejected);
  EXPECT_FALSE(rejected->result);
  auto state = blockingWait(client_->queryEcStageV2({request, token}));
  ASSERT_OK(state);
  EXPECT_EQ(state->prefixBytes, 0);
  append.payload.data = original.substr(0, 65536);
  ASSERT_OK(blockingWait(client_->appendEcStageV2(append)));
  ASSERT_OK(blockingWait(client_->appendEcStageV2(append)));  // Exact duplicate is idempotent.
  append.blockIndex = 1;
  append.payload.data = original.substr(65536) + "padding";
  rejected = blockingWait(messenger_->appendEcStageV2(address_, append, &options_));
  ASSERT_OK(rejected);
  EXPECT_FALSE(rejected->result);
  EXPECT_FALSE(blockingWait(client_->sealEcStageV2({request, token})));
  append.payload.data = original.substr(65536);
  ASSERT_OK(blockingWait(client_->appendEcStageV2(append)));
  ASSERT_OK(blockingWait(client_->sealEcStageV2({request, token})));
}

TEST_F(TestEcStageService, LostSealReplyIsUnknownAndRetryDoesNotDoubleAccount) {
  std::string original;
  auto request = access(65543, 50, original);
  auto token = grant(request);
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
  ASSERT_NO_FATAL_FAILURE(appendAll(request, token, original));
  replyDrop_.arm();
  ASSERT_ERROR(blockingWait(client_->sealEcStageV2({request, token})), StorageCode::kEcSealOutcomeUnknown);
  auto snapshot = replyDrop_.snapshot();
  ASSERT_EQ(snapshot.sealCalls, 1);
  ASSERT_TRUE(snapshot.droppedReceipt);
  auto physical = components_->targetMap.getByTargetId(targetId_);
  ASSERT_OK(physical);
  const auto before = (*physical)->storageTarget->usedSize();
  EXPECT_GE(before, original.size());
  auto query = blockingWait(client_->queryEcStageV2({request, token}));
  ASSERT_OK(query);
  EXPECT_EQ(query->state, 2);  // Observation is not a fresh durability ACK.
  ASSERT_OK(blockingWait(client_->reconcileEcStageV2({request, token})));
  auto confirmed = blockingWait(client_->sealEcStageV2({request, token}));
  ASSERT_OK(confirmed);
  EXPECT_EQ(confirmed->operationId, snapshot.droppedReceipt->operationId);
  EXPECT_EQ((*physical)->storageTarget->usedSize(), before);
}

TEST_F(TestEcStageService, ExpiryAtWorkerAndAfterSealUseDistinctOutcomes) {
  std::string original;
  auto request = access(4097, 60, original);
  auto token = grant(request);
  auto calls = std::make_shared<std::atomic<unsigned>>(0);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator,
                                               [calls] { return ++*calls >= 4 ? uint64_t{1100} : uint64_t{1000}; });
  ASSERT_ERROR(blockingWait(client_->beginEcStageV2({request, token})), StatusCode::kAuthenticationFail);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
  ASSERT_NO_FATAL_FAILURE(appendAll(request, token, original));
  calls->store(0);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator,
                                               [calls] { return ++*calls >= 5 ? uint64_t{1100} : uint64_t{1000}; });
  ASSERT_ERROR(blockingWait(client_->sealEcStageV2({request, token})), StorageCode::kEcSealOutcomeUnknown);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  auto state = blockingWait(client_->queryEcStageV2({request, token}));
  ASSERT_OK(state);
  EXPECT_EQ(state->state, 2);
  ASSERT_OK(blockingWait(client_->sealEcStageV2({request, token})));
}

TEST_F(TestEcStageService, ControlledBlockReadUsesRealTcpAndFiniteDeadline) {
  std::string original;
  auto request = access(4097, 70, original);
  auto token = grant(request);
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
  ASSERT_NO_FATAL_FAILURE(appendAll(request, token, original));
  ASSERT_OK(blockingWait(client_->sealEcStageV2({request, token})));
  EcReadBlockV2Req read;
  read.request = request;
  read.blockIndex = 0;
  read.grant = token;
  client::EcRequestControl control;
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  auto result = blockingWait(client_->readEcBlockV2Controlled(read, control));
  ASSERT_OK(result);
  EXPECT_EQ(result->payload.data, original);
  control.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
  ASSERT_ERROR(blockingWait(client_->readEcBlockV2Controlled(read, control)), StorageClientCode::kTimeout);
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  CancellationSource cancel;
  cancel.requestCancellation();
  control.cancellation = cancel.getToken();
  ASSERT_ERROR(blockingWait(client_->readEcBlockV2Controlled(read, control)), StorageClientCode::kRequestCanceled);

  client::StorageClient::Config queuedConfig;
  queuedConfig.set_implementation_type(client::StorageClient::ImplementationType::RPC);
  queuedConfig.traffic_control().read().set_max_concurrent_requests(0);
  queuedConfig.traffic_control().read().set_max_concurrent_requests_per_server(2);
  smallClient(queuedConfig.net_client());
  smallClient(queuedConfig.net_client_for_updates());
  auto queued = client::StorageClient::create(ClientId::random(), queuedConfig, *mgmtd_->asCommon());
  ASSERT_NE(queued, nullptr);
  auto stopQueued = folly::makeGuard([&] { queued->stop(); });
  control.cancellation = {};
  control.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  ASSERT_ERROR(blockingWait(queued->readEcBlockV2Controlled(read, control)), StorageClientCode::kTimeout);

  auto delay = std::make_shared<StageReplyDropState::ReadDelay>();
  auto entered = delay->entered.get_future();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.delayedRead = delay;
  }
  auto releaseDelay = folly::makeGuard([&] { delay->unblock(); });
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  auto pending =
      std::async(std::launch::async, [&] { return blockingWait(client_->readEcBlockV2Controlled(read, control)); });
  auto settle = folly::makeGuard([&] {
    delay->unblock();
    if (pending.valid()) pending.wait();
  });
  ASSERT_EQ(entered.wait_for(std::chrono::seconds(5)), std::future_status::ready);
  ASSERT_EQ(pending.wait_for(std::chrono::seconds(4)), std::future_status::ready);
  ASSERT_ERROR(pending.get(), StorageClientCode::kTimeout);
  // A local transport timeout is not proof of remote drain. Release the real
  // server handler and let fixture teardown join it before destroying Engine.
  delay->unblock();
}

TEST_F(TestEcStageService, LegacyBearerAndChangedRouteCannotBypassV2) {
  std::string original;
  auto request = access(1, 80, original);
  auto token = grant(request);
  auto stale = request;
  stale.vChainId.chainVer = ChainVer{999};
  EXPECT_FALSE(blockingWait(client_->beginEcStageV2({stale, token})));
  EcCreateReq legacy;
  legacy.identity = request.identity;
  legacy.operationId = request.operationId;
  legacy.vChainId = request.vChainId;
  legacy.targetId = request.targetId;
  legacy.payload.data = original;
  legacy.checksum = ChecksumInfo{ChecksumType::CRC32C, ~request.integrity.wholeCrc32c};
  ASSERT_ERROR(blockingWait(client_->createEcFragment(legacy)), StatusCode::kAuthenticationFail);
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
}

}  // namespace
}  // namespace hf3fs::storage
