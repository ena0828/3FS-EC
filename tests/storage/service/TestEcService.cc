#include <algorithm>
#include <folly/experimental/coro/BlockingWait.h>
#include <linux/magic.h>
#include <mutex>
#include <optional>
#include <sys/resource.h>
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
