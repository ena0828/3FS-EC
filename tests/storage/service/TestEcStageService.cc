#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Sleep.h>
#include <future>
#include <linux/magic.h>
#include <mutex>
#include <optional>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "client/ec/NativeEcBlockTransport.h"
#include "client/ec/NativeEcRepairTransport.h"
#include "client/storage/StorageClient.h"
#include "client/storage/StorageMessenger.h"
#include "common/net/Server.h"
#include "fbs/storage/EcStageResultV2.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_codec/EcCodec.h"
#include "storage/ec_repair/EcHelperAuthorization.h"
#include "storage/service/Components.h"
#include "storage/service/StorageService.h"
#include "tests/EcRepairTestData.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"
#include "tests/storage/EcRmwTestAccess.h"

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
  // One fixed window=2 attempt. Counts describe real service-handler bodies,
  // not a distributed drain certificate or the connection's response queue.
  struct ConcurrentWindow {
    struct Snapshot {
      bool held = false;
      bool dropped = false;
      bool sameConnection = false;
      bool tcpConnection = false;
      int shutdownResult = -1, shutdownErrno = 0;
      size_t readEntered = 0, readFinished = 0, readSucceeded = 0;
      std::array<size_t, 10> helperEntered{}, helperFinished{}, helperSucceeded{}, helperBusy{};
    };
    EcRepairPlanInput plan;
    EcFragmentAccessV2 sourceRequest;
    bool helper = false;
    std::mutex mutex;
    std::condition_variable changed;
    Snapshot state;
    net::TransportPtr firstHop;
    folly::coro::Baton entered, resume;
    std::atomic<bool> released{false};

    Snapshot snapshot() {
      std::lock_guard lock(mutex);
      return state;
    }
    template <class Predicate>
    bool waitFor(Predicate predicate) {
      std::unique_lock lock(mutex);
      return changed.wait_for(lock, std::chrono::seconds(10), [&] { return predicate(state); });
    }
    void unblock() {
      if (!released.exchange(true)) {
        // Also unblock the post-commit Append handler on an assertion failure
        // before the intended remote request reached its barrier.
        entered.post();
        resume.post();
      }
    }
    ~ConcurrentWindow() { unblock(); }
  };
  struct ReadDelay {
    std::promise<void> entered;
    // Suspend only this handler; never block its shared network processor.
    folly::coro::Baton resume;
    std::atomic<bool> resumed{false};
    std::atomic<bool> started{false};
    void unblock() {
      if (!resumed.exchange(true)) resume.post();
    }
    ~ReadDelay() { unblock(); }
  };
  struct Snapshot {
    size_t appendCalls = 0;
    size_t sealCalls = 0;
    std::optional<EcStageStateV2> droppedAppend;
    std::optional<EcFragmentReceiptV2> droppedReceipt;
  };

  void arm(std::optional<EcFragmentAccessV2> request = std::nullopt) {
    std::lock_guard lock(mutex);
    armed = true;
    sealRequest = std::move(request);
    appendRequest.reset();
    state = {};
  }

  void armAppend(const EcFragmentAccessV2 &request, uint32_t block) {
    std::lock_guard lock(mutex);
    armed = false;
    sealRequest.reset();
    appendRequest = request;
    appendBlock = block;
    state = {};
  }

  static bool sameStage(const EcFragmentAccessV2 &left, const EcFragmentAccessV2 &right) {
    return serde::equals(left.identity, right.identity) && left.operationId == right.operationId &&
           left.targetId == right.targetId && left.vChainId == right.vChainId;
  }

  Snapshot snapshot() const {
    std::lock_guard lock(mutex);
    return state;
  }

  mutable std::mutex mutex;
  bool armed = false;
  std::optional<EcFragmentAccessV2> sealRequest;
  std::optional<EcFragmentAccessV2> appendRequest;
  uint32_t appendBlock = 0;
  Snapshot state;
  std::shared_ptr<ReadDelay> delayedRead;
  std::array<size_t, 10> helperHopCalls{};
  std::optional<uint8_t> helperDelayPosition;
  std::shared_ptr<ReadDelay> delayedHelper;
  std::vector<std::shared_ptr<ReadDelay>> delayedBegins;
  size_t beginCalls = 0;
  size_t queryCalls = 0;
  size_t reconcileCalls = 0;
  std::optional<uint16_t> delayedReadShard;
  std::shared_ptr<ConcurrentWindow> concurrentWindow;
};

// Every handler still executes the real StorageService. Rebind the serde
// reflection to this derived type so post-success faults can drop an Append
// or Seal reply; no synthetic storage result is supplied to the client.
class StageReplyDropStorageService : public StorageService {
 public:
  StageReplyDropStorageService(StorageOperator &storageOperator, StageReplyDropState &fault)
      : StorageService(storageOperator),
        fault_(fault) {}

  CoTryTask<EcReadBlockV2Rsp> readEcBlockV2(serde::CallContext &ctx, const EcReadBlockV2Req &req) {
    std::shared_ptr<StageReplyDropState::ConcurrentWindow> window;
    {
      std::lock_guard lock(fault_.mutex);
      if (fault_.concurrentWindow && !fault_.concurrentWindow->helper && req.blockIndex == 1 &&
          StageReplyDropState::sameStage(req.request, fault_.concurrentWindow->sourceRequest)) {
        window = fault_.concurrentWindow;
      }
    }
    if (window) {
      bool success = false;
      {
        std::lock_guard lock(window->mutex);
        ++window->state.readEntered;
        window->firstHop = ctx.transport();
        window->state.held = true;
      }
      auto finished = folly::makeGuard([&] {
        std::lock_guard lock(window->mutex);
        ++window->state.readFinished;
        window->state.readSucceeded += success;
        window->changed.notify_all();
      });
      window->changed.notify_all();
      window->entered.post();
      co_await window->resume;
      auto result = co_await StorageService::readEcBlockV2(ctx, req);
      success = result && result->result;
      co_return result;
    }
    std::shared_ptr<StageReplyDropState::ReadDelay> delay;
    {
      std::lock_guard lock(fault_.mutex);
      if (!fault_.delayedReadShard || *fault_.delayedReadShard == req.request.identity.shard) {
        delay = std::move(fault_.delayedRead);
        fault_.delayedReadShard.reset();
      }
    }
    if (delay) {
      delay->started = true;
      delay->entered.set_value();
      co_await delay->resume;
    }
    // Delay the real server handler; never supply synthetic successful data.
    co_return co_await StorageService::readEcBlockV2(ctx, req);
  }

  CoTryTask<EcHelperHopRsp> executeEcHelper(serde::CallContext &ctx, const EcHelperHopReq &request) {
    std::shared_ptr<StageReplyDropState::ConcurrentWindow> window;
    {
      std::lock_guard lock(fault_.mutex);
      if (fault_.concurrentWindow && fault_.concurrentWindow->helper && request.packet.blockIndex == 1 &&
          request.packet.nextHelper < 10 &&
          serde::serialize(request.plan) == serde::serialize(fault_.concurrentWindow->plan)) {
        window = fault_.concurrentWindow;
      }
    }
    if (window) {
      const auto position = request.packet.nextHelper;
      bool success = false, busy = false;
      {
        std::lock_guard lock(window->mutex);
        ++window->state.helperEntered[position];
        if (position == 0 && !window->firstHop) window->firstHop = ctx.transport();
        if (position == 4) window->state.held = true;
      }
      auto finished = folly::makeGuard([&] {
        std::lock_guard lock(window->mutex);
        ++window->state.helperFinished[position];
        window->state.helperSucceeded[position] += success;
        window->state.helperBusy[position] += busy;
        window->changed.notify_all();
      });
      window->changed.notify_all();
      if (position == 4) {
        window->entered.post();
        co_await window->resume;
      }
      auto result = co_await StorageService::executeEcHelper(ctx, request);
      success = result && result->result;
      busy = result && !result->result && result->result.error().code() == StorageClientCode::kResourceBusy;
      co_return result;
    }
    std::shared_ptr<StageReplyDropState::ReadDelay> delay;
    {
      std::lock_guard lock(fault_.mutex);
      if (request.packet.nextHelper < 10) ++fault_.helperHopCalls[request.packet.nextHelper];
      if (fault_.helperDelayPosition && *fault_.helperDelayPosition == request.packet.nextHelper) {
        delay = std::move(fault_.delayedHelper);
        fault_.helperDelayPosition.reset();
      }
    }
    if (delay) {
      delay->entered.set_value();
      co_await delay->resume;
    }
    co_return co_await StorageService::executeEcHelper(ctx, request);
  }
  CoTryTask<EcStageV2Rsp> beginEcStageV2(serde::CallContext &ctx, const EcBeginStageV2Req &request) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.beginCalls;
    }
    auto result = co_await StorageService::beginEcStageV2(ctx, request);
    std::shared_ptr<StageReplyDropState::ReadDelay> delay;
    if (result && result->result) {
      std::lock_guard lock(fault_.mutex);
      if (!fault_.delayedBegins.empty()) {
        delay = fault_.delayedBegins.front();
        fault_.delayedBegins.erase(fault_.delayedBegins.begin());
      }
    }
    if (delay) {
      delay->entered.set_value();
      co_await delay->resume;
    }
    co_return result;
  }

  CoTryTask<EcStageV2Rsp> queryEcStageV2(serde::CallContext &ctx, const EcQueryStageV2Req &request) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.queryCalls;
    }
    co_return co_await StorageService::queryEcStageV2(ctx, request);
  }
  CoTryTask<EcStageV2Rsp> reconcileEcStageV2(serde::CallContext &ctx, const EcReconcileStageV2Req &request) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.reconcileCalls;
    }
    co_return co_await StorageService::reconcileEcStageV2(ctx, request);
  }

  CoTryTask<EcStageV2Rsp> appendEcStageV2(serde::CallContext &ctx, const EcAppendStageV2Req &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.state.appendCalls;
    }
    auto response = co_await StorageService::appendEcStageV2(ctx, req);
    bool drop = false;
    if (response && response->result) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.appendRequest && StageReplyDropState::sameStage(*fault_.appendRequest, req.request) &&
          fault_.appendBlock == req.blockIndex) {
        // The real Engine has synced data and its progress WAL before success.
        // A failed/pending handler never consumes this one-shot injection.
        fault_.state.droppedAppend = *response->result;
        fault_.appendRequest.reset();
        drop = true;
      }
    }
    if (drop) {
      std::shared_ptr<StageReplyDropState::ConcurrentWindow> window;
      {
        std::lock_guard lock(fault_.mutex);
        window = fault_.concurrentWindow;
      }
      if (window) {
        // The actual Append has succeeded. Wait until the other block is
        // really in a remote handler before disconnecting this shared socket.
        co_await window->entered;
        const auto transport = ctx.transport();
        {
          std::lock_guard lock(window->mutex);
          window->state.sameConnection = window->firstHop == transport;
        }
        // invalidate alone cannot close TCP while held CallContexts (and this
        // window) keep the Transport alive. Shut down this real connection,
        // without closing/reusing its fd or changing production cancellation.
        const bool tcp = transport->isTCP();
        int shutdownResult = -1, shutdownErrno = ENOTSOCK;
        if (tcp) {
          const auto &handler = static_cast<const net::EventLoop::EventHandler &>(*transport);
          shutdownResult = ::shutdown(handler.fd(), SHUT_RDWR);
          shutdownErrno = shutdownResult < 0 ? errno : 0;
        }
        transport->invalidate(false);
        {
          std::lock_guard lock(window->mutex);
          window->state.tcpConnection = tcp;
          window->state.shutdownResult = shutdownResult;
          window->state.shutdownErrno = shutdownErrno;
          window->state.dropped = true;
          window->changed.notify_all();
        }
      } else {
        ctx.transport()->invalidate(false);
      }
    }
    co_return response;
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
      if (fault_.armed && (!fault_.sealRequest || StageReplyDropState::sameStage(*fault_.sealRequest, req.request))) {
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
  virtual void configureEcAuthorization() {
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
    // StorageServer installs Components::getCoroutinesPool independently of
    // group.processor.max_coroutines_num. Colocated ten-hop helpers retain a
    // pool slot while awaiting downstream; exercise that exact dispatch path.
    if (config_.storage().enable_ec_helpers()) config_.coroutines_pool_default().set_coroutines_num(128);
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
      group.processor().set_max_processing_requests_num(config_.storage().enable_ec_helpers() ? 128 : 16);
      group.processor().set_max_coroutines_num(config_.storage().enable_ec_helpers() ? 128 : 16);
      group.processor().set_response_compression_level(0);
    }
    server_ = std::make_unique<net::Server>(serverConfig_);
    ASSERT_OK(server_->addSerdeService(
        std::make_unique<StageReplyDropStorageService>(components_->storageOperator, replyDrop_),
        true));
    ASSERT_OK(server_->setup());
    ASSERT_NO_FATAL_FAILURE(startProductionHelperDispatch());
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
    // The network has joined every request, including queued handlers. Only
    // then stop its custom dispatch pool, before destroying borrowed targets.
    if (components_ && helperDispatchStarted_) {
      auto stoppedPool = components_->defaultPool.stopAndJoin();
      EXPECT_TRUE(stoppedPool) << stoppedPool.error().describe();
      helperDispatchStarted_ = false;
    }
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

  void startProductionHelperDispatch() {
    if (!config_.storage().enable_ec_helpers()) return;
    ASSERT_FALSE(helperDispatchStarted_);
    ASSERT_EQ(config_.coroutines_pool_default().coroutines_num(), 128);
    ASSERT_OK(components_->defaultPool.start());
    helperDispatchStarted_ = true;
    size_t selected = 0;
    for (auto &group : server_->groups()) {
      if (!group->serviceNameList().contains("StorageSerde")) continue;
      ++selected;
      group->setCoroutinesPoolGetter([this](const serde::MessagePacket<> &packet) -> DynamicCoroutinesPool & {
        if (packet.serviceId == StorageSerde<>::kServiceID) {
          if (packet.methodId == StorageSerde<>::executeEcHelperMethodId) ++helperDispatches_;
          // This is the production Components routing function, not a
          // test-only decision duplicating its method classification.
          return components_->getCoroutinesPool(packet.methodId);
        }
        return components_->defaultPool;
      });
    }
    ASSERT_EQ(selected, 1);
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
  bool helperDispatchStarted_ = false;
  std::atomic<size_t> helperDispatches_{0};
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
  auto physical = components_->targetMap.getByTargetId(targetId_);
  ASSERT_OK(physical);
  auto target = (*physical)->storageTarget;
  EcStageRequest query;
  query.operation = EcStageOperation::Query;
  query.identity = request.identity;
  query.vChainId = request.vChainId;
  query.targetId = request.targetId;
  query.operationId = request.operationId;
  query.integrity = request.integrity;
  const auto usedBefore = target->usedSize();
  ASSERT_ERROR(target->executeEcStage(query), StorageCode::kChunkMetadataNotFound);
  auto restoreClock = folly::makeGuard([&] {
    StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  });
  // Retain this existing pre-mutation injection. Its ordinal is tied to the
  // current admission checks; the assertions below prove no stage was created.
  auto calls = std::make_shared<std::atomic<unsigned>>(0);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator,
                                               [calls] { return ++*calls >= 4 ? uint64_t{1100} : uint64_t{1000}; });
  ASSERT_ERROR(blockingWait(client_->beginEcStageV2({request, token})), StatusCode::kAuthenticationFail);
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  ASSERT_ERROR(blockingWait(client_->queryEcStageV2({request, token})), StorageCode::kChunkMetadataNotFound);
  EXPECT_EQ(target->usedSize(), usedBefore);
  ASSERT_OK(blockingWait(client_->beginEcStageV2({request, token})));
  ASSERT_NO_FATAL_FAILURE(appendAll(request, token, original));
  auto active = target->executeEcStage(query);
  ASSERT_OK(active);
  ASSERT_TRUE(active->state);
  ASSERT_EQ(active->state->state, 1);
  ASSERT_EQ(active->state->prefix_bytes, original.size());
  ASSERT_FALSE(active->state->pending_block);
  const auto activeRevision = active->state->revision;
  EXPECT_EQ(target->usedSize(), usedBefore);

  auto observedActive = std::make_shared<std::atomic<bool>>(false);
  auto observedSealed = std::make_shared<std::atomic<bool>>(false);
  auto invalidObservation = std::make_shared<std::atomic<bool>>(false);
  // Auth callbacks run before stage execution or after it has returned. This
  // direct, read-only query neither re-enters auth nor holds a seal slot lock.
  // Query observes the event; it is not a fresh durability acknowledgment.
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator,
                                               [target, query, observedActive, observedSealed, invalidObservation] {
                                                 auto observed = target->executeEcStage(query);
                                                 if (!observed || !observed->state) {
                                                   invalidObservation->store(true);
                                                   return uint64_t{1100};
                                                 }
                                                 if (observed->state->state == 1) {
                                                   observedActive->store(true);
                                                   return uint64_t{1000};
                                                 }
                                                 if (observed->state->state == 2) {
                                                   observedSealed->store(true);
                                                   return uint64_t{1100};
                                                 }
                                                 invalidObservation->store(true);
                                                 return uint64_t{1100};
                                               });
  auto expiredSeal = blockingWait(client_->sealEcStageV2({request, token}));
  StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
  ASSERT_ERROR(expiredSeal, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_TRUE(observedActive->load());
  EXPECT_TRUE(observedSealed->load());
  EXPECT_FALSE(invalidObservation->load());
  auto state = blockingWait(client_->queryEcStageV2({request, token}));
  ASSERT_OK(state);
  EXPECT_EQ(state->state, 2);
  EXPECT_GT(state->revision, activeRevision);
  EXPECT_EQ(state->prefixBytes, original.size());
  EXPECT_FALSE(state->pendingBlock);
  const auto committedAfterSeal = target->usedSize();
  // Engine accounting uses the allocator size class, not logical byte length.
  EXPECT_GE(committedAfterSeal, usedBefore + original.size());
  ASSERT_OK(blockingWait(client_->reconcileEcStageV2({request, token})));
  ASSERT_OK(blockingWait(client_->sealEcStageV2({request, token})));
  EXPECT_EQ(target->usedSize(), committedAfterSeal);
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
  client::EcRpcObservation observation;
  control.observation = &observation;
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  auto result = blockingWait(client_->readEcBlockV2Controlled(read, control));
  ASSERT_OK(result);
  EXPECT_EQ(result->payload.data, original);
  auto sizes = observation.snapshot().at(client::EcRpcMethod::Read);
  EXPECT_EQ(sizes.observedEncodedRequestFrames, 1);
  EXPECT_EQ(sizes.observedEncodedResponseFrames, 1);
  EXPECT_GT(sizes.requestFrameBytes, 8);
  EXPECT_GT(sizes.responseFrameBytes, 8);
  control.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
  ASSERT_ERROR(blockingWait(client_->readEcBlockV2Controlled(read, control)), StorageClientCode::kTimeout);
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  CancellationSource cancel;
  cancel.requestCancellation();
  control.cancellation = cancel.getToken();
  ASSERT_ERROR(blockingWait(client_->readEcBlockV2Controlled(read, control)), StorageClientCode::kRequestCanceled);
  // Early control rejection precedes messenger entry and cannot fabricate bytes.
  sizes = observation.snapshot().at(client::EcRpcMethod::Read);
  EXPECT_EQ(sizes.entered, 1);
  EXPECT_EQ(sizes.observedEncodedRequestFrames, 1);
  EXPECT_EQ(sizes.observedEncodedResponseFrames, 1);

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
  sizes = observation.snapshot().at(client::EcRpcMethod::Read);
  EXPECT_EQ(sizes.active, 0);
  EXPECT_EQ(sizes.observedEncodedRequestFrames, 2);
  EXPECT_EQ(sizes.observedEncodedResponseFrames, 1);
  EXPECT_EQ(sizes.missingEncodedResponseFrames, 1);
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

// Twelve logical targets share one real Engine and one physical failure domain.
// Helper RPCs still traverse TCP at every hop, including ten distinct target
// incarnations. This fixture does not claim a twelve-node or RDMA experiment.
class TestEcNativeRepairService : public TestEcStageService {
 protected:
  void configureEcAuthorization() override {
    TestEcStageService::configureEcAuthorization();
    const auto path = traces_.path() / "helper.key";
    std::array<uint8_t, 32> bytes;
    for (size_t i = 0; i != bytes.size(); ++i) bytes[i] = i + 91;
    const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::write(fd, bytes.data(), bytes.size()), ssize_t(bytes.size()));
    ASSERT_EQ(::close(fd), 0);
    config_.storage().set_enable_ec_helpers(true);
    config_.storage().set_ec_helper_key_file(path);
  }
  void SetUp() override {
    TestEcStageService::SetUp();
    if (HasFatalFailure()) return;
    auto key = EcHelperKey::loadFile(std::filesystem::path(config_.storage().ec_helper_key_file().string()));
    ASSERT_OK(key);
    helperKey_ = std::move(*key);
    // The alias never outlives this fixture's owned fake routing source.
    components_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(mgmtd_.get(), [](auto *) {}));
    auto next = std::make_shared<flat::RoutingInfo>(*routing_);
    for (uint16_t i = 0; i != 12; ++i) {
      const TargetId id(1000 + i);
      const ChainId chainId(2000 + i);
      EcCreateTargetReq create;
      create.settings.targetId = id;
      create.settings.chainId = chainId;
      create.settings.onlyChunkEngine = true;
      ASSERT_OK(blockingWait(client_->createEcTarget(nodeId_, create)));
      flat::TargetInfo target;
      target.targetId = id;
      target.chainId = chainId;
      target.nodeId = nodeId_;
      target.diskIndex = 0;
      target.publicState = flat::PublicTargetState::SERVING;
      target.localState = flat::LocalTargetState::UPTODATE;
      next->targets[id] = target;
      flat::ChainInfo chain;
      chain.chainId = chainId;
      chain.chainVersion = ChainVer(1);
      flat::ChainTargetInfo member;
      member.targetId = id;
      member.publicState = flat::PublicTargetState::SERVING;
      chain.targets.push_back(member);
      next->chains[chainId] = chain;
      auto loaded = components_->targetMap.getByTargetId(id);
      ASSERT_OK(loaded);
      auto scope = (*loaded)->storageTarget->ecScopeState();
      ASSERT_OK(scope);
      endpoints_[i].nodeId = nodeId_;
      endpoints_[i].chainId = chainId;
      endpoints_[i].targetId = id;
      std::copy(scope->second.engine.begin(), scope->second.engine.end(), std::begin(endpoints_[i].engineUuid.data));
      std::copy(scope->second.incarnation.begin(),
                scope->second.incarnation.end(),
                std::begin(endpoints_[i].targetIncarnation.data));
    }
    next->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
    routing_ = next;
    mgmtd_->setRoutingInfo(next);
    ASSERT_OK(components_->targetMap.updateRouting(mgmtd_->getRoutingInfo()));
  }
  void reopenStorage() {
    // Exercise actual RocksDB/Engine reopen and restored target incarnations.
    // Call only after all RPCs have completed; no live target lease is retained.
    server_->stopAndJoin();
    server_.reset();
    ASSERT_TRUE(helperDispatchStarted_);
    ASSERT_OK(components_->defaultPool.stopAndJoin());
    helperDispatchStarted_ = false;
    ASSERT_OK(components_->storageOperator.stopAndJoin());
    operatorInitialized_ = false;
    {
      auto map = components_->targetMap.release();
      ASSERT_NE(map, nullptr);
      for (const auto &[id, target] : map->getTargets()) {
        if (target.storageTarget) ASSERT_OK(target.storageTarget->release());
      }
    }
    ASSERT_OK(components_->storageTargets.globalFileStore().clear(loader_));
    components_.reset();
    components_ = std::make_unique<Components>(config_);
    components_->appInfo.nodeId = nodeId_;
    ASSERT_OK(components_->storageTargets.load(loader_));
    components_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(mgmtd_.get(), [](auto *) {}));
    ASSERT_OK(components_->targetMap.updateRouting(mgmtd_->getRoutingInfo()));
    ASSERT_OK(components_->storageOperator.init(1));
    operatorInitialized_ = true;
    StorageEcStageAuthorizationTestAccess::clock(components_->storageOperator, [] { return uint64_t{1000}; });
    server_ = std::make_unique<net::Server>(serverConfig_);
    ASSERT_OK(server_->addSerdeService(
        std::make_unique<StageReplyDropStorageService>(components_->storageOperator, replyDrop_),
        true));
    ASSERT_OK(server_->setup());
    ASSERT_NO_FATAL_FAILURE(startProductionHelperDispatch());
    flat::AppInfo app;
    app.nodeId = nodeId_;
    ASSERT_OK(server_->start(app));
    auto groups = server_->getServiceGroupInfos();
    for (auto &group : groups) {
      const auto loopback = std::find_if(group.endpoints.begin(), group.endpoints.end(), [](const auto &endpoint) {
        return endpoint.type == net::Address::TCP && endpoint.ipStr() == "127.0.0.1";
      });
      ASSERT_NE(loopback, group.endpoints.end());
      const auto endpoint = *loopback;
      group.endpoints.assign(1, endpoint);
      if (group.services.contains("StorageSerde")) address_ = endpoint;
    }
    auto next = std::make_shared<flat::RoutingInfo>(*routing_);
    next->nodes.at(nodeId_).app.serviceGroups = std::move(groups);
    next->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
    routing_ = next;
    mgmtd_->setRoutingInfo(next);
    ASSERT_OK(components_->targetMap.updateRouting(mgmtd_->getRoutingInfo()));
    for (const auto &expected : endpoints_) {
      auto loaded = components_->targetMap.getByTargetId(expected.targetId);
      ASSERT_OK(loaded);
      auto state = (*loaded)->storageTarget->ecScopeState();
      ASSERT_OK(state);
      Uuid engine = Uuid::zero(), incarnation = Uuid::zero();
      std::copy(state->second.engine.begin(), state->second.engine.end(), std::begin(engine.data));
      std::copy(state->second.incarnation.begin(), state->second.incarnation.end(), std::begin(incarnation.data));
      EXPECT_EQ(engine, expected.engineUuid);
      EXPECT_EQ(incarnation, expected.targetIncarnation);
    }
  }
  struct Case {
    repair_test::Data data;
    std::shared_ptr<const EcRepairPlan> plan;
    hf3fs::client::ec::EcRepairNativeBindings bindings;
    std::array<EcHelperCapability, 10> helpers;
  };
  Result<EcCapabilityV2> token(const EcRepairFragment &fragment,
                               const EcRepairPlanInput &plan,
                               uint16_t rights,
                               Uuid scope) {
    EcGrantClaimsV2 claims;
    claims.engineUuid = fragment.endpoint.engineUuid;
    claims.targetIncarnation = fragment.endpoint.targetIncarnation;
    claims.identity = fragment.identity;
    claims.fragmentOperationId = fragment.operationId;
    claims.chainId = fragment.endpoint.chainId;
    claims.targetId = fragment.endpoint.targetId;
    claims.nodeId = fragment.endpoint.nodeId;
    claims.expectedLength = fragment.integrity.wholeLength;
    claims.expectedCrc32c = fragment.integrity.wholeCrc32c;
    CHECK_RESULT(digest, digestEcIntegrityV2(fragment.identity, fragment.integrity));
    claims.integrityDigest = digest;
    claims.ownerUid = plan.ownerUid;
    claims.clientNamespace = plan.clientNamespace;
    claims.scopeObject = fragment.identity.object;
    claims.scopeKind = EcGrantScope::WriteOperation;
    claims.scopeId = scope;
    claims.rights = rights;
    claims.grantId = Uuid::random();
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = 1100;
    return signEcGrantV2(*signingKey_, claims, 1000);
  }
  EcFragmentAccessV2 access(const EcRepairFragment &fragment) {
    EcFragmentAccessV2 result;
    result.identity = fragment.identity;
    result.operationId = fragment.operationId;
    result.vChainId = {fragment.endpoint.chainId, ChainVer(1)};
    result.targetId = fragment.endpoint.targetId;
    result.integrity = fragment.integrity;
    return result;
  }
  Result<Case> prepare(std::vector<uint16_t> missing,
                       uint32_t length = kEcIntegrityBlockBytes + 7,
                       uint8_t window = 2,
                       uint64_t logicalLength = UINT64_MAX) {
    Case result;
    result.data = repair_test::makeData(length, missing, window, logicalLength);
    auto &input = result.data.input;
    std::copy(endpoints_.begin(), endpoints_.end(), input.operationEndpoints.begin());
    input.operationEndpointCount = 12;
    for (auto &fragment : input.sources) {
      fragment.endpoint = endpoints_[fragment.identity.shard];
      fragment.writerNamespace = input.clientNamespace;
    }
    for (size_t target = 0; target != input.targetCount; ++target) {
      input.targets[target].endpoint = endpoints_[input.targets[target].identity.shard];
    }
    CHECK_RESULT(plan, EcRepairPlan::create(input));
    result.plan = plan;
    for (uint8_t i = 0; i != 10; ++i) {
      const auto &fragment = input.sources[i];
      auto request = access(fragment);
      CHECK_RESULT(write, token(fragment, input, kEcGrantAllRightsV2, fragment.operationId));
      RETURN_ON_ERROR(blockingWait(client_->beginEcStageV2({request, write})));
      for (uint32_t block = 0; block != fragment.integrity.blockCount; ++block) {
        EcAppendStageV2Req append;
        append.request = request;
        append.grant = write;
        append.blockIndex = block;
        append.payload.data = repair_test::blockBytes(result.data, fragment, block);
        RETURN_ON_ERROR(blockingWait(client_->appendEcStageV2(append)));
      }
      RETURN_ON_ERROR(blockingWait(client_->sealEcStageV2({request, write})));
      CHECK_RESULT(read, token(fragment, input, uint16_t(EcGrantRightV2::ReadBlock), input.operationId));
      result.bindings.sources[i].request = request;
      result.bindings.sources[i].grant = read;
      CHECK_RESULT(claims, makeEcHelperClaims(*plan, i, uint16_t((1u << plan->blockCount()) - 1), 1000, 100));
      CHECK_RESULT(helper, signEcHelperGrant(*helperKey_, claims, 1000));
      result.helpers[i] = helper;
    }
    for (uint8_t i = 0; i != input.targetCount; ++i) {
      CHECK_RESULT(write, token(input.targets[i], input, kEcGrantAllRightsV2, input.operationId));
      result.bindings.targets[i] = {access(input.targets[i]), write};
    }
    return result;
  }
  EcHelperHopReq request(const Case &value, uint32_t block = 0) {
    EcHelperHopReq result;
    result.plan = value.plan->input();
    result.helpers = value.helpers;
    for (size_t i = 0; i != 10; ++i) {
      result.reads[i] = value.bindings.sources[i].grant;
      result.routeVersions[i] = ChainVer(1);
    }
    auto packet = EcRepairBlockCore::begin(*value.plan, block);
    EXPECT_TRUE(packet);
    result.packet = helperPacket(std::move(*packet));
    result.deadlineUnixMillis =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() +
        10000;
    return result;
  }
  client::EcRequestControl control() {
    return {std::chrono::steady_clock::now() + std::chrono::seconds(10),
            {},
            client::EcRequestControl::TransportPolicy::TcpOnly};
  }
  Result<uint64_t> committedBytes(const EcRepairFragment &fragment) {
    CHECK_RESULT(target, components_->targetMap.getByTargetId(fragment.endpoint.targetId));
    return target->storageTarget->usedSize();
  }
  void expectRecovered(const Case &value,
                       const hf3fs::client::ec::EcRepairSealed &sealed,
                       const std::array<uint64_t, 2> &before) {
    ASSERT_EQ(value.plan->shardBytes(), kEcIntegrityBlockBytes + 7);
    EXPECT_EQ(sealed.planDigest, value.plan->digest());
    ASSERT_EQ(sealed.targetCount, value.plan->input().targetCount);
    for (uint8_t target = 0; target != sealed.targetCount; ++target) {
      const auto &fragment = value.plan->input().targets[target];
      const auto &fixed = value.bindings.targets[target];
      EXPECT_TRUE(serde::equals(sealed.receipts[target], repair_test::receipt(fragment)));
      auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(state);
      EXPECT_EQ(state->state, 2);
      EXPECT_EQ(state->prefixBytes, fragment.integrity.wholeLength);
      EXPECT_FALSE(state->pendingBlock);
      EXPECT_FALSE(state->needsReconcile);
      std::string bytes;
      for (uint32_t block = 0; block != value.plan->blockCount(); ++block) {
        auto read = blockingWait(client_->readEcBlockV2Controlled({fixed.request, block, fixed.grant}, control()));
        ASSERT_OK(read);
        EXPECT_TRUE(serde::equals(read->receipt, sealed.receipts[target]));
        bytes += read->payload.data;
      }
      EXPECT_EQ(bytes, value.data.shards[fragment.identity.shard]);
      auto used = committedBytes(fragment);
      ASSERT_OK(used);
      // Used-size accounting is allocation capacity, not logical payload:
      // the 65543-byte fixture fits one 128 KiB slot, committed only at Seal.
      EXPECT_EQ(*used, before[target] + 2 * kEcIntegrityBlockBytes);
    }
  }
  std::unique_ptr<EcHelperKey> helperKey_;
  std::array<EcScopeEndpoint, 12> endpoints_;
};

TEST_F(TestEcNativeRepairService, ThreeNativeStrategiesRepairSingleAndDoubleTargetsThroughTcp) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  for (auto missing : {std::vector<uint16_t>{0}, std::vector<uint16_t>{0, 11}}) {
    for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
      SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(mode) << " missing=" << missing.size()
                                        << " window=2");
      auto value = prepare(missing);
      ASSERT_OK(value);
      auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers);
      ASSERT_OK(transport);
      const auto ctl = control();
      auto result = blockingWait(
          EcRepairPipeline::run(value->plan, *transport, mode, {ctl.deadline, ctl.cancellation}, executor));
      ASSERT_OK(result);
      for (uint8_t target = 0; target != value->plan->input().targetCount; ++target) {
        std::string bytes;
        for (uint32_t block = 0; block != value->plan->blockCount(); ++block) {
          EcReadBlockV2Req read{value->bindings.targets[target].request, block, value->bindings.targets[target].grant};
          auto actual = blockingWait(client_->readEcBlockV2Controlled(std::move(read), control()));
          ASSERT_OK(actual);
          bytes += actual->payload.data;
        }
        EXPECT_EQ(bytes, value->data.shards[value->plan->input().targets[target].identity.shard]);
      }
    }
  }
  std::lock_guard lock(replyDrop_.mutex);
  for (auto count : replyDrop_.helperHopCalls) EXPECT_EQ(count, 4);  // Two blocks, two erasure scenarios.
  EXPECT_EQ(helperDispatches_.load(), 40);  // Every nested TCP hop used the production pool getter.
  RecordProperty("helper_rpc_dispatch", "Components::getCoroutinesPool, started defaultPool128, real TCP hops");
}

TEST_F(TestEcNativeRepairService, ThreeStrategiesResumeOriginalPartialStagesAfterEngineReopen) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  constexpr std::array modes{EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain};
  std::vector<Case> cases;
  for (const auto mode : modes) {
    (void)mode;
    auto value = prepare({0, 11});
    ASSERT_OK(value);
    for (uint8_t target = 0; target != value->plan->input().targetCount; ++target) {
      const auto &fixed = value->bindings.targets[target];
      ASSERT_OK(blockingWait(client_->beginEcStageV2Controlled(fixed, control())));
      EcAppendStageV2Req append{fixed.request, 0, {}, fixed.grant};
      append.payload.data = repair_test::blockBytes(value->data, value->plan->input().targets[target], 0);
      auto progress = blockingWait(client_->appendEcStageV2Controlled(std::move(append), control()));
      ASSERT_OK(progress);
      ASSERT_EQ(progress->prefixBytes, kEcIntegrityBlockBytes);
      ASSERT_FALSE(progress->needsReconcile);
    }
    cases.push_back(std::move(*value));
  }
  ASSERT_NO_FATAL_FAILURE(reopenStorage());
  for (size_t index = 0; index != modes.size(); ++index) {
    SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(modes[index]) << " missing=2 window=2");
    auto &value = cases[index];
    for (uint8_t target = 0; target != value.plan->input().targetCount; ++target) {
      const auto &fixed = value.bindings.targets[target];
      auto observed = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(observed);
      ASSERT_EQ(observed->state, 1);
      ASSERT_EQ(observed->prefixBytes, kEcIntegrityBlockBytes);
      ASSERT_TRUE(observed->needsReconcile);  // The actual restored Rust slot is unknown.
    }
    auto transport = NativeEcRepairTransport::create(value.plan, client_, value.bindings, value.helpers);
    ASSERT_OK(transport);
    auto ctl = control();
    ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    auto repaired = blockingWait(
        EcRepairPipeline::run(value.plan, *transport, modes[index], {ctl.deadline, ctl.cancellation}, executor));
    ASSERT_OK(repaired);
    EXPECT_EQ(repaired->planDigest, value.plan->digest());
    for (uint8_t target = 0; target != value.plan->input().targetCount; ++target) {
      const auto &fixed = value.bindings.targets[target];
      EXPECT_TRUE(serde::equals(repaired->receipts[target].identity, fixed.request.identity));
      EXPECT_EQ(repaired->receipts[target].operationId, fixed.request.operationId);
      std::string bytes;
      for (uint32_t block = 0; block != value.plan->blockCount(); ++block) {
        auto read = blockingWait(client_->readEcBlockV2Controlled({fixed.request, block, fixed.grant}, control()));
        ASSERT_OK(read);
        bytes += read->payload.data;
      }
      EXPECT_EQ(bytes, value.data.shards[value.plan->input().targets[target].identity.shard]);
    }
  }
  // This fixture proves reopened Storage recovery plus real TCP/Seal/readback;
  // it does not contain Meta and is not a publication or power-failure test.
}

TEST_F(TestEcNativeRepairService, ThreeStrategiesRecoverLostAppendReplyOnOriginalStages) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  for (auto missing : {std::vector<uint16_t>{0}, std::vector<uint16_t>{0, 11}}) {
    for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
      SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(mode) << " missing=" << missing.size()
                                        << " window=1");
      // Isolate one lost mutation reply from unrelated multiplexed helper
      // calls. Existing window/held-helper cases cover concurrent ownership;
      // joining a client call alone never proves every remote hop has stopped.
      auto value = prepare(missing, kEcIntegrityBlockBytes + 7, 1);
      ASSERT_OK(value);
      std::array<uint64_t, 2> before{};
      for (uint8_t target = 0; target != value->plan->input().targetCount; ++target) {
        auto used = committedBytes(value->plan->input().targets[target]);
        ASSERT_OK(used);
        before[target] = *used;
      }
      EcRepairObservation observation;
      auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers, &observation);
      ASSERT_OK(transport);
      const auto &fixed = value->bindings.targets[0];
      replyDrop_.armAppend(fixed.request, 0);
      auto ctl = control();
      ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
      auto failed = blockingWait(EcRepairPipeline::run(
          value->plan, *transport, mode, {ctl.deadline, ctl.cancellation}, executor, &observation));
      ASSERT_ERROR(failed, StorageCode::kEcSealOutcomeUnknown);
      const auto dropped = replyDrop_.snapshot();
      ASSERT_EQ(dropped.appendCalls, 1);
      ASSERT_TRUE(dropped.droppedAppend);
      EXPECT_EQ(dropped.sealCalls, 0);
      EXPECT_FALSE(dropped.droppedReceipt);
      EXPECT_TRUE(serde::equals(dropped.droppedAppend->receipt, repair_test::receipt(value->plan->input().targets[0])));
      EXPECT_EQ(dropped.droppedAppend->state, 1);
      EXPECT_EQ(dropped.droppedAppend->prefixBytes, kEcIntegrityBlockBytes);
      EXPECT_FALSE(dropped.droppedAppend->pendingBlock);
      EXPECT_FALSE(dropped.droppedAppend->needsReconcile);
      // These are joined local coroutine frames, not a distributed T2 claim.
      const auto joined = observation.snapshot();
      for (const auto &point : joined.points) {
        EXPECT_EQ(point.active, 0);
        EXPECT_EQ(point.entered, point.finished);
      }
      EXPECT_EQ(joined.at(EcRepairPoint::NativeSeal).entered, 0);
      const auto &appendFrames = joined.storageRpc.at(client::EcRpcMethod::Append);
      EXPECT_EQ(appendFrames.active, 0);
      EXPECT_EQ(appendFrames.observedEncodedRequestFrames, 1);
      EXPECT_EQ(appendFrames.missingEncodedRequestFrames, 0);
      EXPECT_GT(appendFrames.requestFrameBytes, 8);
      EXPECT_EQ(appendFrames.observedEncodedResponseFrames, 0);
      EXPECT_EQ(appendFrames.missingEncodedResponseFrames, 1);
      EXPECT_EQ(appendFrames.responseFrameBytes, 0);  // The server committed; its reply was not observed.
      CancellationSource cancelled;
      cancelled.requestCancellation();
      ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {ctl.deadline, cancelled.getToken()})),
                   StorageCode::kEcSealOutcomeUnknown);
      for (uint8_t target = 0; target != value->plan->input().targetCount; ++target) {
        const auto &binding = value->bindings.targets[target];
        auto state = blockingWait(client_->queryEcStageV2Controlled({binding.request, binding.grant}, control()));
        ASSERT_OK(state);
        EXPECT_EQ(state->state, 1);  // No Abort, Seal or replacement allocation.
        EXPECT_TRUE(serde::equals(state->receipt, repair_test::receipt(value->plan->input().targets[target])));
        EXPECT_EQ(state->prefixBytes, target == 0 ? kEcIntegrityBlockBytes : 0);
        EXPECT_FALSE(state->pendingBlock);
        EXPECT_FALSE(state->needsReconcile);
        auto used = committedBytes(value->plan->input().targets[target]);
        ASSERT_OK(used);
        EXPECT_EQ(*used, before[target]);
      }
      // An external Query sees committed progress, but cannot resolve this
      // adapter's unknown mutation. Recovery must execute Query AND Reconcile.
      ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {ctl.deadline, cancelled.getToken()})),
                   StorageCode::kEcSealOutcomeUnknown);
      size_t queries, reconciles;
      {
        std::lock_guard lock(replyDrop_.mutex);
        queries = replyDrop_.queryCalls;
        reconciles = replyDrop_.reconcileCalls;
      }
      ctl = control();
      ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
      const EcRepairControl live{ctl.deadline, ctl.cancellation};
      ASSERT_OK(blockingWait((*transport)->begin(value->plan, 0, live)));
      {
        std::lock_guard lock(replyDrop_.mutex);
        EXPECT_EQ(replyDrop_.queryCalls, queries + 1);
        EXPECT_EQ(replyDrop_.reconcileCalls, reconciles + 1);
      }
      // Exact duplicate block replay must retain progress/revision and use
      // the original reservation, before the full pipeline resumes block 1.
      auto reconciled = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(reconciled);
      auto bytes = repair_test::blockBytes(value->data, value->plan->input().targets[0], 0);
      ASSERT_OK(blockingWait((*transport)->append(value->plan, 0, 0, std::move(bytes), live)));
      auto replayed = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(replayed);
      EXPECT_TRUE(serde::equals(*replayed, *reconciled));
      auto repaired = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor, &observation));
      ASSERT_OK(repaired);
      const auto recoveredRpc = observation.snapshot().storageRpc;
      for (auto method : {client::EcRpcMethod::Query, client::EcRpcMethod::Reconcile}) {
        const auto &frames = recoveredRpc.at(method);
        EXPECT_GT(frames.observedEncodedRequestFrames, 0);
        EXPECT_EQ(frames.observedEncodedRequestFrames, frames.entered);
        EXPECT_EQ(frames.observedEncodedResponseFrames, frames.entered);
        EXPECT_GT(frames.requestFrameBytes, 8);
        EXPECT_GT(frames.responseFrameBytes, 8);
      }
      EXPECT_EQ(replyDrop_.snapshot().sealCalls, value->plan->input().targetCount);
      ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repaired, before));
      // All original allocations remain replayable; a new operation is never
      // substituted to hide an unknown result or duplicate additive accounting.
      auto repeated = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor));
      ASSERT_OK(repeated);
      ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repeated, before));
    }
  }
  RecordProperty("unknown_append_fault_cut",
                 "real successful Append reply dropped over TCP; two blocks, window=1; three strategies, one/two targets");
  RecordProperty("unknown_append_join_scope", "local pipeline/adapter frames only; no distributed drain claim");
}

TEST_F(TestEcNativeRepairService, WindowTwoLostAppendReplyRecoversBothOriginalTargets) {
  using namespace hf3fs::client::ec;
  // These are the fixture's existing defaults, not a production cancellation
  // policy change. Check the actual server-side connection identity below too.
  ASSERT_FALSE(clientConfig_.create_net_client_for_updates());
  ASSERT_EQ(clientConfig_.net_client().io_worker().transport_pool().max_connections(), 1);
  folly::CPUThreadPoolExecutor executor(2);
  for (auto mode : {EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
    SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(mode) << " missing=2 window=2");
    auto value = prepare({0, 11}, kEcIntegrityBlockBytes + 7, 2);
    ASSERT_OK(value);
    std::array<uint64_t, 2> before{};
    for (uint8_t target = 0; target != 2; ++target) {
      auto used = committedBytes(value->plan->input().targets[target]);
      ASSERT_OK(used);
      before[target] = *used;
    }
    EcRepairObservation observation;
    auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers, &observation);
    ASSERT_OK(transport);
    auto window = std::make_shared<StageReplyDropState::ConcurrentWindow>();
    window->plan = value->plan->input();
    window->sourceRequest = value->bindings.sources[0].request;
    window->helper = mode == EcRepairMode::HelperChain;
    const auto &unknown = value->bindings.targets[1];
    replyDrop_.armAppend(unknown.request, 0);
    {
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.concurrentWindow = window;
    }
    auto ctl = control();
    ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    std::future<Result<EcRepairSealed>> running;
    SCOPE_EXIT {
      // Failure cleanup releases both test barriers and joins the local call.
      // Remote handlers keep their shared window alive. The fixture then joins
      // the real default dispatch pool and helper sessions before targets go;
      // this fallback is not the successful per-handler completion proof below.
      window->unblock();
      if (running.valid()) running.wait();
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.concurrentWindow.reset();
    };
    running = std::async(std::launch::async, [&] {
      return blockingWait(EcRepairPipeline::run(
          value->plan, *transport, mode, {ctl.deadline, ctl.cancellation}, executor, &observation));
    });
    ASSERT_TRUE(window->waitFor([](const auto &s) { return s.held && s.dropped; }));
    ASSERT_TRUE(window->snapshot().sameConnection);
    const auto disconnected = window->snapshot();
    RecordProperty(fmt::format("window_two_tcp_shutdown_{}", static_cast<unsigned>(mode)),
                   fmt::format("tcp={},result={},errno={}", disconnected.tcpConnection,
                               disconnected.shutdownResult, disconnected.shutdownErrno));
    ASSERT_TRUE(disconnected.tcpConnection);
    ASSERT_EQ(disconnected.shutdownResult, 0) << "shutdown errno=" << disconnected.shutdownErrno;
    ASSERT_EQ(running.wait_for(std::chrono::seconds(10)), std::future_status::ready);
    auto failed = running.get();
    ASSERT_ERROR(failed, StorageCode::kEcSealOutcomeUnknown);
    const auto dropped = replyDrop_.snapshot();
    ASSERT_EQ(dropped.appendCalls, 2);  // target 0 ACK, then target 1's real committed reply was lost.
    ASSERT_TRUE(dropped.droppedAppend);
    EXPECT_TRUE(serde::equals(dropped.droppedAppend->receipt, repair_test::receipt(value->plan->input().targets[1])));
    EXPECT_EQ(dropped.droppedAppend->prefixBytes, kEcIntegrityBlockBytes);
    EXPECT_FALSE(dropped.droppedAppend->pendingBlock);
    EXPECT_FALSE(dropped.droppedAppend->needsReconcile);
    EXPECT_EQ(dropped.sealCalls, 0);
    const auto joined = observation.snapshot();
    EXPECT_EQ(joined.at(EcRepairPoint::BlockActor).peakActive, 2);
    for (const auto &point : joined.points) {
      EXPECT_EQ(point.active, 0);
      EXPECT_EQ(point.entered, point.finished);
    }
    EXPECT_EQ(joined.at(EcRepairPoint::NativeSeal).entered, 0);
    const auto remote = window->snapshot();
    if (window->helper) {
      // The client has joined, but upstream hops still await the held hop 4.
      for (size_t hop = 0; hop != 5; ++hop) {
        EXPECT_EQ(remote.helperEntered[hop], 1);
        EXPECT_EQ(remote.helperFinished[hop], 0);
      }
      for (size_t hop = 5; hop != 10; ++hop) EXPECT_EQ(remote.helperEntered[hop], 0);
    } else {
      EXPECT_EQ(remote.readEntered, 1);
      EXPECT_EQ(remote.readFinished, 0);
    }
    CancellationSource cancelled;
    cancelled.requestCancellation();
    ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {ctl.deadline, cancelled.getToken()})),
                 StorageClientCode::kRequestCanceled);
    ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 1, {ctl.deadline, cancelled.getToken()})),
                 StorageCode::kEcSealOutcomeUnknown);
    for (uint8_t target = 0; target != 2; ++target) {
      const auto &binding = value->bindings.targets[target];
      auto state = blockingWait(client_->queryEcStageV2Controlled({binding.request, binding.grant}, control()));
      ASSERT_OK(state);
      EXPECT_EQ(state->state, 1);
      EXPECT_EQ(state->prefixBytes, kEcIntegrityBlockBytes);
      EXPECT_FALSE(state->pendingBlock);
      EXPECT_FALSE(state->needsReconcile);
      EXPECT_TRUE(serde::equals(state->receipt, repair_test::receipt(value->plan->input().targets[target])));
      auto used = committedBytes(value->plan->input().targets[target]);
      ASSERT_OK(used);
      EXPECT_EQ(*used, before[target]);
    }
    size_t queries, reconciles;
    {
      std::lock_guard lock(replyDrop_.mutex);
      queries = replyDrop_.queryCalls;
      reconciles = replyDrop_.reconcileCalls;
    }
    const EcRepairControl live{ctl.deadline, {}};
    ASSERT_OK(blockingWait((*transport)->begin(value->plan, 0, live)));
    ASSERT_OK(blockingWait((*transport)->begin(value->plan, 1, live)));
    {
      std::lock_guard lock(replyDrop_.mutex);
      EXPECT_EQ(replyDrop_.queryCalls, queries + 1);
      EXPECT_EQ(replyDrop_.reconcileCalls, reconciles + 1);
    }
    // Target reconciliation is not a remote helper barrier. One intentional
    // duplicate is rejected while the original block still owns its window.
    if (window->helper) {
      ASSERT_ERROR(blockingWait(client_->executeEcHelper(request(*value, 1), control())),
                   StorageClientCode::kResourceBusy);
      const auto busy = window->snapshot();
      EXPECT_EQ(busy.helperEntered[0], 2);
      EXPECT_EQ(busy.helperFinished[0], 1);
      EXPECT_EQ(busy.helperBusy[0], 1);
      EXPECT_EQ(busy.helperSucceeded[0], 0);
      EXPECT_EQ(busy.helperFinished[4], 0);
    } else {
      EXPECT_EQ(window->snapshot().readFinished, 0);
    }
    window->unblock();
    // Do not retry through Busy. Wait for the actual old request tree to
    // succeed and leave every entered handler, including its first hop. An
    // expired/failed helper chain cannot satisfy these counts.
    ASSERT_TRUE(window->waitFor([&](const auto &s) {
      if (!window->helper) return s.readEntered == 1 && s.readFinished == 1 && s.readSucceeded == 1;
      for (size_t hop = 0; hop != 10; ++hop) {
        const size_t expected = hop == 0 ? 2 : 1;
        if (s.helperEntered[hop] != expected || s.helperFinished[hop] != expected ||
            s.helperSucceeded[hop] != 1 || s.helperBusy[hop] != (hop == 0 ? 1u : 0u)) {
          return false;
        }
      }
      return true;
    }));
    {
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.concurrentWindow.reset();
    }
    auto repaired = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor));
    ASSERT_OK(repaired);
    EXPECT_EQ(replyDrop_.snapshot().sealCalls, 2);
    ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repaired, before));
    auto repeated = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor));
    ASSERT_OK(repeated);
    ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repeated, before));
  }
  RecordProperty("window_two_unknown_append",
                 "real target1/block0 Append ACK lost on shared TCP while block1 Read/helper hop4 is held");
  RecordProperty("window_two_completion_scope",
                 "local actors joined before remote release; real old handler completion before same-plan recovery; no T2");
}

TEST_F(TestEcNativeRepairService, ThreeStrategiesRecoverLostSealReplyAfterEngineReopen) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
    SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(mode) << " missing=2 window=2");
    auto value = prepare({0, 11});
    ASSERT_OK(value);
    std::array<uint64_t, 2> before{};
    for (uint8_t target = 0; target != 2; ++target) {
      auto used = committedBytes(value->plan->input().targets[target]);
      ASSERT_OK(used);
      before[target] = *used;
    }
    EcRepairObservation observation;
    auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers, &observation);
    ASSERT_OK(transport);
    replyDrop_.arm(value->bindings.targets[0].request);
    auto ctl = control();
    ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    auto failed = blockingWait(EcRepairPipeline::run(
        value->plan, *transport, mode, {ctl.deadline, ctl.cancellation}, executor, &observation));
    ASSERT_ERROR(failed, StorageCode::kEcSealOutcomeUnknown);
    const auto dropped = replyDrop_.snapshot();
    ASSERT_EQ(dropped.appendCalls, 2 * value->plan->blockCount());
    ASSERT_EQ(dropped.sealCalls, 1);
    ASSERT_TRUE(dropped.droppedReceipt);
    EXPECT_TRUE(serde::equals(*dropped.droppedReceipt, repair_test::receipt(value->plan->input().targets[0])));
    const auto sealFrames = observation.snapshot().storageRpc.at(client::EcRpcMethod::Seal);
    EXPECT_EQ(sealFrames.active, 0);
    EXPECT_EQ(sealFrames.observedEncodedRequestFrames, 1);
    EXPECT_EQ(sealFrames.missingEncodedRequestFrames, 0);
    EXPECT_GT(sealFrames.requestFrameBytes, 8);
    EXPECT_EQ(sealFrames.observedEncodedResponseFrames, 0);
    EXPECT_EQ(sealFrames.missingEncodedResponseFrames, 1);
    EXPECT_EQ(sealFrames.responseFrameBytes, 0);
    for (const auto &point : observation.snapshot().points) {
      EXPECT_EQ(point.active, 0);
      EXPECT_EQ(point.entered, point.finished);
    }
    for (uint8_t target = 0; target != 2; ++target) {
      const auto &fixed = value->bindings.targets[target];
      auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(state);
      EXPECT_EQ(state->state, target == 0 ? 2 : 1);
      EXPECT_EQ(state->prefixBytes, value->plan->shardBytes());
      EXPECT_FALSE(state->pendingBlock);
      EXPECT_FALSE(state->needsReconcile);
      auto used = committedBytes(value->plan->input().targets[target]);
      ASSERT_OK(used);
      EXPECT_EQ(*used, before[target] + (target == 0 ? 2 * kEcIntegrityBlockBytes : 0));
    }
    CancellationSource cancelled;
    cancelled.requestCancellation();
    ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {ctl.deadline, cancelled.getToken()})),
                 StorageCode::kEcSealOutcomeUnknown);
    ASSERT_NO_FATAL_FAILURE(reopenStorage());  // Real handler/worker joins, RocksDB close and original-disk reopen.
    for (uint8_t target = 0; target != 2; ++target) {
      const auto &fixed = value->bindings.targets[target];
      auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
      ASSERT_OK(state);
      EXPECT_EQ(state->state, target == 0 ? 2 : 1);
      EXPECT_EQ(state->prefixBytes, value->plan->shardBytes());
      EXPECT_TRUE(state->needsReconcile);
      EXPECT_TRUE(serde::equals(state->receipt, repair_test::receipt(value->plan->input().targets[target])));
    }
    size_t queries, reconciles;
    {
      std::lock_guard lock(replyDrop_.mutex);
      queries = replyDrop_.queryCalls;
      reconciles = replyDrop_.reconcileCalls;
    }
    ctl = control();
    ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const EcRepairControl live{ctl.deadline, ctl.cancellation};
    auto repaired = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor, &observation));
    ASSERT_OK(repaired);
    {
      std::lock_guard lock(replyDrop_.mutex);
      EXPECT_EQ(replyDrop_.queryCalls, queries + 2);
      EXPECT_EQ(replyDrop_.reconcileCalls, reconciles + 2);
    }
    // The original sealed target skips Append but still obtains a fresh Seal;
    // the second target replays its exact two blocks before its first Seal.
    EXPECT_EQ(replyDrop_.snapshot().appendCalls, dropped.appendCalls + value->plan->blockCount());
    EXPECT_EQ(replyDrop_.snapshot().sealCalls, dropped.sealCalls + 2);
    ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repaired, before));
    const auto appends = replyDrop_.snapshot().appendCalls;
    auto repeated = blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, live, executor));
    ASSERT_OK(repeated);
    EXPECT_EQ(replyDrop_.snapshot().appendCalls, appends);
    ASSERT_NO_FATAL_FAILURE(expectRecovered(*value, *repeated, before));
  }
  // This proves real Storage/TCP recovery, not Meta publication, journal
  // recovery, a power cut or a distributed no-further-effects certificate.
  RecordProperty("unknown_seal_fault_cut",
                 "real successful Seal reply dropped over TCP; two blocks, window=2; three strategies, two targets");
  RecordProperty("unknown_seal_recovery", "normal Storage stop/join and original-disk reopen; fixed plan and bindings");
}

TEST_F(TestEcNativeRepairService, UnknownSealSurvivesCancellationUntilSameStageIsReconciled) {
  using namespace hf3fs::client::ec;
  auto value = prepare({0}, 31);
  ASSERT_OK(value);
  auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers);
  ASSERT_OK(transport);
  auto ctl = control();
  EcRepairControl live{ctl.deadline, ctl.cancellation};
  ASSERT_OK(blockingWait((*transport)->begin(value->plan, 0, live)));
  const auto bytes = repair_test::blockBytes(value->data, value->plan->input().targets[0], 0);
  ASSERT_OK(blockingWait((*transport)->append(value->plan, 0, 0, bytes, live)));
  replyDrop_.arm();
  ASSERT_ERROR(blockingWait((*transport)->seal(value->plan, 0, live)), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.snapshot().droppedReceipt);
  CancellationSource stopped;
  stopped.requestCancellation();
  ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {live.deadline, stopped.getToken()})),
               StorageCode::kEcSealOutcomeUnknown);
  const auto &fixed = value->bindings.targets[0];
  auto observed = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
  ASSERT_OK(observed);
  ASSERT_EQ(observed->state, 2);
  ASSERT_FALSE(observed->needsReconcile);
  size_t queries, reconciles;
  {
    std::lock_guard lock(replyDrop_.mutex);
    queries = replyDrop_.queryCalls;
    reconciles = replyDrop_.reconcileCalls;
  }
  // A fresh Begin observation of Sealed still cannot clear this adapter's
  // previously observed unknown completion without the real Reconcile barrier.
  ctl = control();
  live = {ctl.deadline, ctl.cancellation};
  ASSERT_OK(blockingWait((*transport)->begin(value->plan, 0, live)));
  {
    std::lock_guard lock(replyDrop_.mutex);
    EXPECT_EQ(replyDrop_.queryCalls, queries + 1);
    EXPECT_EQ(replyDrop_.reconcileCalls, reconciles + 1);
  }
  auto sealed = blockingWait((*transport)->seal(value->plan, 0, live));
  ASSERT_OK(sealed);
  EXPECT_TRUE(serde::equals(sealed->identity, fixed.request.identity));
  ASSERT_ERROR(blockingWait((*transport)->begin(value->plan, 0, {live.deadline, stopped.getToken()})),
               StorageClientCode::kRequestCanceled);
}

TEST_F(TestEcNativeRepairService, RecoveryRequiresExplicitQueryAndReconcileRights) {
  using namespace hf3fs::client::ec;
  auto value = prepare({0}, 31);
  ASSERT_OK(value);
  constexpr auto writes =
      uint16_t(EcGrantRightV2::Begin) | uint16_t(EcGrantRightV2::Append) | uint16_t(EcGrantRightV2::Seal);
  for (auto omitted : {EcGrantRightV2::Query, EcGrantRightV2::Reconcile}) {
    auto bindings = value->bindings;
    const auto rights = writes | uint16_t(EcGrantRightV2::Query) | uint16_t(EcGrantRightV2::Reconcile);
    auto grant = token(value->plan->input().targets[0],
                       value->plan->input(),
                       uint16_t(rights & ~uint16_t(omitted)),
                       value->plan->input().operationId);
    ASSERT_OK(grant);
    bindings.targets[0].grant = *grant;
    ASSERT_ERROR(NativeEcRepairTransport::create(value->plan, client_, std::move(bindings), value->helpers),
                 StatusCode::kInvalidArg);
  }
}

TEST_F(TestEcNativeRepairService, WrongHopMacAndMissingReadCredentialFailThroughRealService) {
  auto value = prepare({0, 11}, 31, 1);
  ASSERT_OK(value);
  auto wire = request(*value);
  auto computed = EcRepairBlockCore::advance(*value->plan,
                                             0,
                                             repairBlock(std::move(wire.packet)),
                                             repair_test::blockBytes(value->data, value->plan->input().sources[0], 0));
  ASSERT_OK(computed);
  wire.packet = helperPacket(std::move(*computed));
  auto stamp = ec_helper_detail::stamp(*helperKey_, *value->plan, wire.packet, 1000, 1100);
  ASSERT_OK(stamp);
  auto serialized = serde::serialize(*stamp);
  serialized.back() ^= 1;
  ASSERT_OK(serde::deserialize(wire.predecessor, serialized));
  ASSERT_ERROR(blockingWait(client_->executeEcHelper(wire, control())), StatusCode::kAuthenticationFail);
  wire = request(*value);
  serialized = serde::serialize(wire.reads[3]);
  serialized.back() ^= 1;
  ASSERT_OK(serde::deserialize(wire.reads[3], serialized));
  ASSERT_ERROR(blockingWait(client_->executeEcHelper(wire, control())), StatusCode::kAuthenticationFail);
}

TEST_F(TestEcNativeRepairService, Small112KiBLogicalKvHasOneBlockAndDoesNotClaimPipelineOverlap) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  auto value = prepare({0, 11}, (112 * 1024 + 9) / 10, 2, 112 * 1024);
  ASSERT_OK(value);
  ASSERT_EQ(value->plan->input().logicalLength, 112u * 1024);
  ASSERT_EQ(value->plan->blockCount(), 1);
  auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers);
  ASSERT_OK(transport);
  auto ctl = control();
  ASSERT_OK(blockingWait(EcRepairPipeline::run(value->plan,
                                               *transport,
                                               EcRepairMode::HelperChain,
                                               {ctl.deadline, ctl.cancellation},
                                               executor)));
  // Same durable allocation/operation replays through a fresh Seal barrier;
  // the client must not append to a stage already returned as Sealed by Begin.
  ASSERT_OK(blockingWait(EcRepairPipeline::run(value->plan,
                                               *transport,
                                               EcRepairMode::ClientPipeline,
                                               {ctl.deadline, ctl.cancellation},
                                               executor)));
}

TEST_F(TestEcNativeRepairService, MaximumShardRunsSixteenNativeBlocksWithBoundedWindow) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor executor(2);
  for (auto mode : {EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
    SCOPED_TRACE(::testing::Message() << "mode=" << static_cast<unsigned>(mode) << " window=2");
    auto value = prepare({0, 11}, 1u << 20, 2);
    ASSERT_OK(value);
    ASSERT_EQ(value->plan->blockCount(), 16);
    auto transport = NativeEcRepairTransport::create(value->plan, client_, value->bindings, value->helpers);
    ASSERT_OK(transport);
    auto ctl = control();
    ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    auto result =
        blockingWait(EcRepairPipeline::run(value->plan, *transport, mode, {ctl.deadline, ctl.cancellation}, executor));
    ASSERT_OK(result);
    EXPECT_EQ(result->blocks, 16);
  }
}

TEST_F(TestEcNativeRepairService, UpstreamTicketRemainsPendingWhileDownstreamTcpHandlerIsBlocked) {
  auto value = prepare({0}, 31, 1);
  ASSERT_OK(value);
  auto delay = std::make_shared<StageReplyDropState::ReadDelay>();
  auto entered = delay->entered.get_future();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.helperDelayPosition = 4;
    replyDrop_.delayedHelper = delay;
  }
  auto wire = request(*value);
  auto future = std::async(std::launch::async, [&] { return blockingWait(client_->executeEcHelper(wire, control())); });
  SCOPE_EXIT {
    delay->unblock();
    if (future.valid()) future.wait();
  };
  ASSERT_EQ(entered.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  // An in-flight retry must not join/XOR the same block twice or consume a
  // second per-plan slot while its original downstream request remains owned.
  ASSERT_ERROR(blockingWait(client_->executeEcHelper(wire, control())), StorageClientCode::kResourceBusy);
  auto target = components_->targetMap.getByTargetId(value->plan->input().sources[0].endpoint.targetId);
  ASSERT_OK(target);
  auto scope = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(scope);
  EcScopeRevocation revoke{};
  revoke.binding.target = scope->second;
  revoke.binding.kind = 2;
  const auto copyUuid = [](auto &to, const Uuid &from) {
    std::copy(std::begin(from.data), std::end(from.data), to.begin());
  };
  copyUuid(revoke.binding.object, value->plan->input().sources[0].identity.object);
  copyUuid(revoke.binding.scope, value->plan->input().operationId);
  copyUuid(revoke.binding.client_namespace, value->plan->input().clientNamespace);
  revoke.binding.owner_uid = value->plan->input().ownerUid.toUnderType();
  copyUuid(revoke.id, Uuid::random());
  revoke.endpoint_set_digest = value->plan->endpointSetDigest();
  auto pending = scope->first->revoke(revoke);
  ASSERT_OK(pending);
  EXPECT_TRUE(pending->durable);
  EXPECT_FALSE(pending->drained);
  EXPECT_GE(pending->inflight, 1);
  delay->unblock();
  auto result = future.get();
  EXPECT_FALSE(result);
  auto drained = scope->first->drainStatus(revoke);
  ASSERT_OK(drained);
  EXPECT_TRUE(drained->drained);
}

TEST_F(TestEcStageService, ControlledWriteQuotaTimeoutAndPostCommitCancellationKeepOwningWaiters) {
  auto first = std::make_shared<StageReplyDropState::ReadDelay>();
  auto second = std::make_shared<StageReplyDropState::ReadDelay>();
  auto firstEntered = first->entered.get_future();
  auto secondEntered = second->entered.get_future();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.delayedBegins = {first, second};
  }
  std::string bytes;
  auto a = access(31, 901, bytes), b = access(31, 902, bytes), c = access(31, 903, bytes);
  CancellationSource cancel;
  auto ctl = client::EcRequestControl{std::chrono::steady_clock::now() + std::chrono::seconds(5),
                                      cancel.getToken(),
                                      client::EcRequestControl::TransportPolicy::TcpOnly};
  auto plain = ctl;
  plain.cancellation = {};
  auto fa = std::async(std::launch::async, [&] {
    return blockingWait(client_->beginEcStageV2Controlled({a, grant(a)}, ctl));
  });
  auto fb = std::async(std::launch::async, [&] {
    return blockingWait(client_->beginEcStageV2Controlled({b, grant(b)}, plain));
  });
  SCOPE_EXIT {
    first->unblock();
    second->unblock();
    if (fa.valid()) fa.wait();
    if (fb.valid()) fb.wait();
  };
  ASSERT_EQ(firstEntered.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  ASSERT_EQ(secondEntered.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  auto shortControl = plain;
  shortControl.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30);
  auto blocked = blockingWait(client_->beginEcStageV2Controlled({c, grant(c)}, shortControl));
  ASSERT_ERROR(blocked, StorageClientCode::kTimeout);
  {
    std::lock_guard lock(replyDrop_.mutex);
    EXPECT_EQ(replyDrop_.beginCalls, 2);
  }
  cancel.requestCancellation();
  EXPECT_EQ(fa.wait_for(std::chrono::milliseconds(10)), std::future_status::timeout);
  first->unblock();
  second->unblock();
  ASSERT_ERROR(fa.get(), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_OK(fb.get());
  auto query = blockingWait(client_->queryEcStageV2Controlled({a, grant(a)}, plain));
  ASSERT_OK(query);
  EXPECT_EQ(query->state, 1);
  EXPECT_FALSE(query->needsReconcile);
}

// Twelve distinct logical allocations on one local target/Engine. This is a
// real Storage TCP/authorization/disk/selector test, not twelve failure domains
// and not an AcquireV2 Meta RPC test; the pinned snapshot is constructed here.
TEST_F(TestEcStageService, BlockQuorumReadyPrecedesRealTcpLateCleanup) {
  namespace ec = hf3fs::client::ec;
  using namespace std::chrono_literals;
  meta::EcV2PinnedRead pinned;
  auto &manifest = pinned.manifest;
  manifest.object.inode = meta::InodeId(54321);
  manifest.object.incarnation = Uuid::from(811, 812);
  manifest.stripe = 3;
  manifest.generation = 1;
  manifest.revision = 1;
  manifest.logicalLength = 65543 * 10 - 3;
  auto &snapshot = pinned.snapshot;
  snapshot.object = manifest.object;
  snapshot.pin = Uuid::from(100, 88);  // Same signed read-pin namespace as grant().
  snapshot.owner = {flat::Uid(1234), Uuid::from(99, 66)};
  snapshot.stripe = manifest.stripe;
  snapshot.generation = manifest.generation;
  snapshot.revision = manifest.revision;
  std::array<EcCapabilityV2, 12> grants;
  std::array<VersionedChainId, 12> routes;
  std::array<EcScopeEndpoint, 12> endpoints;
  std::string logical(manifest.logicalLength, '\0');
  for (size_t i = 0; i != logical.size(); ++i) logical[i] = static_cast<char>((i * 37 + 19) & 255);
  auto encoded = EcCodec::encode(logical, 65543);
  ASSERT_OK(encoded);
  auto expected = std::move(*encoded);
  for (size_t index = 0; index != 12; ++index) {
    std::string scratch;
    auto request = access(0, 200 + index, scratch);
    request.identity.object = manifest.object.incarnation;
    request.identity.stripe = manifest.stripe;
    request.identity.shard = static_cast<uint16_t>(index);
    auto descriptor = computeEcIntegrity(request.identity, expected[index]);
    ASSERT_OK(descriptor);
    request.integrity = *descriptor;
    auto writeGrant = grant(request);
    ASSERT_OK(blockingWait(client_->beginEcStageV2({request, writeGrant})));
    ASSERT_NO_FATAL_FAILURE(appendAll(request, writeGrant, expected[index]));
    ASSERT_OK(blockingWait(client_->sealEcStageV2({request, writeGrant})));
    grants[index] = grant(request, uint16_t(EcGrantRightV2::ReadBlock), true);
    routes[index] = request.vChainId;
    auto &fragment = manifest.fragments[index];
    fragment.identity = request.identity;
    fragment.operation = request.operationId;
    fragment.placement = {chainId_, targetId_, nodeId_};
    fragment.integrity = request.integrity;
    auto &mapping = snapshot.endpoints[index];
    mapping.identity = fragment.identity;
    mapping.operation = fragment.operation;
    mapping.endpoint = {fragment.placement, grants[index].claims.engineUuid, grants[index].claims.targetIncarnation};
    endpoints[index] = mapping.endpoint.controlEndpoint();
  }
  auto digest = computeEcScopeEndpointDigest(endpoints);
  ASSERT_OK(digest);
  snapshot.endpointSetDigest = *digest;
  auto input = ec::makeEcBlockReadInput(std::move(pinned), grants, routes, 1);
  ASSERT_OK(input);

  auto delay = std::make_shared<StageReplyDropState::ReadDelay>();
  auto entered = delay->entered.get_future();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.delayedRead = delay;
    replyDrop_.delayedReadShard = 10;
  }
  class NativeBarrierTransport final : public ec::EcBlockReadTransport {
   public:
    NativeBarrierTransport(std::shared_ptr<client::StorageClient> client,
                           std::shared_ptr<StageReplyDropState::ReadDelay> barrier)
        : native(std::move(client)),
          delay(std::move(barrier)) {}
    CoTryTask<EcReadBlockResultV2> read(EcReadBlockV2Req request, ec::EcReadControl control) override {
      // Ensure the delayed eleventh response really reached the server before
      // ten fast sources can finish. This wrapper fabricates no response and
      // retains the fixture's real two-request StorageClient quota.
      while (request.request.identity.shard != 10 && !delay->started.load()) {
        if (std::chrono::steady_clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
        if (control.cancellation.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
        co_await folly::coro::sleep(1ms);
      }
      co_return co_await native.read(std::move(request), control);
    }
    ec::NativeEcBlockTransport native;
    std::shared_ptr<StageReplyDropState::ReadDelay> delay;
  };
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<NativeBarrierTransport>(client_, delay);
  ec::EcBlockRead reader(transport, executor, {});
  SCOPE_EXIT {
    delay->unblock();
    blockingWait(reader.close());
  };
  ec::EcStripeReadOptions options;
  options.deadline = std::chrono::steady_clock::now() + 5s;
  options.hedgeAfter = 2s;
  auto started = reader.start(std::move(*input), options);
  ASSERT_OK(started);
  ASSERT_EQ(entered.wait_for(2s), std::future_status::ready);
  auto selected = blockingWait(started->takeReady());
  ASSERT_OK(selected);
  EXPECT_EQ(selected->attempted, 11);
  EXPECT_FALSE(started->localCleanupComplete());
  EXPECT_EQ(reader.snapshot().activeRequests, 1);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 7);
  for (const auto &block : selected->shards) {
    EXPECT_NE(block.index, 10);
    EXPECT_EQ(block.result.payload.data, expected[block.index].substr(65536));
  }
  std::array<EcCodecShardView, 10> views;
  for (size_t index = 0; index != 10; ++index) {
    views[index] = {selected->shards[index].index, selected->shards[index].result.payload.data};
  }
  // The final vertical block has ten seven-byte data slices and three padded
  // bytes in shard nine. Reuse the production codec with its actual indices.
  auto decoded = EcCodec::recover(views, 10 * 7 - 3, 7);
  ASSERT_OK(decoded);
  for (size_t index = 0; index != 12; ++index) EXPECT_EQ((*decoded)[index], expected[index].substr(65536));
  delay->unblock();
  blockingWait(started->waitLocalCleanup());
  EXPECT_EQ(reader.snapshot().activeRequests, 0);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 10 * 7);
  selected = makeError(StatusCode::kUnknown);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

#include "EcRmwNativeTests.inc"

}  // namespace
}  // namespace hf3fs::storage
