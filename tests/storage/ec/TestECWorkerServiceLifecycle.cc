#include <barrier>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <latch>
#include <thread>

#include "storage/service/Components.h"
#include "storage/service/StorageServer.h"
#include "tests/lib/Helper.h"
#include "tests/lib/UnitTestFabric.h"

using namespace hf3fs;
using namespace hf3fs::storage;
using namespace hf3fs::storage::ec;
using namespace std::chrono_literals;

namespace hf3fs::test {
struct ComponentsECTestHelper {
  static auto start(Components &c, std::shared_ptr<ECShardWorker> worker = {}) {
    return c.startECShardWorker(std::move(worker));
  }
  static auto open(Components &c) { return c.openECShardAdmission(); }
  static void stop(Components &c) { c.stopECShardWorker(); }
  static auto worker(Components &c) {
    std::lock_guard lock(c.ecAdmissionMutex_);
    return c.ecShardWorker_;
  }
  static bool accepting(Components &c) {
    std::lock_guard lock(c.ecAdmissionMutex_);
    return c.ecAccepting_;
  }
  static bool attempted(Components &c) {
    std::lock_guard lock(c.ecAdmissionMutex_);
    return c.ecStartAttempted_;
  }
};
struct ECShardWorkerTestHelper {
  static void hook(ECShardWorker &w, std::function<void(const std::shared_ptr<ECShardJob> &)> fn) {
    std::lock_guard lock(w.mutex_);
    w.beforeExecuteForTest_ = std::move(fn);
  }
  static size_t threads(ECShardWorker &w) {
    std::lock_guard lock(w.mutex_);
    return w.threads_.size();
  }
};
}  // namespace hf3fs::test

namespace {
using H = hf3fs::test::ComponentsECTestHelper;
using W = hf3fs::test::ECShardWorkerTestHelper;
struct Gate {
  std::latch entered{1}, proceed{1};
  std::atomic<bool> opened{false};
  void block() {
    entered.count_down();
    proceed.wait();
  }
  void open() {
    if (!opened.exchange(true)) proceed.count_down();
  }
};
struct DrainGate {
  Components &c;
  Gate &gate;
  ~DrainGate() {
    gate.open();
    H::stop(c);
  }
};
CoTask<void> observe(std::shared_ptr<const ECShardJob> job, std::atomic<bool> &done) {
  auto result = co_await ECShardJob::waitAsync(std::move(job));
  EXPECT_TRUE(std::get<ECShardJob::WriteResult>(result));
  done = true;
}

class ECWorkerService : public testing::Test {
 protected:
  Components::Config config;
  std::unique_ptr<CPUExecutorGroup> executor;
  std::unique_ptr<Components> components;
  Path root;
  erasure::ECShardKey key{456, 7, 0, 11};
  void SetUp() override {
    const char *base = std::getenv("EC_TEST_ROOT");
    ASSERT_NE(base, nullptr);
    std::filesystem::create_directories(base);
    auto pattern = std::string(base) + "/service-case-XXXXXX";
    ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
    root = pattern;
    std::filesystem::create_directories((root / "disk0").string());
    config.targets().set_target_paths({root / "disk0"});
    config.targets().set_allow_disk_without_uuid(true);
    config.targets().set_collect_all_fds(false);
    config.targets().set_ec_target_ids({"101", "102"});
    config.targets().storage_target().file_store().set_preopen_chunk_size_list({});
    config.set_speed_up_quit(false);
    config.sync_worker().set_num_threads(1);
    config.aio_read_worker().set_num_threads(1);
    config.storage().write_worker().set_num_threads(1);
    config.storage().write_worker().set_bg_num_threads(1);
    for (auto *pool : {&config.coroutines_pool_read(),
                       &config.coroutines_pool_update(),
                       &config.coroutines_pool_sync(),
                       &config.coroutines_pool_default()}) {
      pool->set_threads_num(1);
      pool->set_coroutines_num(4);
    }
    for (auto *group : {&config.base().thread_pool(),
                        &config.base().independent_thread_pool(),
                        &config.client().thread_pool(),
                        &config.forward_client().thread_pool()}) {
      group->set_num_proc_threads(1);
      group->set_num_io_threads(1);
      group->set_num_connect_threads(1);
      group->set_num_bg_threads(1);
    }
    config.buffer_pool().set_rdmabuf_size(4_KB);
    config.buffer_pool().set_rdmabuf_count(1);
    config.buffer_pool().set_big_rdmabuf_size(4_KB);
    config.buffer_pool().set_big_rdmabuf_count(1);
    executor = std::make_unique<CPUExecutorGroup>(1, "ECServiceRelease");
  }
  Components &make(bool enabled = true, bool init = true) {
    config.set_enable_ec_shard_rpc(enabled);
    components = std::make_unique<Components>(config);
    if (init) EXPECT_TRUE(components->storageTargets.init(*executor));
    return *components;
  }
  auto target(Components &c, uint32_t disk = 0) {
    CreateTargetReq req;
    req.targetId = TargetId{101 + disk};
    req.chainId = ChainId{201 + disk};
    req.diskIndex = disk;
    req.physicalFileCount = 1;
    req.chunkSizeList = {512_KB};
    EXPECT_TRUE(c.storageTargets.create(req));
    auto snapshot = c.targetMap.snapshot();
    auto result = snapshot->getTarget(req.targetId);
    return result ? (*result)->storageTarget : std::shared_ptr<StorageTarget>{};
  }
  auto job(const std::shared_ptr<StorageTarget> &t, uint64_t version = 1) {
    return ECShardJob::write(t, key, version, 73, std::vector<uint8_t>(erasure::ECLayout::kShardSize, 27));
  }
  void TearDown() override {
    if (components) {
      EXPECT_TRUE(components->stopAndJoin(*executor));
      components.reset();
    }
    executor.reset();
  }
};

TEST_F(ECWorkerService, DefaultOffAllocatesNoWorkerEvenWithEnabledTarget) {
  EXPECT_FALSE(config.enable_ec_shard_rpc());
  auto &c = make(false);
  auto t = target(c);
  ASSERT_TRUE(t);
  ASSERT_TRUE(H::start(c));
  ASSERT_TRUE(H::open(c));
  EXPECT_FALSE(H::worker(c));
  EXPECT_FALSE(H::accepting(c));
  auto j = job(t);
  auto rejected = c.submitECShard(j);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error().code(), RPCCode::kRequestRefused);
  EXPECT_EQ(j->completionCount(), 0u);
}

TEST_F(ECWorkerService, StartsPerInitializedDiskAndOnlyOpensExplicitly) {
  std::filesystem::create_directories((root / "disk1").string());
  config.targets().set_target_paths({root / "disk0", root / "disk1"});
  auto &c = make();
  auto t = target(c, 1);
  ASSERT_TRUE(t);
  ASSERT_TRUE(H::start(c));
  auto worker = H::worker(c);
  ASSERT_TRUE(worker);
  EXPECT_EQ(W::threads(*worker), 2u);
  EXPECT_FALSE(c.submitECShard(job(t)));
  ASSERT_TRUE(H::open(c));
  auto j = job(t);
  ASSERT_TRUE(c.submitECShard(j));
  ASSERT_TRUE(j->waitFor(5s));
  auto result = std::get<ECShardJob::WriteResult>(j->wait());
  ASSERT_TRUE(result);
  ASSERT_TRUE(*result);
  H::stop(c);
  EXPECT_FALSE(H::worker(c));
}

TEST_F(ECWorkerService, StartupFailureDoesNotPublishWorkerOrAdmission) {
  auto &c = make();
  auto bad = std::make_shared<ECShardWorker>(0);  // actual Worker.start failure, no production config override
  auto result = H::start(c, bad);
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StatusCode::kInvalidConfig);
  EXPECT_EQ(W::threads(*bad), 0u);
  EXPECT_FALSE(H::worker(c));
  EXPECT_FALSE(H::open(c));
  EXPECT_FALSE(c.submitECShard(nullptr));
  EXPECT_FALSE(H::start(c));  // one-shot, no hidden retry
}

TEST_F(ECWorkerService, MissingInitializedDisksFailsClosed) {
  auto &c = make(true, false);
  auto result = H::start(c);
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StatusCode::kInvalidConfig);
  EXPECT_FALSE(H::worker(c));
  EXPECT_FALSE(H::accepting(c));
}

TEST_F(ECWorkerService, CloseAdmissionDoesNotStopAcceptedWork) {
  auto &c = make();
  auto t = target(c);
  ASSERT_TRUE(t);
  auto worker = std::make_shared<ECShardWorker>();
  Gate gate;
  DrainGate drain{c, gate};
  W::hook(*worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(H::start(c, worker));
  ASSERT_TRUE(H::open(c));
  auto active = job(t);
  ASSERT_TRUE(c.submitECShard(active));
  gate.entered.wait();
  c.closeECShardAdmission();
  c.closeECShardAdmission();
  EXPECT_EQ(W::threads(*worker), 1u);
  EXPECT_EQ(active->completionCount(), 0u);
  auto late = job(t, 2);
  EXPECT_FALSE(c.submitECShard(late));
  EXPECT_EQ(late->completionCount(), 0u);
  EXPECT_FALSE(H::open(c));
  gate.open();
  H::stop(c);
  ASSERT_TRUE(active->waitFor(5s));
  EXPECT_EQ(active->completionCount(), 1u);
}

TEST_F(ECWorkerService, FullStopDrainsWorkerBeforeCoroutinePoolAndTargetRelease) {
  auto &c = make();
  auto t = target(c);
  ASSERT_TRUE(t);
  ASSERT_TRUE(c.defaultPool.start());
  auto worker = std::make_shared<ECShardWorker>();
  Gate gate;
  DrainGate drain{c, gate};
  W::hook(*worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(H::start(c, worker));
  ASSERT_TRUE(H::open(c));
  auto j = job(t);
  ASSERT_TRUE(c.submitECShard(j));
  gate.entered.wait();
  std::atomic<bool> observed{false}, stopped{false};
  c.defaultPool.enqueue(observe(j, observed));
  std::thread stopper([&] {
    EXPECT_TRUE(c.stopAndJoin(*executor));
    stopped = true;
  });
  // close is a controlled gate fence: a late submit is rejected while the
  // consumer remains paused. Neither close nor submit waits for the join.
  c.closeECShardAdmission();
  EXPECT_FALSE(c.submitECShard(job(t, 2)));
  EXPECT_FALSE(stopped.load());
  gate.open();
  stopper.join();
  EXPECT_TRUE(stopped.load());
  EXPECT_TRUE(observed.load());
  ASSERT_TRUE(j->waitFor(5s));
  EXPECT_EQ(j->completionCount(), 1u);
  auto result = std::get<ECShardJob::WriteResult>(j->wait());
  ASSERT_TRUE(result);
  ASSERT_TRUE(*result);
  EXPECT_FALSE(t->readECShard(key, 1));  // Target released only after successful job.
  EXPECT_TRUE(c.stopAndJoin(*executor));
}

TEST_F(ECWorkerService, ConcurrentStopAndSubmitCompleteEveryAcceptedJobOnce) {
  auto &c = make();
  auto t = target(c);
  ASSERT_TRUE(t);
  auto worker = std::make_shared<ECShardWorker>();
  Gate gate;
  DrainGate drain{c, gate};
  W::hook(*worker, [&](const auto &j) {
    if (j->dataVersion() == 1) gate.block();
  });
  ASSERT_TRUE(H::start(c, worker));
  ASSERT_TRUE(H::open(c));
  auto active = job(t);
  ASSERT_TRUE(c.submitECShard(active));
  gate.entered.wait();
  constexpr size_t n = 16;
  std::barrier start(n + 2);
  std::vector<std::shared_ptr<ECShardJob>> jobs;
  std::vector<Result<Void>> results(n, makeError(StatusCode::kUnknown));
  for (size_t i = 0; i < n; ++i) jobs.push_back(job(t, i + 2));
  std::vector<std::thread> producers;
  for (size_t i = 0; i < n; ++i)
    producers.emplace_back([&, i] {
      start.arrive_and_wait();
      results[i] = c.submitECShard(jobs[i]);
    });
  std::thread stopper([&] {
    start.arrive_and_wait();
    H::stop(c);
  });
  start.arrive_and_wait();
  for (auto &p : producers) p.join();
  c.closeECShardAdmission();
  EXPECT_FALSE(c.submitECShard(job(t, 99)));
  gate.open();
  stopper.join();
  for (size_t i = 0; i < n; ++i) {
    if (results[i]) {
      ASSERT_TRUE(jobs[i]->waitFor(5s));
      EXPECT_EQ(jobs[i]->completionCount(), 1u);
      auto result = std::get<ECShardJob::WriteResult>(jobs[i]->wait());
      ASSERT_TRUE(result);
      ASSERT_TRUE(*result);
    } else {
      EXPECT_TRUE(results[i].error().code() == RPCCode::kRequestRefused ||
                  results[i].error().code() == StatusCode::kQueueFull);
      EXPECT_EQ(jobs[i]->completionCount(), 0u);
    }
  }
  EXPECT_EQ(active->completionCount(), 1u);
}

TEST_F(ECWorkerService, RepeatedConcurrentStopsAndCloseBeforeStartAreSafe) {
  auto &c = make();
  ASSERT_TRUE(H::start(c));
  ASSERT_TRUE(H::open(c));
  std::barrier begin(5);
  std::vector<std::thread> stoppers;
  for (int i = 0; i < 4; ++i)
    stoppers.emplace_back([&] {
      begin.arrive_and_wait();
      EXPECT_TRUE(c.stopAndJoin(*executor));
    });
  begin.arrive_and_wait();
  for (auto &t : stoppers) t.join();
  EXPECT_FALSE(H::worker(c));
  EXPECT_FALSE(c.submitECShard(nullptr));
  EXPECT_FALSE(H::start(c));
  EXPECT_FALSE(H::open(c));
}

TEST_F(ECWorkerService, StopBeforeStartCannotReopenAdmission) {
  auto &c = make();
  c.closeECShardAdmission();
  EXPECT_FALSE(H::start(c));
  EXPECT_FALSE(H::open(c));
  EXPECT_FALSE(H::worker(c));
}

// Full Components start: deliberately invalid native AIO size fails AFTER EC
// worker startup. This does not rely on a sandbox denying a valid operation.
TEST_F(ECWorkerService, PartialComponentsStartupDrainsECOnSubsequentFailure) {
  config.set_enable_ec_shard_rpc(true);
  config.aio_read_worker().set_max_events(0);
  Components c(config);
  net::ThreadPoolGroup tpg("ECPartial", config.base().thread_pool());
  auto result = c.start({}, tpg);
  EXPECT_FALSE(result);
  if (!result) {
    EXPECT_EQ(result.error().code(), StatusCode::kInvalidConfig);
    EXPECT_NE(result.error().message().find("init aio context failed"), std::string_view::npos);
  }
  EXPECT_TRUE(H::attempted(c));  // proves we passed StorageTargets load and EC startup
  EXPECT_FALSE(H::worker(c));
  EXPECT_FALSE(H::accepting(c));
  EXPECT_FALSE(c.submitECShard(nullptr));
  EXPECT_FALSE(c.start({}, tpg));  // failed startup cannot reinitialize ordinary pools
  EXPECT_TRUE(c.stopAndJoin(*executor));
  EXPECT_TRUE(c.stopAndJoin(*executor));
  EXPECT_FALSE(c.start({}, tpg));
}

TEST_F(ECWorkerService, RealStorageServerStartStopUsesExistingFacilities) {
  for (size_t i = 0; i < config.base().groups_length(); ++i) {
    config.base().groups(i).set_network_type(net::Address::LOCAL);
    config.base().groups(i).listener().set_listen_port(0);
  }
  for (bool enabled : {false, true}) {
    config.set_enable_ec_shard_rpc(enabled);
    StorageServer server(config);
    auto &c = hf3fs::test::StorageServerHelper::components(server);
    c.mgmtdClient = std::make_shared<hf3fs::test::FakeMgmtdClient>(std::make_shared<flat::RoutingInfo>());
    ASSERT_TRUE(server.setup());
    ASSERT_TRUE(server.net::Server::start());
    auto worker = H::worker(c);
    if (enabled) {
      ASSERT_TRUE(worker);
      EXPECT_EQ(W::threads(*worker), config.targets().target_paths().size());
    } else {
      EXPECT_FALSE(worker);
    }
    EXPECT_EQ(H::accepting(c), enabled);
    server.stopAndJoin();
    server.stopAndJoin();
    EXPECT_FALSE(H::worker(c));
    EXPECT_FALSE(c.submitECShard(nullptr));
  }
}

}  // namespace
