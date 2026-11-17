#include <filesystem>
#include <folly/experimental/coro/BlockingWait.h>
#include <future>
#include <gtest/gtest.h>
#include <latch>

#include "storage/service/StorageServer.h"
#include "tests/lib/Helper.h"
#include "tests/lib/UnitTestFabric.h"
using namespace hf3fs;
using namespace hf3fs::storage;
using namespace hf3fs::storage::ec;
using namespace std::chrono_literals;
namespace hf3fs::test {
struct ComponentsECTestHelper {
  static auto worker(Components &c) {
    std::lock_guard l(c.ecAdmissionMutex_);
    return c.ecShardWorker_;
  }
};
struct ECShardWorkerTestHelper {
  static size_t queued(ECShardWorker &w) {
    std::lock_guard l(w.mutex_);
    return w.queues_.front()->count;
  }
  static void hook(ECShardWorker &w, std::function<void(const std::shared_ptr<ECShardJob> &)> f) {
    std::lock_guard l(w.mutex_);
    w.beforeExecuteForTest_ = std::move(f);
  }
};
}  // namespace hf3fs::test
namespace {
class ECRealRPC : public testing::Test {
 protected:
  Components::Config config;
  Path root;
  std::unique_ptr<StorageServer> server;
  net::Client::Config clientConfig;
  std::unique_ptr<hf3fs::storage::client::StorageMessenger> messenger;
  net::Address address;
  Components &c() { return hf3fs::test::StorageServerHelper::components(*server); }
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
    config.set_enable_ec_shard_rpc(true);
    for (size_t i = 0; i < config.base().groups_length(); ++i) {
      config.base().groups(i).set_network_type(net::Address::LOCAL);
      config.base().groups(i).listener().set_listen_port(0);
    }
    clientConfig.set_default_timeout(10_s);
  }
  void start(bool create = true) {
    server = std::make_unique<StorageServer>(config);
    c().mgmtdClient = std::make_shared<hf3fs::test::FakeMgmtdClient>(std::make_shared<flat::RoutingInfo>());
    ASSERT_TRUE(server->setup());
    ASSERT_TRUE(server->net::Server::start());
    address = server->groups().front()->addressList().front();
    ASSERT_EQ(address.type, net::Address::TCP);
    ASSERT_EQ(address.ipStr(), "127.0.0.1");
    if (create)
      for (uint32_t i = 0; i < 2; ++i) {
        CreateTargetReq req;
        req.targetId = TargetId{101 + i};
        req.chainId = ChainId{201 + i};
        req.diskIndex = 0;
        req.physicalFileCount = 1;
        req.chunkSizeList = {512_KB};
        ASSERT_TRUE(c().storageTargets.create(req));
      }
    route();
    messenger = std::make_unique<hf3fs::storage::client::StorageMessenger>(clientConfig);
    ASSERT_TRUE(messenger->start("ECRealRPC"));
  }
  void route(flat::PublicTargetState state = flat::PublicTargetState::SERVING) {
    auto r = std::make_shared<flat::RoutingInfo>();
    for (uint32_t i = 0; i < 2; ++i) {
      flat::TargetInfo t;
      t.targetId = TargetId{101 + i};
      t.chainId = ChainId{201 + i};
      t.publicState = state;
      r->targets.emplace(t.targetId, t);
      flat::ChainInfo chain;
      chain.chainId = t.chainId;
      chain.chainVersion = flat::ChainVersion{1};
      flat::ChainTargetInfo ct;
      ct.targetId = t.targetId;
      chain.targets.push_back(ct);
      r->chains.emplace(chain.chainId, chain);
    }
    ASSERT_TRUE(c().targetMap.updateRouting(std::make_shared<hf3fs::client::RoutingInfo>(r, SteadyClock::now())));
  }
  WriteECShardReq writeReq() {
    WriteECShardReq w;
    w.targetId = TargetId{101};
    w.record.key = {456, 7, 0, 11};
    w.record.version = 1;
    w.record.validBytes = 73;
    w.record.payload.bytes.assign(kECShardPayloadLimit, 27);
    checksum(w);
    return w;
  }
  void checksum(WriteECShardReq &w) {
    w.record.payloadChecksum = folly::crc32c(w.record.payload.bytes.data(), w.record.payload.bytes.size(), 0);
  }
  ReadECShardReq readReq() {
    auto w = writeReq();
    return {.targetId = w.targetId, .key = w.record.key, .version = 1};
  }
  auto write(WriteECShardReq w) { return folly::coro::blockingWait(messenger->writeECShard(address, std::move(w))); }
  auto read(ReadECShardReq r) { return folly::coro::blockingWait(messenger->readECShard(address, std::move(r))); }
  void stop() {
    if (messenger) {
      messenger->stopAndJoin();
      messenger.reset();
    }
    if (server) {
      server->stopAndJoin();
      server.reset();
    }
  }
  void TearDown() override { stop(); }
};
TEST_F(ECRealRPC, RoundTripIdempotencyConflictAndFullObjectRebuild) {
  ASSERT_NO_FATAL_FAILURE(start());
  auto w = writeReq();
  auto first = write(w);
  ASSERT_TRUE(first);
  EXPECT_EQ(first->status, ECShardStatus::Created);
  auto duplicate = write(w);
  ASSERT_TRUE(duplicate);
  EXPECT_EQ(duplicate->status, ECShardStatus::ExistingVerified);
  auto conflict = w;
  conflict.record.payload.bytes[10] ^= 1;
  checksum(conflict);
  auto bad = write(conflict);
  ASSERT_TRUE(bad);
  EXPECT_EQ(bad->status, ECShardStatus::ContentConflict);
  auto r = read(readReq());
  ASSERT_TRUE(r);
  ASSERT_TRUE(r->succeeded());
  EXPECT_EQ(serde::serialize(*r->record), serde::serialize(w.record));
  stop();
  ASSERT_NO_FATAL_FAILURE(start(false));
  auto persisted = read(readReq());
  ASSERT_TRUE(persisted);
  ASSERT_TRUE(persisted->succeeded());
  EXPECT_EQ(serde::serialize(*persisted->record), serde::serialize(w.record));
  auto again = write(w);
  ASSERT_TRUE(again);
  EXPECT_EQ(again->status, ECShardStatus::ExistingVerified);
}
TEST_F(ECRealRPC, ErrorsAndRoutingGates) {
  config.targets().set_ec_target_ids({"101"});
  ASSERT_NO_FATAL_FAILURE(start());
  auto missing = read(readReq());
  ASSERT_TRUE(missing);
  EXPECT_EQ(missing->status, ECShardStatus::NotFound);
  auto w = writeReq();
  w.targetId = TargetId{999};
  auto unknown = write(w);
  ASSERT_TRUE(unknown);
  EXPECT_EQ(unknown->status, ECShardStatus::TargetUnavailable);
  w.targetId = TargetId{102};
  auto disabled = write(w);
  ASSERT_TRUE(disabled);
  EXPECT_EQ(disabled->status, ECShardStatus::ECDisabled);
  auto disabledRead = readReq();
  disabledRead.targetId = TargetId{102};
  auto dr = read(disabledRead);
  ASSERT_TRUE(dr);
  EXPECT_EQ(dr->status, ECShardStatus::ECDisabled);
  ASSERT_TRUE(c().targetMap.updateDiskState(root / "disk0", true, true));
  auto diskRejected = write(writeReq());
  ASSERT_TRUE(diskRejected);
  EXPECT_EQ(diskRejected->status, ECShardStatus::TargetUnavailable);
  ASSERT_TRUE(c().targetMap.updateDiskState(root / "disk0", false, false));
  route(flat::PublicTargetState::SYNCING);
  auto syncing = write(writeReq());
  ASSERT_TRUE(syncing);
  EXPECT_EQ(syncing->status, ECShardStatus::TargetUnavailable);
  route();
  config.storage().set_read_only(true);
  auto ro = write(writeReq());
  ASSERT_TRUE(ro);
  EXPECT_EQ(ro->status, ECShardStatus::TargetUnavailable);
  config.storage().set_read_only(false);
  ASSERT_TRUE(c().targetMap.offlineTarget(TargetId{101}));
  auto offline = read(readReq());
  ASSERT_TRUE(offline);
  EXPECT_EQ(offline->status, ECShardStatus::TargetUnavailable);
}
TEST_F(ECRealRPC, InvalidWireRequestIsRejectedBeforeDiskWork) {
  ASSERT_NO_FATAL_FAILURE(start());
  auto w = writeReq();
  w.record.payloadChecksum ^= 1;
  auto bad = write(w);
  EXPECT_FALSE(bad);
  auto r = read(readReq());
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, ECShardStatus::NotFound);
}
TEST_F(ECRealRPC, QueueFullAndClientTimeoutStillPersistAcceptedJobs) {
  config.coroutines_pool_default().set_coroutines_num(32);
  ASSERT_NO_FATAL_FAILURE(start());
  auto worker = hf3fs::test::ComponentsECTestHelper::worker(c());
  ASSERT_TRUE(worker);
  std::promise<void> release;
  auto released = release.get_future().share();
  std::promise<void> entered;
  std::atomic<bool> first{true};
  hf3fs::test::ECShardWorkerTestHelper::hook(*worker, [&](const auto &) {
    if (first.exchange(false)) entered.set_value();
    released.wait();
  });
  struct Release {
    std::promise<void> &p;
    std::shared_ptr<ECShardWorker> worker;
    bool done = false;
    void open() {
      if (!done) {
        done = true;
        p.set_value();
      }
    }
    ~Release() {
      open();
      worker->stopAndJoin();
    }
  } guard{release, worker};
  net::UserRequestOptions options;
  options.timeout = 100_ms;
  // One active and eight queued. Timed-out client calls do not cancel accepted jobs.
  for (uint64_t v = 1; v <= 9; ++v) {
    auto w = writeReq();
    w.record.version = v;
    auto r = folly::coro::blockingWait(messenger->writeECShard(address, w, &options));
    ASSERT_FALSE(r) << "version " << v << " status " << static_cast<uint16_t>(r->status);
    EXPECT_EQ(r.error().code(), RPCCode::kTimeout);
    if (v == 1) {
      ASSERT_EQ(entered.get_future().wait_for(5s), std::future_status::ready);
    } else {
      auto deadline = std::chrono::steady_clock::now() + 5s;
      while (hf3fs::test::ECShardWorkerTestHelper::queued(*worker) != v - 1 &&
             std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(1ms);
      ASSERT_EQ(hf3fs::test::ECShardWorkerTestHelper::queued(*worker), v - 1);
    }
  }
  auto full = writeReq();
  full.record.version = 10;
  auto result = write(full);
  ASSERT_TRUE(result);
  EXPECT_EQ(result->status, ECShardStatus::QueueFull);
  guard.open();
  stop();
  ASSERT_NO_FATAL_FAILURE(start(false));
  for (uint64_t v = 1; v <= 9; ++v) {
    auto req = readReq();
    req.version = v;
    auto persisted = read(req);
    ASSERT_TRUE(persisted);
    EXPECT_TRUE(persisted->succeeded());
  }
  auto absent = readReq();
  absent.version = 10;
  auto rejected = read(absent);
  ASSERT_TRUE(rejected);
  // Store reports VersionMismatch when this key has other versions. Wire v1
  // has no separate mismatch status; fail closed as CorruptRecord.
  EXPECT_EQ(rejected->status, ECShardStatus::CorruptRecord);
}
TEST_F(ECRealRPC, DefaultOffRejectsRPC) {
  config.set_enable_ec_shard_rpc(false);
  ASSERT_NO_FATAL_FAILURE(start());
  auto w = write(writeReq());
  ASSERT_TRUE(w);
  EXPECT_EQ(w->status, ECShardStatus::TargetUnavailable);
  auto r = read(readReq());
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, ECShardStatus::TargetUnavailable);
}
TEST_F(ECRealRPC, AsyncQueueAndShutdownDrainRealAcceptedRPC) {
  ASSERT_NO_FATAL_FAILURE(start());
  auto worker = hf3fs::test::ComponentsECTestHelper::worker(c());
  ASSERT_TRUE(worker);
  std::promise<void> entered, release;
  auto released = release.get_future().share();
  std::atomic<bool> first{true};
  hf3fs::test::ECShardWorkerTestHelper::hook(*worker, [&](const auto &) {
    if (first.exchange(false)) {
      entered.set_value();
      released.wait();
    }
  });
  auto pending = std::async(std::launch::async, [&] { return write(writeReq()); });
  struct Unblock {
    std::promise<void> &p;
    bool done = false;
    void open() {
      if (!done) {
        done = true;
        p.set_value();
      }
    }
    ~Unblock() { open(); }
  } unblock{release};
  auto enteredStatus = entered.get_future().wait_for(5s);
  if (enteredStatus != std::future_status::ready) unblock.open();
  ASSERT_EQ(enteredStatus, std::future_status::ready);
  // An unrelated RPC must run while the only disk consumer is paused.
  auto invalid = writeReq();
  invalid.targetId = TargetId{999};
  auto other = write(invalid);
  ASSERT_TRUE(other);
  EXPECT_EQ(other->status, ECShardStatus::TargetUnavailable);
  c().closeECShardAdmission();
  auto late = read(readReq());
  ASSERT_TRUE(late);
  EXPECT_EQ(late->status, ECShardStatus::TargetUnavailable);
  auto stopped = std::async(std::launch::async, [&] { server->stopAndJoin(); });
  EXPECT_EQ(stopped.wait_for(100ms), std::future_status::timeout);
  unblock.open();
  ASSERT_EQ(pending.wait_for(5s), std::future_status::ready);
  auto result = pending.get();
  ASSERT_TRUE(result);
  EXPECT_EQ(result->status, ECShardStatus::Created);
  ASSERT_EQ(stopped.wait_for(5s), std::future_status::ready);
  stopped.get();
  stop();
  ASSERT_NO_FATAL_FAILURE(start(false));
  auto persisted = read(readReq());
  ASSERT_TRUE(persisted);
  EXPECT_TRUE(persisted->succeeded());
}
}  // namespace
