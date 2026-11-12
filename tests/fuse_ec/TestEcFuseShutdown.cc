#include <cstdlib>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>

#include "client/storage/StorageClientInMem.h"
#include "fuse/FuseClients.h"
#include "fuse/FuseMainLoop.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::fuse {
namespace {
using folly::coro::blockingWait;
TEST(TestEcFuseShutdown, EmptyAndFailedInitStopIsIdempotentBeforeConfigurationDestruction) {
  FuseConfig cfg;
  cfg.set_batch_io_coros(0);
  FuseClients clients;
  auto result = clients.init(flat::AppInfo{}, "/unused", "/unused", cfg);
  ASSERT_ERROR(result, StatusCode::kInvalidArg);
  ASSERT_OK(clients.stop());
  EXPECT_TRUE(clients.ioJoined);
  EXPECT_TRUE(clients.fullyStopped);
  clients.config = nullptr;  // Final stop must not read borrowed configuration.
  ASSERT_OK(clients.stop());
  checkedFuseShutdownOrExit(clients);
}
TEST(TestEcFuseShutdown, StickyJoinUsesActualTopLevelExitBeforeHooksAndDestructors) {
  folly::test::TemporaryDirectory directory;
  const auto marker = (directory.path() / "must-not-exist").string();
  ASSERT_EXIT(
      {
        auto destruction = folly::makeGuard([&] {
          int fd = ::open(marker.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
          if (fd >= 0) ::close(fd);
        });
        FuseClients clients;
        clients.ioJoinStarted = true;
        clients.ioJoined = false;
        checkedFuseShutdownOrExit(clients);
        ::_Exit(99);
      },
      ::testing::ExitedWithCode(EXIT_FAILURE),
      "shutdown did not confirm local joins");
  EXPECT_FALSE(std::filesystem::exists(marker));
}
// Actual watch()/ioRingWorker()/IoRing::process, with a capacity-one queue and
// a consumer held before its first dequeue. No fake completion or queue-empty
// surrogate is used: every claimed SQE must obtain a real error CQE.
TEST(TestEcFuseShutdown, FullClaimedBatchDrainsBeforeOwnedJoinAndStopsFurtherClaims) {
  FuseConfig cfg;
  cfg.set_max_uid(256);
  cfg.io_worker_coros().set_hi(1);
  cfg.io_worker_coros().set_lo(0);
  cfg.set_max_jobs_per_ioring(16);
  storage::client::StorageClient::Config storageCfg;
  auto mgmtd = tests::FakeMgmtdClient::create({}, 1, 0);
  auto storage = std::make_shared<storage::client::StorageClientInMem>(ClientId::random(), storageCfg, *mgmtd);
  folly::CPUThreadPoolExecutor executor(2);
  std::vector<uint64_t> bytes((IoRing::bytesRequired(16) + 7) / 8, 0);
  auto ring = std::make_shared<IoRing>(nullptr,
                                       "shutdown-claimed",
                                       flat::UserInfo{flat::Uid(123), flat::Gid(123), "token"},
                                       true,
                                       reinterpret_cast<uint8_t *>(bytes.data()),
                                       bytes.size() * 8,
                                       1,
                                       0,
                                       0_ms,
                                       0);
  for (int i = 0; i != 8; ++i) ASSERT_TRUE(ring->addSqe(INT32_MAX, nullptr));
  FuseClients clients;
  clients.config = &cfg;
  clients.storageClient = storage;
  clients.userConfig.init(cfg);
  clients.jitter.store(std::chrono::milliseconds(1));
  clients.iors.init(4);
  for (int i = 0; i != 3; ++i) clients.iojqs.emplace_back(new BoundedQueue<IoRingJob>(1));
  auto slot = clients.iors.ioRings->alloc();
  ASSERT_TRUE(slot.has_value());
  clients.iors.ioRings->table[*slot].store(ring);
  folly::coro::Baton startConsumer;
  auto drain = [&]() -> CoTask<void> {
    co_await folly::coro::co_withCancellation(CancellationToken{}, startConsumer);
    co_await folly::coro::co_withCancellation(clients.cancelIos.getToken(), clients.ioRingWorker(0, 1));
  };
  clients.ioScope.add(drain().scheduleOn(&executor));
  auto stop = folly::makeGuard([&]() noexcept {
    startConsumer.post();
    if (!clients.stop()) std::terminate();
  });
  clients.ioWatches.emplace_back([&](std::stop_token token) { clients.watch(0, token); });
  sem_post(clients.iors.sems[0].get());
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (!clients.iojqs[0]->full() && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
  ASSERT_TRUE(clients.iojqs[0]->full());
  // Reject new claims before releasing the worker. The watch owns the already
  // claimed eight-job vector and may be blocked enqueueing its second element.
  clients.ioClaimsClosed.store(true);
  startConsumer.post();
  ASSERT_OK(clients.stop());
  EXPECT_TRUE(clients.ioWatches.empty());
  EXPECT_TRUE(clients.ioJoined);
  ASSERT_EQ(ring->cqeCount(), 8);
  for (int i = 0; i != 8; ++i)
    EXPECT_EQ(ring->cqeSection[i].result, -static_cast<int64_t>(StatusCode::toErrno(StatusCode::kInvalidArg)));
  const auto previousTail = ring->sqeTail.load();
  ASSERT_TRUE(ring->addSqe(INT32_MAX, nullptr));
  EXPECT_EQ(ring->sqeTail.load(), previousTail);
  EXPECT_EQ(ring->cqeCount(), 8);
  ASSERT_OK(clients.stop());
}
}  // namespace
}  // namespace hf3fs::fuse
