#include "storage/ec/ECShardWorker.h"

#include <gtest/gtest.h>
#include <folly/executors/ManualExecutor.h>

#include <algorithm>
#include <array>
#include <barrier>
#include <cstdlib>
#include <filesystem>
#include <latch>
#include <stdexcept>

using namespace hf3fs;
using namespace hf3fs::storage;
using namespace hf3fs::storage::ec;
using namespace std::chrono_literals;

namespace hf3fs::test {
struct ECShardWorkerTestHelper {
  static void finish(ECShardJob &job, ECShardJob::Completion result) {
    job.finish(std::move(result));
  }
  static void setHook(ECShardWorker &worker,
                      std::function<void(const std::shared_ptr<ECShardJob> &)> hook) {
    std::lock_guard lock(worker.mutex_);
    if (worker.state_ != ECShardWorker::State::New) throw std::logic_error("hook after start");
    worker.beforeExecuteForTest_ = std::move(hook);
  }
  static bool waitForStopping(ECShardWorker &worker) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    for (;;) {
      {
        std::lock_guard lock(worker.mutex_);
        if (worker.state_ == ECShardWorker::State::Stopping ||
            worker.state_ == ECShardWorker::State::Stopped) return true;
      }
      if (std::chrono::steady_clock::now() >= deadline) return false;
      std::this_thread::yield();
    }
  }
};
}  // namespace hf3fs::test

namespace {
using Helper = hf3fs::test::ECShardWorkerTestHelper;
using WriteResult = ECShardJob::WriteResult;
using ReadResult = ECShardJob::ReadResult;

struct Gate {
  std::latch entered{1}, proceed{1};
  std::atomic_flag opened = ATOMIC_FLAG_INIT;
  void block() { entered.count_down(); proceed.wait(); }
  void open() { if (!opened.test_and_set()) proceed.count_down(); }
};
// On fatal assertions, release the test gate and join before destroying latches.
struct DrainGate {
  ECShardWorker &worker;
  Gate &gate;
  ~DrainGate() { gate.open(); worker.stopAndJoin(); }
};

class ShardWorker : public testing::Test {
 protected:
  ChunkStore::Config config;
  GlobalFileStore files;
  Path root;
  const erasure::ECShardKey key{920, 3, 0, 10};

  void SetUp() override {
    const char *base = std::getenv("EC_TEST_ROOT");
    ASSERT_NE(base, nullptr);
    std::filesystem::create_directories(base);
    std::string pattern = std::string(base) + "/worker-case-XXXXXX";
    ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
    root = pattern;
    config.file_store().set_preopen_chunk_size_list({});
  }
  PhysicalConfig physical(uint64_t id = 100) {
    PhysicalConfig p;
    p.path = root / std::to_string(id);
    p.target_id = id;
    p.allow_disk_without_uuid = true;
    p.physical_file_count = 1;
    p.chunk_size_list = {Size{512 * 1024}};
    return p;
  }
  auto target(uint32_t disk = 0, bool enabled = true) {
    return StorageTarget::enable_shared_from_this::create(config, files, disk, nullptr, enabled);
  }
  std::vector<uint8_t> bytes(uint8_t seed = 19) {
    return std::vector<uint8_t>(erasure::ECLayout::kShardSize, seed);
  }
  auto write(const std::shared_ptr<StorageTarget> &t, uint64_t version, uint8_t seed = 19) {
    return ECShardJob::write(t, key, version, 73, bytes(seed));
  }
};

TEST_F(ShardWorker, WriteReadIdempotencyAndConflict) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  auto first = write(t, 1);
  ASSERT_TRUE(worker.enqueue(first));
  ASSERT_TRUE(first->waitFor(5s));
  const auto &created = std::get<WriteResult>(first->wait());
  ASSERT_TRUE(created);
  ASSERT_TRUE(*created);
  EXPECT_EQ(created->value, IdempotentWriteDisposition::Created);
  auto repeat = write(t, 1);
  ASSERT_TRUE(worker.enqueue(repeat));
  ASSERT_TRUE(repeat->waitFor(5s));
  const auto &verified = std::get<WriteResult>(repeat->wait());
  ASSERT_TRUE(verified);
  ASSERT_TRUE(*verified);
  EXPECT_EQ(verified->value, IdempotentWriteDisposition::ExistingVerified);
  auto conflict = write(t, 1, 20);
  ASSERT_TRUE(worker.enqueue(conflict));
  ASSERT_TRUE(conflict->waitFor(5s));
  const auto &different = std::get<WriteResult>(conflict->wait());
  ASSERT_TRUE(different);
  EXPECT_EQ(different->error, StoreError::ContentConflict);
  auto read = ECShardJob::read(t, key, 1);
  ASSERT_TRUE(worker.enqueue(read));
  ASSERT_TRUE(read->waitFor(5s));
  const auto &loaded = std::get<ReadResult>(read->wait());
  ASSERT_TRUE(loaded);
  ASSERT_TRUE(*loaded);
  EXPECT_EQ(loaded->value.key, key);
  EXPECT_EQ(loaded->value.dataVersion, 1u);
  EXPECT_EQ(loaded->value.validBytes, 73u);
  EXPECT_EQ(loaded->value.payload, bytes());
  for (const auto &job : {first, repeat, conflict, read}) EXPECT_EQ(job->completionCount(), 1u);
}

TEST_F(ShardWorker, DiskQueuesExecuteIndependently) {
  auto t0 = target(0), t1 = target(1);
  ASSERT_TRUE(t0->create(physical(100)));
  ASSERT_TRUE(t1->create(physical(200)));
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  std::array<std::thread::id, 2> consumers;
  Helper::setHook(worker, [&](const auto &job) {
    if (job->dataVersion() == 1) { consumers[0] = std::this_thread::get_id(); gate.block(); }
    else consumers[1] = std::this_thread::get_id();
  });
  ASSERT_TRUE(worker.start(2));
  auto j0 = write(t0, 1, 31), j1 = write(t1, 2, 32);
  ASSERT_TRUE(worker.enqueue(j0));
  gate.entered.wait();
  ASSERT_TRUE(worker.enqueue(j1));
  ASSERT_TRUE(j1->waitFor(5s));  // Disk 1 progresses while disk 0 is blocked.
  EXPECT_EQ(j0->completionCount(), 0u);
  gate.open();
  worker.stopAndJoin();
  EXPECT_NE(consumers[0], consumers[1]);
  for (const auto &job : {j0, j1}) {
    ASSERT_TRUE(job->waitFor(5s));
    const auto &result = std::get<WriteResult>(job->wait());
    ASSERT_TRUE(result);
    ASSERT_TRUE(*result);
    EXPECT_EQ(job->completionCount(), 1u);
  }
  auto read0 = t0->readECShard(key, 1), read1 = t1->readECShard(key, 2);
  ASSERT_TRUE(read0); ASSERT_TRUE(*read0);
  ASSERT_TRUE(read1); ASSERT_TRUE(*read1);
  EXPECT_EQ(read0->value.payload, bytes(31));
  EXPECT_EQ(read1->value.payload, bytes(32));
}

TEST_F(ShardWorker, QueueFullRejectsImmediatelyAndJobCanBeRetried) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;  // Exactly eight waiting slots, plus one executing Job.
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &job) { if (job->dataVersion() == 1) gate.block(); });
  ASSERT_TRUE(worker.start(1));
  auto active = write(t, 1);
  ASSERT_TRUE(worker.enqueue(active));
  gate.entered.wait();
  std::vector<std::shared_ptr<ECShardJob>> queued;
  for (uint64_t version = 2; version <= 9; ++version) {
    queued.push_back(write(t, version));
    ASSERT_TRUE(worker.enqueue(queued.back()));
  }
  auto rejected = write(t, 10);
  auto full = worker.enqueue(rejected);
  ASSERT_FALSE(full);
  EXPECT_EQ(full.error().code(), StatusCode::kQueueFull);
  EXPECT_EQ(rejected->completionCount(), 0u);
  gate.open();
  for (const auto &job : queued) ASSERT_TRUE(job->waitFor(5s));
  ASSERT_TRUE(worker.enqueue(rejected));
  ASSERT_TRUE(rejected->waitFor(5s));
  worker.stopAndJoin();
  queued.push_back(active);
  queued.push_back(rejected);
  for (const auto &job : queued) {
    const auto &result = std::get<WriteResult>(job->wait());
    ASSERT_TRUE(result); ASSERT_TRUE(*result);
    EXPECT_EQ(job->completionCount(), 1u);
  }
}

TEST_F(ShardWorker, ConcurrentEnqueueCompletesEveryAcceptedJob) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  constexpr size_t count = 8;
  std::barrier start(static_cast<std::ptrdiff_t>(count + 1));
  std::vector<std::shared_ptr<ECShardJob>> jobs;
  for (size_t i = 0; i < count; ++i) jobs.push_back(write(t, i + 1));
  std::vector<Result<Void>> results(count, makeError(StatusCode::kUnknown));
  std::vector<std::thread> producers;
  for (size_t i = 0; i < count; ++i) producers.emplace_back([&, i] {
    start.arrive_and_wait(); results[i] = worker.enqueue(jobs[i]);
  });
  start.arrive_and_wait();
  for (auto &thread : producers) thread.join();
  worker.stopAndJoin();
  for (size_t i = 0; i < count; ++i) {
    ASSERT_TRUE(results[i]);
    ASSERT_TRUE(jobs[i]->waitFor(5s));
    const auto &result = std::get<WriteResult>(jobs[i]->wait());
    ASSERT_TRUE(result); ASSERT_TRUE(*result);
    EXPECT_EQ(jobs[i]->completionCount(), 1u);
  }
}

TEST_F(ShardWorker, StopRacesEnqueueAndDrainsWithoutStrandingJobs) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &job) { if (job->dataVersion() == 1) gate.block(); });
  ASSERT_TRUE(worker.start(1));
  auto active = write(t, 1);
  ASSERT_TRUE(worker.enqueue(active));
  gate.entered.wait();
  constexpr size_t count = 16;
  std::barrier start(static_cast<std::ptrdiff_t>(count + 2));
  std::vector<std::shared_ptr<ECShardJob>> jobs;
  for (size_t i = 0; i < count; ++i) jobs.push_back(write(t, i + 2));
  std::vector<Result<Void>> results(count, makeError(StatusCode::kUnknown));
  std::vector<std::thread> producers;
  for (size_t i = 0; i < count; ++i) producers.emplace_back([&, i] {
    start.arrive_and_wait(); results[i] = worker.enqueue(jobs[i]);
  });
  std::atomic<bool> stopped{false};
  std::thread stopper([&] { start.arrive_and_wait(); worker.stopAndJoin(); stopped.store(true); });
  start.arrive_and_wait();
  const bool stopping = Helper::waitForStopping(worker);
  EXPECT_TRUE(stopping);
  EXPECT_FALSE(stopped.load());
  for (auto &thread : producers) thread.join();
  auto late = write(t, 99);
  auto refused = worker.enqueue(late);
  EXPECT_FALSE(refused);
  if (!refused) EXPECT_EQ(refused.error().code(), RPCCode::kRequestRefused);
  gate.open();
  stopper.join();
  ASSERT_TRUE(active->waitFor(5s));
  const auto &activeResult = std::get<WriteResult>(active->wait());
  ASSERT_TRUE(activeResult); ASSERT_TRUE(*activeResult);
  EXPECT_EQ(active->completionCount(), 1u);
  for (size_t i = 0; i < count; ++i) {
    if (results[i]) {
      ASSERT_TRUE(jobs[i]->waitFor(5s));
      const auto &result = std::get<WriteResult>(jobs[i]->wait());
      ASSERT_TRUE(result); ASSERT_TRUE(*result);
      EXPECT_EQ(jobs[i]->completionCount(), 1u);
    } else {
      EXPECT_TRUE(results[i].error().code() == StatusCode::kQueueFull ||
                  results[i].error().code() == RPCCode::kRequestRefused);
      EXPECT_EQ(jobs[i]->completionCount(), 0u);
    }
  }
  EXPECT_EQ(late->completionCount(), 0u);
}

TEST_F(ShardWorker, DestructorDrainsAndConcurrentStopsAreSafe) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  std::vector<std::shared_ptr<ECShardJob>> jobs;
  {
    ECShardWorker worker;
    ASSERT_TRUE(worker.start(1));
    for (uint64_t i = 1; i <= 8; ++i) {
      jobs.push_back(write(t, i));
      ASSERT_TRUE(worker.enqueue(jobs.back()));
    }
  }
  for (const auto &job : jobs) {
    ASSERT_TRUE(job->waitFor(5s));
    const auto &result = std::get<WriteResult>(job->wait());
    ASSERT_TRUE(result); ASSERT_TRUE(*result);
    EXPECT_EQ(job->completionCount(), 1u);
  }
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  std::barrier start(5);
  std::vector<std::thread> closers;
  for (int i = 0; i < 4; ++i) closers.emplace_back([&] { start.arrive_and_wait(); worker.stopAndJoin(); });
  start.arrive_and_wait();
  for (auto &thread : closers) thread.join();
  auto refused = worker.enqueue(write(t, 20));
  ASSERT_FALSE(refused);
  EXPECT_EQ(refused.error().code(), RPCCode::kRequestRefused);
}

TEST_F(ShardWorker, TargetAndStoreErrorsRemainDistinct) {
  auto disabled = target(0, false), closed = target();
  ASSERT_TRUE(disabled->create(physical(100)));
  ASSERT_TRUE(closed->create(physical(200)));
  ASSERT_TRUE(closed->release());
  auto normal = target();
  ASSERT_TRUE(normal->create(physical(300)));
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  auto d = write(disabled, 1), c = write(closed, 1);
  auto missing = ECShardJob::read(normal, key, 1);
  auto invalid = write(normal, 0);
  for (const auto &job : {d, c, missing, invalid}) ASSERT_TRUE(worker.enqueue(job));
  worker.stopAndJoin();
  const auto &dr = std::get<WriteResult>(d->wait());
  const auto &cr = std::get<WriteResult>(c->wait());
  ASSERT_FALSE(dr); EXPECT_EQ(dr.error().code(), StorageCode::kStorageInitFailed);
  ASSERT_FALSE(cr); EXPECT_EQ(cr.error().code(), StorageCode::kTargetOffline);
  const auto &mr = std::get<ReadResult>(missing->wait());
  const auto &ir = std::get<WriteResult>(invalid->wait());
  ASSERT_TRUE(mr); EXPECT_EQ(mr->error, StoreError::NotFound);
  ASSERT_TRUE(ir); EXPECT_EQ(ir->error, StoreError::InvalidArgument);
  for (const auto &job : {d, c, missing, invalid}) EXPECT_EQ(job->completionCount(), 1u);
}

TEST_F(ShardWorker, TargetReleaseWhileJobExecutingPropagatesClosure) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(worker.start(1));
  auto job = write(t, 1);
  ASSERT_TRUE(worker.enqueue(job));
  gate.entered.wait();
  ASSERT_TRUE(t->release());  // Job owns Target, but must respect its closing state.
  gate.open();
  worker.stopAndJoin();
  const auto &result = std::get<WriteResult>(job->wait());
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageCode::kTargetOffline);
  EXPECT_EQ(job->completionCount(), 1u);
}

TEST_F(ShardWorker, DroppedCallerReferencesDoNotLosePayloadOrTarget) {
  const auto p = physical();
  auto t = target();
  ASSERT_TRUE(t->create(p));
  std::weak_ptr<StorageTarget> weakTarget = t;
  std::weak_ptr<ECShardJob> weakJob;
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(worker.start(1));
  {
    auto input = bytes(71);
    auto job = ECShardJob::write(t, key, 1, 73, input);  // Copies caller's vector.
    weakJob = job;
    ASSERT_TRUE(worker.enqueue(job));
    gate.entered.wait();
    std::fill(input.begin(), input.end(), 0);  // Cannot alter owned Job payload.
  }
  t.reset();
  EXPECT_FALSE(weakJob.expired());
  EXPECT_FALSE(weakTarget.expired());
  gate.open();
  worker.stopAndJoin();
  EXPECT_TRUE(weakJob.expired());
  EXPECT_TRUE(weakTarget.expired());
  auto loaded = target();
  ASSERT_TRUE(loaded->load(p.path));
  auto record = loaded->readECShard(key, 1);
  ASSERT_TRUE(record); ASSERT_TRUE(*record);
  EXPECT_EQ(record->value.payload, bytes(71));
}

TEST_F(ShardWorker, ExceptionsCompleteBothJobTypesAndConsumerContinues) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  Helper::setHook(worker, [](const auto &job) {
    if (job->dataVersion() == 1) throw std::runtime_error("injected write failure");
    if (job->dataVersion() == 2) throw 42;  // Non-std exception on the Read path.
  });
  ASSERT_TRUE(worker.start(1));
  auto w = write(t, 1), r = ECShardJob::read(t, key, 2), good = write(t, 3);
  for (const auto &job : {w, r, good}) ASSERT_TRUE(worker.enqueue(job));
  worker.stopAndJoin();
  const auto &wr = std::get<WriteResult>(w->wait());
  const auto &rr = std::get<ReadResult>(r->wait());
  ASSERT_FALSE(wr); EXPECT_EQ(wr.error().code(), StatusCode::kUnknown);
  ASSERT_FALSE(rr); EXPECT_EQ(rr.error().code(), StatusCode::kUnknown);
  const auto &ok = std::get<WriteResult>(good->wait());
  ASSERT_TRUE(ok); ASSERT_TRUE(*ok);
  for (const auto &job : {w, r, good}) EXPECT_EQ(job->completionCount(), 1u);
}

TEST_F(ShardWorker, DuplicateSubmissionAndMultipleWaitersNotifyOnce) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker, other;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(worker.start(1)); ASSERT_TRUE(other.start(1));
  auto job = write(t, 1);
  ASSERT_TRUE(worker.enqueue(job));
  gate.entered.wait();
  auto duplicate = other.enqueue(job);
  ASSERT_FALSE(duplicate);
  EXPECT_EQ(duplicate.error().code(), StatusCode::kQueueConflict);
  std::barrier start(5);
  std::atomic<size_t> completedWaiters{0};
  std::vector<std::thread> waiters;
  for (int i = 0; i < 4; ++i) waiters.emplace_back([&] {
    start.arrive_and_wait();
    if (job->waitFor(5s)) ++completedWaiters;
  });
  start.arrive_and_wait();
  gate.open();
  for (auto &thread : waiters) thread.join();
  worker.stopAndJoin();
  EXPECT_EQ(completedWaiters.load(), 4u);
  EXPECT_EQ(job->completionCount(), 1u);
  auto again = other.enqueue(job);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code(), StatusCode::kQueueConflict);
}

TEST_F(ShardWorker, InvalidConfigurationAndDiskAreRejectedWithoutAcceptance) {
  auto t = target(1);
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  auto job = write(t, 1);
  EXPECT_FALSE(worker.enqueue(job));
  EXPECT_FALSE(worker.start(0));
  ASSERT_TRUE(worker.start(1));
  auto disk = worker.enqueue(job);
  ASSERT_FALSE(disk); EXPECT_EQ(disk.error().code(), StatusCode::kInvalidArg);
  EXPECT_FALSE(worker.enqueue(nullptr));
  EXPECT_FALSE(worker.enqueue(ECShardJob::read(nullptr, key, 1)));
  auto local = target();
  ASSERT_TRUE(local->create(physical(200)));
  auto shortPayload = ECShardJob::write(local, key, 1, 73, {1, 2, 3});
  EXPECT_FALSE(worker.enqueue(shortPayload));
  EXPECT_EQ(shortPayload->completionCount(), 0u);
  EXPECT_EQ(job->completionCount(), 0u);
  worker.stopAndJoin();
  EXPECT_FALSE(worker.start(1));
  ECShardWorker zero(0), excessive(9);
  EXPECT_FALSE(zero.start(1));
  EXPECT_FALSE(excessive.start(1));
}

// Named coroutine: all values needed after suspension are frame-owned.
CoTask<ECShardJob::Completion> observeAsync(
    std::shared_ptr<const ECShardJob> job, folly::Executor *expected,
    std::atomic<size_t> &resumed) {
  auto before = co_await folly::coro::co_current_executor;
  EXPECT_EQ(before, expected);
  auto result = co_await ECShardJob::waitAsync(std::move(job));
  auto after = co_await folly::coro::co_current_executor;
  EXPECT_EQ(after, expected);
  ++resumed;
  co_return result;
}

TEST_F(ShardWorker, AsyncAfterWorkerCompletionAndOwnedReadPayload) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  auto w = write(t, 1);
  ASSERT_TRUE(worker.enqueue(w));
  ASSERT_TRUE(w->waitFor(5s));
  auto r = ECShardJob::read(t, key, 1);
  ASSERT_TRUE(worker.enqueue(r));
  worker.stopAndJoin();
  folly::ManualExecutor executor;
  auto future = ECShardJob::waitAsync(r).scheduleOn(&executor).start();
  executor.drain();
  ASSERT_TRUE(future.isReady());
  auto completion = std::move(future).get();
  r.reset(); w.reset();
  ASSERT_TRUE(t->release());
  t.reset();
  const auto &result = std::get<ReadResult>(completion);
  ASSERT_TRUE(result); ASSERT_TRUE(*result);
  EXPECT_EQ(result->value.payload, bytes());
}

TEST_F(ShardWorker, AsyncMultipleWaitersMixSyncAndResumeOnParentExecutor) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &) { gate.block(); });
  ASSERT_TRUE(worker.start(1));
  auto job = write(t, 1);
  ASSERT_TRUE(worker.enqueue(job));
  gate.entered.wait();
  folly::ManualExecutor executor;
  std::atomic<size_t> resumed{0};
  std::vector<folly::SemiFuture<ECShardJob::Completion>> futures;
  for (int i = 0; i < 4; ++i)
    futures.push_back(observeAsync(job, &executor, resumed).scheduleOn(&executor).start());
  executor.drain();  // All four suspend; this thread can still run a sentinel.
  bool sentinel = false;
  executor.add([&] { sentinel = true; });
  executor.drain();
  EXPECT_TRUE(sentinel);
  EXPECT_EQ(resumed.load(), 0u);
  for (const auto &f : futures) EXPECT_FALSE(f.isReady());
  std::latch syncStarted{1};
  std::atomic<bool> syncDone{false};
  std::thread sync([&] { syncStarted.count_down(); job->wait(); syncDone = true; });
  syncStarted.wait();
  gate.open();
  worker.stopAndJoin();
  sync.join();
  EXPECT_TRUE(syncDone.load());
  // Worker posting only schedules the continuations; it cannot run them here.
  EXPECT_EQ(resumed.load(), 0u);
  executor.drain();
  EXPECT_EQ(resumed.load(), 4u);
  for (auto &f : futures) {
    ASSERT_TRUE(f.isReady());
    auto result = std::get<WriteResult>(std::move(f).get());
    ASSERT_TRUE(result); ASSERT_TRUE(*result);
  }
  EXPECT_EQ(job->completionCount(), 1u);
}

TEST_F(ShardWorker, AsyncLazyTaskKeepsJobAliveWithoutCallerReference) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  ASSERT_TRUE(worker.start(1));
  auto job = write(t, 1);
  std::weak_ptr<const ECShardJob> weak = job;
  auto task = ECShardJob::waitAsync(job);  // Lazy; has not started yet.
  ASSERT_TRUE(worker.enqueue(job));
  worker.stopAndJoin();
  job.reset(); t.reset();
  ASSERT_FALSE(weak.expired());  // Only the lazy Task owns the completed Job.
  folly::ManualExecutor executor;
  auto future = std::move(task).scheduleOn(&executor).start();
  executor.drain();
  ASSERT_TRUE(future.isReady());
  auto result = std::get<WriteResult>(std::move(future).get());
  ASSERT_TRUE(result); ASSERT_TRUE(*result);
  EXPECT_TRUE(weak.expired());
}

TEST_F(ShardWorker, AsyncDuplicateFinishPublishesOnlyFirstResult) {
  auto job = ECShardJob::read(nullptr, key, 1);
  folly::ManualExecutor executor;
  auto f = ECShardJob::waitAsync(job).scheduleOn(&executor).start();
  executor.drain();
  ASSERT_FALSE(f.isReady());
  Helper::finish(*job, ReadResult(makeError(StatusCode::kUnknown)));
  Helper::finish(*job, ReadResult(makeError(StorageCode::kTargetOffline)));
  EXPECT_TRUE(job->waitFor(0ms));
  EXPECT_EQ(job->completionCount(), 1u);
  executor.drain();
  ASSERT_TRUE(f.isReady());
  const auto result = std::get<ReadResult>(std::move(f).get());
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StatusCode::kUnknown);
  auto late = ECShardJob::waitAsync(job).scheduleOn(&executor).start();
  executor.drain();
  ASSERT_TRUE(late.isReady());
  const auto again = std::get<ReadResult>(std::move(late).get());
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code(), StatusCode::kUnknown);
}

TEST_F(ShardWorker, AsyncWorkerExceptionWakesSuspendedWaiter) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  ECShardWorker worker;
  Gate gate;
  DrainGate drain{worker, gate};
  Helper::setHook(worker, [&](const auto &) { gate.block(); throw std::runtime_error("async failure"); });
  ASSERT_TRUE(worker.start(1));
  auto job = write(t, 1);
  ASSERT_TRUE(worker.enqueue(job));
  gate.entered.wait();
  folly::ManualExecutor executor;
  auto future = ECShardJob::waitAsync(job).scheduleOn(&executor).start();
  executor.drain();
  EXPECT_FALSE(future.isReady());
  gate.open();
  worker.stopAndJoin();
  executor.drain();
  ASSERT_TRUE(future.isReady());
  auto result = std::get<WriteResult>(std::move(future).get());
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StatusCode::kUnknown);
  EXPECT_EQ(job->completionCount(), 1u);
}

}  // namespace
