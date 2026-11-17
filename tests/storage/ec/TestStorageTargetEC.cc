#include "storage/store/StorageTarget.h"
#include <gtest/gtest.h>
#include <array>
#include <barrier>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <latch>
#include <thread>
#include <vector>

using namespace hf3fs;
using namespace hf3fs::storage;
using ec::ECShardStore;
using ec::StoreError;
using ec::IdempotentWriteDisposition;

namespace hf3fs::test {
struct StorageTargetECTestHelper {
  static void setOperationHook(StorageTarget &target, std::function<void()> hook) {
    std::lock_guard guard(target.ecLifecycleMutex_);
    target.ecOperationHookForTest_ = std::move(hook);
  }
  static bool waitForClosing(StorageTarget &target) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!target.ecClosing_.load(std::memory_order_acquire)) {
      if (std::chrono::steady_clock::now() >= deadline) return false;
      std::this_thread::yield();
    }
    return true;
  }
};
}  // namespace hf3fs::test

namespace {
using WriteResult = Result<ec::StoreResult<IdempotentWriteDisposition>>;
using ReadResult = Result<ec::StoreResult<ec::ShardRecord>>;
class TargetEC : public testing::Test {
 protected:
  ChunkStore::Config config;
  GlobalFileStore files;
  Path root;
  const erasure::ECShardKey key{123, 4, 0, 0};
  void SetUp() override {
    const char *base = std::getenv("EC_TEST_ROOT");
    ASSERT_NE(base, nullptr);
    std::filesystem::create_directories(base);
    std::string pattern = std::string(base) + "/target-case-XXXXXX";
    ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
    root = pattern;
    config.file_store().set_preopen_chunk_size_list({});
  }
  auto target(bool enabled = true) {
    return StorageTarget::enable_shared_from_this::create(config, files, 0, nullptr, enabled);
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
  Path db(const PhysicalConfig &p) { return p.path / fmt::format("ec_shards_{}", p.target_id); }
  std::vector<uint8_t> bytes(uint8_t seed) { return std::vector<uint8_t>(erasure::ECLayout::kShardSize, seed); }

  void checkReleaseWaitsForOperation(bool write) {
    const auto p = physical();
    auto t = target();
    ASSERT_TRUE(t->create(p));
    const auto data = bytes(17);
    if (!write) {
      auto initial = t->writeECShard(key, 1, 31, data);
      ASSERT_TRUE(initial);
      ASSERT_TRUE(*initial);
    }
    std::latch entered(1), proceed(1);
    hf3fs::test::StorageTargetECTestHelper::setOperationHook(*t, [&] {
      entered.count_down();
      proceed.wait();  // The test driver does not need the lifecycle lock.
    });
    WriteResult writeResult = makeError(StatusCode::kUnknown);
    ReadResult readResult = makeError(StatusCode::kUnknown);
    std::thread operation([&, held = t] {
      if (write) writeResult = held->writeECShard(key, 1, 31, data);
      else readResult = held->readECShard(key, 1);
    });
    entered.wait();  // The operation passed admission and owns the lifecycle lock.
    std::atomic<bool> releaseDone{false};
    bool releaseOK = false;
    std::thread closer([&, held = t] {
      releaseOK = bool(held->release());
      releaseDone.store(true, std::memory_order_release);
    });
    const bool closing = hf3fs::test::StorageTargetECTestHelper::waitForClosing(*t);
    EXPECT_TRUE(closing);
    EXPECT_FALSE(releaseDone.load(std::memory_order_acquire));
    // No newly arriving operation may wait on the held lock after closing.
    if (closing) {
      auto rejectedWrite = t->writeECShard(key, 2, 31, data);
      auto rejectedRead = t->readECShard(key, 1);
      EXPECT_FALSE(rejectedWrite);
      EXPECT_FALSE(rejectedRead);
      if (!rejectedWrite) EXPECT_EQ(rejectedWrite.error().code(), StorageCode::kTargetOffline);
      if (!rejectedRead) EXPECT_EQ(rejectedRead.error().code(), StorageCode::kTargetOffline);
    }
    EXPECT_FALSE(ECShardStore::open(db(p), false));  // Still held until the admitted operation completes.
    proceed.count_down();
    operation.join();
    closer.join();
    // Destroy the hook's borrowed latch captures while they are still alive.
    hf3fs::test::StorageTargetECTestHelper::setOperationHook(*t, {});
    ASSERT_TRUE(releaseOK);
    if (write) {
      ASSERT_TRUE(writeResult);
      ASSERT_TRUE(*writeResult);
      EXPECT_EQ(writeResult->value, IdempotentWriteDisposition::Created);
    } else {
      ASSERT_TRUE(readResult);
      ASSERT_TRUE(*readResult);
      EXPECT_EQ(readResult->value.payload, data);  // Owning result survives release.
    }
    auto reopened = ECShardStore::open(db(p), false);
    ASSERT_TRUE(reopened);
    auto persisted = reopened.value->read(key, 1);
    ASSERT_TRUE(persisted);
    EXPECT_EQ(persisted.value.payload, data);
  }
};
TEST_F(TargetEC, CreateDestroyLoadIntegrity) {
  auto p = physical();
  auto t = target();
  ASSERT_TRUE(t->create(p));
  ASSERT_NE(t->ecShardStore(), nullptr);
  ASSERT_EQ(t->ecShardStore()->write(key, 1, 31, bytes(7)), StoreError::Ok);
  t.reset();
  t = target();
  ASSERT_TRUE(t->load(p.path));
  auto read = t->ecShardStore()->read(key, 1);
  ASSERT_TRUE(read);
  EXPECT_EQ(read.value.payload, bytes(7));
  EXPECT_EQ(read.value.validBytes, 31u);
}
TEST_F(TargetEC, TargetIsolation) {
  auto a = target(), b = target();
  ASSERT_TRUE(a->create(physical(100)));
  ASSERT_TRUE(b->create(physical(101)));
  ASSERT_EQ(a->ecShardStore()->write(key, 1, 20, bytes(3)), StoreError::Ok);
  ASSERT_EQ(b->ecShardStore()->write(key, 1, 20, bytes(9)), StoreError::Ok);
  EXPECT_EQ(a->ecShardStore()->read(key, 1).value.payload, bytes(3));
  EXPECT_EQ(b->ecShardStore()->read(key, 1).value.payload, bytes(9));
}
TEST_F(TargetEC, ReleaseClosesLockAndIsRepeatable) {
  auto p = physical();
  auto t = target();
  ASSERT_TRUE(t->create(p));
  EXPECT_FALSE(ECShardStore::open(db(p), false));
  ASSERT_TRUE(t->release());
  EXPECT_EQ(t->ecShardStore(), nullptr);
  auto reopened = ECShardStore::open(db(p), false);
  ASSERT_TRUE(reopened);
  EXPECT_TRUE(t->release());
}
TEST_F(TargetEC, DisabledAndMissingDatabase) {
  auto p = physical();
  { auto t = target(false); ASSERT_TRUE(t->create(p)); EXPECT_EQ(t->ecShardStore(), nullptr); }
  EXPECT_FALSE(std::filesystem::exists(db(p).string()));
  { auto t = target(); EXPECT_FALSE(t->load(p.path)); EXPECT_EQ(t->ecShardStore(), nullptr); }
  EXPECT_FALSE(std::filesystem::exists(db(p).string()));
}
TEST_F(TargetEC, OccupiedDatabaseFailsAndCanRetryWithNewObject) {
  auto p = physical();
  { auto t = target(); ASSERT_TRUE(t->create(p)); }
  auto held = ECShardStore::open(db(p), false);
  ASSERT_TRUE(held);
  { auto t = target(); EXPECT_FALSE(t->load(p.path)); EXPECT_EQ(t->ecShardStore(), nullptr); }
  held.value.reset();
  auto t = target();
  EXPECT_TRUE(t->load(p.path));
}
TEST_F(TargetEC, InvalidDatabasePathAndEarlyFailureDestruction) {
  auto p = physical();
  std::filesystem::create_directories(p.path.string());
  { std::ofstream file(db(p).string()); file << "not a directory"; }
  { auto t = target(); EXPECT_FALSE(t->create(p)); EXPECT_EQ(t->ecShardStore(), nullptr); }
  { auto t = target(); EXPECT_FALSE(t->load(root / "missing")); }
  // A failed CRAQ initialization also leaves destruction safe.
  auto other = physical(101);
  std::filesystem::create_directories(other.path.string());
  { std::ofstream file((other.path / "meta").string()); file << "invalid"; }
  { auto t = target(); EXPECT_FALSE(t->create(other)); }
}
TEST_F(TargetEC, ExistingIdentityMismatchDoesNotOpenEC) {
  auto p = physical();
  { auto t = target(); ASSERT_TRUE(t->create(p)); }
  p.allow_existing_targets = true;
  p.target_id = 999;
  { auto t = target(); EXPECT_FALSE(t->create(p)); EXPECT_EQ(t->ecShardStore(), nullptr); }
  EXPECT_TRUE(ECShardStore::open(db(physical()), false));
}
TEST_F(TargetEC, FailureAfterExistingLoadClosesEC) {
  auto p = physical();
  { auto t = target(); ASSERT_TRUE(t->create(p)); }
  // load succeeds, then addChunkSize cannot open its temporary config file.
  std::filesystem::create_directory((p.path / "target.toml.tmp").string());
  p.allow_existing_targets = true;
  p.chunk_size_list.push_back(Size{1024 * 1024});
  auto t = target();
  EXPECT_FALSE(t->create(p));
  EXPECT_EQ(t->ecShardStore(), nullptr);
  EXPECT_TRUE(ECShardStore::open(db(p), false));
}

TEST_F(TargetEC, SafeInterfacesWriteReadReopenAndOwnedResult) {
  const auto p = physical();
  auto t = target();
  ASSERT_TRUE(t->create(p));
  const auto data = bytes(21);
  auto written = t->writeECShard(key, 1, 33, data);
  ASSERT_TRUE(written);
  ASSERT_TRUE(*written);
  EXPECT_EQ(written->value, IdempotentWriteDisposition::Created);
  auto repeated = t->writeECShard(key, 1, 33, data);
  ASSERT_TRUE(repeated);
  ASSERT_TRUE(*repeated);
  EXPECT_EQ(repeated->value, IdempotentWriteDisposition::ExistingVerified);
  auto read = t->readECShard(key, 1);
  ASSERT_TRUE(read);
  ASSERT_TRUE(*read);
  EXPECT_EQ(read->value.validBytes, 33u);
  ASSERT_TRUE(t->release());
  t.reset();
  EXPECT_EQ(read->value.payload, data);
  t = target();
  ASSERT_TRUE(t->load(p.path));
  auto loaded = t->readECShard(key, 1);
  ASSERT_TRUE(loaded);
  ASSERT_TRUE(*loaded);
  EXPECT_EQ(loaded->value.payload, data);
}

TEST_F(TargetEC, SafeInterfacePreservesStoreErrors) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  auto invalid = t->writeECShard(key, 0, 31, bytes(1));
  ASSERT_TRUE(invalid);
  EXPECT_EQ(invalid->error, StoreError::InvalidArgument);
  auto missing = t->readECShard(key, 1);
  ASSERT_TRUE(missing);
  EXPECT_EQ(missing->error, StoreError::NotFound);
}

TEST_F(TargetEC, ConcurrentSameContentWritesUseIdempotency) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  const auto data = bytes(22);
  constexpr size_t count = 8;
  std::vector<WriteResult> results(count, WriteResult{makeError(StatusCode::kUnknown)});
  std::barrier start(static_cast<std::ptrdiff_t>(count + 1));
  std::vector<std::thread> threads;
  for (size_t i = 0; i < count; ++i) threads.emplace_back([&, i, held = t] {
    start.arrive_and_wait();
    results[i] = held->writeECShard(key, 1, 34, data);
  });
  start.arrive_and_wait();
  for (auto &thread : threads) thread.join();
  size_t created = 0, verified = 0;
  for (const auto &result : results) {
    ASSERT_TRUE(result);
    ASSERT_TRUE(*result);
    created += result->value == IdempotentWriteDisposition::Created;
    verified += result->value == IdempotentWriteDisposition::ExistingVerified;
  }
  EXPECT_EQ(created, 1u);
  EXPECT_EQ(verified, count - 1);
}

TEST_F(TargetEC, ConcurrentDifferentContentWritesConflict) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  const std::array data{bytes(23), bytes(24)};
  std::vector<WriteResult> results(2, WriteResult{makeError(StatusCode::kUnknown)});
  std::barrier start(3);
  std::array<std::thread, 2> threads;
  for (size_t i = 0; i < threads.size(); ++i) threads[i] = std::thread([&, i, held = t] {
    start.arrive_and_wait();
    results[i] = held->writeECShard(key, 1, 35, data[i]);
  });
  start.arrive_and_wait();
  for (auto &thread : threads) thread.join();
  ASSERT_TRUE(results[0]);
  ASSERT_TRUE(results[1]);
  ASSERT_NE(bool(*results[0]), bool(*results[1]));
  const size_t winner = *results[0] ? 0 : 1;
  EXPECT_EQ(results[winner]->value, IdempotentWriteDisposition::Created);
  EXPECT_EQ(results[1 - winner]->error, StoreError::ContentConflict);
  auto read = t->readECShard(key, 1);
  ASSERT_TRUE(read);
  ASSERT_TRUE(*read);
  EXPECT_EQ(read->value.payload, data[winner]);
}

TEST_F(TargetEC, ConcurrentReadsReturnOwnedPayloads) {
  auto t = target();
  ASSERT_TRUE(t->create(physical()));
  const auto data = bytes(25);
  auto written = t->writeECShard(key, 1, 36, data);
  ASSERT_TRUE(written);
  ASSERT_TRUE(*written);
  constexpr size_t count = 8;
  std::vector<ReadResult> results(count, ReadResult{makeError(StatusCode::kUnknown)});
  std::barrier start(static_cast<std::ptrdiff_t>(count + 1));
  std::vector<std::thread> threads;
  for (size_t i = 0; i < count; ++i) threads.emplace_back([&, i, held = t] {
    start.arrive_and_wait();
    results[i] = held->readECShard(key, 1);
  });
  start.arrive_and_wait();
  for (auto &thread : threads) thread.join();
  ASSERT_TRUE(t->release());
  for (const auto &result : results) {
    ASSERT_TRUE(result);
    ASSERT_TRUE(*result);
    EXPECT_EQ(result->value.payload, data);
    EXPECT_EQ(result->value.validBytes, 36u);
  }
}

TEST_F(TargetEC, ReleaseWaitsForAdmittedWriteAndClosesAdmission) {
  checkReleaseWaitsForOperation(true);
}

TEST_F(TargetEC, ReleaseWaitsForAdmittedReadAndClosesAdmission) {
  checkReleaseWaitsForOperation(false);
}

TEST_F(TargetEC, ConcurrentRepeatedReleaseClosesOnceAndRejectsOperations) {
  const auto p = physical();
  auto t = target();
  ASSERT_TRUE(t->create(p));
  const auto data = bytes(26);
  auto written = t->writeECShard(key, 1, 37, data);
  ASSERT_TRUE(written);
  ASSERT_TRUE(*written);
  constexpr size_t count = 8;
  std::vector<Result<Void>> results(count, Result<Void>{makeError(StatusCode::kUnknown)});
  std::barrier start(static_cast<std::ptrdiff_t>(count + 1));
  std::vector<std::thread> threads;
  for (size_t i = 0; i < count; ++i) threads.emplace_back([&, i, held = t] {
    start.arrive_and_wait();
    results[i] = held->release();
  });
  start.arrive_and_wait();
  for (auto &thread : threads) thread.join();
  for (const auto &result : results) ASSERT_TRUE(result);
  auto write = t->writeECShard(key, 2, 37, data);
  auto read = t->readECShard(key, 1);
  ASSERT_FALSE(write);
  ASSERT_FALSE(read);
  EXPECT_EQ(write.error().code(), StorageCode::kTargetOffline);
  EXPECT_EQ(read.error().code(), StorageCode::kTargetOffline);
  auto reopened = ECShardStore::open(db(p), false);
  ASSERT_TRUE(reopened);
  ASSERT_TRUE(t->release());  // Cannot close the independently reopened database.
  EXPECT_TRUE(reopened.value->read(key, 1));
}

TEST_F(TargetEC, DisabledSafeInterfacesRejectWithoutCreatingDatabase) {
  const auto p = physical();
  auto t = target(false);
  ASSERT_TRUE(t->create(p));
  auto write = t->writeECShard(key, 1, 38, bytes(27));
  auto read = t->readECShard(key, 1);
  ASSERT_FALSE(write);
  ASSERT_FALSE(read);
  EXPECT_EQ(write.error().code(), StorageCode::kStorageInitFailed);
  EXPECT_EQ(read.error().code(), StorageCode::kStorageInitFailed);
  EXPECT_FALSE(std::filesystem::exists(db(p).string()));
}

TEST_F(TargetEC, FailedInitializationSafeInterfacesReject) {
  const auto p = physical();
  std::filesystem::create_directories(p.path.string());
  { std::ofstream file(db(p).string()); file << "not a directory"; }
  auto t = target();
  ASSERT_FALSE(t->create(p));
  auto write = t->writeECShard(key, 1, 39, bytes(28));
  auto read = t->readECShard(key, 1);
  ASSERT_FALSE(write);
  ASSERT_FALSE(read);
  EXPECT_EQ(write.error().code(), StorageCode::kStorageInitFailed);
  EXPECT_EQ(read.error().code(), StorageCode::kStorageInitFailed);
  ASSERT_TRUE(t->release());
  EXPECT_FALSE(t->readECShard(key, 1));
}
}  // namespace
