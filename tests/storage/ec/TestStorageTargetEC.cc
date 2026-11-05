#include "storage/store/StorageTarget.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <cstdlib>

using namespace hf3fs;
using namespace hf3fs::storage;
using ec::ECShardStore;
using ec::StoreError;
namespace {
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
}  // namespace
