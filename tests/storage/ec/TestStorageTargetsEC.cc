#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

#include "storage/store/StorageTargets.h"

using namespace hf3fs;
using namespace hf3fs::storage;

namespace {
struct Opened {
  AtomicallyTargetMap map;
  StorageTargets targets;
  explicit Opened(const StorageTargets::Config &config)
      : targets(config, map) {}
  ~Opened() { map.release(); }  // Close Targets before their file store/engines.
  auto get(uint64_t id) {
    auto snapshot = map.snapshot();
    auto found = snapshot->getTarget(TargetId{id});
    return found ? (*found)->storageTarget : std::shared_ptr<StorageTarget>{};
  }
};

class StorageTargetsEC : public testing::Test {
 protected:
  StorageTargets::Config config;
  Path disk;
  const erasure::ECShardKey key{987, 2, 0, 11};
  void SetUp() override {
    const char *base = std::getenv("EC_TEST_ROOT");
    ASSERT_NE(base, nullptr);
    std::filesystem::create_directories(base);
    auto pattern = std::string(base) + "/targets-case-XXXXXX";
    ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
    disk = Path(pattern) / "disk";
    std::filesystem::create_directories(disk.string());
    config.set_target_paths({disk});
    config.set_target_num_per_path(1);
    config.set_allow_disk_without_uuid(true);
    config.storage_target().file_store().set_preopen_chunk_size_list({});
  }
  StorageTargets::CreateConfig batch(std::vector<uint64_t> ids = {101}) {
    StorageTargets::CreateConfig c;
    c.set_target_ids(ids);
    c.set_physical_file_count(1);
    c.set_allow_disk_without_uuid(true);
    c.set_chunk_size_list({512_KB});
    return c;
  }
  CreateTargetReq request(uint64_t id = 101, uint32_t chain = 201) {
    CreateTargetReq req;
    req.targetId = TargetId{id};
    req.chainId = ChainId{chain};
    req.physicalFileCount = 1;
    req.chunkSizeList = {512_KB};
    return req;
  }
  Path db(uint64_t id = 101) { return disk / std::to_string(id) / fmt::format("ec_shards_{}", id); }
  auto payload() { return std::vector<uint8_t>(erasure::ECLayout::kShardSize, 83); }
  void ordinary(bool viaCreateRequest = false) {
    Opened live(config);
    if (viaCreateRequest) {
      CPUExecutorGroup executor(1, "OrdinaryCreate");
      ASSERT_TRUE(live.targets.init(executor));
      ASSERT_TRUE(live.targets.create(request()));
    } else {
      ASSERT_TRUE(live.targets.create(batch()));
    }
    ASSERT_FALSE(boost::filesystem::exists(db()));
  }
  void save(const PhysicalConfig &p, const Path &directory) {
    std::ofstream out(directory / kPhysicalConfigFileName);
    ASSERT_TRUE(out);
    out << serde::toTomlString(p);
    ASSERT_TRUE(out);
  }
};

TEST_F(StorageTargetsEC, DefaultBatchDoesNotEnableOrCreateEC) {
  EXPECT_TRUE(config.ec_target_ids().empty());
  Opened live(config);
  ASSERT_TRUE(live.targets.create(batch()));
  auto target = live.get(101);
  ASSERT_TRUE(target);
  EXPECT_FALSE(boost::filesystem::exists(db()));
  EXPECT_FALSE(target->readECShard(key, 1));
}

TEST_F(StorageTargetsEC, BatchAllowlistIsSelective) {
  config.set_target_num_per_path(2);
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  Opened live(config);
  ASSERT_TRUE(live.targets.create(batch({101, 102})));
  auto enabled = live.get(101), disabled = live.get(102);
  ASSERT_TRUE(enabled);
  ASSERT_TRUE(disabled);
  auto w = enabled->writeECShard(key, 1, 73, payload());
  ASSERT_TRUE(w);
  ASSERT_TRUE(*w);
  EXPECT_TRUE(boost::filesystem::is_directory(db(101)));
  EXPECT_FALSE(boost::filesystem::exists(db(102)));
  EXPECT_FALSE(disabled->writeECShard(key, 1, 73, payload()));
}

TEST_F(StorageTargetsEC, CreateTargetRequestUsesOnlyServiceAllowlist) {
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  Opened live(config);
  CPUExecutorGroup executor(1, "ECTargetConfig");
  ASSERT_TRUE(live.targets.init(executor));
  ASSERT_TRUE(live.targets.create(request()));
  ASSERT_TRUE(live.targets.create(request(102, 202)));
  auto enabled = live.get(101), disabled = live.get(102);
  ASSERT_TRUE(enabled);
  ASSERT_TRUE(disabled);
  auto w = enabled->writeECShard(key, 1, 73, payload());
  ASSERT_TRUE(w);
  ASSERT_TRUE(*w);
  EXPECT_FALSE(disabled->readECShard(key, 1));
  EXPECT_FALSE(boost::filesystem::exists(db(102)));
  auto repeat = request();
  repeat.allowExistingTarget = true;
  EXPECT_TRUE(live.targets.create(repeat));
}

TEST_F(StorageTargetsEC, RestartLoadsOriginalRecordThroughLoadTarget) {
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  {
    Opened live(config);
    ASSERT_TRUE(live.targets.create(batch()));
    auto target = live.get(101);
    ASSERT_TRUE(target);
    auto w = target->writeECShard(key, 9, 73, payload());
    ASSERT_TRUE(w);
    ASSERT_TRUE(*w);
  }
  {
    Opened restarted(config);
    CPUExecutorGroup executor(1, "ECReload");
    ASSERT_TRUE(restarted.targets.load(executor));
    auto target = restarted.get(101);
    ASSERT_TRUE(target);
    auto r = target->readECShard(key, 9);
    ASSERT_TRUE(r);
    ASSERT_TRUE(*r);
    EXPECT_EQ(r->value.key, key);
    EXPECT_EQ(r->value.dataVersion, 9u);
    EXPECT_EQ(r->value.validBytes, 73u);
    EXPECT_EQ(r->value.payload, payload());
    EXPECT_EQ(r->value.payloadChecksum, folly::crc32c(payload().data(), payload().size(), 0));
  }
}

TEST_F(StorageTargetsEC, MissingECOnLoadFailsWithoutCreatingDatabase) {
  ordinary();
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  Opened live(config);
  CPUExecutorGroup executor(1, "ECMissing");
  auto result = live.targets.load(executor);
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageCode::kStorageInitFailed);
  EXPECT_FALSE(live.get(101));
  EXPECT_FALSE(boost::filesystem::exists(db()));
}

TEST_F(StorageTargetsEC, ExistingBatchAndCreateRequestCannotBootstrapMissingEC) {
  ordinary(true);  // Persist the same chain identity the later request expects.
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  {
    Opened live(config);
    auto c = batch();
    c.set_allow_existing_targets(true);
    EXPECT_FALSE(live.targets.create(c));
    EXPECT_FALSE(live.get(101));
    EXPECT_FALSE(boost::filesystem::exists(db()));
  }
  {
    Opened live(config);
    CPUExecutorGroup executor(1, "ECExisting");
    ASSERT_TRUE(live.targets.init(executor));
    auto req = request();
    req.allowExistingTarget = true;
    EXPECT_FALSE(live.targets.create(req));
    EXPECT_FALSE(live.get(101));
    EXPECT_FALSE(boost::filesystem::exists(db()));
  }
}

TEST_F(StorageTargetsEC, PersistedIdMustMatchDirectoryAndRequest) {
  ordinary();
  PhysicalConfig p;
  ASSERT_TRUE(serde::fromTomlFile(p, disk / "101" / kPhysicalConfigFileName));
  p.target_id = 999;
  save(p, disk / "101");
  ASSERT_TRUE(config.set_ec_target_ids({"101", "999"}));
  Opened live(config);
  CPUExecutorGroup executor(1, "ECIdentity");
  ASSERT_TRUE(live.targets.init(executor));
  EXPECT_FALSE(live.targets.loadTarget(disk / "101"));
  auto req = request();
  req.allowExistingTarget = true;
  EXPECT_FALSE(live.targets.create(req));
  EXPECT_FALSE(live.get(101));
  EXPECT_FALSE(live.get(999));
  EXPECT_FALSE(boost::filesystem::exists(db()));
  EXPECT_FALSE(boost::filesystem::exists(disk / "101" / "ec_shards_999"));
}

TEST_F(StorageTargetsEC, PhysicalPathAndNoncanonicalDirectoryAreRejected) {
  ordinary();
  PhysicalConfig p;
  ASSERT_TRUE(serde::fromTomlFile(p, disk / "101" / kPhysicalConfigFileName));
  p.path = disk / "elsewhere";
  save(p, disk / "101");
  Opened live(config);
  CPUExecutorGroup executor(1, "ECPaths");
  ASSERT_TRUE(live.targets.init(executor));
  EXPECT_FALSE(live.targets.loadTarget(disk / "101"));
  std::filesystem::rename((disk / "101").string(), (disk / "00101").string());
  p.path = disk / "00101";
  save(p, disk / "00101");
  EXPECT_FALSE(live.targets.loadTarget(p.path));
  EXPECT_FALSE(live.get(101));
}

TEST_F(StorageTargetsEC, ExistingECRejectsFileCountAndChainMismatch) {
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  {
    Opened live(config);
    CPUExecutorGroup executor(1, "ECCreate");
    ASSERT_TRUE(live.targets.init(executor));
    ASSERT_TRUE(live.targets.create(request()));
  }
  Opened live(config);
  CPUExecutorGroup executor(1, "ECMismatch");
  ASSERT_TRUE(live.targets.init(executor));
  auto req = request();
  req.allowExistingTarget = true;
  req.physicalFileCount = 2;
  EXPECT_FALSE(live.targets.create(req));
  req.physicalFileCount = 1;
  req.chainId = ChainId{202};
  EXPECT_FALSE(live.targets.create(req));
  EXPECT_FALSE(live.get(101));
  req.chainId = ChainId{201};
  ASSERT_TRUE(live.targets.create(req));
  EXPECT_TRUE(live.get(101));
  // The already-registered early-return path must not bypass identity checks.
  req.physicalFileCount = 2;
  EXPECT_FALSE(live.targets.create(req));
}

TEST_F(StorageTargetsEC, AllowlistValidationAndRestartOnlyPolicy) {
  EXPECT_FALSE(config.set_ec_target_ids({"0"}));
  EXPECT_FALSE(config.set_ec_target_ids({"101", "101"}));
  EXPECT_TRUE(config.ec_target_ids().empty());
  for (const char *bad : {"ec_target_ids = [-1]",
                          "ec_target_ids = [1.5]",
                          R"(ec_target_ids = ["-1"])",
                          R"(ec_target_ids = ["00101"])",
                          R"(ec_target_ids = ["18446744073709551616"])",
                          R"(ec_target_ids = ["+101"])",
                          R"(ec_target_ids = [""])"}) {
    EXPECT_FALSE(config.update(toml::parse(bad), false)) << bad;
  }
  EXPECT_FALSE(config.update(toml::parse("ec_target_ids = [\"101\"]"), true));
  EXPECT_TRUE(config.ec_target_ids().empty());
  StorageTargets::Config parsed;
  ASSERT_TRUE(parsed.update(toml::parse(R"(ec_target_ids = ["101", "18446744073709551615"])"), false));
  EXPECT_EQ(parsed.ec_target_ids().size(), 2u);
  Opened live(config);
  // Direct programmatic mutation is detected, never used to enable a Target.
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  CPUExecutorGroup executor(1, "ECPolicy");
  EXPECT_FALSE(live.targets.init(executor));
  EXPECT_FALSE(live.targets.create(batch()));
  EXPECT_FALSE(live.targets.create(request()));
  EXPECT_FALSE(boost::filesystem::exists(db()));
}

TEST_F(StorageTargetsEC, LegacyZeroTargetRemainsDisabledAndDuplicatesAreRejected) {
  {
    Opened live(config);
    ASSERT_TRUE(live.targets.create(batch({0})));
    auto target = live.get(0);
    ASSERT_TRUE(target);
    EXPECT_FALSE(target->readECShard(key, 1));
    EXPECT_FALSE(boost::filesystem::exists(db(0)));
    EXPECT_FALSE(live.targets.create(batch({101, 101})));
  }
  {
    Opened restarted(config);
    CPUExecutorGroup executor(1, "LegacyZeroReload");
    ASSERT_TRUE(restarted.targets.load(executor));
    ASSERT_TRUE(restarted.get(0));
    EXPECT_FALSE(boost::filesystem::exists(db(0)));
  }
}

TEST_F(StorageTargetsEC, UnidentifiedExistingDirectoryCannotBootstrapEC) {
  ASSERT_TRUE(config.set_ec_target_ids({"101"}));
  std::filesystem::create_directories((disk / "101").string());
  {
    std::ofstream old(disk / "101" / "old-data");
    old << "preserve";
  }
  Opened live(config);
  EXPECT_FALSE(live.targets.create(batch()));
  EXPECT_FALSE(boost::filesystem::exists(db()));
  EXPECT_TRUE(boost::filesystem::exists(disk / "101" / "old-data"));
  EXPECT_FALSE(live.get(101));
}

}  // namespace
