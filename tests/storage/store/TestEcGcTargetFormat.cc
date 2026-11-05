#include <boost/filesystem/operations.hpp>
#include <fstream>
#include <iterator>
#include <sstream>

#include "common/serde/Serde.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view gcMarker = "3FS_EC_ENGINE_ROOT_V3_GC\n";
constexpr std::string_view gcBlocker = "3FS_EC_ENGINE_V1_BLOCKED_BY_V3_GC\n";

StorageTargets::Config processConfig(const Path &root, bool gc) {
  StorageTargets::Config config;
  config.set_target_paths({root});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  config.set_ec_exact_gc(gc);
  return config;
}
CreateTargetReq createRequest() {
  CreateTargetReq req;
  req.chainId = ChainId{91};
  req.targetId = TargetId{92};
  req.onlyChunkEngine = true;
  return req;
}
std::string readFile(const Path &path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void writeFile(const Path &path, std::string_view bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(bytes.data(), bytes.size());
  output.close();
  ASSERT_TRUE(output.good()) << path;
}
EcStageRequest stageRequest(std::string_view data) {
  EcStageRequest request;
  request.operation = EcStageOperation::Begin;
  request.identity.object = Uuid::from(101, 102);
  request.identity.allocation = Uuid::from(103, 104);
  request.identity.generation = 1;
  request.vChainId = VersionedChainId{ChainId{91}, ChainVer{3}};
  request.targetId = TargetId{92};
  request.operationId = Uuid::from(105, 106);
  request.writerNamespace = Uuid::from(107, 108);
  auto integrity = computeEcIntegrity(request.identity, data);
  if (integrity) request.integrity = *integrity;
  return request;
}

TEST(TestEcGcTargetFormat, FreshFormatThreeSealsAndReopensWithSameIdentity) {
  folly::test::TemporaryDirectory directory;
  auto config = processConfig(directory.path(), true);
  CPUExecutorGroup executor(1, "GcFormat");
  const std::string data(65543, 'g');
  auto request = stageRequest(data);
  ASSERT_OK(request.validate());
  EcScopeTargetIdentity identity{};
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    ASSERT_OK(targets.create(createRequest(), true));
    auto found = map.getByTargetId(request.targetId);
    ASSERT_OK(found);
    const auto store = (*found)->storageTarget;
    ASSERT_TRUE(store->usesEcStagingEngine());
    ASSERT_TRUE(targets.engines().empty());
    auto physical = StorageTarget::readPhysicalConfig(store->path());
    ASSERT_OK(physical);
    EXPECT_TRUE(physical->ec_exact_gc);
    EXPECT_TRUE(physical->ec_only);
    EXPECT_TRUE(physical->ec_staging_v2);
    auto scope = store->ecScopeState();
    ASSERT_OK(scope);
    identity = scope->second;
    ASSERT_OK(store->executeEcStage(request));
    for (uint8_t block = 0; block != request.integrity.blockCount; ++block) {
      auto append = request;
      append.operation = EcStageOperation::Append;
      append.blockIndex = block;
      append.payload = data.substr(size_t(block) * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
      ASSERT_OK(store->executeEcStage(append));
    }
    auto seal = request;
    seal.operation = EcStageOperation::Seal;
    auto sealed = store->executeEcStage(seal);
    ASSERT_OK(sealed);
    ASSERT_TRUE(sealed->sealed);
    EXPECT_EQ(sealed->sealed->length, data.size());
    auto repeated = createRequest();
    repeated.allowExistingTarget = true;
    ASSERT_OK(targets.create(repeated, true));
  }
  EXPECT_EQ(readFile(directory.path() / "engine"), gcMarker);
  EXPECT_EQ(readFile(directory.path() / "engine-ec-v1"), gcBlocker);
  {
    // Query the actual same persisted namespace through the explicit opener,
    // after all previous target/map/scope owners were destroyed normally.
    auto facade = EcStagingEngine::openExactGc(directory.path() / "engine-ec-v2", false);
    ASSERT_OK(facade);
    auto actual = (*facade)->actualDiskFormat();
    ASSERT_OK(actual);
    EXPECT_EQ(*actual, 3);
  }
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    auto found = map.getByTargetId(request.targetId);
    ASSERT_OK(found);
    const auto store = (*found)->storageTarget;
    auto scope = store->ecScopeState();
    ASSERT_OK(scope);
    EXPECT_EQ(scope->second, identity);
    auto reconcile = request;
    reconcile.operation = EcStageOperation::Reconcile;
    ASSERT_OK(store->executeEcStage(reconcile));
    std::string read;
    for (uint8_t block = 0; block != request.integrity.blockCount; ++block) {
      auto input = request;
      input.operation = EcStageOperation::ReadBlock;
      input.blockIndex = block;
      auto output = store->executeEcStage(input);
      ASSERT_OK(output);
      read += output->data;
    }
    EXPECT_EQ(read, data);
    EXPECT_FALSE(store->createEcFragment(EcCreateReq{}));
  }
}

TEST(TestEcGcTargetFormat, RootModesRejectBothConversionsWithoutRewritingMarkers) {
  CPUExecutorGroup executor(1, "GcMode");
  for (bool gc : {false, true}) {
    SCOPED_TRACE(gc);
    folly::test::TemporaryDirectory directory;
    auto config = processConfig(directory.path(), gc);
    {
      AtomicallyTargetMap map;
      StorageTargets targets(config, map);
      ASSERT_OK(targets.load(executor));
      ASSERT_OK(targets.create(createRequest(), true));
    }
    const auto marker = readFile(directory.path() / "engine");
    const auto blocker = readFile(directory.path() / "engine-ec-v1");
    const auto physical = readFile(directory.path() / "92" / kEcPhysicalConfigFileName);
    {
      auto wrong = processConfig(directory.path(), !gc);
      AtomicallyTargetMap map;
      StorageTargets targets(wrong, map);
      ASSERT_FALSE(targets.load(executor));
    }
    EXPECT_EQ(readFile(directory.path() / "engine"), marker);
    EXPECT_EQ(readFile(directory.path() / "engine-ec-v1"), blocker);
    EXPECT_EQ(readFile(directory.path() / "92" / kEcPhysicalConfigFileName), physical);
    {
      AtomicallyTargetMap map;
      StorageTargets targets(config, map);
      ASSERT_OK(targets.load(executor));
    }
  }
}

TEST(TestEcGcTargetFormat, ContradictoryProcessFlagsRejectBeforeRootMutation) {
  CPUExecutorGroup executor(1, "GcFlags");
  for (unsigned flags : {0u, 1u, 2u}) {
    folly::test::TemporaryDirectory directory;
    auto config = processConfig(directory.path(), true);
    config.set_ec_only((flags & 1) != 0);
    config.set_ec_staging_v2((flags & 2) != 0);
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.init(executor));
    EXPECT_TRUE(boost::filesystem::is_empty(directory.path()));
  }
}

TEST(TestEcGcTargetFormat, PartialMarkerRecoveryStopsOnceEngineExists) {
  folly::test::TemporaryDirectory directory;
  auto config = processConfig(directory.path(), true);
  CPUExecutorGroup executor(1, "GcMarker");
  ASSERT_NO_FATAL_FAILURE(writeFile(directory.path() / "engine", gcMarker));
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.init(executor));
  }
  EXPECT_EQ(readFile(directory.path() / "engine-ec-v1"), gcBlocker);
  ASSERT_TRUE(boost::filesystem::is_directory(directory.path() / "engine-ec-v2"));
  ASSERT_TRUE(boost::filesystem::remove(directory.path() / "engine-ec-v1"));
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.init(executor));
  }
  EXPECT_FALSE(boost::filesystem::exists(directory.path() / "engine-ec-v1"));
  EXPECT_EQ(readFile(directory.path() / "engine"), gcMarker);
}

TEST(TestEcGcTargetFormat, UnsafeOrContradictoryRootsDoNotOpenDatabase) {
  CPUExecutorGroup executor(1, "GcBadRoot");
  for (unsigned scenario = 0; scenario != 6; ++scenario) {
    SCOPED_TRACE(scenario);
    folly::test::TemporaryDirectory directory;
    const auto root = directory.path();
    switch (scenario) {
      case 0:
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine", "3FS_EC_ENGINE_ROOT_V2\n"));
        break;
      case 1:
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine", "incorrect marker\n"));
        break;
      case 2:
        boost::filesystem::create_symlink("missing-root", root / "engine");
        break;
      case 3:
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine", gcMarker));
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine-ec-v1", "3FS_EC_ENGINE_V1_BLOCKED_BY_V2\n"));
        break;
      case 4:
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine", gcMarker));
        boost::filesystem::create_directory(root / "unexpected");
        break;
      case 5:
        ASSERT_NO_FATAL_FAILURE(writeFile(root / "engine-ec-v1", gcBlocker));
        break;
    }
    auto config = processConfig(root, true);
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.init(executor));
    EXPECT_FALSE(boost::filesystem::exists(root / "engine-ec-v2" / "meta"));
  }
}

TEST(TestEcGcTargetFormat, ActualFacadeRejectsPhysicalModeConflictsBeforeCreatingTarget) {
  folly::test::TemporaryDirectory directory;
  auto process = processConfig(directory.path(), true);
  CPUExecutorGroup executor(1, "GcPhysical");
  {
    AtomicallyTargetMap map;
    StorageTargets targets(process, map);
    ASSERT_OK(targets.init(executor));
  }
  auto opened = EcStagingEngine::openExactGc(directory.path() / "engine-ec-v2", false);
  ASSERT_OK(opened);
  GlobalFileStore files;
  auto store = StorageTarget::enable_shared_from_this::create(process.storage_target(), files, 0, nullptr, *opened);
  PhysicalConfig physical;
  physical.path = directory.path() / "92";
  physical.target_id = 92;
  physical.chain_id = 91;
  physical.allow_disk_without_uuid = true;
  physical.only_chunk_engine = true;
  physical.ec_only = true;
  physical.ec_staging_v2 = true;
  // Default false means format 2, even when a caller supplies a format-3 facade.
  ASSERT_FALSE(store->create(physical));
  EXPECT_FALSE(boost::filesystem::exists(physical.path));
  physical.ec_exact_gc = true;
  ASSERT_OK(store->create(physical));
  ASSERT_OK(store->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
  physical.allow_existing_targets = true;
  ASSERT_OK(store->create(physical));
  physical.ec_exact_gc = false;
  ASSERT_FALSE(store->create(physical));

  auto stored = StorageTarget::readPhysicalConfig(physical.path);
  ASSERT_OK(stored);
  stored->ec_exact_gc = false;
  ASSERT_NO_FATAL_FAILURE(writeFile(physical.path / kEcPhysicalConfigFileName, serde::toTomlString(*stored)));
  auto another = StorageTarget::enable_shared_from_this::create(process.storage_target(), files, 0, nullptr, *opened);
  ASSERT_FALSE(another->load(physical.path));
  stored->ec_exact_gc = true;
  stored->ec_staging_v2 = false;
  ASSERT_NO_FATAL_FAILURE(writeFile(physical.path / kEcPhysicalConfigFileName, serde::toTomlString(*stored)));
  ASSERT_FALSE(StorageTarget::readPhysicalConfig(physical.path));
}

TEST(TestEcGcTargetFormat, ExistingTargetReplayRechecksPersistentFormat) {
  folly::test::TemporaryDirectory directory;
  auto config = processConfig(directory.path(), true);
  CPUExecutorGroup executor(1, "GcReplay");
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(executor));
  auto request = createRequest();
  ASSERT_OK(targets.create(request, true));
  request.allowExistingTarget = true;
  const auto path = directory.path() / "92";
  const auto original = readFile(path / kEcPhysicalConfigFileName);
  auto physical = StorageTarget::readPhysicalConfig(path);
  ASSERT_OK(physical);
  physical->ec_exact_gc = false;
  ASSERT_NO_FATAL_FAILURE(writeFile(path / kEcPhysicalConfigFileName, serde::toTomlString(*physical)));
  ASSERT_FALSE(targets.create(request, true));
  ASSERT_NO_FATAL_FAILURE(writeFile(path / kEcPhysicalConfigFileName, original));
  ASSERT_OK(targets.create(request, true));
}

TEST(TestEcGcTargetFormat, MissingPhysicalFlagKeepsExistingFormatTwoCompatible) {
  folly::test::TemporaryDirectory directory;
  auto config = processConfig(directory.path(), false);
  CPUExecutorGroup executor(1, "GcLegacyV2");
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    ASSERT_OK(targets.create(createRequest(), true));
  }
  const auto path = directory.path() / "92" / kEcPhysicalConfigFileName;
  std::istringstream input(readFile(path));
  std::string line;
  std::string previousSchema;
  bool removed = false;
  while (std::getline(input, line)) {
    if (line.find("ec_exact_gc") != std::string::npos) {
      EXPECT_NE(line.find("false"), std::string::npos);
      removed = true;
    } else {
      previousSchema += line + '\n';
    }
  }
  ASSERT_TRUE(removed);
  ASSERT_NO_FATAL_FAILURE(writeFile(path, previousSchema));
  PhysicalConfig decoded;
  ASSERT_OK(serde::fromTomlString(decoded, previousSchema));
  EXPECT_FALSE(decoded.ec_exact_gc);
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(executor));
}
}  // namespace
}  // namespace hf3fs::storage
