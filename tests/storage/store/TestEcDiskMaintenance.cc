#include <atomic>
#include <boost/filesystem/operations.hpp>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include "storage/service/Components.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"
#include "tests/lib/UnitTestFabric.h"

namespace hf3fs::storage {
namespace {
using namespace std::chrono_literals;

EcStageRequest stageRequest() {
  EcStageRequest request;
  request.operation = EcStageOperation::Begin;
  request.identity.object = Uuid::from(300, 301);
  request.identity.allocation = Uuid::from(302, 303);
  request.identity.generation = 1;
  request.identity.shard = 0;
  request.vChainId = VersionedChainId{ChainId{91}, ChainVer{1}};
  request.targetId = TargetId{92};
  request.operationId = Uuid::from(304, 305);
  request.writerNamespace = Uuid::from(306, 307);
  auto integrity = computeEcIntegrity(request.identity, std::string(65536, 'D'));
  EXPECT_TRUE(integrity);
  if (integrity) request.integrity = *integrity;
  return request;
}

bool waitFor(const std::function<bool()> &predicate, std::chrono::seconds timeout = 8s) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) return true;
    std::this_thread::sleep_for(20ms);
  }
  return predicate();
}

void smallComponents(Components::Config &config, const std::vector<Path> &paths, bool staging) {
  config.targets().set_target_paths(paths);
  config.targets().set_allow_disk_without_uuid(true);
  config.targets().set_ec_only(true);
  config.targets().set_ec_staging_v2(staging);
  config.aio_read_worker().set_num_threads(1);
  config.aio_read_worker().set_queue_size(8);
  config.sync_worker().set_num_threads(1);
  config.storage().write_worker().set_num_threads(1);
  config.storage().write_worker().set_bg_num_threads(1);
  config.storage().write_worker().set_queue_size(8);
  for (auto *pool : {&config.coroutines_pool_read(),
                     &config.coroutines_pool_update(),
                     &config.coroutines_pool_sync(),
                     &config.coroutines_pool_default()}) {
    pool->set_threads_num(1);
    pool->set_coroutines_num(2);
    pool->set_queue_size(8);
  }
}

TEST(TestEcDiskMaintenance, V1AndV2AccountingAndExpansionGateUseActualDisk) {
  for (bool staging : {false, true}) {
    SCOPED_TRACE(staging ? "V2 staging" : "V1 immutable");
    folly::test::TemporaryDirectory directory;
    StorageTargets::Config config;
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(staging);
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    CPUExecutorGroup loader(1, "EcMaintenance");
    ASSERT_OK(targets.load(loader));
    EXPECT_EQ(targets.engines().empty(), staging);
    CreateTargetReq create;
    create.chainId = ChainId{91};
    create.targetId = TargetId{92};
    create.onlyChunkEngine = true;
    ASSERT_OK(targets.create(create, true));
    auto target = map.getByTargetId(create.targetId);
    ASSERT_OK(target);
    auto store = (*target)->storageTarget;
    ASSERT_NE(store, nullptr);
    auto initial = targets.physicalUsedSize(0);
    ASSERT_OK(initial);
    ASSERT_ERROR(targets.physicalUsedSize(1), StatusCode::kInvalidArg);
    ASSERT_ERROR(targets.sampleEngineMetrics(1), StatusCode::kInvalidArg);
    ASSERT_ERROR(targets.setAllowToAllocate(1, false), StatusCode::kInvalidArg);

    auto request = stageRequest();
    EcCreateReq immutable;
    immutable.identity = request.identity;
    immutable.vChainId = request.vChainId;
    immutable.targetId = request.targetId;
    immutable.operationId = request.operationId;
    immutable.payload.data.assign(65536, 'D');
    immutable.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                              reinterpret_cast<const uint8_t *>(immutable.payload.data.data()),
                                              immutable.payload.data.size());
    ASSERT_OK(targets.setAllowToAllocate(0, false));
    if (staging) {
      ASSERT_ERROR(store->executeEcStage(request), StorageClientCode::kNoSpace);
    } else {
      // V1 preserves its conservative mutation-error contract even when
      // this local fixture knows the disk was empty before the call.
      ASSERT_ERROR(store->createEcFragment(immutable), StorageCode::kEcSealOutcomeUnknown);
    }
    auto denied = targets.physicalUsedSize(0);
    ASSERT_OK(denied);
    EXPECT_EQ(denied->allocated_size, initial->allocated_size);
    EXPECT_EQ(denied->position_count, initial->position_count);
    ASSERT_OK(targets.setAllowToAllocate(0, true));
    if (staging) {
      ASSERT_OK(store->executeEcStage(request));
      ASSERT_OK(targets.setAllowToAllocate(0, false));
      request.operation = EcStageOperation::Append;
      request.payload = immutable.payload.data;
      ASSERT_OK(store->executeEcStage(request));
      request.operation = EcStageOperation::Seal;
      request.payload.clear();
      auto sealed = store->executeEcStage(request);
      ASSERT_OK(sealed);
      ASSERT_TRUE(sealed->sealed);
      request.operation = EcStageOperation::ReadBlock;
      auto read = store->executeEcStage(request);
      ASSERT_OK(read);
      EXPECT_EQ(read->data, immutable.payload.data);
    } else {
      ASSERT_OK(store->createEcFragment(immutable));
      ASSERT_OK(targets.setAllowToAllocate(0, false));
      ASSERT_ERROR(store->createEcFragment(immutable), StorageCode::kChunkAlreadyExists);
      EcReadReq read;
      read.identity = immutable.identity;
      read.vChainId = immutable.vChainId;
      read.targetId = immutable.targetId;
      read.operationId = immutable.operationId;
      read.expectedLength = immutable.payload.data.size();
      read.checksum = immutable.checksum;
      auto stored = store->readEcFragment(read);
      ASSERT_OK(stored);
      EXPECT_EQ(stored->payload.data, immutable.payload.data);
    }
    auto committed = targets.physicalUsedSize(0);
    ASSERT_OK(committed);
    EXPECT_GT(committed->allocated_size, initial->allocated_size);
    EXPECT_EQ(committed->position_count, initial->position_count + 1);
    EXPECT_GT(store->usedSize(), 0);
    ASSERT_OK(targets.sampleEngineMetrics(0));
    map.release().reset();
  }
}

TEST(TestEcDiskMaintenance, BackgroundWorkerChecksDifferentDiskCountsAndStops) {
  // Reconstruct the actual worker twice in one process: the old function-static
  // recorder vector had size one and was indexed as size two on the second run.
  for (bool staging : {false, true}) {
    SCOPED_TRACE(staging ? "V2, two disks" : "V1, one disk");
    folly::test::TemporaryDirectory first;
    folly::test::TemporaryDirectory second;
    std::vector<Path> paths{first.path()};
    if (staging) paths.push_back(second.path());
    Components::Config config;
    smallComponents(config, paths, staging);
    // A deterministic local watermark, independent of host disk occupancy.
    config.check_worker().set_disk_low_space_threshold(0.0);
    config.check_worker().set_disk_reject_create_chunk_threshold(0.0);
    config.check_worker().set_update_target_size_interval(1_ms);
    Components components(config);
    components.mgmtdClient = std::make_shared<hf3fs::test::FakeMgmtdClient>(std::make_shared<flat::RoutingInfo>());
    CPUExecutorGroup loader(1, "EcCheckWorker");
    ASSERT_OK(components.storageTargets.load(loader));
    for (size_t disk = 0; disk != paths.size(); ++disk) {
      CreateTargetReq create;
      create.diskIndex = disk;
      create.chainId = ChainId{static_cast<uint32_t>(91 + disk)};
      create.targetId = TargetId{92 + disk};
      create.onlyChunkEngine = true;
      ASSERT_OK(components.storageTargets.create(create, true));
    }
    // Before the worker starts, make its exact probe path on disk 1 a
    // directory. This deterministic writability failure does not depend on
    // chmod behavior under root, and avoids racing an active probe write.
    if (staging) {
      const auto probe = paths[1] / ".hf3fs_check";
      // load() has already probed this disk. Replace only that regular file
      // inside the test-owned temporary directory, before starting the worker.
      ASSERT_TRUE(boost::filesystem::is_regular_file(boost::filesystem::symlink_status(probe)));
      ASSERT_TRUE(boost::filesystem::remove(probe));
      ASSERT_TRUE(boost::filesystem::create_directory(probe));
    }
    std::atomic<size_t> observations{0};
    components.targetMap.setUpdateCallback([&](const TargetMap &) { ++observations; });
    bool started = false;
    SCOPE_EXIT {
      if (started) EXPECT_TRUE(components.checkWorker.stopAndJoin());
      components.targetMap.setUpdateCallback([](const TargetMap &) {});
      components.targetMap.release().reset();
      components.mgmtdClient.store(nullptr);
    };
    const auto startedAt = std::chrono::steady_clock::now();
    ASSERT_OK(components.checkWorker.start(components.storageTargets.targetPaths(),
                                           components.storageTargets.manufacturers()));
    started = true;
    // Callbacks also arise from disk-state/offline transitions, so their count
    // is not an iteration count. Require both observable worker progress and a
    // monotonic interval exceeding its one-second metrics period. stopAndJoin
    // below waits for the current complete iteration, including metrics.
    ASSERT_TRUE(
        waitFor([&] { return observations.load() >= 25 && std::chrono::steady_clock::now() - startedAt >= 1500ms; }));
    for (size_t disk = 0; disk != paths.size(); ++disk) {
      auto target = components.targetMap.getByTargetId(TargetId{92 + disk});
      ASSERT_OK(target);
      if (staging && disk == 1) {
        EXPECT_TRUE((*target)->diskError);
        EXPECT_TRUE(boost::filesystem::is_directory(paths[disk] / ".hf3fs_check"));
        continue;
      }
      EXPECT_TRUE((*target)->lowSpace);
      EXPECT_TRUE((*target)->rejectCreateChunk);
      EXPECT_FALSE((*target)->diskError);
      EXPECT_TRUE(boost::filesystem::is_regular_file(paths[disk] / ".hf3fs_check"));
      auto request = stageRequest();
      request.vChainId.chainId = ChainId{static_cast<uint32_t>(91 + disk)};
      request.targetId = TargetId{92 + disk};
      if (staging) {
        // No physical group exists yet: the real worker has closed the Rust
        // expansion gate, so direct local Begin also reports NoSpace.
        ASSERT_ERROR((*target)->storageTarget->executeEcStage(request), StorageClientCode::kNoSpace);
      }
    }
    ASSERT_OK(components.checkWorker.stopAndJoin());
    started = false;
  }
}
}  // namespace
}  // namespace hf3fs::storage
