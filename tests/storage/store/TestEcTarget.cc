#include <array>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <map>

#include "common/serde/Serde.h"
#include "storage/store/StorageTargets.h"
#include "storage/update/UpdateWorker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {

CreateTargetReq targetRequest() {
  CreateTargetReq request;
  request.targetId = TargetId{71};
  request.chainId = ChainId{81};
  request.onlyChunkEngine = true;
  return request;
}

EcCreateReq fragmentRequest() {
  EcCreateReq request;
  request.identity.object = Uuid::from(1, 2);
  request.identity.allocation = Uuid::from(3, 4);
  request.identity.generation = 1;
  request.identity.stripe = 5;
  request.identity.shard = 11;
  request.vChainId = VersionedChainId{ChainId{81}, ChainVer{1}};
  request.targetId = TargetId{71};
  request.operationId = Uuid::from(6, 7);
  request.payload.data = std::string("fragment\0with-tail", 18);
  request.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                          reinterpret_cast<const uint8_t *>(request.payload.data.data()),
                                          request.payload.data.size());
  return request;
}

EcReadReq readRequest(const EcCreateReq &create) {
  EcReadReq request;
  request.identity = create.identity;
  request.vChainId = create.vChainId;
  request.targetId = create.targetId;
  request.operationId = create.operationId;
  request.expectedLength = create.payload.data.size();
  request.checksum = create.checksum;
  return request;
}

EcReconcileReq reconcileRequest(const EcCreateReq &create) {
  EcReconcileReq request;
  request.identity = create.identity;
  request.vChainId = create.vChainId;
  request.targetId = create.targetId;
  request.operationId = create.operationId;
  request.expectedLength = create.payload.data.size();
  request.checksum = create.checksum;
  return request;
}

template <typename Job>
void runJob(UpdateWorker &worker, Job &job) {
  folly::coro::blockingWait(worker.enqueue(&job));
  folly::coro::blockingWait(job.complete());
}

auto snapshotFiles(const Path &root) {
  std::map<std::string, std::pair<uint64_t, uint32_t>> snapshot;
  std::array<uint8_t, 64 * 1024> buffer;
  for (const auto &entry : boost::filesystem::recursive_directory_iterator(root)) {
    if (!boost::filesystem::is_regular_file(entry.path())) continue;
    std::ifstream input(entry.path(), std::ios::binary);
    uint64_t size = 0;
    uint32_t checksum = ~uint32_t{};
    while (input.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || input.gcount() != 0) {
      const auto count = static_cast<size_t>(input.gcount());
      checksum = folly::crc32c(buffer.data(), count, checksum);
      size += count;
    }
    EXPECT_TRUE(input.eof()) << entry.path();
    snapshot.emplace(boost::filesystem::relative(entry.path(), root).string(), std::make_pair(size, checksum));
  }
  return snapshot;
}

TEST(TestEcTarget, WorkerCreateReadAndCleanReopen) {
  folly::test::TemporaryDirectory directory;
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup executor(1, "EcTest");
  auto create = fragmentRequest();
  auto read = readRequest(create);
  auto empty = create;
  empty.identity.allocation = Uuid::from(20, 21);
  empty.payload.data.clear();
  empty.checksum =
      ChecksumInfo::create(ChecksumType::CRC32C, reinterpret_cast<const uint8_t *>(empty.payload.data.data()), 0);
  for (unsigned reopen = 0; reopen != 2; ++reopen) {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    if (reopen == 0) ASSERT_OK(targets.create(targetRequest(), true));
    auto target = map.getByTargetId(create.targetId);
    ASSERT_OK(target);
    auto store = (*target)->storageTarget;
    ASSERT_TRUE(store->ecOnly());
    UpdateWorker::Config workerConfig;
    workerConfig.set_num_threads(1);
    workerConfig.set_bg_num_threads(1);
    workerConfig.set_queue_size(2);
    UpdateWorker worker(workerConfig);
    ASSERT_OK(worker.start(1));
    const auto validRoute = []() -> Result<Void> { return Void{}; };
    if (reopen == 0) {
      // A stale route at dequeue must prevent creation, not merely suppress
      // its response after an otherwise successful write.
      EcCreateJob stale(create, store, []() -> Result<Void> {
        return makeError(StorageClientCode::kRoutingVersionMismatch, "injected stale route");
      });
      runJob(worker, stale);
      ASSERT_FALSE(stale.result());
      ASSERT_EQ(stale.result().error().code(), StorageClientCode::kRoutingVersionMismatch);
      ASSERT_FALSE(store->readEcFragment(read));

      EcCreateJob job(create, store, validRoute);
      runJob(worker, job);
      ASSERT_OK(job.result());
      ASSERT_EQ(job.result()->length, create.payload.data.size());
      ASSERT_EQ(job.result()->checksum, create.checksum);
      EcCreateJob emptyJob(empty, store, validRoute);
      runJob(worker, emptyJob);
      ASSERT_OK(emptyJob.result());
      EcCreateJob duplicate(create, store, validRoute);
      runJob(worker, duplicate);
      ASSERT_FALSE(duplicate.result());
      ASSERT_EQ(duplicate.result().error().code(), StorageCode::kChunkAlreadyExists);

      auto invalid = create;
      invalid.identity.allocation = Uuid::from(8, 9);
      invalid.checksum.value ^= 1;
      EcCreateJob corrupt(invalid, store, validRoute);
      runJob(worker, corrupt);
      ASSERT_FALSE(corrupt.result());
      ASSERT_EQ(corrupt.result().error().code(), StorageCode::kChecksumMismatch);
      invalid.payload.data.resize(kEcFragmentRpcMaxBytes + 1);
      ASSERT_FALSE(store->createEcFragment(invalid));

      // Construct an actual pre-existing uncommitted engine operation. Only
      // this test bypasses StorageTarget's legacy-operation prohibition.
      // The second create writes a private allocation before observing that
      // occupied writing-list entry, so its engine InvalidArg is ambiguous.
      {
        auto pending = create;
        pending.identity.allocation = Uuid::from(30, 31);
        auto pendingKey = pending.identity.chunkId();
        ASSERT_OK(pendingKey);
        const auto chainId = pending.vChainId.chainId;
        std::string engineKey(reinterpret_cast<const char *>(&chainId), sizeof(chainId));
        engineKey.append(pendingKey->data());
        chunk_engine::UpdateReq initial{};
        initial.length = pending.payload.data.size();
        initial.checksum = ~pending.checksum.value;
        initial.chain_ver = pending.vChainId.chainVer;
        // This existing API consumes the pointer synchronously; pending owns
        // the unchanged payload throughout the call and both operations.
        initial.data = reinterpret_cast<uint64_t>(pending.payload.data.data());
        std::string error;
        auto *inFlight = targets.engines()[0]->update_raw_chunk(ChunkEngine::toSlice(engineKey), initial, error);
        ASSERT_TRUE(error.empty()) << error;
        ASSERT_NE(inFlight, nullptr);
        SCOPE_EXIT { targets.engines()[0]->release_writing_chunk(inFlight); };
        EcCreateJob uncertain(pending, store, validRoute);
        runJob(worker, uncertain);
        ASSERT_FALSE(uncertain.result());
        ASSERT_EQ(uncertain.result().error().code(), StorageCode::kEcSealOutcomeUnknown);
        ASSERT_NE(uncertain.result().error().message().find("engine code 3"), std::string::npos);
        ASSERT_NE(uncertain.result().error().message().find("reconcile"), std::string::npos);
      }

      // All legacy mutation kinds, including CRAQ commit, are rejected at
      // the physical target even when a caller bypasses service checks.
      ServiceRequestContext context;
      ChunkEngineUpdateJob chunk;
      auto key = create.identity.chunkId();
      ASSERT_OK(key);
      for (auto type : {UpdateType::WRITE, UpdateType::REMOVE, UpdateType::TRUNCATE, UpdateType::EXTEND}) {
        UpdateIO io;
        io.key.chunkId = *key;
        io.updateType = type;
        UpdateJob legacy(context, io, {}, chunk, store);
        runJob(worker, legacy);
        ASSERT_FALSE(legacy.result().lengthInfo);
      }
      CommitIO commit;
      commit.key.chunkId = *key;
      UpdateJob legacyCommit(context, commit, {}, chunk, store);
      runJob(worker, legacyCommit);
      ASSERT_FALSE(legacyCommit.result().lengthInfo);
      ASSERT_FALSE(store->queryChunk(*key));
      ASSERT_FALSE(store->uncommitted());
      ASSERT_FALSE(store->resetUncommitted(ChainVer{2}));
      ASSERT_FALSE(store->addChunkSize({1_MB}));
      ChunkMetaVector metadata;
      ASSERT_FALSE(store->getAllMetadata(metadata));
      BatchReadReq legacyRead;
      legacyRead.payloads.emplace_back();
      legacyRead.payloads.front().key.chunkId = *key;
      legacyRead.payloads.front().length = create.payload.data.size();
      BatchReadRsp legacyReadResponse;
      legacyReadResponse.results.resize(1);
      BatchReadJob legacyReadJob(legacyRead.payloads, legacyReadResponse.results, ChecksumType::NONE);
      ASSERT_FALSE(store->aioPrepareRead(legacyReadJob.front()));
      ASSERT_FALSE(targets.removeChunkEngineTarget(create.vChainId.chainId, 0));
      ASSERT_FALSE(map.removeTarget(create.targetId));
    }
    EcReadJob job(read, store, validRoute);
    runJob(worker, job);
    ASSERT_OK(job.result());
    ASSERT_EQ(job.result()->payload.data, create.payload.data);
    ASSERT_EQ(job.result()->receipt.checksum, create.checksum);
    auto emptyRead = store->readEcFragment(readRequest(empty));
    ASSERT_OK(emptyRead);
    ASSERT_TRUE(emptyRead->payload.data.empty());
    auto reconcile = reconcileRequest(create);
    reconcile.vChainId.chainVer = ChainVer{2};
    EcReconcileJob confirmation(reconcile, store, validRoute);
    runJob(worker, confirmation);
    ASSERT_OK(confirmation.result());
    ASSERT_EQ(confirmation.result()->vChainId, reconcile.vChainId);
    ASSERT_EQ(confirmation.result()->operationId, create.operationId);
    ASSERT_EQ(confirmation.result()->checksum, create.checksum);
    ASSERT_EQ(confirmation.result()->length, create.payload.data.size());
    ASSERT_OK(store->reconcileEcFragment(reconcileRequest(empty)));

    EcReconcileJob staleConfirmation(reconcile, store, []() -> Result<Void> {
      return makeError(StorageClientCode::kRoutingVersionMismatch, "injected stale route");
    });
    runJob(worker, staleConfirmation);
    ASSERT_FALSE(staleConfirmation.result());
    ASSERT_EQ(staleConfirmation.result().error().code(), StorageClientCode::kRoutingVersionMismatch);
    auto wrongReconcile = reconcile;
    wrongReconcile.operationId = Uuid::from(99, 100);
    auto mismatchedConfirmation = store->reconcileEcFragment(wrongReconcile);
    ASSERT_FALSE(mismatchedConfirmation);
    ASSERT_EQ(mismatchedConfirmation.error().code(), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcile;
    ++wrongReconcile.expectedLength;
    mismatchedConfirmation = store->reconcileEcFragment(wrongReconcile);
    ASSERT_FALSE(mismatchedConfirmation);
    ASSERT_EQ(mismatchedConfirmation.error().code(), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcile;
    wrongReconcile.checksum.value ^= 1;
    mismatchedConfirmation = store->reconcileEcFragment(wrongReconcile);
    ASSERT_FALSE(mismatchedConfirmation);
    ASSERT_EQ(mismatchedConfirmation.error().code(), StorageCode::kEcSealOutcomeUnknown);
    wrongReconcile = reconcile;
    wrongReconcile.identity.allocation = Uuid::from(100, 101);
    mismatchedConfirmation = store->reconcileEcFragment(wrongReconcile);
    ASSERT_FALSE(mismatchedConfirmation);
    ASSERT_EQ(mismatchedConfirmation.error().code(), StorageCode::kEcSealOutcomeUnknown);
    auto missingRead = read;
    missingRead.identity = wrongReconcile.identity;
    auto absent = store->readEcFragment(missingRead);
    ASSERT_FALSE(absent);
    ASSERT_EQ(absent.error().code(), StorageCode::kChunkMetadataNotFound);
    wrongReconcile.expectedLength = kEcFragmentRpcMaxBytes + 1;
    auto invalidConfirmation = store->reconcileEcFragment(wrongReconcile);
    ASSERT_FALSE(invalidConfirmation);
    ASSERT_EQ(invalidConfirmation.error().code(), StatusCode::kInvalidArg);
    auto wrongRead = read;
    wrongRead.operationId = Uuid::from(99, 100);
    ASSERT_FALSE(store->readEcFragment(wrongRead));
    wrongRead = read;
    ++wrongRead.expectedLength;
    ASSERT_FALSE(store->readEcFragment(wrongRead));
    wrongRead = read;
    wrongRead.checksum.value ^= 1;
    ASSERT_FALSE(store->readEcFragment(wrongRead));
  }
}

TEST(TestEcTarget, StrictConfigurationAndLegacyCreationIsolation) {
  folly::test::TemporaryDirectory directory;
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup executor(1, "EcConfig");
  const auto path = directory.path() / "71";
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    auto request = targetRequest();
    ASSERT_OK(targets.create(request, true));
    PhysicalConfig legacyParser;
    ASSERT_FALSE(serde::fromTomlFile(legacyParser, path / kPhysicalConfigFileName));
    request.allowExistingTarget = true;
    ASSERT_FALSE(targets.create(request));
    ASSERT_OK(targets.create(request, true));
    request.addChunkSize = true;
    ASSERT_FALSE(targets.create(request, true));
    request = targetRequest();
    request.targetId = TargetId{72};
    ASSERT_FALSE(targets.create(request, true));
    request.chainId = ChainId{82};
    ASSERT_FALSE(targets.create(request));
    ASSERT_OK(targets.create(request, true));
    request.allowExistingTarget = true;
    ASSERT_FALSE(targets.create(request));
  }
  PhysicalConfig ecConfig;
  ASSERT_OK(serde::fromTomlFile(ecConfig, path / kEcPhysicalConfigFileName));
  const auto original = serde::toTomlString(ecConfig);
  const auto write = [](const Path &file, std::string_view bytes) {
    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), bytes.size());
    ASSERT_TRUE(stream.good());
  };
  const auto rejectsLoad = [&]() {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.load(executor));
  };
  ecConfig.ec_only = false;
  write(path / kEcPhysicalConfigFileName, serde::toTomlString(ecConfig));
  rejectsLoad();
  write(path / kEcPhysicalConfigFileName, original);
  write(path / kPhysicalConfigFileName, "3FS_EC_TARGET_V1\nextra");
  rejectsLoad();
  boost::filesystem::remove(path / kPhysicalConfigFileName);
  rejectsLoad();  // Companion without marker is not silently skipped.
  write(path / kPhysicalConfigFileName, kEcTargetMarker);
  boost::filesystem::remove(path / kEcPhysicalConfigFileName);
  rejectsLoad();  // Marker without companion cannot become legacy TOML.
  write(path / kEcPhysicalConfigFileName, original);
  const auto dangling = directory.path() / "73" / kEcPhysicalConfigFileName;
  boost::filesystem::create_directory(dangling.parent_path());
  boost::filesystem::create_symlink("missing-ec-config", dangling);
  rejectsLoad();  // A dangling EC companion is not an absent configuration.
  boost::filesystem::remove(dangling);
  boost::filesystem::remove(dangling.parent_path());
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(executor));
}

TEST(TestEcTarget, EcRootBlocksLegacyEngineOpenAndModeDowngrade) {
  folly::test::TemporaryDirectory directory;
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup executor(1, "EcRoot");
  const auto create = fragmentRequest();
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    ASSERT_OK(targets.create(targetRequest(), true));
    auto target = map.getByTargetId(create.targetId);
    ASSERT_OK(target);
    ASSERT_OK((*target)->storageTarget->createEcFragment(create));
    ASSERT_FALSE(targets.create(StorageTargets::CreateConfig{}));
  }
  const auto marker = directory.path() / "engine";
  const auto ecEngine = directory.path() / kEcEngineDirectoryName;
  ASSERT_TRUE(boost::filesystem::is_regular_file(marker));
  ASSERT_TRUE(boost::filesystem::is_directory(ecEngine));
  const auto original = snapshotFiles(ecEngine);
  ASSERT_FALSE(original.empty());
  // Exercise the actual old path and unchanged Engine::open entry point,
  // while the EC engine is closed. TOML parsing plays no role in this test.
  for (const bool allowCreate : {false, true}) {
    std::string error;
    auto *legacy = chunk_engine::create(marker.c_str(), allowCreate, sizeof(ChainId), error);
    if (legacy != nullptr) {
      auto unexpectedEngine = rust::Box<chunk_engine::Engine>::from_raw(legacy);
    }
    ASSERT_EQ(legacy, nullptr);
    ASSERT_FALSE(error.empty());
    ASSERT_EQ(snapshotFiles(ecEngine), original);
  }
  config.set_ec_only(false);
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.load(executor));
  }
  ASSERT_EQ(snapshotFiles(ecEngine), original);
  config.set_ec_only(true);
  {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(executor));
    auto target = map.getByTargetId(create.targetId);
    ASSERT_OK(target);
    auto read = (*target)->storageTarget->readEcFragment(readRequest(create));
    ASSERT_OK(read);
    ASSERT_EQ(read->payload.data, create.payload.data);
    ASSERT_OK((*target)->storageTarget->reconcileEcFragment(reconcileRequest(create)));
  }
}

TEST(TestEcTarget, EcRootRejectsLegacyRestoreAndUnsafeMarkersBeforeEngineOpen) {
  CPUExecutorGroup executor(1, "EcRootReject");
  const auto write = [](const Path &file, std::string_view bytes) {
    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), bytes.size());
    ASSERT_TRUE(stream.good());
  };
  for (unsigned scenario = 0; scenario != 6; ++scenario) {
    folly::test::TemporaryDirectory directory;
    const auto root = directory.path();
    const auto marker = root / "engine";
    const auto ecEngine = root / kEcEngineDirectoryName;
    StorageTargets::Config config;
    config.set_target_paths({root});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    switch (scenario) {
      case 0:
        boost::filesystem::create_directory(marker);  // A legacy engine is never migrated.
        write(marker / "sentinel", "legacy-data");
        break;
      case 1:
        write(marker, "incorrect-marker");
        break;
      case 2:
        boost::filesystem::create_symlink("missing-marker", marker);
        break;
      case 3:
        write(marker, kEcEngineRootMarker);
        boost::filesystem::create_symlink("missing-engine", ecEngine);
        break;
      case 4:
        boost::filesystem::create_directory(root / "71");  // An unmarked, nonempty root cannot be converted.
        break;
      case 5:
        write(marker, kEcEngineRootMarker);
        boost::filesystem::create_directory(ecEngine);
        boost::filesystem::create_directory(root / "71");
        PhysicalConfig legacy;
        legacy.path = root / "71";
        legacy.target_id = 71;
        legacy.chain_id = 81;
        legacy.only_chunk_engine = true;
        write(legacy.path / kPhysicalConfigFileName, serde::toTomlString(legacy));
        break;
    }
    const auto before = snapshotFiles(root);
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_FALSE(targets.load(executor)) << scenario;
    ASSERT_EQ(snapshotFiles(root), before) << scenario;
    ASSERT_FALSE(boost::filesystem::exists(ecEngine / "meta")) << scenario;
  }
}

TEST(TestEcTarget, RejectsMultipleMembersEvenWhenOnlyOneIsServing) {
  folly::test::TemporaryDirectory directory;
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup executor(1, "EcRoute");
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(executor));
  const auto request = targetRequest();
  ASSERT_OK(targets.create(request, true));
  auto routing = std::make_shared<flat::RoutingInfo>();
  flat::TargetInfo local;
  local.targetId = request.targetId;
  local.chainId = request.chainId;
  local.publicState = flat::PublicTargetState::SERVING;
  routing->targets.emplace(local.targetId, local);
  flat::ChainInfo chain;
  chain.chainId = request.chainId;
  chain.chainVersion = ChainVer{1};
  chain.targets.push_back(flat::ChainTargetInfo::create(local.targetId, local.publicState));
  routing->chains.emplace(chain.chainId, chain);
  ASSERT_OK(map.updateRouting(std::make_shared<client::RoutingInfo>(routing, SteadyClock::now())));
  const VersionedChainId versioned{request.chainId, ChainVer{1}};
  ASSERT_OK(map.getByChainId(versioned));
  ASSERT_FALSE(map.syncReceiveDone(versioned));
  auto changed = std::make_shared<flat::RoutingInfo>(*routing);
  changed->routingInfoVersion = flat::RoutingInfoVersion{2};
  changed->chains.at(chain.chainId)
      .targets.push_back(flat::ChainTargetInfo::create(TargetId{99}, flat::PublicTargetState::OFFLINE));
  ASSERT_OK(map.updateRouting(std::make_shared<client::RoutingInfo>(changed, SteadyClock::now())));
  ASSERT_FALSE(map.getByChainId(versioned));
  auto target = map.getByTargetId(local.targetId);
  ASSERT_OK(target);
  ASSERT_EQ((*target)->chainMemberCount, 2);
  ASSERT_FALSE((*target)->successor);
  ASSERT_TRUE(map.snapshot()->syncingChains().empty());

  auto reassigned = std::make_shared<flat::RoutingInfo>(*routing);
  reassigned->routingInfoVersion = flat::RoutingInfoVersion{3};
  reassigned->chains.clear();
  chain.chainId = ChainId{82};
  reassigned->chains.emplace(chain.chainId, chain);
  reassigned->targets.at(local.targetId).chainId = chain.chainId;
  ASSERT_OK(map.updateRouting(std::make_shared<client::RoutingInfo>(reassigned, SteadyClock::now())));
  ASSERT_FALSE(map.getByChainId(versioned));
  ASSERT_FALSE(map.getByChainId(VersionedChainId{chain.chainId, ChainVer{1}}));
  target = map.getByTargetId(local.targetId);
  ASSERT_OK(target);
  ASSERT_EQ((*target)->chainId, request.chainId);
  ASSERT_EQ((*target)->vChainId.chainId, chain.chainId);
}

}  // namespace
}  // namespace hf3fs::storage
