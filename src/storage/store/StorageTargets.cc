#include "storage/store/StorageTargets.h"

#include <boost/filesystem/operations.hpp>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Collect.h>
#include <folly/experimental/coro/Sleep.h>
#include <folly/experimental/coro/Task.h>
#include <memory>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <unordered_map>

#include "chunk_engine/src/cxx.rs.h"
#include "common/monitor/Sample.h"
#include "common/utils/CPUExecutorGroup.h"
#include "common/utils/Duration.h"
#include "common/utils/LogCommands.h"
#include "common/utils/Result.h"
#include "common/utils/SysResource.h"
#include "storage/service/Components.h"

namespace hf3fs::storage {
namespace {

bool pathPresent(const Path &path) { return boost::filesystem::exists(path) || boost::filesystem::is_symlink(path); }

Result<Void> syncRootFd(int fd, const Path &path) {
  while (::fsync(fd) != 0) {
    if (errno == EINTR) continue;
    return makeError(StorageCode::kStorageInitFailed, fmt::format("sync EC root {} failed: {}", path, errno));
  }
  return Void{};
}

Result<Void> validateEcRootMarker(const Path &marker) {
  const int fd = ::open(marker.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    return makeError(StorageCode::kStorageInitFailed, fmt::format("open EC root marker {} failed: {}", marker, errno));
  }
  SCOPE_EXIT { ::close(fd); };
  const std::string_view expected{kEcEngineRootMarker};
  struct stat info {};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size != static_cast<off_t>(expected.size())) {
    return makeError(StorageCode::kStorageInitFailed, "EC root marker must be a regular file with the exact format");
  }
  std::string bytes(expected.size(), '\0');
  size_t offset = 0;
  while (offset != bytes.size()) {
    const auto count = ::read(fd, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StorageCode::kStorageInitFailed, "cannot read the complete EC root marker");
    offset += static_cast<size_t>(count);
  }
  if (bytes != expected) return makeError(StorageCode::kStorageInitFailed, "EC root marker contents mismatch");
  return syncRootFd(fd, marker);
}

Result<Void> createEcRootMarker(const Path &marker) {
  const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
  if (fd < 0) {
    return makeError(StorageCode::kStorageInitFailed,
                     fmt::format("create EC root marker {} failed: {}", marker, errno));
  }
  SCOPE_EXIT { ::close(fd); };
  std::string_view bytes{kEcEngineRootMarker};
  while (!bytes.empty()) {
    const auto count = ::write(fd, bytes.data(), bytes.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StorageCode::kStorageInitFailed, "cannot write the complete EC root marker");
    bytes.remove_prefix(static_cast<size_t>(count));
  }
  return syncRootFd(fd, marker);
}

// Run before opening any engine: opening RocksDB already performs recovery.
// This protects EC roots from the old root/engine layout without depending on
// the old executable understanding any new target or engine format field.
Result<Path> prepareEngineRoot(const Path &root, bool ecOnly) {
  const auto legacyEngine = root / "engine";
  const auto ecEngine = root / kEcEngineDirectoryName;
  if (ecOnly) {
    if (!boost::filesystem::is_directory(root) || boost::filesystem::is_symlink(root)) {
      return makeError(StorageCode::kStorageInitFailed, "EC target root must be a real directory");
    }
    if (!pathPresent(legacyEngine)) {
      if (!boost::filesystem::is_empty(root)) {
        return makeError(StorageCode::kStorageInitFailed,
                         "unmarked EC target root must be empty; migration is forbidden");
      }
      RETURN_ON_ERROR(createEcRootMarker(legacyEngine));
    } else {
      RETURN_ON_ERROR(validateEcRootMarker(legacyEngine));
    }
    const bool hasEngine = pathPresent(ecEngine);
    if (hasEngine && (!boost::filesystem::is_directory(ecEngine) || boost::filesystem::is_symlink(ecEngine))) {
      return makeError(StorageCode::kStorageInitFailed, "EC engine path must be a real directory");
    }
    for (const auto &entry : boost::filesystem::directory_iterator(root)) {
      const auto &path = entry.path();
      if (path == legacyEngine || path == ecEngine) continue;
      if (path.filename() == ".hf3fs_check" && boost::filesystem::is_regular_file(path) &&
          !boost::filesystem::is_symlink(path))
        continue;
      if (!hasEngine || !boost::filesystem::is_directory(path) || boost::filesystem::is_symlink(path)) {
        return makeError(StorageCode::kStorageInitFailed,
                         "EC root contains an unexpected entry or has lost its engine");
      }
      CHECK_RESULT(config, StorageTarget::readPhysicalConfig(path));
      if (!config.ec_only || path.filename().string() != std::to_string(config.target_id)) {
        return makeError(StorageCode::kStorageInitFailed, "EC root contains a legacy or mismatched target");
      }
    }
    const int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return makeError(StorageCode::kStorageInitFailed, "cannot open EC root directory for synchronization");
    SCOPE_EXIT { ::close(fd); };
    RETURN_ON_ERROR(syncRootFd(fd, root));
    return ecEngine;
  }
  if (pathPresent(ecEngine) || (pathPresent(legacyEngine) && (!boost::filesystem::is_directory(legacyEngine) ||
                                                              boost::filesystem::is_symlink(legacyEngine)))) {
    return makeError(StorageCode::kStorageInitFailed, "legacy mode cannot open an EC or incompatible engine root");
  }
  for (const auto &entry : boost::filesystem::directory_iterator(root)) {
    const auto &path = entry.path();
    if (path == legacyEngine || !boost::filesystem::is_directory(path)) continue;
    if (pathPresent(path / kPhysicalConfigFileName) || pathPresent(path / kEcPhysicalConfigFileName)) {
      CHECK_RESULT(config, StorageTarget::readPhysicalConfig(path));
      if (config.ec_only) return makeError(StorageCode::kStorageInitFailed, "legacy process cannot load an EC target");
    }
  }
  return legacyEngine;
}

}  // namespace

using namespace std::chrono_literals;

StorageTargets::~StorageTargets() { void(); }

Result<Void> StorageTargets::init(CPUExecutorGroup &executor) {
  auto diskInfoResult = SysResource::scanDiskInfo();
  RETURN_AND_LOG_ON_ERROR(diskInfoResult);
  std::unordered_map<uint32_t, std::string> deviceIdToManufacturer;
  for (auto &info : *diskInfoResult) {
    deviceIdToManufacturer[info.deviceId] = info.manufacturer;
  }

  targetPaths_ = config_.target_paths();
  for (auto &path : targetPaths_) {
    struct stat st;
    int succ = ::stat(path.c_str(), &st);
    if (succ != 0) {
      auto msg = fmt::format("stat {} failed: {}", path, errno);
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageStatFailed, std::move(msg));
    }
    manufacturers_.push_back(deviceIdToManufacturer[st.st_dev]);
  }

  uint32_t i = 0;
  for (auto &path : targetPaths_) {
    pathToDiskIndex_[path] = i++;
  }

  std::vector<folly::coro::TaskWithExecutor<Result<rust::Box<chunk_engine::Engine>>>> tasks;
  std::vector<Path> enginePaths;
  for (auto &path : targetPaths_) {
    CHECK_RESULT(enginePath, prepareEngineRoot(path, config_.ec_only()));
    enginePaths.push_back(std::move(enginePath));
  }
  for (auto &engine_path : enginePaths) {
    bool create = !boost::filesystem::exists(engine_path);
    // Existing EC engines must not silently recreate a lost metadata store.
    if (!config_.ec_only()) create |= config_.create_engine_path();
    tasks.push_back(folly::coro::co_invoke([engine_path, create]() -> CoTryTask<rust::Box<chunk_engine::Engine>> {
                      std::string error;
                      auto engine = chunk_engine::create(engine_path.c_str(), create, sizeof(ChainId), error);
                      if (!error.empty()) {
                        co_return makeError(StorageCode::kStorageStatFailed, std::move(error));
                      }
                      co_return rust::Box<chunk_engine::Engine>::from_raw(engine);
                    }).scheduleOn(&executor.pickNext()));
  }

  auto results = folly::coro::blockingWait(folly::coro::collectAllRange(std::move(tasks)));
  for (auto &result : results) {
    RETURN_AND_LOG_ON_ERROR(result);
    engines_.push_back(std::move(result.value()));
  }

  return Void{};
}

Result<Void> StorageTargets::create(const CreateConfig &createConfig) {
  if (config_.ec_only()) {
    return makeError(StorageCode::kStorageInitFailed, "legacy batch creation is forbidden in an EC-only process");
  }
  CPUExecutorGroup executor(1, "Creator");
  RETURN_AND_LOG_ON_ERROR(init(executor));
  auto targetPaths = config_.target_paths();
  auto targetNumPerPath = config_.target_num_per_path();
  auto targetIdSize = createConfig.target_ids().size();
  if (targetPaths.empty()) {
    auto msg = fmt::format("List of target path is empty");
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  if (targetNumPerPath == 0) {
    auto msg = fmt::format("Target num per path is 0!");
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  if (targetPaths.size() * targetNumPerPath != targetIdSize) {
    auto msg = fmt::format("Unable to arrange target. path size {}, target num per path {}, target id size {}",
                           targetPaths.size(),
                           targetNumPerPath,
                           targetIdSize);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, msg);
  }

  size_t idx = 0;
  for (auto &targetId : createConfig.target_ids()) {
    auto diskIndex = idx / targetNumPerPath;
    auto storageTarget = StorageTarget::enable_shared_from_this::create(config_.storage_target(),
                                                                        globalFileStore_,
                                                                        diskIndex,
                                                                        &*engines_[diskIndex]);
    PhysicalConfig targetConfig;
    targetConfig.path = targetPaths[diskIndex] / std::to_string(targetId);
    targetConfig.target_id = targetId;
    targetConfig.allow_disk_without_uuid = createConfig.allow_disk_without_uuid();
    targetConfig.allow_existing_targets = createConfig.allow_existing_targets();
    targetConfig.physical_file_count = createConfig.physical_file_count();
    targetConfig.chunk_size_list = createConfig.chunk_size_list();
    targetConfig.only_chunk_engine = createConfig.only_chunk_engine();
    RETURN_AND_LOG_ON_ERROR(storageTarget->create(targetConfig));
    ++idx;
    RETURN_AND_LOG_ON_ERROR(targetMap_.addStorageTarget(std::move(storageTarget)));
  }
  return Void{};
}

Result<Void> StorageTargets::create(const CreateTargetReq &req, bool ecOnly) {
  if (ecOnly != config_.ec_only()) {
    return makeError(StorageCode::kStorageInitFailed, "target mode must match the dedicated process mode");
  }
  if (ecOnly && (!req.onlyChunkEngine || req.addChunkSize)) {
    return makeError(StorageCode::kStorageInitFailed, "EC targets require ChunkEngine and forbid legacy resizing");
  }
  if (req.diskIndex >= config_.target_paths().size()) {
    auto msg = fmt::format("disk index exceed {} >= {}", req.diskIndex, config_.target_paths().size());
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  if (req.chainId == ChainId{}) {
    auto msg = fmt::format("target {} without chain id", req.targetId);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }

  folly::coro::Baton baton;
  auto lock = targetLocks_.lock(baton, fmt::to_string(req.chainId));
  if (!lock.locked()) {
    folly::coro::blockingWait(lock.lock());
  }
  folly::coro::Baton targetBaton;
  auto targetLock = targetLocks_.lock(targetBaton, fmt::format("target:{}", req.targetId));
  if (!targetLock.locked()) {
    folly::coro::blockingWait(targetLock.lock());
  }
  const auto snapshot = targetMap_.snapshot();
  // Check physical identities as well as the routing index: an unloaded or
  // unrouted EC target still owns its chain prefix in the shared engine.
  for (const auto &[id, target] : snapshot->getTargets()) {
    const auto chainId = target.storageTarget ? target.storageTarget->chainId() : target.chainId;
    if ((ecOnly || target.ecOnly) && chainId == req.chainId && id != req.targetId) {
      return makeError(StorageCode::kStorageInitFailed, "another physical target already owns this chain");
    }
  }
  if (auto existing = snapshot->getTarget(req.targetId)) {
    const auto *target = *existing;
    if (target->ecOnly != ecOnly ||
        (ecOnly && (target->chainId != req.chainId || target->diskIndex != req.diskIndex || !target->storageTarget))) {
      return makeError(StorageCode::kStorageInitFailed, "existing target mode, chain, disk or availability differs");
    }
  }
  if (auto existingTarget = snapshot->getByChainId(VersionedChainId{req.chainId, {}}, true)) {
    auto existingTargetId = (*existingTarget)->targetId;
    if (existingTargetId != req.targetId) {
      auto msg = fmt::format("target {} is existing with same chain id {}, req target {}",
                             existingTargetId,
                             req.chainId,
                             req.targetId);
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    if (req.addChunkSize) {
      RETURN_AND_LOG_ON_ERROR((*existingTarget)->storageTarget->addChunkSize(req.chunkSizeList));
    }
  } else if (req.addChunkSize) {
    auto msg = fmt::format("target {} {} is not existing", req.chainId, req.targetId);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  if (snapshot->getTarget(req.targetId)) {
    if (req.allowExistingTarget) {
      auto targetPath = config_.target_paths()[req.diskIndex] / std::to_string(req.targetId);
      if (!boost::filesystem::exists(targetPath)) {
        auto msg = fmt::format("target {} is existing in memory, but not found in disk", req.targetId);
        XLOG(ERR, msg);
        return makeError(StorageCode::kStorageInitFailed, std::move(msg));
      }
      XLOGF(INFO, "target {} is already existing, return succ", req.targetId);
      return Void{};
    } else {
      auto msg = fmt::format("target {} is already existing", req.targetId);
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
  }

  auto storageTarget = StorageTarget::enable_shared_from_this::create(config_.storage_target(),
                                                                      globalFileStore_,
                                                                      req.diskIndex,
                                                                      &*engines_[req.diskIndex]);
  PhysicalConfig targetConfig;
  auto targetPath = config_.target_paths()[req.diskIndex] / std::to_string(req.targetId);
  targetConfig.path = targetPath;
  targetConfig.target_id = req.targetId;
  targetConfig.chain_id = req.chainId;
  targetConfig.allow_disk_without_uuid = config_.allow_disk_without_uuid();
  targetConfig.allow_existing_targets = req.allowExistingTarget;
  targetConfig.physical_file_count = req.physicalFileCount;
  targetConfig.chunk_size_list = req.chunkSizeList;
  targetConfig.kv_store_type = config_.storage_target().kv_store().type();
  targetConfig.only_chunk_engine = req.onlyChunkEngine;
  targetConfig.ec_only = ecOnly;
  RETURN_AND_LOG_ON_ERROR(storageTarget->create(targetConfig));
  XLOGF(INFO, "Create storage target {} at {}", storageTarget->targetId(), targetPath.string());
  RETURN_AND_LOG_ON_ERROR(targetMap_.addStorageTarget(std::move(storageTarget)));
  return Void{};
}

Result<Void> StorageTargets::load(CPUExecutorGroup &executor) {
  RETURN_AND_LOG_ON_ERROR(init(executor));
  std::vector<folly::coro::TaskWithExecutor<Result<Void>>> tasks;
  for (auto &parentPath : config_.target_paths()) {
    auto writable = CheckWorker::checkWritable(parentPath);
    if (!writable) {
      XLOGF(DFATAL, "path {} isn't writable, skip it", parentPath);
    }
    for (auto &targetPath : boost::filesystem::directory_iterator(parentPath)) {
      auto targetConfigPath = targetPath / kPhysicalConfigFileName;
      if (boost::filesystem::is_directory(targetPath) &&
          (boost::filesystem::exists(targetConfigPath) || boost::filesystem::is_symlink(targetConfigPath) ||
           boost::filesystem::exists(targetPath / kEcPhysicalConfigFileName) ||
           boost::filesystem::is_symlink(targetPath / kEcPhysicalConfigFileName))) {
        tasks.push_back(folly::coro::co_invoke([this, targetPath]() -> CoTryTask<Void> {
                          co_return loadTarget(targetPath);
                        }).scheduleOn(&executor.pickNext()));
      }
    }
  }
  auto results = folly::coro::blockingWait(folly::coro::collectAllRange(std::move(tasks)));
  for (auto &result : results) {
    RETURN_AND_LOG_ON_ERROR(result);
  }
  if (config_.collect_all_fds()) {
    globalFileStore_.collect(fds_);
  }
  return Void{};
}

// load a target.
Result<Void> StorageTargets::loadTarget(const Path &targetPath) {
  auto diskPath = targetPath.parent_path();
  if (UNLIKELY(!pathToDiskIndex_.contains(diskPath))) {
    auto msg = fmt::format("Target path ({}) not belongs to any of disk paths", targetPath);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }

  auto diskIndex = pathToDiskIndex_[diskPath];
  CHECK_RESULT(physical, StorageTarget::readPhysicalConfig(targetPath));
  if (physical.ec_only != config_.ec_only()) {
    return makeError(StorageCode::kStorageInitFailed, "restored target mode differs from the process mode");
  }
  auto storageTarget = StorageTarget::enable_shared_from_this::create(config_.storage_target(),
                                                                      globalFileStore_,
                                                                      diskIndex,
                                                                      &*engines_[diskIndex]);
  RETURN_AND_LOG_ON_ERROR(storageTarget->load(targetPath));
  XLOGF(INFO, "Load storage target {} at {}", storageTarget->targetId(), targetPath.string());
  auto targetId = storageTarget->targetId();
  if (UNLIKELY(targetPath.filename().string() != fmt::format("{}", targetId.toUnderType()))) {
    auto msg = fmt::format("Target id {} and path {} mismatch!", targetId, targetPath);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  RETURN_AND_LOG_ON_ERROR(targetMap_.addStorageTarget(std::move(storageTarget)));
  return Void{};
}

Result<std::vector<SpaceInfo>> StorageTargets::spaceInfos(bool force) {
  folly::coro::Baton baton;
  auto lock = targetLocks_.lock(baton, "spaceInfos");
  if (!lock.locked()) {
    folly::coro::blockingWait(lock.lock());
  }

  auto now = RelativeTime::now();
  auto elapsedTime = now - spaceInfoUpdatedTime_;
  if (elapsedTime < config_.space_info_cache_timeout() && !force) {
    return cachedSpaceInfos_;
  }

  std::unordered_map<std::string, uint64_t> diskUnusedSize;
  std::unordered_map<std::string, std::vector<hf3fs::flat::TargetId>> pathToTargetIds;
  auto snapshot = targetMap_.snapshot();
  for (auto &[targetId, target] : snapshot->getTargets()) {
    pathToTargetIds[target.path.parent_path().string()].emplace_back(targetId);
    if (target.storageTarget != nullptr) {
      diskUnusedSize[target.path.parent_path().string()] += target.storageTarget->unusedSize();
    }
  }

  std::vector<SpaceInfo> ret;
  for (auto &[path, index] : pathToDiskIndex_) {
    SpaceInfo info;
    info.path = targetPaths_[index].string();
    info.targetIds = pathToTargetIds[info.path];

    boost::system::error_code ec{};
    auto spaceInfo = boost::filesystem::space(path, ec);
    if (UNLIKELY(ec.failed())) {
      auto msg = fmt::format("get space info of directory {} failed: {}", path, ec.message());
      XLOG(ERR, msg);
      return makeError(StorageCode::kChunkOpenFailed, std::move(msg));
    }
    auto usedSize = engines_[index]->raw_used_size();
    info.capacity = spaceInfo.capacity;
    info.free = spaceInfo.free + diskUnusedSize[info.path] + usedSize.reserved_size;
    info.available = spaceInfo.available;
    info.manufacturer = manufacturers_[index];
    ret.push_back(std::move(info));
  }
  cachedSpaceInfos_ = ret;
  spaceInfoUpdatedTime_ = RelativeTime::now();
  return ret;
}

}  // namespace hf3fs::storage
