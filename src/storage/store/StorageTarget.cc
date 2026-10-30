#include "storage/store/StorageTarget.h"

#include <boost/filesystem/operations.hpp>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/symbolizer/Symbolizer.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include "common/monitor/Recorder.h"
#include "common/serde/Serde.h"
#include "common/utils/MagicEnum.hpp"
#include "common/utils/Result.h"
#include "common/utils/SysResource.h"
#include "storage/store/ChunkEngine.h"
#include "storage/store/ChunkReplica.h"

namespace hf3fs::storage {
namespace {

monitor::CountRecorder storageUpdateChecksumMismatch{"storage.chunk_update.checksum_mismatch"};
monitor::CountRecorder storageUpdateReplace{"storage.chunk_update.replace"};
monitor::CountRecorder storageUpdateCommitted{"storage.chunk_update.committed"};
monitor::CountRecorder storageUpdateStale{"storage.chunk_update.stale"};
monitor::CountRecorder storageUpdateMissing{"storage.chunk_update.missing"};
monitor::CountRecorder storageUpdateAdvance{"storage.chunk_update.advance"};
monitor::CountRecorder storageWriteTimes{"storage.chunk_write.times"};
monitor::CountRecorder storageRemoveTimes{"storage.chunk_remove.times"};
monitor::CountRecorder storageTruncateTimes{"storage.chunk_truncate.times"};

monitor::CountRecorder aioReadCountPerDisk{"storage.aio_read.count_per_disk"};
monitor::CountRecorder aioReadBytesPerDisk{"storage.aio_read.bytes_per_disk"};
monitor::CountRecorder aioReadSuccBytesPerDisk{"storage.aio_read.succ_bytes_per_disk"};
monitor::LatencyRecorder aioReadSuccLatencyPerDisk{"storage.aio_read.succ_latency_per_disk"};
monitor::ValueRecorder targetUsedSize{"storage.target.used_size", std::nullopt, false};
monitor::ValueRecorder targetReservedSize{"storage.target.reserved_size", std::nullopt, false};
monitor::ValueRecorder targetUnrecycledSize{"storage.target.unrecycled_size", std::nullopt, false};
monitor::OperationRecorder pointQueryRecorder{"storage.point_query"};
std::atomic<uint32_t> gGenerationId{};

Result<Void> writeNewEcConfigFile(const Path &path, std::string_view bytes) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0) {
    return makeError(StorageCode::kStorageInitFailed, fmt::format("create EC config {} failed: {}", path, errno));
  }
  SCOPE_EXIT { ::close(fd); };
  while (!bytes.empty()) {
    const auto written = ::write(fd, bytes.data(), bytes.size());
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) {
      return makeError(StorageCode::kStorageInitFailed, fmt::format("write EC config {} failed: {}", path, errno));
    }
    bytes.remove_prefix(static_cast<size_t>(written));
  }
  while (::fsync(fd) != 0) {
    if (errno == EINTR) continue;
    return makeError(StorageCode::kStorageInitFailed, fmt::format("sync EC config {} failed: {}", path, errno));
  }
  return Void{};
}

Result<Void> syncEcConfigDirectory(const Path &path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return makeError(StorageCode::kStorageInitFailed,
                     fmt::format("open EC config directory {} failed: {}", path, errno));
  }
  SCOPE_EXIT { ::close(fd); };
  while (::fsync(fd) != 0) {
    if (errno == EINTR) continue;
    return makeError(StorageCode::kStorageInitFailed,
                     fmt::format("sync EC config directory {} failed: {}", path, errno));
  }
  return Void{};
}

Result<Path> physicalConfigPath(const Path &path) {
  const auto marker = path / kPhysicalConfigFileName;
  const auto ecConfig = path / kEcPhysicalConfigFileName;
  if (!boost::filesystem::exists(ecConfig) && !boost::filesystem::is_symlink(ecConfig)) return marker;
  if (!boost::filesystem::is_regular_file(ecConfig) || boost::filesystem::is_symlink(ecConfig) ||
      !boost::filesystem::is_regular_file(marker) || boost::filesystem::is_symlink(marker)) {
    return makeError(StorageCode::kStorageInitFailed, "EC target requires two regular configuration files");
  }
  const std::string_view expected{kEcTargetMarker};
  if (boost::filesystem::file_size(marker) != expected.size()) {
    return makeError(StorageCode::kStorageInitFailed, "EC target marker length mismatch");
  }
  std::ifstream input(marker, std::ios::binary);
  std::string actual(expected.size(), '\0');
  if (!input.read(actual.data(), actual.size()) || actual != expected) {
    return makeError(StorageCode::kStorageInitFailed, "EC target marker mismatch");
  }
  return ecConfig;
}

Result<std::string> getDeviceUUID(const Path &path) {
  struct stat st;
  int ret = ::stat(path.c_str(), &st);
  if (ret != 0) {
    auto msg = fmt::format("stat {} failed: {}", path.string(), errno);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageStatFailed, std::move(msg));
  }

  auto getDeviceUUIDResult = SysResource::fileSystemUUID();
  RETURN_AND_LOG_ON_ERROR(getDeviceUUIDResult);
  if (!getDeviceUUIDResult->count(st.st_dev)) {
    auto msg = fmt::format("Not found UUID for path {} device {}", path.string(), st.st_dev);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageUUIDMismatch, std::move(msg));
  }
  return getDeviceUUIDResult->at(st.st_dev);
}

}  // namespace

StorageTarget::StorageTarget(const Config &config,
                             GlobalFileStore &globalFileStore,
                             uint32_t diskIndex,
                             chunk_engine::Engine *engine)
    : config_(config),
      diskIndex_(diskIndex),
      generationId_(++gGenerationId),
      engine_(engine),
      diskTag_(monitor::instanceTagSet(std::to_string(diskIndex))),
      targetTag_(monitor::instanceTagSet(std::to_string(0))),
      readCountPerDisk_(aioReadCountPerDisk.getRecorderWithTag(diskTag_)),
      readBytesPerDisk_(aioReadBytesPerDisk.getRecorderWithTag(diskTag_)),
      readSuccBytesPerDisk_(aioReadSuccBytesPerDisk.getRecorderWithTag(diskTag_)),
      readSuccLatencyPerDisk_(aioReadSuccLatencyPerDisk.getRecorderWithTag(diskTag_)),
      targetUsedSize_(targetUsedSize.getRecorderWithTag(targetTag_)),
      targetReservedSize_(targetReservedSize.getRecorderWithTag(targetTag_)),
      targetUnrecycledSize_(targetUnrecycledSize.getRecorderWithTag(targetTag_)),
      chunkStore_(config_, globalFileStore) {}

StorageTarget::~StorageTarget() {
  if (released_ || !initialized_) {
    return;
  }
  auto result = sync();
  if (UNLIKELY(!result)) {
    XLOGF(CRITICAL, "storage target sync meta failed {}, error: {}", targetConfig_.path, result.error());
  }
}

Result<Void> StorageTarget::create(const PhysicalConfig &config) {
  if (config.ec_only && (!config.only_chunk_engine || config.chain_id == 0)) {
    return makeError(StorageCode::kStorageInitFailed, "EC target requires ChunkEngine and a nonzero fixed chain id");
  }
  Path targetConfigFilePath = config.path / kPhysicalConfigFileName;
  if (boost::filesystem::exists(targetConfigFilePath) || boost::filesystem::is_symlink(targetConfigFilePath) ||
      boost::filesystem::exists(config.path / kEcPhysicalConfigFileName) ||
      boost::filesystem::is_symlink(config.path / kEcPhysicalConfigFileName)) {
    auto msg = fmt::format("Target config file {} already exists", targetConfigFilePath.string());
    XLOG(INFO, msg);
    if (!config.allow_existing_targets) {
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    RETURN_AND_LOG_ON_ERROR(load(config.path));
    if (targetConfig_.ec_only != config.ec_only || (config.ec_only && targetConfig_.chain_id != config.chain_id)) {
      return makeError(StorageCode::kStorageInitFailed,
                       "existing target mode or EC chain differs; conversion is forbidden");
    }
    if (targetConfig_.target_id != config.target_id) {
      auto msg = fmt::format("target id is different: {} != {}", targetConfig_.target_id, config.target_id);
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    if (targetConfig_.physical_file_count != config.physical_file_count) {
      auto msg = fmt::format("Physical file count is different: {} != {}",
                             targetConfig_.physical_file_count,
                             config.physical_file_count);
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    if (!ecOnly()) RETURN_AND_LOG_ON_ERROR(addChunkSize(config.chunk_size_list));
    XLOGF(INFO, "Target config file {} check passed", targetConfigFilePath.string());
    return Void{};
  }

  targetConfig_ = config;
  targetConfig_.has_sentinel = true;
  auto kvPath = config_.kv_path();
  if (kvPath.empty()) {
    targetConfig_.kv_path = std::nullopt;
  } else {
    targetConfig_.kv_path = kvPath;
  }
  if (useChunkEngine()) {
    boost::system::error_code ec{};
    const bool created = boost::filesystem::create_directories(targetConfig_.path, ec);
    if (UNLIKELY(ec.failed())) {
      auto msg = fmt::format("target create directory {} failed: {}", targetConfig_.path.string(), ec.message());
      XLOG(ERR, msg);
      return makeError(StorageCode::kChunkOpenFailed, std::move(msg));
    }
    if (ecOnly() && !created) {
      return makeError(StorageCode::kStorageInitFailed,
                       "EC creation requires a fresh target directory or complete EC config");
    }
  } else {
    RETURN_AND_LOG_ON_ERROR(chunkStore_.create(targetConfig_));
  }

  auto getDeviceUUIDResult = getDeviceUUID(targetConfig_.path);
  if (getDeviceUUIDResult) {
    targetConfig_.block_device_uuid = *getDeviceUUIDResult;
  } else if (targetConfig_.allow_disk_without_uuid) {
    targetConfig_.block_device_uuid = "";
  } else {
    RETURN_AND_LOG_ON_ERROR(getDeviceUUIDResult);
  }

  if (ecOnly()) {
    // Write the incompatible marker first. Any interrupted initialization stays
    // unreadable by both old loaders and the strict two-file EC loader.
    RETURN_AND_LOG_ON_ERROR(writeNewEcConfigFile(targetConfigFilePath, kEcTargetMarker));
    RETURN_AND_LOG_ON_ERROR(
        writeNewEcConfigFile(config.path / kEcPhysicalConfigFileName, serde::toTomlString(targetConfig_)));
    RETURN_AND_LOG_ON_ERROR(syncEcConfigDirectory(config.path));
    RETURN_AND_LOG_ON_ERROR(syncEcConfigDirectory(config.path.parent_path()));
  } else {
    std::ofstream targetConfigFile(targetConfigFilePath, std::ios::out);
    if (!targetConfigFile) {
      auto msg = fmt::format("Open target config file {} failed", targetConfigFilePath.string());
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    if (!(targetConfigFile << serde::toTomlString(targetConfig_))) {
      auto msg = fmt::format("Write target config file {} failed", targetConfigFilePath.string());
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
  }
  *chunkSizeList_.lock() = {targetConfig_.chunk_size_list.begin(), targetConfig_.chunk_size_list.end()};
  targetTag_ = monitor::instanceTagSet(std::to_string(targetConfig_.target_id));
  targetUsedSize_ = targetUsedSize.getRecorderWithTag(targetTag_);
  targetReservedSize_ = targetReservedSize.getRecorderWithTag(targetTag_);
  targetUnrecycledSize_ = targetUnrecycledSize.getRecorderWithTag(targetTag_);
  initialized_ = true;
  return Void{};
}

Result<PhysicalConfig> StorageTarget::readPhysicalConfig(const Path &path) {
  CHECK_RESULT(configPath, physicalConfigPath(path));
  PhysicalConfig config;
  RETURN_AND_LOG_ON_ERROR(serde::fromTomlFile(config, configPath));
  const bool hasEcConfig = configPath.filename() == kEcPhysicalConfigFileName;
  if (config.ec_only != hasEcConfig || (hasEcConfig && (!config.only_chunk_engine || config.chain_id == 0))) {
    return makeError(StorageCode::kStorageInitFailed, "EC target files and physical mode disagree");
  }
  if (path != config.path) {
    auto msg = fmt::format("Path config mismatch {} != real {}", config.path, path);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  return config;
}

Result<Void> StorageTarget::load(const Path &path) {
  CHECK_RESULT(config, readPhysicalConfig(path));
  targetConfig_ = std::move(config);

  auto getDeviceUUIDResult = getDeviceUUID(path);
  if (!getDeviceUUIDResult) {
    if (targetConfig_.allow_disk_without_uuid) {
      getDeviceUUIDResult = "";
    } else {
      RETURN_AND_LOG_ON_ERROR(getDeviceUUIDResult);
    }
  }
  if (targetConfig_.block_device_uuid != *getDeviceUUIDResult) {
    auto msg = fmt::format("UUID mismatch config {} != real {}", targetConfig_.block_device_uuid, *getDeviceUUIDResult);
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageUUIDMismatch, std::move(msg));
  }

  if (!targetConfig_.only_chunk_engine) {
    RETURN_AND_LOG_ON_ERROR(chunkStore_.load(targetConfig_));
  }
  if (!targetConfig_.only_chunk_engine && config_.migrate_kv_store() &&
      config_.kv_store().type() != targetConfig_.kv_store_type) {
    XLOGF(WARNING, "start migrate kv {} -> {}", targetConfig_, magic_enum::enum_name(config_.kv_store().type()));
    targetConfig_.kv_store_name = "kv";
    targetConfig_.kv_store_type = config_.kv_store().type();
    targetConfig_.has_sentinel = true;
    RETURN_AND_LOG_ON_ERROR(chunkStore_.migrate(targetConfig_));
    Path targetConfigFilePath = path / kPhysicalConfigFileName;
    std::ofstream targetConfigFile(targetConfigFilePath, std::ios::out);
    if (!targetConfigFile || !(targetConfigFile << serde::toTomlString(targetConfig_))) {
      auto msg = fmt::format("Write target config file {} failed", targetConfigFilePath.string());
      XLOG(ERR, msg);
      return makeError(StorageCode::kStorageInitFailed, std::move(msg));
    }
    XLOGF(WARNING, "finish migrate kv {} -> {}", targetConfig_, magic_enum::enum_name(config_.kv_store().type()));
  }
  *chunkSizeList_.lock() = {targetConfig_.chunk_size_list.begin(), targetConfig_.chunk_size_list.end()};
  targetTag_ = monitor::instanceTagSet(std::to_string(targetConfig_.target_id));
  targetUsedSize_ = targetUsedSize.getRecorderWithTag(targetTag_);
  targetReservedSize_ = targetReservedSize.getRecorderWithTag(targetTag_);
  targetUnrecycledSize_ = targetUnrecycledSize.getRecorderWithTag(targetTag_);
  initialized_ = true;
  return Void{};
}

Result<Void> StorageTarget::addChunkSize(const std::vector<Size> &sizeList) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy resizing is forbidden on an EC target");
  if (useChunkEngine()) {
    return Void{};
  }

  auto chunkSizeListGuard = chunkSizeList_.lock();

  std::vector<Size> newSizeList;
  for (auto size : sizeList) {
    if (!chunkSizeListGuard->contains(size)) {
      newSizeList.push_back(size);
    }
  }
  if (newSizeList.empty()) {
    return Void{};
  }
  RETURN_AND_LOG_ON_ERROR(chunkStore_.addChunkSize(newSizeList));

  for (auto size : *chunkSizeListGuard) {
    newSizeList.push_back(size);
  }
  std::sort(newSizeList.begin(), newSizeList.end());

  auto newTargetConfig = targetConfig_;
  newTargetConfig.chunk_size_list = newSizeList;
  Path tempPath = newTargetConfig.path / fmt::format("{}.tmp", kPhysicalConfigFileName);
  std::ofstream targetConfigFile(tempPath, std::ios::out);
  if (!targetConfigFile || !(targetConfigFile << serde::toTomlString(newTargetConfig))) {
    auto msg = fmt::format("Write target config file {} failed", tempPath.string());
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }

  Path targetPath = newTargetConfig.path / kPhysicalConfigFileName;
  boost::system::error_code ec;
  boost::filesystem::rename(tempPath, targetPath, ec);
  if (UNLIKELY(ec.failed())) {
    auto msg = fmt::format("Re-write target config file {} failed, error: {}", targetPath.string(), ec.message());
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }
  for (auto size : sizeList) {
    chunkSizeListGuard->insert(size);
  }
  return Void{};
}

Result<EcFragmentReceipt> StorageTarget::createEcFragment(const EcCreateReq &request) {
  if (!ecOnly() || !useChunkEngine() || engine_ == nullptr || request.targetId != targetId() ||
      request.vChainId.chainId != chainId()) {
    return makeError(StatusCode::kInvalidArg, "EC creation requires the matching dedicated ChunkEngine target");
  }
  return ChunkEngine::createEcFragment(*engine_, request);
}

Result<EcReadResult> StorageTarget::readEcFragment(const EcReadReq &request) {
  if (!ecOnly() || !useChunkEngine() || engine_ == nullptr || request.targetId != targetId() ||
      request.vChainId.chainId != chainId()) {
    return makeError(StatusCode::kInvalidArg, "EC read requires the matching dedicated ChunkEngine target");
  }
  return ChunkEngine::readEcFragment(*engine_, request);
}

Result<EcFragmentReceipt> StorageTarget::reconcileEcFragment(const EcReconcileReq &request) {
  if (!ecOnly() || !useChunkEngine() || engine_ == nullptr || request.targetId != targetId() ||
      request.vChainId.chainId != chainId()) {
    return makeError(StatusCode::kInvalidArg, "EC reconciliation requires the matching dedicated ChunkEngine target");
  }
  return ChunkEngine::reconcileEcFragment(*engine_, request);
}

Result<Void> StorageTarget::setChainId(ChainId chainId) {
  auto chunkSizeListGuard = chunkSizeList_.lock();
  if (ecOnly() && chainId != ChainId{targetConfig_.chain_id}) {
    return makeError(StorageCode::kStorageInitFailed, "EC target chain id is immutable");
  }
  if (targetConfig_.chain_id != 0) {
    return Void{};
  }

  auto newTargetConfig = targetConfig_;
  newTargetConfig.chain_id = chainId;
  Path tempPath = newTargetConfig.path / fmt::format("{}.tmp", kPhysicalConfigFileName);
  std::ofstream targetConfigFile(tempPath, std::ios::out);
  if (!targetConfigFile || !(targetConfigFile << serde::toTomlString(newTargetConfig))) {
    auto msg = fmt::format("Write target config file {} failed", tempPath.string());
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }

  Path targetPath = newTargetConfig.path / kPhysicalConfigFileName;
  boost::system::error_code ec;
  boost::filesystem::rename(tempPath, targetPath, ec);
  if (UNLIKELY(ec.failed())) {
    auto msg = fmt::format("Re-write target config file {} failed, error: {}", targetPath.string(), ec.message());
    XLOG(ERR, msg);
    return makeError(StorageCode::kStorageInitFailed, std::move(msg));
  }

  targetConfig_.chain_id = chainId;
  return Void{};
}

// prepare aio read.
Result<Void> StorageTarget::aioPrepareRead(AioReadJob &job) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy reads are forbidden on an EC target");
  readCountPerDisk_->addSample(1);
  readBytesPerDisk_->addSample(job.alignedLength());
  if (useChunkEngine()) {
    return ChunkEngine::aioPrepareRead(*engine_, job);
  } else {
    return ChunkReplica::aioPrepareRead(chunkStore_, job);
  }
}

Result<Void> StorageTarget::aioFinishRead(AioReadJob &job) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy reads are forbidden on an EC target");
  if (job.state().chunkEngineJob.has_chunk()) {
    return Void{};
  }
  return ChunkReplica::aioFinishRead(chunkStore_, job);
}

// update chunk (write/remove/truncate).
void StorageTarget::updateChunk(UpdateJob &job, folly::CPUThreadPoolExecutor &executor) {
  if (ecOnly()) {
    job.setResult(makeError(StatusCode::kInvalidArg, "legacy mutations are forbidden on an EC target"));
    return;
  }
  if (job.type() == UpdateType::COMMIT) {
    if (useChunkEngine()) {
      job.setResult(ChunkEngine::commit(*engine_, job, config_.kv_store().sync_when_write()));
    } else {
      job.setResult(ChunkReplica::commit(chunkStore_, job));
    }
  } else {
    auto result =
        useChunkEngine() ? ChunkEngine::update(*engine_, job) : ChunkReplica::update(chunkStore_, job, executor);
    if (LIKELY(result.hasValue())) {
      if (job.options().isSyncing) {
        storageUpdateReplace.addSample(1);
      }
      if (job.updateIO().isWrite()) {
        storageWriteTimes.addSample(1);
      } else if (job.updateIO().isRemove()) {
        storageRemoveTimes.addSample(1);
      } else if (job.updateIO().isExtend()) {
        storageTruncateTimes.addSample(1);
      }
    } else {
      uint32_t code = result.error().code();
      switch (code) {
        case StorageCode::kChecksumMismatch:
          storageUpdateChecksumMismatch.addSample(1);
          break;

        case StorageCode::kChunkCommittedUpdate:
          storageUpdateCommitted.addSample(1);
          break;

        case StorageCode::kChunkStaleUpdate:
          storageUpdateStale.addSample(1);
          break;

        case StorageCode::kChunkMissingUpdate:
          storageUpdateMissing.addSample(1);
          break;

        case StorageCode::kChunkAdvanceUpdate:
          storageUpdateAdvance.addSample(1);
          break;

        default:
          break;
      }
    }
    job.setResult(std::move(result));
  }
}

Result<std::vector<std::pair<ChunkId, ChunkMetadata>>> StorageTarget::queryChunks(const ChunkIdRange &chunkIdRange) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy range queries are forbidden on an EC target");
  auto pointQueryStrategy = config_.point_query_strategy();
  if ((pointQueryStrategy == PointQueryStrategy::CLASSIC && chunkIdRange.begin.nextChunkId() == chunkIdRange.end) ||
      (pointQueryStrategy == PointQueryStrategy::MODERN &&
       chunkIdRange.begin.rangeEndForCurrentChunk() == chunkIdRange.end)) {
    auto reportGuard = pointQueryRecorder.record();
    auto result = queryChunk(chunkIdRange.begin);
    if (result.hasValue()) {
      reportGuard.succ();
      return std::vector<std::pair<ChunkId, ChunkMetadata>>(1, std::make_pair(chunkIdRange.begin, *result));
    } else if (result.error().code() == StorageCode::kChunkMetadataNotFound) {
      reportGuard.succ();
      return std::vector<std::pair<ChunkId, ChunkMetadata>>{};
    } else {
      return makeError(std::move(result.error()));
    }
  }
  if (useChunkEngine()) {
    return ChunkEngine::queryChunks(*engine_, chunkIdRange, chainId());
  }
  return chunkStore_.queryChunks(chunkIdRange);
}

Result<ChunkMetadata> StorageTarget::queryChunk(const ChunkId &chunkId) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy chunk queries are forbidden on an EC target");
  if (useChunkEngine()) {
    return ChunkEngine::queryChunk(*engine_, chunkId, chainId());
  }
  auto getResult = chunkStore_.get(chunkId);
  RETURN_AND_LOG_ON_ERROR(getResult);
  return (*getResult)->second.meta;
}

Result<Void> StorageTarget::reportUnrecycledSize() {
  targetUsedSize_->set(usedSize());

  if (useChunkEngine()) {
    return Void{};
  }

  int64_t reseredSize = 0;
  int64_t unrecycledSize = 0;
  auto result = chunkStore_.unusedSize(reseredSize, unrecycledSize);
  if (UNLIKELY(!result)) {
    targetReservedSize_->set(-1);
    targetUnrecycledSize_->set(-1);
    XLOGF(ERR, "target get unused size failed, {}, error: {}", targetConfig_.target_id, result.error());
  } else {
    unusedSize_ = reseredSize + unrecycledSize;
    targetReservedSize_->set(reseredSize);
    targetUnrecycledSize_->set(unrecycledSize);
  }
  return Void{};
}

Result<Void> StorageTarget::getAllMetadata(ChunkMetaVector &metadataVec) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy metadata enumeration is forbidden on an EC target");
  if (useChunkEngine()) {
    return ChunkEngine::getAllMetadata(*engine_, chainId(), metadataVec);
  } else {
    return chunkStore_.getAllMetadata(metadataVec);
  }
}

Result<Void> StorageTarget::getAllMetadataMap(std::unordered_map<ChunkId, ChunkMetadata> &metas) {
  if (ecOnly()) return makeError(StatusCode::kInvalidArg, "legacy metadata enumeration is forbidden on an EC target");
  if (useChunkEngine()) {
    return ChunkEngine::getAllMetadataMap(*engine_, metas, chainId());
  } else {
    auto iteratorResult = chunkStore_.metaIterator();
    RETURN_AND_LOG_ON_ERROR(iteratorResult);
    for (auto &it = *iteratorResult; it.valid(); it.next()) {
      auto chunkId = it.chunkId();
      auto metaResult = it.meta();
      if (UNLIKELY(!metaResult)) {
        auto msg = fmt::format("storage target dump parse meta failed: {}, chunk {}", metaResult.error(), chunkId);
        XLOG(ERR, msg);
        return makeError(StorageCode::kStorageInitFailed, std::move(msg));
      }
      metas[it.chunkId()] = *metaResult;
    }
    return iteratorResult->status();
  }
}

void StorageTarget::recordRealRead(uint32_t bytes, Duration latency) const {
  readSuccBytesPerDisk_->addSample(bytes);
  readSuccLatencyPerDisk_->addSample(latency);
}

}  // namespace hf3fs::storage
