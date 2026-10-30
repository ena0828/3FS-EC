#include "ChunkEngine.h"

#include <cstring>

#include "chunk_engine/src/cxx.rs.h"
#include "fbs/storage/Common.h"
#include "storage/update/UpdateJob.h"

namespace hf3fs::storage {
namespace {

monitor::OperationRecorder storageUpdateRecorder{"storage.engine_update"};
monitor::OperationRecorder storageCommitRecorder{"storage.engine_commit"};

}  // namespace

Result<EcFragmentReceipt> ChunkEngine::createEcFragment(chunk_engine::Engine &engine, const EcCreateReq &request) {
  RETURN_ON_ERROR(request.validate());
  CHECK_RESULT(chunkId, request.identity.chunkId());
  const auto chainId = request.vChainId.chainId;
  std::string key(reinterpret_cast<const char *>(&chainId), sizeof(chainId));
  key.append(chunkId.data());

  chunk_engine::RawImmutableContext context{};
  context.chain_ver = request.vChainId.chainVer;
  context.last_request_id = request.tag.requestId;
  const auto client = request.tag.clientId.uuid.asStringView();
  std::memcpy(&context.last_client_low, client.data(), sizeof(context.last_client_low));
  std::memcpy(&context.last_client_high,
              client.data() + sizeof(context.last_client_low),
              sizeof(context.last_client_high));
  const auto operation = request.operationId.asStringView();
  const rust::Slice<const uint8_t> etag{reinterpret_cast<const uint8_t *>(operation.data()), operation.size()};
  auto result = engine.create_immutable_raw_chunk(toSlice(key),
                                                  toSlice(request.payload.data),
                                                  ~request.checksum.value,
                                                  true,
                                                  context,
                                                  etag);
  if (result.error_code != 0) {
    // A failed confirmation is not proof of absence. Never remove this key or
    // convert AlreadyExists into success without explicit durable reconciliation.
    // InvalidArg is not necessarily pre-write: the engine can encounter an
    // occupied writing-list entry after allocating and writing the new bytes.
    const bool rejectedBeforeWrite =
        result.error_code == StorageCode::kChecksumMismatch || result.error_code == StorageCode::kChunkAlreadyExists;
    return makeError(rejectedBeforeWrite ? result.error_code : StorageCode::kEcSealOutcomeUnknown,
                     fmt::format("EC create failed (engine code {}); retain allocation and reconcile outcome: {}",
                                 result.error_code,
                                 std::string_view(result.error.data(), result.error.size())));
  }
  const auto &meta = result.meta;
  const std::string_view returnedTag(reinterpret_cast<const char *>(result.etag.data()), result.etag.size());
  if (meta.len != request.payload.data.size() || meta.checksum != ~request.checksum.value ||
      meta.chain_ver != context.chain_ver || meta.last_request_id != context.last_request_id ||
      meta.last_client_low != context.last_client_low || meta.last_client_high != context.last_client_high ||
      returnedTag != operation) {
    return makeError(StorageCode::kEcSealOutcomeUnknown,
                     "EC create returned inconsistent metadata; retain allocation and reconcile outcome");
  }
  EcFragmentReceipt receipt;
  receipt.identity = request.identity;
  receipt.vChainId = request.vChainId;
  receipt.targetId = request.targetId;
  receipt.operationId = request.operationId;
  receipt.length = meta.len;
  receipt.checksum = ChecksumInfo{ChecksumType::CRC32C, ~meta.checksum};
  return receipt;
}

Result<EcReadResult> ChunkEngine::readEcFragment(chunk_engine::Engine &engine, const EcReadReq &request) {
  RETURN_ON_ERROR(request.validate());
  CHECK_RESULT(chunkId, request.identity.chunkId());
  const auto chainId = request.vChainId.chainId;
  std::string key(reinterpret_cast<const char *>(&chainId), sizeof(chainId));
  key.append(chunkId.data());
  const auto operation = request.operationId.asStringView();
  const rust::Slice<const uint8_t> etag{reinterpret_cast<const uint8_t *>(operation.data()), operation.size()};
  auto result = engine.read_immutable_raw_chunk(toSlice(key), request.expectedLength, ~request.checksum.value, etag);
  if (result.error_code != 0) {
    return makeError(result.error_code, std::string(result.error.data(), result.error.size()));
  }
  if (result.meta.len != request.expectedLength || result.data.size() != request.expectedLength ||
      result.meta.checksum != ~request.checksum.value) {
    return makeError(StorageCode::kChunkMetadataGetError, "EC read returned inconsistent metadata");
  }
  EcReadResult out;
  out.receipt.identity = request.identity;
  out.receipt.vChainId = request.vChainId;
  out.receipt.targetId = request.targetId;
  out.receipt.operationId = request.operationId;
  out.receipt.length = result.meta.len;
  out.receipt.checksum = ChecksumInfo{ChecksumType::CRC32C, ~result.meta.checksum};
  if (!result.data.empty()) {
    out.payload.data.assign(reinterpret_cast<const char *>(result.data.data()), result.data.size());
  }
  return out;
}

Result<EcFragmentReceipt> ChunkEngine::reconcileEcFragment(chunk_engine::Engine &engine,
                                                           const EcReconcileReq &request) {
  RETURN_ON_ERROR(request.validate());
  CHECK_RESULT(chunkId, request.identity.chunkId());
  const auto chainId = request.vChainId.chainId;
  std::string key(reinterpret_cast<const char *>(&chainId), sizeof(chainId));
  key.append(chunkId.data());
  const auto operation = request.operationId.asStringView();
  const rust::Slice<const uint8_t> etag{reinterpret_cast<const uint8_t *>(operation.data()), operation.size()};
  auto result =
      engine.reconcile_immutable_raw_chunk(toSlice(key), request.expectedLength, ~request.checksum.value, etag);
  if (result.error_code != 0) {
    return makeError(
        StorageCode::kEcSealOutcomeUnknown,
        fmt::format("EC durability reconciliation failed (engine code {}); retain allocation and reconcile outcome: {}",
                    result.error_code,
                    std::string_view(result.error.data(), result.error.size())));
  }
  const std::string_view returnedTag(reinterpret_cast<const char *>(result.etag.data()), result.etag.size());
  if (result.meta.len != request.expectedLength || result.meta.checksum != ~request.checksum.value ||
      returnedTag != operation) {
    return makeError(StorageCode::kEcSealOutcomeUnknown,
                     "EC reconciliation returned inconsistent metadata; retain allocation and reconcile outcome");
  }
  // The immutable identity and operation tag survive route-version advances.
  // The worker and operator validate the current route independently; the
  // persisted creation chain version is not a durability precondition here.
  EcFragmentReceipt receipt;
  receipt.identity = request.identity;
  receipt.vChainId = request.vChainId;
  receipt.targetId = request.targetId;
  receipt.operationId = request.operationId;
  receipt.length = result.meta.len;
  receipt.checksum = ChecksumInfo{ChecksumType::CRC32C, ~result.meta.checksum};
  return receipt;
}

Result<uint32_t> ChunkEngine::update(chunk_engine::Engine &engine, UpdateJob &job) {
  auto recordGuard = storageUpdateRecorder.record();

  // 1. prepare.
  const auto &updateIO = job.updateIO();
  const auto &chunkId = updateIO.key.chunkId;
  const auto &options = job.options();
  const auto &state = job.state();
  auto &result = job.result();

  auto chainId = updateIO.key.vChainId.chainId;
  std::string key;
  key.reserve(sizeof(chainId) + chunkId.data().size());
  key.append((const char *)&chainId, sizeof(chainId));
  key.append(chunkId.data());

  // 2. start update.
  chunk_engine::UpdateReq req{};
  if (updateIO.isTruncate()) {
    req.is_truncate = true;
  } else if (updateIO.isRemove()) {
    req.is_remove = true;
  }
  req.is_syncing = options.isSyncing;
  req.update_ver = updateIO.updateVer;
  req.chain_ver = job.commitChainVer();
  if (updateIO.checksum.type == ChecksumType::CRC32C) {
    req.checksum = ~updateIO.checksum.value;
  } else if (state.data) {
    req.without_checksum = true;
  }
  if (updateIO.isWrite()) {
    req.length = updateIO.length;
    req.offset = updateIO.offset;
  } else {
    req.length = 0;
    req.offset = updateIO.length;
  }
  req.data = reinterpret_cast<uint64_t>(state.data);
  req.last_request_id = job.requestCtx().tag.requestId;
  auto clientId = job.requestCtx().tag.clientId.uuid.asStringView();
  req.last_client_low = *(const uint64_t *)clientId.data();
  req.last_client_high = *(const uint64_t *)(clientId.data() + 8);

  std::string error{};
  auto chunk = engine.update_raw_chunk(toSlice(key), req, error);
  result.updateVer = result.commitVer = ChunkVer{req.out_commit_ver};
  result.commitChainVer = ChainVer{req.out_chain_ver};
  if (req.is_remove && req.out_non_existent) {
    result.checksum = ChecksumInfo{ChecksumType::NONE, 0};
  } else {
    result.checksum = ChecksumInfo{ChecksumType::CRC32C, ~req.out_checksum};
  }

  if (UNLIKELY(!error.empty())) {
    return makeError(req.out_error_code, std::move(error));
  }

  job.chunkEngineJob().set(engine, chunk);

  recordGuard.succ();
  if (updateIO.isTruncate() || updateIO.isExtend()) {
    return chunk->raw_meta().len;
  }
  return updateIO.length;
}

Result<uint32_t> ChunkEngine::commit(chunk_engine::Engine &engine, UpdateJob &job, bool sync) {
  auto recordGuard = storageCommitRecorder.record();

  const auto &commitIO = job.commitIO();
  const auto &chunkId = commitIO.key.chunkId;
  auto &result = job.result();

  auto chainId = commitIO.key.vChainId.chainId;
  std::string key;
  key.reserve(sizeof(chainId) + chunkId.data().size());
  key.append((const char *)&chainId, sizeof(chainId));
  key.append(chunkId.data());

  auto chunk = job.chunkEngineJob().chunk();
  chunk->set_chain_ver(job.commitChainVer());
  auto &meta = chunk->raw_meta();
  result.updateVer = result.commitVer = ChunkVer{meta.chunk_ver};
  result.commitChainVer = ChainVer{meta.chain_ver};

  std::string error;
  engine.commit_raw_chunk(chunk, sync, error);
  job.chunkEngineJob().release();
  if (UNLIKELY(!error.empty())) {
    return makeError(StorageCode::kChunkMetadataSetError, std::move(error));
  }

  recordGuard.succ();
  return uint32_t{};
}

}  // namespace hf3fs::storage
