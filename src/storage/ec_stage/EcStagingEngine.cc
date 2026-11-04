#include "EcStagingEngine.h"

#include <algorithm>

namespace hf3fs::storage {
namespace {
rust::Slice<const uint8_t> bytes(std::string_view value) {
  return {reinterpret_cast<const uint8_t *>(value.data()), value.size()};
}
Result<Void> check(const chunk_engine::RawEcScopeStatus &status) {
  if (status.error_code) return makeError(status.error_code, std::string(status.error.data(), status.error.size()));
  if (!status.error.empty()) return makeError(StatusCode::kFoundBug, "stage bridge success contains an error");
  return Void{};
}
Result<EcStageResult> stateResult(chunk_engine::RawEcStageResult result) {
  RETURN_ON_ERROR(check(result.status));
  if (result.state.state < 1 || result.state.state > 3 || !result.state.revision) {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "stage bridge returned invalid state");
  }
  EcStageResult output;
  output.state = result.state;
  return output;
}
}  // namespace

Result<Void> EcStageRequest::validate() const {
  RETURN_ON_ERROR(identity.validate());
  RETURN_ON_ERROR(validateEcIntegrity(identity, integrity));
  if (operationId.is_nil() || vChainId.chainId == ChainId{} || targetId == TargetId{} ||
      integrity.wholeLength > kEcFragmentRpcMaxBytes || payload.size() > kEcIntegrityBlockBytes) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 stage request binding or size");
  }
  switch (operation) {
    case EcStageOperation::Begin:
      if (writerNamespace.is_nil()) return makeError(StatusCode::kInvalidArg, "stage begin needs writer namespace");
      break;
    case EcStageOperation::Append:
      RETURN_ON_ERROR(verifyEcIntegrityBlock(identity, integrity, blockIndex, payload));
      break;
    case EcStageOperation::ReadBlock:
      if (blockIndex >= integrity.blockCount) return makeError(StatusCode::kInvalidArg, "invalid V2 block index");
      break;
    case EcStageOperation::Query:
    case EcStageOperation::Reconcile:
    case EcStageOperation::Seal:
      break;
    default:
      return makeError(StatusCode::kInvalidArg, "unknown V2 stage operation");
  }
  if (operation != EcStageOperation::Append && !payload.empty()) {
    return makeError(StatusCode::kInvalidArg, "only append accepts a block payload");
  }
  return Void{};
}

Result<std::shared_ptr<EcStagingEngine>> EcStagingEngine::open(const Path &path,
                                                               bool create,
                                                               chunk_engine::RawEcStageLimits limits) {
  const auto text = path.string();
  auto result = chunk_engine::stage_open(text, create, sizeof(ChainId), limits);
  RETURN_ON_ERROR(check(result.status));
  return std::shared_ptr<EcStagingEngine>(new EcStagingEngine(std::move(result.handle)));
}
Result<std::shared_ptr<EcScope>> EcStagingEngine::scope() const {
  return EcScope::fromResult(chunk_engine::stage_scope_open(*handle_));
}
Result<uint64_t> EcStagingEngine::committedSize(ChainId chain) const {
  auto result = chunk_engine::stage_used_size(*handle_, {reinterpret_cast<const uint8_t *>(&chain), sizeof(chain)});
  RETURN_ON_ERROR(check(result.status));
  return result.committed;
}

Result<EcStageResult> EcStagingEngine::execute(const EcStageRequest &request) const {
  RETURN_ON_ERROR(request.validate());
  CHECK_RESULT(id, request.identity.chunkId());
  const auto chain = request.vChainId.chainId;
  std::string key(reinterpret_cast<const char *>(&chain), sizeof(chain));
  key.append(id.data());
  chunk_engine::RawEcStageBinding binding{};
  std::copy(std::begin(request.operationId.data), std::end(request.operationId.data), binding.operation.begin());
  binding.length = request.integrity.wholeLength;
  binding.checksum = request.integrity.wholeCrc32c;
  const auto readBlock = [&](uint8_t index) -> Result<std::string> {
    auto result = chunk_engine::stage_read_block(*handle_, bytes(key), binding, index);
    RETURN_ON_ERROR(check(result.status));
    std::string data;
    if (!result.data.empty()) data.assign(reinterpret_cast<const char *>(result.data.data()), result.data.size());
    RETURN_ON_ERROR(verifyEcIntegrityBlock(request.identity, request.integrity, index, data));
    return data;
  };
  switch (request.operation) {
    case EcStageOperation::Begin: {
      std::array<uint8_t, 16> writer{};
      std::copy(std::begin(request.writerNamespace.data), std::end(request.writerNamespace.data), writer.begin());
      return stateResult(chunk_engine::stage_begin(*handle_, bytes(key), binding, writer));
    }
    case EcStageOperation::Append:
      return stateResult(
          chunk_engine::stage_append(*handle_, bytes(key), binding, request.blockIndex, bytes(request.payload)));
    case EcStageOperation::Query:
      return stateResult(chunk_engine::stage_query(*handle_, bytes(key), binding));
    case EcStageOperation::Reconcile:
      return stateResult(chunk_engine::stage_reconcile(*handle_, bytes(key), binding));
    case EcStageOperation::ReadBlock: {
      CHECK_RESULT(data, readBlock(request.blockIndex));
      EcStageResult output;
      output.data = std::move(data);
      return output;
    }
    case EcStageOperation::Seal: {
      auto result = chunk_engine::stage_seal(*handle_, bytes(key), binding);
      if (result.error_code) return makeError(result.error_code, std::string(result.error.data(), result.error.size()));
      if (result.meta.len != binding.length || result.meta.checksum != binding.checksum || result.meta.chain_ver != 0 ||
          result.etag.size() != binding.operation.size() ||
          !std::equal(result.etag.begin(), result.etag.end(), binding.operation.begin())) {
        return makeError(StorageCode::kEcSealOutcomeUnknown, "stage seal returned inconsistent immutable metadata");
      }
      // Bounded verification against the trusted descriptor even if a local
      // caller previously used the lower-level bridge with a colliding CRC.
      for (uint8_t block = 0; block != request.integrity.blockCount; ++block) {
        auto verified = readBlock(block);
        if (!verified)
          return makeError(StorageCode::kEcSealOutcomeUnknown,
                           "sealed data did not confirm the trusted descriptor; retain allocation");
      }
      EcFragmentReceipt receipt;
      receipt.identity = request.identity;
      receipt.vChainId = request.vChainId;
      receipt.targetId = request.targetId;
      receipt.operationId = request.operationId;
      receipt.length = binding.length;
      receipt.checksum = ChecksumInfo{ChecksumType::CRC32C, ~binding.checksum};
      EcStageResult output;
      output.sealed = std::move(receipt);
      return output;
    }
  }
  return makeError(StatusCode::kInvalidArg, "unknown stage operation");
}
}  // namespace hf3fs::storage
