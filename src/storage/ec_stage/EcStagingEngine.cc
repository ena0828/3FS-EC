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
Result<std::shared_ptr<EcStagingEngine>> EcStagingEngine::openExactGc(const Path &path,
                                                                      bool create,
                                                                      chunk_engine::RawEcStageLimits limits) {
  const auto text = path.string();
  auto result = chunk_engine::stage_open_gc(text, create, sizeof(ChainId), limits);
  RETURN_ON_ERROR(check(result.status));
  auto format = chunk_engine::stage_actual_disk_format(*result.handle);
  RETURN_ON_ERROR(check(format.status));
  if (format.disk_format != 3) {
    return makeError(StatusCode::kFoundBug, "exact GC opener returned another disk format");
  }
  return std::shared_ptr<EcStagingEngine>(new EcStagingEngine(std::move(result.handle)));
}
Result<uint16_t> EcStagingEngine::actualDiskFormat() const {
  auto result = chunk_engine::stage_actual_disk_format(*handle_);
  RETURN_ON_ERROR(check(result.status));
  if (result.disk_format != 2 && result.disk_format != 3) {
    return makeError(StatusCode::kFoundBug, "stage bridge returned unknown disk format");
  }
  return result.disk_format;
}
Result<std::shared_ptr<EcScope>> EcStagingEngine::scope() const {
  return EcScope::fromResult(chunk_engine::stage_scope_open(*handle_));
}
Result<uint64_t> EcStagingEngine::committedSize(ChainId chain) const {
  auto result = chunk_engine::stage_used_size(*handle_, {reinterpret_cast<const uint8_t *>(&chain), sizeof(chain)});
  RETURN_ON_ERROR(check(result.status));
  return result.committed;
}

Result<chunk_engine::RawUsedSize> EcStagingEngine::physicalUsedSize() const {
  auto result = chunk_engine::stage_physical_used_size(*handle_);
  RETURN_ON_ERROR(check(result.status));
  return result.value;
}
Result<chunk_engine::Metrics> EcStagingEngine::sampleMetrics() const {
  auto result = chunk_engine::stage_sample_metrics(*handle_);
  RETURN_ON_ERROR(check(result.status));
  return result.value;
}
Result<Void> EcStagingEngine::setAllowToAllocate(bool allow) const {
  return check(chunk_engine::stage_set_allow_to_allocate(*handle_, allow));
}

chunk_engine::RawEcStageTrimResult EcStagingEngine::trimEmptyGroups(
    const chunk_engine::RawEcStageTrimLimits &limits) const {
  return chunk_engine::stage_trim_empty_groups(*handle_, limits);
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
Result<EcGcLedgerReceipt> EcStagingEngine::executeGc(const VerifiedEcGcRequest &verified, ChainId actualChain) const {
  const auto &certificate = verified.certificate();
  if (actualChain != certificate.endpoint.chainId) {
    return makeError(StorageCode::kTargetStateInvalid, "GC actual chain differs from certificate");
  }
  CHECK_RESULT(format, actualDiskFormat());
  if (format != 3) return makeError(StorageCode::kTargetStateInvalid, "GC requires disk format 3");
  CHECK_RESULT(id, certificate.fragment.chunkId());
  // Native ChainId prefix, exactly as execute()/stage_begin. Neither caller
  // supplied bytes nor a route table can replace the signed fragment identity.
  std::string key(reinterpret_cast<const char *>(&actualChain), sizeof(actualChain));
  key.append(id.data());
  chunk_engine::RawEcStageGcClaim claim{};
  std::copy(std::begin(certificate.claimId.data), std::end(certificate.claimId.data), claim.claim_id.begin());
  claim.claim_digest = verified.claimDigest();
  claim.eligibility_digest = certificate.eligibilityDigest;
  std::copy(std::begin(certificate.endpoint.engineUuid.data),
            std::end(certificate.endpoint.engineUuid.data),
            claim.target.engine.begin());
  std::copy(std::begin(certificate.endpoint.targetIncarnation.data),
            std::end(certificate.endpoint.targetIncarnation.data),
            claim.target.incarnation.begin());
  claim.target.chain = actualChain.toUnderType();
  claim.target.target = certificate.endpoint.targetId.toUnderType();
  std::copy(std::begin(certificate.fragmentOperation.data),
            std::end(certificate.fragmentOperation.data),
            claim.binding.operation.begin());
  claim.binding.length = certificate.integrity.wholeLength;
  claim.binding.checksum = certificate.integrity.wholeCrc32c;
  std::copy(std::begin(certificate.writerClient.data), std::end(certificate.writerClient.data), claim.writer.begin());
  // Both primitives use the same opaque handle. Query never invokes Collect,
  // and its successful receipt includes the Rust terminal/WAL confirmation.
  auto result = verified.action() == EcGcAction::Collect ? chunk_engine::stage_gc_collect(*handle_, bytes(key), claim)
                                                         : chunk_engine::stage_gc_query(*handle_, bytes(key), claim);
  if (result.status.error_code)
    return makeError(result.status.error_code, std::string(result.status.error.data(), result.status.error.size()));
  if (!result.status.error.empty()) return makeError(StorageCode::kEcSealOutcomeUnknown);
  if (result.receipt.claim_id != claim.claim_id || result.receipt.terminal_revision < 2 ||
      std::all_of(result.receipt.ledger_sha256.begin(), result.receipt.ledger_sha256.end(), [](uint8_t byte) {
        return byte == 0;
      })) {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "GC bridge returned an invalid confirmation");
  }
  EcGcLedgerReceipt receipt;
  std::copy(result.receipt.claim_id.begin(), result.receipt.claim_id.end(), std::begin(receipt.claimId.data));
  receipt.ledgerSha256 = result.receipt.ledger_sha256;
  receipt.terminalRevision = result.receipt.terminal_revision;
  return receipt;
}
}  // namespace hf3fs::storage
