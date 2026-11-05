#include "EcStageJob.h"

#include <algorithm>

#include "storage/store/StorageTarget.h"
#include "storage/update/EcJob.h"

namespace hf3fs::storage {
Result<Void> EcStageJob::validateAdmission() const {
  if (!ticket_ || !session_ || !target_ || !target_->usesEcStagingEngine()) {
    return makeError(StatusCode::kInvalidArg, "stage job requires an initialized V2 target and admission");
  }
  const auto &binding = ticket_->binding();
  if (request_.operation == EcStageOperation::ReadBlock ? (binding.kind != 1 && binding.kind != 2)
                                                        : binding.kind != 2) {
    return makeError(StatusCode::kTokenMismatch, "stage operation does not match the admitted scope kind");
  }
  if (request_.operation == EcStageOperation::Begin &&
      !std::equal(binding.client_namespace.begin(), binding.client_namespace.end(), request_.writerNamespace.data)) {
    return makeError(StatusCode::kTokenMismatch, "stage writer namespace differs from the admitted scope");
  }
  RETURN_ON_ERROR(ticket_->checkExecution());
  RETURN_ON_ERROR(request_.validate());
  return checkEcJobTarget(*target_, *ticket_, request_.vChainId.chainId, request_.targetId, request_.identity.object);
}
void EcStageJob::execute() {
  try {
    auto access = validateRoute();
    if (access) access = validateAdmission();
    if (!access) {
      setResult(makeError(access.error()));
      return;
    }
    setResult(target_->executeEcStage(request_));
  } catch (const std::exception &) {
    setResult(makeError(request_.durable() ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError));
  } catch (...) {
    setResult(makeError(request_.durable() ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError));
  }
}
Result<EcStageResult> EcStageJob::takeResult() {
  if (!completion_.observed() || consumed_) {
    return makeError(StorageClientCode::kResourceBusy, "stage job result is incomplete or already consumed");
  }
  consumed_ = true;
  auto finish = folly::makeGuard([this] {
    ticket_.reset();
    session_.reset();
  });
  auto output = std::move(result_);
  if (completion_.waitFailed()) {
    return makeError(request_.durable() ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  }
  const auto access = [&]() -> Result<Void> {
    try {
      auto result = validateRoute();
      if (result) result = validateAdmission();
      return result;
    } catch (...) {
      return makeError(request_.durable() ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError,
                       "stage final access check failed unexpectedly");
    }
  }();
  if (!access && output) {
    if (request_.durable()) {
      return makeError(StorageCode::kEcSealOutcomeUnknown,
                       "stage operation completed but final route, grant or scope check failed; reconcile outcome");
    }
    return makeError(access.error());
  }
  return output;
}
}  // namespace hf3fs::storage
