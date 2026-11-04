#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
Result<EcStageResult> StorageTarget::executeEcStage(const EcStageRequest &request) {
  if (!usesEcStagingEngine() || request.targetId != targetId() || request.vChainId.chainId != chainId()) {
    return makeError(StorageCode::kTargetStateInvalid, "stage request does not identify an initialized V2 target");
  }
  return staging_->execute(request);
}
}  // namespace hf3fs::storage
