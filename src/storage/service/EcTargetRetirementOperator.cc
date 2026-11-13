#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
CoTryTask<EcTargetRetirementRsp> StorageOperator::controlEcTargetRetirement(
    const EcTargetRetirementRequest &request, EcTargetRetirementAction action) {
  EcTargetRetirementRsp response;
  if (!config_.enable_ec_target_retirement() || !ecTargetRetirement_) {
    response.result = makeError(StatusCode::kAuthenticationFail, "target retirement is disabled");
    co_return response;
  }
  auto valid = ecTargetRetirement_->validateRequest(action, request);
  if (!valid) {
    response.result = makeError(valid.error());
    co_return response;
  }
  auto target = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!target || !(*target)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid, "fixed retirement target is not loaded");
    co_return response;
  }
  auto owned = (*target)->storageTarget;
  response.result = co_await ecTargetRetirement_->execute(action, request, owned);
  auto current = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!current || (*current)->storageTarget != owned)
    response.result = makeError(StorageCode::kEcSealOutcomeUnknown);
  co_return response;
}
CoTryTask<EcTargetRetirementRsp> StorageOperator::prepareEcTargetRetirement(const EcTargetRetirementRequest &request) {
  return controlEcTargetRetirement(request, EcTargetRetirementAction::Prepare);
}
CoTryTask<EcTargetRetirementRsp> StorageOperator::queryEcTargetRetirement(const EcTargetRetirementRequest &request) {
  return controlEcTargetRetirement(request, EcTargetRetirementAction::Query);
}
}  // namespace hf3fs::storage
