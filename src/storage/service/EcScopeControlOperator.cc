#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
Result<Void> StorageOperator::initEcScopeControl() {
  if (!config_.enable_ec_scope_control()) return Void{};
  if (!config_.enable_ec_fragments() || !components_.config.targets().ec_staging_v2()) {
    return makeError(StatusCode::kInvalidConfig, "EC scope control requires the V2-only storage mode");
  }
  CHECK_RESULT(authority, Uuid::fromHexString(config_.ec_scope_control_authority()));
  if (authority.is_nil()) return makeError(StatusCode::kInvalidConfig, "EC control authority must be nonzero");
  const std::filesystem::path controlPath(config_.ec_scope_control_key_file().string());
  const std::filesystem::path dataPath(config_.ec_capability_key_file().string());
  if (!dataPath.empty()) {
    std::error_code error;
    const bool same = std::filesystem::equivalent(controlPath, dataPath, error);
    if (error || same) return makeError(StatusCode::kInvalidConfig, "EC control requires a distinct explicit key file");
  }
  CHECK_RESULT(key, EcScopeControlKey::loadFile(controlPath));
  auto shared = std::shared_ptr<const EcScopeControlKey>(std::move(key));
  CHECK_RESULT(
      executor,
      EcScopeControlExecutor::create(std::move(shared), authority, components_.appInfo.nodeId, ecAuthorizationNow_));
  ecScopeControl_ = std::move(executor);
  return Void{};
}
CoTryTask<EcScopeControlRsp> StorageOperator::controlEcScope(const EcScopeControlRequest &request,
                                                             EcScopeControlAction action) {
  EcScopeControlRsp response;
  if (!ecScopeControl_) {
    response.result = makeError(StatusCode::kAuthenticationFail, "EC scope control is disabled");
    co_return response;
  }
  auto valid = ecScopeControl_->validateRequest(action, request);
  if (!valid) {
    response.result = makeError(valid.error());
    co_return response;
  }
  // A fixed, loaded physical instance can be revoked after it stops SERVING.
  // An absent or replaced instance cannot be reported as already drained.
  auto target = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!target || !(*target)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid, "fixed EC control target is not loaded");
    co_return response;
  }
  response.result = co_await ecScopeControl_->execute(action, request, (*target)->storageTarget);
  co_return response;
}
CoTryTask<EcScopeControlRsp> StorageOperator::revokeEcScope(const EcScopeControlRequest &request) {
  return controlEcScope(request, EcScopeControlAction::Revoke);
}
CoTryTask<EcScopeControlRsp> StorageOperator::queryEcScopeDrain(const EcScopeControlRequest &request) {
  return controlEcScope(request, EcScopeControlAction::Query);
}
}  // namespace hf3fs::storage
