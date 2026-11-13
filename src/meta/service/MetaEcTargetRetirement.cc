#include "meta/service/MetaOperator.h"

namespace hf3fs::meta::server {
CoTryTask<void> MetaOperator::authenticateEcTargetRetirement(EcTargetRetirementReq &req) {
  if (!config_.enable_ec_target_retirement() || !config_.enable_ec_catalog() || !config_.enable_ec_v2())
    co_return makeError(StatusCode::kNotImplemented, "explicit target retirement is disabled");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  // Actual UserStore credentials determine the effective UID. The UID carried
  // by an unauthenticated request is never administrative authorization.
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission);
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  CO_RETURN_ON_ERROR(ecTargetRetirement_->checkEnabled());
  co_return Void{};
}
CoTryTask<EcTargetRetirementRsp> MetaOperator::prepareEcTargetRetirement(PrepareEcTargetRetirementReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcTargetRetirement(req));
  co_return co_await folly::coro::co_withCancellation({}, ecTargetRetirement_->prepare(std::move(req)));
}
CoTryTask<EcTargetRetirementRsp> MetaOperator::queryEcTargetRetirement(QueryEcTargetRetirementReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcTargetRetirement(req));
  co_return co_await folly::coro::co_withCancellation({}, ecTargetRetirement_->query(std::move(req)));
}
}  // namespace hf3fs::meta::server
