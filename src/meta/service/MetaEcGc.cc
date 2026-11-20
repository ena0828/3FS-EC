#include "meta/service/MetaOperator.h"

namespace hf3fs::meta::server {
CoTryTask<void> MetaOperator::authenticateEcGcAdmin(ReqBase &req) {
  CO_RETURN_ON_ERROR(ecGcAdmin_->checkEnabled());
  CO_RETURN_ON_ERROR(req.checkUuid());
  // Never use AUTHENTICATE's optional bypass. authenticate() validates the
  // actual UserStore token and effective UID before this root-only check.
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission, "exact GC requires authenticated root");
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  co_return Void{};
}
CoTryTask<EcGcAdminRsp> MetaOperator::collectEcFragmentV2(CollectEcFragmentV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcGcAdmin(req));
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await folly::coro::co_withCancellation({}, ecGcAdmin_->collect(std::move(req)));
}
CoTryTask<EcGcAdminRsp> MetaOperator::queryEcFragmentGcV2(QueryEcFragmentGcV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcGcAdmin(req));
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await folly::coro::co_withCancellation({}, ecGcAdmin_->query(std::move(req)));
}
CoTryTask<EcRetiredAdminRsp> MetaOperator::resolveEcFragmentRetired(ResolveEcFragmentRetiredReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcGcAdmin(req));
  CO_RETURN_ON_ERROR(req.valid());
  if (!config_.enable_ec_target_retirement() || !config_.enable_ec_host_fence())
    co_return makeError(StatusCode::kNotImplemented, "external target fencing is disabled");
  CO_RETURN_ON_ERROR(ecTargetRetirement_->checkEnabled());
  co_return co_await folly::coro::co_withCancellation({}, ecGcAdmin_->resolveRetired(std::move(req)));
}
}  // namespace hf3fs::meta::server
