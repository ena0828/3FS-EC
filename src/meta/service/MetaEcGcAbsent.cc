#include "meta/service/MetaOperator.h"

namespace hf3fs::meta::server {
CoTryTask<EcAbsentAdminRsp> MetaOperator::confirmEcFragmentAbsent(ConfirmEcFragmentAbsentReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcGcAdmin(req));
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await folly::coro::co_withCancellation({}, ecGcAdmin_->confirmAbsent(std::move(req)));
}
CoTryTask<EcAbsentAdminRsp> MetaOperator::queryEcFragmentAbsent(QueryEcFragmentAbsentReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcGcAdmin(req));
  CO_RETURN_ON_ERROR(req.valid());
  // This may persist an authenticated observation of an already existing
  // Storage absence ledger. It cannot create that ledger, claim or original T0.
  co_return co_await folly::coro::co_withCancellation({}, ecGcAdmin_->queryAbsent(std::move(req)));
}
}  // namespace hf3fs::meta::server
