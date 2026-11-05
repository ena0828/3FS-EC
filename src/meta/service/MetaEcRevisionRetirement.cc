#include <exception>
#include <new>
#include <utility>

#include "meta/service/MetaOperator.h"
#include "meta/store/EcRevisionRetirementCatalog.h"

namespace hf3fs::meta::server {
namespace {
CoTryTask<EcRevisionRetirementRsp> executeRetirement(std::shared_ptr<kv::IKVEngine> engine,
                                                     const Config &config,
                                                     EcRevisionRetirementReq req,
                                                     bool query) {
  bool commitStarted = false;
  try {
    if (!query && config.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
    auto txn = engine->createReadWriteTransaction();
    if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
    if (query) co_return co_await EcRevisionRetirementCatalog::query(*txn, req);
    auto result = co_await EcRevisionRetirementCatalog::retire(*txn, req);
    CO_RETURN_ON_ERROR(result);
    if (config.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
    // The permanent record and reference decrements are atomic. No generic
    // expiring result cache or automatic retry may hide a conflicting request.
    commitStarted = true;
    auto committed = co_await txn->commit();
    if (!committed) co_return makeError(std::move(committed.error()));
    co_return std::move(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
}  // namespace

CoTryTask<void> MetaOperator::authenticateEcRevisionRetirement(EcRevisionRetirementReq &req) {
  if (!config_.enable_ec_revision_retirement() || !config_.enable_ec_catalog() || !config_.enable_ec_v2())
    co_return makeError(StatusCode::kNotImplemented, "explicit EC revision retirement is disabled");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  // This validates UserStore credentials and rewrites effective identity.
  // An unauthenticated request containing uid=0 is never administrative proof.
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission, "retirement requires authenticated root");
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  co_return Void{};
}

CoTryTask<EcRevisionRetirementRsp> MetaOperator::retireEcRevisionV2(RetireEcRevisionV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcRevisionRetirement(req));
  co_return co_await folly::coro::co_withCancellation({}, executeRetirement(kvEngine_, config_, std::move(req), false));
}

CoTryTask<EcRevisionRetirementRsp> MetaOperator::queryEcRevisionRetirementV2(QueryEcRevisionRetirementV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcRevisionRetirement(req));
  co_return co_await folly::coro::co_withCancellation({}, executeRetirement(kvEngine_, config_, std::move(req), true));
}

}  // namespace hf3fs::meta::server
