#include "MetaOperator.h"
#include "meta/store/EcTreeGcCatalog.h"
namespace hf3fs::meta::server {
namespace {
CoTryTask<AdvanceEcTreeReclaimRsp> executeReclaim(std::shared_ptr<kv::IKVEngine> engine,
                                                  const Config &config,
                                                  AdvanceEcTreeReclaimReq req) {
  bool committing = false;
  try {
    auto raw = engine->createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget t(*raw, EcFileTreeTxnBudget::Profile::Gc);
    auto observed = co_await EcTreeGcCatalog::reclaimRequest(t, req, config.readonly());
    CO_RETURN_ON_ERROR(observed);
    if (!observed->needsCommit) co_return std::move(observed->response);
    if (config.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
    committing = true;
    CO_RETURN_ON_ERROR(co_await t.commit());
    co_return std::move(observed->response);
  } catch (const std::bad_alloc &) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
}  // namespace
CoTryTask<AdvanceEcTreeReclaimRsp> MetaOperator::advanceEcTreeReclaim(AdvanceEcTreeReclaimReq req) {
  if (!config_.enable_ec_revision_retirement() || !config_.enable_ec_rmw() || !config_.enable_ec_v2() ||
      !config_.enable_ec_catalog())
    co_return makeError(StatusCode::kNotImplemented, "explicit tree maintenance is disabled");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission);
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  co_return co_await folly::coro::co_withCancellation({}, executeReclaim(kvEngine_, config_, std::move(req)));
}
}  // namespace hf3fs::meta::server
