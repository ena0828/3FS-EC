#include <new>

#include "meta/components/EcV2Coordinator.h"
#include "meta/service/MetaOperator.h"
#include "meta/store/EcFileOutputResolutionCatalog.h"

namespace hf3fs::meta::server {
CoTryTask<ConfirmEcFileOutputResolutionRsp> MetaOperator::confirmEcFileOutputResolution(
    ConfirmEcFileOutputResolutionReq req) {
  if (!config_.enable_ec_catalog() || !config_.enable_ec_v2() || !config_.enable_ec_rmw())
    co_return makeError(StatusCode::kNotImplemented);
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission);
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  auto key = ecV2Coordinator_->controlKeyForObservation();
  CO_RETURN_ON_ERROR(key);
  try {
    auto raw = kvEngine_->createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
    auto resolution = co_await EcFileOutputResolutionCatalog::confirm(tx, req.identity, req.resolutionId,
                                                                      req.client.uuid, **key);
    CO_RETURN_ON_ERROR(resolution);
    // No automatic retry and no response before checked commit. Unknown commit
    // is recovered only by the same permanent resolution ID, never a new child.
    CO_RETURN_ON_ERROR(co_await tx.commit());
    ConfirmEcFileOutputResolutionRsp out;
    out.clientNamespace = req.client.uuid;
    out.requestId = req.uuid;
    out.resolution = std::move(*resolution);
    co_return out;
  } catch (const std::bad_alloc &) { co_return makeError(StatusCode::kNotEnoughMemory); }
  catch (...) { co_return makeError(StatusCode::kIOError); }
}
CoTryTask<QueryEcFileOutputResolutionRsp> MetaOperator::queryEcFileOutputResolution(
    QueryEcFileOutputResolutionReq req) {
  if (!config_.enable_ec_catalog() || !config_.enable_ec_v2() || !config_.enable_ec_rmw())
    co_return makeError(StatusCode::kNotImplemented);
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission);
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  auto key = ecV2Coordinator_->controlKeyForObservation();
  CO_RETURN_ON_ERROR(key);
  try {
    auto raw = kvEngine_->createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
    auto resolution = co_await EcFileOutputResolutionCatalog::query(tx, req.identity, req.resolutionId, **key);
    CO_RETURN_ON_ERROR(resolution);
    QueryEcFileOutputResolutionRsp out;
    out.clientNamespace = req.client.uuid;
    out.requestId = req.uuid;
    out.resolution = std::move(*resolution);
    co_return out;
  } catch (const std::bad_alloc &) { co_return makeError(StatusCode::kNotEnoughMemory); }
  catch (...) { co_return makeError(StatusCode::kIOError); }
}
}  // namespace hf3fs::meta::server
