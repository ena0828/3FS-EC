#include <new>

#include "meta/service/MetaOperator.h"
#include "meta/store/EcFileExecutionCatalog.h"

namespace hf3fs::meta::server {
CoTryTask<QueryEcFileOutputRsp> MetaOperator::queryEcFileOutput(QueryEcFileOutputReq req) {
  if (!config_.enable_ec_catalog() || !config_.enable_ec_v2() || !config_.enable_ec_rmw())
    co_return makeError(StatusCode::kNotImplemented, "file output observation is disabled");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission, "file output observation requires root");
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  try {
    auto raw = kvEngine_->createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget txn(*raw, EcFileTreeTxnBudget::Profile::Repair);
    auto observation = co_await EcFileExecutionCatalog::observeOutput(txn, req.identity);
    CO_RETURN_ON_ERROR(observation);
    QueryEcFileOutputRsp out;
    out.requestId = req.uuid;
    out.clientNamespace = req.client.uuid;
    out.observation = std::move(*observation);
    // No mutation, issuance, Storage RPC, result cache, or commit. FDB reads in
    // this transaction observe one version; failing any check returns no DTO.
    co_return out;
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::meta::server
