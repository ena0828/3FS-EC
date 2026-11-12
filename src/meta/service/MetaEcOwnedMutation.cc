#include <new>

#include "meta/service/MetaOperator.h"
#include "meta/store/EcOwnedMutationCatalog.h"

namespace hf3fs::meta::server {
CoTryTask<EcOwnedMutationRsp> MetaOperator::queryEcOwnedMutationV2(QueryEcOwnedMutationV2Req req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  if (!ecV2Coordinator_) co_return makeError(StatusCode::kNotImplemented, "native coordinator is unavailable");
  auto key = ecV2Coordinator_->controlKeyForObservation();
  CO_RETURN_ON_ERROR(key);
  try {
    auto txn = kvEngine_->createReadWriteTransaction();
    if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
    // A changing observation, not a permanently cached mutation result. No
    // transaction commit, inode ACL/liveness check, or current routing lookup.
    co_return co_await EcOwnedMutationCatalog::query(*txn, req, **key);
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::meta::server
