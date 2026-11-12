#include <new>

#include "meta/service/MetaOperator.h"
#include "meta/store/EcRangeCatalog.h"

namespace hf3fs::meta::server {
namespace {
CoTryTask<EcRangeRsp> executeRange(std::shared_ptr<kv::IKVEngine> engine, EcRangeReq req, bool query) {
  bool commitStarted = false;
  try {
    auto txn = engine->createReadWriteTransaction();
    if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
    if (query) co_return co_await EcRangeCatalog::query(*txn, req);
    auto result = co_await EcRangeCatalog::acquire(*txn, req);
    CO_RETURN_ON_ERROR(result);
    // Reference maintenance follows existing Acquire/Release readonly-mode
    // semantics. One real commit covers EOF, all pins, GC scopes and ECFR.
    // Do not retry with a fresh identity or use the expiring OpLog cache.
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

CoTryTask<void> MetaOperator::authenticateEcFileRange(ReqBase &req) {
  if (!config_.enable_ec_file_ranges() || !config_.enable_ec_catalog() || !config_.enable_ec_v2())
    co_return makeError(StatusCode::kNotImplemented, "bounded EC file range service is disabled");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  // UserStore applies the existing root-delegation semantics; all permanent
  // ownership below binds its resulting effective UID, not claimed privilege.
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  co_return Void{};
}

CoTryTask<DescribeEcFileV2Rsp> MetaOperator::describeEcFileV2(DescribeEcFileV2Req req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  auto txn = kvEngine_->createReadWriteTransaction();
  if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
  auto file = co_await loadV2File(*txn, req.user, req.object, req.access);
  CO_RETURN_ON_ERROR(file);
  CO_RETURN_ON_ERROR(co_await requireTrackedEcFile(*txn, req.object));
  DescribeEcFileV2Rsp rsp;
  rsp.file = ecFileState(*file);
  co_return rsp;
}

CoTryTask<EcRangeRsp> MetaOperator::acquireEcRangeV2(AcquireEcRangeV2Req req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  co_return co_await folly::coro::co_withCancellation({}, executeRange(kvEngine_, std::move(req), false));
}

CoTryTask<EcRangeRsp> MetaOperator::queryEcRangeV2(QueryEcRangeV2Req req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  co_return co_await folly::coro::co_withCancellation({}, executeRange(kvEngine_, std::move(req), true));
}
}  // namespace hf3fs::meta::server
