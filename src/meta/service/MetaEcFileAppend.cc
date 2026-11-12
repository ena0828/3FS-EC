#include "MetaOperator.h"
#include "meta/store/EcFileAppendCatalog.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcFileTreeTxnBudget;
EcOwner ownerOf(const ReqBase &r) { return {r.user.uid, r.client.uuid}; }
template <class R, class Fn>
CoTryTask<R> transaction(kv::IKVEngine &db, Fn fn) {
  bool committing = false;
  try {
    auto raw = db.createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    Tx tx(*raw);
    auto r = co_await fn(tx);
    CO_RETURN_ON_ERROR(r);
    committing = true;
    CO_RETURN_ON_ERROR(co_await tx.commit());
    co_return std::move(*r);
  } catch (const std::bad_alloc &) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
}  // namespace
CoTryTask<EcFileAppendRsp> MetaOperator::beginEcFileAppend(BeginEcFileAppendReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await transaction<EcFileAppendRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileAppendRsp> {
    auto r = co_await EcFileAppendCatalog::begin(tx, req.intent);
    CO_RETURN_ON_ERROR(r);
    EcFileAppendRsp out;
    out.requestId = req.uuid;
    out.record = std::move(*r);
    co_return out;
  });
}
CoTryTask<EcFileAppendRsp> MetaOperator::queryEcFileAppend(QueryEcFileAppendReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await transaction<EcFileAppendRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileAppendRsp> {
    auto r = co_await EcFileAppendCatalog::query(tx, req.intent);
    CO_RETURN_ON_ERROR(r);
    EcFileAppendRsp out;
    out.requestId = req.uuid;
    out.record = std::move(*r);
    co_return out;
  });
}
CoTryTask<SyncEcFileSessionRsp> MetaOperator::syncEcFileSession(SyncEcFileSessionReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  // This path creates a persistent barrier receipt; readonly Meta cannot
  // silently turn it into a local/no-op acknowledgement.
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await transaction<SyncEcFileSessionRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<SyncEcFileSessionRsp> {
    auto r = co_await EcFileAppendCatalog::sync(tx, req.intent);
    CO_RETURN_ON_ERROR(r);
    SyncEcFileSessionRsp out;
    out.requestId = req.uuid;
    out.record = std::move(*r);
    co_return out;
  });
}
}  // namespace hf3fs::meta::server
