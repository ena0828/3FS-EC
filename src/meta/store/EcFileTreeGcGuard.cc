#include "EcFileTreeGcGuard.h"

#include <limits>

#include "EcFileExecutionCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "detail/EcFileTreeKeys.h"
#include "fbs/meta/EcV2Gc.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
Result<Void> valid(const EcTreeAllocationHolds &record,
                   const EcObjectRef &object,
                   const storage::EcFragmentIdentity &identity) {
  RETURN_ON_ERROR(identity.validate());
  if (record.object != object || identity.object != object.incarnation || !same(record.identity, identity))
    return makeError(StatusCode::kDataCorruption, "EC tree allocation hold identity mismatch");
  return Void{};
}
}  // namespace
CoTryTask<Void> EcFileTreeGcGuard::requireUnheld(kv::IReadWriteTransaction &txn,
                                                 const EcObjectRef &object,
                                                 const storage::EcFragmentIdentity &identity) {
  CO_RETURN_ON_ERROR(co_await EcTreeSourcePinCatalog::requireUnheld(txn, object, identity));
  CO_RETURN_ON_ERROR(co_await EcFileExecutionCatalog::requireUnheld(txn, object, identity));
  CO_RETURN_ON_ERROR(identity.validate());
  if (identity.object != object.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  auto key = allocationKey(kv::KeyPrefix::EcTreeAllocationHold, identity);
  CO_RETURN_ON_ERROR(key);
  auto record = co_await load<EcTreeAllocationHolds>(txn, *key);
  CO_RETURN_ON_ERROR(record);
  if (*record) {
    CO_RETURN_ON_ERROR(valid(**record, object, identity));
    if ((**record).holds)
      co_return makeError(StatusCode::kTokenStale, "reachable EC tree allocation cannot be claimed");
  }
  co_return Void{};
}
CoTryTask<Void> EcFileTreeGcGuard::adjust(kv::IReadWriteTransaction &txn,
                                          const EcObjectRef &object,
                                          const storage::EcFragmentIdentity &identity,
                                          bool increment) {
  CO_RETURN_ON_ERROR(identity.validate());
  if (identity.object != object.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  auto key = allocationKey(kv::KeyPrefix::EcTreeAllocationHold, identity);
  CO_RETURN_ON_ERROR(key);
  auto loaded = co_await load<EcTreeAllocationHolds>(txn, *key);
  CO_RETURN_ON_ERROR(loaded);
  EcTreeAllocationHolds value;
  if (*loaded) {
    value = **loaded;
    CO_RETURN_ON_ERROR(valid(value, object, identity));
  } else {
    value.object = object;
    value.identity = identity;
  }
  if (increment) {
    auto claimKey = allocationKey(kv::KeyPrefix::EcGcClaim, identity);
    CO_RETURN_ON_ERROR(claimKey);
    auto claimed = co_await txn.get(*claimKey);
    CO_RETURN_ON_ERROR(claimed);
    if (*claimed) co_return makeError(StatusCode::kTokenStale, "permanent GC claim forbids a tree hold");
    auto protectionKey = allocationKey(kv::KeyPrefix::EcGcAllocation, identity);
    CO_RETURN_ON_ERROR(protectionKey);
    auto protection = co_await load<EcGcAllocationRecord>(txn, *protectionKey);
    CO_RETURN_ON_ERROR(protection);
    if (*protection && (!(**protection).claimId.is_nil() || (**protection).object != object ||
                        !same((**protection).allocation.identity, identity)))
      co_return makeError(StatusCode::kDataCorruption, "GC allocation state forbids a new tree hold");
    if (value.holds == std::numeric_limits<uint64_t>::max()) co_return makeError(StatusCode::kDataCorruption);
    ++value.holds;
  } else {
    if (!value.holds) co_return makeError(StatusCode::kDataCorruption, "EC tree allocation hold underflow");
    --value.holds;
  }
  co_return co_await store(txn, *key, value);
}
}  // namespace hf3fs::meta::server
