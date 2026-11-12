#pragma once
#include "EcTreeGcCatalog.h"
#include "detail/EcGcTxnScope.h"
namespace hf3fs::meta::server {
// Typed dispatch; the original flat catalogs retain their strict mode2/3 gates.
class EcExactGcCatalog {
 public:
  using Tx = kv::IReadWriteTransaction;
  static CoTryTask<std::optional<EcGcClaim>> getClaim(Tx &t,
                                                      const EcObjectRef &o,
                                                      const storage::EcFragmentIdentity &i) {
    EcGcTxnScope scope(t);
    auto &budget = scope.transaction();
    auto tree = co_await EcTreeGcCatalog::isTree(budget, o);
    CO_RETURN_ON_ERROR(tree);
    if (*tree) co_return co_await EcTreeGcCatalog::getClaim(budget, o, i);
    co_return co_await EcV2GcCatalog::getClaim(t, o, i);
  }
  static CoTryTask<EcGcClaim> claim(Tx &t,
                                    const EcObjectRef &o,
                                    const storage::EcFragmentIdentity &i,
                                    const Uuid &id,
                                    const storage::EcScopeControlKey &key) {
    EcGcTxnScope scope(t);
    auto &budget = scope.transaction();
    auto tree = co_await EcTreeGcCatalog::isTree(budget, o);
    CO_RETURN_ON_ERROR(tree);
    if (*tree) co_return co_await EcTreeGcCatalog::claim(budget, o, i, id, key);
    co_return co_await EcV2GcCatalog::claim(t, o, i, id, key);
  }
};
}  // namespace hf3fs::meta::server
