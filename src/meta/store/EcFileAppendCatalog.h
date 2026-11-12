#pragma once
#include "EcFileMutationCatalog.h"
#include "fbs/meta/EcFileAppend.h"

namespace hf3fs::meta::server {
class EcFileAppendCatalog {
 public:
  // Caller authenticates, commits once, and discards the whole transaction on
  // any error. A returned record before commit is not an acceptance proof.
  static CoTryTask<EcFileAppendRecord> begin(EcFileTreeTxnBudget &, const EcFileAppendIntent &);
  static CoTryTask<std::optional<EcFileAppendRecord>> query(EcFileTreeTxnBudget &, const EcFileAppendIntent &);
  static CoTryTask<Void> requireMutationOpen(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &parent);
  static CoTryTask<Void> finishParent(EcFileTreeTxnBudget &, const EcFileMutationRecord &);
  static CoTryTask<EcFileSyncRecord> sync(EcFileTreeTxnBudget &, const EcFileSyncIntent &);
};
}  // namespace hf3fs::meta::server
