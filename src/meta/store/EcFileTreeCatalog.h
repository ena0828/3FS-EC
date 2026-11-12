#pragma once

#include "EcFileTreeTxnBudget.h"
#include "fbs/meta/EcFileTree.h"
#include "fbs/meta/EcTreeCut.h"

namespace hf3fs::meta::server {
namespace detail {
struct EcFileTreeTestAccess;
}
class EcFileTreeCatalog;
// Bound to one exact wrapper attempt. Not serializable or constructible from a
// caller mode bit; every root operation also rereads permanent birth evidence.
class EcTreeContext {
 public:
  const EcTreeBirth &birth() const { return birth_; }

 private:
  friend class EcFileTreeCatalog;
  EcTreeContext(EcFileTreeTxnBudget &txn, EcTreeBirth birth)
      : txn_(&txn),
        attempt_(txn.attempt()),
        birth_(std::move(birth)) {}
  EcFileTreeTxnBudget *txn_;
  uint64_t attempt_;
  EcTreeBirth birth_;
  bool retiredMaintenance_ = false;
};
// Every non-success requires the caller to discard the transaction. The
// budget wrapper poisons budget/KV failures, not all catalog semantic errors.
class EcFileTreeCatalog {
 public:
  // Internal namespace transaction primitive only. No inode/dentry/RPC is
  // created by W0; an existing mode-2/3 object never receives a new birth.
  static CoTryTask<EcTreeRoot> createBirth(EcFileTreeTxnBudget &, const EcTreeBirth &);
  // Permanent mode/birth evidence; intentionally independent of a live root.
  static CoTryTask<EcTreeBirth> getBirth(EcFileTreeTxnBudget &, const EcObjectRef &);
  static CoTryTask<EcTreeContext> open(EcFileTreeTxnBudget &, const EcObjectRef &);
  static CoTryTask<EcTreeRoot> getRoot(EcTreeContext &);
  static CoTryTask<EcTreeSlot> lookup(EcTreeContext &, uint64_t stripe);
  static CoTryTask<EcTreeEditResult> replaceZero(EcTreeContext &, const EcTreeEdit &);
  static CoTryTask<std::optional<EcTreeEditResult>> queryEdit(EcTreeContext &, const Uuid &operation);
  // Exactly one queued node / <=16 outgoing edges. Repeated successful calls
  // return the same terminal state without repeating decrements.
  static CoTryTask<EcTreeNodeRefs> reclaimNode(EcTreeContext &, const Uuid &node);

 private:
  friend struct detail::EcFileTreeTestAccess;
  friend class EcFileTruncateCatalog;
  friend class EcFileRepairCatalog;
  friend class EcFileDataInstaller;
  friend class EcTreeGcCatalog;
  friend class EcFileLifecycleCatalog;
  static CoTryTask<EcTreeRoot> detachForRetirement(EcTreeContext &);
  static CoTryTask<EcTreeNodeRefs> reclaimRetired(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &);
  static CoTryTask<EcTreeRoot> cut(EcTreeContext &, const EcTreeCut &);
  static CoTryTask<EcTreeRoot> validateContext(EcTreeContext &);
  static CoTryTask<EcTreeEditResult> replace(EcTreeContext &, const EcTreeEdit &);
  static CoTryTask<EcTreeManifestHolds> installed(EcTreeContext &, const EcTreeSlot &, bool verifyPermanent = false);
  static Result<EcTreeManifestHolds> commitment(const EcObjectRef &,
                                                const EcManifest &,
                                                const EcV2AllocationBindings &,
                                                const storage::EcSha256 &);
  static CoTryTask<Void> manifestHold(EcTreeContext &, const EcTreeSlot &, bool increment);
};
}  // namespace hf3fs::meta::server
