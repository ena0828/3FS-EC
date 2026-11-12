#pragma once

#include "EcFileSessionCatalog.h"

namespace hf3fs::meta::server {
namespace detail {
struct EcFileMutationTestAccess;
}
class EcFileMutationCoordinator;
class EcRmwPublicationProof;
class EcFileMutationCatalog;
class EcFilePublicationGate {
 public:
  const EcFileChildRecord &child() const { return child_; }
  const EcTreeRoot &currentRoot() const { return root_; }

 private:
  friend class EcFileMutationCatalog;
  EcFilePublicationGate(EcFileTreeTxnBudget &txn, EcFileChildRecord child, EcTreeRoot root)
      : txn_(&txn),
        attempt_(txn.attempt()),
        child_(std::move(child)),
        root_(std::move(root)) {}
  EcFileTreeTxnBudget *txn_;
  uint64_t attempt_;
  EcFileChildRecord child_;
  EcTreeRoot root_;
};
// A failed operation requires discarding the whole transaction. Snapshot reads
// are never used as CAS. Missing Query is absence of a record, not a statement
// that a formerly dispatched operation did not execute.
class EcFileMutationCatalog {
 public:
  static CoTryTask<EcFileMutationRecord> begin(EcFileTreeTxnBudget &, const EcFilePwriteIntent &);
  static CoTryTask<std::optional<EcFileMutationRecord>> query(EcFileTreeTxnBudget &,
                                                              const EcObjectRef &,
                                                              const Uuid &parent,
                                                              const EcOwner &);
  static CoTryTask<EcFileChildRecord> planChild(EcFileTreeTxnBudget &, const EcOwner &, const EcFileChildIntent &);
  static CoTryTask<std::optional<EcFileChildRecord>> queryChild(EcFileTreeTxnBudget &,
                                                                const EcObjectRef &,
                                                                const Uuid &child,
                                                                const EcOwner &);
  static CoTryTask<EcFileMutationRecord> sealPrefix(EcFileTreeTxnBudget &,
                                                    const EcObjectRef &,
                                                    const Uuid &parent,
                                                    const EcOwner &);
  // Does not authorize Data installation. Checks the source CAS before the
  // trusted W1-proof installer changes the tree in this same transaction.
  static CoTryTask<EcFilePublicationGate> preparePublication(EcFileTreeTxnBudget &,
                                                             const EcObjectRef &,
                                                             const Uuid &child,
                                                             const EcOwner &);

 private:
  friend class EcFileMutationCoordinator;
  friend class EcFileDataInstaller;
  friend struct detail::EcFileMutationTestAccess;
  // This is only the final metadata step, not a Data installer or a seal proof.
  // The trusted installer must first consume W1's unforgeable publication proof,
  // install its manifest and change the tree, then call this in that SAME txn.
  // The public service cannot invoke this step with a caller-built receipt.
  static CoTryTask<EcFileMutationRecord> finishPublished(EcFileTreeTxnBudget &,
                                                         const EcOwner &,
                                                         const EcFilePublicationGate &,
                                                         const EcTreeEditResult &);
};
}  // namespace hf3fs::meta::server
