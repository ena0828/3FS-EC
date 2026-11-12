#pragma once

#include "DirEntry.h"
#include "EcFileSessionCatalog.h"
#include "fbs/meta/EcFileLifecycle.h"

namespace hf3fs::meta::server {
class GcManager;
// Every helper is part of the caller's authenticated namespace transaction.
// Semantic errors require discarding that transaction. No background I/O,
// timeout reclamation, G capability, or physical deletion is performed here.
class EcFileLifecycleCatalog {
 public:
  static CoTryTask<std::optional<RenameRsp>> replay(EcFileTreeTxnBudget &, const RenameReq &);
  // The caller's normal Rename transaction owns resolution/permission checks;
  // this branch repeats conflict reads and atomically moves/replaces names.
  static CoTryTask<RenameRsp> rename(EcFileTreeTxnBudget &,
                                     const RenameReq &,
                                     const DirEntry &source,
                                     InodeId destinationParent,
                                     const String &destinationName,
                                     GcManager &);
  static CoTryTask<std::optional<HardLinkRsp>> replay(EcFileTreeTxnBudget &, const HardLinkReq &);
  static CoTryTask<std::optional<RemoveRsp>> replay(EcFileTreeTxnBudget &, const RemoveReq &);
  static CoTryTask<HardLinkRsp> link(EcFileTreeTxnBudget &,
                                     const HardLinkReq &,
                                     InodeId source,
                                     InodeId destinationParent,
                                     const String &destinationName);
  static CoTryTask<RemoveRsp> unlink(EcFileTreeTxnBudget &, const RemoveReq &, const DirEntry &);
  static CoTryTask<Void> requireUnlinkedSession(EcFileTreeTxnBudget &, const EcObjectRef &);
  static CoTryTask<Void> retireIfUnreferenced(EcFileTreeTxnBudget &, const EcObjectRef &);
  static CoTryTask<EcTreeRoot> historicalRoot(EcFileTreeTxnBudget &, const EcObjectRef &);
  // Internal bounded maintenance: one known queued node, no scan/no physical GC.
  static CoTryTask<EcTreeNodeRefs> reclaimRetiredNode(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &);
};
}  // namespace hf3fs::meta::server
