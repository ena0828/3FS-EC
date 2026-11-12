#pragma once

#include "EcFileTreeCatalog.h"
#include "fbs/meta/EcFileMutation.h"

namespace hf3fs::meta {
struct OpenEcFileSessionReq;
}
namespace hf3fs::meta::server {
class EcFileMutationCatalog;

// Internal transaction primitives; caller authenticates every operation.
// Open additionally validates the actual inode/ACL in this same transaction.
// No method commits, signs a capability, or reaps a session by elapsed time.
class EcFileSessionCatalog {
 public:
  // Full semantic request (without bearer token/transport forwarding) is bound
  // permanently before an implicit birth can be used by a retry.
  static CoTryTask<EcFileSessionRecord> openExisting(EcFileTreeTxnBudget &,
                                                     const flat::UserInfo &authenticated,
                                                     const OpenEcFileSessionReq &);
  static CoTryTask<EcFileSessionRecord> open(EcFileTreeTxnBudget &,
                                             const flat::UserInfo &authenticated,
                                             const EcFileOpenIntent &);
  static CoTryTask<EcFileSessionRecord> get(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &, const EcOwner &);
  static CoTryTask<EcFileSessionRecord> close(EcFileTreeTxnBudget &,
                                              const EcObjectRef &,
                                              const Uuid &,
                                              const EcOwner &);

 private:
  friend class EcFileMutationCatalog;
  friend class EcFileAppendCatalog;
  friend class EcFileTruncateCatalog;
  friend class EcFileRepairCatalog;
  friend class EcFileTreeReadCatalog;
  static CoTryTask<EcFileSessionRecord> require(EcFileTreeTxnBudget &,
                                                const EcObjectRef &,
                                                const Uuid &,
                                                const EcOwner &,
                                                uint8_t rights,
                                                bool allowClosing);
  static CoTryTask<Void> retainReadRange(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &, const EcOwner &);
  static CoTryTask<Void> releaseReadRange(EcFileTreeTxnBudget &, const EcObjectRef &, const Uuid &, const EcOwner &);
  static CoTryTask<Void> retainStructural(EcFileTreeTxnBudget &,
                                          const EcObjectRef &,
                                          const Uuid &,
                                          const EcOwner &,
                                          const Uuid &operation);
  static CoTryTask<Void> releaseStructural(EcFileTreeTxnBudget &,
                                           const EcObjectRef &,
                                           const Uuid &,
                                           const EcOwner &,
                                           const Uuid &operation);
};
}  // namespace hf3fs::meta::server
