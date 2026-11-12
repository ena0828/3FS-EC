#pragma once

#include "EcFileSessionCatalog.h"
#include "fbs/meta/EcFileTruncate.h"

namespace hf3fs::meta::server {
class EcRmwPublicationProof;
class EcFileTruncateCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  // Internal authenticated-service primitives. No method commits or retries;
  // actual UID/namespace authentication belongs to the owning coordinator.
  static CoTryTask<EcFileTruncateRecord> begin(Tx &, const EcFileTruncateIntent &);
  static CoTryTask<std::optional<EcFileTruncateRecord>> query(Tx &,
                                                              const EcOwner &,
                                                              const EcObjectRef &,
                                                              const Uuid &operation);
  static CoTryTask<EcFileTruncateRecord> publishWithoutTail(Tx &,
                                                            const EcOwner &,
                                                            const EcObjectRef &,
                                                            const Uuid &operation);
  static CoTryTask<EcFileTruncateRecord> publishDataTail(Tx &,
                                                         const EcOwner &,
                                                         const EcObjectRef &,
                                                         const Uuid &operation,
                                                         const EcRmwPublicationProof &);
  static CoTryTask<EcFileTruncateRecord> abort(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &operation);
  // Normal conflict read, required before each NEW pwrite begin/child/issue
  // and publication. Query and debt cleanup must not use this admission gate.
  static CoTryTask<Void> requireMutationOpen(Tx &, const EcObjectRef &);
  // Fixed internal W1/W2 adapter, not a caller-supplied polymorphic callback.
  static CoTryTask<EcFileChildRecord> executionChild(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &childId);
  static CoTryTask<Void> requireExecutable(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &childId);
  static CoTryTask<Void> fenceExecution(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &childId);

 private:
  static CoTryTask<EcFileTruncateRecord> finish(Tx &, EcFileTruncateRecord, const std::optional<EcTreeSlot> &);
};
}  // namespace hf3fs::meta::server
