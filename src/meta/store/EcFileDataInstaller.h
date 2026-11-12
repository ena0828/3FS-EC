#pragma once

#include "EcFileExecutionCatalog.h"
#include "meta/components/EcRmwPublicationProof.h"

namespace hf3fs::meta::server {
class EcFileTruncateCatalog;
class EcFileDataInstaller final {
 public:
  // Internal transaction primitive. The only accepted data authority is the
  // private actual-W1-verifier proof, never a MAC, receipt or caller callback.
  // The caller must commit this transaction before reporting written bytes.
  static CoTryTask<EcFileMutationRecord> publishPwrite(EcFileTreeTxnBudget &,
                                                       const EcOwner &,
                                                       const EcRmwPublicationProof &);

 private:
  friend class EcFileTruncateCatalog;
  friend class EcFileRepairCatalog;
  // Only the three closed publication functions may pass a factory-created
  // validation. Each must activate the manifest and consume the validation
  // after its typed Published result in this same transaction attempt.
  static CoTryTask<EcTreeSlot> installValidated(EcFileTreeTxnBudget &,
                                                const EcFileExecutionCatalog::PublicationValidation &);
};
}  // namespace hf3fs::meta::server
