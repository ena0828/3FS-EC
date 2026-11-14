#pragma once

#include "fbs/meta/EcFileOutputResolution.h"
#include "meta/store/EcFileTreeTxnBudget.h"

namespace hf3fs::meta::server {
class EcFileOutputResolutionCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  // Caller authenticates root. Every read, negative allocation read, both
  // permanent writes and the checked commit share this budget transaction.
  static CoTryTask<EcFileOutputResolution> confirm(Tx &, const EcFileOutputIdentity &, const Uuid &resolutionId,
                                                  const Uuid &confirmingNamespace,
                                                  const storage::EcScopeControlKey &);
  // No issuance, Storage I/O, writes, commit or index repair. Revalidate both
  // original closures and both permanent indexes; caller namespace is not rebound.
  static CoTryTask<EcFileOutputResolution> query(Tx &, const EcFileOutputIdentity &, const Uuid &resolutionId,
                                                const storage::EcScopeControlKey &);
};
}  // namespace hf3fs::meta::server
