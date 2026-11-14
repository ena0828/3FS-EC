#pragma once

#include "fbs/meta/EcGcAbsentCompletion.h"
#include "meta/store/EcTreeGcCatalog.h"

namespace hf3fs::meta::server {
class EcGcAbsentCompletionCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  static Result<storage::EcGcLocalClosureWitness> project(const EcGcBoundClosure &);
  static CoTryTask<std::optional<EcGcAbsentCompletion>> get(Transaction &, const EcObjectRef &,
      const storage::EcFragmentIdentity &, const Uuid &claimId, const storage::EcScopeControlKey &,
      const storage::EcGcKey &, const Uuid &authority);
  static CoTryTask<EcGcAbsentCompletion> record(Transaction &, const EcObjectRef &,
      const storage::EcFragmentIdentity &, const Uuid &claimId, const storage::EcGcAbsentRequest &,
      const storage::EcGcAbsentAck &, const storage::EcScopeControlKey &, const storage::EcGcKey &,
      const Uuid &authority);
};
}  // namespace hf3fs::meta::server
