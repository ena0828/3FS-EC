#pragma once

#include "fbs/meta/EcGcCompletion.h"
#include "meta/store/EcV2GcCatalog.h"

namespace hf3fs::meta::server {
class EcGcCompletionCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;

  // Pure full-field projection; it has no signing or commit authority. The
  // versions express the required protocol, not discovered target support.
  static Result<storage::EcGcCertificate> project(const EcGcClaim &);

  // Both methods re-read the permanent claim. They verify the original request
  // and ACK signatures, authority, key, complete certificate and exact instance.
  // No current time invalidates an already observed irreversible confirmation.
  static CoTryTask<std::optional<EcGcCompletion>> get(Transaction &,
                                                      const EcObjectRef &,
                                                      const storage::EcFragmentIdentity &,
                                                      const Uuid &claimId,
                                                      const storage::EcGcKey &,
                                                      const Uuid &authority);
  static CoTryTask<EcGcCompletion> record(Transaction &,
                                          const EcObjectRef &,
                                          const storage::EcFragmentIdentity &,
                                          const Uuid &claimId,
                                          const storage::EcGcRequest &exactIssuedRequest,
                                          const storage::EcGcAck &,
                                          const storage::EcGcKey &,
                                          const Uuid &authority);
};
}  // namespace hf3fs::meta::server
