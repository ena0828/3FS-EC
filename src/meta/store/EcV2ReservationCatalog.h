#pragma once

#include "fbs/meta/EcV2Lifecycle.h"
#include "meta/store/EcV2BindingCatalog.h"

namespace hf3fs::meta::server {
// Internal transaction primitives. Caller authenticates Meta UID and current
// inode access first. No method commits or performs network I/O. Discard every
// failed transaction. The physical pool must come from trusted configuration,
// never from client request fields. Invoke reserve in the same txn as Begin.
class EcV2ReservationCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  using PhysicalPool = std::array<EcV2PhysicalEndpoint, 12>;
  static CoTryTask<EcV2Reservation> reserve(Transaction &,
                                            const EcOperationRecord &,
                                            const EcOwner &,
                                            const storage::EcSha256 &contentSha256,
                                            const PhysicalPool &trustedPool);
  static CoTryTask<EcV2Reservation> get(Transaction &, const EcObjectRef &, const Uuid &operation, const EcOwner &);
  static CoTryTask<EcV2OperationBinding> bind(Transaction &,
                                              const EcObjectRef &,
                                              const Uuid &operation,
                                              const EcOwner &,
                                              const std::array<storage::EcIntegrityDescriptor, 12> &);
  // Must invoke this in every grant-producing txn, including replay. It reads
  // ECVD and increments the separate ECVI sequence (with overflow rejection).
  // This is a genuine mutation; immutable reservation/pin contents never change.
  // Signing may occur after commit: a late token still names this fixed scope
  // and its fixed instances, so the irreversible deny covers it as well.
  static CoTryTask<Void> checkIssuanceOpen(Transaction &,
                                           const EcObjectRef &,
                                           storage::EcGrantScope,
                                           const Uuid &scopeId,
                                           const EcOwner &);
};
}  // namespace hf3fs::meta::server
