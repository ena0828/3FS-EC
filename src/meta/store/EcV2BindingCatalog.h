#pragma once

#include "fbs/meta/EcV2.h"
#include "meta/store/EcCatalog.h"

namespace hf3fs::meta::server {

// Internal transaction primitives; no commits, retry loop, networking, Storage
// or Meta RPCs. The caller authenticates the owner and inode WRITE/READ rights,
// and supplies trusted registered physical instances before starting the txn.
// On every failure discard/reset the transaction, including acquireRead after
// it has tentatively changed the legacy pin count. Unknown commit is retried
// with the same operation/pin and full bindings, never a new instance snapshot.
//
// This is not a public V2 service. Before exposure, ECVM object mode must be
// created atomically with a new V2 object, all legacy EC entrypoints must reject
// that mode, and V2 publish/cancel must revoke and drain the full operation set
// before calling EcCatalog::publish/cancel (which release the repair base pin).
// A twelve-endpoint read-pin snapshot is not a repair-operation drain set.
class EcV2BindingCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  // Atomic new object+mode creation only. Existing unmarked objects are never
  // upgraded, including empty ones. The namespace layer adds inode/entry/create
  // idempotency records in this same caller-owned transaction.
  static CoTryTask<EcObjectRecord> createV2Object(Transaction &,
                                                  const EcObjectRef &,
                                                  uint32_t shardBytes,
                                                  bool allowColocated,
                                                  const EcOwner &creator,
                                                  const Uuid &createRequest);
  // Fresh public V2 files use mode 3 and enroll protection history atomically.
  // Existing mode-2 objects are returned unchanged on an exact create retry.
  // createV2Object above deliberately remains the low-level mode-2 constructor.
  static CoTryTask<EcObjectRecord> createTrackedV2Object(Transaction &,
                                                         const EcObjectRef &,
                                                         uint32_t shardBytes,
                                                         bool allowColocated,
                                                         const EcOwner &,
                                                         const Uuid &createRequest);
  static CoTryTask<std::optional<EcV2ObjectMode>> getObjectMode(Transaction &, const EcObjectRef &);
  static CoTryTask<EcV2ObjectMode> requireV2Mode(Transaction &, const EcObjectRef &);
  static CoTryTask<EcV2OperationBinding> bindPreparing(Transaction &,
                                                       const EcOperationRecord &expected,
                                                       const EcOwner &authenticatedOwner,
                                                       const EcV2AllocationBindings &);
  static CoTryTask<EcV2OperationBinding> getOperationBinding(Transaction &,
                                                             const EcObjectRef &,
                                                             const Uuid &operation,
                                                             const EcOwner &authenticatedOwner);
  static CoTryTask<EcV2AllocationBinding> getAllocationBinding(Transaction &, const storage::EcFragmentIdentity &);
  static CoTryTask<EcV2PinnedRead> acquireRead(Transaction &,
                                               const EcObjectRef &,
                                               uint64_t stripe,
                                               const Uuid &pin,
                                               const EcOwner &authenticatedOwner);
  static CoTryTask<EcV2PinSnapshot> getPinSnapshot(Transaction &,
                                                   const EcObjectRef &,
                                                   const Uuid &pin,
                                                   const EcOwner &authenticatedOwner);

 private:
  static CoTryTask<EcObjectRecord>
  createObjectWithMode(Transaction &, const EcObjectRef &, uint32_t, bool, const EcOwner &, const Uuid &, bool tracked);
};
}  // namespace hf3fs::meta::server
