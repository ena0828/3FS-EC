#pragma once

#include "fbs/meta/EcV2Repair.h"
#include "meta/store/EcV2PublishedCatalog.h"
#include "storage/ec_repair/EcRepairPlan.h"

namespace hf3fs::meta::server {
// Borrowed, transaction-consistent database records. This is not an RPC input
// or an authorization credential. Historical content may belong to a previous
// writer; healthy fragments retain their own original writer and operation.
struct EcV2RepairSnapshot {
  const EcOperationRecord &operation;
  const EcV2Reservation &reservation;
  const EcV2OperationBinding &binding;
  const EcManifest &base;
  const EcV2AllocationBindings &baseAllocations;
  const EcV2PublishedContent &content;
};

class EcV2RepairPlanCatalog {
 public:
  using Transaction = kv::IReadWriteTransaction;
  // Pure consistency checking and reconstruction; no authentication or signing.
  static Result<EcV2RepairPlanRecord> build(const EcV2RepairSnapshot &, const EcV2RepairSelection &);
  static Result<std::shared_ptr<const storage::EcRepairPlan>> validate(const EcV2RepairPlanRecord &);

  // The caller authenticates UID and checks WRITE, inode incarnation/flags and
  // current epoch first, in this same transaction. This method re-reads all
  // durable bindings, retains the implicit base pin, saves/replays ECRP, and
  // performs a genuine ECVI increment even on an identical renewal. It does
  // not commit. Discard a failed transaction; sign only after commit succeeds.
  static CoTryTask<EcV2RepairPlanRecord> prepare(Transaction &,
                                                 const EcObjectRef &,
                                                 const Uuid &operation,
                                                 const EcOwner &authenticatedOwner,
                                                 const EcV2RepairSelection &);
};
}  // namespace hf3fs::meta::server
