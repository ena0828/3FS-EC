#pragma once
#include "EcFileSessionCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "fbs/meta/EcFileRepair.h"
#include "storage/ec_repair/EcRepairPlan.h"

namespace hf3fs::meta::server {
class EcRmwPublicationProof;
class EcFileRepairCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  static CoTryTask<EcFileRepairRecord> begin(Tx &, const EcFileRepairIntent &);
  static CoTryTask<std::optional<EcFileRepairRecord>> query(Tx &,
                                                            const EcOwner &,
                                                            const EcObjectRef &,
                                                            const Uuid &operation);
  static CoTryTask<EcFileRepairRecord> abort(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &operation);
  static CoTryTask<EcFileRepairRecord> publish(Tx &,
                                               const EcOwner &,
                                               const EcObjectRef &,
                                               const Uuid &operation,
                                               const EcRmwPublicationProof &);
  static CoTryTask<EcFileChildRecord> executionChild(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &child);
  static CoTryTask<Void> requireExecutable(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &child);
  static CoTryTask<Void> fenceExecution(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &child);
  static CoTryTask<EcFileRepairRecord> byChild(Tx &, const EcOwner &, const EcObjectRef &, const Uuid &child);
  // Complete authorized operation set, including selected healthy helpers.
  // Source metadata protection still includes all twelve original fragments
  // in its independent exact pin; unreachable originals are not fake-ACKed.
  static CoTryTask<Void> addHelperEndpoints(Tx &, const EcFileChildRecord &, EcV2OperationEndpoints &);
  static CoTryTask<std::shared_ptr<const storage::EcRepairPlan>> repairPlan(Tx &,
                                                                            const EcOwner &,
                                                                            const EcObjectRef &,
                                                                            const Uuid &child);
};
}  // namespace hf3fs::meta::server
