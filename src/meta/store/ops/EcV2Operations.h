#pragma once

#include "fbs/meta/Service.h"
#include "meta/store/EcV2DrainCatalog.h"
#include "meta/store/MetaStore.h"

namespace hf3fs::meta::server {
class EcV2Coordinator;
enum class EcV2Phase {
  PrepareRepair,
  Begin,
  Bind,
  Get,
  PreparePublish,
  StartPublish,
  StartCancel,
  RecordAck,
  RecordRetirement,
  FinishPublish,
  FinishCancel,
  AcquireRead,
  StartRelease,
  FinishRelease
};
// These fields are server-internal and never part of ReqBase's wire schema.
struct EcV2PhaseRequest : EcOperationReq {
  EcV2Phase phase = EcV2Phase::Get;
  storage::EcGrantScope scopeKind = storage::EcGrantScope::WriteOperation;
  BeginEcMutationV2Req begin;
  EcV2RepairSelection repairSelection;
  std::array<storage::EcIntegrityDescriptor, 12> descriptors{};
  uint64_t stripe = 0;
  size_t retirementIndex = 0;
  Uuid revocation = Uuid::random();
  const EcV2Coordinator *coordinator = nullptr;
  std::shared_ptr<const EcV2PublishEvidence> publication;
  std::shared_ptr<const EcVerifiedDrainAck> observation;
};
// Serializable for the generic OperationDriver template; never a public RPC.
struct EcV2PhaseRsp {
  SERDE_STRUCT_FIELD(mutation, EcV2MutationRsp{});
  SERDE_STRUCT_FIELD(repair, (std::optional<EcV2RepairPlanRecord>{}));
  SERDE_STRUCT_FIELD(read, (std::optional<AcquireEcReadV2Rsp>{}));
  SERDE_STRUCT_FIELD(drain, (std::optional<EcV2DrainRecord>{}));
};
MetaStore::OpPtr<CreateEcFileRsp> makeCreateEcV2Op(MetaStore &, const CreateEcFileV2Req &);
MetaStore::OpPtr<EcV2PhaseRsp> makeEcV2PhaseOp(MetaStore &, const EcV2PhaseRequest &);
}  // namespace hf3fs::meta::server
