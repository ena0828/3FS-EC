#pragma once

#include "fbs/meta/Ec.h"
#include "fbs/storage/EcRmwRpc.h"

namespace hf3fs::meta {
// Dedicated trusted worker exchange, not an ordinary authenticated-user write
// request. The Meta52 handler requires configured independent RMW key and both
// live Execute grant + computed-result MAC against its permanent mode4 record.
struct BindEcRmwOutputReq {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(execution, storage::EcRmwGrant{});
  SERDE_STRUCT_FIELD(computed, storage::EcRmwComputedCommitment{});
};
struct BindEcRmwOutputRsp {
  SERDE_STRUCT_FIELD(planDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(writes, (std::array<storage::EcCapabilityV2, 12>{}));
};
}  // namespace hf3fs::meta
