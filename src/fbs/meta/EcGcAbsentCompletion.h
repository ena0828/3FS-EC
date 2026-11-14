#pragma once

#include "fbs/meta/EcV2Gc.h"
#include "fbs/storage/EcGcAbsentControl.h"

namespace hf3fs::meta {
// Separate permanent proof: never decode this as old ECGD/Collected. Query may
// save the first authenticated observation of an existing Storage ledger, but
// cannot create the original claim, local fence or Storage absence fact.
struct EcGcAbsentCompletion {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(claimDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(closureDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(request, storage::EcGcAbsentRequest{});
  SERDE_STRUCT_FIELD(ack, storage::EcGcAbsentAck{});
};
}  // namespace hf3fs::meta
