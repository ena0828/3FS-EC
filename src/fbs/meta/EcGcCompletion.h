#pragma once

#include "fbs/meta/EcV2Gc.h"
#include "fbs/storage/EcGcControl.h"

namespace hf3fs::meta {
// Presence means that the exact Storage ledger receipt was authenticated and
// this record committed. Absence never means that Collect did not execute.
// Keep the first complete exchange permanently; later Query replies may use a
// different nonce, time or bootNonce while confirming the same ledger fact.
struct EcGcCompletion {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(claimDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(request, storage::EcGcRequest{});
  SERDE_STRUCT_FIELD(ack, storage::EcGcAck{});
};
// A host-fenced allocation remains on its retired medium. This independent
// disposition binds its original permanent claim to the verified host fence.
struct EcGcRetainedDisposition {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(claimDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(endpoint, EcV2PhysicalEndpoint{});
  SERDE_STRUCT_FIELD(retirementId, Uuid::zero());
  SERDE_STRUCT_FIELD(fenceCompletionDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(fenceProofDigest, storage::EcSha256{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(identity.validate());
    if (version != 1 || !object.inode.u64() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        object.incarnation != identity.object || identity.shard >= 12 || claimId.is_nil() || retirementId.is_nil() ||
        endpoint.placement.node == flat::NodeId{} || endpoint.placement.chain == storage::ChainId{} ||
        endpoint.placement.target == storage::TargetId{} || endpoint.engineUuid.is_nil() || endpoint.targetIncarnation.is_nil() ||
        claimDigest == storage::EcSha256{} || fenceCompletionDigest == storage::EcSha256{} ||
        fenceProofDigest == storage::EcSha256{})
      return makeError(StatusCode::kDataCorruption, "invalid retained allocation disposition");
    return Void{};
  }
};
}  // namespace hf3fs::meta
