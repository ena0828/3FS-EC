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
}  // namespace hf3fs::meta
