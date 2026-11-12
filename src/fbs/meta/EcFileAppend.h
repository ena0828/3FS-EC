#pragma once
#include "fbs/meta/EcFileMutation.h"

namespace hf3fs::meta {
struct EcFileAppendIntent {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(inputSha256, storage::EcSha256{});
};
struct EcFileAppendRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(intent, EcFileAppendIntent{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(acceptedRoot, EcTreeRoot{});
  SERDE_STRUCT_FIELD(parent, EcFileMutationRecord{});
};
struct EcFileAppendGate {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(active, false);
};
// A barrier is a fixed historical receipt, not a live promise about future
// writes. Contract 1 requires all production Data installation to consume the
// actual twelve durable Seal receipts and publication proof before FDB commit.
struct EcFileSyncIntent {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
};
struct EcFileSyncRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(intent, EcFileSyncIntent{});
  SERDE_STRUCT_FIELD(durabilityContract, uint16_t{1});
  SERDE_STRUCT_FIELD(sessionSequence, uint64_t{});
  SERDE_STRUCT_FIELD(root, EcTreeRoot{});
};
inline Result<Void> validateEcAppend(const EcFileAppendIntent &i) {
  if (i.version != 1 || i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() ||
      i.object.inode > InodeId::normalMax() || i.owner.client.is_nil() || i.session.is_nil() || i.operation.is_nil() ||
      i.request.is_nil() || i.operation == i.request || !i.length || i.length > kEcPwriteMaxBytes ||
      i.inputSha256 == storage::EcSha256{})
    return makeError(StatusCode::kInvalidArg, "invalid fixed append intent");
  return Void{};
}
inline Result<Void> validateEcSync(const EcFileSyncIntent &i) {
  if (i.version != 1 || i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() ||
      i.object.inode > InodeId::normalMax() || i.owner.client.is_nil() || i.session.is_nil() || i.request.is_nil())
    return makeError(StatusCode::kInvalidArg);
  return Void{};
}
}  // namespace hf3fs::meta
