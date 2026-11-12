#pragma once

#include "EcFileTreeKeys.h"
#include "fbs/meta/EcFileMutation.h"

namespace hf3fs::meta::server::ec_file_mutation_detail {
using namespace ec_tree_detail;
inline Result<Void> owner(const EcOwner &stored, const EcOwner &actual) {
  if (actual.client.is_nil()) return makeError(StatusCode::kInvalidArg, "zero file-session namespace");
  if (!same(stored, actual)) return makeError(MetaCode::kNoPermission, "file session belongs to another owner");
  return Void{};
}
inline Result<Void> valid(const EcFileOpenIntent &i) {
  if (i.version != kEcFileMutationVersion || i.object.incarnation.is_nil() || i.birth.is_nil() ||
      i.owner.client.is_nil() || i.session.is_nil() || i.openRequest.is_nil() || !i.rights ||
      (i.rights & ~(kEcSessionRead | kEcSessionWrite)))
    return makeError(StatusCode::kInvalidArg, "invalid fixed file-session intent");
  return Void{};
}
inline Result<Void> valid(const EcFilePwriteIntent &i) {
  if (i.version != kEcFileMutationVersion || i.object.incarnation.is_nil() || i.owner.client.is_nil() ||
      i.session.is_nil() || i.request.is_nil() || i.length > kEcPwriteMaxBytes || i.inputSha256 == storage::EcSha256{})
    return makeError(StatusCode::kInvalidArg, "invalid fixed pwrite intent");
  RETURN_ON_ERROR(rangeEnd(i.offset, i.length));
  return Void{};
}
inline Result<Void> valid(const EcFileSessionRecord &r) {
  RETURN_ON_ERROR(valid(r.intent));
  if (r.version != kEcFileMutationVersion ||
      (r.state != EcFileSessionState::Open && r.state != EcFileSessionState::Closing &&
       r.state != EcFileSessionState::Closed) ||
      (r.state == EcFileSessionState::Closed &&
       (!r.activeParent.is_nil() || r.activeReadRanges || !r.activeStructural.is_nil())))
    return makeError(StatusCode::kDataCorruption, "invalid file-session state");
  return Void{};
}
inline Result<Void> valid(const EcFileMutationRecord &r) {
  RETURN_ON_ERROR(valid(r.intent));
  if (r.version != kEcFileMutationVersion || !r.sessionSequence || !r.epoch || r.confirmedPrefix > r.intent.length ||
      (r.state != EcFileMutationState::Open && r.state != EcFileMutationState::ClosedLogical) ||
      (r.state == EcFileMutationState::ClosedLogical && !r.activeChild.is_nil()) ||
      (r.state == EcFileMutationState::Open && !r.fencedChild.is_nil()))
    return makeError(StatusCode::kDataCorruption, "invalid pwrite progress");
  return Void{};
}
}  // namespace hf3fs::meta::server::ec_file_mutation_detail
