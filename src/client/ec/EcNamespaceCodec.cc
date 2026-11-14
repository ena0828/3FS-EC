#include "EcNamespaceJournal.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> bad() { return makeError(StatusCode::kInvalidFormat, "namespace unlink identity or progress changed"); }
template <class T>
Result<std::string> encode(const T &v, std::string_view tag) {
  try {
    auto bytes = serde::serialize(v);
    if (bytes.size() > 150u * 1024) return makeError(bad().error());
    return std::string(tag) + bytes;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
template <class T>
Result<T> decode(std::string_view bytes, std::string_view tag) {
  try {
    if (!bytes.starts_with(tag) || bytes.size() > 160u * 1024) return makeError(bad().error());
    bytes.remove_prefix(tag.size());
    T value;
    RETURN_ON_ERROR(serde::deserialize(value, bytes));
    if (serde::serialize(value) != bytes) return makeError(bad().error());
    return value;
  } catch (...) {
    return makeError(bad().error());
  }
}
}  // namespace
Result<Void> EcNamespaceRun::validate() const {
  const auto &i = session.intent;
  if (version != 1 || cluster.empty() || cluster.size() > 256 || cluster.find('\0') != std::string::npos ||
      session.version != 1 || i.version != 1 || i.object.inode.isTreeRoot() ||
      i.object.inode > meta::InodeId::normalMax() || i.object.incarnation.is_nil() ||
      i.birth.is_nil() || i.owner.client.is_nil() || i.session.is_nil() || i.openRequest.is_nil() ||
      !i.rights || (i.rights & ~uint8_t{3}) || request.is_nil() || request == i.openRequest || request == i.session ||
      (session.state != meta::EcFileSessionState::Open && session.state != meta::EcFileSessionState::Closed) ||
      (session.state == meta::EcFileSessionState::Closed &&
       (!session.activeParent.is_nil() || session.activeReadRanges || !session.activeStructural.is_nil())) ||
      path.empty() || path.size() > 4096 || path.find('\0') != std::string::npos)
    return bad();
  const std::filesystem::path name(path);
  if (!name.is_absolute() || name == name.root_path() || name.filename().empty() ||
      name.lexically_normal().string() != path)
    return bad();
  for (const auto &part : name)
    if (part == "." || part == "..") return bad();
  return Void{};
}
Result<Void> EcNamespaceJournalState::validate(const EcNamespaceRun &r,
                                               const EcNamespaceJournalState *old) const {
  RETURN_ON_ERROR(r.validate());
  if (version != 1 || sequence >= 4096 || (acknowledged && !issued) ||
      (!old && sequence != 0) ||
      (old && (sequence != old->sequence + 1 || (old->issued && !issued) ||
               (old->acknowledged && !acknowledged))))
    return bad();
  return Void{};
}
Result<EcNamespaceRun> prepareEcUnlink(const EcFilePwriteJournal &session, std::string path) {
  RETURN_ON_ERROR(session.record().validate());
  if (session.poisoned() || session.record().kind != EcPwriteRunKind::Session || !session.latest() ||
      !session.latest()->issued || !session.latest()->session)
    return makeError(StatusCode::kInvalidArg, "unlink needs a durably accepted original session");
  RETURN_ON_ERROR(session.latest()->validate(session.record()));
  EcNamespaceRun r;
  r.cluster = session.record().cluster;
  r.session = *session.latest()->session;
  r.path = std::move(path);
  r.request = Uuid::random();
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcNamespaceRun(const EcNamespaceRun &r) {
  RETURN_ON_ERROR(r.validate());
  return encode(r, "ECUNLINK1\n");
}
Result<EcNamespaceRun> decodeEcNamespaceRun(std::string_view bytes) {
  CHECK_RESULT(r, decode<EcNamespaceRun>(bytes, "ECUNLINK1\n"));
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcNamespaceState(const EcNamespaceJournalState &s) { return encode(s, "ECUNLINKSTATE1\n"); }
Result<EcNamespaceJournalState> decodeEcNamespaceState(std::string_view bytes) {
  return decode<EcNamespaceJournalState>(bytes, "ECUNLINKSTATE1\n");
}
}  // namespace hf3fs::client::ec
