#include <algorithm>
#include <folly/json.h>
#include <limits>
#include <set>

#include "EcFilePwriteJournal.h"
#include "detail/EcFileValidation.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> bad() { return makeError(StatusCode::kInvalidFormat, "invalid fixed pwrite run"); }
bool text(const std::string &s, size_t max) { return s.size() <= max && s.find('\0') == std::string::npos; }
bool validObject(const meta::EcObjectRef &o) {
  return !o.incarnation.is_nil() && !o.inode.isTreeRoot() && o.inode <= meta::InodeId::normalMax();
}
uint64_t mask(size_t n) { return n == 64 ? ~uint64_t{} : ((uint64_t{1} << n) - 1); }
std::string hex(std::string_view s) {
  static constexpr char d[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 * s.size());
  for (unsigned char c : s) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 15]);
  }
  return out;
}
Result<std::string> unhex(std::string_view s) {
  if (s.size() % 2 || s.size() > 240u * 1024) return makeError(bad().error());
  std::string out(s.size() / 2, '\0');
  auto n = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
  for (size_t i = 0; i < out.size(); ++i) {
    int a = n(s[2 * i]), b = n(s[2 * i + 1]);
    if (a < 0 || b < 0) return makeError(bad().error());
    out[i] = char(a * 16 + b);
  }
  return out;
}
template <class T>
Result<T> decode(std::string_view s, std::string_view kind) {
  try {
    if (s.size() > 256u * 1024) return makeError(bad().error());
    auto j = folly::parseJson(s);
    if (!j.isObject() || j.size() != 3 || !j["schema"].isInt() || j["schema"] != 1 || j["kind"] != std::string(kind) ||
        !j["body_hex"].isString())
      return makeError(bad().error());
    CHECK_RESULT(bytes, unhex(j["body_hex"].getString()));
    T value;
    RETURN_ON_ERROR(serde::deserialize(value, bytes));
    if (serde::serialize(value) != bytes) return makeError(bad().error());
    return value;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(bad().error());
  }
}
template <class T>
Result<std::string> encode(const T &v, const char *kind) {
  try {
    auto bytes = serde::serialize(v);
    if (bytes.size() > 120u * 1024) return makeError(bad().error());
    folly::dynamic j = folly::dynamic::object("schema", 1)("kind", kind)("body_hex", hex(bytes));
    return folly::toJson(j);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
}  // namespace
Result<Void> EcPwriteRunRecord::validate() const {
  if (version != 1 || cluster.empty() || !text(cluster, 256) || owner.client.is_nil() || session.is_nil() ||
      openRequest.is_nil() || closeRequest.is_nil() || !shardBytes || shardBytes > (1u << 20) || !rights ||
      (rights & ~(meta::kEcSessionRead | meta::kEcSessionWrite)) || (permission & ~07777u))
    return bad();
  if (kind == EcPwriteRunKind::Session) {
    if (createNew ? (path.empty() || path.front() != '/' || !text(path, 4096) || !object.incarnation.is_nil() ||
                     !birth.is_nil())
                  : (!path.empty() || !validObject(object) || birth.is_nil()))
      return bad();
    if (count || length || offset || !operation.is_nil() || !inputPath.empty()) return bad();
    for (const auto &c : children)
      if (serde::serialize(c) != serde::serialize(EcPwriteChildIds{})) return bad();
    return Void{};
  }
  if ((kind != EcPwriteRunKind::Write && kind != EcPwriteRunKind::AcceptedAppend) || createNew || !path.empty() ||
      !validObject(object) || birth.is_nil() || !(rights & meta::kEcSessionWrite) || operation.is_nil() ||
      beginRequest.is_nil() || queryRequest.is_nil() || sealRequest.is_nil() || !length ||
      length > meta::kEcPwriteMaxBytes || offset > UINT64_MAX - length || !text(inputPath, 4096) ||
      !std::filesystem::path(inputPath).is_absolute() || !count || count > children.size())
    return bad();
  const uint64_t width = uint64_t(shardBytes) * 10;
  if ((offset % width + length + width - 1) / width != count) return bad();
  std::set<Uuid> unique;
  auto id = [&](Uuid u) { return !u.is_nil() && unique.insert(u).second; };
  if (!id(operation) || !id(beginRequest) || !id(queryRequest) || !id(sealRequest)) return bad();
  uint64_t prefix = 0;
  for (size_t i = 0; i < children.size(); ++i) {
    const auto &c = children[i];
    if (i >= count) {
      if (serde::serialize(c) != serde::serialize(EcPwriteChildIds{})) return bad();
      continue;
    }
    const auto &p = c.intent;
    if (p.version != 1 || p.object != object || p.parent != operation || p.expectedPrefix != prefix || !id(p.child) ||
        !id(p.plan) || !id(p.sourcePin) || !id(c.query) || !id(c.planRequest) || !id(c.publish) || !id(c.cleanup) ||
        !id(c.outputRevocation) || !id(c.sourceRevocation))
      return bad();
    for (const auto &n : p.nodeIds)
      if (!id(n)) return bad();
    prefix += std::min(length - prefix, width - (offset + prefix) % width);
  }
  return prefix == length ? Result<Void>(Void{}) : bad();
}
Result<Void> EcPwriteRunProgress::validate(const EcPwriteRunRecord &r, const EcPwriteRunProgress *old) const {
  if (version != 1 || sequence >= 4096 ||
      (old && (sequence != old->sequence + 1 || (old->issued && !issued) ||
               (cleanedMask & old->cleanedMask) != old->cleanedMask)))
    return bad();
  if (cleanedMask & ~mask(r.count)) return bad();
  if (session) {
    const auto &s = *session;
    const auto &i = s.intent;
    if (s.version != 1 || i.version != 1 || i.owner.uid != r.owner.uid || i.owner.client != r.owner.client ||
        i.session != r.session || i.openRequest != r.openRequest || i.rights != r.rights || !validObject(i.object) ||
        i.birth.is_nil() || (!r.createNew && (i.object != r.object || i.birth != r.birth)) || !shardBytes ||
        shardBytes > (1u << 20) ||
        (s.state != meta::EcFileSessionState::Open && s.state != meta::EcFileSessionState::Closing &&
         s.state != meta::EcFileSessionState::Closed))
      return bad();
    if (old && old->session &&
        (serde::serialize(old->session->intent) != serde::serialize(i) || old->shardBytes != shardBytes ||
         uint8_t(s.state) < uint8_t(old->session->state)))
      return bad();
  } else if (shardBytes || (old && old->session))
    return bad();
  if (root && (!session || root->version != 1 || root->object != session->intent.object ||
               root->birth != session->intent.birth || !root->sequence || !root->epoch))
    return bad();
  if (parent) {
    const auto &p = *parent;
    const auto &i = p.intent;
    if ((r.kind != EcPwriteRunKind::Write && r.kind != EcPwriteRunKind::AcceptedAppend) || p.version != 1 ||
        i.version != 1 || i.object != r.object || i.owner.uid != r.owner.uid || i.owner.client != r.owner.client ||
        i.session != r.session || i.request != r.operation || i.offset != r.offset || i.length != r.length ||
        i.inputSha256 != r.inputSha256 || !p.sessionSequence || !p.epoch || p.confirmedPrefix > r.length ||
        (p.state != meta::EcFileMutationState::Open && p.state != meta::EcFileMutationState::ClosedLogical))
      return bad();
    if (old && old->parent &&
        (p.confirmedPrefix < old->parent->confirmedPrefix || p.epoch != old->parent->epoch ||
         p.sessionSequence != old->parent->sessionSequence || uint8_t(p.state) < uint8_t(old->parent->state)))
      return bad();
    bool boundary = p.confirmedPrefix == 0 || p.confirmedPrefix == r.length;
    bool knownActive = p.activeChild.is_nil(), knownFenced = p.fencedChild.is_nil();
    uint64_t end = 0;
    for (size_t n = 0; n < r.count; ++n) {
      const auto &c = r.children[n];
      boundary = boundary || p.confirmedPrefix == c.intent.expectedPrefix;
      knownActive = knownActive || p.activeChild == c.intent.child;
      knownFenced = knownFenced || p.fencedChild == c.intent.child;
      end = (n + 1 < r.count) ? r.children[n + 1].intent.expectedPrefix : r.length;
      if ((cleanedMask & (uint64_t{1} << n)) && p.confirmedPrefix < end &&
          p.state != meta::EcFileMutationState::ClosedLogical)
        return bad();
    }
    if (!boundary || !knownActive || !knownFenced) return bad();
  } else if (cleanedMask || (old && old->parent))
    return bad();
  return Void{};
}
Result<std::string> encodeEcPwriteRunRecord(const EcPwriteRunRecord &v) {
  RETURN_ON_ERROR(v.validate());
  return encode(v, "mode4-pwrite-record");
}
Result<EcPwriteRunRecord> decodeEcPwriteRunRecord(std::string_view s) {
  CHECK_RESULT(v, decode<EcPwriteRunRecord>(s, "mode4-pwrite-record"));
  RETURN_ON_ERROR(v.validate());
  return v;
}
Result<std::string> encodeEcPwriteRunProgress(const EcPwriteRunProgress &v) {
  return encode(v, "mode4-pwrite-observation");
}
Result<EcPwriteRunProgress> decodeEcPwriteRunProgress(std::string_view s) {
  return decode<EcPwriteRunProgress>(s, "mode4-pwrite-observation");
}
Result<EcPwriteRunRecord> prepareEcPwriteSession(meta::EcOwner owner,
                                                 std::string cluster,
                                                 bool createNew,
                                                 std::string path,
                                                 meta::EcObjectRef object,
                                                 Uuid birth,
                                                 uint32_t shardBytes,
                                                 uint8_t rights,
                                                 uint32_t permission) {
  EcPwriteRunRecord r;
  r.owner = owner;
  r.cluster = std::move(cluster);
  r.createNew = createNew;
  r.path = std::move(path);
  r.object = object;
  r.birth = birth;
  r.shardBytes = shardBytes;
  r.rights = rights;
  r.permission = permission;
  r.session = Uuid::random();
  r.openRequest = Uuid::random();
  r.closeRequest = Uuid::random();
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<EcPwriteRunRecord> prepareEcPwrite(const EcFilePwriteJournal &session,
                                          uint64_t offset,
                                          std::string inputPath,
                                          std::span<const uint8_t> input) {
  if (session.poisoned() || session.record().kind != EcPwriteRunKind::Session || !session.latest() ||
      !session.latest()->session || session.latest()->session->state != meta::EcFileSessionState::Open ||
      input.empty() || input.size() > meta::kEcPwriteMaxBytes || offset > UINT64_MAX - input.size())
    return makeError(StatusCode::kInvalidArg);
  auto r = session.record();
  r.kind = EcPwriteRunKind::Write;
  r.createNew = false;
  r.path.clear();
  r.object = session.latest()->session->intent.object;
  r.birth = session.latest()->session->intent.birth;
  r.shardBytes = session.latest()->shardBytes;
  r.offset = offset;
  r.length = input.size();
  r.inputPath = std::move(inputPath);
  const uint64_t width = uint64_t(r.shardBytes) * 10;
  const auto count = (offset % width + input.size() + width - 1) / width;
  if (count > kEcPwriteClientMaxChildren)
    return makeError(StatusCode::kInvalidArg, "pwrite exceeds 64 fixed child plans");
  r.count = uint16_t(count);
  r.operation = Uuid::random();
  r.beginRequest = Uuid::random();
  r.queryRequest = Uuid::random();
  r.sealRequest = Uuid::random();
  CHECK_RESULT(sha, detail::fileContentSha(input));
  r.inputSha256 = sha;
  uint64_t prefix = 0;
  for (size_t n = 0; n < r.count; ++n) {
    auto &c = r.children[n];
    auto &p = c.intent;
    p.object = r.object;
    p.parent = r.operation;
    p.child = Uuid::random();
    p.plan = Uuid::random();
    p.sourcePin = Uuid::random();
    p.expectedPrefix = prefix;
    for (auto &id : p.nodeIds) id = Uuid::random();
    const auto size = std::min(r.length - prefix, width - (r.offset + prefix) % width);
    CHECK_RESULT(part, detail::fileContentSha(input.subspan(prefix, size)));
    p.patchSha256 = part;
    c.query = Uuid::random();
    c.planRequest = Uuid::random();
    c.publish = Uuid::random();
    c.cleanup = Uuid::random();
    c.outputRevocation = Uuid::random();
    c.sourceRevocation = Uuid::random();
    prefix += size;
  }
  RETURN_ON_ERROR(r.validate());
  return r;
}
}  // namespace hf3fs::client::ec
