#include "EcAppendJournal.h"
#include "detail/EcFileValidation.h"

namespace hf3fs::client::ec {
namespace {
template <class T>
bool same(const T &a, const T &b) {
  return serde::serialize(a) == serde::serialize(b);
}
Result<Void> bad() { return makeError(StatusCode::kInvalidFormat, "append/sync journal identity or progress changed"); }
bool path(const std::string &p) {
  return !p.empty() && p.size() <= 4096 && p.find('\0') == std::string::npos && std::filesystem::path(p).is_absolute();
}
template <class T>
Result<std::string> encode(const T &x, const char *tag) {
  try {
    auto bytes = serde::serialize(x);
    if (bytes.size() > 150u * 1024) return makeError(bad().error());
    return std::string(tag) + bytes;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
template <class T>
Result<T> decode(std::string_view s, std::string_view tag) {
  try {
    if (!s.starts_with(tag) || s.size() > 160u * 1024) return makeError(bad().error());
    s.remove_prefix(tag.size());
    T v;
    RETURN_ON_ERROR(serde::deserialize(v, s));
    if (serde::serialize(v) != s) return makeError(bad().error());
    return v;
  } catch (...) {
    return makeError(bad().error());
  }
}
}  // namespace
Result<Void> EcAppendRun::validate() const {
  const auto &i = session.intent;
  if (version != 1 || cluster.empty() || cluster.size() > 256 || cluster.find('\0') != std::string::npos ||
      session.version != 1 || i.version != 1 || i.object.incarnation.is_nil() || i.birth.is_nil() ||
      i.owner.client.is_nil() || i.session.is_nil() || i.openRequest.is_nil() ||
      session.state != meta::EcFileSessionState::Open || !i.rights || (i.rights & ~uint8_t{3}))
    return bad();
  if (kind == EcAppendRunKind::Append) {
    RETURN_ON_ERROR(meta::validateEcAppend(appendIntent));
    if (!(i.rights & meta::kEcSessionWrite) || appendIntent.object != i.object || !same(appendIntent.owner, i.owner) ||
        appendIntent.session != i.session || !shardBytes || shardBytes > (1u << 20) || queryRequest.is_nil() ||
        queryRequest == appendIntent.request || queryRequest == appendIntent.operation || sealRequest.is_nil() ||
        sealRequest == queryRequest || sealRequest == appendIntent.request || sealRequest == appendIntent.operation ||
        !path(inputPath) || !path(childDirectory) || !same(syncIntent, meta::EcFileSyncIntent{}))
      return bad();
    // At most 64 stripe children for any accepted EOF alignment.
    if ((appendIntent.length + uint64_t(shardBytes) * 10 - 2) / (uint64_t(shardBytes) * 10) + 1 >
        kEcPwriteClientMaxChildren)
      return bad();
  } else if (kind == EcAppendRunKind::Sync) {
    RETURN_ON_ERROR(meta::validateEcSync(syncIntent));
    if (syncIntent.object != i.object || !same(syncIntent.owner, i.owner) || syncIntent.session != i.session ||
        shardBytes || !queryRequest.is_nil() || !sealRequest.is_nil() || !inputPath.empty() ||
        !childDirectory.empty() || !same(appendIntent, meta::EcFileAppendIntent{}))
      return bad();
  } else
    return bad();
  return Void{};
}
Result<Void> EcAppendJournalState::validate(const EcAppendRun &r, const EcAppendJournalState *old) const {
  RETURN_ON_ERROR(r.validate());
  if (version != 1 || sequence >= 4096 ||
      (old && (sequence != old->sequence + 1 || (old->issued && !issued) || (old->accepted && !accepted) ||
               (old->synced && !synced))))
    return bad();
  if (accepted) {
    const auto &a = *accepted;
    const auto &p = a.parent;
    const auto &i = p.intent;
    const auto &f = r.appendIntent;
    if (r.kind != EcAppendRunKind::Append || !issued || a.version != 1 || !same(a.intent, f) ||
        a.birth != r.session.intent.birth || a.acceptedRoot.object != f.object || a.acceptedRoot.birth != a.birth ||
        !a.acceptedRoot.sequence || !a.acceptedRoot.epoch || p.version != 1 || i.version != 1 || i.object != f.object ||
        !same(i.owner, f.owner) || i.session != f.session || i.request != f.operation ||
        i.offset != a.acceptedRoot.visibleLength || i.length != f.length || i.inputSha256 != f.inputSha256 ||
        i.offset > UINT64_MAX - i.length || p.epoch != a.acceptedRoot.epoch || !p.sessionSequence ||
        p.confirmedPrefix > i.length ||
        (p.state != meta::EcFileMutationState::Open && p.state != meta::EcFileMutationState::ClosedLogical) ||
        (p.state == meta::EcFileMutationState::ClosedLogical && !p.activeChild.is_nil()))
      return bad();
    if (old && old->accepted) {
      const auto &b = *old->accepted;
      if (!same(a.acceptedRoot, b.acceptedRoot) || !same(i, b.parent.intent) || p.epoch != b.parent.epoch ||
          p.sessionSequence != b.parent.sessionSequence || p.confirmedPrefix < b.parent.confirmedPrefix ||
          uint8_t(p.state) < uint8_t(b.parent.state))
        return bad();
    }
  }
  if (synced) {
    const auto &s = *synced;
    if (r.kind != EcAppendRunKind::Sync || !issued || s.version != 1 || s.durabilityContract != 1 ||
        !same(s.intent, r.syncIntent) || s.root.object != r.syncIntent.object ||
        s.root.birth != r.session.intent.birth || !s.root.sequence || !s.root.epoch ||
        s.sessionSequence < r.session.acceptedSequence || (old && old->synced && !same(s, *old->synced)))
      return bad();
  }
  return Void{};
}
Result<EcAppendRun> prepareEcAppend(const meta::EcFileSessionRecord &s,
                                    uint32_t shard,
                                    std::string cluster,
                                    std::string input,
                                    std::string child,
                                    std::span<const uint8_t> bytes) {
  EcAppendRun r;
  r.session = s;
  r.cluster = std::move(cluster);
  r.shardBytes = shard;
  r.inputPath = std::move(input);
  r.childDirectory = std::move(child);
  auto &i = r.appendIntent;
  i.object = s.intent.object;
  i.owner = s.intent.owner;
  i.session = s.intent.session;
  i.operation = Uuid::random();
  i.request = Uuid::random();
  i.length = bytes.size();
  r.queryRequest = Uuid::random();
  r.sealRequest = Uuid::random();
  CHECK_RESULT(hash, detail::fileContentSha(bytes));
  i.inputSha256 = hash;
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<EcAppendRun> prepareEcSync(const meta::EcFileSessionRecord &s, std::string cluster) {
  EcAppendRun r;
  r.kind = EcAppendRunKind::Sync;
  r.session = s;
  r.cluster = std::move(cluster);
  r.syncIntent.object = s.intent.object;
  r.syncIntent.owner = s.intent.owner;
  r.syncIntent.session = s.intent.session;
  r.syncIntent.request = Uuid::random();
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcAppendRun(const EcAppendRun &r) {
  RETURN_ON_ERROR(r.validate());
  return encode(r, "ECAPPEND1\n");
}
Result<EcAppendRun> decodeEcAppendRun(std::string_view s) {
  CHECK_RESULT(r, decode<EcAppendRun>(s, "ECAPPEND1\n"));
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcAppendState(const EcAppendJournalState &s) { return encode(s, "ECAPPENDSTATE1\n"); }
Result<EcAppendJournalState> decodeEcAppendState(std::string_view s) {
  return decode<EcAppendJournalState>(s, "ECAPPENDSTATE1\n");
}
}  // namespace hf3fs::client::ec
