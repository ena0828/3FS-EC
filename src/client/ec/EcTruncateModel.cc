#include <set>

#include "EcTruncateJournal.h"

namespace hf3fs::client::ec {
namespace {
bool same(const auto &a, const auto &b) { return serde::serialize(a) == serde::serialize(b); }
Result<Void> invalid(const char *s) { return makeError(StatusCode::kInvalidFormat, s); }
template <class T>
Result<std::string> encode(std::string_view tag, const T &v) {
  auto bytes = serde::serialize(v);
  if (bytes.size() > 160u * 1024 - tag.size()) return makeError(StatusCode::kInvalidFormat, "truncate journal bound");
  return std::string(tag) + bytes;
}
template <class T>
Result<T> decode(std::string_view tag, std::string_view bytes) {
  if (bytes.size() > 160u * 1024 || !bytes.starts_with(tag)) return makeError(StatusCode::kInvalidFormat);
  T v;
  RETURN_ON_ERROR(serde::deserialize(v, bytes.substr(tag.size())));
  CHECK_RESULT(encoded, encode(tag, v));
  if (encoded != bytes) return makeError(StatusCode::kInvalidFormat, "noncanonical truncate journal");
  return v;
}
}  // namespace
Result<Void> EcTruncateRun::validate() const {
  RETURN_ON_ERROR(meta::validateEcFileTruncateIntent(intent));
  if (version != 1 || cluster.empty() || cluster.size() > 1024 || cluster.find('\0') != std::string::npos ||
      session.version != meta::kEcFileMutationVersion || session.birth.is_nil() || session.openRequest.is_nil() ||
      !(session.rights & meta::kEcSessionWrite) || (session.rights & ~(meta::kEcSessionRead | meta::kEcSessionWrite)) ||
      session.object != intent.object || session.session != intent.session || !same(session.owner, intent.owner))
    return invalid("truncate requires accepted WRITE session and fixed owner");
  std::set<Uuid> ids{intent.operation, intent.child, intent.plan, intent.sourcePin};
  for (const auto &id : intent.nodeIds) ids.insert(id);
  for (const auto &id : {beginRequest, queryRequest, advanceRequest, closeRequest, outputRevocation, sourceRevocation})
    if (id.is_nil() || !ids.insert(id).second) return invalid("truncate request IDs overlap");
  return Void{};
}
Result<EcTruncateRun> prepareEcFileTruncate(const meta::EcFileSessionRecord &s,
                                            const meta::EcTreeRoot &root,
                                            std::string cluster,
                                            uint64_t length) {
  if (s.state != meta::EcFileSessionState::Open || !(s.intent.rights & meta::kEcSessionWrite))
    return makeError(MetaCode::kNoPermission);
  if (root.version != meta::kEcFileTreeVersion || root.object != s.intent.object || root.birth != s.intent.birth)
    return makeError(StatusCode::kTokenMismatch);
  EcTruncateRun r;
  r.cluster = std::move(cluster);
  r.session = s.intent;
  auto &i = r.intent;
  i.object = s.intent.object;
  i.owner = s.intent.owner;
  i.session = s.intent.session;
  i.operation = Uuid::random();
  i.child = Uuid::random();
  i.plan = Uuid::random();
  i.sourcePin = Uuid::random();
  for (auto &id : i.nodeIds) id = Uuid::random();
  i.expectedRoot = root.root;
  i.expectedSequence = root.sequence;
  i.expectedEpoch = root.epoch;
  i.expectedLength = root.visibleLength;
  i.length = length;
  r.beginRequest = Uuid::random();
  r.queryRequest = Uuid::random();
  r.advanceRequest = Uuid::random();
  r.closeRequest = Uuid::random();
  r.outputRevocation = Uuid::random();
  r.sourceRevocation = Uuid::random();
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<Void> validateEcTruncateProgress(const EcTruncateRun &r, const meta::EcFileTruncateProgress &p) {
  RETURN_ON_ERROR(r.validate());
  if (!same(r.intent, p.intent)) return invalid("truncate response changed fixed intent");
  if (!p.observed) return Void{};
  const auto &o = *p.observed;
  const auto &f = o.fencedRoot;
  const auto &i = r.intent;
  if (o.birth != r.session.birth || f.version != meta::kEcFileTreeVersion || f.object != i.object ||
      f.birth != o.birth || f.root != i.expectedRoot || f.sequence != i.expectedSequence + 1 ||
      f.epoch != i.expectedEpoch + 1 || f.visibleLength != i.expectedLength ||
      (o.state != meta::EcFileTruncateState::Planned && o.state != meta::EcFileTruncateState::Published &&
       o.state != meta::EcFileTruncateState::Aborted) ||
      (o.publishedRoot.has_value() != (o.state == meta::EcFileTruncateState::Published)) ||
      (o.tailRequired && i.length >= i.expectedLength) ||
      (!o.tailRequired && (!o.outputDrained || !o.sourceReleased)) || (o.sourceReleased && !o.outputDrained))
    return invalid("invalid truncate observation");
  if (o.publishedRoot) {
    const auto &root = *o.publishedRoot;
    if (root.version != meta::kEcFileTreeVersion || root.object != i.object || root.birth != o.birth ||
        root.sequence != f.sequence + 1 || root.epoch != f.epoch || root.visibleLength != i.length ||
        root.root != (i.length < i.expectedLength ? i.nodeIds[15] : f.root) || !o.outputDrained)
      return invalid("truncate publication root differs from original CAS");
  }
  return Void{};
}
Result<Void> compareEcTruncateProgress(const meta::EcFileTruncateProgress &a, const meta::EcFileTruncateProgress &b) {
  if (!same(a.intent, b.intent)) return invalid("truncate intent changed");
  if (!a.observed) return Void{};
  if (!b.observed) return invalid("known truncate disappeared; missing is not a new Begin permit");
  const auto &x = *a.observed;
  const auto &y = *b.observed;
  if (x.birth != y.birth || !same(x.fencedRoot, y.fencedRoot) || x.tailRequired != y.tailRequired ||
      (x.state != meta::EcFileTruncateState::Planned && x.state != y.state) ||
      (x.publishedRoot && !same(x.publishedRoot, y.publishedRoot)) || (x.outputDrained && !y.outputDrained) ||
      (x.sourceReleased && !y.sourceReleased))
    return invalid("truncate progress regressed");
  return Void{};
}
Result<Void> EcTruncateJournalState::validate(const EcTruncateRun &r, const EcTruncateJournalState *p) const {
  if (version != 1 || ((advanceIssued || closeIssued) && (!progress || !progress->observed)))
    return invalid("truncate progress dependency missing");
  if (progress) RETURN_ON_ERROR(validateEcTruncateProgress(r, *progress));
  if (p) {
    if (p->sequence == UINT64_MAX || sequence != p->sequence + 1 || attempt < p->attempt ||
        (attempt != p->attempt && (p->attempt == UINT64_MAX || attempt != p->attempt + 1)) ||
        (p->beginIssued && !beginIssued) || (p->advanceIssued && !advanceIssued) || (p->closeIssued && !closeIssued) ||
        (p->progress && !progress) || (p->localComplete && attempt == p->attempt && !localComplete))
      return invalid("truncate journal regressed");
    if (p->progress) RETURN_ON_ERROR(compareEcTruncateProgress(*p->progress, *progress));
  } else if (sequence)
    return invalid("truncate sequence does not start at zero");
  return Void{};
}
Result<std::string> encodeEcTruncateRun(const EcTruncateRun &r) {
  RETURN_ON_ERROR(r.validate());
  return encode("3FS-TRUNCATE-RUN-v1\n", r);
}
Result<EcTruncateRun> decodeEcTruncateRun(std::string_view b) {
  CHECK_RESULT(r, decode<EcTruncateRun>("3FS-TRUNCATE-RUN-v1\n", b));
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcTruncateState(const EcTruncateJournalState &s) {
  return encode("3FS-TRUNCATE-STATE-v1\n", s);
}
Result<EcTruncateJournalState> decodeEcTruncateState(std::string_view b) {
  return decode<EcTruncateJournalState>("3FS-TRUNCATE-STATE-v1\n", b);
}
}  // namespace hf3fs::client::ec
