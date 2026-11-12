#include <set>

#include "EcTreeRepairJournal.h"
namespace hf3fs::client::ec {
namespace {
bool same(const auto &a, const auto &b) { return serde::serialize(a) == serde::serialize(b); }
Result<Void> bad() { return makeError(StatusCode::kInvalidFormat, "repair journal identity or progress differs"); }
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

Result<Void> EcTreeRepairRun::validate() const {
  RETURN_ON_ERROR(meta::validateEcFileRepairIntent(intent));
  if (version != 1 || birth.is_nil() || cluster.empty() || cluster.size() > 256 ||
      cluster.find('\0') != std::string::npos)
    return bad();
  std::set<Uuid> ids{intent.request, intent.operation, intent.child, intent.sourcePin, intent.selection.planId};
  for (auto u : {queryRequest, prepareRequest, publishRequest, closeRequest, outputRevocation, sourceRevocation})
    if (u.is_nil() || !ids.insert(u).second) return bad();
  for (auto u : intent.nodeIds)
    if (!ids.insert(u).second) return bad();
  return Void{};
}
Result<Void> EcTreeRepairState::validate(const EcTreeRepairRun &r, const EcTreeRepairState *old) const {
  RETURN_ON_ERROR(r.validate());
  const auto &p = progress;
  if (version != 1 || sequence >= 4096 || (dataComplete && !issued) ||
      (old && (sequence != old->sequence + 1 || (old->issued && !issued) || (old->dataComplete && !dataComplete) ||
               (old->progress.record && !p.record) || (old->progress.outputDrained && !p.outputDrained) ||
               (old->progress.sourceReleased && !p.sourceReleased))))
    return bad();
  if (!p.record) {
    if (p.outputDrained || p.sourceReleased || p.outputClosing || dataComplete) return bad();
    return Void{};
  }
  const auto &a = *p.record;
  const auto &c = a.child;
  const auto &i = r.intent;
  if (!issued || a.version != 1 || !same(a.intent, i) || c.birth != r.birth || c.session != i.session ||
      !same(c.owner, i.owner) || c.intent.object != i.object || c.intent.parent != i.operation ||
      c.intent.child != i.child || c.intent.sourcePin != i.sourcePin || c.intent.plan != i.selection.planId ||
      c.intent.nodeIds != i.nodeIds || c.sourceRoot != i.expectedRoot || c.sourceSequence != i.expectedSequence ||
      c.epoch != i.expectedEpoch || c.stripe != i.stripe || c.source.kind != meta::EcTreeSlotKind::Data ||
      c.source.stripe != i.stripe || c.targetGeneration != c.source.generation ||
      c.targetRevision <= c.source.revision || c.targetLogicalLength != c.source.logicalLength || c.patchLength ||
      c.patchOffset || c.intent.expectedPrefix ||
      (a.state == meta::EcFileRepairState::Planned     ? c.state != meta::EcFileChildState::Planned
       : a.state == meta::EcFileRepairState::Published ? c.state != meta::EcFileChildState::Published
       : a.state == meta::EcFileRepairState::Aborted   ? c.state != meta::EcFileChildState::Fenced
                                                       : true) ||
      ((a.state == meta::EcFileRepairState::Published) != c.publishedRoot.has_value()) ||
      (a.state == meta::EcFileRepairState::Published && !p.outputDrained) || (p.sourceReleased && !p.outputDrained))
    return bad();
  if (old && old->progress.record) {
    auto before = old->progress.record->child, after = c;
    before.state = after.state;
    before.publishedRoot = after.publishedRoot;
    if (!same(before, after) ||
        (old->progress.record->state != meta::EcFileRepairState::Planned && old->progress.record->state != a.state))
      return bad();
  }
  return Void{};
}
Result<EcTreeRepairRun> prepareEcTreeRepair(const meta::EcFileSessionRecord &s,
                                            const meta::EcTreeRoot &root,
                                            std::string cluster,
                                            uint64_t stripe,
                                            uint16_t mask,
                                            meta::EcFileRepairMode mode,
                                            std::array<uint8_t, 10> sources,
                                            uint16_t window) {
  if (s.state != meta::EcFileSessionState::Open || s.intent.rights != 3 || root.object != s.intent.object ||
      root.birth != s.intent.birth)
    return makeError(MetaCode::kNoPermission, "repair requires a live READ and WRITE session and captured root");
  if (!window || window > 4) return makeError(StatusCode::kInvalidArg);
  EcTreeRepairRun r;
  r.cluster = std::move(cluster);
  r.birth = s.intent.birth;
  auto &i = r.intent;
  i.object = s.intent.object;
  i.owner = s.intent.owner;
  i.session = s.intent.session;
  i.request = Uuid::random();
  i.operation = Uuid::random();
  i.child = Uuid::random();
  i.sourcePin = Uuid::random();
  i.expectedRoot = root.root;
  i.expectedSequence = root.sequence;
  i.expectedEpoch = root.epoch;
  i.stripe = stripe;
  i.replacementMask = mask;
  i.mode = mode;
  i.selection.planId = Uuid::random();
  i.selection.sourceOrder = sources;
  i.selection.maxBlocksInFlight = window;
  for (auto &u : i.nodeIds) u = Uuid::random();
  r.queryRequest = Uuid::random();
  r.prepareRequest = Uuid::random();
  r.publishRequest = Uuid::random();
  r.closeRequest = Uuid::random();
  r.outputRevocation = Uuid::random();
  r.sourceRevocation = Uuid::random();
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcTreeRepairRun(const EcTreeRepairRun &r) {
  RETURN_ON_ERROR(r.validate());
  return encode(r, "ECTREEREPAIR1\n");
}
Result<EcTreeRepairRun> decodeEcTreeRepairRun(std::string_view s) {
  CHECK_RESULT(r, decode<EcTreeRepairRun>(s, "ECTREEREPAIR1\n"));
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcTreeRepairState(const EcTreeRepairState &s) { return encode(s, "ECTREEREPAIRSTATE1\n"); }
Result<EcTreeRepairState> decodeEcTreeRepairState(std::string_view s) {
  return decode<EcTreeRepairState>(s, "ECTREEREPAIRSTATE1\n");
}
}  // namespace hf3fs::client::ec
