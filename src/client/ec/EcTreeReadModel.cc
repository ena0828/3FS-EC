#include <algorithm>
#include <set>

#include "EcTreeReadJournal.h"
#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::client::ec {
namespace {
bool same(const auto &a, const auto &b) {
  const auto left = serde::serialize(a), right = serde::serialize(b);
  return std::string_view(left) == std::string_view(right);
}
Result<Void> invalid(const char *s) { return makeError(StatusCode::kInvalidFormat, s); }
constexpr size_t maximumBytes = 160u << 10;
template <class T>
Result<std::string> encode(std::string_view tag, const T &v) {
  std::string out(tag);
  const auto bytes = serde::serialize(v);
  out.append(bytes.data(), bytes.size());
  if (out.size() > maximumBytes) return makeError(StatusCode::kInvalidFormat, "tree journal record exceeds bound");
  return out;
}
template <class T>
Result<T> decode(std::string_view tag, std::string_view bytes) {
  if (bytes.size() > maximumBytes || !bytes.starts_with(tag))
    return makeError(StatusCode::kInvalidFormat, "tree journal type/version differs");
  T value;
  RETURN_ON_ERROR(serde::deserialize(value, bytes.substr(tag.size())));
  CHECK_RESULT(canonical, encode(tag, value));
  if (canonical != bytes) return makeError(StatusCode::kInvalidFormat, "noncanonical/trailing tree journal bytes");
  return value;
}
}  // namespace
Result<Void> EcTreeReadRun::validate() const {
  if (version != 1 || cluster.empty() || cluster.size() > 1024 || cluster.find('\0') != std::string::npos ||
      session.version != 1 || session.session.is_nil() || session.openRequest.is_nil() || session.birth.is_nil() ||
      !(session.rights & meta::kEcSessionRead) || (session.rights & ~(meta::kEcSessionRead | meta::kEcSessionWrite)) ||
      intent.version != meta::kEcFileTreeVersion || intent.session != session.session ||
      !same(intent.owner, session.owner) || intent.selection.object != session.object)
    return invalid("tree read requires the fixed accepted READ session");
  meta::EcManifestLayoutV1 layout;
  layout.incarnation = session.object.incarnation;
  layout.shardBytes = shardBytes;
  RETURN_ON_ERROR(intent.selection.matchesLayout(layout));
  if (intent.owner.client.is_nil()) return invalid("tree read owner is missing");
  std::set<Uuid> ids;
  const auto accept = [&](const Uuid &id) { return !id.is_nil() && ids.insert(id).second; };
  if (!accept(intent.request) || !accept(intent.range) || !accept(queryRequest) || !accept(releaseRequest))
    return invalid("tree request identity reused");
  for (size_t n = 0; n < 8; ++n) {
    if (n < intent.selection.pinCount) {
      if (!accept(intent.selection.pins[n].pin) || !accept(refreshRequests[n]) || !accept(revocations[n]))
        return invalid("tree slot ID reused");
    } else if (!refreshRequests[n].is_nil() || !revocations[n].is_nil())
      return invalid("unused tree slot ID nonzero");
  }
  return Void{};
}
Result<EcTreeReadRun> prepareEcTreeRead(const meta::EcFileSessionRecord &session,
                                        std::string cluster,
                                        uint32_t shardBytes,
                                        uint64_t offset,
                                        uint64_t length) {
  if (session.state != meta::EcFileSessionState::Open || !(session.intent.rights & meta::kEcSessionRead))
    return makeError(MetaCode::kNoPermission, "new tree read needs an open READ session");
  CHECK_RESULT(plan, planEcFileRead(shardBytes, offset, length));
  EcTreeReadRun r;
  r.cluster = std::move(cluster);
  r.session = session.intent;
  r.shardBytes = shardBytes;
  r.intent.owner = session.intent.owner;
  r.intent.session = session.intent.session;
  r.intent.request = Uuid::random();
  r.intent.range = Uuid::random();
  r.intent.selection.object = session.intent.object;
  r.intent.selection.offset = offset;
  r.intent.selection.length = length;
  r.intent.selection.pinCount = plan.count;
  r.queryRequest = Uuid::random();
  r.releaseRequest = Uuid::random();
  for (size_t i = 0; i < plan.count; ++i) {
    r.intent.selection.pins[i] = {plan.slices[i].stripe, Uuid::random()};
    r.refreshRequests[i] = Uuid::random();
    r.revocations[i] = Uuid::random();
  }
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<Void> validateEcTreeReadSnapshot(const EcTreeReadRun &r, const meta::EcTreeReadRecord &s) {
  RETURN_ON_ERROR(r.validate());
  CHECK_RESULT(plan, planEcFileRead(r.shardBytes, r.intent.selection.offset, r.intent.selection.length));
  CHECK_RESULT(clipped, clipEcFileRead(plan, s.root.visibleLength));
  if (s.version != meta::kEcFileTreeVersion || !same(s.intent, r.intent) ||
      s.root.version != meta::kEcFileTreeVersion || s.root.object != r.session.object ||
      s.root.birth != r.session.birth || !s.root.sequence || !s.root.epoch || s.shardBytes != r.shardBytes ||
      s.readableLength != clipped.length || s.stripeCount != clipped.count ||
      (s.state != meta::EcTreeReadState::Active && s.state != meta::EcTreeReadState::Closing &&
       s.state != meta::EcTreeReadState::Released) ||
      ((s.state == meta::EcTreeReadState::Active) != s.closeAuthority.is_nil()))
    return invalid("tree snapshot identity/extent changed");
  for (size_t n = 0; n < 8; ++n) {
    const auto &entry = s.stripes[n];
    const bool data = n < s.stripeCount && entry.slot.kind == meta::EcTreeSlotKind::Data;
    if (n >= s.stripeCount) {
      if (!same(entry, meta::EcTreeReadStripe{})) return invalid("unused tree snapshot slot nonzero");
    } else {
      if (entry.slot.stripe != r.intent.selection.pins[n].stripe) return invalid("tree slot stripe changed");
      if (data) {
        const uint64_t begin = entry.slot.stripe * uint64_t(r.shardBytes) * 10;
        if (!entry.snapshot || !entry.slot.revision || !entry.slot.generation || !entry.slot.logicalLength ||
            entry.slot.logicalLength > uint64_t(r.shardBytes) * 10 || begin > s.root.visibleLength ||
            entry.slot.logicalLength > s.root.visibleLength - begin ||
            entry.slot.contentSha256 == storage::EcSha256{} || s.root.root.is_nil())
          return invalid("invalid Data tree snapshot");
        const auto &pin = *entry.snapshot;
        if (pin.version != meta::kEcBindingCatalogVersion || pin.object != r.session.object ||
            !same(pin.owner, r.session.owner) || pin.pin != r.intent.selection.pins[n].pin ||
            pin.stripe != entry.slot.stripe || pin.revision != entry.slot.revision ||
            pin.generation != entry.slot.generation)
          return invalid("Data source pin differs");
        std::array<storage::EcScopeEndpoint, 12> endpoints;
        std::set<Uuid> allocations;
        for (size_t i = 0; i < 12; ++i) {
          const auto &p = pin.endpoints[i];
          RETURN_ON_ERROR(p.identity.validate());
          if (p.identity.object != r.session.object.incarnation || p.identity.stripe != entry.slot.stripe ||
              p.identity.generation != entry.slot.generation || p.identity.shard != i || p.operation.is_nil() ||
              !allocations.insert(p.identity.allocation).second)
            return invalid("Data source allocation differs");
          endpoints[i] = p.endpoint.controlEndpoint();
          if (endpoints[i].nodeId == flat::NodeId{} || endpoints[i].chainId == storage::ChainId{} ||
              endpoints[i].targetId == storage::TargetId{} || endpoints[i].engineUuid.is_nil() ||
              endpoints[i].targetIncarnation.is_nil())
            return invalid("Data source endpoint is incomplete");
        }
        CHECK_RESULT(digest, storage::computeEcScopeEndpointDigest(endpoints));
        if (digest != pin.endpointSetDigest) return invalid("Data endpoint set digest differs");
      } else {
        meta::EcTreeSlot zero;
        zero.stripe = entry.slot.stripe;
        if (entry.snapshot || !same(entry.slot, zero)) return invalid("Zero slot contains Data state");
      }
    }
    const auto expected = (s.state != meta::EcTreeReadState::Active && data) ? r.revocations[n] : Uuid::zero();
    if (s.revocations[n] != expected) return invalid("tree range revocation differs from fixed journal");
  }
  return Void{};
}
Result<Void> sameEcTreeReadSnapshot(const meta::EcTreeReadRecord &a, const meta::EcTreeReadRecord &b) {
  auto left = a, right = b;
  left.state = right.state = meta::EcTreeReadState::Active;
  left.closeAuthority = right.closeAuthority = Uuid::zero();
  left.revocations = {};
  right.revocations = {};
  if (!same(left, right)) return invalid("fixed tree range root/slots changed");
  if (static_cast<uint8_t>(b.state) < static_cast<uint8_t>(a.state) ||
      (!a.closeAuthority.is_nil() && a.closeAuthority != b.closeAuthority))
    return invalid("tree range state regressed");
  return Void{};
}
Result<Void> EcTreeReadProgress::validate(const EcTreeReadRun &r, const EcTreeReadProgress *p) const {
  if (version != 1 || (snapshot && !acquisitionIssued) || (dataReady && !snapshot) || (releaseIssued && !snapshot))
    return invalid("invalid tree progress dependencies");
  if (snapshot) RETURN_ON_ERROR(validateEcTreeReadSnapshot(r, *snapshot));
  if (p) {
    if (p->sequence == UINT64_MAX || sequence != p->sequence + 1 || attempt < p->attempt ||
        (attempt != p->attempt && (p->attempt == UINT64_MAX || attempt != p->attempt + 1)) ||
        (p->acquisitionIssued && !acquisitionIssued) || (p->releaseIssued && !releaseIssued) ||
        (p->dataReady && !dataReady) || (p->snapshot && !snapshot) ||
        (attempt == p->attempt && p->localComplete && !localComplete))
      return invalid("tree progress regressed");
    if (p->snapshot) RETURN_ON_ERROR(sameEcTreeReadSnapshot(*p->snapshot, *snapshot));
  } else if (sequence)
    return invalid("tree progress sequence did not start at zero");
  return Void{};
}
Result<std::string> encodeEcTreeReadRun(const EcTreeReadRun &r) {
  RETURN_ON_ERROR(r.validate());
  return encode("3FS-TREE-READ-RUN-v1\n", r);
}
Result<EcTreeReadRun> decodeEcTreeReadRun(std::string_view bytes) {
  CHECK_RESULT(r, decode<EcTreeReadRun>("3FS-TREE-READ-RUN-v1\n", bytes));
  RETURN_ON_ERROR(r.validate());
  return r;
}
Result<std::string> encodeEcTreeReadProgress(const EcTreeReadProgress &p) {
  return encode("3FS-TREE-READ-STATE-v1\n", p);
}
Result<EcTreeReadProgress> decodeEcTreeReadProgress(std::string_view bytes) {
  return decode<EcTreeReadProgress>("3FS-TREE-READ-STATE-v1\n", bytes);
}
}  // namespace hf3fs::client::ec
