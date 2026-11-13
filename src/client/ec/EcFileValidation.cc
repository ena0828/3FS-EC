#include "detail/EcFileValidation.h"

#include <algorithm>

#include "fbs/meta/EcRequestDigest.h"
namespace hf3fs::client::ec::detail {
namespace {
Result<Void> corrupt() {
  return makeError(StatusCode::kDataCorruption, "file observation differs from its fixed plan");
}
bool owner(const meta::EcOwner &a, const meta::EcOwner &b) { return a.uid == b.uid && a.client == b.client; }
}  // namespace
meta::EcRangeSelection fileSelection(const EcFileRunRecord &r) {
  meta::EcRangeSelection s;
  s.object = r.object;
  s.offset = r.offset;
  s.length = r.length;
  s.pinCount = r.count;
  for (size_t i = 0; i != r.count; ++i) s.pins[i] = {r.slots[i].stripe, r.slots[i].pin};
  return s;
}
Result<Void> validateFileSnapshot(const EcFileRunRecord &r, const meta::EcRangeSnapshot &s) {
  RETURN_ON_ERROR(r.validate());
  if (r.kind != EcFileRunKind::RangeRead || s.version != 1 || !owner(s.owner, r.owner) ||
      s.requestId != r.rangeRequest || s.rangeId != r.rangeId || !serde::equals(s.selection, fileSelection(r)) ||
      s.file.object != r.object || !s.file.epoch || s.file.layout.shardBytes != r.shardBytes)
    return corrupt();
  RETURN_ON_ERROR(s.selection.matchesLayout(s.file.layout));
  CHECK_RESULT(requested, planEcFileRead(r.shardBytes, r.offset, r.length));
  CHECK_RESULT(clipped, clipEcFileRead(requested, s.file.length));
  if (s.readableLength != clipped.length || s.stripeCount != clipped.count) return corrupt();
  for (size_t i = 0; i != s.stripes.size(); ++i) {
    const auto &entry = s.stripes[i];
    const auto &pin = entry.snapshot;
    if (i >= s.stripeCount) {
      if (!serde::equals(entry, meta::EcRangeStripe{})) return corrupt();
      continue;
    }
    if (entry.state != meta::EcRangePinState::Active && entry.state != meta::EcRangePinState::Closing &&
        entry.state != meta::EcRangePinState::Released)
      return corrupt();
    const auto length = std::min<uint64_t>(uint64_t(r.shardBytes) * 10,
                                           s.file.length - r.slots[i].stripe * uint64_t(r.shardBytes) * 10);
    if (pin.version != meta::kEcBindingCatalogVersion || pin.object != r.object || pin.pin != r.slots[i].pin ||
        pin.stripe != r.slots[i].stripe || !pin.revision || !pin.generation || !owner(pin.owner, r.owner) ||
        entry.logicalLength != length || !length || entry.contentSha256 == storage::EcSha256{})
      return corrupt();
    std::array<storage::EcScopeEndpoint, 12> endpoints;
    for (size_t j = 0; j != 12; ++j) {
      const auto &e = pin.endpoints[j];
      RETURN_ON_ERROR(e.identity.validate());
      if (e.identity.object != r.object.incarnation || e.identity.stripe != pin.stripe ||
          e.identity.generation != pin.generation || e.identity.shard != j || e.operation.is_nil())
        return corrupt();
      endpoints[j] = e.endpoint.controlEndpoint();
      for (size_t k = 0; k != j; ++k)
        if (e.identity.allocation == pin.endpoints[k].identity.allocation ||
            e.endpoint.placement.target == pin.endpoints[k].endpoint.placement.target ||
            e.endpoint.placement.chain == pin.endpoints[k].endpoint.placement.chain)
          return corrupt();
    }
    CHECK_RESULT(digest, storage::computeEcScopeEndpointDigest(endpoints));
    if (digest != pin.endpointSetDigest) return corrupt();
  }
  return Void{};
}
Result<Void> validateSameFileSnapshot(const meta::EcRangeSnapshot &a, const meta::EcRangeSnapshot &b) {
  auto left = a, right = b;
  for (size_t i = 0; i != 8; ++i) left.stripes[i].state = right.stripes[i].state = meta::EcRangePinState::Unused;
  if (!serde::equals(left, right)) return corrupt();
  return Void{};
}
Result<Void> validateFileStripe(const meta::EcRangeStripe &fixed, const EcStripeReadOutput &read) {
  const auto &manifest = read.pinned.manifest;
  if (!serde::equals(fixed.snapshot, read.pinned.snapshot) || fixed.contentSha256 != read.contentSha256 ||
      manifest.version != meta::kEcCatalogVersion || manifest.object != fixed.snapshot.object ||
      manifest.stripe != fixed.snapshot.stripe || manifest.revision != fixed.snapshot.revision ||
      manifest.generation != fixed.snapshot.generation || manifest.logicalLength != fixed.logicalLength ||
      read.logicalData.size() != fixed.logicalLength)
    return corrupt();
  for (size_t j = 0; j != 12; ++j) {
    const auto &f = manifest.fragments[j];
    const auto &e = fixed.snapshot.endpoints[j];
    if (!serde::equals(f.identity, e.identity) || f.operation != e.operation || f.placement != e.endpoint.placement)
      return corrupt();
    RETURN_ON_ERROR(storage::validateEcIntegrity(f.identity, f.integrity));
  }
  return Void{};
}
Result<storage::EcSha256> fileContentSha(std::span<const uint8_t> bytes) {
  std::array<std::string_view, 10> parts{};
  parts[0] = {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
  return meta::computeEcLogicalSha256(parts, bytes.size());
}
Result<Void> validateFileInput(const EcFileRunRecord &r, std::span<const uint8_t> bytes) {
  RETURN_ON_ERROR(r.validate());
  if (r.kind != EcFileRunKind::AppendAt || bytes.size() != r.length) return corrupt();
  CHECK_RESULT(whole, fileContentSha(bytes));
  if (whole != r.contentSha256) return corrupt();
  const size_t stripeBytes = size_t(r.shardBytes) * 10;
  for (size_t i = 0; i != r.count; ++i) {
    CHECK_RESULT(part, fileContentSha(bytes.subspan(i * stripeBytes, stripeBytes)));
    if (part != r.slots[i].contentSha256) return corrupt();
  }
  return Void{};
}
Result<Void> validateFileIntent(const EcFileRunRecord &r, size_t index, const meta::EcV2MutationRsp &rsp) {
  if (index >= r.count || !rsp.reservation) return corrupt();
  const auto &intent = rsp.record.intent;
  if (rsp.record.version != meta::kEcCatalogVersion || intent.version != meta::kEcCatalogVersion ||
      !owner(rsp.record.owner, r.owner) || rsp.object.object != r.object || rsp.object.shardBytes != r.shardBytes ||
      intent.object != r.object || intent.operation != r.slots[index].mutation.operation ||
      intent.stripe != r.slots[index].stripe || intent.expectedEpoch != r.epoch || intent.expectedRevision != 0 ||
      intent.kind != meta::EcMutationKind::Write || intent.replacementMask != meta::kEcAllShards ||
      intent.logicalLength != uint64_t(r.shardBytes) * 10 ||
      rsp.reservation->contentSha256 != r.slots[index].contentSha256 ||
      !serde::equals(rsp.reservation->original.intent, intent) || !owner(rsp.reservation->original.owner, r.owner))
    return corrupt();
  CHECK_RESULT(digest, meta::computeEcRequestDigest(intent, r.shardBytes, r.slots[index].contentSha256));
  if (digest != intent.requestDigest) return corrupt();
  return Void{};
}
Result<Void> validateFileOwnedObservation(const EcFileRunRecord &run,
                                          size_t index,
                                          const meta::EcOwnedMutationRsp &rsp) {
  RETURN_ON_ERROR(run.validate());
  if (run.kind != EcFileRunKind::AppendAt || index >= run.count) return corrupt();
  const auto &slot = run.slots[index];
  const auto &op = rsp.record;
  const auto &intent = op.intent;
  const auto &manifest = op.candidate;
  if (rsp.requestId != slot.mutation.getRequest || rsp.clientNamespace != run.owner.client ||
      rsp.shardBytes != run.shardBytes || rsp.contentSha256 != slot.contentSha256 ||
      op.version != meta::kEcCatalogVersion || intent.version != meta::kEcCatalogVersion ||
      manifest.version != meta::kEcCatalogVersion || !owner(op.owner, run.owner) || intent.object != run.object ||
      intent.operation != slot.mutation.operation || intent.stripe != slot.stripe ||
      intent.expectedEpoch != run.epoch || intent.expectedRevision != 0 || intent.kind != meta::EcMutationKind::Write ||
      intent.replacementMask != meta::kEcAllShards || intent.logicalLength != uint64_t(run.shardBytes) * 10 ||
      manifest.logicalLength != intent.logicalLength || manifest.object != run.object ||
      manifest.stripe != slot.stripe || !manifest.generation || !manifest.revision)
    return corrupt();
  if (op.state != meta::EcOperationState::Preparing && op.state != meta::EcOperationState::Published &&
      op.state != meta::EcOperationState::Aborted)
    return corrupt();
  CHECK_RESULT(digest, meta::computeEcRequestDigest(intent, run.shardBytes, slot.contentSha256));
  if (intent.requestDigest != digest ||
      rsp.publishedContentConfirmed != (op.state == meta::EcOperationState::Published))
    return corrupt();
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = manifest.fragments[i];
    const auto &identity = fragment.identity;
    RETURN_ON_ERROR(identity.validate());
    if (identity.object != run.object.incarnation || identity.stripe != slot.stripe ||
        identity.generation != manifest.generation || identity.shard != i || fragment.operation != intent.operation ||
        fragment.placement != intent.placements[i] || !fragment.placement.node.toUnderType() ||
        !fragment.placement.chain.toUnderType() || !fragment.placement.target.toUnderType())
      return corrupt();
    // Unbound Preparing/Aborted records retain the original zero descriptor.
    // Published always requires the complete bound content description.
    if (op.state == meta::EcOperationState::Published || fragment.integrity != storage::EcIntegrityDescriptor{}) {
      RETURN_ON_ERROR(storage::validateEcIntegrity(identity, fragment.integrity));
      if (fragment.integrity.wholeLength != run.shardBytes ||
          fragment.integrity.wholeCrc32c != intent.fragmentCrc32c[i])
        return corrupt();
    }
    for (size_t j = 0; j != i; ++j) {
      const auto &other = manifest.fragments[j];
      if (identity.allocation == other.identity.allocation || fragment.placement.chain == other.placement.chain ||
          fragment.placement.target == other.placement.target)
        return corrupt();
    }
  }
  if (rsp.drain) {
    const auto &d = *rsp.drain;
    const auto expected = op.state == meta::EcOperationState::Published ? meta::EcV2DrainState::Published
                          : op.state == meta::EcOperationState::Aborted ? meta::EcV2DrainState::Aborted
                                                                        : meta::EcV2DrainState::Closing;
    if ((op.state == meta::EcOperationState::Published && d.retiredEndpoints != 0) ||
        d.revocation.is_nil() || d.state != expected || d.expectedEndpoints != 12 || d.terminalEndpoints() > 12 ||
        (op.state != meta::EcOperationState::Preparing && d.terminalEndpoints() != 12))
      return corrupt();
  } else if (op.state != meta::EcOperationState::Preparing)
    return corrupt();
  // Physical instances and historical ACK signatures are checked by Meta45
  // against ECVR/ECVO/ECVA/ECVD/ECVC in its read transaction. Its narrow response
  // intentionally contains no instances, reservations or grants to fabricate.
  return Void{};
}
Result<Void> validateFilePublished(const EcFileRunRecord &run, size_t index, const meta::EcV2MutationRsp &rsp) {
  if (index >= run.count || run.kind != EcFileRunKind::AppendAt) return corrupt();
  const auto &slot = run.slots[index];
  const auto &op = rsp.record;
  const auto &intent = op.intent;
  const auto &manifest = op.candidate;
  const auto &expected = run.owner;
  if (op.version != meta::kEcCatalogVersion || intent.version != meta::kEcCatalogVersion ||
      manifest.version != meta::kEcCatalogVersion || rsp.object.version != meta::kEcCatalogVersion ||
      op.state != meta::EcOperationState::Published || !owner(op.owner, expected) || intent.object != run.object ||
      intent.operation != slot.mutation.operation || intent.stripe != slot.stripe || intent.expectedRevision != 0 ||
      intent.expectedEpoch != run.epoch || intent.logicalLength != uint64_t(run.shardBytes) * 10 ||
      intent.kind != meta::EcMutationKind::Write || intent.replacementMask != meta::kEcAllShards ||
      manifest.object != run.object || manifest.stripe != slot.stripe || !manifest.generation || !manifest.revision ||
      manifest.logicalLength != uint64_t(run.shardBytes) * 10 || rsp.object.object != run.object ||
      rsp.object.shardBytes != run.shardBytes || !rsp.reservation || !rsp.allocations)
    return corrupt();
  const auto &reservation = *rsp.reservation;
  if (reservation.version != meta::kEcV2LifecycleVersion || reservation.original.version != meta::kEcCatalogVersion ||
      reservation.original.candidate.version != meta::kEcCatalogVersion ||
      reservation.original.state != meta::EcOperationState::Preparing ||
      !serde::equals(reservation.original.intent, intent) || !owner(reservation.original.owner, expected) ||
      reservation.original.candidate.object != manifest.object ||
      reservation.original.candidate.stripe != manifest.stripe ||
      reservation.original.candidate.generation != manifest.generation ||
      reservation.original.candidate.revision != manifest.revision ||
      reservation.original.candidate.logicalLength != manifest.logicalLength ||
      reservation.contentSha256 != slot.contentSha256)
    return corrupt();
  CHECK_RESULT(digest, meta::computeEcRequestDigest(intent, run.shardBytes, reservation.contentSha256));
  if (digest != intent.requestDigest) return corrupt();
  const auto &set = reservation.operationEndpoints;
  if (set.count != 12 || !rsp.drain || rsp.drain->state != meta::EcV2DrainState::Published ||
      rsp.drain->revocation.is_nil() || rsp.drain->expectedEndpoints != set.count ||
      rsp.drain->acknowledgedEndpoints != set.count)
    return corrupt();
  std::array<storage::EcScopeEndpoint, 24> endpoints{};
  for (size_t i = 0; i != set.endpoints.size(); ++i) {
    if (i >= set.count) {
      if (set.endpoints[i] != meta::EcV2PhysicalEndpoint{}) return corrupt();
      continue;
    }
    for (size_t j = 0; j != i; ++j)
      if (set.endpoints[i] == set.endpoints[j]) return corrupt();
    endpoints[i] = set.endpoints[i].controlEndpoint();
  }
  CHECK_RESULT(endpointDigest, storage::computeEcScopeEndpointDigest(std::span(endpoints.data(), set.count)));
  if (endpointDigest != set.digest) return corrupt();
  for (size_t i = 0; i != 12; ++i) {
    const auto &binding = (*rsp.allocations)[i];
    const auto &fragment = binding.fragment;
    const auto &identity = fragment.identity;
    const auto &reserved = reservation.candidates[i];
    const auto &original = reservation.original.candidate.fragments[i];
    RETURN_ON_ERROR(identity.validate());
    RETURN_ON_ERROR(storage::validateEcIntegrity(identity, fragment.integrity));
    if (binding.version != meta::kEcBindingCatalogVersion || binding.object != run.object ||
        !(fragment == manifest.fragments[i]) || identity.object != run.object.incarnation ||
        identity.stripe != manifest.stripe || identity.generation != manifest.generation || identity.shard != i ||
        fragment.operation.is_nil() || binding.writer.client.is_nil() || !fragment.placement.node.toUnderType() ||
        !fragment.placement.chain.toUnderType() || !fragment.placement.target.toUnderType() ||
        binding.engineUuid.is_nil() || binding.targetIncarnation.is_nil() ||
        fragment.placement != intent.placements[i] || fragment.integrity.wholeLength != run.shardBytes ||
        fragment.integrity.wholeCrc32c != intent.fragmentCrc32c[i] || !serde::equals(identity, original.identity) ||
        fragment.operation != original.operation || fragment.placement != original.placement ||
        original.integrity != storage::EcIntegrityDescriptor{} || !serde::equals(identity, reserved.identity) ||
        fragment.operation != reserved.operation || binding.endpoint() != reserved.endpoint ||
        !owner(binding.writer, reserved.writer) ||
        std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, binding.endpoint()) ==
            set.endpoints.begin() + set.count)
      return corrupt();
    // Every allocation of this append belongs to the original write identity.
    if ((intent.replacementMask & (1u << i)) &&
        (fragment.operation != slot.mutation.operation || !owner(binding.writer, expected)))
      return corrupt();
    for (size_t previous = 0; previous != i; ++previous) {
      const auto &other = (*rsp.allocations)[previous];
      if (identity.allocation == other.fragment.identity.allocation ||
          fragment.placement.target == other.fragment.placement.target ||
          fragment.placement.chain == other.fragment.placement.chain)
        return corrupt();
    }
  }
  return Void{};
}

}  // namespace hf3fs::client::ec::detail
