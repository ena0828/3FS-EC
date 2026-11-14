#include "fbs/meta/EcFileOutputResolution.h"

#include <algorithm>
#include <openssl/evp.h>
#include <span>
#include <string>

namespace hf3fs::meta {
Result<storage::EcSha256> ecFileOutputResolutionDigest(std::string_view domain, std::string_view bytes) {
  std::string input(domain);
  input.push_back('\0');
  input.append(bytes);
  storage::EcSha256 result{};
  unsigned int size = 0;
  if (EVP_Digest(input.data(), input.size(), result.data(), &size, EVP_sha256(), nullptr) != 1 ||
      size != result.size())
    return makeError(StatusCode::kIOError, "file output resolution digest failed");
  return result;
}
Result<storage::EcSha256> ecFileOutputCandidateDigest(const std::array<EcV2ReservedAllocation, 12> &candidates) {
  return ecFileOutputResolutionDigest("hf3fs.ec.file-output.candidates.v1", serde::serialize(candidates));
}
Result<storage::EcSha256> ecFileOutputZeroSourceDigest(const EcFileOutputIdentity &identity, const Uuid &birth,
                                                    uint64_t epoch) {
  auto bytes = serde::serialize(identity);
  bytes.append(serde::serialize(birth));
  bytes.append(serde::serialize(epoch));
  return ecFileOutputResolutionDigest("hf3fs.ec.file-output.zero-source.v1", bytes);
}
namespace {
Result<Void> closureValid(const EcFileOutputDrain &d, const EcFileOutputResolution &r, bool source) {
  const auto &id = d.identity;
  const auto &set = id.endpoints;
  if ((d.version != kEcV2LifecycleVersion && d.version != kEcV2RetirementDrainVersion) ||
      id.object != r.identity.object || !serde::equals(id.owner, r.identity.owner) || id.objectEpoch != r.childEpoch ||
      id.scopeId != (source ? r.sourcePin : r.identity.child) || id.clusterAuthority.is_nil() ||
      id.revocationId.is_nil() || !id.generation || !id.revision ||
      id.kind != (source ? storage::EcGrantScope::ReadPin : storage::EcGrantScope::WriteOperation) ||
      d.state != (source ? EcV2DrainState::ReadReleased : EcV2DrainState::Aborted) ||
      d.recordDigest == storage::EcSha256{} || !set.count || set.count > set.endpoints.size() ||
      (d.ackMask >> set.count) != 0 ||
      d.terminalUse != (d.version == kEcV2LifecycleVersion ? EcV2DrainUse::AckOnly
                           : source ? EcV2DrainUse::ReadRelease : EcV2DrainUse::AbortOnly))
    return makeError(StatusCode::kDataCorruption, "invalid resolution closure identity");
  std::array<storage::EcScopeEndpoint, 24> endpoints{};
  for (size_t n = 0; n < set.endpoints.size(); ++n) {
    const bool ack = (d.ackMask & (uint32_t{1} << n)) != 0;
    const auto &ref = d.retirements[n];
    if (n >= set.count) {
      if (set.endpoints[n] != EcV2PhysicalEndpoint{} || ref)
        return makeError(StatusCode::kDataCorruption, "nonempty unused closure slot");
      continue;
    }
    const auto &e = set.endpoints[n];
    if (e.placement.node == flat::NodeId{} || e.placement.chain == storage::ChainId{} ||
        e.placement.target == storage::TargetId{} || e.engineUuid.is_nil() || e.targetIncarnation.is_nil() ||
        ack == ref.has_value() || (ref && (d.version != kEcV2RetirementDrainVersion ||
        ref->retirementId.is_nil() || ref->completionDigest == storage::EcSha256{})))
      return makeError(StatusCode::kDataCorruption, "incomplete resolution endpoint closure");
    for (size_t p = 0; p < n; ++p)
      if (set.endpoints[p] == e) return makeError(StatusCode::kDataCorruption, "duplicate closure endpoint");
    endpoints[n] = e.controlEndpoint();
  }
  CHECK_RESULT(digest, storage::computeEcScopeEndpointDigest(std::span(endpoints).first(set.count)));
  if (digest != set.digest) return makeError(StatusCode::kDataCorruption, "closure endpoint digest mismatch");
  return Void{};
}
}  // namespace
Result<Void> EcFileOutputResolution::valid() const {
  RETURN_ON_ERROR(identity.valid());
  if (version != 1 || resolutionId.is_nil() || confirmingClientNamespace.is_nil() || birth.is_nil() ||
      !childEpoch || !candidateReservationsReleaseEligible || collected || physicalReclamationConfirmed ||
      executionDigest == storage::EcSha256{} ||
      kind != (issuanceSequence == 0 ? EcFileOutputResolutionKind::NoIssuanceAfterClose
                                    : EcFileOutputResolutionKind::NeverBoundAfterClose))
    return makeError(StatusCode::kDataCorruption, "invalid file output resolution");
  RETURN_ON_ERROR(closureValid(outputClosure, *this, false));
  if (outputClosureDigest != outputClosure.recordDigest)
    return makeError(StatusCode::kDataCorruption, "output closure digest mismatch");
  for (size_t n = 0; n < candidates.size(); ++n) {
    const auto &a = candidates[n];
    RETURN_ON_ERROR(a.identity.validate());
    const auto &set = outputClosure.identity.endpoints;
    if (a.identity.object != identity.object.incarnation || a.identity.shard != n ||
        a.identity.stripe != candidates[0].identity.stripe ||
        a.identity.generation != outputClosure.identity.generation || a.operation != identity.child ||
        !serde::equals(a.writer, identity.owner) ||
        std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, a.endpoint) == set.endpoints.begin() + set.count)
      return makeError(StatusCode::kDataCorruption, "resolution candidate identity changed");
    for (size_t p = 0; p < n; ++p)
      if (candidates[p].identity.allocation == a.identity.allocation)
        return makeError(StatusCode::kDataCorruption, "duplicate candidate allocation");
  }
  CHECK_RESULT(candidatesSha, ecFileOutputCandidateDigest(candidates));
  if (candidatesSha != candidateDigest) return makeError(StatusCode::kDataCorruption, "candidate digest mismatch");
  if (sourceKind == EcTreeSlotKind::Data) {
    if (sourcePin.is_nil() || !sourceClosure) return makeError(StatusCode::kDataCorruption, "source closure missing");
    RETURN_ON_ERROR(closureValid(*sourceClosure, *this, true));
    if (sourceClosureDigest != sourceClosure->recordDigest ||
        sourceClosure->identity.clusterAuthority != outputClosure.identity.clusterAuthority)
      return makeError(StatusCode::kDataCorruption, "source closure digest mismatch");
  } else if (sourceKind == EcTreeSlotKind::Zero) {
    if (!sourcePin.is_nil() || sourceClosure) return makeError(StatusCode::kDataCorruption, "zero source has a pin");
    CHECK_RESULT(zeroSha, ecFileOutputZeroSourceDigest(identity, birth, childEpoch));
    if (sourceClosureDigest != zeroSha) return makeError(StatusCode::kDataCorruption, "zero source digest mismatch");
  } else return makeError(StatusCode::kDataCorruption, "unknown source kind");
  return Void{};
}
}  // namespace hf3fs::meta
