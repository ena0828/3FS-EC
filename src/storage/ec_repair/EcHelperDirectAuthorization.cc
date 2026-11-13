#include "EcHelperDirectAuthorization.h"

#include <algorithm>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"
#include "fbs/storage/EcStageValidationV2.h"

namespace hf3fs::storage {
namespace {
void integer(std::string &out, uint64_t value, size_t width) {
  for (size_t i = width; i != 0; --i) out.push_back(static_cast<char>(value >> ((i - 1) * 8)));
}
void hash(std::string &out, const EcSha256 &value) {
  out.append(reinterpret_cast<const char *>(value.data()), value.size());
}
void endpoint(std::string &out, const EcScopeEndpoint &value) {
  integer(out, value.nodeId.toUnderType(), 4);
  integer(out, value.chainId.toUnderType(), 4);
  integer(out, value.targetId.toUnderType(), 8);
  out.append(value.engineUuid.asStringView());
  out.append(value.targetIncarnation.asStringView());
}
bool sameEndpoint(const EcScopeEndpoint &a, const EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId &&
         a.engineUuid == b.engineUuid && a.targetIncarnation == b.targetIncarnation;
}
template <typename T>
bool same(const T &a, const T &b) {
  return serde::serialize(a) == serde::serialize(b);
}
template <typename T>
void field(std::string &out, const T &value) {
  const auto encoded = serde::serialize(value);
  integer(out, encoded.size(), 8);
  out.append(encoded);
}
Result<EcSha256> sha256(std::string_view value) {
  EcSha256 result{};
  unsigned int size = 0;
  if (EVP_Digest(value.data(), value.size(), result.data(), &size, EVP_sha256(), nullptr) != 1 ||
      size != result.size())
    return makeError(StatusCode::kIOError, "direct helper SHA-256 failed");
  return result;
}
Result<Void> lifetime(uint64_t issued, uint64_t expires) {
  if (expires <= issued || expires - issued > kEcHelperMaxTtlSeconds)
    return makeError(StatusCode::kAuthenticationFail, "direct helper lifetime is invalid");
  return Void{};
}
Result<Void> time(uint64_t issued, uint64_t expires, uint64_t now) {
  RETURN_ON_ERROR(lifetime(issued, expires));
  if (issued > now || expires <= now)
    return makeError(StatusCode::kAuthenticationFail, "direct helper authority is not currently valid");
  return Void{};
}
Result<Void> dataBinding(const EcRepairPlan &plan,
                         const EcRepairFragment &fragment,
                         const EcCapabilityV2 &grant,
                         EcGrantRightV2 right) {
  const auto &c = grant.claims;
  CHECK_RESULT(integrity, digestEcIntegrityV2(fragment.identity, fragment.integrity));
  if (c.version != kEcGrantVersionV2 || c.rights != uint16_t(right) || c.grantId.is_nil() ||
      !same(c.identity, fragment.identity) || c.fragmentOperationId != fragment.operationId ||
      c.engineUuid != fragment.endpoint.engineUuid || c.targetIncarnation != fragment.endpoint.targetIncarnation ||
      c.nodeId != fragment.endpoint.nodeId || c.chainId != fragment.endpoint.chainId ||
      c.targetId != fragment.endpoint.targetId || c.expectedLength != fragment.integrity.wholeLength ||
      c.expectedCrc32c != fragment.integrity.wholeCrc32c || c.integrityDigest != integrity ||
      c.ownerUid != plan.input().ownerUid || c.clientNamespace != plan.input().clientNamespace ||
      c.scopeObject != fragment.identity.object || c.scopeKind != EcGrantScope::WriteOperation ||
      c.scopeId != plan.input().operationId)
    return makeError(StatusCode::kAuthenticationFail, "direct data authority differs from fixed plan or exact role");
  return lifetime(c.issuedAtSeconds, c.expiresAtSeconds);
}
Result<Void> dataSlots(const EcRepairPlan &plan, const EcHelperDirectDelegation &d) {
  for (size_t i = 0; i != 2; ++i) {
    if (i < plan.input().targetCount) {
      RETURN_ON_ERROR(dataBinding(plan, plan.input().targets[i], d.appendGrants[i], EcGrantRightV2::Append));
      RETURN_ON_ERROR(dataBinding(plan, plan.input().targets[i], d.queryGrants[i], EcGrantRightV2::Query));
    } else if (!same(d.appendGrants[i], EcCapabilityV2{}) || !same(d.queryGrants[i], EcCapabilityV2{})) {
      return makeError(StatusCode::kAuthenticationFail, "unused direct data authority must be empty");
    }
  }
  return Void{};
}
Result<EcSha256> delegationDigest(const EcHelperDirectDelegation &d) {
  std::string bytes("3FSECDD1", 8);
  for (const auto &grant : d.appendGrants) field(bytes, grant);
  for (const auto &grant : d.queryGrants) field(bytes, grant);
  return sha256(bytes);
}
std::string canonical(const EcHelperDirectClaims &c) {
  std::string out("3FSECDG1", 8);
  integer(out, c.version, 2);
  hash(out, c.planDigest);
  hash(out, c.delegationDigest);
  endpoint(out, c.lastHelper);
  integer(out, c.targetCount, 1);
  integer(out, c.maxBlocksInFlight, 1);
  integer(out, c.blockMask, 2);
  out.append(c.grantId.asStringView());
  integer(out, c.issuedAtSeconds, 8);
  integer(out, c.expiresAtSeconds, 8);
  return out;
}
std::string canonical(const EcHelperDirectStamp &s, std::string_view domain) {
  std::string out(domain);
  integer(out, s.version, 2);
  hash(out, s.contextDigest);
  hash(out, s.valueDigest);
  integer(out, s.senderPosition, 1);
  integer(out, s.recipientPosition, 1);
  integer(out, s.issuedAtSeconds, 8);
  integer(out, s.expiresAtSeconds, 8);
  return out;
}
uint64_t expires(const EcRepairPlan &plan, const EcHelperDirectHopReq &request) {
  auto result = request.delegation.directGrant.claims.expiresAtSeconds;
  for (size_t i = 0; i != 10; ++i) {
    result = std::min(result, request.helpers[i].claims.expiresAtSeconds);
    result = std::min(result, request.reads[i].claims.expiresAtSeconds);
  }
  for (size_t i = 0; i != plan.input().targetCount; ++i) {
    result = std::min(result, request.delegation.appendGrants[i].claims.expiresAtSeconds);
    result = std::min(result, request.delegation.queryGrants[i].claims.expiresAtSeconds);
  }
  return result;
}
Result<Void> requestTimes(const EcRepairPlan &plan, const EcHelperDirectHopReq &request, uint64_t now) {
  // Runtime enforces the finer millisecond/steady deadline, including after
  // waits. This second-resolution check must never extend the signed envelope.
  if (request.deadlineUnixMillis / 1000 < now)
    return makeError(StorageClientCode::kTimeout, "direct helper deadline elapsed");
  for (size_t i = 0; i != 10; ++i) {
    RETURN_ON_ERROR(time(request.helpers[i].claims.issuedAtSeconds, request.helpers[i].claims.expiresAtSeconds, now));
    RETURN_ON_ERROR(time(request.reads[i].claims.issuedAtSeconds, request.reads[i].claims.expiresAtSeconds, now));
  }
  for (size_t i = 0; i != plan.input().targetCount; ++i) {
    RETURN_ON_ERROR(time(request.delegation.appendGrants[i].claims.issuedAtSeconds,
                         request.delegation.appendGrants[i].claims.expiresAtSeconds, now));
    RETURN_ON_ERROR(time(request.delegation.queryGrants[i].claims.issuedAtSeconds,
                         request.delegation.queryGrants[i].claims.expiresAtSeconds, now));
  }
  return Void{};
}
Result<EcSha256> resultDigest(const EcHelperDirectHopResult &r) {
  std::string out("3FSECDR1", 8);
  integer(out, r.version, 2);
  hash(out, r.planDigest);
  hash(out, r.contextDigest);
  integer(out, r.blockIndex, 4);
  integer(out, r.targetCount, 1);
  integer(out, r.activeTargetMask, 1);
  integer(out, r.appendedTargetMask, 1);
  for (const auto &state : r.states) field(out, state);
  return sha256(out);
}
Result<Void> resultFields(const EcRepairPlan &plan,
                           const EcHelperDirectHopReq &request,
                           const EcHelperDirectHopResult &result) {
  RETURN_ON_ERROR(validateEcHelperDirectRequest(plan, request));
  CHECK_RESULT(context, digestEcHelperDirectContext(plan, request));
  if (result.version != kEcHelperDirectVersion || result.planDigest != plan.digest() ||
      result.contextDigest != context || result.blockIndex != request.packet.blockIndex ||
      result.targetCount != plan.input().targetCount || result.activeTargetMask != request.activeTargetMask ||
      result.appendedTargetMask != request.activeTargetMask)
    return makeError(StatusCode::kDataCorruption, "direct result differs from fixed request context");
  for (size_t i = 0; i != 2; ++i) {
    const auto &state = result.states[i];
    if (!(result.activeTargetMask & (uint8_t{1} << i))) {
      if (!same(state, EcStageStateV2{}))
        return makeError(StatusCode::kDataCorruption, "unused direct result state must be empty");
      continue;
    }
    const auto &target = plan.input().targets[i];
    EcFragmentAccessV2 access;
    access.identity = target.identity;
    access.operationId = target.operationId;
    access.vChainId = {target.endpoint.chainId, request.targetRouteVersions[i]};
    access.targetId = target.endpoint.targetId;
    access.integrity = target.integrity;
    RETURN_ON_ERROR(validateEcStageStateV2(state, access, request.delegation.appendGrants[i].claims));
    const auto end = request.packet.blockIndex * kEcIntegrityBlockBytes +
                     target.integrity.blocks[request.packet.blockIndex].validLength;
    if (state.state != 1 || state.pendingBlock || state.needsReconcile || state.prefixBytes < end)
      return makeError(StorageCode::kEcSealOutcomeUnknown, "direct Append state is not confirmed");
  }
  return Void{};
}
}  // namespace

namespace ec_helper_direct_detail {
struct Access {
  static Result<EcSha256> mac(const EcHelperKey &key, std::string_view value) {
    return ec_authorization_detail::Access::authenticate(
        *key.key_, {reinterpret_cast<const uint8_t *>(value.data()), value.size()});
  }
  static void set(EcHelperDirectGrant &g, const EcSha256 &s) { g.signature_ = s; }
  static void set(EcHelperDirectStamp &g, const EcSha256 &s) { g.signature_ = s; }
  static bool matches(const EcHelperDirectGrant &g, const EcSha256 &s) {
    return ec_authorization_detail::Access::constantTimeEqual(g.signature_, s);
  }
  static bool matches(const EcHelperDirectStamp &g, const EcSha256 &s) {
    return ec_authorization_detail::Access::constantTimeEqual(g.signature_, s);
  }
  static bool empty(const EcHelperDirectStamp &s) { return same(s, EcHelperDirectStamp{}); }
};
}  // namespace ec_helper_direct_detail

Result<EcHelperDirectDelegation> issueEcHelperDirectDelegation(const EcHelperKey &key,
                                                              const EcRepairPlan &plan,
                                                              std::array<EcCapabilityV2, 2> appendGrants,
                                                              std::array<EcCapabilityV2, 2> queryGrants,
                                                              uint16_t blockMask,
                                                              uint64_t now,
                                                              uint64_t ttl) {
  if (!ttl || ttl > kEcHelperMaxTtlSeconds || now > UINT64_MAX - ttl || !blockMask ||
      (uint32_t(blockMask) >> plan.blockCount()) != 0)
    return makeError(StatusCode::kInvalidArg, "invalid direct blocks or issuance lifetime");
  EcHelperDirectDelegation d;
  d.appendGrants = std::move(appendGrants);
  d.queryGrants = std::move(queryGrants);
  RETURN_ON_ERROR(dataSlots(plan, d));
  auto &c = d.directGrant.claims;
  c.planDigest = plan.digest();
  CHECK_RESULT(digest, delegationDigest(d));
  c.delegationDigest = digest;
  c.lastHelper = plan.input().sources[9].endpoint;
  c.targetCount = plan.input().targetCount;
  c.maxBlocksInFlight = plan.input().maxBlocksInFlight;
  c.blockMask = blockMask;
  c.grantId = Uuid::random();
  c.issuedAtSeconds = now;
  c.expiresAtSeconds = now + ttl;
  for (size_t i = 0; i != c.targetCount; ++i) {
    for (const auto *grant : {&d.appendGrants[i], &d.queryGrants[i]}) {
      RETURN_ON_ERROR(time(grant->claims.issuedAtSeconds, grant->claims.expiresAtSeconds, now));
      c.expiresAtSeconds = std::min(c.expiresAtSeconds, grant->claims.expiresAtSeconds);
    }
  }
  CHECK_RESULT(signature, ec_helper_direct_detail::Access::mac(key, canonical(c)));
  ec_helper_direct_detail::Access::set(d.directGrant, signature);
  return d;
}

Result<Void> validateEcHelperDirectDelegation(const EcRepairPlan &plan,
                                              const EcHelperDirectDelegation &d,
                                              uint32_t block) {
  RETURN_ON_ERROR(dataSlots(plan, d));
  const auto &c = d.directGrant.claims;
  RETURN_ON_ERROR(lifetime(c.issuedAtSeconds, c.expiresAtSeconds));
  if (c.version != kEcHelperDirectVersion || c.planDigest != plan.digest() || c.grantId.is_nil() ||
      !sameEndpoint(c.lastHelper, plan.input().sources[9].endpoint) || c.targetCount != plan.input().targetCount ||
      c.maxBlocksInFlight != plan.input().maxBlocksInFlight || block >= plan.blockCount() || !c.blockMask ||
      (uint32_t(c.blockMask) >> plan.blockCount()) != 0 || !(c.blockMask & (uint16_t{1} << block)))
    return makeError(StatusCode::kAuthenticationFail, "direct authority differs from fixed plan, blocks or last hop");
  CHECK_RESULT(digest, delegationDigest(d));
  if (c.delegationDigest != digest)
    return makeError(StatusCode::kAuthenticationFail, "direct delegation commitment mismatch");
  for (size_t i = 0; i != c.targetCount; ++i) {
    for (const auto *grant : {&d.appendGrants[i], &d.queryGrants[i]}) {
      if (c.issuedAtSeconds < grant->claims.issuedAtSeconds || c.expiresAtSeconds > grant->claims.expiresAtSeconds)
        return makeError(StatusCode::kAuthenticationFail, "direct authority exceeds delegated data lifetime");
    }
  }
  return Void{};
}

Result<Void> verifyEcHelperDirectDelegation(const EcHelperKey &key,
                                            const EcRepairPlan &plan,
                                            const EcHelperDirectDelegation &d,
                                            uint32_t block,
                                            uint64_t now) {
  RETURN_ON_ERROR(validateEcHelperDirectDelegation(plan, d, block));
  RETURN_ON_ERROR(time(d.directGrant.claims.issuedAtSeconds, d.directGrant.claims.expiresAtSeconds, now));
  CHECK_RESULT(signature, ec_helper_direct_detail::Access::mac(key, canonical(d.directGrant.claims)));
  if (!ec_helper_direct_detail::Access::matches(d.directGrant, signature))
    return makeError(StatusCode::kAuthenticationFail, "direct authority MAC mismatch");
  return Void{};
}

Result<Void> validateEcHelperDirectRequest(const EcRepairPlan &plan, const EcHelperDirectHopReq &r) {
  if (r.version != kEcHelperDirectVersion || !same(r.plan, plan.input()) || !r.deadlineUnixMillis ||
      !r.activeTargetMask || (uint32_t(r.activeTargetMask) >> plan.input().targetCount) != 0 ||
      r.packet.nextHelper >= 10)
    return makeError(StatusCode::kInvalidArg, "invalid direct request identity, mask or hop");
  RETURN_ON_ERROR(validateEcHelperDirectDelegation(plan, r.delegation, r.packet.blockIndex));
  RETURN_ON_ERROR(EcRepairBlockCore::validate(plan, repairBlock(r.packet), r.packet.nextHelper));
  for (size_t i = 0; i != 10; ++i) {
    if (r.sourceRouteVersions[i] == ChainVer{})
      return makeError(StatusCode::kInvalidArg, "direct source route is missing");
  }
  for (size_t i = 0; i != 2; ++i) {
    if ((r.targetRouteVersions[i] != ChainVer{}) != (i < plan.input().targetCount))
      return makeError(StatusCode::kInvalidArg, "direct target route is missing or unused");
  }
  return Void{};
}

Result<EcSha256> digestEcHelperDirectContext(const EcRepairPlan &plan, const EcHelperDirectHopReq &r) {
  RETURN_ON_ERROR(validateEcHelperDirectRequest(plan, r));
  std::string out("3FSECDC1", 8);
  integer(out, r.version, 2);
  hash(out, plan.digest());
  field(out, r.delegation);
  for (const auto &grant : r.helpers) field(out, grant);
  for (const auto &grant : r.reads) field(out, grant);
  for (auto route : r.sourceRouteVersions) integer(out, route.toUnderType(), 4);
  for (auto route : r.targetRouteVersions) integer(out, route.toUnderType(), 4);
  integer(out, r.activeTargetMask, 1);
  integer(out, r.packet.blockIndex, 4);
  integer(out, r.deadlineUnixMillis, 8);
  return sha256(out);
}

Result<Void> verifyEcHelperDirectPredecessor(const EcHelperKey &key,
                                             const EcRepairPlan &plan,
                                             const EcHelperDirectHopReq &r,
                                             uint64_t now) {
  RETURN_ON_ERROR(validateEcHelperDirectRequest(plan, r));
  RETURN_ON_ERROR(verifyEcHelperDirectDelegation(key, plan, r.delegation, r.packet.blockIndex, now));
  RETURN_ON_ERROR(requestTimes(plan, r, now));
  if (!r.packet.nextHelper) {
    if (!ec_helper_direct_detail::Access::empty(r.predecessor))
      return makeError(StatusCode::kAuthenticationFail, "first direct predecessor must be empty");
    return Void{};
  }
  const auto &s = r.predecessor;
  if (s.version != kEcHelperDirectVersion || s.senderPosition != r.packet.nextHelper - 1 ||
      s.recipientPosition != r.packet.nextHelper || s.expiresAtSeconds > expires(plan, r))
    return makeError(StatusCode::kAuthenticationFail, "direct predecessor position or lifetime mismatch");
  RETURN_ON_ERROR(time(s.issuedAtSeconds, s.expiresAtSeconds, now));
  CHECK_RESULT(context, digestEcHelperDirectContext(plan, r));
  CHECK_RESULT(packet, EcRepairBlockCore::digestPacket(plan, repairBlock(r.packet)));
  if (s.contextDigest != context || s.valueDigest != packet)
    return makeError(StatusCode::kAuthenticationFail, "direct predecessor context or packet mismatch");
  CHECK_RESULT(signature, ec_helper_direct_detail::Access::mac(key, canonical(s, "3FSECDP1")));
  if (!ec_helper_direct_detail::Access::matches(s, signature))
    return makeError(StatusCode::kAuthenticationFail, "direct predecessor MAC mismatch");
  return Void{};
}

Result<Void> validateEcHelperDirectResult(const EcRepairPlan &plan,
                                         const EcHelperDirectHopReq &request,
                                         const EcHelperDirectHopResult &result) {
  RETURN_ON_ERROR(resultFields(plan, request, result));
  CHECK_RESULT(digest, resultDigest(result));
  const auto &stamp = result.finalStamp;
  if (stamp.version != kEcHelperDirectVersion || stamp.senderPosition != 9 || stamp.recipientPosition != 255 ||
      stamp.contextDigest != result.contextDigest || stamp.valueDigest != digest ||
      stamp.expiresAtSeconds > expires(plan, request))
    return makeError(StatusCode::kDataCorruption, "direct final stamp fields differ from small result");
  RETURN_ON_ERROR(lifetime(stamp.issuedAtSeconds, stamp.expiresAtSeconds));
  if (serde::serialize(result).size() > kEcHelperDirectResultMaxBytes)
    return makeError(StatusCode::kInvalidFormat, "direct result exceeds its fixed envelope");
  return Void{};
}

Result<Void> verifyEcHelperDirectResult(const EcHelperKey &key,
                                       const EcRepairPlan &plan,
                                       const EcHelperDirectHopReq &request,
                                       const EcHelperDirectHopResult &result,
                                       uint64_t now) {
  RETURN_ON_ERROR(validateEcHelperDirectResult(plan, request, result));
  RETURN_ON_ERROR(verifyEcHelperDirectDelegation(key, plan, request.delegation, request.packet.blockIndex, now));
  RETURN_ON_ERROR(requestTimes(plan, request, now));
  RETURN_ON_ERROR(time(result.finalStamp.issuedAtSeconds, result.finalStamp.expiresAtSeconds, now));
  CHECK_RESULT(signature, ec_helper_direct_detail::Access::mac(key, canonical(result.finalStamp, "3FSECDF1")));
  if (!ec_helper_direct_detail::Access::matches(result.finalStamp, signature))
    return makeError(StatusCode::kAuthenticationFail, "direct final result MAC mismatch");
  return Void{};
}

namespace ec_helper_direct_detail {
Result<EcHelperDirectStamp> stamp(const EcHelperKey &key,
                                  const EcRepairPlan &plan,
                                  const EcHelperDirectHopReq &request,
                                  const EcHelperPacket &computed,
                                  uint64_t now) {
  RETURN_ON_ERROR(verifyEcHelperDirectPredecessor(key, plan, request, now));
  if (request.packet.nextHelper >= 9 || computed.nextHelper != request.packet.nextHelper + 1 ||
      computed.blockIndex != request.packet.blockIndex)
    return makeError(StatusCode::kInvalidArg, "direct predecessor must advance exactly one non-final helper");
  RETURN_ON_ERROR(EcRepairBlockCore::validate(plan, repairBlock(computed), computed.nextHelper));
  EcHelperDirectStamp result;
  CHECK_RESULT(context, digestEcHelperDirectContext(plan, request));
  CHECK_RESULT(value, EcRepairBlockCore::digestPacket(plan, repairBlock(computed)));
  result.contextDigest = context;
  result.valueDigest = value;
  result.senderPosition = request.packet.nextHelper;
  result.recipientPosition = computed.nextHelper;
  result.issuedAtSeconds = now;
  result.expiresAtSeconds = expires(plan, request);
  CHECK_RESULT(signature, Access::mac(key, canonical(result, "3FSECDP1")));
  Access::set(result, signature);
  return result;
}

Result<EcHelperDirectHopResult> finish(const EcHelperKey &key,
                                      const EcRepairPlan &plan,
                                      const EcHelperDirectHopReq &request,
                                      const EcHelperPacket &complete,
                                      std::array<EcStageStateV2, 2> states,
                                      uint64_t now) {
  RETURN_ON_ERROR(verifyEcHelperDirectPredecessor(key, plan, request, now));
  if (request.packet.nextHelper != 9 || complete.blockIndex != request.packet.blockIndex)
    return makeError(StatusCode::kInvalidArg, "only the last direct helper may finish the requested block");
  RETURN_ON_ERROR(EcRepairBlockCore::validateComplete(plan, repairBlock(complete)));
  EcHelperDirectHopResult result;
  result.planDigest = plan.digest();
  CHECK_RESULT(context, digestEcHelperDirectContext(plan, request));
  result.contextDigest = context;
  result.blockIndex = request.packet.blockIndex;
  result.targetCount = plan.input().targetCount;
  result.activeTargetMask = request.activeTargetMask;
  result.appendedTargetMask = request.activeTargetMask;
  result.states = std::move(states);
  RETURN_ON_ERROR(resultFields(plan, request, result));
  auto &stamp = result.finalStamp;
  stamp.contextDigest = context;
  CHECK_RESULT(value, resultDigest(result));
  stamp.valueDigest = value;
  stamp.senderPosition = 9;
  stamp.recipientPosition = 255;
  stamp.issuedAtSeconds = now;
  stamp.expiresAtSeconds = expires(plan, request);
  CHECK_RESULT(signature, Access::mac(key, canonical(stamp, "3FSECDF1")));
  Access::set(stamp, signature);
  RETURN_ON_ERROR(validateEcHelperDirectResult(plan, request, result));
  return result;
}
}  // namespace ec_helper_direct_detail
}  // namespace hf3fs::storage
