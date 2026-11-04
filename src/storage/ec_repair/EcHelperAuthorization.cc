#include "EcHelperAuthorization.h"

#include <algorithm>

#include "fbs/storage/EcAuthorizationCrypto.h"

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
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}
std::span<const uint8_t> bytes(std::string_view value) {
  return {reinterpret_cast<const uint8_t *>(value.data()), value.size()};
}
Result<Void> time(uint64_t issued, uint64_t expires, uint64_t now) {
  if (issued > now || expires <= now || expires <= issued || expires - issued > kEcHelperMaxTtlSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "helper authority expired or has invalid lifetime");
  }
  return Void{};
}
std::string canonical(const EcHelperClaims &claims) {
  std::string out("3FSECHG1", 8);
  integer(out, claims.version, 2);
  integer(out, claims.rights, 2);
  hash(out, claims.planDigest);
  endpoint(out, claims.recipient);
  integer(out, claims.helperPosition, 1);
  integer(out, claims.blockMask, 2);
  out.append(claims.grantId.asStringView());
  integer(out, claims.issuedAtSeconds, 8);
  integer(out, claims.expiresAtSeconds, 8);
  return out;
}
std::string canonical(const EcHelperStamp &value, const EcRepairPlan &plan) {
  std::string out("3FSECHS1", 8);
  integer(out, value.version, 2);
  hash(out, plan.digest());
  hash(out, value.packetDigest);
  integer(out, value.senderPosition, 1);
  integer(out, value.recipientPosition, 1);
  integer(out, value.issuedAtSeconds, 8);
  integer(out, value.expiresAtSeconds, 8);
  return out;
}
Result<Void> shape(const EcHelperClaims &claims, uint64_t now) {
  RETURN_ON_ERROR(time(claims.issuedAtSeconds, claims.expiresAtSeconds, now));
  if (claims.version != kEcHelperVersion || claims.helperPosition >= 10 || claims.blockMask == 0 ||
      claims.rights == 0 || (claims.rights & ~kEcHelperAllRights) || claims.grantId.is_nil() ||
      claims.recipient.nodeId == NodeId{} || claims.recipient.chainId == ChainId{} ||
      claims.recipient.targetId == TargetId{} || claims.recipient.engineUuid.is_nil() ||
      claims.recipient.targetIncarnation.is_nil()) {
    return makeError(StatusCode::kAuthenticationFail, "invalid helper authority shape");
  }
  return Void{};
}
}  // namespace

namespace ec_helper_detail {
struct Access {
  static Result<EcSha256> mac(const EcHelperKey &key, std::string_view value) {
    return ec_authorization_detail::Access::authenticate(*key.key_, bytes(value));
  }
  static void set(EcHelperCapability &value, const EcSha256 &signature) { value.signature_ = signature; }
  static void set(EcHelperStamp &value, const EcSha256 &signature) { value.signature_ = signature; }
  static bool matches(const EcHelperCapability &value, const EcSha256 &signature) {
    return ec_authorization_detail::Access::constantTimeEqual(value.signature_, signature);
  }
  static bool matches(const EcHelperStamp &value, const EcSha256 &signature) {
    return ec_authorization_detail::Access::constantTimeEqual(value.signature_, signature);
  }
  static bool empty(const EcHelperStamp &value) {
    const EcSha256 zero{};
    return value.packetDigest == zero && value.senderPosition == 0 && value.recipientPosition == 0 &&
           value.issuedAtSeconds == 0 && value.expiresAtSeconds == 0 && value.signature_ == zero &&
           value.version == kEcHelperVersion;
  }
};
}  // namespace ec_helper_detail

Result<std::unique_ptr<EcHelperKey>> EcHelperKey::loadFile(const std::filesystem::path &path) {
  CHECK_RESULT(key, EcCapabilityKey::loadFile(path));
  return std::unique_ptr<EcHelperKey>(new EcHelperKey(std::move(key)));
}

Result<EcHelperClaims> makeEcHelperClaims(const EcRepairPlan &plan,
                                          uint8_t position,
                                          uint16_t mask,
                                          uint64_t now,
                                          uint64_t ttl) {
  if (position >= 10 || ttl == 0 || ttl > kEcHelperMaxTtlSeconds || now > UINT64_MAX - ttl || mask == 0 ||
      (uint32_t(mask) >> plan.blockCount()) != 0) {
    return makeError(StatusCode::kInvalidArg, "helper claim position, blocks or lifetime is invalid");
  }
  EcHelperClaims value;
  value.rights = position == 9 ? uint16_t(EcHelperRight::Compute) : kEcHelperAllRights;
  value.planDigest = plan.digest();
  value.recipient = plan.input().sources[position].endpoint;
  value.helperPosition = position;
  value.blockMask = mask;
  value.grantId = Uuid::random();
  value.issuedAtSeconds = now;
  value.expiresAtSeconds = now + ttl;
  return value;
}

Result<EcHelperCapability> signEcHelperGrant(const EcHelperKey &key, const EcHelperClaims &claims, uint64_t now) {
  RETURN_ON_ERROR(shape(claims, now));
  CHECK_RESULT(signature, ec_helper_detail::Access::mac(key, canonical(claims)));
  EcHelperCapability result;
  result.claims = claims;
  ec_helper_detail::Access::set(result, signature);
  return result;
}

Result<Void> verifyEcHelperGrant(const EcHelperKey &key,
                                 const EcHelperCapability &grant,
                                 const EcRepairPlan &plan,
                                 const EcScopeEndpoint &actual,
                                 uint8_t position,
                                 uint32_t block,
                                 uint64_t now) {
  const auto &claims = grant.claims;
  RETURN_ON_ERROR(shape(claims, now));
  const auto rights = position == 9 ? uint16_t(EcHelperRight::Compute) : kEcHelperAllRights;
  if (position >= 10 || block >= plan.blockCount() || claims.helperPosition != position ||
      claims.planDigest != plan.digest() || !sameEndpoint(actual, plan.input().sources[position].endpoint) ||
      !sameEndpoint(claims.recipient, actual) || (claims.rights & rights) != rights ||
      !(claims.blockMask & (uint16_t{1} << block)) || (uint32_t(claims.blockMask) >> plan.blockCount()) != 0) {
    return makeError(StatusCode::kAuthenticationFail,
                     "helper authority does not bind this plan, hop, instance or block");
  }
  CHECK_RESULT(signature, ec_helper_detail::Access::mac(key, canonical(claims)));
  if (!ec_helper_detail::Access::matches(grant, signature))
    return makeError(StatusCode::kAuthenticationFail, "helper MAC mismatch");
  return Void{};
}

EcHelperPacket helperPacket(EcRepairBlock block) {
  EcHelperPacket result;
  result.planDigest = block.planDigest;
  result.blockIndex = block.blockIndex;
  result.contributorMask = block.contributorMask;
  result.nextHelper = block.nextHelper;
  result.targetCount = block.targetCount;
  for (size_t i = 0; i != 2; ++i) result.outputs[i].data = std::move(block.outputs[i]);
  return result;
}
EcRepairBlock repairBlock(EcHelperPacket packet) {
  EcRepairBlock result;
  result.planDigest = packet.planDigest;
  result.blockIndex = packet.blockIndex;
  result.contributorMask = packet.contributorMask;
  result.nextHelper = packet.nextHelper;
  result.targetCount = packet.targetCount;
  for (size_t i = 0; i != 2; ++i) result.outputs[i] = std::move(packet.outputs[i].data);
  return result;
}

namespace ec_helper_detail {
Result<EcHelperStamp> stamp(const EcHelperKey &key,
                            const EcRepairPlan &plan,
                            const EcHelperPacket &packet,
                            uint64_t now,
                            uint64_t expires) {
  RETURN_ON_ERROR(time(now, expires, now));
  if (packet.nextHelper == 0 || packet.nextHelper > 10) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(digest, EcRepairBlockCore::digestPacket(plan, repairBlock(packet)));
  EcHelperStamp result;
  result.packetDigest = digest;
  result.senderPosition = packet.nextHelper - 1;
  result.recipientPosition = packet.nextHelper == 10 ? 255 : packet.nextHelper;
  result.issuedAtSeconds = now;
  result.expiresAtSeconds = expires;
  CHECK_RESULT(signature, Access::mac(key, canonical(result, plan)));
  Access::set(result, signature);
  return result;
}
}  // namespace ec_helper_detail

Result<Void> verifyEcHelperPredecessor(const EcHelperKey &key,
                                       const EcRepairPlan &plan,
                                       const EcHelperPacket &packet,
                                       const EcHelperStamp &stamp,
                                       uint8_t recipient,
                                       uint64_t now) {
  RETURN_ON_ERROR(EcRepairBlockCore::validate(plan, repairBlock(packet), recipient));
  if (recipient == 0) {
    if (!ec_helper_detail::Access::empty(stamp))
      return makeError(StatusCode::kAuthenticationFail, "first helper stamp must be empty");
    return Void{};
  }
  if (recipient >= 10 || stamp.version != kEcHelperVersion || stamp.senderPosition != recipient - 1 ||
      stamp.recipientPosition != recipient)
    return makeError(StatusCode::kAuthenticationFail, "helper predecessor position mismatch");
  RETURN_ON_ERROR(time(stamp.issuedAtSeconds, stamp.expiresAtSeconds, now));
  CHECK_RESULT(digest, EcRepairBlockCore::digestPacket(plan, repairBlock(packet)));
  if (stamp.packetDigest != digest)
    return makeError(StatusCode::kAuthenticationFail, "helper packet differs from predecessor stamp");
  CHECK_RESULT(signature, ec_helper_detail::Access::mac(key, canonical(stamp, plan)));
  if (!ec_helper_detail::Access::matches(stamp, signature))
    return makeError(StatusCode::kAuthenticationFail, "helper predecessor MAC mismatch");
  return Void{};
}

Result<Void> verifyEcHelperFinal(const EcHelperKey &key,
                                 const EcRepairPlan &plan,
                                 const EcHelperHopResult &result,
                                 uint64_t now) {
  RETURN_ON_ERROR(EcRepairBlockCore::validateComplete(plan, repairBlock(result.packet)));
  const auto &stamp = result.finalStamp;
  if (stamp.version != kEcHelperVersion || stamp.senderPosition != 9 || stamp.recipientPosition != 255) {
    return makeError(StatusCode::kAuthenticationFail, "helper final stamp has wrong endpoints");
  }
  RETURN_ON_ERROR(time(stamp.issuedAtSeconds, stamp.expiresAtSeconds, now));
  CHECK_RESULT(digest, EcRepairBlockCore::digestPacket(plan, repairBlock(result.packet)));
  if (stamp.packetDigest != digest)
    return makeError(StatusCode::kAuthenticationFail, "helper final packet digest mismatch");
  CHECK_RESULT(signature, ec_helper_detail::Access::mac(key, canonical(stamp, plan)));
  if (!ec_helper_detail::Access::matches(stamp, signature))
    return makeError(StatusCode::kAuthenticationFail, "helper final MAC mismatch");
  return Void{};
}

}  // namespace hf3fs::storage
