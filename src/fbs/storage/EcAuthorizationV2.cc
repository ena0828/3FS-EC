#include "fbs/storage/EcAuthorizationV2.h"

#include <algorithm>
#include <cassert>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view kGrantDomain("3FSECG\0\2", 8);
constexpr std::string_view kIntegrityDomain("3FSECI\0\2", 8);

template <size_t Size>
class CanonicalWriter {
 public:
  void integer(uint64_t value, size_t width) {
    assert(width <= 8 && offset + width <= Size);
    for (size_t i = width; i != 0; --i) bytes[offset++] = static_cast<uint8_t>(value >> ((i - 1) * 8));
  }
  void raw(std::span<const uint8_t> value) {
    assert(offset + value.size() <= Size);
    std::copy(value.begin(), value.end(), bytes.begin() + offset);
    offset += value.size();
  }
  void uuid(const Uuid &value) { raw(std::span<const uint8_t>(value.data, 16)); }
  void domain(std::string_view value) { raw({reinterpret_cast<const uint8_t *>(value.data()), value.size()}); }
  std::array<uint8_t, Size> finish() {
    assert(offset == Size);
    return bytes;
  }

 private:
  std::array<uint8_t, Size> bytes{};
  size_t offset = 0;
};

bool oneRight(EcGrantRightV2 right) {
  switch (right) {
    case EcGrantRightV2::ReadBlock:
    case EcGrantRightV2::Begin:
    case EcGrantRightV2::Append:
    case EcGrantRightV2::Query:
    case EcGrantRightV2::Reconcile:
    case EcGrantRightV2::Seal:
      return true;
  }
  return false;
}

Result<Void> validateBinding(const EcGrantBindingV2 &binding) {
  RETURN_ON_ERROR(binding.identity.validate());
  if (binding.engineUuid.is_nil() || binding.targetIncarnation.is_nil() || binding.identity.shard >= 12 ||
      binding.fragmentOperationId.is_nil() || binding.chainId == ChainId{} || binding.targetId == TargetId{} ||
      binding.nodeId == NodeId{} || binding.expectedLength > kEcFragmentRpcMaxBytes ||
      (binding.expectedLength == 0 && binding.expectedCrc32c != 0) || binding.integrityDigest == EcSha256{} ||
      binding.clientNamespace.is_nil() || binding.scopeObject != binding.identity.object || binding.scopeId.is_nil() ||
      (binding.scopeKind != EcGrantScope::ReadPin && binding.scopeKind != EcGrantScope::WriteOperation)) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 EC instance, fragment, scope, integrity or extent");
  }
  return Void{};
}

Result<Void> validateClaims(const EcGrantClaimsV2 &claims, uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateBinding(claims));
  if (claims.version != kEcGrantVersionV2 || claims.grantId.is_nil() || claims.rights == 0 ||
      (claims.rights & ~kEcGrantAllRightsV2) != 0 ||
      (claims.scopeKind == EcGrantScope::ReadPin &&
       claims.rights != static_cast<uint16_t>(EcGrantRightV2::ReadBlock)) ||
      maxTtlSeconds == 0 || maxTtlSeconds > kEcGrantMaxTtlSeconds ||
      claims.expiresAtSeconds <= claims.issuedAtSeconds ||
      claims.expiresAtSeconds - claims.issuedAtSeconds > maxTtlSeconds) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 EC rights, version or bounded lifetime");
  }
  return Void{};
}

Result<Void> checkTime(const EcGrantClaimsV2 &claims, uint64_t nowSeconds) {
  if (nowSeconds < claims.issuedAtSeconds || nowSeconds >= claims.expiresAtSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "V2 EC grant is not currently valid");
  }
  return Void{};
}
}  // namespace

namespace ec_authorization_v2_detail {
// No native struct layout or Serde framing is part of this MAC input. The last
// three bytes are reserved zeros; decoders reject noncanonical alternatives.
std::array<uint8_t, kEcGrantCanonicalBytesV2> encodeClaims(const EcGrantClaimsV2 &claims) {
  CanonicalWriter<kEcGrantCanonicalBytesV2> out;
  out.domain(kGrantDomain);
  out.integer(claims.version, 2);
  out.integer(claims.identity.version, 2);
  out.uuid(claims.identity.object);
  out.integer(claims.identity.stripe, 8);
  out.integer(claims.identity.generation, 8);
  out.integer(claims.identity.shard, 2);
  out.uuid(claims.identity.allocation);
  out.uuid(claims.fragmentOperationId);
  out.integer(claims.chainId.toUnderType(), 4);
  out.integer(claims.targetId.toUnderType(), 8);
  out.integer(claims.nodeId.toUnderType(), 4);
  out.integer(claims.expectedLength, 4);
  out.integer(claims.expectedCrc32c, 4);
  out.uuid(claims.engineUuid);
  out.uuid(claims.targetIncarnation);
  out.raw(claims.integrityDigest);
  out.integer(claims.rights, 2);
  out.uuid(claims.grantId);
  out.integer(claims.ownerUid.toUnderType(), 4);
  out.uuid(claims.clientNamespace);
  out.uuid(claims.scopeObject);
  out.integer(static_cast<uint8_t>(claims.scopeKind), 1);
  out.uuid(claims.scopeId);
  out.integer(claims.issuedAtSeconds, 8);
  out.integer(claims.expiresAtSeconds, 8);
  out.integer(0, 3);
  return out.finish();
}

Result<EcGrantClaimsV2> decodeClaims(std::string_view bytes) {
  if (bytes.size() != kEcGrantCanonicalBytesV2 || bytes.substr(0, kGrantDomain.size()) != kGrantDomain ||
      bytes.substr(bytes.size() - 3) != std::string_view("\0\0\0", 3)) {
    return makeError(StatusCode::kInvalidFormat, "V2 EC capability extent, domain or reserved bytes differ");
  }
  size_t offset = kGrantDomain.size();
  const auto integer = [&](size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i != width; ++i) value = (value << 8) | static_cast<uint8_t>(bytes[offset++]);
    return value;
  };
  const auto uuid = [&]() {
    Uuid value;
    std::memcpy(value.data, bytes.data() + offset, 16);
    offset += 16;
    return value;
  };
  EcGrantClaimsV2 claims;
  claims.version = integer(2);
  claims.identity.version = integer(2);
  claims.identity.object = uuid();
  claims.identity.stripe = integer(8);
  claims.identity.generation = integer(8);
  claims.identity.shard = integer(2);
  claims.identity.allocation = uuid();
  claims.fragmentOperationId = uuid();
  claims.chainId = ChainId(integer(4));
  claims.targetId = TargetId(integer(8));
  claims.nodeId = NodeId(integer(4));
  claims.expectedLength = integer(4);
  claims.expectedCrc32c = integer(4);
  claims.engineUuid = uuid();
  claims.targetIncarnation = uuid();
  std::memcpy(claims.integrityDigest.data(), bytes.data() + offset, 32);
  offset += 32;
  claims.rights = integer(2);
  claims.grantId = uuid();
  claims.ownerUid = flat::Uid(integer(4));
  claims.clientNamespace = uuid();
  claims.scopeObject = uuid();
  claims.scopeKind = static_cast<EcGrantScope>(integer(1));
  claims.scopeId = uuid();
  claims.issuedAtSeconds = integer(8);
  claims.expiresAtSeconds = integer(8);
  RETURN_ON_ERROR(validateClaims(claims, kEcGrantMaxTtlSeconds));
  return claims;
}

struct Access {
  static void setSignature(EcCapabilityV2 &grant, const EcSha256 &signature) { grant.signature_ = signature; }
  static bool matches(const EcCapabilityV2 &grant, const EcSha256 &signature) {
    return ec_authorization_detail::Access::constantTimeEqual(grant.signature_, signature);
  }
};
}  // namespace ec_authorization_v2_detail

Result<EcSha256> digestEcIntegrityV2(const EcFragmentIdentity &identity, const EcIntegrityDescriptor &descriptor) {
  RETURN_ON_ERROR(validateEcIntegrity(identity, descriptor));
  CanonicalWriter<kEcIntegrityCanonicalBytesV2> out;
  out.domain(kIntegrityDomain);
  out.integer(descriptor.version, 2);
  out.integer(descriptor.codecId, 2);
  out.integer(descriptor.matrixVersion, 2);
  out.integer(descriptor.dataShards, 2);
  out.integer(descriptor.parityShards, 2);
  out.integer(descriptor.fieldPolynomial, 2);
  out.integer(descriptor.blockBytes, 4);
  out.integer(descriptor.wholeLength, 4);
  out.integer(descriptor.wholeCrc32c, 4);
  out.integer(descriptor.blockCount, 2);
  for (const auto &block : descriptor.blocks) {
    out.integer(block.validLength, 4);
    out.integer(block.crc32c, 4);
    out.raw(block.sha256);
  }
  out.raw(descriptor.root);
  const auto bytes = out.finish();
  EcSha256 digest{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != digest.size()) {
    return makeError(StatusCode::kIOError, "V2 EC descriptor SHA-256 calculation failed");
  }
  return digest;
}

std::string EcCapabilityV2::serdeToReadable() const {
  return fmt::format("EcCapabilityV2(grant={}, signature=REDACTED)", claims.grantId);
}

Result<EcCapabilityV2> signEcGrantV2(const EcCapabilityKey &key,
                                     const EcGrantClaimsV2 &claims,
                                     uint64_t nowSeconds,
                                     uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateClaims(claims, maxTtlSeconds));
  RETURN_ON_ERROR(checkTime(claims, nowSeconds));
  CHECK_RESULT(signature,
               ec_authorization_detail::Access::authenticate(key, ec_authorization_v2_detail::encodeClaims(claims)));
  EcCapabilityV2 grant;
  grant.claims = claims;
  ec_authorization_v2_detail::Access::setSignature(grant, signature);
  return grant;
}

Result<VerifiedEcGrantV2> verifyEcGrantV2(const EcCapabilityKey &key,
                                          const EcCapabilityV2 &grant,
                                          const EcGrantBindingV2 &expected,
                                          EcGrantRightV2 requiredRight,
                                          uint64_t nowSeconds,
                                          uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateClaims(grant.claims, maxTtlSeconds));
  RETURN_ON_ERROR(validateBinding(expected));
  if (!oneRight(requiredRight))
    return makeError(StatusCode::kInvalidArg, "V2 EC verification requires one known right");
  const auto canonical = ec_authorization_v2_detail::encodeClaims(grant.claims);
  CHECK_RESULT(signature, ec_authorization_detail::Access::authenticate(key, canonical));
  if (!ec_authorization_v2_detail::Access::matches(grant, signature)) {
    return makeError(StatusCode::kAuthenticationFail, "V2 EC capability authentication failed");
  }
  auto checked = grant.claims;
  static_cast<EcGrantBindingV2 &>(checked) = expected;
  if (ec_authorization_v2_detail::encodeClaims(checked) != canonical ||
      !(grant.claims.rights & static_cast<uint16_t>(requiredRight))) {
    return makeError(StatusCode::kAuthenticationFail, "V2 EC capability does not authorize this request");
  }
  RETURN_ON_ERROR(checkTime(grant.claims, nowSeconds));
  return VerifiedEcGrantV2(grant.claims, requiredRight);
}
}  // namespace hf3fs::storage
