#pragma once

#include <utility>

#include "fbs/storage/EcAuthorization.h"

namespace hf3fs::storage {

inline constexpr uint16_t kEcGrantVersionV2 = 2;
inline constexpr size_t kEcGrantCanonicalBytesV2 = 256;
inline constexpr size_t kEcIntegrityCanonicalBytesV2 = 706;

enum class EcGrantRightV2 : uint16_t {
  ReadBlock = 1,
  Begin = 2,
  Append = 4,
  Query = 8,
  Reconcile = 16,
  Seal = 32,
};
inline constexpr uint16_t kEcGrantAllRightsV2 = 63;

// An independently issued V2 binding. There is deliberately no conversion from
// EcGrantBinding/V1: copying a Storage instance into an old token is not proof.
struct EcGrantBindingV2 {
  Uuid engineUuid = Uuid::zero();
  Uuid targetIncarnation = Uuid::zero();
  EcFragmentIdentity identity;
  // A repair may read a healthy allocation created by a different operation.
  Uuid fragmentOperationId = Uuid::zero();
  ChainId chainId{};
  TargetId targetId{};
  NodeId nodeId{};
  uint32_t expectedLength = 0;
  uint32_t expectedCrc32c = 0;  // Standard CRC32C, including final complement.
  EcSha256 integrityDigest{};
  flat::Uid ownerUid{};
  // Caller retry namespace, not an independently authenticated process ID.
  Uuid clientNamespace = Uuid::zero();
  Uuid scopeObject = Uuid::zero();
  EcGrantScope scopeKind = EcGrantScope::ReadPin;
  Uuid scopeId = Uuid::zero();
};

struct EcGrantClaimsV2 : EcGrantBindingV2 {
  uint16_t version = kEcGrantVersionV2;
  uint16_t rights = 0;
  Uuid grantId = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};

namespace ec_authorization_v2_detail {
struct Access;
std::array<uint8_t, kEcGrantCanonicalBytesV2> encodeClaims(const EcGrantClaimsV2 &claims);
Result<EcGrantClaimsV2> decodeClaims(std::string_view bytes);
}  // namespace ec_authorization_v2_detail

struct EcCapabilityV2 {
  EcGrantClaimsV2 claims;
  std::string serdeToReadable() const;

 private:
  friend struct ec_authorization_v2_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcCapabilityV2>;
  EcSha256 signature_{};
};

class VerifiedEcGrantV2;
Result<VerifiedEcGrantV2> verifyEcGrantV2(const EcCapabilityKey &key,
                                          const EcCapabilityV2 &grant,
                                          const EcGrantBindingV2 &expected,
                                          EcGrantRightV2 requiredRight,
                                          uint64_t nowSeconds,
                                          uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);

// A successful check at one instant, not a renewable authority or drain proof.
// Queue execution and postchecks must validate the original grant again against
// fresh route/instance context and time. This value cannot be deserialized.
class VerifiedEcGrantV2 {
 public:
  VerifiedEcGrantV2(const VerifiedEcGrantV2 &) = default;
  VerifiedEcGrantV2 &operator=(const VerifiedEcGrantV2 &) = default;
  const EcGrantClaimsV2 &claims() const { return claims_; }
  EcGrantRightV2 right() const { return right_; }

 private:
  friend Result<VerifiedEcGrantV2> verifyEcGrantV2(const EcCapabilityKey &,
                                                   const EcCapabilityV2 &,
                                                   const EcGrantBindingV2 &,
                                                   EcGrantRightV2,
                                                   uint64_t,
                                                   uint64_t);
  VerifiedEcGrantV2(EcGrantClaimsV2 claims, EcGrantRightV2 right)
      : claims_(std::move(claims)),
        right_(right) {}
  EcGrantClaimsV2 claims_;
  EcGrantRightV2 right_;
};

// Canonical descriptor SHA-256: fixed domain, explicit big-endian fields,
// exactly sixteen slots and root. Validates the descriptor first. Its root
// binds content identity; allocation and instance are separately in the MAC.
// A caller-supplied, internally consistent descriptor is not authoritative:
// Meta must sign the digest from its intended/published integrity descriptor.
Result<EcSha256> digestEcIntegrityV2(const EcFragmentIdentity &identity, const EcIntegrityDescriptor &descriptor);
Result<EcCapabilityV2> signEcGrantV2(const EcCapabilityKey &key,
                                     const EcGrantClaimsV2 &claims,
                                     uint64_t nowSeconds,
                                     uint64_t maxTtlSeconds = kEcGrantDefaultTtlSeconds);

// These rights authorize data methods only. There is no Delete, Abort, revoke,
// target registration or drain-ACK authority in this format. Expiry is never
// permission to release a pin or physical allocation.

}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcCapabilityV2> {
  static void serialize(const storage::EcCapabilityV2 &grant, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      const auto claims = storage::ec_authorization_v2_detail::encodeClaims(grant.claims);
      out.arrayBegin();
      serde::serialize(grant.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(claims.data()), claims.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(grant.serdeToReadable(), out);
    }
  }

  static Result<Void> deserialize(storage::EcCapabilityV2 &grant, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat,
                       "V2 EC capabilities require binary Serde; readable output is redacted");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "V2 EC capability requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_authorization_v2_detail::decodeClaims(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcCapabilityV2 decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      grant = std::move(decoded);
      return Void{};
    }
  }
};

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcCapabilityV2> : formatter<std::string_view> {
  template <typename FormatContext>
  auto format(const hf3fs::storage::EcCapabilityV2 &grant, FormatContext &ctx) const {
    return formatter<std::string_view>::format(grant.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
