#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <span>

#include "fbs/storage/EcIntegrity.h"

namespace hf3fs::storage {

inline constexpr uint16_t kEcGrantVersion = 1;
inline constexpr uint64_t kEcGrantDefaultTtlSeconds = 300;
inline constexpr uint64_t kEcGrantMaxTtlSeconds = 3600;
inline constexpr size_t kEcGrantCanonicalBytes = 188;

enum class EcGrantRight : uint8_t { Create = 1, Read = 2, Reconcile = 4 };
enum class EcGrantScope : uint8_t { ReadPin = 1, WriteOperation = 2 };

// Construct this from the authorized request and current local placement. In
// particular, ownerUid/clientUuid must not be trusted merely because an
// unauthenticated request supplied matching userInfo fields.
struct EcGrantBinding {
  EcFragmentIdentity identity;
  // The operation that created this allocation, including for shared fragments
  // read during repair. It need not equal the current repair's scopeId.
  Uuid fragmentOperationId = Uuid::zero();
  ChainId chainId{};
  TargetId targetId{};
  NodeId nodeId{};
  uint32_t expectedLength = 0;
  // Standard CRC32C including the final complement: ~ChecksumInfo::value.
  uint32_t expectedCrc32c = 0;
  flat::Uid ownerUid{};  // UID zero is valid; it is not an absent identity.
  Uuid clientUuid = Uuid::zero();
  Uuid scopeObject = Uuid::zero();
  EcGrantScope scopeKind = EcGrantScope::ReadPin;
  Uuid scopeId = Uuid::zero();
};

struct EcGrantClaims : EcGrantBinding {
  uint16_t version = kEcGrantVersion;
  uint8_t rights = 0;
  Uuid grantId = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};

namespace ec_authorization_detail {
struct Access;
std::array<uint8_t, kEcGrantCanonicalBytes> encodeClaims(const EcGrantClaims &claims);
Result<EcGrantClaims> decodeClaims(std::string_view bytes);
}  // namespace ec_authorization_detail

// Non-secret identity captured by fstat on the same fd that supplied the key.
// It is not a later path lookup and does not prove distinct secret bytes.
struct EcKeyFileIdentity {
  uint64_t device = 0;
  uint64_t inode = 0;
  bool operator==(const EcKeyFileIdentity &) const = default;
};

// Explicitly supplied secret, with no Serde, stream or formatter interface.
// The caller owns entropy and must clear any source buffer it retains. This
// class clears its own copy; it does not claim locked memory or dump protection.
class EcCapabilityKey final {
 public:
  explicit EcCapabilityKey(std::span<const uint8_t, 32> bytes);
  ~EcCapabilityKey();
  // Linux configuration loader: an explicit existing regular file, owned by
  // euid or root, with no group/world permissions, exactly 32 nonzero-key bytes.
  // No default path, key generation, text/hex decoding, or symlink following.
  static Result<std::unique_ptr<EcCapabilityKey>> loadFile(const std::filesystem::path &path);
  EcCapabilityKey(const EcCapabilityKey &) = delete;
  EcCapabilityKey &operator=(const EcCapabilityKey &) = delete;
  EcCapabilityKey(EcCapabilityKey &&) = delete;
  EcCapabilityKey &operator=(EcCapabilityKey &&) = delete;
  // Raw-memory keys have no file identity. Callers requiring role-file
  // separation must reject absence instead of consulting the current path.
  const std::optional<EcKeyFileIdentity> &fileIdentity() const noexcept { return fileIdentity_; }

 private:
  friend struct ec_authorization_detail::Access;
  std::array<uint8_t, 32> bytes_;
  std::optional<EcKeyFileIdentity> fileIdentity_;
};

// Binary Serde is the transport format. Readable Serde and fmt are deliberately
// redacted and are not accepted as a token import format. Do not log binary
// serialized tokens: the MAC makes the complete token a bearer credential.
struct EcCapability {
  EcGrantClaims claims;
  std::string serdeToReadable() const;

 private:
  friend struct ec_authorization_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcCapability>;
  EcSha256 signature_{};
};

// HMAC grants authorize their holder only within protected, trusted cluster
// transport. Meta must derive claims from authenticated identity. Storage must
// also recheck current route version, local target and requested byte range.
// Expiry is access validity only: it proves neither pin release nor read drain.
// No persistent revocation, admission/drain protocol, or GC/delete authority is
// implemented here. Grant IDs do not provide replay prevention. In particular
// there is no Delete permission.
Result<EcCapability> signEcGrant(const EcCapabilityKey &key,
                                 const EcGrantClaims &claims,
                                 uint64_t nowSeconds,
                                 uint64_t maxTtlSeconds = kEcGrantDefaultTtlSeconds);
Result<Void> verifyEcGrant(const EcCapabilityKey &key,
                           const EcCapability &grant,
                           const EcGrantBinding &expected,
                           EcGrantRight requiredRight,
                           uint64_t nowSeconds,
                           uint64_t maxTtlSeconds = kEcGrantDefaultTtlSeconds);

}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcCapability> {
  static void serialize(const storage::EcCapability &grant, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      const auto claims = storage::ec_authorization_detail::encodeClaims(grant.claims);
      out.arrayBegin();
      // Binary output grows downward, so write the two fixed fields in reverse.
      serde::serialize(grant.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(claims.data()), claims.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(grant.serdeToReadable(), out);
    }
  }

  static Result<Void> deserialize(storage::EcCapability &grant, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC capabilities require binary Serde; readable output is redacted");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC capability requires exactly two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_authorization_detail::decodeClaims(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      // Publish the decoded value only when both fixed extents are valid.
      storage::EcCapability decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      grant = std::move(decoded);
      return Void{};
    }
  }
};

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcCapability> : formatter<std::string_view> {
  template <typename FormatContext>
  auto format(const hf3fs::storage::EcCapability &grant, FormatContext &ctx) const {
    return formatter<std::string_view>::format(grant.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
