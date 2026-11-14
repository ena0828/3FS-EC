#pragma once

#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::meta::server {
class EcGcCoordinator;
}

namespace hf3fs::storage {
class EcGcExecutor;
namespace ec_gc_absent_detail { class Codec; }
namespace ec_gc_absent_discovery_detail { class Codec; }
namespace ec_gc_discovery_detail {
class Codec;
}
class EcGcControlTestAccess;
namespace ec_gc_control_detail {
class Codec;
class RequestSigner;
class AckSigner;
}  // namespace ec_gc_control_detail

inline constexpr uint16_t kEcGcControlVersion = 1;
// Highest supported GC certificate protocol. Runtime2 supports exact G1 and
// G2, without upgrading a mode3 claim. Discovery is a point observation only.
inline constexpr uint16_t kEcGcSupportedProtocol = 2;
inline constexpr bool ecGcProtocolSupports(uint16_t supported, uint16_t required) {
  return supported >= 1 && supported <= kEcGcSupportedProtocol && required >= 1 && required <= supported;
}
inline constexpr size_t kEcGcCertificateBytes = 1046;
inline constexpr size_t kEcGcRequestBytes = 1122;
inline constexpr size_t kEcGcAckBytes = 268;
inline constexpr uint64_t kEcGcMaxTtlSeconds = 300;
enum class EcGcAction : uint8_t { Collect = 1, Query = 2 };
enum class EcGcConfirmedState : uint8_t { Collected = 1 };

// Obtained from the fd used to load an already configured role, not a later
// stat(path). The caller must include every enabled data/control/helper role.
struct EcGcRoleFileIdentity {
  uint64_t device = 0;
  uint64_t inode = 0;
  bool operator==(const EcGcRoleFileIdentity &) const = default;
};

// Separate G-role key. No conversion from data/control/helper keys, Serde,
// formatter, copy or move operation. The inner key owns and cleanses its bytes.
class EcGcKey final {
 public:
  static Result<std::unique_ptr<EcGcKey>> loadFile(const std::filesystem::path &path,
                                                   const Uuid &keyId,
                                                   std::span<const EcGcRoleFileIdentity> alreadyLoadedOtherRoles);
  EcGcKey(const EcGcKey &) = delete;
  EcGcKey &operator=(const EcGcKey &) = delete;
  EcGcKey(EcGcKey &&) = delete;
  EcGcKey &operator=(EcGcKey &&) = delete;
  ~EcGcKey() = default;
  const Uuid &keyId() const { return keyId_; }
  const EcGcRoleFileIdentity &fileIdentity() const { return fileIdentity_; }

 private:
  friend class ec_gc_control_detail::Codec;
  friend class ec_gc_absent_detail::Codec;
  friend class ec_gc_absent_discovery_detail::Codec;
  friend class ec_gc_discovery_detail::Codec;
  EcGcKey(std::unique_ptr<EcCapabilityKey> key, Uuid keyId, EcGcRoleFileIdentity fileIdentity)
      : key_(std::move(key)),
        keyId_(keyId),
        fileIdentity_(fileIdentity) {}
  std::unique_ptr<EcCapabilityKey> key_;
  Uuid keyId_;
  EcGcRoleFileIdentity fileIdentity_;
};

// Fixed projection of a committed Meta claim. Structural validity is not a
// proof of refcount zero, T2 completion, or a successfully committed claim.
// These independent versions must never be inferred from one another.
struct EcGcCertificate {
  uint16_t version = 1;
  uint16_t metaMode = 3;
  uint16_t catalogVersion = 1;  // GC catalog, not the general EC catalog v2.
  uint16_t enrollmentVersion = 1;
  uint16_t bindingVersion = 1;
  uint16_t dataProtocol = 2;
  uint16_t diskFormat = 3;
  uint16_t gcProtocol = 1;
  Uuid claimId = Uuid::zero();
  uint64_t objectInode = 0;
  Uuid objectIncarnation = Uuid::zero();
  flat::Uid creatorUid{};
  Uuid creatorClient = Uuid::zero();
  Uuid createRequest = Uuid::zero();
  EcFragmentIdentity fragment;
  Uuid fragmentOperation = Uuid::zero();
  EcScopeEndpoint endpoint;
  flat::Uid writerUid{};
  Uuid writerClient = Uuid::zero();
  EcIntegrityDescriptor integrity;
  uint64_t registeredScopes = 0;
  uint64_t releasedScopes = 0;
  EcSha256 releaseHistory{};
  EcSha256 originDrainEvidence{};
  EcSha256 eligibilityDigest{};
};

struct EcGcRequestClaims {
  uint16_t version = kEcGcControlVersion;
  EcGcAction action = EcGcAction::Collect;
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
  EcGcCertificate certificate;
};
struct EcGcRequest {
  EcGcRequestClaims claims;
  std::string serdeToReadable() const { return "EcGcRequest(REDACTED)"; }

 private:
  friend class ec_gc_control_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcRequest>;
  EcSha256 signature_{};
};

struct EcGcAckClaims {
  uint16_t version = kEcGcControlVersion;
  EcGcConfirmedState state = EcGcConfirmedState::Collected;
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  EcSha256 requestDigest{};
  EcSha256 claimDigest{};
  Uuid claimId = Uuid::zero();
  EcSha256 eligibilityDigest{};
  EcScopeEndpoint endpoint;
  EcSha256 ledgerSha256{};
  uint64_t terminalRevision = 0;
  uint64_t observedAtSeconds = 0;
  Uuid bootNonce = Uuid::zero();
};
struct EcGcAck {
  EcGcAckClaims claims;
  std::string serdeToReadable() const { return "EcGcAck(REDACTED)"; }

 private:
  friend class ec_gc_control_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcAck>;
  EcSha256 signature_{};
};

// Supplied by the actual, still-owned StorageTarget/facade. Discovery data v2
// alone cannot supply diskFormat=3 or prove the GC executor is enabled.
struct EcGcLocalTarget {
  EcScopeEndpoint endpoint;
  uint16_t dataProtocol = 0;
  uint16_t diskFormat = 0;
  uint16_t gcProtocol = 0;
  bool enabled = false;
};

class VerifiedEcGcRequest {
 public:
  const EcGcRequest &request() const { return request_; }
  const EcGcCertificate &certificate() const { return request_.claims.certificate; }
  const EcSha256 &claimDigest() const { return claimDigest_; }
  EcGcAction action() const { return request_.claims.action; }

 private:
  friend class ec_gc_control_detail::Codec;
  VerifiedEcGcRequest(EcGcRequest request, EcSha256 claimDigest)
      : request_(std::move(request)),
        claimDigest_(claimDigest) {}
  EcGcRequest request_;
  EcSha256 claimDigest_;
};
class VerifiedEcGcAck {
 public:
  const EcGcAck &ack() const { return ack_; }

 private:
  friend class ec_gc_control_detail::Codec;
  explicit VerifiedEcGcAck(EcGcAck ack)
      : ack_(std::move(ack)) {}
  EcGcAck ack_;
};

// The narrow Rust bridge returns this tuple only after its dedicated ledger,
// terminal consistency and WAL checks. Merely observing stage/ledger bytes is
// insufficient. This plain tuple itself has no public signing capability.
struct EcGcLedgerReceipt {
  Uuid claimId = Uuid::zero();
  EcSha256 ledgerSha256{};
  uint64_t terminalRevision = 0;
};

namespace ec_gc_control_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcGcCertificateBytes> encode(const EcGcCertificate &);
  static std::array<uint8_t, kEcGcRequestBytes> encode(const EcGcRequestClaims &);
  static std::array<uint8_t, kEcGcAckBytes> encode(const EcGcAckClaims &);
  static Result<EcGcCertificate> decodeCertificate(std::string_view);
  static Result<EcGcRequestClaims> decodeRequestClaims(std::string_view);
  static Result<EcGcAckClaims> decodeAckClaims(std::string_view);
  static Result<EcGcRequest> decodeRequest(std::string_view body, std::string_view mac);
  static Result<EcGcAck> decodeAck(std::string_view body, std::string_view mac);
  static std::array<uint8_t, kEcGcRequestBytes + 32> frame(const EcGcRequest &);
  static std::array<uint8_t, kEcGcAckBytes + 32> frame(const EcGcAck &);
  static Result<EcSha256> claimDigest(const EcGcCertificate &);
  static Result<VerifiedEcGcRequest> verifyRequest(const EcGcKey &,
                                                   const EcGcRequest &,
                                                   const Uuid &configuredAuthority,
                                                   EcGcAction requiredAction,
                                                   const EcGcLocalTarget &actualTarget,
                                                   uint64_t nowSeconds,
                                                   uint64_t maxTtlSeconds = kEcGcMaxTtlSeconds);
  // Historical confirmation checks observation time against the exact issued
  // request. It does not discard an irreversible proof when current time moves.
  static Result<VerifiedEcGcAck> verifyAck(const EcGcKey &, const EcGcAck &, const EcGcRequest &exactIssuedRequest);

 private:
  friend class RequestSigner;
  friend class AckSigner;
  // The coordinator must first re-read the same definitely committed claim.
  // There is no public signer accepting an untrusted client's claim/receipt.
  static Result<EcGcRequest> signRequest(const EcGcKey &,
                                         const EcGcRequestClaims &,
                                         uint64_t nowSeconds,
                                         uint64_t maxTtlSeconds = kEcGcMaxTtlSeconds);
  // Only the actual executor may supply the dedicated Rust GC result. Missing
  // and unknown errors remain errors. Success followed by failed fresh checks
  // returns 4085, never a fabricated Collected ACK or ordinary auth rejection.
  static Result<EcGcAck> signConfirmed(const EcGcKey &,
                                       const VerifiedEcGcRequest &,
                                       Result<EcGcLedgerReceipt> receipt,
                                       const EcGcLocalTarget &actualTarget,
                                       const Uuid &configuredAuthority,
                                       const Uuid &bootNonce,
                                       uint64_t nowSeconds);
};
// Each trusted role gets only its own entry point. These classes neither
// expose a public signer nor widen the underlying shared G trust domain.
class RequestSigner final {
 private:
  friend class ::hf3fs::meta::server::EcGcCoordinator;
  friend class ::hf3fs::storage::EcGcControlTestAccess;
  static Result<EcGcRequest> sign(const EcGcKey &key,
                                  const EcGcRequestClaims &claims,
                                  uint64_t now,
                                  uint64_t ttl = kEcGcMaxTtlSeconds) {
    return Codec::signRequest(key, claims, now, ttl);
  }
};
class AckSigner final {
 private:
  friend class ::hf3fs::storage::EcGcExecutor;
  friend class ::hf3fs::storage::EcGcControlTestAccess;
  static Result<EcGcAck> sign(const EcGcKey &key,
                              const VerifiedEcGcRequest &request,
                              Result<EcGcLedgerReceipt> receipt,
                              const EcGcLocalTarget &target,
                              const Uuid &authority,
                              const Uuid &boot,
                              uint64_t now) {
    return Codec::signConfirmed(key, request, std::move(receipt), target, authority, boot, now);
  }
};
}  // namespace ec_gc_control_detail
}  // namespace hf3fs::storage

// These adapters inspect fixed field counts/lengths before publishing output.
// Readable output is deliberately not a token import format.
template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcRequest> {
  static void serialize(const storage::EcGcRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      const auto bytes = storage::ec_gc_control_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "GC requests require binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "GC request requires two fixed fields");
      std::string_view body, mac;
      RETURN_ON_ERROR(serde::deserialize(body, in));
      RETURN_ON_ERROR(serde::deserialize(mac, in));
      CHECK_RESULT(decoded, storage::ec_gc_control_detail::Codec::decodeRequest(body, mac));
      value = std::move(decoded);
      return Void{};
    }
  }
};
template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcAck> {
  static void serialize(const storage::EcGcAck &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      const auto bytes = storage::ec_gc_control_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcAck &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "GC acknowledgements require binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "GC acknowledgement requires two fixed fields");
      std::string_view body, mac;
      RETURN_ON_ERROR(serde::deserialize(body, in));
      RETURN_ON_ERROR(serde::deserialize(mac, in));
      CHECK_RESULT(decoded, storage::ec_gc_control_detail::Codec::decodeAck(body, mac));
      value = std::move(decoded);
      return Void{};
    }
  }
};

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcGcRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcGcAck> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcAck &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
