#pragma once

#include "fbs/storage/EcGcAbsentControl.h"

namespace hf3fs::storage {
class EcGcAbsentExecutor;
namespace ec_gc_absent_discovery_detail {
class Codec;
}
inline constexpr uint16_t kEcGcAbsentDiscoveryVersion = 1;
// Fixed canonical bodies, including the eight-byte MAC domain. Binary Serde
// sends these bodies and a 32-byte MAC with its own array/string framing; these
// constants are not complete Serde or RPC packet sizes.
inline constexpr size_t kEcGcAbsentDiscoveryRequestBytes = 90;
inline constexpr size_t kEcGcAbsentDiscoveryObservationBytes = 154;
inline constexpr uint64_t kEcGcAbsentDiscoveryMaxTtlSeconds = 60;
inline constexpr uint16_t kEcGcAbsentDiscoveryConfirmQuery = 3;
inline constexpr uint16_t kEcGcAbsentDiscoveryQueryOnly = 2;

struct EcGcAbsentDiscoveryClaims {
  uint16_t version = kEcGcAbsentDiscoveryVersion;
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};
struct EcGcAbsentDiscoveryRequest {
  EcGcAbsentDiscoveryClaims claims;
  std::string serdeToReadable() const { return "EcGcAbsentDiscoveryRequest(REDACTED)"; }

 private:
  friend class ec_gc_absent_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcAbsentDiscoveryRequest>;
  EcSha256 signature_{};
};
// A live, G-authenticated capability observation, not a GC claim, a receipt,
// or absence confirmation authority. Data protocol 2, disk format 3 and the embedded GC protocol 2 are
// independent. Storage cannot assert the Meta object's tracking mode.
struct EcGcAbsentDiscoveryObservationClaims {
  uint16_t version = kEcGcAbsentDiscoveryVersion;
  EcSha256 requestDigest{};
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  EcScopeEndpoint endpoint;
  uint16_t dataProtocol = 0;
  uint16_t diskFormat = 0;
  uint16_t gcProtocol = 0;
  uint16_t capabilities = 0;
  Uuid bootNonce = Uuid::zero();
  uint64_t observedAtSeconds = 0;
};
struct EcGcAbsentDiscoveryObservation {
  EcGcAbsentDiscoveryObservationClaims claims;
  std::string serdeToReadable() const { return "EcGcAbsentDiscoveryObservation(REDACTED)"; }

 private:
  friend class ec_gc_absent_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcAbsentDiscoveryObservation>;
  EcSha256 signature_{};
};
Result<EcGcAbsentDiscoveryRequest> signEcGcAbsentDiscovery(const EcGcKey &, const EcGcAbsentDiscoveryClaims &, uint64_t nowSeconds);
Result<Void> verifyEcGcAbsentDiscovery(const EcGcKey &,
                                 const EcGcAbsentDiscoveryRequest &,
                                 const Uuid &configuredAuthority,
                                 NodeId localNode,
                                 uint64_t nowSeconds);
Result<Void> verifyEcGcAbsentDiscoveryObservation(const EcGcKey &,
                                            const EcGcAbsentDiscoveryObservation &,
                                            const EcGcAbsentDiscoveryRequest &issuedRequest,
                                            uint64_t nowSeconds);

namespace ec_gc_absent_discovery_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcGcAbsentDiscoveryRequestBytes> encode(const EcGcAbsentDiscoveryClaims &);
  static std::array<uint8_t, kEcGcAbsentDiscoveryObservationBytes> encode(const EcGcAbsentDiscoveryObservationClaims &);
  static std::array<uint8_t, kEcGcAbsentDiscoveryRequestBytes + 32> frame(const EcGcAbsentDiscoveryRequest &);
  static std::array<uint8_t, kEcGcAbsentDiscoveryObservationBytes + 32> frame(const EcGcAbsentDiscoveryObservation &);
  static Result<EcGcAbsentDiscoveryClaims> decodeRequest(std::string_view);
  static Result<EcGcAbsentDiscoveryObservationClaims> decodeObservation(std::string_view);
  static Result<EcGcAbsentDiscoveryRequest> signRequest(const EcGcKey &, const EcGcAbsentDiscoveryClaims &, uint64_t);
  static Result<Void> verifyRequest(const EcGcKey &, const EcGcAbsentDiscoveryRequest &, const Uuid &, NodeId, uint64_t);
  static Result<Void> verifyObservation(const EcGcKey &,
                                        const EcGcAbsentDiscoveryObservation &,
                                        const EcGcAbsentDiscoveryRequest &,
                                        uint64_t);

 private:
  friend class ::hf3fs::storage::EcGcAbsentExecutor;
  // No public observation factory accepts an enabled bool or caller UUIDs.
  // Runtime/session and actual-target evidence is supplied only by the owner.
  static Result<EcGcAbsentDiscoveryObservation> signObserved(const EcGcKey &,
                                                       const EcGcAbsentDiscoveryRequest &,
                                                       const EcGcLocalTarget &,
                                                       const Uuid &configuredAuthority,
                                                       const Uuid &actualBootNonce,
                                                       uint16_t actualAdmissionMask,
                                                       uint64_t);
};
}  // namespace ec_gc_absent_discovery_detail
}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcAbsentDiscoveryRequest> {
  static void serialize(const storage::EcGcAbsentDiscoveryRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_gc_absent_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcAbsentDiscoveryRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_gc_absent_discovery_detail::Codec::decodeRequest(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcGcAbsentDiscoveryRequest decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcAbsentDiscoveryObservation> {
  static void serialize(const storage::EcGcAbsentDiscoveryObservation &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_gc_absent_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcAbsentDiscoveryObservation &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_gc_absent_discovery_detail::Codec::decodeObservation(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcGcAbsentDiscoveryObservation decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

namespace hf3fs::storage {
struct EcGcAbsentDiscoveryRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcGcAbsentDiscoveryObservation>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(serde::Serializable<EcGcAbsentDiscoveryRequest>);
static_assert(serde::Serializable<EcGcAbsentDiscoveryObservation>);
}  // namespace hf3fs::storage

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcGcAbsentDiscoveryRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcAbsentDiscoveryRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcGcAbsentDiscoveryObservation> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcAbsentDiscoveryObservation &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
