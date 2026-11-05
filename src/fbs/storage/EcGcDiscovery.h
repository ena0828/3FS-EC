#pragma once

#include "fbs/storage/EcGcControl.h"

namespace hf3fs::storage {
class EcGcExecutor;
namespace ec_gc_discovery_detail {
class Codec;
}
inline constexpr uint16_t kEcGcDiscoveryVersion = 2;
// Fixed canonical bodies, including the eight-byte MAC domain. Binary Serde
// sends these bodies and a 32-byte MAC with its own array/string framing; these
// constants are not complete Serde or RPC packet sizes.
inline constexpr size_t kEcGcDiscoveryRequestBytes = 90;
inline constexpr size_t kEcGcDiscoveryObservationBytes = 154;
inline constexpr uint64_t kEcGcDiscoveryMaxTtlSeconds = 60;
inline constexpr uint16_t kEcGcDiscoveryCollectQuery = 3;
inline constexpr uint16_t kEcGcDiscoveryQueryOnly = 2;

struct EcGcDiscoveryClaims {
  uint16_t version = kEcGcDiscoveryVersion;
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};
struct EcGcDiscoveryRequest {
  EcGcDiscoveryClaims claims;
  std::string serdeToReadable() const { return "EcGcDiscoveryRequest(REDACTED)"; }

 private:
  friend class ec_gc_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcDiscoveryRequest>;
  EcSha256 signature_{};
};
// A live, G-authenticated capability observation, not a GC claim, a receipt,
// or deletion authority. Data protocol 2, disk format 3 and GC protocol 1 are
// independent. Storage cannot assert the Meta object's tracking mode.
struct EcGcDiscoveryObservationClaims {
  uint16_t version = kEcGcDiscoveryVersion;
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
struct EcGcDiscoveryObservation {
  EcGcDiscoveryObservationClaims claims;
  std::string serdeToReadable() const { return "EcGcDiscoveryObservation(REDACTED)"; }

 private:
  friend class ec_gc_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcDiscoveryObservation>;
  EcSha256 signature_{};
};
Result<EcGcDiscoveryRequest> signEcGcDiscovery(const EcGcKey &, const EcGcDiscoveryClaims &, uint64_t nowSeconds);
Result<Void> verifyEcGcDiscovery(const EcGcKey &,
                                 const EcGcDiscoveryRequest &,
                                 const Uuid &configuredAuthority,
                                 NodeId localNode,
                                 uint64_t nowSeconds);
Result<Void> verifyEcGcDiscoveryObservation(const EcGcKey &,
                                            const EcGcDiscoveryObservation &,
                                            const EcGcDiscoveryRequest &issuedRequest,
                                            uint64_t nowSeconds);

namespace ec_gc_discovery_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcGcDiscoveryRequestBytes> encode(const EcGcDiscoveryClaims &);
  static std::array<uint8_t, kEcGcDiscoveryObservationBytes> encode(const EcGcDiscoveryObservationClaims &);
  static std::array<uint8_t, kEcGcDiscoveryRequestBytes + 32> frame(const EcGcDiscoveryRequest &);
  static std::array<uint8_t, kEcGcDiscoveryObservationBytes + 32> frame(const EcGcDiscoveryObservation &);
  static Result<EcGcDiscoveryClaims> decodeRequest(std::string_view);
  static Result<EcGcDiscoveryObservationClaims> decodeObservation(std::string_view);
  static Result<EcGcDiscoveryRequest> signRequest(const EcGcKey &, const EcGcDiscoveryClaims &, uint64_t);
  static Result<Void> verifyRequest(const EcGcKey &, const EcGcDiscoveryRequest &, const Uuid &, NodeId, uint64_t);
  static Result<Void> verifyObservation(const EcGcKey &,
                                        const EcGcDiscoveryObservation &,
                                        const EcGcDiscoveryRequest &,
                                        uint64_t);

 private:
  friend class ::hf3fs::storage::EcGcExecutor;
  // No public observation factory accepts an enabled bool or caller UUIDs.
  // Runtime/session and actual-target evidence is supplied only by the owner.
  static Result<EcGcDiscoveryObservation> signObserved(const EcGcKey &,
                                                       const EcGcDiscoveryRequest &,
                                                       const EcGcLocalTarget &,
                                                       const Uuid &configuredAuthority,
                                                       const Uuid &actualBootNonce,
                                                       uint16_t actualAdmissionMask,
                                                       uint64_t);
};
}  // namespace ec_gc_discovery_detail
}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcDiscoveryRequest> {
  static void serialize(const storage::EcGcDiscoveryRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_gc_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcDiscoveryRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_gc_discovery_detail::Codec::decodeRequest(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcGcDiscoveryRequest decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcGcDiscoveryObservation> {
  static void serialize(const storage::EcGcDiscoveryObservation &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_gc_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcGcDiscoveryObservation &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_gc_discovery_detail::Codec::decodeObservation(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcGcDiscoveryObservation decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

namespace hf3fs::storage {
struct EcGcDiscoveryRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcGcDiscoveryObservation>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(serde::Serializable<EcGcDiscoveryRequest>);
static_assert(serde::Serializable<EcGcDiscoveryObservation>);
}  // namespace hf3fs::storage

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcGcDiscoveryRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcDiscoveryRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcGcDiscoveryObservation> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcGcDiscoveryObservation &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
