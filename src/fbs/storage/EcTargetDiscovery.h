#pragma once

#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::storage {
class EcTargetDiscoveryExecutor;
namespace ec_target_discovery_detail {
class Codec;
}
inline constexpr uint16_t kEcTargetDiscoveryVersion = 1;
inline constexpr size_t kEcTargetDiscoveryRequestBytes = 74;
inline constexpr size_t kEcTargetDiscoveryObservationBytes = 100;
inline constexpr uint64_t kEcTargetDiscoveryMaxTtlSeconds = 60;

struct EcTargetDiscoveryClaims {
  uint16_t version = kEcTargetDiscoveryVersion;
  Uuid clusterAuthority = Uuid::zero();
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};
struct EcTargetDiscoveryRequest {
  EcTargetDiscoveryClaims claims;
  std::string serdeToReadable() const { return "EcTargetDiscoveryRequest(REDACTED)"; }

 private:
  friend class ec_target_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcTargetDiscoveryRequest>;
  EcSha256 signature_{};
};
// An observation of a loaded instance. No scope, drain, deletion or data-access
// authority is represented by this type. Historical allocation bindings do not
// change when a newly discovered instance differs from their recorded value.
struct EcTargetDiscoveryObservationClaims {
  uint16_t version = kEcTargetDiscoveryVersion;
  EcSha256 requestDigest{};
  EcScopeEndpoint endpoint;
  uint16_t protocolVersion = 2;
  uint64_t observedAtSeconds = 0;
};
struct EcTargetDiscoveryObservation {
  EcTargetDiscoveryObservationClaims claims;
  std::string serdeToReadable() const { return "EcTargetDiscoveryObservation(REDACTED)"; }

 private:
  friend class ec_target_discovery_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcTargetDiscoveryObservation>;
  EcSha256 signature_{};
};
Result<EcTargetDiscoveryRequest> signEcTargetDiscovery(const EcScopeControlKey &,
                                                       const EcTargetDiscoveryClaims &,
                                                       uint64_t nowSeconds);
Result<Void> verifyEcTargetDiscovery(const EcScopeControlKey &,
                                     const EcTargetDiscoveryRequest &,
                                     const Uuid &configuredAuthority,
                                     NodeId localNode,
                                     uint64_t nowSeconds);
Result<Void> verifyEcTargetDiscoveryObservation(const EcScopeControlKey &,
                                                const EcTargetDiscoveryObservation &,
                                                const EcTargetDiscoveryRequest &issuedRequest,
                                                uint64_t nowSeconds);

namespace ec_target_discovery_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcTargetDiscoveryRequestBytes> encode(const EcTargetDiscoveryClaims &);
  static std::array<uint8_t, kEcTargetDiscoveryObservationBytes> encode(const EcTargetDiscoveryObservationClaims &);
  static Result<EcTargetDiscoveryClaims> decodeRequest(std::string_view);
  static Result<EcTargetDiscoveryObservationClaims> decodeObservation(std::string_view);
  static Result<EcTargetDiscoveryRequest> signRequest(const EcScopeControlKey &,
                                                      const EcTargetDiscoveryClaims &,
                                                      uint64_t);
  static Result<Void> verifyRequest(const EcScopeControlKey &,
                                    const EcTargetDiscoveryRequest &,
                                    const Uuid &,
                                    NodeId,
                                    uint64_t);
  static Result<Void> verifyObservation(const EcScopeControlKey &,
                                        const EcTargetDiscoveryObservation &,
                                        const EcTargetDiscoveryRequest &,
                                        uint64_t);

 private:
  friend class ::hf3fs::storage::EcTargetDiscoveryExecutor;
  // Only the disk executor may sign an observation after confirming the actual
  // already-loaded target. There is no public factory accepting caller UUIDs.
  static Result<EcTargetDiscoveryObservation> signObserved(const EcScopeControlKey &,
                                                           const EcTargetDiscoveryRequest &,
                                                           const EcScopeEndpoint &,
                                                           uint64_t);
};
}  // namespace ec_target_discovery_detail
}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcTargetDiscoveryRequest> {
  static void serialize(const storage::EcTargetDiscoveryRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_target_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcTargetDiscoveryRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_target_discovery_detail::Codec::decodeRequest(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcTargetDiscoveryRequest decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcTargetDiscoveryObservation> {
  static void serialize(const storage::EcTargetDiscoveryObservation &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_target_discovery_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcTargetDiscoveryObservation &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC discovery requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC discovery requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_target_discovery_detail::Codec::decodeObservation(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcTargetDiscoveryObservation decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

namespace hf3fs::storage {
struct EcTargetDiscoveryRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcTargetDiscoveryObservation>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(serde::Serializable<EcTargetDiscoveryRequest>);
static_assert(serde::Serializable<EcTargetDiscoveryObservation>);
}  // namespace hf3fs::storage

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcTargetDiscoveryRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcTargetDiscoveryRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcTargetDiscoveryObservation> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcTargetDiscoveryObservation &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
