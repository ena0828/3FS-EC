#pragma once

#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::storage {
class EcTargetRetirementExecutor;

inline constexpr uint16_t kEcTargetRetirementVersion = 1;
inline constexpr size_t kEcTargetRetirementRequestBytes = 123;
inline constexpr size_t kEcTargetRetirementObservationBytes = 108;
inline constexpr uint64_t kEcTargetRetirementMaxTtlSeconds = 300;
enum class EcTargetRetirementAction : uint8_t { Prepare = 1, Query = 2 };
enum class EcTargetRetirementState : uint8_t { Pending = 1, LocalDataDrained = 2 };

// Canonical request: domain 3FSETRQ1, fixed-width big-endian integers and raw
// UUID bytes in the field order below. The wire version is independent of the
// persistent target format used by retirementDigest.
struct EcTargetRetirementClaims {
  uint16_t version = kEcTargetRetirementVersion;
  EcTargetRetirementAction action = EcTargetRetirementAction::Prepare;
  Uuid clusterAuthority = Uuid::zero();
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid engineUuid = Uuid::zero();
  Uuid targetIncarnation = Uuid::zero();
  Uuid retirementId = Uuid::zero();
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};

struct EcTargetRetirementRequest {
  EcTargetRetirementClaims claims;
  std::string serdeToReadable() const { return "EcTargetRetirementRequest(REDACTED)"; }

 private:
  friend class ec_target_retirement_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcTargetRetirementRequest>;
  EcSha256 signature_{};
};

struct EcTargetRetirementObservationClaims {
  uint16_t version = kEcTargetRetirementVersion;
  // Binds the entire canonical request, including its action/nonce/authority.
  EcSha256 requestDigest{};
  // SHA256("3FSETRD1"|format:u16BE=2|engine:16|incarnation:16|chain:u32BE|
  // target:u64BE|retirementId:16). Logical record, not physical DB bytes.
  // With durable=true this binds the observed sync-confirmed record. With
  // durable=false it is only the intended content commitment; record existence
  // and durability remain unknown. The record contains no authority/node/time.
  EcSha256 retirementDigest{};
  Uuid bootNonce = Uuid::zero();
  EcTargetRetirementState state = EcTargetRetirementState::Pending;
  bool durable = false;
  uint64_t inflight = 0;
  uint64_t observedAtSeconds = 0;
};
struct EcTargetRetirementObservation {
  EcTargetRetirementObservationClaims claims;
  std::string serdeToReadable() const { return "EcTargetRetirementObservation(REDACTED)"; }

 private:
  friend class ec_target_retirement_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcTargetRetirementObservation>;
  EcSha256 signature_{};
};

// Signing requests is a coordinator capability, never a client-data right.
Result<EcTargetRetirementRequest> signEcTargetRetirement(const EcScopeControlKey &key,
                                                         const EcTargetRetirementClaims &claims,
                                                         uint64_t nowSeconds);
Result<Void> verifyEcTargetRetirement(const EcScopeControlKey &key,
                                      const EcTargetRetirementRequest &request,
                                      const Uuid &configuredAuthority,
                                      NodeId localNode,
                                      EcTargetRetirementAction requiredAction,
                                      uint64_t nowSeconds);
// The caller supplies its exact issued request, retaining its intended authority
// and target. Historical verification authenticates both MACs and requires the
// observation time inside the request window; it does not expire a durable fact.
// This shared control-key MAC is not Storage-exclusive private-key attestation.
// LocalDataDrained concerns local cooperative data tickets, not scope drain,
// remote work completion, physical I/O isolation, or permission to release data.
Result<Void> verifyEcTargetRetirementObservation(const EcScopeControlKey &key,
                                                 const EcTargetRetirementObservation &observation,
                                                 const EcTargetRetirementRequest &issuedRequest);

namespace ec_target_retirement_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcTargetRetirementRequestBytes> encode(const EcTargetRetirementClaims &);
  static Result<EcTargetRetirementClaims> decodeRequest(std::string_view);
  static std::array<uint8_t, kEcTargetRetirementObservationBytes> encode(const EcTargetRetirementObservationClaims &);
  static Result<EcTargetRetirementObservationClaims> decodeObservation(std::string_view);
  static Result<EcTargetRetirementRequest> signRequest(const EcScopeControlKey &,
                                                       const EcTargetRetirementClaims &,
                                                       uint64_t);
  static Result<Void> verifyRequest(const EcScopeControlKey &,
                                    const EcTargetRetirementRequest &,
                                    const Uuid &,
                                    NodeId,
                                    EcTargetRetirementAction,
                                    uint64_t);
  static Result<Void> verifyObservation(const EcScopeControlKey &,
                                        const EcTargetRetirementObservation &,
                                        const EcTargetRetirementRequest &);

 private:
  friend class ::hf3fs::storage::EcTargetRetirementExecutor;
  // The real disk executor alone calls this after observing the registry and
  // rechecking the exact loaded target, configured authority, and request time.
  // No public receipt factory accepts caller-supplied drain claims.
  static Result<EcTargetRetirementObservation> signObserved(const EcScopeControlKey &,
                                                            const EcTargetRetirementRequest &,
                                                            const Uuid &bootNonce,
                                                            bool durable,
                                                            uint64_t inflight,
                                                            uint64_t nowSeconds);
};
}  // namespace ec_target_retirement_detail
}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcTargetRetirementRequest> {
  static void serialize(const storage::EcTargetRetirementRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_target_retirement_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcTargetRetirementRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC target retirement requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC target retirement requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_target_retirement_detail::Codec::decodeRequest(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcTargetRetirementRequest decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcTargetRetirementObservation> {
  static void serialize(const storage::EcTargetRetirementObservation &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_target_retirement_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcTargetRetirementObservation &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC target retirement requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC target retirement requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_target_retirement_detail::Codec::decodeObservation(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcTargetRetirementObservation decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

namespace hf3fs::storage {
struct EcTargetRetirementRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcTargetRetirementObservation>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(serde::Serializable<EcTargetRetirementRequest>);
static_assert(serde::Serializable<EcTargetRetirementObservation>);
}  // namespace hf3fs::storage

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcTargetRetirementRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcTargetRetirementRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcTargetRetirementObservation> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcTargetRetirementObservation &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
