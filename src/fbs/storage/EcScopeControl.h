#pragma once

#include "fbs/storage/EcAuthorization.h"

namespace hf3fs::storage {
class EcScopeControlExecutor;
namespace ec_target_discovery_detail {
class Codec;
}
namespace ec_scope_control_detail {
class Codec;
}

inline constexpr uint16_t kEcScopeControlVersion = 1;
inline constexpr size_t kEcScopeControlRequestBytes = 208;
inline constexpr size_t kEcScopeControlAckBytes = 108;
inline constexpr uint64_t kEcScopeControlMaxTtlSeconds = 300;
enum class EcScopeControlAction : uint8_t { Revoke = 1, Query = 2 };
enum class EcScopeControlState : uint8_t { Pending = 1, Drained = 2 };

// An explicit control-role key. Data capability keys cannot implicitly convert
// to this type. Configuration must supply a separate owner-only raw key file.
class EcScopeControlKey final {
 public:
  static Result<std::unique_ptr<EcScopeControlKey>> loadFile(const std::filesystem::path &path);
  EcScopeControlKey(const EcScopeControlKey &) = delete;
  EcScopeControlKey &operator=(const EcScopeControlKey &) = delete;

 private:
  friend class ec_scope_control_detail::Codec;
  friend class ec_target_discovery_detail::Codec;
  explicit EcScopeControlKey(std::unique_ptr<EcCapabilityKey> key)
      : key_(std::move(key)) {}
  std::unique_ptr<EcCapabilityKey> key_;
};

struct EcScopeControlClaims {
  uint16_t version = kEcScopeControlVersion;
  EcScopeControlAction action = EcScopeControlAction::Revoke;
  Uuid clusterAuthority = Uuid::zero();
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid engineUuid = Uuid::zero();
  Uuid targetIncarnation = Uuid::zero();
  Uuid object = Uuid::zero();
  EcGrantScope scopeKind = EcGrantScope::ReadPin;
  Uuid scopeId = Uuid::zero();
  flat::Uid ownerUid{};
  Uuid clientNamespace = Uuid::zero();
  EcSha256 endpointSetDigest{};
  Uuid revocationId = Uuid::zero();
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};

struct EcScopeControlRequest {
  EcScopeControlClaims claims;
  std::string serdeToReadable() const { return "EcScopeControlRequest(REDACTED)"; }

 private:
  friend class ec_scope_control_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcScopeControlRequest>;
  EcSha256 signature_{};
};

struct EcScopeControlAckClaims {
  uint16_t version = kEcScopeControlVersion;
  // Binds the entire canonical request, including its action/nonce/authority.
  EcSha256 requestDigest{};
  // Canonical logical deny record, not RocksDB's physical byte encoding.
  EcSha256 revocationDigest{};
  Uuid bootNonce = Uuid::zero();
  EcScopeControlState state = EcScopeControlState::Pending;
  bool durable = false;
  uint64_t inflight = 0;
  uint64_t observedAtSeconds = 0;
};
struct EcScopeControlAck {
  EcScopeControlAckClaims claims;
  std::string serdeToReadable() const { return "EcScopeControlAck(REDACTED)"; }

 private:
  friend class ec_scope_control_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcScopeControlAck>;
  EcSha256 signature_{};
};

struct EcScopeEndpoint {
  NodeId nodeId{};
  ChainId chainId{};
  TargetId targetId{};
  Uuid engineUuid = Uuid::zero();
  Uuid targetIncarnation = Uuid::zero();
};
// 1..24 supplied endpoints; exact duplicates are removed. Canonical records
// are node:u32BE|chain:u32BE|target:u64BE|engine:16raw|incarnation:16raw, sorted
// lexicographically. Distinct incarnations of one logical target remain in set.
// SHA256("3FSECEP1"|version:u16BE=1|uniqueCount:u16BE|records), not a trust proof.
Result<EcSha256> computeEcScopeEndpointDigest(std::span<const EcScopeEndpoint> endpoints);

// Signing requests is a coordinator capability, never a client-data right.
Result<EcScopeControlRequest> signEcScopeControl(const EcScopeControlKey &key,
                                                 const EcScopeControlClaims &claims,
                                                 uint64_t nowSeconds);
Result<Void> verifyEcScopeControl(const EcScopeControlKey &key,
                                  const EcScopeControlRequest &request,
                                  const Uuid &clusterAuthority,
                                  NodeId localNode,
                                  EcScopeControlAction requiredAction,
                                  uint64_t nowSeconds);
// The caller supplies its exact issued request. ACK observation time is not a
// TTL or GC fence: a durable, irreversible deny proof does not expire by time.
Result<Void> verifyEcScopeControlAck(const EcScopeControlKey &key,
                                     const EcScopeControlAck &ack,
                                     const EcScopeControlRequest &issuedRequest);

namespace ec_scope_control_detail {
class Codec {
 public:
  static std::array<uint8_t, kEcScopeControlRequestBytes> encode(const EcScopeControlClaims &);
  static Result<EcScopeControlClaims> decodeRequest(std::string_view);
  static std::array<uint8_t, kEcScopeControlAckBytes> encode(const EcScopeControlAckClaims &);
  static Result<EcScopeControlAckClaims> decodeAck(std::string_view);
  static Result<EcScopeControlRequest> signRequest(const EcScopeControlKey &, const EcScopeControlClaims &, uint64_t);
  static Result<Void> verifyRequest(const EcScopeControlKey &,
                                    const EcScopeControlRequest &,
                                    const Uuid &,
                                    NodeId,
                                    EcScopeControlAction,
                                    uint64_t);
  static Result<Void> verifyAck(const EcScopeControlKey &, const EcScopeControlAck &, const EcScopeControlRequest &);

 private:
  friend class ::hf3fs::storage::EcScopeControlExecutor;
  // No public receipt factory accepts caller-supplied "drained" claims. The
  // disk executor alone calls this after a real registry observation.
  static Result<EcScopeControlAck> signObserved(const EcScopeControlKey &,
                                                const EcScopeControlRequest &,
                                                const Uuid &bootNonce,
                                                bool durable,
                                                uint64_t inflight,
                                                uint64_t nowSeconds);
};
}  // namespace ec_scope_control_detail
}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcScopeControlRequest> {
  static void serialize(const storage::EcScopeControlRequest &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_scope_control_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcScopeControlRequest &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC control requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC control requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_scope_control_detail::Codec::decodeRequest(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcScopeControlRequest decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcScopeControlAck> {
  static void serialize(const storage::EcScopeControlAck &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      auto bytes = storage::ec_scope_control_detail::Codec::encode(value.claims);
      out.arrayBegin();
      serde::serialize(value.signature_, out);
      serde::serialize(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), out);
      out.arrayEnd(2);
    } else {
      serde::serialize(value.serdeToReadable(), out);
    }
  }
  static Result<Void> deserialize(storage::EcScopeControlAck &value, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      return makeError(StatusCode::kInvalidFormat, "EC control requires binary Serde");
    } else {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 2) return makeError(StatusCode::kInvalidFormat, "EC control requires two fixed fields");
      std::string_view bytes;
      RETURN_ON_ERROR(serde::deserialize(bytes, in));
      CHECK_RESULT(claims, storage::ec_scope_control_detail::Codec::decodeAck(bytes));
      storage::EcSha256 signature{};
      RETURN_ON_ERROR(serde::deserialize(signature, in));
      storage::EcScopeControlAck decoded;
      decoded.claims = claims;
      decoded.signature_ = signature;
      value = std::move(decoded);
      return Void{};
    }
  }
};

namespace hf3fs::storage {
struct EcScopeControlRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcScopeControlAck>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(serde::Serializable<EcScopeControlRequest>);
static_assert(serde::Serializable<EcScopeControlAck>);
}  // namespace hf3fs::storage

FMT_BEGIN_NAMESPACE
template <>
struct formatter<hf3fs::storage::EcScopeControlRequest> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcScopeControlRequest &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
template <>
struct formatter<hf3fs::storage::EcScopeControlAck> : formatter<std::string_view> {
  template <typename Context>
  auto format(const hf3fs::storage::EcScopeControlAck &value, Context &ctx) const {
    return formatter<std::string_view>::format(value.serdeToReadable(), ctx);
  }
};
FMT_END_NAMESPACE
