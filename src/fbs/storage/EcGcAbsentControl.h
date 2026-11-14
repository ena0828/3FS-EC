#pragma once

#include "fbs/storage/EcGcControl.h"
#include "fbs/storage/EcTargetRetirementControl.h"

namespace hf3fs::meta::server { class EcGcAbsentCoordinator; }
namespace hf3fs::storage {
class EcGcAbsentExecutor;
class EcGcAbsentTestAccess;
namespace ec_gc_absent_detail { class Codec; }

inline constexpr uint16_t kEcGcAbsentProtocol = 1;
inline constexpr size_t kEcGcAbsentMaxBodyBytes = 4096;
enum class EcGcAbsentAction : uint8_t { ConfirmAbsent = 1, QueryAbsent = 2 };
enum class EcGcAbsentState : uint8_t { AbsentAfterClose = 1 };
enum class EcGcClosureKind : uint8_t { ScopeRevocation = 1, TargetRetirement = 2 };
enum class EcGcClosureUse : uint8_t { Publication = 1, FencedAbort = 2 };

// The G issuer revalidates the entire original distributed T2. This is only
// the original local endpoint's witness, never a replacement for that T2.
// Signed C material is binary-only in its own Serde adapters.
struct EcGcLocalClosureWitness {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(kind, EcGcClosureKind::ScopeRevocation);
  SERDE_STRUCT_FIELD(terminalUse, EcGcClosureUse::FencedAbort);
  SERDE_STRUCT_FIELD(scopeKind, EcGrantScope::WriteOperation);
  SERDE_STRUCT_FIELD(scopeId, Uuid::zero());
  SERDE_STRUCT_FIELD(ownerUid, flat::Uid{});
  SERDE_STRUCT_FIELD(clientNamespace, Uuid::zero());
  SERDE_STRUCT_FIELD(objectEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(endpointSetDigest, EcSha256{});
  SERDE_STRUCT_FIELD(revocationId, Uuid::zero());
  SERDE_STRUCT_FIELD(originDrainEvidence, EcSha256{});
  SERDE_STRUCT_FIELD(scopeRequest, (std::optional<EcScopeControlRequest>{}));
  SERDE_STRUCT_FIELD(scopeAck, (std::optional<EcScopeControlAck>{}));
  SERDE_STRUCT_FIELD(retirementRequest, (std::optional<EcTargetRetirementRequest>{}));
  SERDE_STRUCT_FIELD(retirementObservation, (std::optional<EcTargetRetirementObservation>{}));
};

struct EcGcAbsentRequestClaims {
  uint16_t version = kEcGcAbsentProtocol;
  EcGcAbsentAction action = EcGcAbsentAction::ConfirmAbsent;
  Uuid keyId = Uuid::zero();
  Uuid authority = Uuid::zero();
  Uuid nonce = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
  // Exactly the existing complete G2 projection and original claim digest.
  EcGcCertificate certificate;
  EcGcLocalClosureWitness closure;
};
struct EcGcAbsentRequest {
  EcGcAbsentRequestClaims claims;
  std::string serdeToReadable() const { return "EcGcAbsentRequest(REDACTED)"; }
 private:
  friend class ec_gc_absent_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcAbsentRequest>;
  EcSha256 signature_{};
};
struct EcGcAbsentAckClaims {
  uint16_t version = 1;
  EcGcAbsentState state = EcGcAbsentState::AbsentAfterClose;
  Uuid keyId = Uuid::zero(), authority = Uuid::zero();
  EcSha256 requestDigest{}, claimDigest{}, closureDigest{};
  Uuid claimId = Uuid::zero();
  EcScopeEndpoint endpoint;
  EcSha256 ledgerSha256{};
  uint64_t recordRevision = 0, observedAtSeconds = 0;
  Uuid bootNonce = Uuid::zero();
};

struct EcGcAbsentAck {
  EcGcAbsentAckClaims claims;
  std::string serdeToReadable() const { return "EcGcAbsentAck(REDACTED)"; }
 private:
  friend class ec_gc_absent_detail::Codec;
  friend struct ::hf3fs::serde::SerdeMethod<EcGcAbsentAck>;
  EcSha256 signature_{};
};
struct EcGcAbsentLedgerReceipt {
  Uuid claimId = Uuid::zero();
  EcSha256 ledgerSha256{};
  uint64_t recordRevision = 0;
};
class VerifiedEcGcAbsentRequest {
 public:
  const EcGcAbsentRequest &request() const { return request_; }
  const EcGcCertificate &certificate() const { return request_.claims.certificate; }
  EcGcAbsentAction action() const { return request_.claims.action; }
  const EcSha256 &claimDigest() const { return claimDigest_; }
  const EcSha256 &closureDigest() const { return closureDigest_; }
 private:
  friend class ec_gc_absent_detail::Codec;
  VerifiedEcGcAbsentRequest(EcGcAbsentRequest r, EcSha256 c, EcSha256 w)
      : request_(std::move(r)), claimDigest_(c), closureDigest_(w) {}
  EcGcAbsentRequest request_;
  EcSha256 claimDigest_{};
  EcSha256 closureDigest_{};
};
namespace ec_gc_absent_detail {
class Codec {
 public:
  static std::string encode(const EcGcAbsentRequestClaims &);
  static std::string encode(const EcGcAbsentAckClaims &);
  static Result<EcGcAbsentRequest> decodeRequest(std::string_view, std::string_view);
  static Result<EcGcAbsentAck> decodeAck(std::string_view, std::string_view);
  static Result<EcSha256> closureDigest(const EcGcLocalClosureWitness &);
  static Result<VerifiedEcGcAbsentRequest> verifyRequest(const EcGcKey &, const EcGcAbsentRequest &,
      const Uuid &authority, const EcGcLocalTarget &, uint64_t now);
  static Result<Void> verifyAck(const EcGcKey &, const EcGcAbsentAck &, const EcGcAbsentRequest &);
 private:
  friend class RequestSigner;
  friend class AckSigner;
  static Result<EcGcAbsentRequest> signRequest(const EcGcKey &, const EcGcAbsentRequestClaims &, uint64_t);
  static Result<EcGcAbsentAck> signConfirmed(const EcGcKey &, const VerifiedEcGcAbsentRequest &,
      Result<EcGcAbsentLedgerReceipt>, const EcGcLocalTarget &, const Uuid &, const Uuid &, uint64_t);
};
class RequestSigner final {
 private:
  friend class ::hf3fs::meta::server::EcGcAbsentCoordinator;
  friend class ::hf3fs::storage::EcGcAbsentTestAccess;
  static Result<EcGcAbsentRequest> sign(const EcGcKey &key, const EcGcAbsentRequestClaims &c, uint64_t now) {
    return Codec::signRequest(key, c, now);
  }
};
class AckSigner final {
 private:
  friend class ::hf3fs::storage::EcGcAbsentExecutor;
  friend class ::hf3fs::storage::EcGcAbsentTestAccess;
  static Result<EcGcAbsentAck> sign(const EcGcKey &key, const VerifiedEcGcAbsentRequest &r,
      Result<EcGcAbsentLedgerReceipt> receipt, const EcGcLocalTarget &t, const Uuid &a, const Uuid &b, uint64_t now) {
    return Codec::signConfirmed(key, r, std::move(receipt), t, a, b, now);
  }
};
}
struct EcGcAbsentRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcGcAbsentAck>{makeError(StorageClientCode::kNotInitialized)}));
};
}

// Bound binary envelopes. No readable token import, and no signed body is
// included in logs/administrative archives.
#define EC_ABSENT_SERDE(Type, Decode) \
template <> struct hf3fs::serde::SerdeMethod<hf3fs::storage::Type> { \
  static void serialize(const storage::Type &v, auto &out) { \
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) { \
      auto body = storage::ec_gc_absent_detail::Codec::encode(v.claims); \
      out.arrayBegin(); serde::serialize(v.signature_, out); serde::serialize(body, out); out.arrayEnd(2); \
    } else { serde::serialize(v.serdeToReadable(), out); } \
  } \
  static Result<Void> deserialize(storage::Type &v, auto &in) { \
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; }) { \
      return makeError(StatusCode::kInvalidFormat, "absence exchange requires binary Serde"); \
    } else { \
      Varint64 n = 0; RETURN_ON_ERROR(serde::deserialize(n, in)); \
      if (n != 2) return makeError(StatusCode::kInvalidFormat, "invalid absence envelope"); \
      std::string_view body, mac; RETURN_ON_ERROR(serde::deserialize(body, in)); RETURN_ON_ERROR(serde::deserialize(mac, in)); \
      CHECK_RESULT(decoded, storage::ec_gc_absent_detail::Codec::Decode(body, mac)); v = std::move(decoded); return Void{}; \
    } \
  } \
};
EC_ABSENT_SERDE(EcGcAbsentRequest, decodeRequest)
EC_ABSENT_SERDE(EcGcAbsentAck, decodeAck)
#undef EC_ABSENT_SERDE

FMT_BEGIN_NAMESPACE
template <> struct formatter<hf3fs::storage::EcGcAbsentRequest> : formatter<std::string_view> {
  template <typename Context> auto format(const hf3fs::storage::EcGcAbsentRequest &v, Context &c) const {
    return formatter<std::string_view>::format(v.serdeToReadable(), c);
  }
};
template <> struct formatter<hf3fs::storage::EcGcAbsentAck> : formatter<std::string_view> {
  template <typename Context> auto format(const hf3fs::storage::EcGcAbsentAck &v, Context &c) const {
    return formatter<std::string_view>::format(v.serdeToReadable(), c);
  }
};
FMT_END_NAMESPACE
