#include "EcGcAbsentControl.h"

#include <cstring>
#include <openssl/evp.h>

#include "common/serde/Serde.h"
#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
using Crypto = ec_authorization_detail::Access;
constexpr std::string_view requestDomain = "3FSGABQ1";
constexpr std::string_view ackDomain = "3FSGABA1";
constexpr std::string_view closureDomain = "3FSGABC1";
struct RequestWire {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(action, EcGcAbsentAction::ConfirmAbsent);
  SERDE_STRUCT_FIELD(keyId, Uuid::zero());
  SERDE_STRUCT_FIELD(authority, Uuid::zero());
  SERDE_STRUCT_FIELD(nonce, Uuid::zero());
  SERDE_STRUCT_FIELD(issuedAtSeconds, uint64_t{});
  SERDE_STRUCT_FIELD(expiresAtSeconds, uint64_t{});
  SERDE_STRUCT_FIELD(certificate, std::string{});
  SERDE_STRUCT_FIELD(closure, EcGcLocalClosureWitness{});
};
struct AckWire {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(state, EcGcAbsentState::AbsentAfterClose);
  SERDE_STRUCT_FIELD(keyId, Uuid::zero());
  SERDE_STRUCT_FIELD(authority, Uuid::zero());
  SERDE_STRUCT_FIELD(requestDigest, EcSha256{});
  SERDE_STRUCT_FIELD(claimDigest, EcSha256{});
  SERDE_STRUCT_FIELD(closureDigest, EcSha256{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(node, NodeId{});
  SERDE_STRUCT_FIELD(chain, ChainId{});
  SERDE_STRUCT_FIELD(target, TargetId{});
  SERDE_STRUCT_FIELD(engine, Uuid::zero());
  SERDE_STRUCT_FIELD(incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(ledgerSha256, EcSha256{});
  SERDE_STRUCT_FIELD(recordRevision, uint64_t{});
  SERDE_STRUCT_FIELD(observedAtSeconds, uint64_t{});
  SERDE_STRUCT_FIELD(bootNonce, Uuid::zero());
};
std::span<const uint8_t> bytes(std::string_view s) {
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}
Result<EcSha256> digest(std::string_view s) {
  EcSha256 result{};
  unsigned int n = 0;
  if (EVP_Digest(s.data(), s.size(), result.data(), &n, EVP_sha256(), nullptr) != 1 || n != result.size())
    return makeError(StatusCode::kIOError);
  return result;
}
bool same(const EcScopeEndpoint &a, const EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId &&
         a.engineUuid == b.engineUuid && a.targetIncarnation == b.targetIncarnation;
}
template <typename T> bool endpoint(const T &v, const EcScopeEndpoint &e) {
  return v.nodeId == e.nodeId && v.chainId == e.chainId && v.targetId == e.targetId &&
         v.engineUuid == e.engineUuid && v.targetIncarnation == e.targetIncarnation;
}
Result<Void> validate(const EcGcAbsentRequestClaims &v) {
  CHECK_RESULT(unused, ec_gc_control_detail::Codec::claimDigest(v.certificate));
  (void)unused;
  const auto &c = v.certificate;
  const auto &w = v.closure;
  if (v.version != 1 || (v.action != EcGcAbsentAction::ConfirmAbsent && v.action != EcGcAbsentAction::QueryAbsent) ||
      v.keyId.is_nil() || v.authority.is_nil() || v.nonce.is_nil() ||
      v.expiresAtSeconds <= v.issuedAtSeconds || v.expiresAtSeconds - v.issuedAtSeconds > kEcGcMaxTtlSeconds ||
      c.version != 2 || c.metaMode != 4 || c.catalogVersion != 2 || c.enrollmentVersion != 2 ||
      c.bindingVersion != 1 || c.dataProtocol != 2 || c.diskFormat != 3 || c.gcProtocol != 2 ||
      w.version != 1 || w.scopeKind != EcGrantScope::WriteOperation || w.scopeId != c.fragmentOperation ||
      w.ownerUid != c.writerUid || w.clientNamespace != c.writerClient ||
      w.objectEpoch == 0 || w.generation != c.fragment.generation || w.revision == 0 ||
      w.endpointSetDigest == EcSha256{} || w.revocationId.is_nil() || w.originDrainEvidence != c.originDrainEvidence ||
      (w.terminalUse != EcGcClosureUse::Publication && w.terminalUse != EcGcClosureUse::FencedAbort))
    return makeError(StatusCode::kInvalidArg, "invalid absence G2 or original closure binding");
  if (w.kind == EcGcClosureKind::ScopeRevocation) {
    if (!w.scopeRequest || !w.scopeAck || w.retirementRequest || w.retirementObservation)
      return makeError(StatusCode::kInvalidArg, "absence requires one complete local witness");
    const auto &r = w.scopeRequest->claims;
    const auto &a = w.scopeAck->claims;
    if (!endpoint(r, c.endpoint) || r.clusterAuthority != v.authority || r.object != c.objectIncarnation ||
        r.scopeKind != w.scopeKind || r.scopeId != w.scopeId || r.ownerUid != w.ownerUid ||
        r.clientNamespace != w.clientNamespace || r.revocationId != w.revocationId ||
        r.endpointSetDigest != w.endpointSetDigest || a.state != EcScopeControlState::Drained || !a.durable || a.inflight != 0)
      return makeError(StatusCode::kTokenMismatch, "absence original scope witness differs");
  } else if (w.kind == EcGcClosureKind::TargetRetirement) {
    if (w.terminalUse != EcGcClosureUse::FencedAbort || w.scopeRequest || w.scopeAck ||
        !w.retirementRequest || !w.retirementObservation)
      return makeError(StatusCode::kInvalidArg, "retirement cannot replace publication evidence");
    const auto &r = w.retirementRequest->claims;
    const auto &a = w.retirementObservation->claims;
    if (!endpoint(r, c.endpoint) || r.clusterAuthority != v.authority || r.retirementId.is_nil() ||
        a.state != EcTargetRetirementState::LocalDataDrained || !a.durable || a.inflight != 0)
      return makeError(StatusCode::kTokenMismatch, "absence original retirement witness differs");
  } else return makeError(StatusCode::kInvalidArg, "unknown absence closure kind");
  return Void{};
}
Result<Void> validate(const EcGcAbsentAckClaims &v) {
  const auto &e = v.endpoint;
  if (v.version != 1 || v.state != EcGcAbsentState::AbsentAfterClose || v.keyId.is_nil() || v.authority.is_nil() ||
      v.claimId.is_nil() || v.bootNonce.is_nil() || v.requestDigest == EcSha256{} || v.claimDigest == EcSha256{} ||
      v.closureDigest == EcSha256{} || v.ledgerSha256 == EcSha256{} || v.recordRevision != 1 ||
      e.nodeId == NodeId{} || e.chainId == ChainId{} || e.targetId == TargetId{} || e.engineUuid.is_nil() ||
      e.targetIncarnation.is_nil()) return makeError(StatusCode::kInvalidArg, "invalid absence acknowledgement");
  return Void{};
}
}
namespace ec_gc_absent_detail {
std::string Codec::encode(const EcGcAbsentRequestClaims &v) {
  RequestWire w;
  w.version = v.version; w.action = v.action; w.keyId = v.keyId; w.authority = v.authority; w.nonce = v.nonce;
  w.issuedAtSeconds = v.issuedAtSeconds; w.expiresAtSeconds = v.expiresAtSeconds; w.closure = v.closure;
  const auto c = ec_gc_control_detail::Codec::encode(v.certificate);
  w.certificate.assign(reinterpret_cast<const char *>(c.data()), c.size());
  return std::string(requestDomain) + serde::serialize(w);
}
std::string Codec::encode(const EcGcAbsentAckClaims &v) {
  AckWire w;
  w.version = v.version; w.state = v.state; w.keyId = v.keyId; w.authority = v.authority;
  w.requestDigest = v.requestDigest; w.claimDigest = v.claimDigest; w.closureDigest = v.closureDigest;
  w.claimId = v.claimId; w.node = v.endpoint.nodeId; w.chain = v.endpoint.chainId; w.target = v.endpoint.targetId;
  w.engine = v.endpoint.engineUuid; w.incarnation = v.endpoint.targetIncarnation; w.ledgerSha256 = v.ledgerSha256;
  w.recordRevision = v.recordRevision; w.observedAtSeconds = v.observedAtSeconds; w.bootNonce = v.bootNonce;
  return std::string(ackDomain) + serde::serialize(w);
}
Result<EcGcAbsentRequest> Codec::decodeRequest(std::string_view body, std::string_view mac) {
  if (body.size() > kEcGcAbsentMaxBodyBytes || body.substr(0, 8) != requestDomain || mac.size() != 32)
    return makeError(StatusCode::kInvalidFormat, "invalid absence request extent or domain");
  RequestWire w;
  RETURN_ON_ERROR(serde::deserialize(w, body.substr(8)));
  CHECK_RESULT(c, ec_gc_control_detail::Codec::decodeCertificate(w.certificate));
  EcGcAbsentRequest r;
  r.claims = {w.version, w.action, w.keyId, w.authority, w.nonce, w.issuedAtSeconds, w.expiresAtSeconds, c, w.closure};
  RETURN_ON_ERROR(validate(r.claims));
  if (encode(r.claims) != body) return makeError(StatusCode::kInvalidFormat, "noncanonical absence request");
  std::memcpy(r.signature_.data(), mac.data(), 32);
  return r;
}
Result<EcGcAbsentAck> Codec::decodeAck(std::string_view body, std::string_view mac) {
  if (body.size() > kEcGcAbsentMaxBodyBytes || body.substr(0, 8) != ackDomain || mac.size() != 32)
    return makeError(StatusCode::kInvalidFormat, "invalid absence acknowledgement extent or domain");
  AckWire w;
  RETURN_ON_ERROR(serde::deserialize(w, body.substr(8)));
  EcGcAbsentAck r;
  auto &a = r.claims;
  a.version=w.version; a.state=w.state; a.keyId=w.keyId; a.authority=w.authority; a.requestDigest=w.requestDigest;
  a.claimDigest=w.claimDigest; a.closureDigest=w.closureDigest; a.claimId=w.claimId;
  a.endpoint={w.node,w.chain,w.target,w.engine,w.incarnation}; a.ledgerSha256=w.ledgerSha256;
  a.recordRevision=w.recordRevision; a.observedAtSeconds=w.observedAtSeconds; a.bootNonce=w.bootNonce;
  RETURN_ON_ERROR(validate(a));
  if (encode(a) != body) return makeError(StatusCode::kInvalidFormat, "noncanonical absence acknowledgement");
  std::memcpy(r.signature_.data(), mac.data(), 32);
  return r;
}
Result<EcSha256> Codec::closureDigest(const EcGcLocalClosureWitness &w) {
  return digest(std::string(closureDomain) + serde::serialize(w));
}
Result<EcGcAbsentRequest> Codec::signRequest(const EcGcKey &key, const EcGcAbsentRequestClaims &v, uint64_t now) {
  RETURN_ON_ERROR(validate(v));
  if (v.keyId != key.keyId() || now < v.issuedAtSeconds || now >= v.expiresAtSeconds)
    return makeError(StatusCode::kAuthenticationFail);
  const auto body = encode(v);
  if (body.size() > kEcGcAbsentMaxBodyBytes) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(mac, Crypto::authenticate(*key.key_, bytes(body)));
  EcGcAbsentRequest r; r.claims=v; r.signature_=mac; return r;
}
Result<VerifiedEcGcAbsentRequest> Codec::verifyRequest(const EcGcKey &key, const EcGcAbsentRequest &r,
    const Uuid &authority, const EcGcLocalTarget &t, uint64_t now) {
  RETURN_ON_ERROR(validate(r.claims));
  CHECK_RESULT(mac, Crypto::authenticate(*key.key_, bytes(encode(r.claims))));
  if (!Crypto::constantTimeEqual(mac, r.signature_) || r.claims.keyId != key.keyId() ||
      r.claims.authority != authority || !same(r.claims.certificate.endpoint,t.endpoint) ||
      now < r.claims.issuedAtSeconds || now >= r.claims.expiresAtSeconds)
    return makeError(StatusCode::kAuthenticationFail);
  if (!t.enabled || t.dataProtocol != 2 || t.diskFormat != 3 || t.gcProtocol != 2)
    return makeError(StatusCode::kInvalidConfig);
  CHECK_RESULT(c, ec_gc_control_detail::Codec::claimDigest(r.claims.certificate));
  CHECK_RESULT(w, closureDigest(r.claims.closure));
  return VerifiedEcGcAbsentRequest(r,c,w);
}
Result<Void> Codec::verifyAck(const EcGcKey &key, const EcGcAbsentAck &a, const EcGcAbsentRequest &r) {
  RETURN_ON_ERROR(validate(a.claims)); RETURN_ON_ERROR(validate(r.claims));
  CHECK_RESULT(rmac, Crypto::authenticate(*key.key_, bytes(encode(r.claims))));
  CHECK_RESULT(amac, Crypto::authenticate(*key.key_, bytes(encode(a.claims))));
  CHECK_RESULT(rd, digest(encode(r.claims)));
  CHECK_RESULT(cd, ec_gc_control_detail::Codec::claimDigest(r.claims.certificate));
  CHECK_RESULT(wd, closureDigest(r.claims.closure));
  const auto &v=a.claims;
  if (!Crypto::constantTimeEqual(rmac,r.signature_) || !Crypto::constantTimeEqual(amac,a.signature_) ||
      v.keyId!=key.keyId() || v.keyId!=r.claims.keyId || v.authority!=r.claims.authority || v.requestDigest!=rd ||
      v.claimDigest!=cd || v.closureDigest!=wd || v.claimId!=r.claims.certificate.claimId ||
      !same(v.endpoint,r.claims.certificate.endpoint) || v.observedAtSeconds<r.claims.issuedAtSeconds ||
      v.observedAtSeconds>=r.claims.expiresAtSeconds) return makeError(StatusCode::kAuthenticationFail);
  return Void{};
}
Result<EcGcAbsentAck> Codec::signConfirmed(const EcGcKey &key, const VerifiedEcGcAbsentRequest &verified,
    Result<EcGcAbsentLedgerReceipt> receipt, const EcGcLocalTarget &t, const Uuid &authority,
    const Uuid &boot, uint64_t now) {
  if (!receipt) return makeError(std::move(receipt.error()));
  try {
    const auto &r=verified.request();
    if (!verifyRequest(key,r,authority,t,now) || receipt->claimId!=verified.certificate().claimId ||
        receipt->recordRevision!=1 || receipt->ledgerSha256==EcSha256{} || boot.is_nil())
      return makeError(StorageCode::kEcSealOutcomeUnknown);
    EcGcAbsentAck a;
    auto &v=a.claims;
    v.keyId=r.claims.keyId; v.authority=authority;
    auto rd=digest(encode(r.claims)); if (!rd) return makeError(StorageCode::kEcSealOutcomeUnknown);
    v.requestDigest=*rd; v.claimDigest=verified.claimDigest(); v.closureDigest=verified.closureDigest();
    v.claimId=receipt->claimId; v.endpoint=t.endpoint; v.ledgerSha256=receipt->ledgerSha256;
    v.recordRevision=receipt->recordRevision; v.observedAtSeconds=now; v.bootNonce=boot;
    auto mac=Crypto::authenticate(*key.key_,bytes(encode(v))); if (!mac) return makeError(StorageCode::kEcSealOutcomeUnknown);
    a.signature_=*mac; return a;
  } catch (...) { return makeError(StorageCode::kEcSealOutcomeUnknown); }
}
}
}
