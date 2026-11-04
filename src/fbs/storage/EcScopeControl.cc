#include "EcScopeControl.h"

#include <algorithm>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view requestDomain = "3FSECRQ1";
constexpr std::string_view ackDomain = "3FSECAK1";
constexpr std::string_view denyDomain = "3FSECDN1";
using Crypto = ec_authorization_detail::Access;

template <size_t N>
struct Writer {
  std::array<uint8_t, N> bytes{};
  size_t offset = 0;
  void integer(uint64_t value, size_t width) {
    assert(offset + width <= N);
    for (size_t i = width; i != 0; --i) bytes[offset++] = static_cast<uint8_t>(value >> ((i - 1) * 8));
  }
  void raw(std::span<const uint8_t> value) {
    assert(offset + value.size() <= N);
    std::copy(value.begin(), value.end(), bytes.begin() + offset);
    offset += value.size();
  }
  void domain(std::string_view value) { raw({reinterpret_cast<const uint8_t *>(value.data()), value.size()}); }
  void uuid(const Uuid &value) { raw(value.data); }
  auto finish() {
    assert(offset == N);
    return bytes;
  }
};
struct Reader {
  std::string_view bytes;
  size_t offset = 8;
  uint64_t integer(size_t width) {
    uint64_t result = 0;
    for (size_t i = 0; i != width; ++i) result = (result << 8) | static_cast<uint8_t>(bytes[offset++]);
    return result;
  }
  Uuid uuid() {
    Uuid value;
    std::memcpy(value.data, bytes.data() + offset, 16);
    offset += 16;
    return value;
  }
  EcSha256 digest() {
    EcSha256 value{};
    std::memcpy(value.data(), bytes.data() + offset, 32);
    offset += 32;
    return value;
  }
};
bool zero(const EcSha256 &value) {
  return std::all_of(value.begin(), value.end(), [](auto b) { return b == 0; });
}
Result<Void> validate(const EcScopeControlClaims &value) {
  if (value.version != kEcScopeControlVersion ||
      (value.action != EcScopeControlAction::Revoke && value.action != EcScopeControlAction::Query) ||
      value.clusterAuthority.is_nil() || value.nodeId == NodeId{} || value.chainId == ChainId{} ||
      value.targetId == TargetId{} || value.engineUuid.is_nil() || value.targetIncarnation.is_nil() ||
      value.object.is_nil() || value.scopeId.is_nil() || value.clientNamespace.is_nil() ||
      value.revocationId.is_nil() || value.nonce.is_nil() || zero(value.endpointSetDigest) ||
      (value.scopeKind != EcGrantScope::ReadPin && value.scopeKind != EcGrantScope::WriteOperation) ||
      value.expiresAtSeconds <= value.issuedAtSeconds ||
      value.expiresAtSeconds - value.issuedAtSeconds > kEcScopeControlMaxTtlSeconds) {
    return makeError(StatusCode::kInvalidArg, "invalid EC control identity, scope, version or bounded lifetime");
  }
  return Void{};
}
Result<Void> validate(const EcScopeControlAckClaims &value) {
  if (value.version != kEcScopeControlVersion || zero(value.requestDigest) || zero(value.revocationDigest) ||
      value.bootNonce.is_nil() ||
      (value.state != EcScopeControlState::Pending && value.state != EcScopeControlState::Drained) ||
      ((value.state == EcScopeControlState::Drained) != (value.durable && value.inflight == 0))) {
    return makeError(StatusCode::kInvalidArg, "invalid or contradictory EC drain acknowledgement");
  }
  return Void{};
}
Result<Void> checkTime(const EcScopeControlClaims &value, uint64_t now) {
  if (now < value.issuedAtSeconds || now >= value.expiresAtSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "EC control request is not currently valid");
  }
  return Void{};
}
Result<EcSha256> digest(std::span<const uint8_t> bytes) {
  EcSha256 value{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), value.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != value.size()) {
    return makeError(StatusCode::kIOError, "EC control SHA-256 calculation failed");
  }
  return value;
}
Result<EcSha256> denyDigest(const EcScopeControlClaims &value) {
  Writer<153> out;
  out.domain(denyDomain);
  out.uuid(value.engineUuid);
  out.uuid(value.targetIncarnation);
  out.integer(value.chainId.toUnderType(), 4);
  out.integer(value.targetId.toUnderType(), 8);
  out.uuid(value.object);
  out.integer(static_cast<uint8_t>(value.scopeKind), 1);
  out.uuid(value.scopeId);
  out.integer(value.ownerUid.toUnderType(), 4);
  out.uuid(value.clientNamespace);
  out.uuid(value.revocationId);
  out.raw(value.endpointSetDigest);
  return digest(out.finish());
}
}  // namespace

Result<EcSha256> computeEcScopeEndpointDigest(std::span<const EcScopeEndpoint> endpoints) {
  if (endpoints.empty() || endpoints.size() > 24) {
    return makeError(StatusCode::kInvalidArg, "EC scope endpoint set requires 1..24 input entries");
  }
  std::array<std::array<uint8_t, 48>, 24> records{};
  size_t count = 0;
  for (const auto &endpoint : endpoints) {
    if (endpoint.nodeId == NodeId{} || endpoint.chainId == ChainId{} || endpoint.targetId == TargetId{} ||
        endpoint.engineUuid.is_nil() || endpoint.targetIncarnation.is_nil()) {
      return makeError(StatusCode::kInvalidArg, "EC scope endpoint identity must be explicit and nonzero");
    }
    Writer<48> out;
    out.integer(endpoint.nodeId.toUnderType(), 4);
    out.integer(endpoint.chainId.toUnderType(), 4);
    out.integer(endpoint.targetId.toUnderType(), 8);
    out.uuid(endpoint.engineUuid);
    out.uuid(endpoint.targetIncarnation);
    records[count++] = out.finish();
  }
  std::sort(records.begin(), records.begin() + count);
  count = std::unique(records.begin(), records.begin() + count) - records.begin();
  std::array<uint8_t, 12 + 24 * 48> canonical{};
  Writer<12> header;
  header.domain("3FSECEP1");
  header.integer(1, 2);
  header.integer(count, 2);
  const auto prefix = header.finish();
  std::copy(prefix.begin(), prefix.end(), canonical.begin());
  for (size_t i = 0; i != count; ++i) std::copy(records[i].begin(), records[i].end(), canonical.begin() + 12 + i * 48);
  return digest(std::span<const uint8_t>(canonical.data(), 12 + count * 48));
}

Result<std::unique_ptr<EcScopeControlKey>> EcScopeControlKey::loadFile(const std::filesystem::path &path) {
  try {
    CHECK_RESULT(key, EcCapabilityKey::loadFile(path));
    return std::unique_ptr<EcScopeControlKey>(new EcScopeControlKey(std::move(key)));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

namespace ec_scope_control_detail {
std::array<uint8_t, kEcScopeControlRequestBytes> Codec::encode(const EcScopeControlClaims &value) {
  Writer<kEcScopeControlRequestBytes> out;
  out.domain(requestDomain);
  out.integer(value.version, 2);
  out.integer(static_cast<uint8_t>(value.action), 1);
  out.uuid(value.clusterAuthority);
  out.integer(value.nodeId.toUnderType(), 4);
  out.integer(value.chainId.toUnderType(), 4);
  out.integer(value.targetId.toUnderType(), 8);
  out.uuid(value.engineUuid);
  out.uuid(value.targetIncarnation);
  out.uuid(value.object);
  out.integer(static_cast<uint8_t>(value.scopeKind), 1);
  out.uuid(value.scopeId);
  out.integer(value.ownerUid.toUnderType(), 4);
  out.uuid(value.clientNamespace);
  out.raw(value.endpointSetDigest);
  out.uuid(value.revocationId);
  out.uuid(value.nonce);
  out.integer(value.issuedAtSeconds, 8);
  out.integer(value.expiresAtSeconds, 8);
  return out.finish();
}
Result<EcScopeControlClaims> Codec::decodeRequest(std::string_view bytes) {
  if (bytes.size() != kEcScopeControlRequestBytes || bytes.substr(0, 8) != requestDomain) {
    return makeError(StatusCode::kInvalidFormat, "EC control request has invalid extent or domain");
  }
  Reader in{bytes};
  EcScopeControlClaims value;
  value.version = in.integer(2);
  value.action = static_cast<EcScopeControlAction>(in.integer(1));
  value.clusterAuthority = in.uuid();
  value.nodeId = NodeId(in.integer(4));
  value.chainId = ChainId(in.integer(4));
  value.targetId = TargetId(in.integer(8));
  value.engineUuid = in.uuid();
  value.targetIncarnation = in.uuid();
  value.object = in.uuid();
  value.scopeKind = static_cast<EcGrantScope>(in.integer(1));
  value.scopeId = in.uuid();
  value.ownerUid = flat::Uid(in.integer(4));
  value.clientNamespace = in.uuid();
  value.endpointSetDigest = in.digest();
  value.revocationId = in.uuid();
  value.nonce = in.uuid();
  value.issuedAtSeconds = in.integer(8);
  value.expiresAtSeconds = in.integer(8);
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
std::array<uint8_t, kEcScopeControlAckBytes> Codec::encode(const EcScopeControlAckClaims &value) {
  Writer<kEcScopeControlAckBytes> out;
  out.domain(ackDomain);
  out.integer(value.version, 2);
  out.raw(value.requestDigest);
  out.raw(value.revocationDigest);
  out.uuid(value.bootNonce);
  out.integer(static_cast<uint8_t>(value.state), 1);
  out.integer(value.durable ? 1 : 0, 1);
  out.integer(value.inflight, 8);
  out.integer(value.observedAtSeconds, 8);
  return out.finish();
}
Result<EcScopeControlAckClaims> Codec::decodeAck(std::string_view bytes) {
  if (bytes.size() != kEcScopeControlAckBytes || bytes.substr(0, 8) != ackDomain) {
    return makeError(StatusCode::kInvalidFormat, "EC control ACK has invalid extent or domain");
  }
  Reader in{bytes};
  EcScopeControlAckClaims value;
  value.version = in.integer(2);
  value.requestDigest = in.digest();
  value.revocationDigest = in.digest();
  value.bootNonce = in.uuid();
  value.state = static_cast<EcScopeControlState>(in.integer(1));
  const auto durable = in.integer(1);
  if (durable > 1) return makeError(StatusCode::kInvalidFormat, "EC control durable flag must be canonical");
  value.durable = durable != 0;
  value.inflight = in.integer(8);
  value.observedAtSeconds = in.integer(8);
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
Result<EcScopeControlRequest> Codec::signRequest(const EcScopeControlKey &key,
                                                 const EcScopeControlClaims &claims,
                                                 uint64_t now) {
  RETURN_ON_ERROR(validate(claims));
  RETURN_ON_ERROR(checkTime(claims, now));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(claims)));
  EcScopeControlRequest result;
  result.claims = claims;
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyRequest(const EcScopeControlKey &key,
                                  const EcScopeControlRequest &request,
                                  const Uuid &authority,
                                  NodeId node,
                                  EcScopeControlAction action,
                                  uint64_t now) {
  RETURN_ON_ERROR(validate(request.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(request.claims)));
  if (!Crypto::constantTimeEqual(signature, request.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "EC control request MAC mismatch");
  }
  if (request.claims.clusterAuthority != authority || request.claims.nodeId != node ||
      request.claims.action != action) {
    return makeError(StatusCode::kTokenMismatch, "EC control authority, local node or action mismatch");
  }
  return checkTime(request.claims, now);
}
Result<EcScopeControlAck> Codec::signObserved(const EcScopeControlKey &key,
                                              const EcScopeControlRequest &request,
                                              const Uuid &bootNonce,
                                              bool durable,
                                              uint64_t inflight,
                                              uint64_t now) {
  RETURN_ON_ERROR(checkTime(request.claims, now));
  EcScopeControlAck result;
  CHECK_RESULT(requestHash, digest(encode(request.claims)));
  result.claims.requestDigest = requestHash;
  CHECK_RESULT(denyHash, denyDigest(request.claims));
  result.claims.revocationDigest = denyHash;
  result.claims.bootNonce = bootNonce;
  result.claims.durable = durable;
  result.claims.inflight = inflight;
  result.claims.state = durable && inflight == 0 ? EcScopeControlState::Drained : EcScopeControlState::Pending;
  result.claims.observedAtSeconds = now;
  RETURN_ON_ERROR(validate(result.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(result.claims)));
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyAck(const EcScopeControlKey &key,
                              const EcScopeControlAck &ack,
                              const EcScopeControlRequest &request) {
  RETURN_ON_ERROR(validate(request.claims));
  RETURN_ON_ERROR(validate(ack.claims));
  CHECK_RESULT(requestSignature, Crypto::authenticate(*key.key_, encode(request.claims)));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(ack.claims)));
  if (!Crypto::constantTimeEqual(requestSignature, request.signature_) ||
      !Crypto::constantTimeEqual(signature, ack.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "EC control request or ACK MAC mismatch");
  }
  CHECK_RESULT(requestHash, digest(encode(request.claims)));
  CHECK_RESULT(denyHash, denyDigest(request.claims));
  if (!Crypto::constantTimeEqual(requestHash, ack.claims.requestDigest) ||
      !Crypto::constantTimeEqual(denyHash, ack.claims.revocationDigest) ||
      ack.claims.observedAtSeconds < request.claims.issuedAtSeconds ||
      ack.claims.observedAtSeconds >= request.claims.expiresAtSeconds) {
    return makeError(StatusCode::kTokenMismatch, "EC ACK does not describe the exact issued control request");
  }
  return Void{};
}
}  // namespace ec_scope_control_detail
Result<EcScopeControlRequest> signEcScopeControl(const EcScopeControlKey &key,
                                                 const EcScopeControlClaims &claims,
                                                 uint64_t now) {
  return ec_scope_control_detail::Codec::signRequest(key, claims, now);
}
Result<Void> verifyEcScopeControl(const EcScopeControlKey &key,
                                  const EcScopeControlRequest &request,
                                  const Uuid &authority,
                                  NodeId node,
                                  EcScopeControlAction action,
                                  uint64_t now) {
  return ec_scope_control_detail::Codec::verifyRequest(key, request, authority, node, action, now);
}
Result<Void> verifyEcScopeControlAck(const EcScopeControlKey &key,
                                     const EcScopeControlAck &ack,
                                     const EcScopeControlRequest &request) {
  return ec_scope_control_detail::Codec::verifyAck(key, ack, request);
}
}  // namespace hf3fs::storage
