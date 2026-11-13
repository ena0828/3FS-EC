#include "EcTargetRetirementControl.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view requestDomain = "3FSETRQ1";
constexpr std::string_view observationDomain = "3FSETRO1";
constexpr std::string_view retirementDomain = "3FSETRD1";
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
Result<Void> validate(const EcTargetRetirementClaims &value) {
  if (value.version != kEcTargetRetirementVersion ||
      (value.action != EcTargetRetirementAction::Prepare && value.action != EcTargetRetirementAction::Query) ||
      value.clusterAuthority.is_nil() || value.nodeId == NodeId{} || value.chainId == ChainId{} ||
      value.targetId == TargetId{} || value.engineUuid.is_nil() || value.targetIncarnation.is_nil() ||
      value.retirementId.is_nil() || value.nonce.is_nil() || value.expiresAtSeconds <= value.issuedAtSeconds ||
      value.expiresAtSeconds - value.issuedAtSeconds > kEcTargetRetirementMaxTtlSeconds) {
    return makeError(StatusCode::kInvalidArg, "invalid EC target retirement identity, version or bounded lifetime");
  }
  return Void{};
}
Result<Void> validate(const EcTargetRetirementObservationClaims &value) {
  if (value.version != kEcTargetRetirementVersion || zero(value.requestDigest) || zero(value.retirementDigest) ||
      value.bootNonce.is_nil() ||
      (value.state != EcTargetRetirementState::Pending && value.state != EcTargetRetirementState::LocalDataDrained) ||
      ((value.state == EcTargetRetirementState::LocalDataDrained) != (value.durable && value.inflight == 0))) {
    return makeError(StatusCode::kInvalidArg, "invalid or contradictory EC target retirement observation");
  }
  return Void{};
}
Result<Void> checkTime(const EcTargetRetirementClaims &value, uint64_t now) {
  if (now < value.issuedAtSeconds || now >= value.expiresAtSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "EC target retirement request is not currently valid");
  }
  return Void{};
}
Result<EcSha256> digest(std::span<const uint8_t> bytes) {
  EcSha256 value{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), value.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != value.size()) {
    return makeError(StatusCode::kIOError, "EC target retirement SHA-256 calculation failed");
  }
  return value;
}
Result<EcSha256> retirementDigest(const EcTargetRetirementClaims &value) {
  // Commit to ECTG content: format 2 + old 44-byte target + retirement ID.
  // Its durable existence is asserted only by an observation with durable=true.
  // Authority/node/nonce are authenticated only by the request.
  Writer<70> out;
  out.domain(retirementDomain);
  out.integer(2, 2);
  out.uuid(value.engineUuid);
  out.uuid(value.targetIncarnation);
  out.integer(value.chainId.toUnderType(), 4);
  out.integer(value.targetId.toUnderType(), 8);
  out.uuid(value.retirementId);
  return digest(out.finish());
}
}  // namespace

namespace ec_target_retirement_detail {
std::array<uint8_t, kEcTargetRetirementRequestBytes> Codec::encode(const EcTargetRetirementClaims &value) {
  Writer<kEcTargetRetirementRequestBytes> out;
  out.domain(requestDomain);
  out.integer(value.version, 2);
  out.integer(static_cast<uint8_t>(value.action), 1);
  out.uuid(value.clusterAuthority);
  out.integer(value.nodeId.toUnderType(), 4);
  out.integer(value.chainId.toUnderType(), 4);
  out.integer(value.targetId.toUnderType(), 8);
  out.uuid(value.engineUuid);
  out.uuid(value.targetIncarnation);
  out.uuid(value.retirementId);
  out.uuid(value.nonce);
  out.integer(value.issuedAtSeconds, 8);
  out.integer(value.expiresAtSeconds, 8);
  return out.finish();
}
Result<EcTargetRetirementClaims> Codec::decodeRequest(std::string_view bytes) {
  if (bytes.size() != kEcTargetRetirementRequestBytes || bytes.substr(0, 8) != requestDomain) {
    return makeError(StatusCode::kInvalidFormat, "EC target retirement request has invalid extent or domain");
  }
  Reader in{bytes};
  EcTargetRetirementClaims value;
  value.version = in.integer(2);
  value.action = static_cast<EcTargetRetirementAction>(in.integer(1));
  value.clusterAuthority = in.uuid();
  value.nodeId = NodeId(in.integer(4));
  value.chainId = ChainId(in.integer(4));
  value.targetId = TargetId(in.integer(8));
  value.engineUuid = in.uuid();
  value.targetIncarnation = in.uuid();
  value.retirementId = in.uuid();
  value.nonce = in.uuid();
  value.issuedAtSeconds = in.integer(8);
  value.expiresAtSeconds = in.integer(8);
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
std::array<uint8_t, kEcTargetRetirementObservationBytes> Codec::encode(const EcTargetRetirementObservationClaims &value) {
  Writer<kEcTargetRetirementObservationBytes> out;
  out.domain(observationDomain);
  out.integer(value.version, 2);
  out.raw(value.requestDigest);
  out.raw(value.retirementDigest);
  out.uuid(value.bootNonce);
  out.integer(static_cast<uint8_t>(value.state), 1);
  out.integer(value.durable ? 1 : 0, 1);
  out.integer(value.inflight, 8);
  out.integer(value.observedAtSeconds, 8);
  return out.finish();
}
Result<EcTargetRetirementObservationClaims> Codec::decodeObservation(std::string_view bytes) {
  if (bytes.size() != kEcTargetRetirementObservationBytes || bytes.substr(0, 8) != observationDomain) {
    return makeError(StatusCode::kInvalidFormat, "EC target retirement observation has invalid extent or domain");
  }
  Reader in{bytes};
  EcTargetRetirementObservationClaims value;
  value.version = in.integer(2);
  value.requestDigest = in.digest();
  value.retirementDigest = in.digest();
  value.bootNonce = in.uuid();
  value.state = static_cast<EcTargetRetirementState>(in.integer(1));
  const auto durable = in.integer(1);
  if (durable > 1) return makeError(StatusCode::kInvalidFormat, "EC target retirement durable flag must be canonical");
  value.durable = durable != 0;
  value.inflight = in.integer(8);
  value.observedAtSeconds = in.integer(8);
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
Result<EcTargetRetirementRequest> Codec::signRequest(const EcScopeControlKey &key,
                                                     const EcTargetRetirementClaims &claims,
                                                     uint64_t now) {
  RETURN_ON_ERROR(validate(claims));
  RETURN_ON_ERROR(checkTime(claims, now));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(claims)));
  EcTargetRetirementRequest result;
  result.claims = claims;
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyRequest(const EcScopeControlKey &key,
                                  const EcTargetRetirementRequest &request,
                                  const Uuid &authority,
                                  NodeId node,
                                  EcTargetRetirementAction action,
                                  uint64_t now) {
  RETURN_ON_ERROR(validate(request.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(request.claims)));
  if (!Crypto::constantTimeEqual(signature, request.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "EC target retirement request MAC mismatch");
  }
  if (request.claims.clusterAuthority != authority || request.claims.nodeId != node ||
      request.claims.action != action) {
    return makeError(StatusCode::kTokenMismatch, "EC target retirement authority, local node or action mismatch");
  }
  return checkTime(request.claims, now);
}
Result<EcTargetRetirementObservation> Codec::signObserved(const EcScopeControlKey &key,
                                                          const EcTargetRetirementRequest &request,
                                                          const Uuid &bootNonce,
                                                          bool durable,
                                                          uint64_t inflight,
                                                          uint64_t now) {
  RETURN_ON_ERROR(verifyRequest(key,
                                request,
                                request.claims.clusterAuthority,
                                request.claims.nodeId,
                                request.claims.action,
                                now));
  EcTargetRetirementObservation result;
  CHECK_RESULT(requestHash, digest(encode(request.claims)));
  result.claims.requestDigest = requestHash;
  CHECK_RESULT(retirementHash, retirementDigest(request.claims));
  result.claims.retirementDigest = retirementHash;
  result.claims.bootNonce = bootNonce;
  result.claims.durable = durable;
  result.claims.inflight = inflight;
  result.claims.state =
      durable && inflight == 0 ? EcTargetRetirementState::LocalDataDrained : EcTargetRetirementState::Pending;
  result.claims.observedAtSeconds = now;
  RETURN_ON_ERROR(validate(result.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(result.claims)));
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyObservation(const EcScopeControlKey &key,
                                      const EcTargetRetirementObservation &observation,
                                      const EcTargetRetirementRequest &request) {
  RETURN_ON_ERROR(validate(request.claims));
  RETURN_ON_ERROR(validate(observation.claims));
  CHECK_RESULT(requestSignature, Crypto::authenticate(*key.key_, encode(request.claims)));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(observation.claims)));
  if (!Crypto::constantTimeEqual(requestSignature, request.signature_) ||
      !Crypto::constantTimeEqual(signature, observation.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "EC target retirement request or observation MAC mismatch");
  }
  CHECK_RESULT(requestHash, digest(encode(request.claims)));
  CHECK_RESULT(retirementHash, retirementDigest(request.claims));
  if (!Crypto::constantTimeEqual(requestHash, observation.claims.requestDigest) ||
      !Crypto::constantTimeEqual(retirementHash, observation.claims.retirementDigest) ||
      observation.claims.observedAtSeconds < request.claims.issuedAtSeconds ||
      observation.claims.observedAtSeconds >= request.claims.expiresAtSeconds) {
    return makeError(StatusCode::kTokenMismatch,
                     "EC target retirement observation does not describe the exact issued control request");
  }
  return Void{};
}
}  // namespace ec_target_retirement_detail
Result<EcTargetRetirementRequest> signEcTargetRetirement(const EcScopeControlKey &key,
                                                         const EcTargetRetirementClaims &claims,
                                                         uint64_t now) {
  return ec_target_retirement_detail::Codec::signRequest(key, claims, now);
}
Result<Void> verifyEcTargetRetirement(const EcScopeControlKey &key,
                                      const EcTargetRetirementRequest &request,
                                      const Uuid &authority,
                                      NodeId node,
                                      EcTargetRetirementAction action,
                                      uint64_t now) {
  return ec_target_retirement_detail::Codec::verifyRequest(key, request, authority, node, action, now);
}
Result<Void> verifyEcTargetRetirementObservation(const EcScopeControlKey &key,
                                                 const EcTargetRetirementObservation &observation,
                                                 const EcTargetRetirementRequest &request) {
  return ec_target_retirement_detail::Codec::verifyObservation(key, observation, request);
}
}  // namespace hf3fs::storage
