#include "EcTargetDiscovery.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view requestDomain = "3FSECDQ1";
constexpr std::string_view observationDomain = "3FSECDR1";
using Crypto = ec_authorization_detail::Access;
template <size_t N>
struct Writer {
  std::array<uint8_t, N> bytes{};
  size_t offset = 0;
  void integer(uint64_t value, size_t width) {
    assert(offset + width <= N);
    for (size_t i = width; i; --i) bytes[offset++] = static_cast<uint8_t>(value >> ((i - 1) * 8));
  }
  void raw(std::span<const uint8_t> value) {
    assert(offset + value.size() <= N);
    std::copy(value.begin(), value.end(), bytes.begin() + offset);
    offset += value.size();
  }
  void uuid(const Uuid &value) { raw(value.data); }
  void domain(std::string_view value) { raw({reinterpret_cast<const uint8_t *>(value.data()), value.size()}); }
  auto finish() {
    assert(offset == N);
    return bytes;
  }
};
struct Reader {
  std::string_view bytes;
  size_t offset = 8;
  uint64_t integer(size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i != width; ++i) value = (value << 8) | static_cast<uint8_t>(bytes[offset++]);
    return value;
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
Result<EcSha256> digest(std::span<const uint8_t> bytes) {
  EcSha256 result{};
  unsigned int size = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), result.data(), &size, EVP_sha256(), nullptr) != 1 || size != result.size())
    return makeError(StatusCode::kIOError, "EC discovery digest failed");
  return result;
}
Result<Void> validate(const EcTargetDiscoveryClaims &v) {
  if (v.version != kEcTargetDiscoveryVersion || v.clusterAuthority.is_nil() || v.nodeId == NodeId{} ||
      v.chainId == ChainId{} || v.targetId == TargetId{} || v.nonce.is_nil() ||
      v.expiresAtSeconds <= v.issuedAtSeconds ||
      v.expiresAtSeconds - v.issuedAtSeconds > kEcTargetDiscoveryMaxTtlSeconds)
    return makeError(StatusCode::kInvalidArg, "invalid EC discovery request binding or lifetime");
  return Void{};
}
Result<Void> validate(const EcTargetDiscoveryObservationClaims &v) {
  const auto &e = v.endpoint;
  if (v.version != kEcTargetDiscoveryVersion || v.protocolVersion != 2 || v.requestDigest == EcSha256{} ||
      e.nodeId == NodeId{} || e.chainId == ChainId{} || e.targetId == TargetId{} || e.engineUuid.is_nil() ||
      e.targetIncarnation.is_nil())
    return makeError(StatusCode::kInvalidArg, "invalid EC discovery observation");
  return Void{};
}
Result<Void> checkTime(const EcTargetDiscoveryClaims &v, uint64_t now) {
  if (now < v.issuedAtSeconds || now >= v.expiresAtSeconds)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery request is not currently valid");
  return Void{};
}
}  // namespace
namespace ec_target_discovery_detail {
std::array<uint8_t, kEcTargetDiscoveryRequestBytes> Codec::encode(const EcTargetDiscoveryClaims &v) {
  Writer<kEcTargetDiscoveryRequestBytes> w;
  w.domain(requestDomain);
  w.integer(v.version, 2);
  w.uuid(v.clusterAuthority);
  w.integer(v.nodeId.toUnderType(), 4);
  w.integer(v.chainId.toUnderType(), 4);
  w.integer(v.targetId.toUnderType(), 8);
  w.uuid(v.nonce);
  w.integer(v.issuedAtSeconds, 8);
  w.integer(v.expiresAtSeconds, 8);
  return w.finish();
}
std::array<uint8_t, kEcTargetDiscoveryObservationBytes> Codec::encode(const EcTargetDiscoveryObservationClaims &v) {
  Writer<kEcTargetDiscoveryObservationBytes> w;
  w.domain(observationDomain);
  w.integer(v.version, 2);
  w.raw(v.requestDigest);
  w.integer(v.endpoint.nodeId.toUnderType(), 4);
  w.integer(v.endpoint.chainId.toUnderType(), 4);
  w.integer(v.endpoint.targetId.toUnderType(), 8);
  w.uuid(v.endpoint.engineUuid);
  w.uuid(v.endpoint.targetIncarnation);
  w.integer(v.protocolVersion, 2);
  w.integer(v.observedAtSeconds, 8);
  return w.finish();
}
Result<EcTargetDiscoveryClaims> Codec::decodeRequest(std::string_view bytes) {
  if (bytes.size() != kEcTargetDiscoveryRequestBytes || !bytes.starts_with(requestDomain))
    return makeError(StatusCode::kInvalidFormat, "wrong EC discovery request extent/domain");
  Reader r{bytes};
  EcTargetDiscoveryClaims v;
  v.version = r.integer(2);
  v.clusterAuthority = r.uuid();
  v.nodeId = NodeId(r.integer(4));
  v.chainId = ChainId(r.integer(4));
  v.targetId = TargetId(r.integer(8));
  v.nonce = r.uuid();
  v.issuedAtSeconds = r.integer(8);
  v.expiresAtSeconds = r.integer(8);
  RETURN_ON_ERROR(validate(v));
  return v;
}
Result<EcTargetDiscoveryObservationClaims> Codec::decodeObservation(std::string_view bytes) {
  if (bytes.size() != kEcTargetDiscoveryObservationBytes || !bytes.starts_with(observationDomain))
    return makeError(StatusCode::kInvalidFormat, "wrong EC discovery observation extent/domain");
  Reader r{bytes};
  EcTargetDiscoveryObservationClaims v;
  v.version = r.integer(2);
  v.requestDigest = r.digest();
  v.endpoint.nodeId = NodeId(r.integer(4));
  v.endpoint.chainId = ChainId(r.integer(4));
  v.endpoint.targetId = TargetId(r.integer(8));
  v.endpoint.engineUuid = r.uuid();
  v.endpoint.targetIncarnation = r.uuid();
  v.protocolVersion = r.integer(2);
  v.observedAtSeconds = r.integer(8);
  RETURN_ON_ERROR(validate(v));
  return v;
}
Result<EcTargetDiscoveryRequest> Codec::signRequest(const EcScopeControlKey &key,
                                                    const EcTargetDiscoveryClaims &claims,
                                                    uint64_t now) {
  RETURN_ON_ERROR(validate(claims));
  RETURN_ON_ERROR(checkTime(claims, now));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(claims)));
  EcTargetDiscoveryRequest result;
  result.claims = claims;
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyRequest(const EcScopeControlKey &key,
                                  const EcTargetDiscoveryRequest &request,
                                  const Uuid &authority,
                                  NodeId node,
                                  uint64_t now) {
  RETURN_ON_ERROR(validate(request.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(request.claims)));
  if (!Crypto::constantTimeEqual(signature, request.signature_) || request.claims.clusterAuthority != authority ||
      request.claims.nodeId != node)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery MAC, authority or local node mismatch");
  return checkTime(request.claims, now);
}
Result<EcTargetDiscoveryObservation> Codec::signObserved(const EcScopeControlKey &key,
                                                         const EcTargetDiscoveryRequest &request,
                                                         const EcScopeEndpoint &actual,
                                                         uint64_t now) {
  RETURN_ON_ERROR(verifyRequest(key, request, request.claims.clusterAuthority, actual.nodeId, now));
  if (actual.chainId != request.claims.chainId || actual.targetId != request.claims.targetId)
    return makeError(StatusCode::kTokenMismatch, "actual target differs from discovery request");
  EcTargetDiscoveryObservation result;
  CHECK_RESULT(requestDigest, digest(encode(request.claims)));
  result.claims.requestDigest = requestDigest;
  result.claims.endpoint = actual;
  result.claims.observedAtSeconds = now;
  RETURN_ON_ERROR(validate(result.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(result.claims)));
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyObservation(const EcScopeControlKey &key,
                                      const EcTargetDiscoveryObservation &value,
                                      const EcTargetDiscoveryRequest &request,
                                      uint64_t now) {
  RETURN_ON_ERROR(verifyRequest(key, request, request.claims.clusterAuthority, request.claims.nodeId, now));
  RETURN_ON_ERROR(validate(value.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(value.claims)));
  CHECK_RESULT(requestDigest, digest(encode(request.claims)));
  const auto &v = value.claims;
  const auto &r = request.claims;
  if (!Crypto::constantTimeEqual(signature, value.signature_) || v.requestDigest != requestDigest ||
      v.endpoint.nodeId != r.nodeId || v.endpoint.chainId != r.chainId || v.endpoint.targetId != r.targetId ||
      v.observedAtSeconds < r.issuedAtSeconds || v.observedAtSeconds >= r.expiresAtSeconds || v.observedAtSeconds > now)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery observation does not bind this live request");
  return Void{};
}
}  // namespace ec_target_discovery_detail
Result<EcTargetDiscoveryRequest> signEcTargetDiscovery(const EcScopeControlKey &key,
                                                       const EcTargetDiscoveryClaims &claims,
                                                       uint64_t now) {
  return ec_target_discovery_detail::Codec::signRequest(key, claims, now);
}
Result<Void> verifyEcTargetDiscovery(const EcScopeControlKey &key,
                                     const EcTargetDiscoveryRequest &request,
                                     const Uuid &authority,
                                     NodeId node,
                                     uint64_t now) {
  return ec_target_discovery_detail::Codec::verifyRequest(key, request, authority, node, now);
}
Result<Void> verifyEcTargetDiscoveryObservation(const EcScopeControlKey &key,
                                                const EcTargetDiscoveryObservation &observation,
                                                const EcTargetDiscoveryRequest &request,
                                                uint64_t now) {
  return ec_target_discovery_detail::Codec::verifyObservation(key, observation, request, now);
}
}  // namespace hf3fs::storage
