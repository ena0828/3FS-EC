#include "EcGcAbsentDiscovery.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
constexpr std::string_view requestDomain = "3FSGADQ1";
constexpr std::string_view observationDomain = "3FSGADR1";
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
Result<Void> validate(const EcGcAbsentDiscoveryClaims &v) {
  if (v.version != kEcGcAbsentDiscoveryVersion || v.keyId.is_nil() || v.authority.is_nil() || v.nodeId == NodeId{} ||
      v.chainId == ChainId{} || v.targetId == TargetId{} || v.nonce.is_nil() ||
      v.expiresAtSeconds <= v.issuedAtSeconds || v.expiresAtSeconds - v.issuedAtSeconds > kEcGcAbsentDiscoveryMaxTtlSeconds)
    return makeError(StatusCode::kInvalidArg, "invalid EC discovery request binding or lifetime");
  return Void{};
}
Result<Void> validate(const EcGcAbsentDiscoveryObservationClaims &v) {
  const auto &e = v.endpoint;
  if (v.version != kEcGcAbsentDiscoveryVersion || v.dataProtocol != 2 || v.diskFormat != 3 ||
      v.gcProtocol != 2 ||
      (v.capabilities != kEcGcAbsentDiscoveryConfirmQuery && v.capabilities != kEcGcAbsentDiscoveryQueryOnly) || v.keyId.is_nil() ||
      v.authority.is_nil() || v.bootNonce.is_nil() || v.requestDigest == EcSha256{} || e.nodeId == NodeId{} ||
      e.chainId == ChainId{} || e.targetId == TargetId{} || e.engineUuid.is_nil() || e.targetIncarnation.is_nil())
    return makeError(StatusCode::kInvalidArg, "invalid EC discovery observation");
  return Void{};
}
Result<Void> checkTime(const EcGcAbsentDiscoveryClaims &v, uint64_t now) {
  if (now < v.issuedAtSeconds || now >= v.expiresAtSeconds)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery request is not currently valid");
  return Void{};
}
}  // namespace
namespace ec_gc_absent_discovery_detail {
std::array<uint8_t, kEcGcAbsentDiscoveryRequestBytes> Codec::encode(const EcGcAbsentDiscoveryClaims &v) {
  Writer<kEcGcAbsentDiscoveryRequestBytes> w;
  w.domain(requestDomain);
  w.integer(v.version, 2);
  w.uuid(v.keyId);
  w.uuid(v.authority);
  w.integer(v.nodeId.toUnderType(), 4);
  w.integer(v.chainId.toUnderType(), 4);
  w.integer(v.targetId.toUnderType(), 8);
  w.uuid(v.nonce);
  w.integer(v.issuedAtSeconds, 8);
  w.integer(v.expiresAtSeconds, 8);
  return w.finish();
}
std::array<uint8_t, kEcGcAbsentDiscoveryObservationBytes> Codec::encode(const EcGcAbsentDiscoveryObservationClaims &v) {
  Writer<kEcGcAbsentDiscoveryObservationBytes> w;
  w.domain(observationDomain);
  w.integer(v.version, 2);
  w.raw(v.requestDigest);
  w.uuid(v.keyId);
  w.uuid(v.authority);
  w.integer(v.endpoint.nodeId.toUnderType(), 4);
  w.integer(v.endpoint.chainId.toUnderType(), 4);
  w.integer(v.endpoint.targetId.toUnderType(), 8);
  w.uuid(v.endpoint.engineUuid);
  w.uuid(v.endpoint.targetIncarnation);
  w.integer(v.dataProtocol, 2);
  w.integer(v.diskFormat, 2);
  w.integer(v.gcProtocol, 2);
  w.integer(v.capabilities, 2);
  w.uuid(v.bootNonce);
  w.integer(v.observedAtSeconds, 8);
  return w.finish();
}
Result<EcGcAbsentDiscoveryClaims> Codec::decodeRequest(std::string_view bytes) {
  if (bytes.size() != kEcGcAbsentDiscoveryRequestBytes || !bytes.starts_with(requestDomain))
    return makeError(StatusCode::kInvalidFormat, "wrong EC discovery request extent/domain");
  Reader r{bytes};
  EcGcAbsentDiscoveryClaims v;
  v.version = r.integer(2);
  v.keyId = r.uuid();
  v.authority = r.uuid();
  v.nodeId = NodeId(r.integer(4));
  v.chainId = ChainId(r.integer(4));
  v.targetId = TargetId(r.integer(8));
  v.nonce = r.uuid();
  v.issuedAtSeconds = r.integer(8);
  v.expiresAtSeconds = r.integer(8);
  RETURN_ON_ERROR(validate(v));
  return v;
}
Result<EcGcAbsentDiscoveryObservationClaims> Codec::decodeObservation(std::string_view bytes) {
  if (bytes.size() != kEcGcAbsentDiscoveryObservationBytes || !bytes.starts_with(observationDomain))
    return makeError(StatusCode::kInvalidFormat, "wrong EC discovery observation extent/domain");
  Reader r{bytes};
  EcGcAbsentDiscoveryObservationClaims v;
  v.version = r.integer(2);
  v.requestDigest = r.digest();
  v.keyId = r.uuid();
  v.authority = r.uuid();
  v.endpoint.nodeId = NodeId(r.integer(4));
  v.endpoint.chainId = ChainId(r.integer(4));
  v.endpoint.targetId = TargetId(r.integer(8));
  v.endpoint.engineUuid = r.uuid();
  v.endpoint.targetIncarnation = r.uuid();
  v.dataProtocol = r.integer(2);
  v.diskFormat = r.integer(2);
  v.gcProtocol = r.integer(2);
  v.capabilities = r.integer(2);
  v.bootNonce = r.uuid();
  v.observedAtSeconds = r.integer(8);
  RETURN_ON_ERROR(validate(v));
  return v;
}
Result<EcGcAbsentDiscoveryRequest> Codec::signRequest(const EcGcKey &key, const EcGcAbsentDiscoveryClaims &claims, uint64_t now) {
  RETURN_ON_ERROR(validate(claims));
  RETURN_ON_ERROR(checkTime(claims, now));
  if (claims.keyId != key.keyId()) return makeError(StatusCode::kAuthenticationFail, "GC discovery key ID mismatch");
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(claims)));
  EcGcAbsentDiscoveryRequest result;
  result.claims = claims;
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyRequest(const EcGcKey &key,
                                  const EcGcAbsentDiscoveryRequest &request,
                                  const Uuid &authority,
                                  NodeId node,
                                  uint64_t now) {
  RETURN_ON_ERROR(validate(request.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(request.claims)));
  if (!Crypto::constantTimeEqual(signature, request.signature_) || request.claims.keyId != key.keyId() ||
      request.claims.authority != authority || request.claims.nodeId != node)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery MAC, authority or local node mismatch");
  return checkTime(request.claims, now);
}
Result<EcGcAbsentDiscoveryObservation> Codec::signObserved(const EcGcKey &key,
                                                     const EcGcAbsentDiscoveryRequest &request,
                                                     const EcGcLocalTarget &local,
                                                     const Uuid &authority,
                                                     const Uuid &bootNonce,
                                                     uint16_t admissionMask,
                                                     uint64_t now) {
  const auto &actual = local.endpoint;
  RETURN_ON_ERROR(verifyRequest(key, request, authority, actual.nodeId, now));
  if (!local.enabled || local.dataProtocol != 2 || local.diskFormat != 3 ||
      local.gcProtocol != 2 || bootNonce.is_nil() || actual.chainId != request.claims.chainId ||
      actual.targetId != request.claims.targetId)
    return makeError(StorageCode::kTargetStateInvalid, "GC discovery requires the actual enabled format3 instance");
  EcGcAbsentDiscoveryObservation result;
  CHECK_RESULT(requestDigest, digest(encode(request.claims)));
  auto &value = result.claims;
  value.requestDigest = requestDigest;
  value.keyId = key.keyId();
  value.authority = authority;
  value.endpoint = actual;
  value.dataProtocol = local.dataProtocol;
  value.diskFormat = local.diskFormat;
  value.gcProtocol = local.gcProtocol;
  value.capabilities = admissionMask;
  value.bootNonce = bootNonce;
  value.observedAtSeconds = now;
  RETURN_ON_ERROR(validate(value));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(value)));
  result.signature_ = signature;
  return result;
}
Result<Void> Codec::verifyObservation(const EcGcKey &key,
                                      const EcGcAbsentDiscoveryObservation &value,
                                      const EcGcAbsentDiscoveryRequest &request,
                                      uint64_t now) {
  RETURN_ON_ERROR(verifyRequest(key, request, request.claims.authority, request.claims.nodeId, now));
  RETURN_ON_ERROR(validate(value.claims));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(value.claims)));
  CHECK_RESULT(requestDigest, digest(encode(request.claims)));
  const auto &v = value.claims;
  const auto &r = request.claims;
  if (!Crypto::constantTimeEqual(signature, value.signature_) || v.requestDigest != requestDigest ||
      v.keyId != key.keyId() || v.keyId != r.keyId || v.authority != r.authority || v.endpoint.nodeId != r.nodeId ||
      v.endpoint.chainId != r.chainId || v.endpoint.targetId != r.targetId || v.observedAtSeconds < r.issuedAtSeconds ||
      v.observedAtSeconds >= r.expiresAtSeconds || v.observedAtSeconds > now)
    return makeError(StatusCode::kAuthenticationFail, "EC discovery observation does not bind this live request");
  return Void{};
}
std::array<uint8_t, kEcGcAbsentDiscoveryRequestBytes + 32> Codec::frame(const EcGcAbsentDiscoveryRequest &value) {
  std::array<uint8_t, kEcGcAbsentDiscoveryRequestBytes + 32> result{};
  auto body = encode(value.claims);
  std::copy(body.begin(), body.end(), result.begin());
  std::copy(value.signature_.begin(), value.signature_.end(), result.begin() + body.size());
  return result;
}
std::array<uint8_t, kEcGcAbsentDiscoveryObservationBytes + 32> Codec::frame(const EcGcAbsentDiscoveryObservation &value) {
  std::array<uint8_t, kEcGcAbsentDiscoveryObservationBytes + 32> result{};
  auto body = encode(value.claims);
  std::copy(body.begin(), body.end(), result.begin());
  std::copy(value.signature_.begin(), value.signature_.end(), result.begin() + body.size());
  return result;
}
}  // namespace ec_gc_absent_discovery_detail
Result<EcGcAbsentDiscoveryRequest> signEcGcAbsentDiscovery(const EcGcKey &key, const EcGcAbsentDiscoveryClaims &claims, uint64_t now) {
  return ec_gc_absent_discovery_detail::Codec::signRequest(key, claims, now);
}
Result<Void> verifyEcGcAbsentDiscovery(const EcGcKey &key,
                                 const EcGcAbsentDiscoveryRequest &request,
                                 const Uuid &authority,
                                 NodeId node,
                                 uint64_t now) {
  return ec_gc_absent_discovery_detail::Codec::verifyRequest(key, request, authority, node, now);
}
Result<Void> verifyEcGcAbsentDiscoveryObservation(const EcGcKey &key,
                                            const EcGcAbsentDiscoveryObservation &observation,
                                            const EcGcAbsentDiscoveryRequest &request,
                                            uint64_t now) {
  return ec_gc_absent_discovery_detail::Codec::verifyObservation(key, observation, request, now);
}
}  // namespace hf3fs::storage
