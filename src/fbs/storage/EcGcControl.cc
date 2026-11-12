#include "EcGcControl.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
using Crypto = ec_authorization_detail::Access;
constexpr std::string_view certificateDomain = "3FSGCC01";
constexpr std::string_view requestDomain = "3FSGCQ01";
constexpr std::string_view ackDomain = "3FSGCA01";
constexpr size_t blockCountOffset = 260;

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
  void endpoint(const EcScopeEndpoint &value) {
    integer(value.nodeId.toUnderType(), 4);
    integer(value.chainId.toUnderType(), 4);
    integer(value.targetId.toUnderType(), 8);
    uuid(value.engineUuid);
    uuid(value.targetIncarnation);
  }
  auto finish() {
    assert(offset == N);
    return bytes;
  }
};
struct Reader {
  std::string_view bytes;
  size_t offset = 8;
  uint64_t integer(size_t width) {
    assert(offset + width <= bytes.size());
    uint64_t value = 0;
    for (size_t i = 0; i != width; ++i) value = (value << 8) | static_cast<uint8_t>(bytes[offset++]);
    return value;
  }
  Uuid uuid() {
    assert(offset + 16 <= bytes.size());
    Uuid value;
    std::memcpy(value.data, bytes.data() + offset, 16);
    offset += 16;
    return value;
  }
  EcSha256 digest() {
    assert(offset + 32 <= bytes.size());
    EcSha256 value{};
    std::memcpy(value.data(), bytes.data() + offset, 32);
    offset += 32;
    return value;
  }
  EcScopeEndpoint endpoint() {
    EcScopeEndpoint value;
    value.nodeId = NodeId(integer(4));
    value.chainId = ChainId(integer(4));
    value.targetId = TargetId(integer(8));
    value.engineUuid = uuid();
    value.targetIncarnation = uuid();
    return value;
  }
};
bool zero(const EcSha256 &value) {
  return std::all_of(value.begin(), value.end(), [](auto byte) { return byte == 0; });
}
bool same(const EcScopeEndpoint &a, const EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}
Result<Void> validate(const EcScopeEndpoint &value) {
  if (value.nodeId == NodeId{} || value.chainId == ChainId{} || value.targetId == TargetId{} ||
      value.engineUuid.is_nil() || value.targetIncarnation.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "GC endpoint requires the exact nonzero physical identity");
  }
  return Void{};
}
Result<Void> validate(const EcGcCertificate &value) {
  const bool flat = value.version == 1 && value.metaMode == 3 && value.catalogVersion == 1 &&
                    value.enrollmentVersion == 1 && value.gcProtocol == 1;
  const bool tree = value.version == 2 && value.metaMode == 4 && value.catalogVersion == 2 &&
                    value.enrollmentVersion == 2 && value.gcProtocol == 2;
  if ((!flat && !tree) || value.bindingVersion != 1 || value.dataProtocol != 2 || value.diskFormat != 3 ||
      value.claimId.is_nil() || value.objectInode < 2 || value.objectInode > ((uint64_t{1} << 57) - 1) ||
      value.objectIncarnation.is_nil() || value.creatorClient.is_nil() || value.createRequest.is_nil() ||
      value.fragment.object != value.objectIncarnation || value.fragmentOperation.is_nil() ||
      value.writerClient.is_nil() || value.registeredScopes == 0 || value.registeredScopes != value.releasedScopes ||
      zero(value.releaseHistory) || zero(value.originDrainEvidence) || zero(value.eligibilityDigest)) {
    return makeError(StatusCode::kInvalidArg, "invalid GC certificate version, enrollment, binding or evidence shape");
  }
  RETURN_ON_ERROR(validate(value.endpoint));
  RETURN_ON_ERROR(validateEcIntegrity(value.fragment, value.integrity));
  return Void{};
}
Result<Void> validate(const EcGcRequestClaims &value, uint64_t ttl) {
  if (value.version != 1 || (value.action != EcGcAction::Collect && value.action != EcGcAction::Query) ||
      value.keyId.is_nil() || value.authority.is_nil() || value.nonce.is_nil() || ttl == 0 ||
      ttl > kEcGcMaxTtlSeconds || value.expiresAtSeconds <= value.issuedAtSeconds ||
      value.expiresAtSeconds - value.issuedAtSeconds > ttl) {
    return makeError(StatusCode::kInvalidArg, "invalid GC action, key, authority, nonce or bounded lifetime");
  }
  return validate(value.certificate);
}
Result<Void> validate(const EcGcAckClaims &value) {
  if (value.version != 1 || value.state != EcGcConfirmedState::Collected || value.keyId.is_nil() ||
      value.authority.is_nil() || zero(value.requestDigest) || zero(value.claimDigest) || value.claimId.is_nil() ||
      zero(value.eligibilityDigest) || zero(value.ledgerSha256) || value.terminalRevision < 2 ||
      value.bootNonce.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "invalid GC confirmation or missing permanent ledger identity");
  }
  return validate(value.endpoint);
}
Result<Void> checkTime(const EcGcRequestClaims &value, uint64_t now) {
  if (now < value.issuedAtSeconds || now >= value.expiresAtSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "GC request is not currently valid");
  }
  return Void{};
}
Result<EcSha256> digest(std::span<const uint8_t> bytes) {
  EcSha256 value{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), value.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != value.size()) {
    return makeError(StatusCode::kIOError, "GC SHA-256 calculation failed");
  }
  return value;
}
class FileDescriptor {
 public:
  explicit FileDescriptor(int fd)
      : fd_(fd) {}
  ~FileDescriptor() {
    if (fd_ >= 0) ::close(fd_);
  }
  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  int get() const { return fd_; }

 private:
  int fd_;
};
struct FileBytes {
  std::array<uint8_t, 33> bytes{};
  ~FileBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
}  // namespace

Result<std::unique_ptr<EcGcKey>> EcGcKey::loadFile(const std::filesystem::path &path,
                                                   const Uuid &keyId,
                                                   std::span<const EcGcRoleFileIdentity> otherRoles) {
  try {
    if (path.empty() || path.native().find('\0') != std::string::npos || keyId.is_nil() || otherRoles.size() > 16 ||
        std::any_of(otherRoles.begin(), otherRoles.end(), [](const auto &id) { return id.inode == 0; })) {
      return makeError(StatusCode::kInvalidConfig, "GC key needs an explicit path, key ID and bounded role identities");
    }
    const auto ioError = [&](std::string_view operation, int error) {
      return makeError(StatusCode::kIOError,
                       fmt::format("GC key file {}: {} failed (errno {})", path.string(), operation, error));
    };
    // Identity and bytes come from this same fd. No second path lookup can
    // substitute a different inode after the role-separation comparison.
    FileDescriptor file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) return ioError("open", errno);
    struct stat stat {};
    if (::fstat(file.get(), &stat) != 0) return ioError("fstat", errno);
    if (!S_ISREG(stat.st_mode) || (stat.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        (stat.st_uid != ::geteuid() && stat.st_uid != 0) || stat.st_size != 32) {
      return makeError(StatusCode::kInvalidConfig,
                       "GC key must be a regular owner-only 32-byte file owned by euid or root");
    }
    const EcGcRoleFileIdentity identity{static_cast<uint64_t>(stat.st_dev), static_cast<uint64_t>(stat.st_ino)};
    if (std::find(otherRoles.begin(), otherRoles.end(), identity) != otherRoles.end()) {
      return makeError(StatusCode::kInvalidConfig, "GC key reuses an already loaded role file or hard link");
    }
    FileBytes material;
    size_t count = 0;
    while (count != material.bytes.size()) {
      const auto got = ::read(file.get(), material.bytes.data() + count, material.bytes.size() - count);
      if (got < 0) {
        if (errno == EINTR) continue;
        return ioError("read", errno);
      }
      if (got == 0) break;
      count += static_cast<size_t>(got);
    }
    if (count != 32 ||
        std::all_of(material.bytes.begin(), material.bytes.begin() + 32, [](auto b) { return b == 0; })) {
      return makeError(StatusCode::kInvalidConfig, "GC key must contain exactly 32 nonzero-key raw bytes");
    }
    auto secret = std::make_unique<EcCapabilityKey>(std::span<const uint8_t, 32>(material.bytes.data(), 32));
    return std::unique_ptr<EcGcKey>(new EcGcKey(std::move(secret), keyId, identity));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

namespace ec_gc_control_detail {
std::array<uint8_t, kEcGcCertificateBytes> Codec::encode(const EcGcCertificate &value) {
  Writer<kEcGcCertificateBytes> out;
  out.domain(certificateDomain);
  for (auto version : {value.version,
                       value.metaMode,
                       value.catalogVersion,
                       value.enrollmentVersion,
                       value.bindingVersion,
                       value.dataProtocol,
                       value.diskFormat,
                       value.gcProtocol}) {
    out.integer(version, 2);
  }
  out.uuid(value.claimId);
  out.integer(value.objectInode, 8);
  out.uuid(value.objectIncarnation);
  out.integer(value.creatorUid.toUnderType(), 4);
  out.uuid(value.creatorClient);
  out.uuid(value.createRequest);
  out.integer(value.fragment.version, 2);
  out.uuid(value.fragment.object);
  out.integer(value.fragment.stripe, 8);
  out.integer(value.fragment.generation, 8);
  out.integer(value.fragment.shard, 2);
  out.uuid(value.fragment.allocation);
  out.uuid(value.fragmentOperation);
  out.endpoint(value.endpoint);
  out.integer(value.writerUid.toUnderType(), 4);
  out.uuid(value.writerClient);
  const auto &d = value.integrity;
  for (auto version : {d.version, d.codecId, d.matrixVersion, d.dataShards, d.parityShards, d.fieldPolynomial}) {
    out.integer(version, 2);
  }
  out.integer(d.blockBytes, 4);
  out.integer(d.wholeLength, 4);
  out.integer(d.wholeCrc32c, 4);
  assert(out.offset == blockCountOffset);
  out.integer(d.blockCount, 2);
  for (const auto &block : d.blocks) {
    out.integer(block.validLength, 4);
    out.integer(block.crc32c, 4);
    out.raw(block.sha256);
  }
  out.raw(d.root);
  out.integer(value.registeredScopes, 8);
  out.integer(value.releasedScopes, 8);
  out.raw(value.releaseHistory);
  out.raw(value.originDrainEvidence);
  out.raw(value.eligibilityDigest);
  return out.finish();
}
std::array<uint8_t, kEcGcRequestBytes> Codec::encode(const EcGcRequestClaims &value) {
  Writer<kEcGcRequestBytes> out;
  out.domain(requestDomain);
  out.integer(value.version, 2);
  out.integer(static_cast<uint8_t>(value.action), 1);
  out.integer(0, 1);
  out.uuid(value.keyId);
  out.uuid(value.authority);
  out.uuid(value.nonce);
  out.integer(value.issuedAtSeconds, 8);
  out.integer(value.expiresAtSeconds, 8);
  out.raw(encode(value.certificate));
  return out.finish();
}
std::array<uint8_t, kEcGcAckBytes> Codec::encode(const EcGcAckClaims &value) {
  Writer<kEcGcAckBytes> out;
  out.domain(ackDomain);
  out.integer(value.version, 2);
  out.integer(static_cast<uint8_t>(value.state), 1);
  out.integer(0, 1);
  out.uuid(value.keyId);
  out.uuid(value.authority);
  out.raw(value.requestDigest);
  out.raw(value.claimDigest);
  out.uuid(value.claimId);
  out.raw(value.eligibilityDigest);
  out.endpoint(value.endpoint);
  out.raw(value.ledgerSha256);
  out.integer(value.terminalRevision, 8);
  out.integer(value.observedAtSeconds, 8);
  out.uuid(value.bootNonce);
  return out.finish();
}
Result<EcGcCertificate> Codec::decodeCertificate(std::string_view bytes) {
  if (bytes.size() != kEcGcCertificateBytes || bytes.substr(0, 8) != certificateDomain) {
    return makeError(StatusCode::kInvalidFormat, "invalid GC certificate fixed extent or domain");
  }
  // Reject the count before copying descriptor slots; never allocate from it.
  Reader countReader{bytes, blockCountOffset};
  if (countReader.integer(2) > kEcIntegrityMaxBlocks) {
    return makeError(StatusCode::kInvalidFormat, "GC certificate block count exceeds sixteen fixed slots");
  }
  Reader in{bytes};
  EcGcCertificate value;
  value.version = in.integer(2);
  value.metaMode = in.integer(2);
  value.catalogVersion = in.integer(2);
  value.enrollmentVersion = in.integer(2);
  value.bindingVersion = in.integer(2);
  value.dataProtocol = in.integer(2);
  value.diskFormat = in.integer(2);
  value.gcProtocol = in.integer(2);
  value.claimId = in.uuid();
  value.objectInode = in.integer(8);
  value.objectIncarnation = in.uuid();
  value.creatorUid = flat::Uid(in.integer(4));
  value.creatorClient = in.uuid();
  value.createRequest = in.uuid();
  value.fragment.version = in.integer(2);
  value.fragment.object = in.uuid();
  value.fragment.stripe = in.integer(8);
  value.fragment.generation = in.integer(8);
  value.fragment.shard = in.integer(2);
  value.fragment.allocation = in.uuid();
  value.fragmentOperation = in.uuid();
  value.endpoint = in.endpoint();
  value.writerUid = flat::Uid(in.integer(4));
  value.writerClient = in.uuid();
  auto &d = value.integrity;
  d.version = in.integer(2);
  d.codecId = in.integer(2);
  d.matrixVersion = in.integer(2);
  d.dataShards = in.integer(2);
  d.parityShards = in.integer(2);
  d.fieldPolynomial = in.integer(2);
  d.blockBytes = in.integer(4);
  d.wholeLength = in.integer(4);
  d.wholeCrc32c = in.integer(4);
  d.blockCount = in.integer(2);
  for (auto &block : d.blocks) {
    block.validLength = in.integer(4);
    block.crc32c = in.integer(4);
    block.sha256 = in.digest();
  }
  d.root = in.digest();
  value.registeredScopes = in.integer(8);
  value.releasedScopes = in.integer(8);
  value.releaseHistory = in.digest();
  value.originDrainEvidence = in.digest();
  value.eligibilityDigest = in.digest();
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
Result<EcGcRequestClaims> Codec::decodeRequestClaims(std::string_view bytes) {
  if (bytes.size() != kEcGcRequestBytes || bytes.substr(0, 8) != requestDomain) {
    return makeError(StatusCode::kInvalidFormat, "invalid GC request fixed extent or domain");
  }
  Reader in{bytes};
  EcGcRequestClaims value;
  value.version = in.integer(2);
  value.action = static_cast<EcGcAction>(in.integer(1));
  if (in.integer(1) != 0) return makeError(StatusCode::kInvalidFormat, "GC request reserved byte is not zero");
  value.keyId = in.uuid();
  value.authority = in.uuid();
  value.nonce = in.uuid();
  value.issuedAtSeconds = in.integer(8);
  value.expiresAtSeconds = in.integer(8);
  CHECK_RESULT(certificate, decodeCertificate(bytes.substr(in.offset)));
  value.certificate = certificate;
  RETURN_ON_ERROR(validate(value, kEcGcMaxTtlSeconds));
  return value;
}
Result<EcGcAckClaims> Codec::decodeAckClaims(std::string_view bytes) {
  if (bytes.size() != kEcGcAckBytes || bytes.substr(0, 8) != ackDomain) {
    return makeError(StatusCode::kInvalidFormat, "invalid GC acknowledgement fixed extent or domain");
  }
  Reader in{bytes};
  EcGcAckClaims value;
  value.version = in.integer(2);
  value.state = static_cast<EcGcConfirmedState>(in.integer(1));
  if (in.integer(1) != 0) return makeError(StatusCode::kInvalidFormat, "GC acknowledgement reserved byte is not zero");
  value.keyId = in.uuid();
  value.authority = in.uuid();
  value.requestDigest = in.digest();
  value.claimDigest = in.digest();
  value.claimId = in.uuid();
  value.eligibilityDigest = in.digest();
  value.endpoint = in.endpoint();
  value.ledgerSha256 = in.digest();
  value.terminalRevision = in.integer(8);
  value.observedAtSeconds = in.integer(8);
  value.bootNonce = in.uuid();
  assert(in.offset == bytes.size());
  RETURN_ON_ERROR(validate(value));
  return value;
}
Result<EcGcRequest> Codec::decodeRequest(std::string_view body, std::string_view mac) {
  if (mac.size() != 32) return makeError(StatusCode::kInvalidFormat, "GC request MAC requires 32 bytes");
  CHECK_RESULT(claims, decodeRequestClaims(body));
  EcGcRequest result;
  result.claims = claims;
  std::memcpy(result.signature_.data(), mac.data(), 32);
  return result;
}
Result<EcGcAck> Codec::decodeAck(std::string_view body, std::string_view mac) {
  if (mac.size() != 32) return makeError(StatusCode::kInvalidFormat, "GC acknowledgement MAC requires 32 bytes");
  CHECK_RESULT(claims, decodeAckClaims(body));
  EcGcAck result;
  result.claims = claims;
  std::memcpy(result.signature_.data(), mac.data(), 32);
  return result;
}
std::array<uint8_t, kEcGcRequestBytes + 32> Codec::frame(const EcGcRequest &value) {
  Writer<kEcGcRequestBytes + 32> out;
  out.raw(encode(value.claims));
  out.raw(value.signature_);
  return out.finish();
}
std::array<uint8_t, kEcGcAckBytes + 32> Codec::frame(const EcGcAck &value) {
  Writer<kEcGcAckBytes + 32> out;
  out.raw(encode(value.claims));
  out.raw(value.signature_);
  return out.finish();
}
Result<EcSha256> Codec::claimDigest(const EcGcCertificate &value) {
  RETURN_ON_ERROR(validate(value));
  return digest(encode(value));
}
Result<EcGcRequest> Codec::signRequest(const EcGcKey &key,
                                       const EcGcRequestClaims &claims,
                                       uint64_t now,
                                       uint64_t ttl) {
  RETURN_ON_ERROR(validate(claims, ttl));
  RETURN_ON_ERROR(checkTime(claims, now));
  if (claims.keyId != key.keyId_) return makeError(StatusCode::kTokenMismatch, "GC signing key ID differs");
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(claims)));
  EcGcRequest result;
  result.claims = claims;
  result.signature_ = signature;
  return result;
}
Result<VerifiedEcGcRequest> Codec::verifyRequest(const EcGcKey &key,
                                                 const EcGcRequest &request,
                                                 const Uuid &authority,
                                                 EcGcAction action,
                                                 const EcGcLocalTarget &actual,
                                                 uint64_t now,
                                                 uint64_t ttl) {
  RETURN_ON_ERROR(validate(request.claims, ttl));
  CHECK_RESULT(signature, Crypto::authenticate(*key.key_, encode(request.claims)));
  if (!Crypto::constantTimeEqual(signature, request.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "GC request MAC mismatch");
  }
  if (request.claims.keyId != key.keyId_ || request.claims.authority != authority || request.claims.action != action ||
      !same(request.claims.certificate.endpoint, actual.endpoint)) {
    return makeError(StatusCode::kTokenMismatch, "GC key, authority, action or actual instance differs");
  }
  if (!actual.enabled || actual.dataProtocol != 2 || actual.diskFormat != 3 ||
      !ecGcProtocolSupports(actual.gcProtocol, request.claims.certificate.gcProtocol)) {
    return makeError(StatusCode::kInvalidConfig, "actual target does not enable the exact data2/disk3/GC protocol");
  }
  RETURN_ON_ERROR(checkTime(request.claims, now));
  CHECK_RESULT(claim, claimDigest(request.claims.certificate));
  return VerifiedEcGcRequest(request, claim);
}
Result<VerifiedEcGcAck> Codec::verifyAck(const EcGcKey &key, const EcGcAck &ack, const EcGcRequest &request) {
  RETURN_ON_ERROR(validate(request.claims, kEcGcMaxTtlSeconds));
  RETURN_ON_ERROR(validate(ack.claims));
  CHECK_RESULT(requestSignature, Crypto::authenticate(*key.key_, encode(request.claims)));
  CHECK_RESULT(ackSignature, Crypto::authenticate(*key.key_, encode(ack.claims)));
  if (!Crypto::constantTimeEqual(requestSignature, request.signature_) ||
      !Crypto::constantTimeEqual(ackSignature, ack.signature_)) {
    return makeError(StatusCode::kAuthenticationFail, "GC request or acknowledgement MAC mismatch");
  }
  CHECK_RESULT(requestHash, digest(encode(request.claims)));
  CHECK_RESULT(claimHash, claimDigest(request.claims.certificate));
  const auto &a = ack.claims;
  const auto &r = request.claims;
  const auto &c = r.certificate;
  if (r.keyId != key.keyId_ || a.keyId != r.keyId || a.authority != r.authority ||
      !Crypto::constantTimeEqual(a.requestDigest, requestHash) ||
      !Crypto::constantTimeEqual(a.claimDigest, claimHash) || a.claimId != c.claimId ||
      !Crypto::constantTimeEqual(a.eligibilityDigest, c.eligibilityDigest) || !same(a.endpoint, c.endpoint) ||
      a.observedAtSeconds < r.issuedAtSeconds || a.observedAtSeconds >= r.expiresAtSeconds) {
    return makeError(StatusCode::kTokenMismatch, "GC acknowledgement does not bind the exact issued exchange");
  }
  return VerifiedEcGcAck(ack);
}
Result<EcGcAck> Codec::signConfirmed(const EcGcKey &key,
                                     const VerifiedEcGcRequest &verified,
                                     Result<EcGcLedgerReceipt> receipt,
                                     const EcGcLocalTarget &actual,
                                     const Uuid &authority,
                                     const Uuid &bootNonce,
                                     uint64_t now) {
  // These errors cannot become Collected, nor can an existing 4085 become an
  // ordinary authentication failure merely because the exchange later expires.
  if (!receipt) return makeError(std::move(receipt.error()));
  try {
    const auto &request = verified.request();
    auto checked = verifyRequest(key, request, authority, verified.action(), actual, now);
    if (!checked || receipt->claimId != verified.certificate().claimId || zero(receipt->ledgerSha256) ||
        receipt->terminalRevision < 2 || bootNonce.is_nil()) {
      return makeError(StorageCode::kEcSealOutcomeUnknown, "GC completed but confirmation checks failed; retain claim");
    }
    EcGcAck result;
    auto &a = result.claims;
    a.keyId = request.claims.keyId;
    a.authority = request.claims.authority;
    auto requestHash = digest(encode(request.claims));
    if (!requestHash) return makeError(StorageCode::kEcSealOutcomeUnknown);
    a.requestDigest = *requestHash;
    a.claimDigest = verified.claimDigest();
    a.claimId = receipt->claimId;
    a.eligibilityDigest = verified.certificate().eligibilityDigest;
    a.endpoint = verified.certificate().endpoint;
    a.ledgerSha256 = receipt->ledgerSha256;
    a.terminalRevision = receipt->terminalRevision;
    a.observedAtSeconds = now;
    a.bootNonce = bootNonce;
    auto signature = Crypto::authenticate(*key.key_, encode(a));
    if (!signature) return makeError(StorageCode::kEcSealOutcomeUnknown);
    result.signature_ = *signature;
    return result;
  } catch (...) {
    // Code-only Status does not allocate while reporting a secondary OOM.
    return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
}
}  // namespace ec_gc_control_detail
}  // namespace hf3fs::storage
