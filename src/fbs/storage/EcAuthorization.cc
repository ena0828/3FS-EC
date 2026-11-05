#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {

constexpr std::string_view kDomain("3FSECG\0\1", 8);
constexpr uint8_t kAllRights = 7;

class KeyFileDescriptor {
 public:
  explicit KeyFileDescriptor(int fd)
      : fd_(fd) {}
  ~KeyFileDescriptor() {
    if (fd_ >= 0) ::close(fd_);
  }
  KeyFileDescriptor(const KeyFileDescriptor &) = delete;
  KeyFileDescriptor &operator=(const KeyFileDescriptor &) = delete;
  int get() const { return fd_; }

 private:
  int fd_;
};

struct KeyFileBytes {
  std::array<uint8_t, 33> value{};
  ~KeyFileBytes() { OPENSSL_cleanse(value.data(), value.size()); }
};

Result<Void> validateBinding(const EcGrantBinding &binding) {
  RETURN_ON_ERROR(binding.identity.validate());
  if (binding.identity.shard >= 12 || binding.fragmentOperationId.is_nil() || binding.chainId == ChainId{} ||
      binding.targetId == TargetId{} || binding.nodeId == NodeId{} || binding.clientUuid.is_nil() ||
      binding.scopeId.is_nil() || binding.scopeObject != binding.identity.object ||
      (binding.scopeKind != EcGrantScope::ReadPin && binding.scopeKind != EcGrantScope::WriteOperation) ||
      binding.expectedLength > kEcFragmentRpcMaxBytes || (binding.expectedLength == 0 && binding.expectedCrc32c != 0)) {
    return makeError(StatusCode::kInvalidArg, "invalid EC grant identity, scope, placement or extent");
  }
  return Void{};
}

Result<Void> validateClaims(const EcGrantClaims &claims, uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateBinding(claims));
  if (claims.version != kEcGrantVersion || claims.grantId.is_nil() || claims.rights == 0 ||
      (claims.rights & ~kAllRights) != 0 ||
      (claims.scopeKind == EcGrantScope::ReadPin && claims.rights != static_cast<uint8_t>(EcGrantRight::Read)) ||
      maxTtlSeconds == 0 || maxTtlSeconds > kEcGrantMaxTtlSeconds ||
      claims.expiresAtSeconds <= claims.issuedAtSeconds ||
      claims.expiresAtSeconds - claims.issuedAtSeconds > maxTtlSeconds) {
    return makeError(StatusCode::kInvalidArg, "invalid EC grant version, rights or bounded lifetime");
  }
  return Void{};
}

Result<Void> checkTime(const EcGrantClaims &claims, uint64_t nowSeconds) {
  if (nowSeconds < claims.issuedAtSeconds || nowSeconds >= claims.expiresAtSeconds) {
    return makeError(StatusCode::kAuthenticationFail, "EC grant is not currently valid");
  }
  return Void{};
}

}  // namespace

namespace ec_authorization_detail {

// Canonical format 1 has no variable-width fields. Numeric values are unsigned
// big endian; UUIDs are their 16 raw bytes. It is independent of native layout
// and of Serde's framing. The MAC covers this complete 188-byte sequence.
std::array<uint8_t, kEcGrantCanonicalBytes> encodeClaims(const EcGrantClaims &claims) {
  std::array<uint8_t, kEcGrantCanonicalBytes> out{};
  size_t offset = 0;
  auto integer = [&](uint64_t value, size_t width) {
    for (size_t i = width; i != 0; --i) out[offset++] = static_cast<uint8_t>(value >> ((i - 1) * 8));
  };
  auto uuid = [&](const Uuid &value) {
    std::copy(std::begin(value.data), std::end(value.data), out.begin() + offset);
    offset += sizeof(value.data);
  };
  for (char byte : kDomain) out[offset++] = static_cast<uint8_t>(byte);
  integer(claims.version, 2);
  integer(claims.identity.version, 2);
  uuid(claims.identity.object);
  integer(claims.identity.stripe, 8);
  integer(claims.identity.generation, 8);
  integer(claims.identity.shard, 2);
  uuid(claims.identity.allocation);
  uuid(claims.fragmentOperationId);
  integer(claims.chainId.toUnderType(), 4);
  integer(claims.targetId.toUnderType(), 8);
  integer(claims.nodeId.toUnderType(), 4);
  integer(claims.expectedLength, 4);
  integer(claims.expectedCrc32c, 4);
  integer(claims.rights, 1);
  uuid(claims.grantId);
  integer(claims.ownerUid.toUnderType(), 4);
  uuid(claims.clientUuid);
  uuid(claims.scopeObject);
  integer(static_cast<uint8_t>(claims.scopeKind), 1);
  uuid(claims.scopeId);
  integer(claims.issuedAtSeconds, 8);
  integer(claims.expiresAtSeconds, 8);
  return out;
}

Result<EcGrantClaims> decodeClaims(std::string_view bytes) {
  if (bytes.size() != kEcGrantCanonicalBytes || bytes.substr(0, kDomain.size()) != kDomain) {
    return makeError(StatusCode::kInvalidFormat, "EC capability has an invalid fixed extent or domain");
  }
  size_t offset = kDomain.size();
  auto integer = [&](size_t width) {
    uint64_t result = 0;
    for (size_t i = 0; i != width; ++i) result = (result << 8) | static_cast<uint8_t>(bytes[offset++]);
    return result;
  };
  auto uuid = [&]() {
    Uuid value;
    std::memcpy(value.data, bytes.data() + offset, sizeof(value.data));
    offset += sizeof(value.data);
    return value;
  };
  EcGrantClaims claims;
  claims.version = integer(2);
  claims.identity.version = integer(2);
  claims.identity.object = uuid();
  claims.identity.stripe = integer(8);
  claims.identity.generation = integer(8);
  claims.identity.shard = integer(2);
  claims.identity.allocation = uuid();
  claims.fragmentOperationId = uuid();
  claims.chainId = ChainId(integer(4));
  claims.targetId = TargetId(integer(8));
  claims.nodeId = NodeId(integer(4));
  claims.expectedLength = integer(4);
  claims.expectedCrc32c = integer(4);
  claims.rights = integer(1);
  claims.grantId = uuid();
  claims.ownerUid = flat::Uid(integer(4));
  claims.clientUuid = uuid();
  claims.scopeObject = uuid();
  claims.scopeKind = static_cast<EcGrantScope>(integer(1));
  claims.scopeId = uuid();
  claims.issuedAtSeconds = integer(8);
  claims.expiresAtSeconds = integer(8);
  // Decoding checks schema but never authenticates a token or its current time.
  RETURN_ON_ERROR(validateClaims(claims, kEcGrantMaxTtlSeconds));
  return claims;
}

Result<EcSha256> Access::authenticate(const EcCapabilityKey &key, std::span<const uint8_t> bytes) {
  EcSha256 signature{};
  unsigned int length = 0;
  if (HMAC(EVP_sha256(), key.bytes_.data(), key.bytes_.size(), bytes.data(), bytes.size(), signature.data(), &length) ==
          nullptr ||
      length != signature.size()) {
    return makeError(StatusCode::kIOError, "EC HMAC-SHA256 calculation failed");
  }
  return signature;
}
bool Access::constantTimeEqual(const EcSha256 &left, const EcSha256 &right) {
  return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}
void Access::setSignature(EcCapability &grant, const EcSha256 &signature) { grant.signature_ = signature; }
bool Access::matches(const EcCapability &grant, const EcSha256 &signature) {
  return constantTimeEqual(grant.signature_, signature);
}

}  // namespace ec_authorization_detail

EcCapabilityKey::EcCapabilityKey(std::span<const uint8_t, 32> bytes) {
  std::copy(bytes.begin(), bytes.end(), bytes_.begin());
}

EcCapabilityKey::~EcCapabilityKey() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

Result<std::unique_ptr<EcCapabilityKey>> EcCapabilityKey::loadFile(const std::filesystem::path &path) {
  try {
    if (path.empty() || path.native().find('\0') != std::string::npos) {
      return makeError(StatusCode::kInvalidConfig, "EC key file requires one explicit nonempty path");
    }
    const auto ioError = [&](std::string_view operation, int error) {
      return makeError(StatusCode::kIOError,
                       fmt::format("EC key file {}: {} failed (errno {})", path.string(), operation, error));
    };
    // O_NONBLOCK prevents opening a FIFO from waiting for a writer. fstat then
    // rejects every non-regular object before any read is attempted.
    KeyFileDescriptor file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) return ioError("open", errno);
    struct stat metadata {};
    if (::fstat(file.get(), &metadata) != 0) return ioError("fstat", errno);
    if (!S_ISREG(metadata.st_mode) || (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        (metadata.st_uid != ::geteuid() && metadata.st_uid != 0)) {
      return makeError(
          StatusCode::kInvalidConfig,
          fmt::format("EC key file {} must be regular, owner-only and owned by euid or root", path.string()));
    }
    if (metadata.st_size != 32) {
      return makeError(StatusCode::kInvalidConfig,
                       fmt::format("EC key file {} must contain exactly 32 raw bytes", path.string()));
    }
    KeyFileBytes bytes;
    size_t readBytes = 0;
    while (readBytes != bytes.value.size()) {
      const auto count = ::read(file.get(), bytes.value.data() + readBytes, bytes.value.size() - readBytes);
      if (count < 0) {
        if (errno == EINTR) continue;
        return ioError("read", errno);
      }
      if (count == 0) break;
      readBytes += static_cast<size_t>(count);
    }
    if (readBytes != 32 ||
        std::all_of(bytes.value.begin(), bytes.value.begin() + 32, [](uint8_t byte) { return byte == 0; })) {
      return makeError(
          StatusCode::kInvalidConfig,
          fmt::format("EC key file {} must contain exactly 32 raw bytes and must not be all zero", path.string()));
    }
    // The 33rd-byte read must reach EOF. The temporary is cleansed after the
    // key copies its 32 bytes, including exceptions and all earlier returns.
    auto key = std::make_unique<EcCapabilityKey>(std::span<const uint8_t, 32>(bytes.value.data(), 32));
    static_assert(sizeof(metadata.st_dev) <= sizeof(uint64_t));
    static_assert(sizeof(metadata.st_ino) <= sizeof(uint64_t));
    // Preserve the identity from the validated fd, even if its pathname
    // is replaced before another role is loaded. Never stat(path) here.
    key->fileIdentity_ =
        EcKeyFileIdentity{static_cast<uint64_t>(metadata.st_dev), static_cast<uint64_t>(metadata.st_ino)};
    return key;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

std::string EcCapability::serdeToReadable() const {
  return fmt::format("EcCapability(grant={}, signature=REDACTED)", claims.grantId);
}

Result<EcCapability> signEcGrant(const EcCapabilityKey &key,
                                 const EcGrantClaims &claims,
                                 uint64_t nowSeconds,
                                 uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateClaims(claims, maxTtlSeconds));
  RETURN_ON_ERROR(checkTime(claims, nowSeconds));
  CHECK_RESULT(signature,
               ec_authorization_detail::Access::authenticate(key, ec_authorization_detail::encodeClaims(claims)));
  EcCapability grant;
  grant.claims = claims;
  ec_authorization_detail::Access::setSignature(grant, signature);
  return grant;
}

Result<Void> verifyEcGrant(const EcCapabilityKey &key,
                           const EcCapability &grant,
                           const EcGrantBinding &expected,
                           EcGrantRight requiredRight,
                           uint64_t nowSeconds,
                           uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(validateClaims(grant.claims, maxTtlSeconds));
  RETURN_ON_ERROR(validateBinding(expected));
  if (requiredRight != EcGrantRight::Create && requiredRight != EcGrantRight::Read &&
      requiredRight != EcGrantRight::Reconcile) {
    return makeError(StatusCode::kInvalidArg, "EC verification requires one known access right");
  }
  const auto canonical = ec_authorization_detail::encodeClaims(grant.claims);
  CHECK_RESULT(signature, ec_authorization_detail::Access::authenticate(key, canonical));
  if (!ec_authorization_detail::Access::matches(grant, signature)) {
    return makeError(StatusCode::kAuthenticationFail, "EC capability authentication failed");
  }
  auto matchingClaims = grant.claims;
  static_cast<EcGrantBinding &>(matchingClaims) = expected;
  const auto binding = ec_authorization_detail::encodeClaims(matchingClaims);
  if (binding != canonical || !(grant.claims.rights & static_cast<uint8_t>(requiredRight))) {
    return makeError(StatusCode::kAuthenticationFail, "EC capability does not authorize this request");
  }
  RETURN_ON_ERROR(checkTime(grant.claims, nowSeconds));
  return Void{};
}

}  // namespace hf3fs::storage
