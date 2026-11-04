#include <algorithm>
#include <chrono>
#include <fstream>
#include <functional>
#include <limits>
#include <new>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <type_traits>

#include "fbs/storage/EcAuthorization.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {

constexpr uint64_t kIssued = 1700000000;

struct GrantEnvelope {
  SERDE_STRUCT_FIELD(token, EcCapability{});
};

struct GrantTextEnvelope {
  SERDE_STRUCT_FIELD(token, std::string{});
};

Uuid grantUuid(uint8_t start) {
  Uuid result;
  for (size_t i = 0; i != 16; ++i) result.data[i] = start + i;
  return result;
}

std::array<uint8_t, 32> keyBytes() {
  std::array<uint8_t, 32> result{};
  for (size_t i = 0; i != result.size(); ++i) result[i] = i;
  return result;
}

EcGrantClaims claims() {
  EcGrantClaims value;
  value.identity.object = grantUuid(1);
  value.identity.stripe = 0x0102030405060708;
  value.identity.generation = 9;
  value.identity.shard = 10;
  value.identity.allocation = grantUuid(21);
  value.fragmentOperationId = grantUuid(41);
  value.chainId = ChainId(0x01020304);
  value.targetId = TargetId(0x1122334455667788);
  value.nodeId = NodeId(0x10203040);
  value.expectedLength = 65539;
  value.expectedCrc32c = 0x12345678;
  value.rights = 7;
  value.grantId = grantUuid(61);
  value.ownerUid = flat::Uid(1000);
  value.clientUuid = grantUuid(81);
  value.scopeObject = value.identity.object;
  value.scopeKind = EcGrantScope::WriteOperation;
  value.scopeId = grantUuid(101);
  value.issuedAtSeconds = kIssued;
  value.expiresAtSeconds = kIssued + 300;
  return value;
}

std::string hex(std::span<const uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

std::string tokenFrame(std::string_view canonical, std::string_view tag) {
  return serde::serialize(Varint64(2)) + serde::serialize(canonical) + serde::serialize(tag);
}

bool writeKeyFile(const std::filesystem::path &path, std::string_view bytes, mode_t permissions = 0600) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(bytes.data(), bytes.size());
  output.close();
  return output.good() && ::chmod(path.c_str(), permissions) == 0;
}

TEST(TestEcAuthorization, OpenSslMatchesRfc4231AndFixedKeyCanonicalGolden) {
  // RFC 4231 section 4.2, https://www.rfc-editor.org/rfc/rfc4231.txt.
  // The RFC's 20-byte key is used only for this independent library check,
  // never by the production key type or a production arbitrary-HMAC API.
  const std::array<uint8_t, 20> rfcKey = [] {
    std::array<uint8_t, 20> value;
    value.fill(0x0b);
    return value;
  }();
  const std::string data = "Hi There";
  EcSha256 rfcDigest{};
  unsigned int size = 0;
  ASSERT_NE(HMAC(EVP_sha256(),
                 rfcKey.data(),
                 rfcKey.size(),
                 reinterpret_cast<const uint8_t *>(data.data()),
                 data.size(),
                 rfcDigest.data(),
                 &size),
            nullptr);
  ASSERT_EQ(size, 32);
  ASSERT_EQ(hex(rfcDigest), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  // Independent Python 3 generation: hmac.new(bytes(range(32)), message,
  // hashlib.sha256).hexdigest(); message is the following complete fixed
  // canonical input, converted with bytes.fromhex(). No production encoder was
  // called when producing the expected input or digest.
  const std::string canonicalHex =
      "3346534543470001000100010102030405060708090a0b0c0d0e0f10"
      "01020304050607080000000000000009000a15161718191a1b1c1d1e1f2021222324"
      "292a2b2c2d2e2f30313233343536373801020304112233445566778810203040"
      "0001000312345678073d3e3f404142434445464748494a4b4c000003e8"
      "5152535455565758595a5b5c5d5e5f600102030405060708090a0b0c0d0e0f10"
      "0265666768696a6b6c6d6e6f7071727374000000006553f100000000006553f22c";
  const auto original = claims();
  ASSERT_EQ(hex(ec_authorization_detail::encodeClaims(original)), canonicalHex);
  const EcCapabilityKey key(keyBytes());
  auto grant = signEcGrant(key, original, kIssued);
  ASSERT_OK(grant);
  const auto wire = serde::serialize(*grant);
  ASSERT_EQ(wire.size(), 224);
  ASSERT_EQ(hex(std::span(reinterpret_cast<const uint8_t *>(wire.data() + wire.size() - 32), size_t(32))),
            "1debce2752bc2a9ef8244b2ec4171d502c28c96ca3eeb9087ee33461a95d17c2");
  EcCapability decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_EQ(serde::serialize(decoded), wire);
  ASSERT_OK(verifyEcGrant(key, decoded, original, EcGrantRight::Create, kIssued));
  ASSERT_OK(verifyEcGrant(key, decoded, original, EcGrantRight::Read, kIssued + 100));
  ASSERT_OK(verifyEcGrant(key, decoded, original, EcGrantRight::Reconcile, kIssued + 299));
}

TEST(TestEcAuthorization, EveryClaimFieldAndSignatureAreAuthenticated) {
  const EcCapabilityKey key(keyBytes());
  const auto original = claims();
  auto grant = signEcGrant(key, original, kIssued);
  ASSERT_OK(grant);
  const std::vector<std::function<void(EcGrantClaims &)>> mutations{
      [](auto &c) { ++c.version; },
      [](auto &c) { ++c.identity.version; },
      [](auto &c) { c.identity.object.data[0] ^= 1; },
      [](auto &c) { ++c.identity.stripe; },
      [](auto &c) { ++c.identity.generation; },
      [](auto &c) { --c.identity.shard; },
      [](auto &c) { c.identity.allocation.data[0] ^= 1; },
      [](auto &c) { c.fragmentOperationId.data[0] ^= 1; },
      [](auto &c) { ++c.chainId; },
      [](auto &c) { ++c.targetId; },
      [](auto &c) { ++c.nodeId; },
      [](auto &c) { ++c.expectedLength; },
      [](auto &c) { c.expectedCrc32c ^= 1; },
      [](auto &c) { c.rights = 3; },
      [](auto &c) { c.grantId.data[0] ^= 1; },
      [](auto &c) { ++c.ownerUid; },
      [](auto &c) { c.clientUuid.data[0] ^= 1; },
      [](auto &c) { c.scopeObject.data[0] ^= 1; },
      [](auto &c) { c.scopeKind = EcGrantScope::ReadPin; },
      [](auto &c) { c.scopeId.data[0] ^= 1; },
      [](auto &c) { ++c.issuedAtSeconds; },
      [](auto &c) { --c.expiresAtSeconds; },
  };
  for (size_t index = 0; index != mutations.size(); ++index) {
    SCOPED_TRACE(index);
    auto changed = *grant;
    mutations[index](changed.claims);
    ASSERT_FALSE(verifyEcGrant(key, changed, original, EcGrantRight::Read, kIssued + 100));
  }
  auto wire = serde::serialize(*grant);
  wire.back() ^= 1;
  EcCapability altered;
  ASSERT_OK(serde::deserialize(altered, wire));
  ASSERT_ERROR(verifyEcGrant(key, altered, original, EcGrantRight::Read, kIssued), StatusCode::kAuthenticationFail);
  auto otherBytes = keyBytes();
  otherBytes[0] ^= 1;
  const EcCapabilityKey wrong(otherBytes);
  ASSERT_ERROR(verifyEcGrant(wrong, *grant, original, EcGrantRight::Read, kIssued), StatusCode::kAuthenticationFail);
}

TEST(TestEcAuthorization, ExactRequestBindingIncludesRepairSourceOperationAndCaller) {
  const EcCapabilityKey key(keyBytes());
  auto original = claims();
  // A repair operation may read an older, shared fragment. The fragment's
  // original operation ID remains separate from this operation's scope ID.
  ASSERT_NE(original.fragmentOperationId, original.scopeId);
  auto grant = signEcGrant(key, original, kIssued);
  ASSERT_OK(grant);
  const std::vector<std::function<void(EcGrantBinding &)>> mutations{
      [](auto &b) {
        b.identity.object.data[0] ^= 1;
        b.scopeObject = b.identity.object;
      },
      [](auto &b) { ++b.identity.stripe; },
      [](auto &b) { ++b.identity.generation; },
      [](auto &b) { --b.identity.shard; },
      [](auto &b) { b.identity.allocation.data[0] ^= 1; },
      [](auto &b) { b.fragmentOperationId = b.scopeId; },
      [](auto &b) { ++b.chainId; },
      [](auto &b) { ++b.targetId; },
      [](auto &b) { ++b.nodeId; },
      [](auto &b) { ++b.expectedLength; },
      [](auto &b) { b.expectedCrc32c ^= 1; },
      [](auto &b) { ++b.ownerUid; },
      [](auto &b) { b.clientUuid.data[0] ^= 1; },
      [](auto &b) { b.scopeKind = EcGrantScope::ReadPin; },
      [](auto &b) { b.scopeId.data[0] ^= 1; },
  };
  for (size_t index = 0; index != mutations.size(); ++index) {
    SCOPED_TRACE(index);
    EcGrantBinding expected = original;
    mutations[index](expected);
    ASSERT_ERROR(verifyEcGrant(key, *grant, expected, EcGrantRight::Read, kIssued), StatusCode::kAuthenticationFail);
  }
}

TEST(TestEcAuthorization, RightsAndClockBoundariesDoNotAuthorizeGcOrDelete) {
  const EcCapabilityKey key(keyBytes());
  auto original = claims();
  original.scopeKind = EcGrantScope::ReadPin;
  original.rights = static_cast<uint8_t>(EcGrantRight::Read);
  original.ownerUid = flat::Uid(0);
  auto grant = signEcGrant(key, original, kIssued);
  ASSERT_OK(grant);
  ASSERT_OK(verifyEcGrant(key, *grant, original, EcGrantRight::Read, kIssued));
  ASSERT_OK(verifyEcGrant(key, *grant, original, EcGrantRight::Read, kIssued + 299));
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, EcGrantRight::Read, kIssued - 1), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, EcGrantRight::Read, kIssued + 300),
               StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, EcGrantRight::Create, kIssued), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, EcGrantRight::Reconcile, kIssued), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, static_cast<EcGrantRight>(8), kIssued), StatusCode::kInvalidArg);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, static_cast<EcGrantRight>(3), kIssued), StatusCode::kInvalidArg);
  ASSERT_ERROR(verifyEcGrant(key, *grant, original, EcGrantRight::Read, kIssued, 299), StatusCode::kInvalidArg);
  for (uint8_t rights : {uint8_t(0), uint8_t(1), uint8_t(4), uint8_t(7), uint8_t(8)}) {
    original.rights = rights;
    ASSERT_ERROR(signEcGrant(key, original, kIssued), StatusCode::kInvalidArg);
  }
  original = claims();
  original.rights = 8;
  ASSERT_ERROR(signEcGrant(key, original, kIssued), StatusCode::kInvalidArg);
  original = claims();
  original.expiresAtSeconds = kIssued + 3600;
  ASSERT_OK(signEcGrant(key, original, kIssued, 3600));
  ASSERT_ERROR(signEcGrant(key, original, kIssued, 3601), StatusCode::kInvalidArg);
  ASSERT_ERROR(signEcGrant(key, original, kIssued, 0), StatusCode::kInvalidArg);
  ++original.expiresAtSeconds;
  ASSERT_ERROR(signEcGrant(key, original, kIssued, 3600), StatusCode::kInvalidArg);
  original = claims();
  ASSERT_ERROR(signEcGrant(key, original, kIssued - 1), StatusCode::kAuthenticationFail);
  original.issuedAtSeconds = std::numeric_limits<uint64_t>::max() - 1;
  original.expiresAtSeconds = 1;
  ASSERT_ERROR(signEcGrant(key, original, kIssued), StatusCode::kInvalidArg);
}

TEST(TestEcAuthorization, RejectsInvalidBindingAndSchemaBeforeSigning) {
  const EcCapabilityKey key(keyBytes());
  const std::vector<std::function<void(EcGrantClaims &)>> invalid{
      [](auto &c) { c.version = 0; },
      [](auto &c) { c.identity.version = 0; },
      [](auto &c) { c.identity.object = Uuid::zero(); },
      [](auto &c) { c.identity.allocation = Uuid::zero(); },
      [](auto &c) { c.identity.generation = 0; },
      [](auto &c) { c.identity.shard = 12; },
      [](auto &c) { c.fragmentOperationId = Uuid::zero(); },
      [](auto &c) { c.chainId = ChainId{}; },
      [](auto &c) { c.targetId = TargetId{}; },
      [](auto &c) { c.nodeId = NodeId{}; },
      [](auto &c) { c.expectedLength = kEcFragmentRpcMaxBytes + 1; },
      [](auto &c) { c.expectedLength = 0; },
      [](auto &c) { c.grantId = Uuid::zero(); },
      [](auto &c) { c.clientUuid = Uuid::zero(); },
      [](auto &c) { c.scopeObject = Uuid::zero(); },
      [](auto &c) { c.scopeKind = static_cast<EcGrantScope>(0); },
      [](auto &c) { c.scopeId = Uuid::zero(); },
      [](auto &c) { c.expiresAtSeconds = c.issuedAtSeconds; },
  };
  for (size_t index = 0; index != invalid.size(); ++index) {
    SCOPED_TRACE(index);
    auto request = claims();
    invalid[index](request);
    ASSERT_ERROR(signEcGrant(key, request, kIssued), StatusCode::kInvalidArg);
  }
  auto empty = claims();
  empty.expectedLength = 0;
  empty.expectedCrc32c = 0;
  ASSERT_OK(signEcGrant(key, empty, kIssued));
}

TEST(TestEcAuthorization, FixedBinarySerdeRejectsMaliciousCountsAndRedactsText) {
  const EcCapabilityKey key(keyBytes());
  auto grant = signEcGrant(key, claims(), kIssued);
  ASSERT_OK(grant);
  const auto canonical = ec_authorization_detail::encodeClaims(grant->claims);
  const std::string_view raw(reinterpret_cast<const char *>(canonical.data()), canonical.size());
  EcCapability decoded = *grant;
  const auto previous = serde::serialize(decoded);
  for (uint64_t count : {uint64_t(0), uint64_t(1), uint64_t(3), std::numeric_limits<uint64_t>::max()}) {
    ASSERT_ERROR(serde::deserialize(decoded, serde::serialize(Varint64(count))), StatusCode::kInvalidFormat);
  }
  for (size_t size : {size_t(0), size_t(187), size_t(189), size_t(4096)}) {
    ASSERT_ERROR(serde::deserialize(decoded, tokenFrame(std::string(size, 'x'), std::string(32, 'y'))),
                 StatusCode::kInvalidFormat);
  }
  for (size_t size : {size_t(0), size_t(31), size_t(33), size_t(4096)}) {
    ASSERT_ERROR(serde::deserialize(decoded, tokenFrame(raw, std::string(size, 'y'))), StatusCode::kInvalidFormat);
  }
  const auto oversizedExtent =
      serde::serialize(Varint64(2)) + serde::serialize(Varint64(std::numeric_limits<uint64_t>::max()));
  ASSERT_ERROR(serde::deserialize(decoded, oversizedExtent), StatusCode::kSerdeInsufficientLength);
  auto domain = std::string(raw);
  domain[0] ^= 1;
  ASSERT_ERROR(serde::deserialize(decoded, tokenFrame(domain, std::string(32, 'y'))), StatusCode::kInvalidFormat);
  ASSERT_EQ(serde::serialize(decoded), previous);

  GrantEnvelope envelope;
  envelope.token = *grant;
  const auto formatted = fmt::format("{}", *grant);
  const auto json = serde::toJsonString(envelope);
  const auto toml = serde::toTomlString(envelope);
  // TOML's 80-column serializer can insert line continuations inside the
  // redaction marker. Check the complete decoded string, not a raw substring;
  // only the grant ID and the fixed marker may appear in the readable value.
  GrantTextEnvelope jsonText, tomlText;
  ASSERT_OK(serde::fromJsonString(jsonText, json));
  ASSERT_OK(serde::fromTomlString(tomlText, toml));
  const auto expected = fmt::format("EcCapability(grant={}, signature=REDACTED)", grant->claims.grantId);
  ASSERT_EQ(formatted, expected);
  ASSERT_EQ(jsonText.token, expected);
  ASSERT_EQ(tomlText.token, expected);
  const auto rawSignature = previous.substr(previous.size() - 32);
  for (const auto &readable : {formatted, json, toml}) {
    ASSERT_EQ(readable.find("1debce2752bc2a9ef8244b2ec4171d502c28c96ca3eeb9087ee33461a95d17c2"), std::string::npos);
    ASSERT_EQ(readable.find(rawSignature), std::string::npos);
  }
  ASSERT_ERROR(serde::fromJsonString(envelope, json), StatusCode::kInvalidFormat);
  ASSERT_ERROR(serde::fromTomlString(envelope, toml), StatusCode::kInvalidFormat);
}

TEST(TestEcAuthorization, SecretHasNoDefaultCopyOrFormatterAndClearsItsStorage) {
  static_assert(!std::is_default_constructible_v<EcCapabilityKey>);
  static_assert(!std::is_copy_constructible_v<EcCapabilityKey>);
  static_assert(!std::is_move_constructible_v<EcCapabilityKey>);
  static_assert(!serde::SerdeType<EcCapabilityKey>);
  static_assert(!fmt::is_formattable<EcCapabilityKey>::value);
  static_assert(sizeof(EcCapabilityKey) == 32);
  alignas(EcCapabilityKey) uint8_t storage[sizeof(EcCapabilityKey)];
  auto bytes = keyBytes();
  auto *key = new (storage) EcCapabilityKey(bytes);
  ASSERT_TRUE(std::equal(std::begin(storage), std::end(storage), bytes.begin()));
  key->~EcCapabilityKey();
  ASSERT_TRUE(std::all_of(std::begin(storage), std::end(storage), [](auto byte) { return byte == 0; }));
}

TEST(TestEcAuthorization, KeyFileLoadsExactRawOwnerOnlyKeyAndRejectsLengthOrZero) {
  folly::test::TemporaryDirectory directory;
  const auto path = std::filesystem::path(directory.path().string()) / "capability.key";
  const auto bytes = keyBytes();
  const std::string_view raw(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  ASSERT_TRUE(writeKeyFile(path, raw));
  auto loaded = EcCapabilityKey::loadFile(path);
  ASSERT_OK(loaded);
  const EcCapabilityKey direct(bytes);
  auto grant = signEcGrant(**loaded, claims(), kIssued);
  ASSERT_OK(grant);
  ASSERT_OK(verifyEcGrant(direct, *grant, claims(), EcGrantRight::Read, kIssued));
  ASSERT_EQ(::chmod(path.c_str(), 0400), 0);
  ASSERT_OK(EcCapabilityKey::loadFile(path));
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  for (size_t length : {size_t(31), size_t(33)}) {
    ASSERT_TRUE(writeKeyFile(path, std::string(length, 'x')));
    ASSERT_ERROR(EcCapabilityKey::loadFile(path), StatusCode::kInvalidConfig);
  }
  ASSERT_TRUE(writeKeyFile(path, std::string(32, '\0')));
  ASSERT_ERROR(EcCapabilityKey::loadFile(path), StatusCode::kInvalidConfig);
  ASSERT_ERROR(EcCapabilityKey::loadFile({}), StatusCode::kInvalidConfig);
  const auto missing = path.parent_path() / "missing.key";
  ASSERT_ERROR(EcCapabilityKey::loadFile(missing), StatusCode::kIOError);
  ASSERT_FALSE(std::filesystem::exists(missing));
}

TEST(TestEcAuthorization, KeyFileRejectsAllGroupWorldPermissionsSymlinksAndFifo) {
  folly::test::TemporaryDirectory directory;
  const auto root = std::filesystem::path(directory.path().string());
  const auto path = root / "capability.key";
  const auto bytes = keyBytes();
  const std::string_view raw(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  ASSERT_TRUE(writeKeyFile(path, raw));
  for (mode_t permission : {S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH}) {
    ASSERT_EQ(::chmod(path.c_str(), 0600 | permission), 0);
    ASSERT_ERROR(EcCapabilityKey::loadFile(path), StatusCode::kInvalidConfig);
  }
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  const auto symlink = root / "symlink.key";
  std::filesystem::create_symlink(path, symlink);
  ASSERT_ERROR(EcCapabilityKey::loadFile(symlink), StatusCode::kIOError);
  ASSERT_ERROR(EcCapabilityKey::loadFile(root), StatusCode::kInvalidConfig);
  const auto fifo = root / "fifo.key";
  ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
  const auto start = std::chrono::steady_clock::now();
  ASSERT_ERROR(EcCapabilityKey::loadFile(fifo), StatusCode::kInvalidConfig);
  ASSERT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(2));
  // Rejected paths never replace or damage the original regular key file.
  ASSERT_OK(EcCapabilityKey::loadFile(path));
}

}  // namespace
}  // namespace hf3fs::storage
