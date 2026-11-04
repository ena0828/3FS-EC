#include <algorithm>
#include <fstream>
#include <functional>
#include <limits>
#include <sys/stat.h>
#include <type_traits>

#include "fbs/storage/EcAuthorizedV2.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
constexpr uint64_t kIssued = 1700000000;
constexpr std::string_view kGoldenMac = "3616029a38491c34c5837899494f3be546367478ee4b3b1db0a63d711872b2d6";

Uuid uuid(uint8_t start) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = start + i;
  return value;
}
std::array<uint8_t, 32> keyBytes() {
  std::array<uint8_t, 32> bytes{};
  for (size_t i = 0; i != bytes.size(); ++i) bytes[i] = i;
  return bytes;
}
std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (uint8_t byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}
template <size_t N>
std::string hex(const std::array<uint8_t, N> &bytes) {
  return hex(std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}
std::string frame(std::string_view claims, std::string_view signature) {
  return serde::serialize(Varint64(2)) + serde::serialize(claims) + serde::serialize(signature);
}
struct Envelope {
  SERDE_STRUCT_FIELD(token, EcCapabilityV2{});
};
struct TextEnvelope {
  SERDE_STRUCT_FIELD(token, std::string{});
};

class TestEcAuthorizationV2 : public ::testing::Test {
 protected:
  void SetUp() override {
    claims.engineUuid = uuid(131);
    claims.targetIncarnation = uuid(151);
    claims.identity.object = uuid(1);
    claims.identity.stripe = 0x0102030405060708;
    claims.identity.generation = 9;
    claims.identity.shard = 10;
    claims.identity.allocation = uuid(21);
    claims.fragmentOperationId = uuid(41);
    claims.chainId = ChainId(0x01020304);
    claims.targetId = TargetId(0x1122334455667788);
    claims.nodeId = NodeId(0x10203040);
    auto descriptor = computeEcIntegrity(claims.identity, payload);
    ASSERT_OK(descriptor);
    integrity = *descriptor;
    claims.expectedLength = integrity.wholeLength;
    claims.expectedCrc32c = integrity.wholeCrc32c;
    auto digest = digestEcIntegrityV2(claims.identity, integrity);
    ASSERT_OK(digest);
    claims.integrityDigest = *digest;
    claims.ownerUid = flat::Uid(1000);
    claims.clientNamespace = uuid(81);
    claims.scopeObject = claims.identity.object;
    claims.scopeKind = EcGrantScope::WriteOperation;
    claims.scopeId = uuid(101);
    claims.rights = kEcGrantAllRightsV2;
    claims.grantId = uuid(61);
    claims.issuedAtSeconds = kIssued;
    claims.expiresAtSeconds = kIssued + 300;
    local.engineUuid = claims.engineUuid;
    local.targetIncarnation = claims.targetIncarnation;
    local.vChainId = {claims.chainId, ChainVer(7)};
    local.targetId = claims.targetId;
    local.nodeId = claims.nodeId;
    access.identity = claims.identity;
    access.operationId = claims.fragmentOperationId;
    access.vChainId = local.vChainId;
    access.targetId = claims.targetId;
    access.integrity = integrity;
  }
  const EcCapabilityKey key{keyBytes()};
  const std::string payload = std::string(65539, 'x');
  EcGrantClaimsV2 claims;
  EcIntegrityDescriptor integrity;
  EcLocalTargetV2 local;
  EcFragmentAccessV2 access;
};

TEST_F(TestEcAuthorizationV2, IndependentCanonicalGoldenAndFixedBinaryRoundtrip) {
  // Independently generated with Python hashlib/hmac and explicit protocol
  // fields in artifacts/ec-authorization-v2/golden_vector.py, not Serde.
  ASSERT_EQ(integrity.wholeCrc32c, 844156180u);
  ASSERT_EQ(hex(integrity.root), "91821ec19a80548ae65917374d889c7c31acf799ac4a3067c75dfef8761d7aff");
  ASSERT_EQ(hex(claims.integrityDigest), "88c5451e87bbd080065576251cbd21af417fb2001e9494bd5c19d554d47c03bd");
  const auto canonical = ec_authorization_v2_detail::encodeClaims(claims);
  ASSERT_EQ(hex(canonical),
            "3346534543470002000200010102030405060708090a0b0c0d0e0f1001020304050607080000000000000009000a"
            "15161718191a1b1c1d1e1f2021222324292a2b2c2d2e2f30313233343536373801020304112233445566778810203040"
            "000100033250cd14838485868788898a8b8c8d8e8f9091929798999a9b9c9d9e9fa0a1a2a3a4a5a6"
            "88c5451e87bbd080065576251cbd21af417fb2001e9494bd5c19d554d47c03bd003f"
            "3d3e3f404142434445464748494a4b4c000003e85152535455565758595a5b5c5d5e5f60"
            "0102030405060708090a0b0c0d0e0f100265666768696a6b6c6d6e6f7071727374"
            "000000006553f100000000006553f22c000000");
  auto grant = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(grant);
  const auto wire = serde::serialize(*grant);
  ASSERT_EQ(wire.size(), 292u);
  ASSERT_EQ(hex(wire.substr(wire.size() - 32)), kGoldenMac);
  EcCapabilityV2 decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_EQ(serde::serialize(decoded), wire);
  for (auto right : {EcGrantRightV2::ReadBlock,
                     EcGrantRightV2::Begin,
                     EcGrantRightV2::Append,
                     EcGrantRightV2::Query,
                     EcGrantRightV2::Reconcile,
                     EcGrantRightV2::Seal}) {
    auto verified = verifyEcGrantV2(key, decoded, claims, right, kIssued + 299);
    ASSERT_OK(verified);
    ASSERT_EQ(verified->right(), right);
  }
}

TEST_F(TestEcAuthorizationV2, EverySignedFieldAndBothInstanceIdentitiesAreBound) {
  auto grant = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(grant);
  const std::vector<std::function<void(EcGrantClaimsV2 &)>> mutations{
      [](auto &c) { ++c.version; },
      [](auto &c) { c.engineUuid.data[0] ^= 1; },
      [](auto &c) { c.targetIncarnation.data[0] ^= 1; },
      [](auto &c) { ++c.identity.version; },
      [](auto &c) {
        c.identity.object.data[0] ^= 1;
        c.scopeObject = c.identity.object;
      },
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
      [](auto &c) { c.integrityDigest[0] ^= 1; },
      [](auto &c) { c.rights = 1; },
      [](auto &c) { c.grantId.data[0] ^= 1; },
      [](auto &c) { ++c.ownerUid; },
      [](auto &c) { c.clientNamespace.data[0] ^= 1; },
      [](auto &c) { c.scopeObject.data[0] ^= 1; },
      [](auto &c) {
        c.scopeKind = EcGrantScope::ReadPin;
        c.rights = 1;
      },
      [](auto &c) { c.scopeId.data[0] ^= 1; },
      [](auto &c) { ++c.issuedAtSeconds; },
      [](auto &c) { --c.expiresAtSeconds; },
  };
  for (size_t i = 0; i != mutations.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = *grant;
    mutations[i](changed.claims);
    ASSERT_FALSE(verifyEcGrantV2(key, changed, claims, EcGrantRightV2::ReadBlock, kIssued + 100));
  }
  const std::vector<std::function<void(EcGrantBindingV2 &)>> expectedMutations{
      [](auto &b) { b.engineUuid.data[0] ^= 1; },
      [](auto &b) { b.targetIncarnation.data[0] ^= 1; },
      [](auto &b) { b.identity.allocation.data[0] ^= 1; },
      [](auto &b) { b.fragmentOperationId = b.scopeId; },
      [](auto &b) { ++b.chainId; },
      [](auto &b) { ++b.targetId; },
      [](auto &b) { ++b.nodeId; },
      [](auto &b) { ++b.expectedLength; },
      [](auto &b) { b.expectedCrc32c ^= 1; },
      [](auto &b) { b.integrityDigest[31] ^= 1; },
      [](auto &b) { ++b.ownerUid; },
      [](auto &b) { b.clientNamespace.data[15] ^= 1; },
      [](auto &b) { b.scopeId.data[15] ^= 1; },
  };
  for (const auto &change : expectedMutations) {
    EcGrantBindingV2 expected = claims;
    change(expected);
    ASSERT_ERROR(verifyEcGrantV2(key, *grant, expected, EcGrantRightV2::ReadBlock, kIssued),
                 StatusCode::kAuthenticationFail);
  }
  auto wire = serde::serialize(*grant);
  wire.back() ^= 1;
  EcCapabilityV2 altered;
  ASSERT_OK(serde::deserialize(altered, wire));
  ASSERT_ERROR(verifyEcGrantV2(key, altered, claims, EcGrantRightV2::ReadBlock, kIssued),
               StatusCode::kAuthenticationFail);
  auto other = keyBytes();
  other[0] ^= 1;
  const EcCapabilityKey wrong(other);
  ASSERT_ERROR(verifyEcGrantV2(wrong, *grant, claims, EcGrantRightV2::ReadBlock, kIssued),
               StatusCode::kAuthenticationFail);
}

TEST_F(TestEcAuthorizationV2, ScopeAndSingleRightChecksNeverAuthorizeControlOrGc) {
  claims.scopeKind = EcGrantScope::ReadPin;
  claims.rights = 1;
  claims.ownerUid = flat::Uid(0);
  auto read = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(read);
  ASSERT_NE(claims.fragmentOperationId, claims.scopeId);
  ASSERT_OK(verifyEcGrantV2(key, *read, claims, EcGrantRightV2::ReadBlock, kIssued));
  for (auto right : {EcGrantRightV2::Begin,
                     EcGrantRightV2::Append,
                     EcGrantRightV2::Query,
                     EcGrantRightV2::Reconcile,
                     EcGrantRightV2::Seal}) {
    ASSERT_ERROR(verifyEcGrantV2(key, *read, claims, right, kIssued), StatusCode::kAuthenticationFail);
    auto invalid = claims;
    invalid.rights = static_cast<uint16_t>(right);
    ASSERT_ERROR(signEcGrantV2(key, invalid, kIssued), StatusCode::kInvalidArg);
  }
  for (uint16_t right : {uint16_t(0), uint16_t(3), uint16_t(64), uint16_t(0xffff)}) {
    ASSERT_ERROR(verifyEcGrantV2(key, *read, claims, static_cast<EcGrantRightV2>(right), kIssued),
                 StatusCode::kInvalidArg);
  }
  claims.scopeKind = EcGrantScope::WriteOperation;
  claims.rights = static_cast<uint16_t>(EcGrantRightV2::Query);
  auto query = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(query);
  ASSERT_OK(verifyEcGrantV2(key, *query, claims, EcGrantRightV2::Query, kIssued));
  ASSERT_ERROR(verifyEcGrantV2(key, *query, claims, EcGrantRightV2::Begin, kIssued), StatusCode::kAuthenticationFail);
  claims.rights = 64;
  ASSERT_ERROR(signEcGrantV2(key, claims, kIssued), StatusCode::kInvalidArg);
}

TEST_F(TestEcAuthorizationV2, LifetimesRejectExpirationFutureAndOverflowWithoutFallback) {
  claims.expiresAtSeconds = kIssued + 600;
  auto grant = signEcGrantV2(key, claims, kIssued, 600);
  ASSERT_OK(grant);
  ASSERT_OK(verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued + 599));
  ASSERT_ERROR(verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued - 1),
               StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued + 600),
               StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued, 599), StatusCode::kInvalidArg);
  ASSERT_ERROR(signEcGrantV2(key, claims, kIssued), StatusCode::kInvalidArg);
  for (uint64_t ttl : {uint64_t(0), uint64_t(3601)}) {
    ASSERT_ERROR(signEcGrantV2(key, claims, kIssued, ttl), StatusCode::kInvalidArg);
  }
  claims.issuedAtSeconds = std::numeric_limits<uint64_t>::max() - 1;
  claims.expiresAtSeconds = 1;
  ASSERT_ERROR(signEcGrantV2(key, claims, kIssued), StatusCode::kInvalidArg);
}

TEST_F(TestEcAuthorizationV2, SixActualRequestTypesBindLocalInstanceDescriptorAndBlockBytes) {
  auto grant = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(grant);
  EcReadBlockV2Req read;
  read.request = access;
  read.grant = *grant;
  ASSERT_OK(verifyEcRequestV2(key, read, local, kIssued));
  read.blockIndex = 1;
  ASSERT_OK(verifyEcRequestV2(key, read, local, kIssued));
  read.blockIndex = 2;
  ASSERT_ERROR(verifyEcRequestV2(key, read, local, kIssued), StatusCode::kInvalidArg);
  read.blockIndex = 0;
  auto wrongLocal = local;
  wrongLocal.engineUuid.data[0] ^= 1;
  ASSERT_ERROR(verifyEcRequestV2(key, read, wrongLocal, kIssued), StatusCode::kAuthenticationFail);
  wrongLocal = local;
  wrongLocal.targetIncarnation.data[0] ^= 1;
  ASSERT_ERROR(verifyEcRequestV2(key, read, wrongLocal, kIssued), StatusCode::kAuthenticationFail);
  wrongLocal = local;
  ++wrongLocal.vChainId.chainVer;
  ASSERT_ERROR(verifyEcRequestV2(key, read, wrongLocal, kIssued), StorageClientCode::kRoutingVersionMismatch);
  auto different = computeEcIntegrity(claims.identity, std::string(payload.size(), 'y'));
  ASSERT_OK(different);
  read.request.integrity = *different;  // Self-consistency is not Meta authority.
  ASSERT_ERROR(verifyEcRequestV2(key, read, local, kIssued), StatusCode::kAuthenticationFail);
  EcBeginStageV2Req begin;
  begin.request = access;
  begin.grant = *grant;
  ASSERT_OK(verifyEcRequestV2(key, begin, local, kIssued));
  EcQueryStageV2Req query;
  query.request = access;
  query.grant = *grant;
  ASSERT_OK(verifyEcRequestV2(key, query, local, kIssued));
  EcReconcileStageV2Req reconcile;
  reconcile.request = access;
  reconcile.grant = *grant;
  ASSERT_OK(verifyEcRequestV2(key, reconcile, local, kIssued));
  EcSealStageV2Req seal;
  seal.request = access;
  seal.grant = *grant;
  ASSERT_OK(verifyEcRequestV2(key, seal, local, kIssued));
  EcAppendStageV2Req append;
  append.request = access;
  append.grant = *grant;
  append.payload.data = payload.substr(0, kEcIntegrityBlockBytes);
  ASSERT_OK(verifyEcRequestV2(key, append, local, kIssued));
  append.payload.data[0] ^= 1;
  ASSERT_ERROR(verifyEcRequestV2(key, append, local, kIssued), StatusCode::kDataCorruption);
  append.blockIndex = 1;
  append.payload.data = payload.substr(kEcIntegrityBlockBytes);
  ASSERT_OK(verifyEcRequestV2(key, append, local, kIssued));
  append.payload.data.push_back('x');
  ASSERT_ERROR(verifyEcRequestV2(key, append, local, kIssued), StatusCode::kInvalidArg);
  append.blockIndex = std::numeric_limits<uint32_t>::max();
  ASSERT_ERROR(verifyEcRequestV2(key, append, local, kIssued), StatusCode::kInvalidArg);
}

TEST_F(TestEcAuthorizationV2, StableBeginMetadataExcludesRetryTagsAndActualRouteVersion) {
  static_assert(!std::is_default_constructible_v<VerifiedEcGrantV2>);
  static_assert(!serde::SerdeType<VerifiedEcGrantV2>);
  auto grant = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(grant);
  EcBeginStageV2Req begin;
  begin.request = access;
  begin.grant = *grant;
  auto first = verifyEcRequestV2(key, begin, local, kIssued);
  ASSERT_OK(first);
  auto spec = deriveEcStageSpecV2(*first);
  ASSERT_OK(spec);
  EXPECT_EQ(spec->stageId, claims.fragmentOperationId);
  EXPECT_EQ(spec->chainVersion, 0u);
  EXPECT_EQ(spec->lastRequestId, 0x292a2b2c2d2e2f30u);
  EXPECT_EQ(spec->lastClientLow, 0x5152535455565758u);
  EXPECT_EQ(spec->lastClientHigh, 0x595a5b5c5d5e5f60u);
  EXPECT_TRUE(std::equal(spec->etag.begin(), spec->etag.end(), claims.fragmentOperationId.data));
  auto retry = claims;
  retry.grantId = uuid(171);
  ++retry.issuedAtSeconds;
  ++retry.expiresAtSeconds;
  auto renewed = signEcGrantV2(key, retry, kIssued + 1);
  ASSERT_OK(renewed);
  begin.grant = *renewed;
  begin.request.tag = MessageTag(ClientId::random(), RequestId(12345));
  begin.request.userInfo.uid = flat::Uid(9999);  // Not an authentication input.
  ++begin.request.vChainId.chainVer;
  auto movedRoute = local;
  ++movedRoute.vChainId.chainVer;
  auto second = verifyEcRequestV2(key, begin, movedRoute, kIssued + 1);
  ASSERT_OK(second);
  auto stable = deriveEcStageSpecV2(*second);
  ASSERT_OK(stable);
  EXPECT_EQ(*stable, *spec);
  ASSERT_ERROR(verifyEcRequestV2(key, begin, local, kIssued + 1), StorageClientCode::kRoutingVersionMismatch);
  auto read = verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued);
  ASSERT_OK(read);
  ASSERT_ERROR(deriveEcStageSpecV2(*read), StatusCode::kInvalidArg);
}

TEST_F(TestEcAuthorizationV2, InvalidSchemaAndNoncanonicalIntegrityAreRejected) {
  const std::vector<std::function<void(EcGrantClaimsV2 &)>> invalid{
      [](auto &c) { c.engineUuid = Uuid::zero(); },
      [](auto &c) { c.targetIncarnation = Uuid::zero(); },
      [](auto &c) { c.identity.shard = 12; },
      [](auto &c) { c.integrityDigest = {}; },
      [](auto &c) { c.clientNamespace = Uuid::zero(); },
      [](auto &c) { c.scopeId = Uuid::zero(); },
      [](auto &c) { c.scopeObject = Uuid::zero(); },
      [](auto &c) { c.fragmentOperationId = Uuid::zero(); },
      [](auto &c) { c.chainId = ChainId{}; },
      [](auto &c) { c.targetId = TargetId{}; },
      [](auto &c) { c.nodeId = NodeId{}; },
      [](auto &c) { c.expectedLength = kEcFragmentRpcMaxBytes + 1; },
      [](auto &c) { c.rights = 0; },
      [](auto &c) { c.version = 1; },
  };
  for (const auto &change : invalid) {
    auto changed = claims;
    change(changed);
    ASSERT_ERROR(signEcGrantV2(key, changed, kIssued), StatusCode::kInvalidArg);
  }
  auto changed = integrity;
  changed.blocks[15].crc32c = 1;
  ASSERT_ERROR(digestEcIntegrityV2(claims.identity, changed), StatusCode::kInvalidArg);
  changed = integrity;
  changed.root[0] ^= 1;
  ASSERT_ERROR(digestEcIntegrityV2(claims.identity, changed), StatusCode::kDataCorruption);
  changed = integrity;
  changed.blocks[0].sha256[0] ^= 1;
  ASSERT_ERROR(digestEcIntegrityV2(claims.identity, changed), StatusCode::kDataCorruption);
}

TEST_F(TestEcAuthorizationV2, BinaryBoundsVersionSeparationAndTextNeverExposeBearerMac) {
  auto grant = signEcGrantV2(key, claims, kIssued);
  ASSERT_OK(grant);
  const auto canonical = ec_authorization_v2_detail::encodeClaims(claims);
  const std::string raw(reinterpret_cast<const char *>(canonical.data()), canonical.size());
  const auto wire = serde::serialize(*grant);
  EcCapabilityV2 decoded = *grant;
  for (uint64_t count : {uint64_t(0), uint64_t(1), uint64_t(3), std::numeric_limits<uint64_t>::max()}) {
    ASSERT_ERROR(serde::deserialize(decoded, serde::serialize(Varint64(count))), StatusCode::kInvalidFormat);
  }
  for (size_t length : {size_t(0), size_t(255), size_t(257), size_t(4096)}) {
    ASSERT_ERROR(serde::deserialize(decoded, frame(std::string(length, 'x'), std::string(32, 'y'))),
                 StatusCode::kInvalidFormat);
  }
  for (size_t length : {size_t(0), size_t(31), size_t(33), size_t(4096)}) {
    ASSERT_ERROR(serde::deserialize(decoded, frame(raw, std::string(length, 'y'))), StatusCode::kInvalidFormat);
  }
  auto reserved = raw;
  reserved.back() = 1;
  ASSERT_ERROR(serde::deserialize(decoded, frame(reserved, std::string(32, 'y'))), StatusCode::kInvalidFormat);
  ASSERT_EQ(serde::serialize(decoded), wire);
  EcCapability old;
  ASSERT_ERROR(serde::deserialize(old, wire), StatusCode::kInvalidFormat);
  EcGrantClaims v1;
  v1.identity = claims.identity;
  v1.fragmentOperationId = claims.fragmentOperationId;
  v1.chainId = claims.chainId;
  v1.targetId = claims.targetId;
  v1.nodeId = claims.nodeId;
  v1.expectedLength = claims.expectedLength;
  v1.expectedCrc32c = claims.expectedCrc32c;
  v1.ownerUid = claims.ownerUid;
  v1.clientUuid = claims.clientNamespace;
  v1.scopeObject = claims.scopeObject;
  v1.scopeKind = claims.scopeKind;
  v1.scopeId = claims.scopeId;
  v1.rights = 7;
  v1.grantId = claims.grantId;
  v1.issuedAtSeconds = claims.issuedAtSeconds;
  v1.expiresAtSeconds = claims.expiresAtSeconds;
  auto oldGrant = signEcGrant(key, v1, kIssued);
  ASSERT_OK(oldGrant);
  ASSERT_ERROR(serde::deserialize(decoded, serde::serialize(*oldGrant)), StatusCode::kInvalidFormat);
  Envelope envelope;
  envelope.token = *grant;
  const auto formatted = fmt::format("{}", *grant);
  const auto json = serde::toJsonString(envelope);
  const auto toml = serde::toTomlString(envelope);
  TextEnvelope jsonText, tomlText;
  ASSERT_OK(serde::fromJsonString(jsonText, json));
  ASSERT_OK(serde::fromTomlString(tomlText, toml));
  const auto expected = fmt::format("EcCapabilityV2(grant={}, signature=REDACTED)", claims.grantId);
  ASSERT_EQ(formatted, expected);
  ASSERT_EQ(jsonText.token, expected);
  ASSERT_EQ(tomlText.token, expected);
  for (const auto &text : {formatted, json, toml}) {
    ASSERT_EQ(text.find(kGoldenMac), std::string::npos);
    ASSERT_EQ(text.find(wire.substr(wire.size() - 32)), std::string::npos);
  }
  ASSERT_ERROR(serde::fromJsonString(envelope, json), StatusCode::kInvalidFormat);
  ASSERT_ERROR(serde::fromTomlString(envelope, toml), StatusCode::kInvalidFormat);
  EcSlicePayloadV2 decodedPayload;
  ASSERT_OK(serde::deserialize(decodedPayload, serde::serialize(std::string(kEcIntegrityBlockBytes, 'x'))));
  ASSERT_EQ(decodedPayload.data.size(), kEcIntegrityBlockBytes);
  ASSERT_ERROR(serde::deserialize(decodedPayload, serde::serialize(std::string(kEcIntegrityBlockBytes + 1, 'x'))),
               StatusCode::kInvalidArg);
  ASSERT_ERROR(serde::deserialize(decodedPayload, serde::serialize(Varint64(std::numeric_limits<uint64_t>::max()))),
               StatusCode::kSerdeInsufficientLength);
}

TEST_F(TestEcAuthorizationV2, ExistingStrictKeyLoaderSignsTheSameV2Token) {
  folly::test::TemporaryDirectory directory;
  const auto path = std::filesystem::path(directory.path().string()) / "v2.key";
  const auto bytes = keyBytes();
  std::ofstream output(path, std::ios::binary);
  output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  output.close();
  ASSERT_TRUE(output.good());
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  auto loaded = EcCapabilityKey::loadFile(path);
  ASSERT_OK(loaded);
  auto grant = signEcGrantV2(**loaded, claims, kIssued);
  ASSERT_OK(grant);
  ASSERT_OK(verifyEcGrantV2(key, *grant, claims, EcGrantRightV2::ReadBlock, kIssued));
  const auto wire = serde::serialize(*grant);
  ASSERT_EQ(hex(wire.substr(wire.size() - 32)), kGoldenMac);
  ASSERT_EQ(::chmod(path.c_str(), 0644), 0);
  ASSERT_ERROR(EcCapabilityKey::loadFile(path), StatusCode::kInvalidConfig);
}
}  // namespace
}  // namespace hf3fs::storage
