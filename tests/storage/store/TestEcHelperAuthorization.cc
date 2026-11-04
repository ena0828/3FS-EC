#include <fstream>
#include <sys/stat.h>
#include <type_traits>

#include "storage/ec_repair/EcHelperAuthorization.h"
#include "tests/EcRepairTestData.h"

namespace hf3fs::storage {
namespace {
Uuid bytesUuid(uint8_t first) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = first + i;
  return value;
}
Result<std::unique_ptr<EcHelperKey>> helperKey(const Path &directory, uint8_t offset = 0) {
  const auto path = directory / ("helper-" + std::to_string(offset) + ".key");
  std::array<uint8_t, 32> bytes;
  for (size_t i = 0; i != bytes.size(); ++i) bytes[i] = i + offset;
  std::ofstream out(path.string(), std::ios::binary);
  out.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  out.close();
  if (!out.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  return EcHelperKey::loadFile(std::filesystem::path(path.string()));
}
std::string hex(std::string_view bytes) {
  const char *digits = "0123456789abcdef";
  std::string out;
  for (uint8_t byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}
// Build real, separately signed data and helper credentials. A default V2
// capability is intentionally not a deserializable empty placeholder.
Result<EcHelperHopReq> signedHopRequest(const EcRepairPlanInput &input,
                                        const EcHelperKey &helper,
                                        const EcCapabilityKey &dataKey) {
  CHECK_RESULT(plan, EcRepairPlan::create(input));
  CHECK_RESULT(block, EcRepairBlockCore::begin(*plan, 0));
  EcHelperHopReq request;
  request.plan = input;
  request.packet = helperPacket(block);
  request.deadlineUnixMillis = 1001000;
  for (size_t i = 0; i != request.reads.size(); ++i) {
    const auto &source = input.sources[i];
    CHECK_RESULT(helperClaims, makeEcHelperClaims(*plan, i, 1, 1000, 30));
    CHECK_RESULT(helperGrant, signEcHelperGrant(helper, helperClaims, 1000));
    request.helpers[i] = std::move(helperGrant);
    EcGrantClaimsV2 claims;
    claims.identity = source.identity;
    claims.fragmentOperationId = source.operationId;
    claims.engineUuid = source.endpoint.engineUuid;
    claims.targetIncarnation = source.endpoint.targetIncarnation;
    claims.nodeId = source.endpoint.nodeId;
    claims.chainId = source.endpoint.chainId;
    claims.targetId = source.endpoint.targetId;
    claims.expectedLength = source.integrity.wholeLength;
    claims.expectedCrc32c = source.integrity.wholeCrc32c;
    CHECK_RESULT(integrity, digestEcIntegrityV2(source.identity, source.integrity));
    claims.integrityDigest = integrity;
    claims.ownerUid = input.ownerUid;
    claims.clientNamespace = input.clientNamespace;
    claims.scopeObject = source.identity.object;
    claims.scopeKind = EcGrantScope::WriteOperation;
    claims.scopeId = input.operationId;
    claims.rights = uint16_t(EcGrantRightV2::ReadBlock);
    claims.grantId = Uuid::random();
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = 1030;
    CHECK_RESULT(read, signEcGrantV2(dataKey, claims, 1000));
    request.reads[i] = std::move(read);
    request.routeVersions[i] = ChainVer(1);
  }
  return request;
}

static_assert(!std::is_constructible_v<EcHelperKey, const EcCapabilityKey &>);
static_assert(!std::is_copy_constructible_v<EcHelperKey>);

TEST(TestEcHelperAuthorization, IndependentHelperDomainHmacGolden) {
  folly::test::TemporaryDirectory directory;
  auto key = helperKey(directory.path());
  ASSERT_OK(key);
  EcHelperClaims claims;
  claims.rights = 3;
  for (size_t i = 0; i != 32; ++i) claims.planDigest[i] = i;
  claims.recipient = {NodeId(11), ChainId(22), TargetId(33), bytesUuid(1), bytesUuid(21)};
  claims.helperPosition = 2;
  claims.blockMask = 3;
  claims.grantId = bytesUuid(41);
  claims.issuedAtSeconds = 1000;
  claims.expiresAtSeconds = 1030;
  auto grant = signEcHelperGrant(**key, claims, 1000);
  ASSERT_OK(grant);
  auto wire = serde::serialize(*grant);
  // Python struct.pack big-endian canonical claims (127 bytes), hashlib/hmac;
  // the production encoder is not used to produce this expected value.
  EXPECT_EQ(hex(std::string_view(wire).substr(wire.size() - 32)),
            "509ebd44dcd37e339065032597b84ee20eea8ba9435013593833d76070edfaad");
  EcHelperCapability decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  EXPECT_EQ(serde::serialize(decoded), wire);
}

TEST(TestEcHelperAuthorization, BindsRightsHopInstanceBlockAndPlan) {
  folly::test::TemporaryDirectory directory;
  auto key = helperKey(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto claims = makeEcHelperClaims(**plan, 0, 1, 1000, 30);
  ASSERT_OK(claims);
  auto grant = signEcHelperGrant(**key, *claims, 1000);
  ASSERT_OK(grant);
  const auto endpoint = data.input.sources[0].endpoint;
  ASSERT_OK(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 0, 0, 1001));
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 1, 0, 1001));
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 0, 1, 1001));
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 0, 0, 1030));
  auto replaced = endpoint;
  replaced.targetIncarnation = Uuid::random();
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **plan, replaced, 0, 0, 1001));
  claims->rights = uint16_t(EcHelperRight::Compute);
  auto computeOnly = signEcHelperGrant(**key, *claims, 1000);
  ASSERT_OK(computeOnly);
  EXPECT_FALSE(verifyEcHelperGrant(**key, *computeOnly, **plan, endpoint, 0, 0, 1001));
  auto changed = data.input;
  changed.ownerUid = flat::Uid(2000);
  auto other = EcRepairPlan::create(changed);
  ASSERT_OK(other);
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **other, endpoint, 0, 0, 1001));
}

TEST(TestEcHelperAuthorization, TamperedCapabilityAndWrongRoleKeyDoNotAuthenticate) {
  folly::test::TemporaryDirectory directory;
  auto key = helperKey(directory.path());
  auto wrongKey = helperKey(directory.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(wrongKey);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto claims = makeEcHelperClaims(**plan, 9, 1, 1000, 30);
  ASSERT_OK(claims);
  auto grant = signEcHelperGrant(**key, *claims, 1000);
  ASSERT_OK(grant);
  const auto endpoint = data.input.sources[9].endpoint;
  ASSERT_OK(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 9, 0, 1000));
  EXPECT_FALSE(verifyEcHelperGrant(**wrongKey, *grant, **plan, endpoint, 9, 0, 1000));
  auto wire = serde::serialize(*grant);
  wire.back() ^= 1;
  EcHelperCapability changed;
  ASSERT_OK(serde::deserialize(changed, wire));
  EXPECT_FALSE(verifyEcHelperGrant(**key, changed, **plan, endpoint, 9, 0, 1000));
  grant->claims.planDigest[0] ^= 1;
  EXPECT_FALSE(verifyEcHelperGrant(**key, *grant, **plan, endpoint, 9, 0, 1000));
}

TEST(TestEcHelperAuthorization, PredecessorMacBindsPacketAndExactContributionPrefix) {
  folly::test::TemporaryDirectory directory;
  auto key = helperKey(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto block = EcRepairBlockCore::begin(**plan, 0);
  ASSERT_OK(block);
  auto zero = helperPacket(*block);
  ASSERT_OK(verifyEcHelperPredecessor(**key, **plan, zero, {}, 0, 1000));
  block =
      EcRepairBlockCore::advance(**plan, 0, std::move(*block), repair_test::blockBytes(data, data.input.sources[0], 0));
  ASSERT_OK(block);
  auto packet = helperPacket(*block);
  auto stamp = ec_helper_detail::stamp(**key, **plan, packet, 1000, 1030);
  ASSERT_OK(stamp);
  ASSERT_OK(verifyEcHelperPredecessor(**key, **plan, packet, *stamp, 1, 1001));
  auto wire = serde::serialize(*stamp);
  wire.back() ^= 1;
  EcHelperStamp changed;
  ASSERT_OK(serde::deserialize(changed, wire));
  EXPECT_FALSE(verifyEcHelperPredecessor(**key, **plan, packet, changed, 1, 1001));
  packet.outputs[0].data[0] ^= 1;
  EXPECT_FALSE(verifyEcHelperPredecessor(**key, **plan, packet, *stamp, 1, 1001));
  packet = helperPacket(*block);
  packet.contributorMask = 3;
  EXPECT_FALSE(verifyEcHelperPredecessor(**key, **plan, packet, *stamp, 1, 1001));
  EXPECT_FALSE(verifyEcHelperPredecessor(**key, **plan, zero, *stamp, 0, 1001));
}

TEST(TestEcHelperAuthorization, FinalStampRequiresCompleteVerifiedTargets) {
  folly::test::TemporaryDirectory directory;
  auto key = helperKey(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto block = EcRepairBlockCore::begin(**plan, 0);
  ASSERT_OK(block);
  for (uint8_t i = 0; i != 10; ++i) {
    block = EcRepairBlockCore::advance(**plan,
                                       i,
                                       std::move(*block),
                                       repair_test::blockBytes(data, data.input.sources[i], 0));
    ASSERT_OK(block);
  }
  EcHelperHopResult result;
  result.packet = helperPacket(*block);
  auto stamp = ec_helper_detail::stamp(**key, **plan, result.packet, 1000, 1030);
  ASSERT_OK(stamp);
  result.finalStamp = *stamp;
  ASSERT_OK(verifyEcHelperFinal(**key, **plan, result, 1001));
  result.packet.outputs[1].data[0] ^= 1;
  EXPECT_FALSE(verifyEcHelperFinal(**key, **plan, result, 1001));
}

TEST(TestEcHelperAuthorization, BoundedSerdeRejectsWrongArraysAndOversizeBeforeOwnedCopy) {
  std::array<EcHelperCapability, 10> grants;
  auto wire = serde::serialize(grants);
  auto malformed = serde::serialize(Varint64(11)) + wire.substr(1);
  EXPECT_FALSE(serde::deserialize(grants, malformed));
  EcHelperPacket packet;
  packet.outputs[0].data.resize(kEcIntegrityBlockBytes + 1);
  wire = serde::serialize(packet);
  EcHelperPacket decoded;
  EXPECT_FALSE(serde::deserialize(decoded, wire));
  folly::test::TemporaryDirectory directory;
  auto helper = helperKey(directory.path());
  ASSERT_OK(helper);
  std::array<uint8_t, 32> secret{};
  secret.fill(43);
  EcCapabilityKey dataKey(secret);
  for (const auto &missing : {std::vector<uint16_t>{0}, std::vector<uint16_t>{0, 11}}) {
    auto data = repair_test::makeData(31, missing);
    auto request = signedHopRequest(data.input, **helper, dataKey);
    ASSERT_OK(request);
    wire = serde::serialize(*request);
    EcHelperHopReq restored;
    ASSERT_OK(serde::deserialize(restored, wire));
    EXPECT_EQ(serde::serialize(restored), wire);
    EXPECT_LT(wire.size(), 32u << 10);  // Fixed metadata/grants and two tiny accumulators.
    auto decodedPlan = EcRepairPlan::create(restored.plan);
    ASSERT_OK(decodedPlan);
    auto originalPlan = EcRepairPlan::create(data.input);
    ASSERT_OK(originalPlan);
    EXPECT_EQ((*decodedPlan)->digest(), (*originalPlan)->digest());
    if (missing.size() == 1) {
      // The unused fixed target slot remains its canonical default record.
      // Unlike a V2 capability, a fragment placeholder has no standalone rights.
      EXPECT_EQ(serde::serialize(restored.plan.targets[1]), serde::serialize(EcRepairFragment{}));
    }
    for (size_t i = 0; i != restored.reads.size(); ++i) {
      ASSERT_OK(verifyEcGrantV2(dataKey, restored.reads[i], request->reads[i].claims, EcGrantRightV2::ReadBlock, 1000));
      ASSERT_OK(verifyEcHelperGrant(**helper,
                                    restored.helpers[i],
                                    **decodedPlan,
                                    restored.plan.sources[i].endpoint,
                                    i,
                                    0,
                                    1000));
    }
  }
}

TEST(TestEcHelperAuthorization, EmptyReadCapabilityCannotDecodeAsAnAuthorizedHelperRequest) {
  EcCapabilityV2 empty;
  EcCapabilityV2 decoded;
  EXPECT_FALSE(serde::deserialize(decoded, serde::serialize(empty)));
  folly::test::TemporaryDirectory directory;
  auto helper = helperKey(directory.path());
  ASSERT_OK(helper);
  std::array<uint8_t, 32> secret{};
  secret.fill(47);
  EcCapabilityKey dataKey(secret);
  auto data = repair_test::makeData(31, {0});
  auto request = signedHopRequest(data.input, **helper, dataKey);
  ASSERT_OK(request);
  for (size_t i = 0; i != request->reads.size(); ++i) {
    auto changed = *request;
    changed.reads[i] = {};
    EcHelperHopReq restored;
    EXPECT_FALSE(serde::deserialize(restored, serde::serialize(changed))) << i;
  }
}

}  // namespace
}  // namespace hf3fs::storage
