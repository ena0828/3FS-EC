#include <fstream>
#include <openssl/hmac.h>
#include <sys/stat.h>

#include "storage/ec_repair/EcHelperDirectAuthorization.h"
#include "tests/EcRepairTestData.h"

namespace hf3fs::storage {
namespace {
Result<std::unique_ptr<EcHelperKey>> keyFile(const Path &directory, uint8_t byte = 37) {
  auto path = directory / ("direct-" + std::to_string(byte) + ".key");
  std::array<uint8_t, 32> secret;
  secret.fill(byte);
  std::ofstream out(path.string(), std::ios::binary);
  out.write(reinterpret_cast<const char *>(secret.data()), secret.size());
  out.close();
  if (!out.good() || ::chmod(path.c_str(), 0600)) return makeError(StatusCode::kIOError);
  return EcHelperKey::loadFile(std::filesystem::path(path.string()));
}
Result<EcCapabilityV2> dataGrant(const EcRepairPlanInput &plan,
                                const EcRepairFragment &fragment,
                                EcGrantRightV2 right,
                                const EcCapabilityKey &key) {
  EcGrantClaimsV2 c;
  c.identity = fragment.identity;
  c.fragmentOperationId = fragment.operationId;
  c.engineUuid = fragment.endpoint.engineUuid;
  c.targetIncarnation = fragment.endpoint.targetIncarnation;
  c.nodeId = fragment.endpoint.nodeId;
  c.chainId = fragment.endpoint.chainId;
  c.targetId = fragment.endpoint.targetId;
  c.expectedLength = fragment.integrity.wholeLength;
  c.expectedCrc32c = fragment.integrity.wholeCrc32c;
  CHECK_RESULT(digest, digestEcIntegrityV2(fragment.identity, fragment.integrity));
  c.integrityDigest = digest;
  c.ownerUid = plan.ownerUid;
  c.clientNamespace = plan.clientNamespace;
  c.scopeObject = fragment.identity.object;
  c.scopeKind = EcGrantScope::WriteOperation;
  c.scopeId = plan.operationId;
  c.rights = uint16_t(right);
  c.grantId = Uuid::random();
  c.issuedAtSeconds = 1000;
  c.expiresAtSeconds = 1030;
  return signEcGrantV2(key, c, 1000);
}
Result<EcHelperDirectHopReq> request(const repair_test::Data &data, const EcHelperKey &helper) {
  CHECK_RESULT(plan, EcRepairPlan::create(data.input));
  std::array<uint8_t, 32> secret;
  secret.fill(61);
  EcCapabilityKey key(secret);
  std::array<EcCapabilityV2, 2> append, query;
  for (size_t i = 0; i != data.input.targetCount; ++i) {
    CHECK_RESULT(a, dataGrant(data.input, data.input.targets[i], EcGrantRightV2::Append, key));
    CHECK_RESULT(q, dataGrant(data.input, data.input.targets[i], EcGrantRightV2::Query, key));
    append[i] = std::move(a);
    query[i] = std::move(q);
  }
  const auto mask = uint16_t((uint32_t{1} << plan->blockCount()) - 1);
  CHECK_RESULT(delegation, issueEcHelperDirectDelegation(helper, *plan, append, query, mask, 1000, 30));
  EcHelperDirectHopReq r;
  r.plan = data.input;
  r.delegation = std::move(delegation);
  r.activeTargetMask = uint8_t((1u << data.input.targetCount) - 1);
  r.deadlineUnixMillis = 1029000;
  CHECK_RESULT(seed, EcRepairBlockCore::begin(*plan, 0));
  r.packet = helperPacket(std::move(seed));
  for (size_t i = 0; i != 10; ++i) {
    CHECK_RESULT(c, makeEcHelperClaims(*plan, i, mask, 1000, 30));
    CHECK_RESULT(h, signEcHelperGrant(helper, c, 1000));
    CHECK_RESULT(read, dataGrant(data.input, data.input.sources[i], EcGrantRightV2::ReadBlock, key));
    r.helpers[i] = std::move(h);
    r.reads[i] = std::move(read);
    r.sourceRouteVersions[i] = ChainVer(1);
  }
  for (size_t i = 0; i != data.input.targetCount; ++i) r.targetRouteVersions[i] = ChainVer(1);
  return r;
}
Result<EcHelperPacket> advance(const repair_test::Data &data, const EcRepairPlan &plan,
                               const EcHelperDirectHopReq &r) {
  CHECK_RESULT(computed, EcRepairBlockCore::advance(
                            plan, r.packet.nextHelper, repairBlock(r.packet),
                            repair_test::blockBytes(data, data.input.sources[r.packet.nextHelper], r.packet.blockIndex)));
  return helperPacket(std::move(computed));
}
Result<EcHelperDirectHopReq> lastHop(const repair_test::Data &data, const EcHelperKey &key,
                                    EcHelperDirectHopReq r) {
  CHECK_RESULT(plan, EcRepairPlan::create(data.input));
  while (r.packet.nextHelper != 9) {
    CHECK_RESULT(computed, advance(data, *plan, r));
    CHECK_RESULT(stamp, ec_helper_direct_detail::stamp(key, *plan, r, computed, 1001));
    r.packet = std::move(computed);
    r.predecessor = std::move(stamp);
  }
  return r;
}
std::array<EcStageStateV2, 2> states(const EcHelperDirectHopReq &r) {
  std::array<EcStageStateV2, 2> result;
  for (size_t i = 0; i != r.plan.targetCount; ++i) {
    if (!(r.activeTargetMask & (1u << i))) continue;
    result[i].receipt = repair_test::receipt(r.plan.targets[i]);
    result[i].receipt.vChainId.chainVer = r.targetRouteVersions[i];
    result[i].state = 1;
    result[i].prefixBytes = r.plan.targets[i].integrity.wholeLength;
    result[i].revision = 7;
    result[i].needsReconcile = false;
  }
  return result;
}

TEST(TestEcHelperDirectAuthorization, SingleAndDoubleDelegationRoundtripPreservesUnusedSlots) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  ASSERT_OK(key);
  for (auto missing : {std::vector<uint16_t>{0}, std::vector<uint16_t>{0, 11}}) {
    auto data = repair_test::makeData(31, missing, 4);
    auto r = request(data, **key);
    ASSERT_OK(r);
    auto plan = EcRepairPlan::create(data.input);
    ASSERT_OK(plan);
    ASSERT_OK(validateEcHelperDirectRequest(**plan, *r));
    ASSERT_OK(verifyEcHelperDirectPredecessor(**key, **plan, *r, 1001));
    auto wire = serde::serialize(*r);
    EcHelperDirectHopReq decoded;
    ASSERT_OK(serde::deserialize(decoded, wire));
    EXPECT_EQ(serde::serialize(decoded), wire);
    ASSERT_OK(verifyEcHelperDirectPredecessor(**key, **plan, decoded, 1001));
    if (missing.size() == 1) {
      EXPECT_EQ(serde::serialize(decoded.delegation.appendGrants[1]), serde::serialize(EcCapabilityV2{}));
      EXPECT_EQ(serde::serialize(decoded.delegation.queryGrants[1]), serde::serialize(EcCapabilityV2{}));
      auto bad = decoded;
      bad.delegation.appendGrants[1] = bad.delegation.appendGrants[0];
      EXPECT_FALSE(validateEcHelperDirectRequest(**plan, bad));
    }
    // The old V2 decoder must still reject a default unauthenticated token.
    EcCapabilityV2 invalid;
    EXPECT_FALSE(serde::deserialize(invalid, serde::serialize(EcCapabilityV2{})));
  }
}

TEST(TestEcHelperDirectAuthorization, IndependentDomainMacExactRightsAndLifetime) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  auto wrong = keyFile(directory.path(), 38);
  ASSERT_OK(key);
  ASSERT_OK(wrong);
  auto data = repair_test::makeData(31);
  auto r = request(data, **key);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(r);
  ASSERT_OK(plan);
  const auto &c = r->delegation.directGrant.claims;
  // Independent HMAC input construction: never calls the production canonical
  // encoder or private-key helper. Random identifiers are observed, not fixed.
  std::string canonical = "3FSECDG1";
  auto number = [&](uint64_t n, size_t width) {
    for (size_t i = width; i != 0; --i) canonical.push_back(char(n >> ((i - 1) * 8)));
  };
  number(1, 2);
  for (const auto &h : {c.planDigest, c.delegationDigest})
    canonical.append(reinterpret_cast<const char *>(h.data()), h.size());
  number(c.lastHelper.nodeId.toUnderType(), 4);
  number(c.lastHelper.chainId.toUnderType(), 4);
  number(c.lastHelper.targetId.toUnderType(), 8);
  canonical.append(c.lastHelper.engineUuid.asStringView());
  canonical.append(c.lastHelper.targetIncarnation.asStringView());
  number(c.targetCount, 1);
  number(c.maxBlocksInFlight, 1);
  number(c.blockMask, 2);
  canonical.append(c.grantId.asStringView());
  number(c.issuedAtSeconds, 8);
  number(c.expiresAtSeconds, 8);
  ASSERT_EQ(canonical.size(), 158);
  std::array<uint8_t, 32> secret, expected;
  secret.fill(37);
  unsigned int size = 0;
  ASSERT_NE(HMAC(EVP_sha256(), secret.data(), secret.size(),
                 reinterpret_cast<const uint8_t *>(canonical.data()), canonical.size(), expected.data(), &size),
            nullptr);
  ASSERT_EQ(size, expected.size());
  auto wire = serde::serialize(r->delegation.directGrant);
  EXPECT_EQ(wire.substr(wire.size() - 32),
            std::string(reinterpret_cast<const char *>(expected.data()), expected.size()));
  EXPECT_FALSE(verifyEcHelperDirectDelegation(**wrong, **plan, r->delegation, 0, 1001));
  EXPECT_FALSE(verifyEcHelperDirectDelegation(**key, **plan, r->delegation, 0, 1030));
  EXPECT_FALSE(verifyEcHelperDirectDelegation(**key, **plan, r->delegation, 0, 999));
  auto broad = r->delegation.appendGrants;
  broad[0].claims.rights |= uint16_t(EcGrantRightV2::Seal);
  EXPECT_FALSE(issueEcHelperDirectDelegation(**key, **plan, broad, r->delegation.queryGrants, 1, 1000, 30));
  EXPECT_FALSE(issueEcHelperDirectDelegation(**key, **plan, r->delegation.queryGrants,
                                            r->delegation.appendGrants, 1, 1000, 30));
  EXPECT_FALSE(issueEcHelperDirectDelegation(**key, **plan, r->delegation.appendGrants,
                                            r->delegation.queryGrants, 2, 1000, 30));
  EXPECT_FALSE(issueEcHelperDirectDelegation(**key, **plan, r->delegation.appendGrants,
                                            r->delegation.queryGrants, 1, UINT64_MAX, 30));
  wire.back() ^= 1;
  ASSERT_OK(serde::deserialize(r->delegation.directGrant, wire));
  ASSERT_OK(validateEcHelperDirectDelegation(**plan, r->delegation, 0));  // Explicitly not MAC authentication.
  EXPECT_FALSE(verifyEcHelperDirectDelegation(**key, **plan, r->delegation, 0, 1001));
}

TEST(TestEcHelperDirectAuthorization, ContextBindsRoutesMaskDeadlineAndEveryCredential) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31);
  auto r = request(data, **key);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(r);
  ASSERT_OK(plan);
  auto context = digestEcHelperDirectContext(**plan, *r);
  auto computed = advance(data, **plan, *r);
  ASSERT_OK(context);
  ASSERT_OK(computed);
  auto stamp = ec_helper_direct_detail::stamp(**key, **plan, *r, *computed, 1001);
  ASSERT_OK(stamp);
  r->packet = *computed;
  r->predecessor = *stamp;
  ASSERT_OK(verifyEcHelperDirectPredecessor(**key, **plan, *r, 1001));
  auto advancedContext = digestEcHelperDirectContext(**plan, *r);
  ASSERT_OK(advancedContext);
  EXPECT_EQ(*advancedContext, *context);
  auto bad = *r;
  bad.targetRouteVersions[0] = ChainVer(2);
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001));
  bad = *r;
  bad.sourceRouteVersions[8] = ChainVer(2);
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001));
  bad = *r;
  bad.activeTargetMask = 1;
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001));
  bad = *r;
  ++bad.deadlineUnixMillis;
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001));
  for (size_t i = 0; i != 10; ++i) {
    bad = *r;
    bad.helpers[i].claims.grantId = Uuid::random();
    EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001)) << i;
    bad = *r;
    bad.reads[i].claims.grantId = Uuid::random();
    EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001)) << i;
  }
  bad = *r;
  bad.packet.outputs[0].data[0] ^= 1;
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, bad, 1001));
}

TEST(TestEcHelperDirectAuthorization, SmallResultAllowsAdvancedPrefixButRejectsUnknownAndTampering) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 31);
  auto initial = request(data, **key);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(initial);
  ASSERT_OK(plan);
  auto r = lastHop(data, **key, *initial);
  ASSERT_OK(r);
  auto complete = advance(data, **plan, *r);
  ASSERT_OK(complete);
  auto observed = states(*r);
  auto final = ec_helper_direct_detail::finish(**key, **plan, *r, *complete, observed, 1001);
  ASSERT_OK(final);
  ASSERT_GT(final->states[0].prefixBytes, kEcIntegrityBlockBytes);  // A later block may already be complete.
  ASSERT_OK(verifyEcHelperDirectResult(**key, **plan, *initial, *final, 1001));
  ASSERT_OK(verifyEcHelperDirectResult(**key, **plan, *r, *final, 1001));
  const auto wire = serde::serialize(*final);
  EXPECT_LE(wire.size(), kEcHelperDirectResultMaxBytes);
  EXPECT_LT(wire.size(), kEcIntegrityBlockBytes);
  EcHelperDirectHopResult decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  EXPECT_EQ(serde::serialize(decoded), wire);
  ASSERT_OK(verifyEcHelperDirectResult(**key, **plan, *r, decoded, 1001));
  for (size_t i = 0; i != 2; ++i) {
    auto bad = observed;
    bad[i].needsReconcile = true;
    EXPECT_FALSE(ec_helper_direct_detail::finish(**key, **plan, *r, *complete, bad, 1001));
    bad = observed;
    bad[i].prefixBytes = 0;
    bad[i].pendingBlock = true;
    EXPECT_FALSE(ec_helper_direct_detail::finish(**key, **plan, *r, *complete, bad, 1001));
    bad = observed;
    bad[i].state = 2;
    EXPECT_FALSE(ec_helper_direct_detail::finish(**key, **plan, *r, *complete, bad, 1001));
  }
  auto bad = *final;
  bad.appendedTargetMask = 1;
  EXPECT_FALSE(validateEcHelperDirectResult(**plan, *r, bad));
  bad = *final;
  bad.states[1].receipt.engineUuid = Uuid::random();
  EXPECT_FALSE(validateEcHelperDirectResult(**plan, *r, bad));
  auto stampWire = serde::serialize(final->finalStamp);
  stampWire.back() ^= 1;
  ASSERT_OK(serde::deserialize(bad.finalStamp, stampWire));
  bad.states = final->states;
  ASSERT_OK(validateEcHelperDirectResult(**plan, *r, bad));
  EXPECT_FALSE(verifyEcHelperDirectResult(**key, **plan, *r, bad, 1001));
  EXPECT_FALSE(verifyEcHelperDirectResult(**key, **plan, *r, *final, 1030));
}

TEST(TestEcHelperDirectAuthorization, ActiveSubsetAndPredecessorCannotBecomeFinalProof) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31);
  auto initial = request(data, **key);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(initial);
  ASSERT_OK(plan);
  initial->activeTargetMask = 2;  // Client already reconciled/sealed target zero; no append assertion for it.
  auto r = lastHop(data, **key, *initial);
  ASSERT_OK(r);
  auto complete = advance(data, **plan, *r);
  ASSERT_OK(complete);
  auto final = ec_helper_direct_detail::finish(**key, **plan, *r, *complete, states(*r), 1001);
  ASSERT_OK(final);
  EXPECT_EQ(serde::serialize(final->states[0]), serde::serialize(EcStageStateV2{}));
  ASSERT_OK(verifyEcHelperDirectResult(**key, **plan, *initial, *final, 1001));
  auto bad = *final;
  bad.states[0] = bad.states[1];
  EXPECT_FALSE(validateEcHelperDirectResult(**plan, *initial, bad));
  bad = *final;
  bad.finalStamp = r->predecessor;
  EXPECT_FALSE(verifyEcHelperDirectResult(**key, **plan, *initial, bad, 1001));
  EcHelperStamp old;
  EXPECT_FALSE(serde::deserialize(old, serde::serialize(final->finalStamp)));
  auto seed = request(data, **key);
  ASSERT_OK(seed);
  seed->predecessor = r->predecessor;
  EXPECT_FALSE(verifyEcHelperDirectPredecessor(**key, **plan, *seed, 1001));
  seed->predecessor = {};
  seed->activeTargetMask = 0;
  EXPECT_FALSE(validateEcHelperDirectRequest(**plan, *seed));
  seed->activeTargetMask = 4;
  EXPECT_FALSE(validateEcHelperDirectRequest(**plan, *seed));
}

TEST(TestEcHelperDirectAuthorization, BoundedWireRejectsArrayCountsOversizeAndEmptyActiveAuthority) {
  folly::test::TemporaryDirectory directory;
  auto key = keyFile(directory.path());
  ASSERT_OK(key);
  auto data = repair_test::makeData(31, {0});
  auto r = request(data, **key);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(r);
  ASSERT_OK(plan);
  auto wire = serde::serialize(*r);
  EcHelperDirectHopReq decoded;
  auto wrongCount = serde::serialize(Varint64(12)) + wire.substr(1);
  EXPECT_FALSE(serde::deserialize(decoded, wrongCount));
  std::array<ChainVer, 2> routes;
  wire = serde::serialize(routes);
  wrongCount = serde::serialize(Varint64(3)) + wire.substr(1);
  EXPECT_FALSE(serde::deserialize(routes, wrongCount));
  auto oversized = *r;
  oversized.packet.outputs[0].data.resize(kEcIntegrityBlockBytes + 1);
  EXPECT_FALSE(serde::deserialize(decoded, serde::serialize(oversized)));
  auto missing = *r;
  missing.delegation.appendGrants[0] = {};
  ASSERT_OK(serde::deserialize(decoded, serde::serialize(missing)));  // Absent syntax is not authority.
  EXPECT_FALSE(validateEcHelperDirectRequest(**plan, decoded));
  missing = *r;
  missing.reads[0] = {};
  EXPECT_FALSE(serde::deserialize(decoded, serde::serialize(missing)));  // Old read grant rules unchanged.
}
}  // namespace
}  // namespace hf3fs::storage
