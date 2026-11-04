#include <algorithm>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <functional>
#include <sys/stat.h>
#include <type_traits>

#include "fbs/storage/EcScopeControl.h"
#include "storage/ec_scope/EcScopeControlExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
constexpr uint64_t issued = 1700000000;
Uuid uuid(uint8_t first) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = first + i;
  return value;
}
Uuid uuid(const std::array<uint8_t, 16> &bytes) {
  Uuid value;
  std::copy(bytes.begin(), bytes.end(), std::begin(value.data));
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
EcScopeControlClaims claims() {
  EcScopeControlClaims value;
  value.clusterAuthority = uuid(1);
  value.nodeId = NodeId(0x10203040);
  value.chainId = ChainId(0x01020304);
  value.targetId = TargetId(0x1122334455667788);
  value.engineUuid = uuid(21);
  value.targetIncarnation = uuid(41);
  value.object = uuid(61);
  value.scopeId = uuid(81);
  value.ownerUid = flat::Uid(1000);
  value.clientNamespace = uuid(101);
  for (size_t i = 0; i != 32; ++i) value.endpointSetDigest[i] = i;
  value.revocationId = uuid(121);
  value.nonce = uuid(141);
  value.issuedAtSeconds = issued;
  value.expiresAtSeconds = issued + 60;
  return value;
}
Result<std::unique_ptr<EcScopeControlKey>> testKey(const Path &directory, uint8_t offset = 0) {
  const auto path = directory / ("control-" + std::to_string(offset) + ".key");
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i != key.size(); ++i) key[i] = i + offset;
  std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(key.data()), key.size());
  output.close();
  if (!output.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  return EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
}
static_assert(!std::is_constructible_v<EcScopeControlKey, const EcCapabilityKey &>);
static_assert(!std::is_copy_constructible_v<EcScopeControlKey>);

TEST(TestEcScopeControl, IndependentCanonicalAndHmacGolden) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = signEcScopeControl(**key, claims(), issued);
  ASSERT_OK(request);
  // Independently assembled with Python struct.pack('>...') and hashlib/hmac,
  // not generated through the production encoder under test.
  const std::string expected =
      "33465345435251310001010102030405060708090a0b0c0d0e0f10"
      "1020304001020304112233445566778815161718191a1b1c1d1e1f2021222324"
      "292a2b2c2d2e2f3031323334353637383d3e3f404142434445464748494a4b4c"
      "015152535455565758595a5b5c5d5e5f60000003e865666768696a6b6c6d6e6f7071727374"
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "797a7b7c7d7e7f8081828384858687888d8e8f909192939495969798999a9b9c"
      "000000006553f100000000006553f13c";
  auto canonical = ec_scope_control_detail::Codec::encode(request->claims);
  ASSERT_EQ(canonical.size(), 208);
  EXPECT_EQ(hex(canonical), expected);
  auto wire = serde::serialize(*request);
  EXPECT_EQ(hex({reinterpret_cast<const uint8_t *>(wire.data() + wire.size() - 32), 32}),
            "b8b2512125cfda9bab064bf75abb6e7930f792813e0d00062fe022c0a8c10f63");
  EcScopeControlRequest decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  EXPECT_EQ(serde::serialize(decoded), wire);
  ASSERT_OK(verifyEcScopeControl(**key,
                                 decoded,
                                 claims().clusterAuthority,
                                 claims().nodeId,
                                 EcScopeControlAction::Revoke,
                                 issued + 1));
}

TEST(TestEcScopeControl, EveryRequestFieldIsAuthenticatedAndActionsAreSeparated) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = signEcScopeControl(**key, claims(), issued);
  ASSERT_OK(request);
  const std::vector<std::function<void(EcScopeControlClaims &)>> changes{
      [](auto &c) { ++c.version; },
      [](auto &c) { c.action = EcScopeControlAction::Query; },
      [](auto &c) { c.clusterAuthority.data[0] ^= 1; },
      [](auto &c) { ++c.nodeId; },
      [](auto &c) { ++c.chainId; },
      [](auto &c) { ++c.targetId; },
      [](auto &c) { c.engineUuid.data[0] ^= 1; },
      [](auto &c) { c.targetIncarnation.data[0] ^= 1; },
      [](auto &c) { c.object.data[0] ^= 1; },
      [](auto &c) { c.scopeKind = EcGrantScope::WriteOperation; },
      [](auto &c) { c.scopeId.data[0] ^= 1; },
      [](auto &c) { ++c.ownerUid; },
      [](auto &c) { c.clientNamespace.data[0] ^= 1; },
      [](auto &c) { c.endpointSetDigest[0] ^= 1; },
      [](auto &c) { c.revocationId.data[0] ^= 1; },
      [](auto &c) { c.nonce.data[0] ^= 1; },
      [](auto &c) { ++c.issuedAtSeconds; },
      [](auto &c) { --c.expiresAtSeconds; }};
  for (size_t i = 0; i != changes.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = *request;
    changes[i](changed.claims);
    ASSERT_FALSE(verifyEcScopeControl(**key,
                                      changed,
                                      claims().clusterAuthority,
                                      claims().nodeId,
                                      EcScopeControlAction::Revoke,
                                      issued + 1));
  }
  ASSERT_ERROR(verifyEcScopeControl(**key,
                                    *request,
                                    claims().clusterAuthority,
                                    claims().nodeId,
                                    EcScopeControlAction::Query,
                                    issued),
               StatusCode::kTokenMismatch);
  ASSERT_ERROR(verifyEcScopeControl(**key, *request, uuid(2), claims().nodeId, EcScopeControlAction::Revoke, issued),
               StatusCode::kTokenMismatch);
  ASSERT_ERROR(
      verifyEcScopeControl(**key, *request, claims().clusterAuthority, NodeId(1), EcScopeControlAction::Revoke, issued),
      StatusCode::kTokenMismatch);
}

TEST(TestEcScopeControl, ExpiryWrongKeyAndMalformedFramesFailClosed) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  auto other = testKey(directory.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(other);
  auto request = signEcScopeControl(**key, claims(), issued);
  ASSERT_OK(request);
  for (auto now : {issued - 1, issued + 60}) {
    ASSERT_ERROR(verifyEcScopeControl(**key,
                                      *request,
                                      claims().clusterAuthority,
                                      claims().nodeId,
                                      EcScopeControlAction::Revoke,
                                      now),
                 StatusCode::kAuthenticationFail);
  }
  ASSERT_ERROR(verifyEcScopeControl(**other,
                                    *request,
                                    claims().clusterAuthority,
                                    claims().nodeId,
                                    EcScopeControlAction::Revoke,
                                    issued),
               StatusCode::kAuthenticationFail);
  auto tooLong = claims();
  tooLong.expiresAtSeconds = issued + 301;
  ASSERT_FALSE(signEcScopeControl(**key, tooLong, issued));
  auto bytes = ec_scope_control_detail::Codec::encode(claims());
  std::string text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  ASSERT_FALSE(ec_scope_control_detail::Codec::decodeRequest(text.substr(1)));
  text[0] ^= 1;
  ASSERT_FALSE(ec_scope_control_detail::Codec::decodeRequest(text));
  auto wire = serde::serialize(*request);
  wire.back() ^= 1;
  EcScopeControlRequest decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_ERROR(verifyEcScopeControl(**key,
                                    decoded,
                                    claims().clusterAuthority,
                                    claims().nodeId,
                                    EcScopeControlAction::Revoke,
                                    issued),
               StatusCode::kAuthenticationFail);
  const auto malformed = serde::serialize(Varint64(3)) + wire.substr(1);
  ASSERT_FALSE(serde::deserialize(decoded, malformed));
}

TEST(TestEcScopeControl, EndpointSetCanonicalOrderDeduplicatesOnlyExactInstances) {
  const auto c = claims();
  EcScopeEndpoint endpoint{c.nodeId, c.chainId, c.targetId, c.engineUuid, c.targetIncarnation};
  auto single = computeEcScopeEndpointDigest(std::span(&endpoint, 1));
  ASSERT_OK(single);
  EXPECT_EQ(hex(*single), "8bdb6b1f96b8e3b51143d832ec4a7edfdbce34fd78c1180ebf8acfafd78e52db");
  std::array endpoints{endpoint, endpoint};
  ASSERT_RESULT_EQ(*single, computeEcScopeEndpointDigest(endpoints));
  endpoints[1].targetIncarnation.data[0] ^= 1;
  auto both = computeEcScopeEndpointDigest(endpoints);
  ASSERT_OK(both);
  EXPECT_NE(*both, *single);
  std::swap(endpoints[0], endpoints[1]);
  ASSERT_RESULT_EQ(*both, computeEcScopeEndpointDigest(endpoints));
  ASSERT_FALSE(computeEcScopeEndpointDigest({}));
  std::array<EcScopeEndpoint, 25> many{};
  many.fill(endpoint);
  ASSERT_FALSE(computeEcScopeEndpointDigest(many));
  endpoint.engineUuid = Uuid::zero();
  ASSERT_FALSE(computeEcScopeEndpointDigest(std::span(&endpoint, 1)));
}

TEST(TestEcScopeControl, ContradictoryAckStateCannotDecodeAsDrained) {
  EcScopeControlAckClaims value;
  value.requestDigest.fill(1);
  value.revocationDigest.fill(2);
  value.bootNonce = uuid(1);
  value.state = EcScopeControlState::Drained;
  value.durable = false;
  value.inflight = 0;
  auto encoded = ec_scope_control_detail::Codec::encode(value);
  auto decode = [&](const auto &bytes) {
    return ec_scope_control_detail::Codec::decodeAck({reinterpret_cast<const char *>(bytes.data()), bytes.size()});
  };
  ASSERT_FALSE(decode(encoded));
  value.durable = true;
  value.inflight = 1;
  ASSERT_FALSE(decode(ec_scope_control_detail::Codec::encode(value)));
  value.inflight = 0;
  ASSERT_OK(decode(ec_scope_control_detail::Codec::encode(value)));
  encoded = ec_scope_control_detail::Codec::encode(value);
  encoded[91] = 2;
  ASSERT_FALSE(decode(encoded));
}

class TestEcScopeControlExecutor : public ::testing::Test {
 protected:
  void SetUp() override {
    auto loaded = testKey(keys.path());
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    targets = std::make_unique<StorageTargets>(config, map);
    ASSERT_OK(targets->load(cpu));
    CreateTargetReq create;
    create.chainId = ChainId(91);
    create.targetId = TargetId(92);
    create.onlyChunkEngine = true;
    ASSERT_OK(targets->create(create, true));
    auto found = map.getByTargetId(create.targetId);
    ASSERT_OK(found);
    target = (*found)->storageTarget;
    ASSERT_TRUE(target->usesEcStagingEngine());
    auto state = target->ecScopeState();
    ASSERT_OK(state);
    scope = state->first;
    original = claims();
    original.chainId = create.chainId;
    original.targetId = create.targetId;
    original.engineUuid = uuid(state->second.engine);
    original.targetIncarnation = uuid(state->second.incarnation);
    EcScopeEndpoint endpoint{original.nodeId,
                             original.chainId,
                             original.targetId,
                             original.engineUuid,
                             original.targetIncarnation};
    auto endpoints = computeEcScopeEndpointDigest(std::span(&endpoint, 1));
    ASSERT_OK(endpoints);
    original.endpointSetDigest = *endpoints;
    binding.target = state->second;
    std::copy(std::begin(original.object.data), std::end(original.object.data), binding.object.begin());
    binding.kind = static_cast<uint8_t>(original.scopeKind);
    std::copy(std::begin(original.scopeId.data), std::end(original.scopeId.data), binding.scope.begin());
    binding.owner_uid = original.ownerUid.toUnderType();
    std::copy(std::begin(original.clientNamespace.data),
              std::end(original.clientNamespace.data),
              binding.client_namespace.begin());
    auto created =
        EcScopeControlExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
    ASSERT_OK(created);
    control = std::move(*created);
  }
  void TearDown() override {
    control.reset();
    scope.reset();
    target.reset();
    map.release().reset();
    targets.reset();
    key.reset();
  }
  Result<EcScopeControlAck> execute(const EcScopeControlRequest &request, EcScopeControlAction action) {
    return folly::coro::blockingWait(control->execute(action, request, target));
  }
  folly::test::TemporaryDirectory directory;
  folly::test::TemporaryDirectory keys;
  CPUExecutorGroup cpu{1, "EcControlTest"};
  StorageTargets::Config config;
  AtomicallyTargetMap map;
  std::unique_ptr<StorageTargets> targets;
  std::shared_ptr<StorageTarget> target;
  std::shared_ptr<EcScope> scope;
  std::shared_ptr<const EcScopeControlKey> key;
  std::unique_ptr<EcScopeControlExecutor> control;
  EcScopeControlClaims original;
  EcScopeBinding binding{};
};

TEST_F(TestEcScopeControlExecutor, RealDurableDenySignsPendingThenExactDrainedAck) {
  auto revoke = signEcScopeControl(*key, original, issued);
  ASSERT_OK(revoke);
  ASSERT_OK(scope->prepare(binding));
  {
    auto ticket = scope->tryAdmit(binding);
    ASSERT_OK(ticket);
    auto pending = execute(*revoke, EcScopeControlAction::Revoke);
    ASSERT_OK(pending);
    ASSERT_OK(verifyEcScopeControlAck(*key, *pending, *revoke));
    EXPECT_EQ(pending->claims.state, EcScopeControlState::Pending);
    EXPECT_TRUE(pending->claims.durable);
    EXPECT_EQ(pending->claims.inflight, 1);
    ASSERT_ERROR(ticket->checkExecution(), StatusCode::kTokenStale);
  }
  auto queryClaims = original;
  queryClaims.action = EcScopeControlAction::Query;
  queryClaims.nonce.data[0] ^= 1;
  auto query = signEcScopeControl(*key, queryClaims, issued);
  ASSERT_OK(query);
  auto drained = execute(*query, EcScopeControlAction::Query);
  ASSERT_OK(drained);
  ASSERT_OK(verifyEcScopeControlAck(*key, *drained, *query));
  EXPECT_EQ(drained->claims.state, EcScopeControlState::Drained);
  EXPECT_TRUE(drained->claims.durable);
  EXPECT_EQ(drained->claims.inflight, 0);
  ASSERT_FALSE(verifyEcScopeControlAck(*key, *drained, *revoke));
  auto tampered = *drained;
  tampered.claims.bootNonce.data[0] ^= 1;
  ASSERT_FALSE(verifyEcScopeControlAck(*key, tampered, *query));
  EcScopeControlAck decoded;
  auto wire = serde::serialize(*drained);
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_OK(verifyEcScopeControlAck(*key, decoded, *query));
}

TEST_F(TestEcScopeControlExecutor, MissingDenyAndWrongInstanceNeverProduceAck) {
  auto query = original;
  query.action = EcScopeControlAction::Query;
  auto signedQuery = signEcScopeControl(*key, query, issued);
  ASSERT_OK(signedQuery);
  ASSERT_FALSE(execute(*signedQuery, EcScopeControlAction::Query));
  auto wrong = original;
  wrong.engineUuid.data[0] ^= 1;
  auto signedWrong = signEcScopeControl(*key, wrong, issued);
  ASSERT_OK(signedWrong);
  ASSERT_ERROR(execute(*signedWrong, EcScopeControlAction::Revoke), StatusCode::kTokenMismatch);
  auto request = signEcScopeControl(*key, original, issued);
  ASSERT_OK(request);
  ASSERT_ERROR(execute(*request, EcScopeControlAction::Query), StatusCode::kTokenMismatch);
}

TEST_F(TestEcScopeControlExecutor, DifferentRevocationCannotReplaceExistingFence) {
  auto request = signEcScopeControl(*key, original, issued);
  ASSERT_OK(request);
  auto ack = execute(*request, EcScopeControlAction::Revoke);
  ASSERT_OK(ack);
  auto changed = original;
  changed.revocationId.data[0] ^= 1;
  auto second = signEcScopeControl(*key, changed, issued);
  ASSERT_OK(second);
  ASSERT_ERROR(execute(*second, EcScopeControlAction::Revoke), StatusCode::kTokenMismatch);
  changed = original;
  changed.endpointSetDigest[0] ^= 1;
  second = signEcScopeControl(*key, changed, issued);
  ASSERT_OK(second);
  ASSERT_ERROR(execute(*second, EcScopeControlAction::Revoke), StatusCode::kTokenMismatch);
}

TEST(TestEcScopeControl, ColdReopenQueryConfirmsSamePersistentDeny) {
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  CPUExecutorGroup cpu(1, "EcControlReopen");
  auto original = claims();
  original.chainId = ChainId(91);
  original.targetId = TargetId(92);
  Uuid priorBoot = Uuid::zero();
  for (unsigned reopen = 0; reopen != 2; ++reopen) {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(cpu));
    if (reopen == 0) {
      CreateTargetReq request;
      request.chainId = original.chainId;
      request.targetId = original.targetId;
      request.onlyChunkEngine = true;
      ASSERT_OK(targets.create(request, true));
    }
    auto target = map.getByTargetId(original.targetId);
    ASSERT_OK(target);
    auto state = (*target)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    if (reopen == 0) {
      original.engineUuid = uuid(state->second.engine);
      original.targetIncarnation = uuid(state->second.incarnation);
    } else {
      EXPECT_EQ(original.engineUuid, uuid(state->second.engine));
      EXPECT_EQ(original.targetIncarnation, uuid(state->second.incarnation));
      original.action = EcScopeControlAction::Query;
      original.nonce.data[0] ^= 1;
    }
    auto control =
        EcScopeControlExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
    ASSERT_OK(control);
    auto request = signEcScopeControl(*key, original, issued);
    ASSERT_OK(request);
    auto result = folly::coro::blockingWait((*control)->execute(original.action, *request, (*target)->storageTarget));
    ASSERT_OK(result);
    ASSERT_OK(verifyEcScopeControlAck(*key, *result, *request));
    EXPECT_EQ(result->claims.state, EcScopeControlState::Drained);
    if (reopen) EXPECT_NE(result->claims.bootNonce, priorBoot);
    priorBoot = result->claims.bootNonce;
    control->reset();
    // No ticket or scope handle crosses the physical close/reopen boundary.
  }
}

TEST(TestEcScopeControl, LegacyTargetCannotIssueDrainedEvenIfLocalScopeWasInitialized) {
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup cpu(1, "EcControlLegacy");
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(cpu));
  CreateTargetReq create;
  create.chainId = ChainId(91);
  create.targetId = TargetId(92);
  create.onlyChunkEngine = true;
  ASSERT_OK(targets.create(create, true));
  auto target = map.getByTargetId(create.targetId);
  ASSERT_OK(target);
  ASSERT_OK((*target)->storageTarget->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
  auto state = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(state);
  auto original = claims();
  original.chainId = create.chainId;
  original.targetId = create.targetId;
  original.engineUuid = uuid(state->second.engine);
  original.targetIncarnation = uuid(state->second.incarnation);
  auto request = signEcScopeControl(*key, original, issued);
  ASSERT_OK(request);
  auto control =
      EcScopeControlExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
  ASSERT_OK(control);
  ASSERT_ERROR(folly::coro::blockingWait((*control)->execute(original.action, *request, (*target)->storageTarget)),
               StorageCode::kTargetStateInvalid);
}
}  // namespace
}  // namespace hf3fs::storage
