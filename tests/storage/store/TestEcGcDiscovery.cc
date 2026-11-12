#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <fstream>
#include <functional>
#include <future>
#include <span>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <thread>
#include <vector>

#include "fbs/storage/EcGcDiscovery.h"
#include "storage/ec_gc/EcGcExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
using namespace std::chrono_literals;
using Codec = ec_gc_discovery_detail::Codec;
constexpr uint64_t issued = 1700000000;
constexpr std::string_view requestGolden =
    "33465347445130320002101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0102030405060708"
    "0102030405060708303132333435363738393a3b3c3d3e3f000000006553f100000000006553f11ee4a7436b78b01a48e6f4"
    "983cac0833709c94621354df936b78e37dcee479efff";
constexpr std::string_view observationGolden =
    "334653474452303200023dbe8513cedbfaaeb37debf69c9fe8f5247c946ee5ef39f5d466ecacc72ada0d1011121314151617"
    "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0102030405060708010203040506070840414243444546474849"
    "4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0002000300010003606162636465666768696a6b6c6d6e6f00000000"
    "6553f103ef9332b2db8f852f83ba19f2cb5af7ee4742d5d90dc87029bc7b2d5071975b03";
Uuid uuid(uint8_t first) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = first + i;
  return value;
}
std::string hex(std::span<const uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}
std::string unhex(std::string_view value) {
  const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  std::string result;
  for (size_t i = 0; i != value.size(); i += 2) result.push_back((digit(value[i]) << 4) | digit(value[i + 1]));
  return result;
}
EcGcDiscoveryClaims claims() {
  EcGcDiscoveryClaims value;
  value.keyId = uuid(0x10);
  value.authority = uuid(0x20);
  value.nodeId = NodeId{0x01020304};
  value.chainId = ChainId{0x05060708};
  value.targetId = TargetId{0x0102030405060708};
  value.nonce = uuid(0x30);
  value.issuedAtSeconds = issued;
  value.expiresAtSeconds = issued + 30;
  return value;
}
Result<std::unique_ptr<EcGcKey>> testKey(const Path &directory, uint8_t offset = 0) {
  const auto path = directory / ("g-" + std::to_string(offset) + ".key");
  std::array<uint8_t, 32> secret{};
  for (size_t i = 0; i != secret.size(); ++i) secret[i] = i + 1 + offset;
  std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(secret.data()), secret.size());
  output.close();
  if (!output.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  return EcGcKey::loadFile(std::filesystem::path(path.string()), claims().keyId, {});
}
Result<EcGcDiscoveryObservation> goldenObservation() {
  const auto frame = unhex(observationGolden);
  EcSha256 signature{};
  std::copy(frame.end() - 32, frame.end(), signature.begin());
  const auto wire = serde::serialize(Varint64(2)) +
                    serde::serialize(std::string_view(frame.data(), kEcGcDiscoveryObservationBytes)) +
                    serde::serialize(signature);
  EcGcDiscoveryObservation result;
  RETURN_ON_ERROR(serde::deserialize(result, wire));
  return result;
}

TEST(TestEcGcDiscovery, IndependentCanonicalMacAndBinaryRoundtrip) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = signEcGcDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  // Independently generated with Python struct.pack BE + hashlib/hmac. Domain
  // bytes are included; frame(body+MAC) is not the complete Serde/RPC message.
  EXPECT_EQ(hex(Codec::frame(*request)), requestGolden);
  EXPECT_EQ(Codec::encode(request->claims).size(), 90);
  auto observed = goldenObservation();
  ASSERT_OK(observed);
  EXPECT_EQ(hex(Codec::frame(*observed)), observationGolden);
  EXPECT_EQ(Codec::encode(observed->claims).size(), 154);
  ASSERT_OK(verifyEcGcDiscoveryObservation(**key, *observed, *request, issued + 3));
  EcGcDiscoveryRequest decodedRequest;
  EcGcDiscoveryObservation decodedObservation;
  ASSERT_OK(serde::deserialize(decodedRequest, serde::serialize(*request)));
  ASSERT_OK(serde::deserialize(decodedObservation, serde::serialize(*observed)));
  EXPECT_EQ(Codec::frame(decodedRequest), Codec::frame(*request));
  EXPECT_EQ(Codec::frame(decodedObservation), Codec::frame(*observed));
  EXPECT_EQ(fmt::format("{}", *request), "EcGcDiscoveryRequest(REDACTED)");
  EXPECT_EQ(fmt::format("{}", *observed), "EcGcDiscoveryObservation(REDACTED)");
}

TEST(TestEcGcDiscovery, EveryCanonicalFieldAndExactRequestAreAuthenticated) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = signEcGcDiscovery(**key, claims(), issued);
  auto observation = goldenObservation();
  ASSERT_OK(request);
  ASSERT_OK(observation);
  const std::vector<std::function<void(EcGcDiscoveryClaims &)>> requestChanges{
      [](auto &v) { ++v.version; },
      [](auto &v) { v.keyId.data[0] ^= 1; },
      [](auto &v) { v.authority.data[0] ^= 1; },
      [](auto &v) { ++v.nodeId; },
      [](auto &v) { ++v.chainId; },
      [](auto &v) { ++v.targetId; },
      [](auto &v) { v.nonce.data[0] ^= 1; },
      [](auto &v) { ++v.issuedAtSeconds; },
      [](auto &v) { --v.expiresAtSeconds; }};
  for (const auto &change : requestChanges) {
    auto changed = *request;
    change(changed.claims);
    EXPECT_FALSE(verifyEcGcDiscovery(**key, changed, claims().authority, claims().nodeId, issued + 3));
  }
  const std::vector<std::function<void(EcGcDiscoveryObservationClaims &)>> observationChanges{
      [](auto &v) { ++v.version; },
      [](auto &v) { v.requestDigest[0] ^= 1; },
      [](auto &v) { v.keyId.data[0] ^= 1; },
      [](auto &v) { v.authority.data[0] ^= 1; },
      [](auto &v) { ++v.endpoint.nodeId; },
      [](auto &v) { ++v.endpoint.chainId; },
      [](auto &v) { ++v.endpoint.targetId; },
      [](auto &v) { v.endpoint.engineUuid.data[0] ^= 1; },
      [](auto &v) { v.endpoint.targetIncarnation.data[0] ^= 1; },
      [](auto &v) { ++v.dataProtocol; },
      [](auto &v) { --v.diskFormat; },
      [](auto &v) { ++v.gcProtocol; },
      [](auto &v) { v.capabilities = 2; },
      [](auto &v) { v.bootNonce.data[0] ^= 1; },
      [](auto &v) { --v.observedAtSeconds; }};
  for (const auto &change : observationChanges) {
    auto changed = *observation;
    change(changed.claims);
    EXPECT_FALSE(verifyEcGcDiscoveryObservation(**key, changed, *request, issued + 3));
  }
  auto next = claims();
  next.nonce = Uuid::random();
  auto other = signEcGcDiscovery(**key, next, issued);
  ASSERT_OK(other);
  EXPECT_FALSE(verifyEcGcDiscoveryObservation(**key, *observation, *other, issued + 3));
}

TEST(TestEcGcDiscovery, FixedSchemaWrongKeyClockAndCountsFailClosed) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  auto wrong = testKey(directory.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(wrong);
  auto request = signEcGcDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  EXPECT_FALSE(verifyEcGcDiscovery(**wrong, *request, claims().authority, claims().nodeId, issued));
  EXPECT_FALSE(verifyEcGcDiscovery(**key, *request, uuid(0x21), claims().nodeId, issued));
  for (auto now : {issued - 1, issued + 30})
    EXPECT_FALSE(verifyEcGcDiscovery(**key, *request, claims().authority, claims().nodeId, now));
  auto intent = claims();
  intent.expiresAtSeconds = issued + 61;
  EXPECT_FALSE(signEcGcDiscovery(**key, intent, issued));
  auto body = unhex(requestGolden).substr(0, 90);
  EXPECT_FALSE(Codec::decodeRequest(body.substr(0, 89)));
  EXPECT_FALSE(Codec::decodeRequest(body + "x"));
  body.replace(0, 8, "3FSECDQ1");
  EXPECT_FALSE(Codec::decodeRequest(body));  // No schema1/domain fallback.
  EcGcDiscoveryRequest output;
  const auto text = serde::toJsonString(*request);
  EXPECT_NE(text.find("REDACTED"), std::string::npos);
  EXPECT_FALSE(serde::fromJsonString(output, text));
  EXPECT_FALSE(serde::deserialize(output, serde::serialize(Varint64(UINT64_MAX))));
  EXPECT_FALSE(serde::deserialize(output, serde::serialize(Varint64(3))));
  const auto badBody = serde::serialize(Varint64(2)) + serde::serialize(std::string_view("small"));
  EXPECT_FALSE(serde::deserialize(output, badBody));
}

class TestEcGcDiscoveryRuntime : public ::testing::Test {
 protected:
  virtual bool exactGc() const { return true; }
  void SetUp() override {
    struct statfs fs {};
    ASSERT_EQ(::statfs(directory.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, 0xef53) << "real Engine test requires ext4 TMPDIR";
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_cur, 8192u);
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    config.set_ec_exact_gc(exactGc());
    targets = std::make_unique<StorageTargets>(config, map);
    ASSERT_OK(targets->load(loader));
    CreateTargetReq create;
    create.chainId = claims().chainId;
    create.targetId = claims().targetId;
    create.onlyChunkEngine = true;
    ASSERT_OK(targets->create(create, true));
    auto found = map.getByTargetId(create.targetId);
    ASSERT_OK(found);
    target = (*found)->storageTarget;
    ASSERT_OK(target->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
    auto loaded = testKey(keys.path());
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcGcKey>(std::move(*loaded));
    auto started = EcGcExecutor::create(
        key,
        claims().authority,
        claims().nodeId,
        [this] { return now.load(); },
        [this] { return readOnly.load(); });
    ASSERT_OK(started);
    executor = std::move(*started);
  }
  void TearDown() override {
    if (executor) EXPECT_TRUE(executor->stopAndJoin());
    executor.reset();
    target.reset();
    map.release().reset();
    targets.reset();
  }
  Result<EcGcDiscoveryObservation> observe(const EcGcDiscoveryRequest &request) {
    return executor->observeCapabilities(request, target, [this]() -> Result<Void> {
      auto current = map.getByTargetId(claims().targetId);
      if (!current || (*current)->storageTarget != target) return makeError(StorageCode::kTargetStateInvalid);
      return Void{};
    });
  }
  folly::test::TemporaryDirectory directory, keys;
  CPUExecutorGroup loader{1, "GcDiscoveryTest"};
  StorageTargets::Config config;
  AtomicallyTargetMap map;
  std::unique_ptr<StorageTargets> targets;
  std::shared_ptr<StorageTarget> target;
  std::shared_ptr<const EcGcKey> key;
  std::unique_ptr<EcGcExecutor> executor;
  std::atomic<uint64_t> now{issued + 3};
  std::atomic<bool> readOnly{false};
};

TEST_F(TestEcGcDiscoveryRuntime, ActualFormatInstanceAndLiveReadOnlyPolicyAreObserved) {
  auto request = signEcGcDiscovery(*key, claims(), issued);
  ASSERT_OK(request);
  auto observed = observe(*request);
  ASSERT_OK(observed);
  ASSERT_OK(verifyEcGcDiscoveryObservation(*key, *observed, *request, now));
  auto state = target->ecScopeState();
  ASSERT_OK(state);
  EXPECT_TRUE(
      std::equal(state->second.engine.begin(), state->second.engine.end(), observed->claims.endpoint.engineUuid.data));
  EXPECT_TRUE(std::equal(state->second.incarnation.begin(),
                         state->second.incarnation.end(),
                         observed->claims.endpoint.targetIncarnation.data));
  EXPECT_EQ(observed->claims.diskFormat, 3);
  EXPECT_EQ(observed->claims.dataProtocol, 2);
  EXPECT_EQ(observed->claims.gcProtocol, kEcGcSupportedProtocol);
  EXPECT_EQ(observed->claims.capabilities, kEcGcDiscoveryCollectQuery);
  readOnly.store(true);
  auto queryOnly = observe(*request);
  ASSERT_OK(queryOnly);
  EXPECT_EQ(queryOnly->claims.capabilities, kEcGcDiscoveryQueryOnly);
  EXPECT_EQ(queryOnly->claims.bootNonce, observed->claims.bootNonce);
  ASSERT_OK(verifyEcGcDiscoveryObservation(*key, *queryOnly, *request, now));
  EXPECT_EQ(executor->activeRequests(), 0);
}

TEST_F(TestEcGcDiscoveryRuntime, MapFencePolicyChangeAndExpirySuppressObservation) {
  auto request = signEcGcDiscovery(*key, claims(), issued);
  ASSERT_OK(request);
  unsigned calls = 0;
  auto replaced = executor->observeCapabilities(*request, target, [&]() -> Result<Void> {
    if (++calls == 2) return makeError(StorageCode::kTargetStateInvalid);
    return Void{};
  });
  ASSERT_ERROR(replaced, StorageCode::kTargetStateInvalid);
  calls = 0;
  auto changed = executor->observeCapabilities(*request, target, [&]() -> Result<Void> {
    if (++calls == 2) readOnly.store(true);
    return Void{};
  });
  ASSERT_ERROR(changed, StorageClientCode::kResourceBusy);
  calls = 0;
  auto expired = executor->observeCapabilities(*request, target, [&]() -> Result<Void> {
    if (++calls == 2) now.store(issued + 30);
    return Void{};
  });
  ASSERT_ERROR(expired, StatusCode::kAuthenticationFail);
  EXPECT_EQ(executor->activeRequests(), 0);
}

TEST_F(TestEcGcDiscoveryRuntime, CloseWaitsForOwnedObservationAndPreventsSuccessfulLateReply) {
  auto request = signEcGcDiscovery(*key, claims(), issued);
  ASSERT_OK(request);
  std::promise<void> entered, release;
  auto enteredFuture = entered.get_future();
  auto released = release.get_future().share();
  std::atomic<bool> first{true};
  auto caller = std::async(std::launch::async, [&] {
    return executor->observeCapabilities(*request, target, [&]() -> Result<Void> {
      if (first.exchange(false)) {
        entered.set_value();
        released.wait();
      }
      return Void{};
    });
  });
  bool unblocked = false;
  SCOPE_EXIT {
    if (!unblocked) release.set_value();
  };
  ASSERT_EQ(enteredFuture.wait_for(5s), std::future_status::ready);
  auto stopping = std::async(std::launch::async, [&] { return executor->stopAndJoin(); });
  SCOPE_EXIT {
    if (!unblocked) {
      release.set_value();
      unblocked = true;
    }
  };
  // Observe the actual close gate, not an assumed scheduling delay.
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (executor->validateDiscoveryRequest(*request) && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_ERROR(executor->validateDiscoveryRequest(*request), StorageClientCode::kResourceBusy);
  EXPECT_EQ(stopping.wait_for(20ms), std::future_status::timeout);
  release.set_value();
  unblocked = true;
  ASSERT_ERROR(caller.get(), StorageClientCode::kResourceBusy);
  ASSERT_OK(stopping.get());
  ASSERT_ERROR(observe(*request), StorageClientCode::kResourceBusy);
  EXPECT_EQ(executor->activeRequests(), 0);
}

class TestEcGcDiscoveryFormat2 : public TestEcGcDiscoveryRuntime {
 protected:
  bool exactGc() const override { return false; }
};
TEST_F(TestEcGcDiscoveryFormat2, ExistingDataProtocol2DoesNotProveGcCapability) {
  auto request = signEcGcDiscovery(*key, claims(), issued);
  ASSERT_OK(request);
  ASSERT_ERROR(observe(*request), StorageCode::kTargetStateInvalid);
}
}  // namespace
}  // namespace hf3fs::storage
