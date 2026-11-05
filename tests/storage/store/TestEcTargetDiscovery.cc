#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <functional>
#include <future>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>
#include <type_traits>

#include "fbs/storage/EcTargetDiscovery.h"
#include "storage/ec_scope/EcTargetDiscoveryExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
class EcDiscoveryExecutorTestAccess {
 public:
  static CoTryTask<EcTargetDiscoveryObservation> execute(EcTargetDiscoveryExecutor &executor,
                                                         EcTargetDiscoveryRequest request,
                                                         std::shared_ptr<StorageTarget> target,
                                                         void (*beforeAwait)()) {
    return executor.executeImpl(std::move(request), std::move(target), beforeAwait);
  }
};
namespace {
constexpr uint64_t issued = 1700000000;
Uuid uuid(uint8_t first) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = first + i;
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
EcTargetDiscoveryClaims claims() {
  EcTargetDiscoveryClaims v;
  v.clusterAuthority = uuid(1);
  v.nodeId = NodeId(0x10203040);
  v.chainId = ChainId(0x01020304);
  v.targetId = TargetId(0x1122334455667788);
  v.nonce = uuid(141);
  v.issuedAtSeconds = issued;
  v.expiresAtSeconds = issued + 60;
  return v;
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

std::string unhex(std::string_view value) {
  const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  std::string result;
  for (size_t i = 0; i < value.size(); i += 2) result.push_back((digit(value[i]) << 4) | digit(value[i + 1]));
  return result;
}
TEST(TestEcTargetDiscovery, IndependentRequestAndObservationCanonicalMacGolden) {
  folly::test::TemporaryDirectory dir;
  auto key = testKey(dir.path());
  ASSERT_OK(key);
  auto request = signEcTargetDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  const auto canonical = ec_target_discovery_detail::Codec::encode(request->claims);
  // Python struct.pack with explicit BE widths + hashlib/hmac, independent of Codec.
  EXPECT_EQ(hex(canonical),
            "334653454344513100010102030405060708090a0b0c0d0e0f10102030400102030411223344556677888d8e8f9091929394959697"
            "98999a9b9c000000006553f100000000006553f13c");
  const auto wire = serde::serialize(*request);
  EXPECT_EQ(hex({reinterpret_cast<const uint8_t *>(wire.data() + wire.size() - 32), 32}),
            "01c576bbb5e7f569ba7ab476afa308b3a8fca9fb20f0f96b04793c6434d56d73");
  const auto observationBytes = unhex(
      "33465345434452310001d13adb88afc08c5cd7e5127160c19946d1f7a8ecf0fc105044abd7b94291053e1020304001020304112233445566"
      "778815161718191a1b1c1d1e1f2021222324292a2b2c2d2e2f3031323334353637380002000000006553f101");
  const auto mac = unhex("304c2ed195ebee7016862da9f3e75f8fedc72b4f5129fa4a7cc555d395139150");
  EcSha256 signature{};
  std::copy(mac.begin(), mac.end(), signature.begin());
  const auto observedWire = serde::serialize(Varint64(2)) + serde::serialize(std::string_view(observationBytes)) +
                            serde::serialize(signature);
  EcTargetDiscoveryObservation observed;
  ASSERT_OK(serde::deserialize(observed, observedWire));
  EXPECT_EQ(hex(ec_target_discovery_detail::Codec::encode(observed.claims)),
            "33465345434452310001d13adb88afc08c5cd7e5127160c19946d1f7a8ecf0fc105044abd7b94291053e1020304001020304112233"
            "445566778815161718191a1b1c1d1e1f2021222324292a2b2c2d2e2f3031323334353637380002000000006553f101");
  ASSERT_OK(verifyEcTargetDiscoveryObservation(**key, observed, *request, issued + 1));
  auto different = *request;
  different.claims.nonce.data[0] ^= 1;
  ASSERT_FALSE(verifyEcTargetDiscoveryObservation(**key, observed, different, issued + 1));
  observed.claims.endpoint.targetIncarnation.data[0] ^= 1;
  ASSERT_FALSE(verifyEcTargetDiscoveryObservation(**key, observed, *request, issued + 1));
}
TEST(TestEcTargetDiscovery, EveryRequestFieldAndConfiguredIdentityAreBound) {
  folly::test::TemporaryDirectory dir;
  auto key = testKey(dir.path());
  ASSERT_OK(key);
  auto request = signEcTargetDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  const std::vector<std::function<void(EcTargetDiscoveryClaims &)>> changes{
      [](auto &v) { ++v.version; },
      [](auto &v) { v.clusterAuthority.data[0] ^= 1; },
      [](auto &v) { ++v.nodeId; },
      [](auto &v) { ++v.chainId; },
      [](auto &v) { ++v.targetId; },
      [](auto &v) { v.nonce.data[0] ^= 1; },
      [](auto &v) { ++v.issuedAtSeconds; },
      [](auto &v) { --v.expiresAtSeconds; }};
  for (const auto &change : changes) {
    auto copy = *request;
    change(copy.claims);
    ASSERT_FALSE(verifyEcTargetDiscovery(**key, copy, claims().clusterAuthority, claims().nodeId, issued + 1));
  }
  ASSERT_FALSE(verifyEcTargetDiscovery(**key, *request, uuid(2), claims().nodeId, issued));
  ASSERT_FALSE(verifyEcTargetDiscovery(**key, *request, claims().clusterAuthority, NodeId(9), issued));
}
TEST(TestEcTargetDiscovery, ExpiryWrongKeyAndLifetimeBoundsFailClosed) {
  folly::test::TemporaryDirectory dir;
  auto key = testKey(dir.path());
  auto wrong = testKey(dir.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(wrong);
  auto request = signEcTargetDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  ASSERT_FALSE(verifyEcTargetDiscovery(**wrong, *request, claims().clusterAuthority, claims().nodeId, issued));
  for (auto now : {issued - 1, issued + 60})
    ASSERT_FALSE(verifyEcTargetDiscovery(**key, *request, claims().clusterAuthority, claims().nodeId, now));
  auto value = claims();
  value.expiresAtSeconds = issued + 61;
  ASSERT_FALSE(signEcTargetDiscovery(**key, value, issued));
  value = claims();
  value.expiresAtSeconds = issued;
  ASSERT_FALSE(signEcTargetDiscovery(**key, value, issued));
}
TEST(TestEcTargetDiscovery, BinarySerdeIsFixedBoundedAndCannotImportTextOrControlDomain) {
  folly::test::TemporaryDirectory dir;
  auto key = testKey(dir.path());
  ASSERT_OK(key);
  auto request = signEcTargetDiscovery(**key, claims(), issued);
  ASSERT_OK(request);
  auto wire = serde::serialize(*request);
  EcTargetDiscoveryRequest decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  EXPECT_EQ(serde::serialize(decoded), wire);
  ASSERT_FALSE(serde::deserialize(decoded, serde::serialize(Varint64(3)) + wire.substr(1)));
  auto canonical = ec_target_discovery_detail::Codec::encode(claims());
  std::string raw(reinterpret_cast<const char *>(canonical.data()), canonical.size());
  ASSERT_FALSE(ec_target_discovery_detail::Codec::decodeRequest(raw.substr(1)));
  ASSERT_FALSE(ec_scope_control_detail::Codec::decodeRequest(raw));
  ASSERT_TRUE(ec_target_discovery_detail::Codec::decodeRequest(raw));
  for (size_t byte = 0; byte != 8; ++byte) {
    SCOPED_TRACE(byte);
    auto changed = raw;
    changed[byte] ^= 1;
    ASSERT_FALSE(ec_target_discovery_detail::Codec::decodeRequest(changed));
  }
  auto text = serde::toJsonString(*request);
  EXPECT_NE(text.find("REDACTED"), std::string::npos);
  EXPECT_EQ(text.find(claims().nonce.toHexString()), std::string::npos);
  ASSERT_FALSE(serde::fromJsonString(decoded, text));
  wire.back() ^= 1;
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_FALSE(verifyEcTargetDiscovery(**key, decoded, claims().clusterAuthority, claims().nodeId, issued));
}
TEST(TestEcTargetDiscovery, ActualEngineReopenKeepsIdentityAndSeparateRootChangesIt) {
  folly::test::TemporaryDirectory first, second, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  CPUExecutorGroup cpu(1, "EcDiscoveryReopen");
  auto intent = claims();
  intent.chainId = ChainId(91);
  intent.targetId = TargetId(92);
  EcScopeEndpoint firstIdentity;
  for (unsigned pass = 0; pass != 3; ++pass) {
    StorageTargets::Config config;
    config.set_target_paths({pass == 2 ? second.path() : first.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(cpu));
    if (pass != 1) {
      CreateTargetReq create;
      create.chainId = intent.chainId;
      create.targetId = intent.targetId;
      create.onlyChunkEngine = true;
      ASSERT_OK(targets.create(create, true));
    }
    auto found = map.getByTargetId(intent.targetId);
    ASSERT_OK(found);
    auto executor =
        EcTargetDiscoveryExecutor::create(key, intent.clusterAuthority, intent.nodeId, [] { return issued + 1; });
    ASSERT_OK(executor);
    auto request = signEcTargetDiscovery(*key, intent, issued);
    ASSERT_OK(request);
    auto observed = folly::coro::blockingWait((*executor)->execute(*request, (*found)->storageTarget));
    ASSERT_OK(observed);
    ASSERT_OK(verifyEcTargetDiscoveryObservation(*key, *observed, *request, issued + 1));
    if (!pass) {
      auto calls = std::make_shared<unsigned>(0);
      auto expires = EcTargetDiscoveryExecutor::create(key, intent.clusterAuthority, intent.nodeId, [calls] {
        return ++*calls >= 3 ? issued + 60 : issued + 1;
      });
      ASSERT_OK(expires);
      auto late = folly::coro::blockingWait((*expires)->execute(*request, (*found)->storageTarget));
      ASSERT_ERROR(late, StatusCode::kAuthenticationFail);
    }
    if (!pass)
      firstIdentity = observed->claims.endpoint;
    else if (pass == 1) {
      EXPECT_EQ(observed->claims.endpoint.engineUuid, firstIdentity.engineUuid);
      EXPECT_EQ(observed->claims.endpoint.targetIncarnation, firstIdentity.targetIncarnation);
    } else {
      EXPECT_NE(observed->claims.endpoint.engineUuid, firstIdentity.engineUuid);
      EXPECT_NE(observed->claims.endpoint.targetIncarnation, firstIdentity.targetIncarnation);
    }
  }
}

thread_local bool discoveryTestCaller = false;
thread_local std::promise<void> *discoveryWaitInjection = nullptr;
void throwAwaitBadAlloc() {
  discoveryWaitInjection->set_value();
  throw std::bad_alloc();
}
void throwAwaitError() {
  discoveryWaitInjection->set_value();
  throw std::runtime_error("test await construction");
}

TEST(TestEcTargetDiscovery, PostEnqueueWaitExceptionJoinsRealWorkerBeforeReleasingBorrow) {
  using namespace std::chrono_literals;
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  CPUExecutorGroup cpu(1, "EcDiscoveryWait");
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(cpu));
  auto intent = claims();
  intent.chainId = ChainId(91);
  intent.targetId = TargetId(92);
  CreateTargetReq create;
  create.chainId = intent.chainId;
  create.targetId = intent.targetId;
  create.onlyChunkEngine = true;
  ASSERT_OK(targets.create(create, true));
  auto found = map.getByTargetId(intent.targetId);
  ASSERT_OK(found);
  auto target = (*found)->storageTarget;
  auto request = signEcTargetDiscovery(*key, intent, issued);
  ASSERT_OK(request);
  const auto identity = target->ecScopeState();
  ASSERT_OK(identity);
  for (bool badAlloc : {true, false}) {
    // This explicit private seam throws after real enqueue, not a process-wide
    // allocator failure. The actual Engine worker is held at its auth clock.
    std::promise<void> entered, resume, injected;
    auto resumed = resume.get_future().share();
    std::atomic<bool> blocked{false};
    auto executor = EcTargetDiscoveryExecutor::create(key, intent.clusterAuthority, intent.nodeId, [&] {
      if (!discoveryTestCaller && !blocked.exchange(true)) {
        entered.set_value();
        resumed.wait();
      }
      return issued + 1;
    });
    ASSERT_OK(executor);
    auto pending = std::async(std::launch::async, [&] {
      discoveryTestCaller = true;
      discoveryWaitInjection = &injected;
      SCOPE_EXIT { discoveryWaitInjection = nullptr; };
      return folly::coro::blockingWait(
          EcDiscoveryExecutorTestAccess::execute(**executor,
                                                 *request,
                                                 target,
                                                 badAlloc ? throwAwaitBadAlloc : throwAwaitError));
    });
    // Unblock before future destruction on assertion failure; never let a
    // failed test hang while its own worker is intentionally paused.
    auto unblock = folly::makeGuard([&] { resume.set_value(); });
    ASSERT_EQ(entered.get_future().wait_for(5s), std::future_status::ready);
    ASSERT_EQ(injected.get_future().wait_for(5s), std::future_status::ready);
    EXPECT_EQ(pending.wait_for(20ms), std::future_status::timeout);
    std::promise<void> stopStarted;
    auto stopper = std::async(std::launch::async, [&] {
      stopStarted.set_value();
      (*executor)->stopAndJoin();
    });
    stopStarted.get_future().wait();
    EXPECT_EQ(stopper.wait_for(20ms), std::future_status::timeout);
    resume.set_value();
    unblock.dismiss();
    auto result = pending.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), badAlloc ? StatusCode::kNotEnoughMemory : StorageCode::kChunkMetadataGetError);
    stopper.get();
    EXPECT_TRUE(blocked);
    auto after = target->ecScopeState();
    ASSERT_OK(after);
    EXPECT_EQ(after->second, identity->second);
  }
  // A later normal request still observes the same real identity.
  auto normal =
      EcTargetDiscoveryExecutor::create(key, intent.clusterAuthority, intent.nodeId, [] { return issued + 1; });
  ASSERT_OK(normal);
  auto observed = folly::coro::blockingWait((*normal)->execute(*request, target));
  ASSERT_OK(observed);
  ASSERT_OK(verifyEcTargetDiscoveryObservation(*key, *observed, *request, issued + 1));
}

TEST(TestEcTargetDiscovery, WorkerReentrantAdmissionFailsBeforeAnyQueueBorrow) {
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  CPUExecutorGroup cpu(1, "EcDiscoveryNested");
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(cpu));
  auto intent = claims();
  intent.chainId = ChainId(91);
  intent.targetId = TargetId(92);
  CreateTargetReq create;
  create.chainId = intent.chainId;
  create.targetId = intent.targetId;
  create.onlyChunkEngine = true;
  ASSERT_OK(targets.create(create, true));
  auto found = map.getByTargetId(intent.targetId);
  ASSERT_OK(found);
  auto target = (*found)->storageTarget;
  auto request = signEcTargetDiscovery(*key, intent, issued);
  ASSERT_OK(request);
  const auto caller = std::this_thread::get_id();
  EcTargetDiscoveryExecutor *raw = nullptr;
  std::atomic<bool> rejected{false};
  auto executor = EcTargetDiscoveryExecutor::create(key, intent.clusterAuthority, intent.nodeId, [&] {
    if (std::this_thread::get_id() != caller) {
      auto nested = folly::coro::blockingWait(raw->execute(*request, target));
      rejected = !nested && nested.error().code() == StatusCode::kInvalidArg;
    }
    return issued + 1;
  });
  ASSERT_OK(executor);
  raw = executor->get();
  auto observed = folly::coro::blockingWait((*executor)->execute(*request, target));
  ASSERT_OK(observed);
  EXPECT_TRUE(rejected);
  ASSERT_OK(verifyEcTargetDiscoveryObservation(*key, *observed, *request, issued + 1));
}
}  // namespace
}  // namespace hf3fs::storage
