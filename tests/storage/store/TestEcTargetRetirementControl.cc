#include <algorithm>
#include <array>
#include <fstream>
#include <functional>
#include <limits>
#include <sys/stat.h>
#include <type_traits>
#include <vector>

#include "fbs/storage/EcTargetRetirementControl.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
using Codec = ec_target_retirement_detail::Codec;
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
std::string unhex(std::string_view text) {
  auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  std::string bytes;
  for (size_t i = 0; i != text.size(); i += 2) {
    bytes.push_back(static_cast<char>((nibble(text[i]) << 4) | nibble(text[i + 1])));
  }
  return bytes;
}
template <typename T>
Result<T> decodeGolden(std::string_view wireHex) {
  T value;
  RETURN_ON_ERROR(serde::deserialize(value, unhex(wireHex)));
  return value;
}
EcTargetRetirementClaims claims() {
  EcTargetRetirementClaims value;
  value.clusterAuthority = uuid(1);
  value.nodeId = NodeId(0x10203040);
  value.chainId = ChainId(0x01020304);
  value.targetId = TargetId(0x1122334455667788);
  value.engineUuid = uuid(21);
  value.targetIncarnation = uuid(41);
  value.retirementId = uuid(121);
  value.nonce = uuid(141);
  value.issuedAtSeconds = issued;
  value.expiresAtSeconds = issued + 60;
  return value;
}
Result<std::unique_ptr<EcScopeControlKey>> testKey(const Path &directory, uint8_t offset = 0) {
  const auto path = directory / ("retirement-control-" + std::to_string(offset) + ".key");
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i != key.size(); ++i) key[i] = i + offset;
  std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(key.data()), key.size());
  output.close();
  if (!output.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  return EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
}
Result<Void> verify(const EcScopeControlKey &key, const EcTargetRetirementRequest &request, uint64_t now = issued) {
  return verifyEcTargetRetirement(key,
                                 request,
                                 claims().clusterAuthority,
                                 claims().nodeId,
                                 EcTargetRetirementAction::Prepare,
                                 now);
}
static_assert(!std::is_constructible_v<EcScopeControlKey, const EcCapabilityKey &>);
static_assert(!std::is_convertible_v<EcTargetRetirementObservation, EcScopeControlAck>);

// Independent Python struct/hashlib/hmac oracle: key bytes 00..1f; all
// integers big-endian; UUIDs raw. These fixed input frames test the codec only,
// and are not evidence of a registry observation. No test calls signObserved
// or exposes a callable receipt-signing factory.
constexpr std::string_view requestGoldenCanonical =
    "33465345545251310001010102030405060708090a0b0c0d0e0f101020304001020304112233445566778815161718191a1b"
    "1c1d1e1f2021222324292a2b2c2d2e2f303132333435363738797a7b7c7d7e7f8081828384858687888d8e8f909192939495"
    "969798999a9b9c000000006553f100000000006553f13c";

constexpr std::string_view requestGoldenWire =
    "027b33465345545251310001010102030405060708090a0b0c0d0e0f10102030400102030411223344556677881516171819"
    "1a1b1c1d1e1f2021222324292a2b2c2d2e2f303132333435363738797a7b7c7d7e7f8081828384858687888d8e8f90919293"
    "9495969798999a9b9c000000006553f100000000006553f13c20a0a9116c0cb115515e72fc979643213455436bfd266e8749"
    "58f11087bc5c4253";

constexpr std::string_view observationGoldenCanonical =
    "3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52cd3c0"
    "d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb002010000000000000000"
    "000000006553f101";

constexpr std::string_view observationGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f1012092f03df26802575e3fb10bdc034158a853411c7213bb20abdfc11d5185645582";

constexpr std::string_view retirementDigestGolden =
    "f19df248d52cd3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71";

constexpr std::string_view pendingGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00101000000000000"
    "0007000000006553f10120767b1886f1628bcb463508f2ec2eae3148e7244054f9bb01740fe63ec40725c2";

constexpr std::string_view undurableGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00100000000000000"
    "0000000000006553f101209db959b51d4516a34429568c9f9ef5ac56ee795d80120f8afb022a0a894df1e1";

constexpr std::string_view issuedBoundaryGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f100207c29d2196de82d4153a117c0837836c7788772dc45ab8b9914b1e3357eee9899";

constexpr std::string_view lastInstantGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f13b205565e215f9c0d9665e056a0aaba88a5a55f12e2260a2c1a185354ba86029efb1";

constexpr std::string_view wrongRequestDigestGoldenWire =
    "026c3346534554524f3100010101010101010101010101010101010101010101010101010101010101010101f19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f1012081e630b7e059b4f0acac0c17f38656a55504e7eb4755b980d7de2eb96b0217e6";

constexpr std::string_view wrongRecordDigestGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7feda020202020202"
    "0202020202020202020202020202020202020202020202020202a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f101202f3556c181f46ce7cec258838631d5f8750114f16636a98dc3cae68b8a2043f0";

constexpr std::string_view beforeWindowGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f0ff204c1277d8e78a5135cbc7b3a76dc255c94cef32a5b8b23d2bb3e7bf5e74d29064";

constexpr std::string_view atExpiryGoldenWire =
    "026c3346534554524f31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f13c20cc95887aa5b727ed1a89035b5e543f28d9058656a0771eaba6311e3e16abb948";

constexpr std::string_view renewedGoldenWire =
    "026c3346534554524f310001e9693f5d524431571feef375080ee660713f90ac739b157850e5a5404ba4ff1ff19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f16520dbb686ddfedd613115346818ca392203d84c8a86e8767f6bf5172aa943d2f89d";

constexpr std::string_view scopeDomainObservationGoldenWire =
    "026c3346534543414b31000126073b41c0d5f239a393c025f474e3e463bf75c5ed9411e4844408e145f7fedaf19df248d52c"
    "d3c0d4a2b8503bc802ecaab4b45d065ad035d912b5f3fb2b0b71a1a2a3a4a5a6a7a8a9aaabacadaeafb00201000000000000"
    "0000000000006553f101203e6b368d704db3a6ad445e39bfbe2b92b17e76edd3401fb47b74ccef5f5f5f36";

TEST(TestEcTargetRetirementControl, RequestCanonicalMacGoldenAndRedactedSerde) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = signEcTargetRetirement(**key, claims(), issued);
  ASSERT_OK(request);
  EXPECT_EQ(hex(Codec::encode(request->claims)), requestGoldenCanonical);
  const auto wire = serde::serialize(*request);
  EXPECT_EQ(wire, unhex(requestGoldenWire));
  auto decoded = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  ASSERT_OK(decoded);
  EXPECT_EQ(serde::serialize(*decoded), wire);
  ASSERT_OK(verify(**key, *decoded));
  EXPECT_EQ(fmt::format("{}", *decoded), "EcTargetRetirementRequest(REDACTED)");
  EXPECT_EQ(serde::toJsonString(*decoded), "\"EcTargetRetirementRequest(REDACTED)\"");
  ASSERT_FALSE(serde::fromJsonString(*decoded, "\"EcTargetRetirementRequest(REDACTED)\""));
}

TEST(TestEcTargetRetirementControl, ObservationCanonicalMacGoldenAndExactRequest) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  auto observation = decodeGolden<EcTargetRetirementObservation>(observationGoldenWire);
  ASSERT_OK(request);
  ASSERT_OK(observation);
  EXPECT_EQ(hex(Codec::encode(observation->claims)), observationGoldenCanonical);
  EXPECT_EQ(serde::serialize(*observation), unhex(observationGoldenWire));
  EXPECT_EQ(hex(observation->claims.retirementDigest), retirementDigestGolden);
  EXPECT_EQ(observation->claims.state, EcTargetRetirementState::LocalDataDrained);
  EXPECT_TRUE(observation->claims.durable);
  EXPECT_EQ(observation->claims.inflight, 0);
  ASSERT_OK(verifyEcTargetRetirementObservation(**key, *observation, *request));
  // A historical observation remains verifiable after the request expires.
  ASSERT_ERROR(verify(**key, *request, issued + 60), StatusCode::kAuthenticationFail);
  ASSERT_OK(verifyEcTargetRetirementObservation(**key, *observation, *request));
  EXPECT_EQ(fmt::format("{}", *observation), "EcTargetRetirementObservation(REDACTED)");
  EXPECT_EQ(serde::toJsonString(*observation), "\"EcTargetRetirementObservation(REDACTED)\"");
  ASSERT_FALSE(serde::fromJsonString(*observation, "\"EcTargetRetirementObservation(REDACTED)\""));
  EcTargetRetirementRsp response;
  response.result = *observation;
  EcTargetRetirementRsp decodedResponse;
  ASSERT_OK(serde::deserialize(decodedResponse, serde::serialize(response)));
  ASSERT_OK(decodedResponse.result);
  ASSERT_OK(verifyEcTargetRetirementObservation(**key, *decodedResponse.result, *request));

  for (auto wire : {pendingGoldenWire, undurableGoldenWire, issuedBoundaryGoldenWire, lastInstantGoldenWire}) {
    auto valid = decodeGolden<EcTargetRetirementObservation>(wire);
    ASSERT_OK(valid);
    ASSERT_OK(verifyEcTargetRetirementObservation(**key, *valid, *request));
    if (wire == pendingGoldenWire || wire == undurableGoldenWire) {
      EXPECT_EQ(valid->claims.state, EcTargetRetirementState::Pending);
      EXPECT_EQ(valid->claims.durable, wire == pendingGoldenWire);
      EXPECT_EQ(valid->claims.inflight, wire == pendingGoldenWire ? 7 : 0);
    }
  }
  // These fixtures have correct HMACs. They isolate semantic binding/time
  // checks from failures caused merely by a corrupted MAC.
  for (auto wire : {wrongRequestDigestGoldenWire, wrongRecordDigestGoldenWire, beforeWindowGoldenWire, atExpiryGoldenWire}) {
    auto invalid = decodeGolden<EcTargetRetirementObservation>(wire);
    ASSERT_OK(invalid);
    ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *invalid, *request), StatusCode::kTokenMismatch);
  }
  auto changed = claims();
  changed.action = EcTargetRetirementAction::Query;
  auto query = signEcTargetRetirement(**key, changed, issued);
  ASSERT_OK(query);
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *observation, *query), StatusCode::kTokenMismatch);
}

TEST(TestEcTargetRetirementControl, EveryRequestFieldIsAuthenticated) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto request = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  auto observation = decodeGolden<EcTargetRetirementObservation>(observationGoldenWire);
  ASSERT_OK(request);
  ASSERT_OK(observation);
  const std::vector<std::function<void(EcTargetRetirementClaims &)>> changes{
      [](auto &c) { ++c.version; },
      [](auto &c) { c.action = EcTargetRetirementAction::Query; },
      [](auto &c) { c.clusterAuthority.data[0] ^= 1; },
      [](auto &c) { c.nodeId = NodeId(1); },
      [](auto &c) { c.chainId = ChainId(1); },
      [](auto &c) { c.targetId = TargetId(1); },
      [](auto &c) { c.engineUuid.data[0] ^= 1; },
      [](auto &c) { c.targetIncarnation.data[0] ^= 1; },
      [](auto &c) { c.retirementId.data[0] ^= 1; },
      [](auto &c) { c.nonce.data[0] ^= 1; },
      [](auto &c) { --c.issuedAtSeconds; },
      [](auto &c) { ++c.expiresAtSeconds; },
  };
  for (size_t i = 0; i != changes.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = *request;
    changes[i](changed.claims);
    const auto code = i == 0 ? StatusCode::kInvalidArg : StatusCode::kAuthenticationFail;
    ASSERT_ERROR(verify(**key, changed), code);
    ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *observation, changed), code);
  }
  auto wire = serde::serialize(*request);
  wire.back() ^= 1;
  EcTargetRetirementRequest badSignature;
  ASSERT_OK(serde::deserialize(badSignature, wire));
  ASSERT_ERROR(verify(**key, badSignature), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *observation, badSignature), StatusCode::kAuthenticationFail);
}

TEST(TestEcTargetRetirementControl, EveryObservationFieldIsAuthenticated) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  auto other = testKey(directory.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(other);
  auto request = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  auto observation = decodeGolden<EcTargetRetirementObservation>(observationGoldenWire);
  ASSERT_OK(request);
  ASSERT_OK(observation);
  const std::vector<std::function<void(EcTargetRetirementObservationClaims &)>> changes{
      [](auto &c) { ++c.version; },
      [](auto &c) { c.requestDigest[0] ^= 1; },
      [](auto &c) { c.retirementDigest[0] ^= 1; },
      [](auto &c) { c.bootNonce.data[0] ^= 1; },
      [](auto &c) { c.state = EcTargetRetirementState::Pending; },
      [](auto &c) { c.durable = false; },
      [](auto &c) { ++c.inflight; },
      [](auto &c) { ++c.observedAtSeconds; },
  };
  for (size_t i = 0; i != changes.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = *observation;
    changes[i](changed.claims);
    ASSERT_FALSE(verifyEcTargetRetirementObservation(**key, changed, *request));
  }
  // Keep the state internally consistent while tampering durable/inflight:
  // these mutations must fail the MAC check, not just state validation.
  auto pending = decodeGolden<EcTargetRetirementObservation>(pendingGoldenWire);
  ASSERT_OK(pending);
  auto changed = *pending;
  changed.claims.durable = false;
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, changed, *request), StatusCode::kAuthenticationFail);
  changed = *pending;
  ++changed.claims.inflight;
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, changed, *request), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**other, *observation, *request), StatusCode::kAuthenticationFail);
  auto wire = serde::serialize(*observation);
  wire.back() ^= 1;
  EcTargetRetirementObservation badSignature;
  ASSERT_OK(serde::deserialize(badSignature, wire));
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, badSignature, *request), StatusCode::kAuthenticationFail);
}

TEST(TestEcTargetRetirementControl, LifetimeAuthorityActionAndWrongKeyFailClosed) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  auto other = testKey(directory.path(), 1);
  ASSERT_OK(key);
  ASSERT_OK(other);
  auto request = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  ASSERT_OK(request);
  for (auto now : {issued - 1, issued + 60, std::numeric_limits<uint64_t>::max()}) {
    ASSERT_ERROR(verify(**key, *request, now), StatusCode::kAuthenticationFail);
    ASSERT_ERROR(signEcTargetRetirement(**key, claims(), now), StatusCode::kAuthenticationFail);
  }
  ASSERT_OK(verify(**key, *request, issued));
  ASSERT_OK(verify(**key, *request, issued + 59));
  ASSERT_ERROR(verify(**other, *request), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verifyEcTargetRetirement(**key, *request, uuid(2), claims().nodeId,
                                       EcTargetRetirementAction::Prepare, issued), StatusCode::kTokenMismatch);
  ASSERT_ERROR(verifyEcTargetRetirement(**key, *request, claims().clusterAuthority, NodeId(1),
                                       EcTargetRetirementAction::Prepare, issued), StatusCode::kTokenMismatch);
  ASSERT_ERROR(verifyEcTargetRetirement(**key, *request, claims().clusterAuthority, claims().nodeId,
                                       EcTargetRetirementAction::Query, issued), StatusCode::kTokenMismatch);
  const std::vector<std::function<void(EcTargetRetirementClaims &)>> invalid{
      [](auto &c) { c.version = 0; },
      [](auto &c) { c.action = static_cast<EcTargetRetirementAction>(3); },
      [](auto &c) { c.clusterAuthority = Uuid::zero(); },
      [](auto &c) { c.nodeId = NodeId{}; },
      [](auto &c) { c.chainId = ChainId{}; },
      [](auto &c) { c.targetId = TargetId{}; },
      [](auto &c) { c.engineUuid = Uuid::zero(); },
      [](auto &c) { c.targetIncarnation = Uuid::zero(); },
      [](auto &c) { c.retirementId = Uuid::zero(); },
      [](auto &c) { c.nonce = Uuid::zero(); },
      [](auto &c) { c.expiresAtSeconds = c.issuedAtSeconds; },
      [](auto &c) { c.expiresAtSeconds = c.issuedAtSeconds - 1; },
      [](auto &c) { c.expiresAtSeconds = c.issuedAtSeconds + 301; },
      [](auto &c) { c.issuedAtSeconds = std::numeric_limits<uint64_t>::max(); c.expiresAtSeconds = 1; },
  };
  for (size_t i = 0; i != invalid.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = claims();
    invalid[i](changed);
    ASSERT_ERROR(signEcTargetRetirement(**key, changed, issued), StatusCode::kInvalidArg);
    const auto encoded = Codec::encode(changed);
    ASSERT_FALSE(Codec::decodeRequest({reinterpret_cast<const char *>(encoded.data()), encoded.size()}));
  }
  auto maximum = claims();
  maximum.expiresAtSeconds = issued + 300;
  ASSERT_OK(signEcTargetRetirement(**key, maximum, issued + 299));
  maximum.issuedAtSeconds = std::numeric_limits<uint64_t>::max() - 300;
  maximum.expiresAtSeconds = std::numeric_limits<uint64_t>::max();
  ASSERT_OK(signEcTargetRetirement(**key, maximum, maximum.issuedAtSeconds));
}

TEST(TestEcTargetRetirementControl, MalformedFramesAndContradictoryStatesFailClosed) {
  const auto request = unhex(requestGoldenCanonical);
  const auto observation = unhex(observationGoldenCanonical);
  for (size_t length = 0; length < request.size(); ++length) {
    ASSERT_FALSE(Codec::decodeRequest(std::string_view(request).substr(0, length)));
  }
  for (size_t length = 0; length < observation.size(); ++length) {
    ASSERT_FALSE(Codec::decodeObservation(std::string_view(observation).substr(0, length)));
  }
  ASSERT_FALSE(Codec::decodeRequest(request + '\0'));
  ASSERT_FALSE(Codec::decodeObservation(observation + '\0'));
  for (size_t offset : {size_t(0), size_t(8), size_t(9), size_t(10)}) {
    auto changed = request;
    changed[offset] = static_cast<char>(255);
    ASSERT_FALSE(Codec::decodeRequest(changed));
  }
  for (size_t offset : {size_t(0), size_t(8), size_t(9), size_t(90), size_t(91)}) {
    auto changed = observation;
    changed[offset] = static_cast<char>(255);
    ASSERT_FALSE(Codec::decodeObservation(changed));
  }
  auto changed = observation;
  changed[91] = 2;  // A truthy byte is not a canonical bool.
  ASSERT_FALSE(Codec::decodeObservation(changed));
  for (const auto &[offset, width] : std::array<std::pair<size_t, size_t>, 3>{{{10, 32}, {42, 32}, {74, 16}}}) {
    changed = observation;
    std::fill_n(changed.begin() + offset, width, '\0');
    ASSERT_FALSE(Codec::decodeObservation(changed));
  }
  for (bool durable : {false, true}) {
    for (uint64_t inflight : {uint64_t(0), uint64_t(1), std::numeric_limits<uint64_t>::max()}) {
      for (auto state : {EcTargetRetirementState::Pending, EcTargetRetirementState::LocalDataDrained}) {
        auto decoded = Codec::decodeObservation(observation);
        ASSERT_OK(decoded);
        decoded->durable = durable;
        decoded->inflight = inflight;
        decoded->state = state;
        const auto encoded = Codec::encode(*decoded);
        const auto result = Codec::decodeObservation({reinterpret_cast<const char *>(encoded.data()), encoded.size()});
        EXPECT_EQ(bool(result), (state == EcTargetRetirementState::LocalDataDrained) == (durable && inflight == 0));
      }
    }
  }
  for (auto golden : {requestGoldenWire, observationGoldenWire}) {
    const auto validWire = unhex(golden);
    auto rejects = [&](const std::string &wire) {
      if (golden == requestGoldenWire) {
        EcTargetRetirementRequest decoded;
        return !serde::deserialize(decoded, wire);
      }
      EcTargetRetirementObservation decoded;
      return !serde::deserialize(decoded, wire);
    };
    for (size_t length = 0; length < validWire.size(); ++length) ASSERT_TRUE(rejects(validWire.substr(0, length)));
    for (uint8_t count : {uint8_t(0), uint8_t(1), uint8_t(3)}) {
      auto wire = validWire;
      wire[0] = count;
      ASSERT_TRUE(rejects(wire));
    }
    auto wire = validWire;
    --wire[1];  // Incorrect canonical frame length.
    ASSERT_TRUE(rejects(wire));
    wire = validWire;
    ++wire[1];
    ASSERT_TRUE(rejects(wire));
    wire = validWire;
    wire[wire.size() - 33] = 31;  // SHA256 byte string must have exactly 32 bytes.
    ASSERT_TRUE(rejects(wire));
  }
}

TEST(TestEcTargetRetirementControl, ScopeAndRetirementDomainsCannotCross) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  const auto c = claims();
  EcScopeControlClaims scope;
  scope.clusterAuthority = c.clusterAuthority;
  scope.nodeId = c.nodeId;
  scope.chainId = c.chainId;
  scope.targetId = c.targetId;
  scope.engineUuid = c.engineUuid;
  scope.targetIncarnation = c.targetIncarnation;
  scope.object = uuid(61);
  scope.scopeId = uuid(81);
  scope.clientNamespace = uuid(101);
  scope.endpointSetDigest.fill(1);
  scope.revocationId = c.retirementId;
  scope.nonce = c.nonce;
  scope.issuedAtSeconds = issued;
  scope.expiresAtSeconds = issued + 60;
  auto scopeRequest = signEcScopeControl(**key, scope, issued);
  ASSERT_OK(scopeRequest);
  EcTargetRetirementRequest retirementRequest;
  ASSERT_FALSE(serde::deserialize(retirementRequest, serde::serialize(*scopeRequest)));
  EcScopeControlRequest oldRequest;
  ASSERT_FALSE(serde::deserialize(oldRequest, unhex(requestGoldenWire)));
  EcScopeControlAck oldAck;
  ASSERT_FALSE(serde::deserialize(oldAck, unhex(observationGoldenWire)));
  auto observation = decodeGolden<EcTargetRetirementObservation>(observationGoldenWire);
  auto request = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  ASSERT_OK(observation);
  ASSERT_OK(request);
  // Equal-size observation/ACK payloads still reject each other's domains.
  auto relabeled = unhex(observationGoldenWire);
  relabeled.replace(2, 8, "3FSECAK1");
  ASSERT_OK(serde::deserialize(oldAck, relabeled));
  ASSERT_ERROR(verifyEcScopeControlAck(**key, oldAck, *scopeRequest), StatusCode::kAuthenticationFail);
  EcTargetRetirementObservation newObservation;
  ASSERT_FALSE(serde::deserialize(newObservation, serde::serialize(oldAck)));
  // This independently MACed old-domain frame also cannot be relabeled into
  // a valid retirement receipt, even when all other fields match exactly.
  auto oldDomain = unhex(scopeDomainObservationGoldenWire);
  ASSERT_OK(serde::deserialize(oldAck, oldDomain));
  oldDomain.replace(2, 8, "3FSETRO1");
  ASSERT_OK(serde::deserialize(newObservation, oldDomain));
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, newObservation, *request), StatusCode::kAuthenticationFail);
  auto denyDomain = unhex(observationGoldenCanonical);
  denyDomain.replace(0, 8, "3FSETRD1");
  ASSERT_FALSE(Codec::decodeObservation(denyDomain));
  ASSERT_FALSE(Codec::decodeRequest(unhex(observationGoldenCanonical)));
  ASSERT_FALSE(Codec::decodeObservation(unhex(requestGoldenCanonical)));
}

TEST(TestEcTargetRetirementControl, RetirementDigestExcludesRequestAuthorityNodeAndNonce) {
  folly::test::TemporaryDirectory directory;
  auto key = testKey(directory.path());
  ASSERT_OK(key);
  auto oldRequest = decodeGolden<EcTargetRetirementRequest>(requestGoldenWire);
  auto oldObservation = decodeGolden<EcTargetRetirementObservation>(observationGoldenWire);
  ASSERT_OK(oldRequest);
  ASSERT_OK(oldObservation);
  auto renewed = claims();
  renewed.action = EcTargetRetirementAction::Query;
  renewed.clusterAuthority = uuid(2);
  renewed.nodeId = NodeId(0x10203041);
  renewed.nonce = uuid(142);
  renewed.issuedAtSeconds += 100;
  renewed.expiresAtSeconds += 100;
  auto request = signEcTargetRetirement(**key, renewed, issued + 100);
  auto observation = decodeGolden<EcTargetRetirementObservation>(renewedGoldenWire);
  ASSERT_OK(request);
  ASSERT_OK(observation);
  EXPECT_EQ(oldObservation->claims.retirementDigest, observation->claims.retirementDigest);
  EXPECT_NE(oldObservation->claims.requestDigest, observation->claims.requestDigest);
  ASSERT_OK(verifyEcTargetRetirementObservation(**key, *observation, *request));
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *observation, *oldRequest), StatusCode::kTokenMismatch);
  ASSERT_ERROR(verifyEcTargetRetirementObservation(**key, *oldObservation, *request), StatusCode::kTokenMismatch);
  ASSERT_ERROR(verifyEcTargetRetirement(**key, *request, claims().clusterAuthority, renewed.nodeId,
                                       EcTargetRetirementAction::Query, issued + 100), StatusCode::kTokenMismatch);
  ASSERT_OK(verifyEcTargetRetirement(**key, *request, renewed.clusterAuthority, renewed.nodeId,
                                   EcTargetRetirementAction::Query, issued + 100));
}
}  // namespace
}  // namespace hf3fs::storage
