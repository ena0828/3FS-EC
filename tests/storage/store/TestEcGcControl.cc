#include <algorithm>
#include <fstream>
#include <functional>
#include <limits>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <optional>
#include <stdexcept>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

#include "fbs/storage/EcGcControl.h"
#include "tests/GtestHelpers.h"
#include "tests/data/EcGcControlGolden.h"

namespace hf3fs::storage {
// Explicit test-only access to the two production-private signing boundaries.
// All claims/ledger observations in these tests are synthetic, not FDB/Rust proofs.
class EcGcControlTestAccess {
 public:
  static Result<EcGcRequest> sign(const EcGcKey &key, const EcGcRequestClaims &c, uint64_t now, uint64_t ttl = 300) {
    return ec_gc_control_detail::RequestSigner::sign(key, c, now, ttl);
  }
  static Result<EcGcAck> confirm(const EcGcKey &key,
                                 const VerifiedEcGcRequest &request,
                                 Result<EcGcLedgerReceipt> receipt,
                                 const EcGcLocalTarget &target,
                                 Uuid boot,
                                 uint64_t now,
                                 std::optional<Uuid> configuredAuthority = std::nullopt) {
    Uuid defaultAuthority;
    std::fill(std::begin(defaultAuthority.data), std::end(defaultAuthority.data), uint8_t{11});
    return ec_gc_control_detail::AckSigner::sign(key,
                                                 request,
                                                 std::move(receipt),
                                                 target,
                                                 configuredAuthority.value_or(defaultAuthority),
                                                 boot,
                                                 now);
  }
};
namespace {
using Codec = ec_gc_control_detail::Codec;
namespace golden = gc_test_vectors;
constexpr uint64_t issued = 1700000000;

Uuid uuid(uint8_t byte) {
  Uuid result;
  std::fill(std::begin(result.data), std::end(result.data), byte);
  return result;
}
std::string unhex(std::string_view text) {
  if (text.size() % 2) throw std::runtime_error("invalid test hex extent");
  const auto digit = [](char ch) -> uint8_t {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    throw std::runtime_error("invalid test hex digit");
  };
  std::string result(text.size() / 2, '\0');
  for (size_t i = 0; i != result.size(); ++i)
    result[i] = static_cast<char>((digit(text[2 * i]) << 4) | digit(text[2 * i + 1]));
  return result;
}
template <size_t N>
std::string bytes(const std::array<uint8_t, N> &value) {
  return {reinterpret_cast<const char *>(value.data()), value.size()};
}
EcSha256 hash(std::string_view text) {
  EcSha256 result{};
  unsigned int size = 0;
  if (EVP_Digest(text.data(), text.size(), result.data(), &size, EVP_sha256(), nullptr) != 1 || size != result.size()) {
    throw std::runtime_error("test SHA-256 failed");
  }
  return result;
}
// Only tests know these public vector bytes. Do not add a raw-signing API to G.
std::string mac(std::string_view body) {
  const auto key = unhex(golden::keyHex);
  std::array<uint8_t, 32> result{};
  unsigned int size = 0;
  if (!HMAC(EVP_sha256(),
            key.data(),
            key.size(),
            reinterpret_cast<const uint8_t *>(body.data()),
            body.size(),
            result.data(),
            &size) ||
      size != result.size()) {
    throw std::runtime_error("test HMAC-SHA256 failed");
  }
  return bytes(result);
}
template <size_t N>
golden::Field field(const std::array<golden::Field, N> &fields, std::string_view name) {
  const auto found = std::find_if(fields.begin(), fields.end(), [&](auto value) { return value.name == name; });
  if (found == fields.end()) throw std::runtime_error("missing frozen field offset");
  return *found;
}
void integer(std::string &out, golden::Field f, uint64_t value) {
  for (size_t i = 0; i != f.width; ++i) out.at(f.offset + i) = static_cast<char>(value >> (8 * (f.width - 1 - i)));
}
Result<EcGcRequest> requestFrame(std::string_view wire) {
  if (wire.size() != kEcGcRequestBytes + 32) return makeError(StatusCode::kInvalidFormat);
  return Codec::decodeRequest(wire.substr(0, kEcGcRequestBytes), wire.substr(kEcGcRequestBytes));
}
Result<EcGcAck> ackFrame(std::string_view wire) {
  if (wire.size() != kEcGcAckBytes + 32) return makeError(StatusCode::kInvalidFormat);
  return Codec::decodeAck(wire.substr(0, kEcGcAckBytes), wire.substr(kEcGcAckBytes));
}
std::string tokenFrame(std::string_view body, std::string_view signature) {
  return serde::serialize(Varint64(2)) + serde::serialize(body) + serde::serialize(signature);
}

class TestEcGcControl : public ::testing::Test {
 protected:
  void SetUp() override {
    auto result = writeKey("gc.key", unhex(golden::keyHex));
    ASSERT_OK(result);
    auto loaded = EcGcKey::loadFile(*result, uuid(10), {});
    ASSERT_OK(loaded);
    key_ = std::move(*loaded);

    certificate_.claimId = uuid(1);
    certificate_.objectInode = (uint64_t{1} << 53) + 17;
    certificate_.objectIncarnation = uuid(2);
    certificate_.creatorUid = flat::Uid(1000);
    certificate_.creatorClient = uuid(3);
    certificate_.createRequest = uuid(4);
    certificate_.fragment.object = uuid(2);
    certificate_.fragment.stripe = 7;
    certificate_.fragment.generation = 9;
    certificate_.fragment.shard = 11;
    certificate_.fragment.allocation = uuid(5);
    certificate_.fragmentOperation = uuid(6);
    certificate_.endpoint = EcScopeEndpoint{NodeId(10001), ChainId(20001), TargetId(30001), uuid(7), uuid(8)};
    certificate_.writerUid = flat::Uid(1001);
    certificate_.writerClient = uuid(9);
    std::string data(65536 + 17, '\0');
    for (size_t i = 0; i != data.size(); ++i) data[i] = static_cast<char>((i * 29 + 17) & 255);
    auto integrity = computeEcIntegrity(certificate_.fragment, data);
    ASSERT_OK(integrity);
    certificate_.integrity = *integrity;
    certificate_.registeredScopes = certificate_.releasedScopes = 5;
    certificate_.releaseHistory = hash("synthetic-release-history-not-FDB-proof");
    certificate_.originDrainEvidence = hash("synthetic-origin-drain-not-ACK-proof");
    certificate_.eligibilityDigest = hash("synthetic-eligibility-not-Meta-Serde-digest");
    claims_.keyId = uuid(10);
    claims_.authority = uuid(11);
    claims_.nonce = uuid(12);
    claims_.issuedAtSeconds = issued;
    claims_.expiresAtSeconds = issued + 60;
    claims_.certificate = certificate_;
    actual_ = EcGcLocalTarget{certificate_.endpoint, 2, 3, 1, true};
    receipt_ = EcGcLedgerReceipt{uuid(1), hash("synthetic-local-ledger-not-Rust-receipt"), 19};
  }
  Result<std::filesystem::path> writeKey(std::string_view name, std::string_view data, mode_t permissions = 0600) {
    const auto path = directory_.path() / std::string(name);
    std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
    output.write(data.data(), data.size());
    output.close();
    if (!output.good() || ::chmod(path.c_str(), permissions) != 0) return makeError(StatusCode::kIOError);
    return std::filesystem::path(path.string());
  }
  Result<VerifiedEcGcRequest> verify(const EcGcRequest &request, uint64_t now = issued + 1) {
    return Codec::verifyRequest(*key_, request, uuid(11), request.claims.action, actual_, now);
  }
  folly::test::TemporaryDirectory directory_;
  std::unique_ptr<EcGcKey> key_;
  EcGcCertificate certificate_;
  EcGcRequestClaims claims_;
  EcGcLocalTarget actual_;
  EcGcLedgerReceipt receipt_;
};

static_assert(!std::is_default_constructible_v<VerifiedEcGcRequest>);
static_assert(!std::is_default_constructible_v<VerifiedEcGcAck>);
static_assert(!std::is_copy_constructible_v<EcGcKey>);
static_assert(!std::is_move_constructible_v<EcGcKey>);
static_assert(!std::is_constructible_v<EcGcKey, const EcCapabilityKey &>);
static_assert(!std::is_constructible_v<EcGcKey, const EcScopeControlKey &>);

TEST_F(TestEcGcControl, CertificateAndBothExchangesMatchFrozenPythonGolden) {
  const auto certificateBytes = bytes(Codec::encode(certificate_));
  ASSERT_EQ(certificateBytes, unhex(golden::certificateHex));
  // Comparing every named field gives a local offset diagnostic on any drift.
  for (const auto &f : golden::certificateFields) {
    SCOPED_TRACE(f.name);
    EXPECT_EQ(certificateBytes.substr(f.offset, f.width), unhex(golden::certificateHex).substr(f.offset, f.width));
  }
  auto decoded = Codec::decodeCertificate(certificateBytes);
  ASSERT_OK(decoded);
  EXPECT_EQ(decoded->objectInode, (uint64_t{1} << 53) + 17);
  EXPECT_EQ(decoded->writerClient, uuid(9));
  EXPECT_EQ(decoded->creatorClient, uuid(3));
  EXPECT_EQ(bytes(Codec::encode(*decoded)), certificateBytes);
  auto digest = Codec::claimDigest(*decoded);
  ASSERT_OK(digest);
  EXPECT_EQ(bytes(*digest), unhex(golden::claimDigestHex));
  for (bool query : {false, true}) {
    auto claims = claims_;
    if (query) {
      claims.action = EcGcAction::Query;
      claims.nonce = uuid(13);
      claims.issuedAtSeconds += 100;
      claims.expiresAtSeconds += 100;
    }
    auto signedRequest = EcGcControlTestAccess::sign(*key_, claims, claims.issuedAtSeconds);
    ASSERT_OK(signedRequest);
    EXPECT_EQ(bytes(Codec::frame(*signedRequest)), unhex(query ? golden::queryHex : golden::collectHex));
    auto checked = verify(*signedRequest, claims.issuedAtSeconds + 1);
    ASSERT_OK(checked);
    EXPECT_EQ(checked->claimDigest(), *digest);
    auto ack = EcGcControlTestAccess::confirm(*key_,
                                              *checked,
                                              receipt_,
                                              actual_,
                                              uuid(query ? 15 : 14),
                                              claims.issuedAtSeconds + 2);
    ASSERT_OK(ack);
    EXPECT_EQ(bytes(Codec::frame(*ack)), unhex(query ? golden::queryAckHex : golden::collectAckHex));
    ASSERT_OK(Codec::verifyAck(*key_, *ack, *signedRequest));
  }
}

TEST_F(TestEcGcControl, EveryRequestAndAckByteIsAuthenticated) {
  const auto collect = unhex(golden::collectHex);
  auto original = requestFrame(collect);
  ASSERT_OK(original);
  for (size_t i = 0; i != collect.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = collect;
    changed[i] ^= 1;
    auto request = requestFrame(changed);
    if (request) EXPECT_FALSE(verify(*request));
  }
  const auto ackBytes = unhex(golden::collectAckHex);
  for (size_t i = 0; i != ackBytes.size(); ++i) {
    SCOPED_TRACE(i);
    auto changed = ackBytes;
    changed[i] ^= 1;
    auto ack = ackFrame(changed);
    if (ack) EXPECT_FALSE(Codec::verifyAck(*key_, *ack, *original));
  }
  ASSERT_OK(verify(*original));
}

TEST_F(TestEcGcControl, AuthenticatedMalformedCertificateAndReservedFieldsAreRejected) {
  const auto body = unhex(golden::collectHex).substr(0, kEcGcRequestBytes);
  const auto certOffset = field(golden::requestFields, "certificate").offset;
  const std::vector<std::pair<std::string_view, uint64_t>> invalid{{"schema", 2},
                                                                   {"meta_mode", 2},
                                                                   {"catalog_version", 2},
                                                                   {"enrollment_version", 2},
                                                                   {"binding_version", 2},
                                                                   {"data_protocol", 3},
                                                                   {"disk_format", 2},
                                                                   {"gc_protocol", 2},
                                                                   {"fragment_version", 2},
                                                                   {"object_inode", 1},
                                                                   {"object_inode", uint64_t{1} << 57},
                                                                   {"generation", 0},
                                                                   {"shard", 12},
                                                                   {"node", 0},
                                                                   {"chain", 0},
                                                                   {"target", 0},
                                                                   {"registered_scopes", 0},
                                                                   {"released_scopes", 4},
                                                                   {"block_count", 65535},
                                                                   {"whole_length", 1048577},
                                                                   {"block_15_length", 1},
                                                                   {"block_1_length", 16}};
  for (auto [name, value] : invalid) {
    SCOPED_TRACE(name);
    auto changed = body;
    auto f = field(golden::certificateFields, name);
    f.offset += certOffset;
    integer(changed, f, value);
    ASSERT_FALSE(Codec::decodeRequest(changed, mac(changed)));
  }
  for (std::string_view name : {"claim_id",
                                "object_incarnation",
                                "creator_client",
                                "create_request",
                                "fragment_object",
                                "allocation",
                                "fragment_operation",
                                "engine",
                                "target_incarnation",
                                "writer_client",
                                "release_history",
                                "origin_drain_evidence",
                                "eligibility_digest"}) {
    SCOPED_TRACE(name);
    auto changed = body;
    const auto f = field(golden::certificateFields, name);
    changed.replace(certOffset + f.offset, f.width, f.width, '\0');
    ASSERT_FALSE(Codec::decodeRequest(changed, mac(changed)));
  }
  for (auto [name, value] : {std::pair<std::string_view, uint64_t>{"schema", 2}, {"action", 3}, {"reserved", 1}}) {
    auto changed = body;
    integer(changed, field(golden::requestFields, name), value);
    ASSERT_FALSE(Codec::decodeRequest(changed, mac(changed)));
  }
}

TEST_F(TestEcGcControl, ExactActionAuthorityKeyAndLiveInstanceAreRequired) {
  auto request = requestFrame(unhex(golden::collectHex));
  ASSERT_OK(request);
  ASSERT_ERROR(Codec::verifyRequest(*key_, *request, uuid(11), EcGcAction::Query, actual_, issued + 1),
               StatusCode::kTokenMismatch);
  ASSERT_ERROR(Codec::verifyRequest(*key_, *request, uuid(12), EcGcAction::Collect, actual_, issued + 1),
               StatusCode::kTokenMismatch);
  const std::vector<std::function<void(EcGcLocalTarget &)>> mutate{
      [](auto &a) { ++a.endpoint.nodeId; },
      [](auto &a) { ++a.endpoint.chainId; },
      [](auto &a) { ++a.endpoint.targetId; },
      [](auto &a) { a.endpoint.engineUuid = uuid(20); },
      [](auto &a) { a.endpoint.targetIncarnation = uuid(21); },
      [](auto &a) { a.dataProtocol = 3; },
      [](auto &a) { a.diskFormat = 2; },
      [](auto &a) { a.gcProtocol = 0; },
      [](auto &a) { a.enabled = false; }};
  for (const auto &change : mutate) {
    auto actual = actual_;
    change(actual);
    ASSERT_FALSE(Codec::verifyRequest(*key_, *request, uuid(11), EcGcAction::Collect, actual, issued + 1));
  }
  auto otherPath = writeKey("other.key", std::string(32, 'q'));
  ASSERT_OK(otherPath);
  auto other = EcGcKey::loadFile(*otherPath, uuid(10), {});
  ASSERT_OK(other);
  ASSERT_ERROR(Codec::verifyRequest(**other, *request, uuid(11), EcGcAction::Collect, actual_, issued + 1),
               StatusCode::kAuthenticationFail);
  auto wrongId = EcGcKey::loadFile(*otherPath, uuid(99), {});
  ASSERT_OK(wrongId);
  ASSERT_FALSE(EcGcControlTestAccess::sign(**wrongId, claims_, issued));
  auto sameSecretWrongId =
      EcGcKey::loadFile(std::filesystem::path((directory_.path() / "gc.key").string()), uuid(99), {});
  ASSERT_OK(sameSecretWrongId);
  ASSERT_ERROR(Codec::verifyRequest(**sameSecretWrongId, *request, uuid(11), EcGcAction::Collect, actual_, issued + 1),
               StatusCode::kTokenMismatch);
}

TEST_F(TestEcGcControl, BoundedTtlClockRollbackAndIntegerEdges) {
  auto request = requestFrame(unhex(golden::collectHex));
  ASSERT_OK(request);
  ASSERT_OK(verify(*request, issued));
  ASSERT_OK(verify(*request, issued + 59));
  ASSERT_ERROR(verify(*request, issued - 1), StatusCode::kAuthenticationFail);
  ASSERT_ERROR(verify(*request, issued + 60), StatusCode::kAuthenticationFail);
  for (uint64_t ttl : {uint64_t{0}, uint64_t{59}, uint64_t{301}}) {
    ASSERT_FALSE(EcGcControlTestAccess::sign(*key_, claims_, issued, ttl));
    ASSERT_FALSE(Codec::verifyRequest(*key_, *request, uuid(11), EcGcAction::Collect, actual_, issued, ttl));
  }
  auto edge = claims_;
  edge.issuedAtSeconds = std::numeric_limits<uint64_t>::max() - 10;
  edge.expiresAtSeconds = std::numeric_limits<uint64_t>::max();
  auto signedEdge = EcGcControlTestAccess::sign(*key_, edge, edge.issuedAtSeconds);
  ASSERT_OK(signedEdge);
  ASSERT_OK(verify(*signedEdge, edge.expiresAtSeconds - 1));
  edge.expiresAtSeconds = 1;
  ASSERT_FALSE(EcGcControlTestAccess::sign(*key_, edge, edge.issuedAtSeconds));
}

TEST_F(TestEcGcControl, QueryRenewalPreservesClaimButNotExchangeAck) {
  auto collect = requestFrame(unhex(golden::collectHex));
  auto query = requestFrame(unhex(golden::queryHex));
  auto collectAck = ackFrame(unhex(golden::collectAckHex));
  auto queryAck = ackFrame(unhex(golden::queryAckHex));
  ASSERT_OK(collect);
  ASSERT_OK(query);
  ASSERT_OK(collectAck);
  ASSERT_OK(queryAck);
  auto a = verify(*collect);
  auto b = verify(*query, issued + 101);
  ASSERT_OK(a);
  ASSERT_OK(b);
  EXPECT_EQ(a->claimDigest(), b->claimDigest());
  ASSERT_ERROR(Codec::verifyAck(*key_, *collectAck, *query), StatusCode::kTokenMismatch);
  ASSERT_ERROR(Codec::verifyAck(*key_, *queryAck, *collect), StatusCode::kTokenMismatch);
  ASSERT_OK(Codec::verifyAck(*key_, *collectAck, *collect));
  ASSERT_OK(Codec::verifyAck(*key_, *queryAck, *query));
  // Verification deliberately takes no current clock: old irreversible proof
  // remains verifiable against its exact original, authenticated exchange.
}

TEST_F(TestEcGcControl, AuthenticatedAckMustMatchWholeHistoricalBinding) {
  auto request = requestFrame(unhex(golden::collectHex));
  ASSERT_OK(request);
  const auto original = unhex(golden::collectAckHex).substr(0, kEcGcAckBytes);
  for (const auto &f : golden::ackFields) {
    if (f.name == "boot_nonce" || f.name == "ledger_sha256" || f.name == "terminal_revision" || f.name == "observed")
      continue;
    SCOPED_TRACE(f.name);
    auto changed = original;
    changed.at(f.offset + f.width - 1) ^= 1;
    auto ack = Codec::decodeAck(changed, mac(changed));
    if (ack) EXPECT_FALSE(Codec::verifyAck(*key_, *ack, *request));
  }
  for (auto [name, value] : {std::pair<std::string_view, uint64_t>{"state", 0},
                             {"terminal_revision", 1},
                             {"observed", issued - 1},
                             {"observed", issued + 60}}) {
    auto changed = original;
    integer(changed, field(golden::ackFields, name), value);
    auto ack = Codec::decodeAck(changed, mac(changed));
    if (ack) EXPECT_FALSE(Codec::verifyAck(*key_, *ack, *request));
  }
  for (std::string_view name : {"ledger_sha256", "boot_nonce"}) {
    auto changed = original;
    const auto f = field(golden::ackFields, name);
    changed.replace(f.offset, f.width, f.width, '\0');
    ASSERT_FALSE(Codec::decodeAck(changed, mac(changed)));
  }
}

TEST_F(TestEcGcControl, MissingAndUnknownNeverBecomeCollectedOrLoseUnknown) {
  auto request = requestFrame(unhex(golden::collectHex));
  ASSERT_OK(request);
  auto verified = verify(*request);
  ASSERT_OK(verified);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_,
                                              *verified,
                                              makeError(StorageCode::kChunkMetadataNotFound),
                                              actual_,
                                              uuid(14),
                                              issued + 2),
               StorageCode::kChunkMetadataNotFound);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_,
                                              *verified,
                                              makeError(StorageCode::kEcSealOutcomeUnknown, "WAL unknown"),
                                              actual_,
                                              uuid(14),
                                              issued + 61),
               StorageCode::kEcSealOutcomeUnknown);
  auto mismatch = receipt_;
  mismatch.claimId = uuid(99);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_, *verified, mismatch, actual_, uuid(14), issued + 2),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_, *verified, receipt_, actual_, uuid(14), issued + 60),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_, *verified, receipt_, actual_, uuid(14), issued + 2, uuid(99)),
               StorageCode::kEcSealOutcomeUnknown);
  auto changed = actual_;
  changed.endpoint.targetIncarnation = uuid(99);
  ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_, *verified, receipt_, changed, uuid(14), issued + 2),
               StorageCode::kEcSealOutcomeUnknown);
  for (const auto &bad : {EcGcLedgerReceipt{},
                          EcGcLedgerReceipt{uuid(1), receipt_.ledgerSha256, 1},
                          EcGcLedgerReceipt{uuid(1), EcSha256{}, 19}}) {
    ASSERT_ERROR(EcGcControlTestAccess::confirm(*key_, *verified, bad, actual_, uuid(14), issued + 2),
                 StorageCode::kEcSealOutcomeUnknown);
  }
}

TEST_F(TestEcGcControl, BinarySerdeFixedBoundsAndRedaction) {
  auto request = requestFrame(unhex(golden::collectHex));
  auto ack = ackFrame(unhex(golden::collectAckHex));
  ASSERT_OK(request);
  ASSERT_OK(ack);
  auto wire = serde::serialize(*request);
  EcGcRequest decoded;
  ASSERT_OK(serde::deserialize(decoded, wire));
  EXPECT_EQ(bytes(Codec::frame(decoded)), bytes(Codec::frame(*request)));
  EcGcAck decodedAck;
  ASSERT_OK(serde::deserialize(decodedAck, serde::serialize(*ack)));
  ASSERT_OK(Codec::verifyAck(*key_, decodedAck, decoded));
  for (uint64_t count : {uint64_t{0}, uint64_t{1}, uint64_t{3}, std::numeric_limits<uint64_t>::max()}) {
    ASSERT_ERROR(serde::deserialize(decoded, serde::serialize(Varint64(count))), StatusCode::kInvalidFormat);
    ASSERT_ERROR(serde::deserialize(decodedAck, serde::serialize(Varint64(count))), StatusCode::kInvalidFormat);
  }
  const auto body = bytes(Codec::encode(request->claims));
  for (size_t size : {size_t{0}, kEcGcRequestBytes - 1, kEcGcRequestBytes + 1}) {
    EXPECT_FALSE(serde::deserialize(decoded, tokenFrame(std::string(size, 'x'), std::string(32, 'y'))));
  }
  for (size_t size : {size_t{0}, size_t{31}, size_t{33}}) {
    EXPECT_FALSE(serde::deserialize(decoded, tokenFrame(body, std::string(size, 'y'))));
  }
  EXPECT_EQ(bytes(Codec::frame(decoded)), bytes(Codec::frame(*request)));
  EXPECT_EQ(bytes(Codec::frame(decodedAck)), bytes(Codec::frame(*ack)));
  EXPECT_EQ(fmt::format("{}", *request), "EcGcRequest(REDACTED)");
  EXPECT_EQ(fmt::format("{}", *ack), "EcGcAck(REDACTED)");
  const auto json = serde::toJsonString(*request);
  EXPECT_EQ(json.find("REDACTED") != std::string::npos, true);
  EXPECT_EQ(json.find(golden::collectHex.substr(golden::collectHex.size() - 64)), std::string::npos);
  EXPECT_FALSE(serde::fromJsonString(decoded, json));
  EXPECT_FALSE(serde::fromJsonString(decodedAck, serde::toJsonString(*ack)));
  EcScopeControlRequest oldControl;
  EcCapability oldData;
  EXPECT_FALSE(serde::deserialize(oldControl, wire));
  EXPECT_FALSE(serde::deserialize(oldData, wire));
}

TEST_F(TestEcGcControl, EmptyAndMaximumFragmentsHaveExactlyFixedSlots) {
  for (size_t length : {size_t{0}, kEcFragmentRpcMaxBytes}) {
    auto c = claims_;
    auto integrity = computeEcIntegrity(c.certificate.fragment, std::string(length, 'e'));
    ASSERT_OK(integrity);
    c.certificate.integrity = *integrity;
    auto request = EcGcControlTestAccess::sign(*key_, c, issued);
    ASSERT_OK(request);
    auto decoded = requestFrame(bytes(Codec::frame(*request)));
    ASSERT_OK(decoded);
    ASSERT_OK(verify(*decoded));
    EXPECT_EQ(decoded->claims.certificate.integrity.blockCount, length == 0 ? 0 : 16);
  }
}

TEST_F(TestEcGcControl, GKeyRequiresExactRawOwnerOnlyRegularFile) {
  for (size_t length : {size_t{31}, size_t{33}}) {
    auto path = writeKey("wrong-size.key", std::string(length, 'x'));
    ASSERT_OK(path);
    EXPECT_FALSE(EcGcKey::loadFile(*path, uuid(10), {}));
  }
  auto zeroPath = writeKey("zero.key", std::string(32, '\0'));
  auto unsafe = writeKey("unsafe.key", std::string(32, 'x'), 0640);
  ASSERT_OK(zeroPath);
  ASSERT_OK(unsafe);
  EXPECT_FALSE(EcGcKey::loadFile(*zeroPath, uuid(10), {}));
  EXPECT_FALSE(EcGcKey::loadFile(*unsafe, uuid(10), {}));
  const auto symlinkPath = directory_.path() / "symlink.key";
  ASSERT_EQ(::symlink((directory_.path() / "gc.key").c_str(), symlinkPath.c_str()), 0);
  EXPECT_FALSE(EcGcKey::loadFile(std::filesystem::path(symlinkPath.string()), uuid(10), {}));
  const auto fifoPath = directory_.path() / "fifo.key";
  ASSERT_EQ(::mkfifo(fifoPath.c_str(), 0600), 0);
  EXPECT_FALSE(EcGcKey::loadFile(std::filesystem::path(fifoPath.string()), uuid(10), {}));
  EXPECT_FALSE(EcGcKey::loadFile({}, uuid(10), {}));
  EXPECT_FALSE(EcGcKey::loadFile(std::filesystem::path((directory_.path() / "gc.key").string()), Uuid::zero(), {}));
}

TEST_F(TestEcGcControl, LoadedRoleIdentityRejectsSameFileAndHardLink) {
  const std::array otherRoles{key_->fileIdentity()};
  const auto original = directory_.path() / "gc.key";
  EXPECT_FALSE(EcGcKey::loadFile(std::filesystem::path(original.string()), uuid(11), otherRoles));
  const auto alias = directory_.path() / "hard-link.key";
  ASSERT_EQ(::link(original.c_str(), alias.c_str()), 0);
  EXPECT_FALSE(EcGcKey::loadFile(std::filesystem::path(alias.string()), uuid(11), otherRoles));
  auto distinct = writeKey("distinct.key", std::string(32, 'g'));
  ASSERT_OK(distinct);
  auto accepted = EcGcKey::loadFile(*distinct, uuid(11), otherRoles);
  ASSERT_OK(accepted);
  EXPECT_NE((*accepted)->fileIdentity(), key_->fileIdentity());
}
}  // namespace
}  // namespace hf3fs::storage
