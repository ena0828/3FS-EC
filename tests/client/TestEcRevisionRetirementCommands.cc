#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/json.h>
#include <fstream>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "client/cli/admin/AdminClientIdentity.h"
#include "client/cli/admin/AdminEnv.h"
#include "client/cli/admin/EcRevisionRetirementCommands.h"
#include "fbs/meta/MockService.h"
#include "fbs/meta/EcFileOutputResolution.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::cli {
namespace {
using folly::coro::blockingWait;

// Only a command/archive protocol fixture. These synthetic closure projections
// are not authenticated Storage ACKs or evidence of an actual Meta commit.
Result<meta::EcFileOutputResolution> resolutionFor(const meta::EcFileOutputIdentity &identity,
                                                    Uuid resolutionId, Uuid confirmer, bool issued) {
  meta::EcFileOutputResolution r;
  r.identity = identity;
  r.resolutionId = resolutionId;
  r.confirmingClientNamespace = confirmer;
  r.birth = Uuid::random();
  r.childEpoch = std::numeric_limits<uint64_t>::max();
  r.issuanceSequence = issued ? std::numeric_limits<uint64_t>::max() : 0;
  r.kind = issued ? meta::EcFileOutputResolutionKind::NeverBoundAfterClose
                  : meta::EcFileOutputResolutionKind::NoIssuanceAfterClose;
  r.executionDigest.fill(21);
  r.candidateReservationsReleaseEligible = true;
  auto &closed = r.outputClosure;
  closed.version = meta::kEcV2LifecycleVersion;
  closed.state = meta::EcV2DrainState::Aborted;
  closed.recordDigest.fill(22);
  auto &id = closed.identity;
  id.object = identity.object;
  id.owner = identity.owner;
  id.kind = storage::EcGrantScope::WriteOperation;
  id.scopeId = identity.child;
  id.objectEpoch = r.childEpoch;
  id.generation = id.revision = std::numeric_limits<uint64_t>::max();
  id.clusterAuthority = Uuid::random();
  id.revocationId = Uuid::random();
  id.endpoints.count = 12;
  std::array<storage::EcScopeEndpoint, 12> endpoints{};
  for (size_t n = 0; n < r.candidates.size(); ++n) {
    auto &a = r.candidates[n];
    a.identity.object = identity.object.incarnation;
    a.identity.stripe = std::numeric_limits<uint64_t>::max();
    a.identity.generation = id.generation;
    a.identity.shard = static_cast<uint16_t>(n);
    a.identity.allocation = Uuid::random();
    a.operation = identity.child;
    a.writer = identity.owner;
    a.endpoint.placement.node = flat::NodeId(static_cast<uint32_t>(n + 1));
    a.endpoint.placement.chain = storage::ChainId(static_cast<uint32_t>(n + 1));
    a.endpoint.placement.target = storage::TargetId(std::numeric_limits<uint64_t>::max() - n);
    a.endpoint.engineUuid = Uuid::random();
    a.endpoint.targetIncarnation = Uuid::random();
    id.endpoints.endpoints[n] = a.endpoint;
    endpoints[n] = a.endpoint.controlEndpoint();
    closed.ackMask |= uint32_t{1} << n;
  }
  CHECK_RESULT(endpointSha, storage::computeEcScopeEndpointDigest(endpoints));
  id.endpoints.digest = endpointSha;
  r.outputClosureDigest = closed.recordDigest;
  CHECK_RESULT(candidateSha, meta::ecFileOutputCandidateDigest(r.candidates));
  r.candidateDigest = candidateSha;
  if (issued) {
    r.sourceKind = meta::EcTreeSlotKind::Data;
    r.sourcePin = Uuid::random();
    r.sourceClosure = closed;
    r.sourceClosure->state = meta::EcV2DrainState::ReadReleased;
    r.sourceClosure->identity.kind = storage::EcGrantScope::ReadPin;
    r.sourceClosure->identity.scopeId = r.sourcePin;
    r.sourceClosure->recordDigest.fill(23);
    r.sourceClosureDigest = r.sourceClosure->recordDigest;
  } else {
    CHECK_RESULT(zeroSha, meta::ecFileOutputZeroSourceDigest(r.identity, r.birth, r.childEpoch));
    r.sourceClosureDigest = zeroSha;
  }
  RETURN_ON_ERROR(r.valid());
  return r;
}

struct Calls {
  std::atomic<size_t> retires{0};
  std::atomic<size_t> queries{0};
  std::atomic<size_t> outputQueries{0};
  std::atomic<size_t> resolutionConfirms{0}, resolutionQueries{0};
  std::atomic<bool> resolutionMissing{false}, resolutionUnknown{false}, resolutionIssued{false};
  std::atomic<int> resolutionMismatch{0};
  Result<meta::EcFileOutputResolution> resolve(const meta::EcFileOutputIdentity &identity,
                                               Uuid resolutionId, Uuid client, bool confirm) {
    std::lock_guard lock(mutex);
    if (!resolution && confirm) {
      CHECK_RESULT(value, resolutionFor(identity, resolutionId, client, resolutionIssued.load()));
      resolution = std::move(value);
    }
    if (!resolution || resolutionMissing) return makeError(MetaCode::kNotFound);
    return *resolution;
  }
  void clearResolution() { std::lock_guard lock(mutex); resolution.reset(); }
  std::atomic<int> mismatch{0};
  std::atomic<bool> missing{false};
  std::atomic<bool> maybeCommitted{false};
  void record(const meta::EcRevisionRetirementReq &req) {
    std::lock_guard lock(mutex);
    last = req;
  }
  std::optional<meta::EcRevisionRetirementReq> snapshot() {
    std::lock_guard lock(mutex);
    return last;
  }

 private:
  std::mutex mutex;
  std::optional<meta::EcRevisionRetirementReq> last;
  std::optional<meta::EcFileOutputResolution> resolution;
};

class RetirementService : public meta::MockMetaService {
 public:
  explicit RetirementService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::ConfirmEcFileOutputResolutionRsp> confirmEcFileOutputResolution(
      serde::CallContext &, const meta::ConfirmEcFileOutputResolutionReq &req) override {
    ++calls_->resolutionConfirms;
    auto value = calls_->resolve(req.identity, req.resolutionId, req.client.uuid, true);
    CO_RETURN_ON_ERROR(value);
    if (calls_->resolutionUnknown) co_return makeError(TransactionCode::kMaybeCommitted);
    co_return resolutionReply<meta::ConfirmEcFileOutputResolutionRsp>(req, *value);
  }
  CoTryTask<meta::QueryEcFileOutputResolutionRsp> queryEcFileOutputResolution(
      serde::CallContext &, const meta::QueryEcFileOutputResolutionReq &req) override {
    ++calls_->resolutionQueries;
    auto value = calls_->resolve(req.identity, req.resolutionId, req.client.uuid, false);
    CO_RETURN_ON_ERROR(value);
    co_return resolutionReply<meta::QueryEcFileOutputResolutionRsp>(req, *value);
  }
  CoTryTask<meta::QueryEcFileOutputRsp> queryEcFileOutput(serde::CallContext &,
                                                         const meta::QueryEcFileOutputReq &req) override {
    ++calls_->outputQueries;
    if (calls_->missing) co_return makeError(MetaCode::kNotFound);
    // Command/archive seam only. The real authorization and durable candidate
    // states are covered separately by TestEcFileNativeWrite over Meta/FDB.
    meta::QueryEcFileOutputRsp rsp;
    rsp.clientNamespace = req.client.uuid;
    rsp.requestId = req.uuid;
    rsp.observation.identity = req.identity;
    rsp.observation.recordDigest.fill(17);
    rsp.observation.generation = std::numeric_limits<uint64_t>::max();
    rsp.observation.candidates[0].identity.generation = std::numeric_limits<uint64_t>::max();
    rsp.observation.candidates[0].endpoint.placement.target = storage::TargetId(std::numeric_limits<uint64_t>::max());
    if (calls_->mismatch) rsp.observation.identity.parent = Uuid::random();
    co_return rsp;
  }
  CoTryTask<meta::EcRevisionRetirementRsp> retireEcRevisionV2(serde::CallContext &,
                                                              const meta::RetireEcRevisionV2Req &req) override {
    calls_->record(req);
    if (++calls_->retires == 1) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    // A hidden automatic retry would return success and fail the single-call test.
    co_return completed(req);
  }
  CoTryTask<meta::EcRevisionRetirementRsp> queryEcRevisionRetirementV2(
      serde::CallContext &,
      const meta::QueryEcRevisionRetirementV2Req &req) override {
    calls_->record(req);
    ++calls_->queries;
    if (calls_->maybeCommitted) co_return makeError(TransactionCode::kMaybeCommitted);
    if (calls_->missing) co_return makeError(StatusCode::kKVStoreNotFound);
    auto rsp = completed(req);
    switch (calls_->mismatch.load()) {
      case 1:
        rsp.object.incarnation = Uuid::random();
        break;
      case 2:
        rsp.stripe = 0;
        break;
      case 3:
        rsp.revision = 0;
        break;
      case 4:
        rsp.generation = 0;
        break;
      case 5:
        rsp.clientNamespace = Uuid::random();
        break;
      case 6:
        rsp.requestId = Uuid::random();
        break;
      case 7:
        rsp.referencesReleased = false;
        break;
      default:
        break;
    }
    co_return rsp;
  }

 private:
  template <class Response, class Request>
  Response resolutionReply(const Request &req, const meta::EcFileOutputResolution &value) {
    Response rsp;
    rsp.clientNamespace = req.client.uuid;
    rsp.requestId = req.uuid;
    rsp.resolution = value;
    auto &r = rsp.resolution;
    switch (calls_->resolutionMismatch.load()) {
      case 1: rsp.clientNamespace = Uuid::random(); break;
      case 2: rsp.requestId = Uuid::random(); break;
      case 3: r.resolutionId = Uuid::random(); break;
      case 4: r.identity.parent = Uuid::random(); break;
      case 5: r.confirmingClientNamespace = Uuid::random(); break;
      case 6: r.version = 2; break;
      case 7: r.candidates[0].identity.shard = 1; break;
      case 8: r.candidateDigest[0] ^= 1; break;
      case 9: r.issuanceSequence = r.issuanceSequence ? 0 : 1; break;
      case 10: r.candidateReservationsReleaseEligible = false; break;
      case 11: r.collected = true; break;
      case 12: r.physicalReclamationConfirmed = true; break;
      case 13: r.outputClosure.ackMask = 0; break;
      case 14: r.sourceClosureDigest[0] ^= 1; break;
      case 15:
        if (r.sourceClosure) r.sourceClosure->identity.clusterAuthority = Uuid::random();
        break;
      default: break;
    }
    return rsp;
  }
  static meta::EcRevisionRetirementRsp completed(const meta::EcRevisionRetirementReq &req) {
    meta::EcRevisionRetirementRsp rsp;
    rsp.object = req.object;
    rsp.stripe = req.stripe;
    rsp.revision = req.revision;
    rsp.generation = std::numeric_limits<uint64_t>::max();
    rsp.clientNamespace = req.client.uuid;
    rsp.requestId = req.uuid;
    rsp.referencesReleased = true;
    return rsp;
  }
  std::shared_ptr<Calls> calls_;
};

class TestEcRevisionRetirementCommands : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK(blockingWait(registerEcRevisionRetirementHandlers(dispatcher_)));
    config_.set_network_type(net::Address::TCP);
    // Keep normal retries enabled; the actual 40/41 entry points choose once.
    config_.retry_default().set_retry_init_wait(1_ms);
    config_.retry_default().set_retry_total_time(1_s);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    client_ = newClient(namespace_);
    env_.userInfo = {flat::Uid{0}, flat::Gid{0}, "test-token-not-for-an-actual-server"};
    env_.metaClientGetter = [&] {
      ++getters_;
      return client_;
    };
  }
  std::shared_ptr<meta::client::MetaClient> newClient(const Uuid &clientNamespace) {
    const auto configured = makeAdminClientId(clientNamespace.toHexString());
    EXPECT_TRUE(configured);
    if (!configured) return nullptr;
    serde::ClientMockContext context;
    context.setService(std::make_unique<RetirementService>(calls_));
    return std::make_shared<meta::client::MetaClient>(*configured,
                                                      config_,
                                                      std::make_unique<meta::client::MetaClient::StubFactory>(context),
                                                      mgmtd_,
                                                      nullptr,
                                                      false);
  }
  Dispatcher::Args args(std::string command, const std::string &file) const {
    return {std::move(command),
            "--inode",
            std::to_string(meta::InodeId::normalMax().u64()),
            "--object-incarnation",
            object_.toHexString(),
            "--stripe",
            "18446744073709551615",
            "--revision",
            "18446744073709551615",
            "--client-namespace",
            namespace_.toHexString(),
            "--request-id",
            request_.toHexString(),
            "--output",
            file};
  }
  Dispatcher::Args resolutionArgs(bool confirm, const std::string &file) const {
    return {confirm ? "ec-confirm-file-output-resolution" : "ec-query-file-output-resolution",
            "--inode", std::to_string(meta::InodeId::normalMax().u64()),
            "--object-incarnation", object_.toHexString(), "--owner-uid", "1000",
            "--owner-client", resolutionOwner_.toHexString(), "--parent", resolutionParent_.toHexString(),
            "--child", resolutionChild_.toHexString(), "--owner-kind", "pwrite",
            "--resolution-id", resolutionId_.toHexString(), "--client-namespace", namespace_.toHexString(),
            "--request-id", request_.toHexString(), "--output", file};
  }
  static void replace(Dispatcher::Args &arguments, std::string_view key, std::string value) {
    auto found = std::find(arguments.begin(), arguments.end(), key);
    ASSERT_NE(found, arguments.end());
    *++found = std::move(value);
  }
  std::vector<folly::dynamic> read(const std::string &file) const {
    std::ifstream input(file);
    std::vector<folly::dynamic> result;
    std::string line;
    while (std::getline(input, line)) result.push_back(folly::parseJson(line));
    return result;
  }
  std::string path(std::string_view file) const { return (temp_.path() / std::string(file)).string(); }
  folly::test::TemporaryDirectory temp_;
  Dispatcher dispatcher_;
  AdminEnv env_;
  meta::client::MetaClient::Config config_;
  std::shared_ptr<Calls> calls_ = std::make_shared<Calls>();
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<meta::client::MetaClient> client_;
  size_t getters_ = 0;
  Uuid namespace_ = Uuid::random(), object_ = Uuid::random(), request_ = Uuid::random();
  Uuid resolutionOwner_ = Uuid::random(), resolutionParent_ = Uuid::random(),
       resolutionChild_ = Uuid::random(), resolutionId_ = Uuid::random();
};

TEST_F(TestEcRevisionRetirementCommands, ResolutionUnknownRetainsOriginalIdsAndQueryNeverConfirmsMissing) {
  calls_->resolutionUnknown = true;
  const auto confirmPath = path("resolution-unknown.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, resolutionArgs(true, confirmPath))), TransactionCode::kMaybeCommitted);
  EXPECT_EQ(calls_->resolutionConfirms.load(), 1);
  auto original = read(confirmPath);
  ASSERT_EQ(original.size(), 2);
  EXPECT_EQ(original[0]["phase"], "prepared");
  EXPECT_EQ(original[0]["resolution_id"], resolutionId_.toHexString());
  EXPECT_EQ(original[1]["outcome"], "unknown");
  EXPECT_TRUE(original[1]["resolution"].isNull());
  EXPECT_FALSE(original[1]["candidate_reservations_release_eligible"].asBool());
  EXPECT_FALSE(original[1]["collected"].asBool());
  EXPECT_FALSE(original[1]["physical_reclamation_confirmed"].asBool());
  calls_->resolutionMissing = true;
  const auto missingPath = path("resolution-missing.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, resolutionArgs(false, missingPath))), MetaCode::kNotFound);
  EXPECT_EQ(calls_->resolutionConfirms.load(), 1);
  EXPECT_EQ(calls_->resolutionQueries.load(), 1);
  const auto missing = read(missingPath);
  ASSERT_EQ(missing.size(), 2);
  EXPECT_EQ(missing[1]["outcome"], "not_observed");
  EXPECT_TRUE(missing[1]["resolution"].isNull());
  EXPECT_FALSE(missing[1]["candidate_reservations_release_eligible"].asBool());
  calls_->resolutionMissing = false;
  // A reconstructed management client may query the original resolution under
  // a different namespace. It must not overwrite its stored confirming owner.
  const auto reader = Uuid::random();
  client_ = newClient(reader);
  const auto queryPath = path("resolution-query.jsonl");
  auto query = resolutionArgs(false, queryPath);
  replace(query, "--client-namespace", reader.toHexString());
  replace(query, "--request-id", Uuid::random().toHexString());
  ASSERT_OK(blockingWait(dispatcher_.run(env_, query)));
  EXPECT_EQ(calls_->resolutionConfirms.load(), 1);
  EXPECT_EQ(calls_->resolutionQueries.load(), 2);
  const auto observed = read(queryPath);
  ASSERT_EQ(observed.size(), 2);
  const auto &result = observed[1];
  EXPECT_EQ(result["outcome"], "observed");
  EXPECT_EQ(result["client_namespace"], reader.toHexString());
  EXPECT_EQ(result["resolution"]["confirmingClientNamespace"], namespace_.toHexString());
  EXPECT_EQ(result["resolution"]["resolutionId"], resolutionId_.toHexString());
  EXPECT_EQ(result["identity"]["parent"], resolutionParent_.toHexString());
  EXPECT_EQ(result["identity"]["child"], resolutionChild_.toHexString());
  EXPECT_EQ(result["resolution"]["childEpoch"], "18446744073709551615");
  EXPECT_EQ(result["resolution"]["issuanceSequence"], "0");
  EXPECT_EQ(result["resolution"]["candidates"][0]["identity"]["stripe"], "18446744073709551615");
  EXPECT_EQ(result["resolution"]["candidates"][0]["endpoint"]["placement"]["target"], "18446744073709551615");
  EXPECT_EQ(result["resolution"]["outputClosure"]["identity"]["objectEpoch"], "18446744073709551615");
  EXPECT_TRUE(result["candidate_reservations_release_eligible"].asBool());
  EXPECT_FALSE(result["collected"].asBool());
  EXPECT_FALSE(result["physical_reclamation_confirmed"].asBool());
  EXPECT_TRUE(result["resolution"]["sourceClosure"].isNull());
  EXPECT_EQ(read(confirmPath), original);
}

TEST_F(TestEcRevisionRetirementCommands, ResolutionChecksCompleteDtoAndArchivesBothKindsWithoutCollectionClaim) {
  for (bool issued : {false, true}) {
    SCOPED_TRACE(issued);
    calls_->clearResolution();
    calls_->resolutionIssued = issued;
    calls_->resolutionMismatch = 0;
    const auto prefix = issued ? "issued" : "never-issued";
    const auto confirmedPath = path(fmt::format("{}-confirm.jsonl", prefix));
    ASSERT_OK(blockingWait(dispatcher_.run(env_, resolutionArgs(true, confirmedPath))));
    const auto confirmed = read(confirmedPath);
    ASSERT_EQ(confirmed.size(), 2);
    EXPECT_EQ(confirmed[1]["outcome"], "confirmed");
    EXPECT_TRUE(confirmed[1]["metadata_resolution_only"].asBool());
    EXPECT_TRUE(confirmed[1]["candidate_reservations_release_eligible"].asBool());
    EXPECT_FALSE(confirmed[1]["collected"].asBool());
    EXPECT_FALSE(confirmed[1]["resolution"]["collected"].asBool());
    EXPECT_FALSE(confirmed[1]["resolution"]["physicalReclamationConfirmed"].asBool());
    if (issued) {
      EXPECT_EQ(confirmed[1]["resolution"]["issuanceSequence"], "18446744073709551615");
      EXPECT_EQ(confirmed[1]["resolution"]["sourceClosure"]["identity"]["revision"], "18446744073709551615");
      EXPECT_EQ(confirmed[1]["resolution"]["sourceClosure"]["identity"]["endpoints"]["endpoints"][0]
                         ["placement"]["target"], "18446744073709551615");
    }
    const auto replayPath = path(fmt::format("{}-replay.jsonl", prefix));
    auto replay = resolutionArgs(true, replayPath);
    replace(replay, "--request-id", Uuid::random().toHexString());
    ASSERT_OK(blockingWait(dispatcher_.run(env_, replay)));
    EXPECT_EQ(read(replayPath)[1]["resolution"], confirmed[1]["resolution"]);
    for (int mismatch = 1; mismatch <= (issued ? 15 : 14); ++mismatch) {
      SCOPED_TRACE(mismatch);
      calls_->resolutionMismatch = mismatch;
      const auto badPath = path(fmt::format("{}-bad-{}.jsonl", prefix, mismatch));
      ASSERT_ERROR(blockingWait(dispatcher_.run(env_, resolutionArgs(true, badPath))), StorageClientCode::kProtocolMismatch);
      const auto rejected = read(badPath);
      ASSERT_EQ(rejected.size(), 2);
      EXPECT_EQ(rejected[1]["outcome"], "unknown");
      EXPECT_TRUE(rejected[1]["resolution"].isNull());
      EXPECT_FALSE(rejected[1]["candidate_reservations_release_eligible"].asBool());
    }
    calls_->resolutionMismatch = 0;
    struct stat info {};
    ASSERT_EQ(::stat(confirmedPath.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0600);
    std::ifstream input(confirmedPath);
    const std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    EXPECT_EQ(raw.find(env_.userInfo.token), std::string::npos);
    EXPECT_EQ(raw.find("capability"), std::string::npos);
  }
}

TEST_F(TestEcRevisionRetirementCommands, ResolutionUsageAndExclusiveArchiveFailuresDoNotDispatch) {
  const auto existing = path("resolution-exclusive.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, resolutionArgs(true, existing))));
  const auto before = read(existing);
  const auto calls = calls_->resolutionConfirms.load();
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, resolutionArgs(true, existing))), StatusCode::kIOError);
  EXPECT_EQ(read(existing), before);
  for (const auto &[flag, value] : std::array<std::pair<const char *, const char *>, 4>{
         {{"--resolution-id", "00000000-0000-0000-0000-000000000000"},
          {"--owner-uid", "4294967296"}, {"--owner-kind", "session"}, {"--inode", "0"}}}) {
    auto invalid = resolutionArgs(true, path("invalid-resolution.jsonl"));
    replace(invalid, flag, value);
    EXPECT_FALSE(blockingWait(dispatcher_.run(env_, invalid)));
    EXPECT_FALSE(std::filesystem::exists(path("invalid-resolution.jsonl")));
  }
  auto invalidPath = resolutionArgs(true, path("nul-resolution.jsonl"));
  replace(invalidPath, "--output", path("nul-resolution.jsonl") + std::string("\0suffix", 7));
  EXPECT_FALSE(blockingWait(dispatcher_.run(env_, invalidPath)));
  EXPECT_FALSE(std::filesystem::exists(path("nul-resolution.jsonl")));
  client_ = newClient(Uuid::random());
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, resolutionArgs(true, path("namespace-resolution.jsonl")))),
               StatusCode::kInvalidArg);
  const auto prepared = read(path("namespace-resolution.jsonl"));
  ASSERT_EQ(prepared.size(), 1);
  EXPECT_EQ(prepared[0]["phase"], "prepared");
  EXPECT_EQ(prepared[0]["resolution_id"], resolutionId_.toHexString());
  EXPECT_EQ(calls_->resolutionConfirms.load(), calls);
  EXPECT_EQ(calls_->resolutionQueries.load(), 0);
}

TEST_F(TestEcRevisionRetirementCommands, OutputObservationArchivesMissingAndChecksFixedIdentity) {
  const auto owner = Uuid::random(), parent = Uuid::random(), child = Uuid::random();
  auto command = [&](const std::string &output) -> Dispatcher::Args {
    return {"ec-observe-file-output", "--inode", std::to_string(meta::InodeId::normalMax().u64()),
            "--object-incarnation", object_.toHexString(), "--owner-uid", "702", "--owner-client", owner.toHexString(),
            "--parent", parent.toHexString(), "--child", child.toHexString(), "--owner-kind", "pwrite",
            "--client-namespace", namespace_.toHexString(), "--request-id", request_.toHexString(), "--output", output};
  };
  calls_->missing = true;
  const auto missingPath = path("missing-output.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, command(missingPath))), MetaCode::kNotFound);
  EXPECT_EQ(calls_->outputQueries.load(), 1);
  const auto absent = read(missingPath);
  ASSERT_EQ(absent.size(), 2);
  EXPECT_EQ(absent[0]["phase"].asString(), "prepared");
  EXPECT_EQ(absent[1]["outcome"].asString(), "not_observed");
  EXPECT_TRUE(absent[1]["observation"].isNull());
  EXPECT_FALSE(absent[1]["physical_reclamation_confirmed"].asBool());
  EXPECT_EQ(absent[1]["identity"]["owner"]["client"].asString(), owner.toHexString());
  EXPECT_EQ(absent[1]["identity"]["parent"].asString(), parent.toHexString());
  EXPECT_EQ(absent[1]["identity"]["child"].asString(), child.toHexString());
  const auto before = read(missingPath);
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, command(missingPath))), StatusCode::kIOError);
  EXPECT_EQ(calls_->outputQueries.load(), 1);
  EXPECT_EQ(read(missingPath), before);
  calls_->missing = false;
  calls_->mismatch = 1;
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, command(path("changed-output.jsonl")))),
               StorageClientCode::kProtocolMismatch);
  calls_->mismatch = 0;
  const auto observedPath = path("observed-output.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, command(observedPath))));
  const auto observed = read(observedPath);
  ASSERT_EQ(observed.size(), 2);
  EXPECT_EQ(observed[1]["outcome"].asString(), "observed");
  EXPECT_TRUE(observed[1]["metadata_observation_only"].asBool());
  EXPECT_EQ(observed[1]["identity"]["object"]["inode"].asString(), std::to_string(meta::InodeId::normalMax().u64()));
  EXPECT_EQ(observed[1]["observation"]["generation"].asString(), "18446744073709551615");
  EXPECT_EQ(observed[1]["observation"]["candidates"][0]["identity"]["generation"].asString(), "18446744073709551615");
  EXPECT_EQ(observed[1]["observation"]["candidates"][0]["endpoint"]["placement"]["target"].asString(), "18446744073709551615");
  EXPECT_FALSE(observed[1]["observation"]["outputT2Confirmed"].asBool());
  EXPECT_FALSE(observed[1]["observation"]["physicalReclamationConfirmed"].asBool());
  struct stat info {};
  ASSERT_EQ(::stat(observedPath.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
  std::ifstream raw(observedPath);
  const std::string text((std::istreambuf_iterator<char>(raw)), std::istreambuf_iterator<char>());
  EXPECT_EQ(text.find(env_.userInfo.token), std::string::npos);
  auto invalid = command(path("invalid-output.jsonl"));
  replace(invalid, "--owner-uid", "4294967296");
  const auto calls = calls_->outputQueries.load();
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, invalid)), StatusCode::kInvalidArg);
  EXPECT_EQ(calls_->outputQueries.load(), calls);
  EXPECT_FALSE(std::filesystem::exists(path("invalid-output.jsonl")));
}

TEST_F(TestEcRevisionRetirementCommands, UnknownHasOneCallAndReconstructedClientQueriesOriginalIdentity) {
  const auto retiredPath = path("retire.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-retire-revision", retiredPath))),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(calls_->retires.load(), 1);
  const auto original = calls_->snapshot();
  ASSERT_TRUE(original);
  EXPECT_EQ(original->client.uuid, namespace_);
  EXPECT_EQ(original->uuid, request_);
  EXPECT_EQ(original->stripe, std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(original->revision, std::numeric_limits<uint64_t>::max());
  auto records = read(retiredPath);
  ASSERT_EQ(records.size(), 2);
  EXPECT_EQ(records[0]["phase"].asString(), "prepared");
  EXPECT_EQ(records[0]["client_namespace"].asString(), namespace_.toHexString());
  EXPECT_EQ(records[0]["request_id"].asString(), request_.toHexString());
  EXPECT_EQ(records[0]["revision_decimal"].asString(), "18446744073709551615");
  EXPECT_EQ(records[1]["outcome"].asString(), "unknown");
  EXPECT_FALSE(records[1]["references_released"].asBool());
  struct stat info {};
  ASSERT_EQ(::stat(retiredPath.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
  std::ifstream raw(retiredPath);
  const std::string text((std::istreambuf_iterator<char>(raw)), std::istreambuf_iterator<char>());
  EXPECT_EQ(text.find(env_.userInfo.token), std::string::npos);

  // Reconstruct the actual MetaClient with the same config-derived namespace;
  // this exercises retry's overwrite of req.client, not a command-only field.
  client_.reset();
  client_ = newClient(namespace_);
  ASSERT_NE(client_, nullptr);
  const auto queriedPath = path("query.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-query-revision-retirement", queriedPath))));
  ASSERT_EQ(calls_->retires.load(), 1);
  ASSERT_EQ(calls_->queries.load(), 1);
  const auto queried = calls_->snapshot();
  ASSERT_TRUE(queried);
  EXPECT_EQ(queried->client.uuid, original->client.uuid);
  EXPECT_EQ(queried->uuid, original->uuid);
  EXPECT_EQ(queried->object, original->object);
  EXPECT_EQ(queried->stripe, original->stripe);
  EXPECT_EQ(queried->revision, original->revision);
  auto confirmed = read(queriedPath);
  ASSERT_EQ(confirmed.size(), 2);
  EXPECT_EQ(confirmed[1]["outcome"].asString(), "confirmed");
  EXPECT_EQ(confirmed[1]["generation_decimal"].asString(), "18446744073709551615");
  EXPECT_TRUE(confirmed[1]["references_released"].asBool());
}

TEST_F(TestEcRevisionRetirementCommands, ActualClientNamespaceMismatchNeverDispatches) {
  auto selected = makeAdminClientId(namespace_.toHexString());
  ASSERT_OK(selected);
  EXPECT_EQ(selected->uuid, namespace_);
  auto random = makeAdminClientId("");
  ASSERT_OK(random);
  EXPECT_FALSE(random->uuid.is_nil());
  for (auto invalid : {"00000000-0000-0000-0000-000000000000", "not-a-uuid", " 12345678-1234-1234-1234-123456789abc"})
    ASSERT_ERROR(makeAdminClientId(invalid), StatusCode::kInvalidArg);
  client_ = newClient(Uuid::random());
  const auto output = path("namespace-mismatch.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-retire-revision", output))), StatusCode::kInvalidArg);
  EXPECT_EQ(getters_, 1);
  EXPECT_EQ(calls_->retires.load() + calls_->queries.load(), 0);
  auto records = read(output);
  ASSERT_EQ(records.size(), 1);
  EXPECT_EQ(records[0]["phase"].asString(), "prepared");
  EXPECT_EQ(records[0]["client_namespace"].asString(), namespace_.toHexString());
}

TEST_F(TestEcRevisionRetirementCommands, InvalidNumbersExistingOutputAndNonRootDoNotObtainMetaClient) {
  const auto existing = path("existing.jsonl");
  {
    std::ofstream out(existing);
    out << "preserve-me\n";
  }
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, args("ec-retire-revision", existing))));
  std::ifstream input(existing);
  std::string preserved;
  std::getline(input, preserved);
  EXPECT_EQ(preserved, "preserve-me");
  for (const auto &[key, value] : std::array<std::pair<std::string_view, std::string_view>, 8>{
           {{"--inode", "-1"},
            {"--inode", "0"},
            {"--revision", "18446744073709551616"},
            {"--revision", "0"},
            {"--stripe", "1.0"},
            {"--stripe", "+1"},
            {"--request-id", "00000000-0000-0000-0000-000000000000"},
            {"--client-namespace", "00000000-0000-0000-0000-000000000000"}}}) {
    auto command = args("ec-query-revision-retirement", path("invalid.jsonl"));
    replace(command, key, std::string(value));
    ASSERT_FALSE(blockingWait(dispatcher_.run(env_, command)));
  }
  env_.userInfo.uid = flat::Uid{1};
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-revision-retirement", path("nonroot.jsonl")))),
               StatusCode::kAuthenticationFail);
  EXPECT_EQ(getters_, 0);
  EXPECT_EQ(calls_->retires.load() + calls_->queries.load(), 0);
  EXPECT_FALSE(std::filesystem::exists(path("invalid.jsonl")));
}

TEST_F(TestEcRevisionRetirementCommands, WholeResponseMustMatchAndMissingIsNotConfirmation) {
  for (int mismatch = 1; mismatch <= 7; ++mismatch) {
    calls_->mismatch = mismatch;
    const auto output = path("mismatch-" + std::to_string(mismatch) + ".jsonl");
    ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-revision-retirement", output))),
                 StorageClientCode::kProtocolMismatch);
    auto records = read(output);
    ASSERT_EQ(records.size(), 2);
    EXPECT_EQ(records[1]["outcome"].asString(), "not_confirmed");
    EXPECT_FALSE(records[1]["references_released"].asBool());
    EXPECT_TRUE(records[1]["generation_decimal"].asString().empty());
  }
  calls_->mismatch = 0;
  calls_->missing = true;
  const auto missing = path("missing.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-revision-retirement", missing))),
               StatusCode::kKVStoreNotFound);
  EXPECT_EQ(calls_->queries.load(), 8);
  auto records = read(missing);
  ASSERT_EQ(records.size(), 2);
  EXPECT_EQ(records[1]["outcome"].asString(), "not_confirmed");
  EXPECT_FALSE(records[1]["references_released"].asBool());
  EXPECT_EQ(records[1]["request_id"].asString(), request_.toHexString());
  calls_->maybeCommitted = true;
  const auto uncertain = path("maybe-committed.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-revision-retirement", uncertain))),
               TransactionCode::kMaybeCommitted);
  EXPECT_EQ(calls_->queries.load(), 9);
  auto unknown = read(uncertain);
  ASSERT_EQ(unknown.size(), 2);
  EXPECT_EQ(unknown[1]["outcome"].asString(), "unknown");
  EXPECT_FALSE(unknown[1]["references_released"].asBool());
}
}  // namespace
}  // namespace hf3fs::client::cli
