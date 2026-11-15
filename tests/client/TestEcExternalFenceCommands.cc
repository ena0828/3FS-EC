#include <algorithm>
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
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "client/cli/admin/AdminClientIdentity.h"
#include "client/cli/admin/AdminEnv.h"
#include "client/cli/admin/EcExternalFenceCommands.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::cli {
namespace {
using folly::coro::blockingWait;

struct Calls {
  std::atomic<size_t> prepares{0}, queries{0};
  std::atomic<unsigned> mismatch{0};
  std::atomic<bool> prepared{false}, loseImportAck{false};
  std::string proof = std::string(meta::kEcHostFenceCertificateBytes, 'x');
  std::atomic<uint32_t> queryError{0};
  void record(const meta::EcTargetRetirementReq &request) {
    std::lock_guard lock(mutex);
    last = request;
  }
  std::optional<meta::EcTargetRetirementReq> snapshot() {
    std::lock_guard lock(mutex);
    return last;
  }
 private:
  std::mutex mutex;
  std::optional<meta::EcTargetRetirementReq> last;
};

// Tests the CLI/real MetaClient dispatch contract only. This mock does not
// establish provider authentication, OS isolation, FDB persistence or Storage retirement.
class ExternalFenceService : public meta::MockMetaService {
 public:
  explicit ExternalFenceService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::EcTargetRetirementRsp> prepareEcTargetRetirement(
      serde::CallContext &, const meta::PrepareEcTargetRetirementReq &req) override {
    calls_->record(req);
    ++calls_->prepares;
    if (calls_->loseImportAck.exchange(false)) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    co_return response(req); // A hidden retry would wrongly turn the lost reply into success.
  }
  CoTryTask<meta::EcTargetRetirementRsp> queryEcTargetRetirement(
      serde::CallContext &, const meta::QueryEcTargetRetirementReq &req) override {
    calls_->record(req);
    ++calls_->queries;
    if (const auto error = calls_->queryError.load()) co_return makeError(error);
    auto value = response(req);
    switch (calls_->mismatch.load()) {
      case 1: value.intent.endpoint.engineUuid = Uuid::random(); break;
      case 2: value.intent.endpoint.targetIncarnation = Uuid::random(); break;
      case 3: value.intent.retirementId = Uuid::random(); break;
      case 4: value.intent.owner.client = Uuid::random(); break;
      case 5: value.intent.requestId = Uuid::random(); break;
      case 6: value.mode = meta::EcTargetRetirementMode::Cooperative; break;
      case 7: value.stage = meta::EcTargetRetirementStage::Completed; break;
      case 8: value.externalBinding->providerId = Uuid::random(); break;
      case 9: value.externalBinding->resourceGeneration = Uuid::random(); break;
      case 10: value.externalBinding->bindingDigest.fill(0); break;
      case 11: value.external.reset(); break;
      case 12: value.external->sequence = 2; break;
      case 13: value.external->denyDigest.fill(0); break;
      case 14: value.external->providerId = Uuid::random(); break;
      case 15: value.completionDigest.fill(0); break;
      case 16: value.intent.version = 1; break;
      case 17: value.external->proofDigest.fill(0); break;
      case 18: value.externalBinding.reset(); break;
      default: break;
    }
    co_return value;
  }
 private:
  meta::EcTargetRetirementRsp response(const meta::EcTargetRetirementReq &req) const {
    meta::EcTargetRetirementRsp value;
    value.mode = meta::EcTargetRetirementMode::HostExecutionFence;
    value.externalBinding = req.externalBinding;
    value.intent.version = 2;
    value.intent.endpoint = req.endpoint;
    value.intent.authority = Uuid::from(201, 202);
    value.intent.retirementId = req.retirementId;
    value.intent.owner.uid = req.user.uid;
    value.intent.owner.client = req.client.uuid;
    value.intent.requestId = req.uuid;
    value.stage = calls_->prepared ? meta::EcTargetRetirementStage::Prepared : meta::EcTargetRetirementStage::HostExecutionFenced;
    if (!calls_->prepared) {
      value.completionDigest.fill(0x5a);
      meta::EcHostFenceSummary proof;
      proof.providerId = req.externalBinding->providerId;
      proof.enrollmentId = req.externalBinding->enrollmentId;
      proof.resourceGeneration = req.externalBinding->resourceGeneration;
      proof.bindingDigest = req.externalBinding->bindingDigest;
      proof.denyDigest.fill(0x6b);
      proof.sequence = 1;
      unsigned length = 0;
      EXPECT_EQ(EVP_Digest(calls_->proof.data(), calls_->proof.size(), proof.proofDigest.data(), &length,
                          EVP_sha256(), nullptr), 1);
      EXPECT_EQ(length, proof.proofDigest.size());
      EXPECT_TRUE(proof.valid());
      value.external = proof;
    }
    return value;
  }
  std::shared_ptr<Calls> calls_;
};

class TestEcExternalFenceCommands : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK(blockingWait(registerEcExternalFenceHandlers(dispatcher_)));
    config_.set_network_type(net::Address::TCP);
    config_.retry_default().set_retry_init_wait(1_ms);
    config_.retry_default().set_retry_total_time(1_s);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    client_ = newClient(namespace_);
    env_.userInfo = {flat::Uid(0), flat::Gid(0), "mock-token-never-for-real-authentication"};
    env_.metaClientGetter = [&] { ++getters_; return client_; };
  }
  std::shared_ptr<meta::client::MetaClient> newClient(const Uuid &id) {
    auto configured = makeAdminClientId(id.toHexString());
    EXPECT_TRUE(configured);
    if (!configured) return nullptr;
    serde::ClientMockContext context;
    context.setService(std::make_unique<ExternalFenceService>(calls_));
    return std::make_shared<meta::client::MetaClient>(*configured,
                                                      config_,
                                                      std::make_unique<meta::client::MetaClient::StubFactory>(context),
                                                      mgmtd_,
                                                      nullptr,
                                                      false);
  }
  Dispatcher::Args args(std::string command, const std::string &file) const {
    return {std::move(command), "--node-id", "4294967295", "--chain-id", "4294967295",
            "--target-id", "18446744073709551615", "--engine-uuid", engine_.toHexString(),
            "--target-incarnation", incarnation_.toHexString(), "--retirement-id", retirement_.toHexString(),
            "--client-namespace", namespace_.toHexString(), "--request-id", request_.toHexString(), "--output", file,
            "--provider-id", provider_.toHexString(), "--enrollment-id", enrollment_.toHexString(),
            "--resource-generation", generation_.toHexString(), "--binding-sha256", std::string(64, 'a')};
  }
  static void replace(Dispatcher::Args &arguments, std::string_view key, std::string value) {
    auto found = std::find(arguments.begin(), arguments.end(), key);
    ASSERT_NE(found, arguments.end());
    *++found = std::move(value);
  }
  std::string path(std::string_view name) const { return (directory_.path() / std::string(name)).string(); }
  std::vector<folly::dynamic> read(const std::string &file) const {
    std::ifstream input(file);
    std::vector<folly::dynamic> rows;
    for (std::string line; std::getline(input, line);) rows.push_back(folly::parseJson(line));
    return rows;
  }
  folly::test::TemporaryDirectory directory_;
  Dispatcher dispatcher_;
  AdminEnv env_;
  meta::client::MetaClient::Config config_;
  std::shared_ptr<Calls> calls_ = std::make_shared<Calls>();
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<meta::client::MetaClient> client_;
  size_t getters_ = 0;
  Uuid namespace_ = Uuid::random(), engine_ = Uuid::random(), incarnation_ = Uuid::random();
  Uuid retirement_ = Uuid::random(), request_ = Uuid::random();
  Uuid provider_ = Uuid::random(), enrollment_ = Uuid::random(), generation_ = Uuid::random();
  std::string writeProof(std::string name, const std::string &bytes) {
    const auto file = path(name);
    std::ofstream stream(file, std::ios::binary);
    stream.write(bytes.data(), bytes.size());
    stream.close();
    return file;
  }
};


TEST_F(TestEcExternalFenceCommands, PreparedBindingDoesNotClaimFencingOrPhysicalRelease) {
  calls_->prepared = true;
  const auto file = path("prepared.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-prepare-external-fence", file))));
  ASSERT_EQ(calls_->prepares.load(), 1u);
  auto request = calls_->snapshot();
  ASSERT_TRUE(request);
  EXPECT_EQ(request->mode, meta::EcTargetRetirementMode::HostExecutionFence);
  ASSERT_TRUE(request->externalBinding);
  EXPECT_EQ(request->externalBinding->providerId, provider_);
  EXPECT_EQ(request->externalBinding->resourceGeneration, generation_);
  EXPECT_TRUE(request->externalEvidence.empty());
  auto rows = read(file);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[0]["phase"].asString(), "prepared");
  EXPECT_EQ(rows[1]["outcome"].asString(), "intent_accepted");
  EXPECT_TRUE(rows[1]["meta_intent_confirmed"].asBool());
  EXPECT_EQ(rows[1]["target_decimal"].asString(), "18446744073709551615");
  for (const auto *key : {"host_execution_fenced", "cooperative_data_drained", "physical_capacity_returned"})
    EXPECT_FALSE(rows[1][key].asBool());
  EXPECT_TRUE(rows[1]["completion_sha256"].asString().empty());
  EXPECT_TRUE(rows[1]["evidence_sha256"].asString().empty());
}

TEST_F(TestEcExternalFenceCommands, LostImportReplyQueriesSameIdentityWithoutHiddenRetry) {
  const auto evidence = writeProof("proof.bin", calls_->proof);
  auto command = args("ec-import-external-fence", path("unknown.jsonl"));
  command.insert(command.end(), {"--evidence", evidence});
  calls_->loseImportAck = true;
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, command)), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(calls_->prepares.load(), 1u);
  auto imported = calls_->snapshot();
  ASSERT_TRUE(imported);
  EXPECT_EQ(imported->externalEvidence, calls_->proof);
  auto rows = read(path("unknown.jsonl"));
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "unknown");
  EXPECT_FALSE(rows[1]["host_execution_fenced"].asBool());
  EXPECT_EQ(rows[0]["evidence_sha256"].asString().size(), 64);
  client_ = newClient(namespace_);
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-query-external-fence", path("query.jsonl")))));
  EXPECT_EQ(calls_->prepares.load(), 1u);
  EXPECT_EQ(calls_->queries.load(), 1u);
  auto queried = calls_->snapshot();
  ASSERT_TRUE(queried);
  EXPECT_TRUE(queried->externalEvidence.empty());
  EXPECT_EQ(queried->uuid, imported->uuid);
  EXPECT_EQ(queried->retirementId, imported->retirementId);
  EXPECT_EQ(queried->endpoint, imported->endpoint);
  EXPECT_EQ(queried->client.uuid, imported->client.uuid);
  EXPECT_TRUE(serde::equals(*queried->externalBinding, *imported->externalBinding));
  rows = read(path("query.jsonl"));
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "host_execution_fenced");
  EXPECT_EQ(rows[1]["sequence_decimal"].asString(), "1");
  EXPECT_EQ(rows[1]["proof_sha256"], read(path("unknown.jsonl"))[0]["evidence_sha256"]);
  EXPECT_FALSE(rows[1]["cooperative_data_drained"].asBool());
  EXPECT_FALSE(rows[1]["physical_capacity_returned"].asBool());
  auto replay = args("ec-import-external-fence", path("replay.jsonl"));
  replay.insert(replay.end(), {"--evidence", evidence});
  ASSERT_OK(blockingWait(dispatcher_.run(env_, replay)));
  EXPECT_EQ(calls_->prepares.load(), 2u);
}

TEST_F(TestEcExternalFenceCommands, InvalidEvidenceAndNamespaceNeverDispatch) {
  unsigned i = 0;
  for (const auto size : {size_t(0), size_t(311), size_t(313), size_t(4097)}) {
    const auto proof = writeProof("bad-" + std::to_string(i) + ".bin", std::string(size, 'x'));
    auto command = args("ec-import-external-fence", path("bad-" + std::to_string(i++) + ".jsonl"));
    command.insert(command.end(), {"--evidence", proof});
    ASSERT_ERROR(blockingWait(dispatcher_.run(env_, command)), StatusCode::kInvalidArg);
  }
  const auto good = writeProof("good.bin", calls_->proof);
  std::filesystem::create_symlink(good, path("link.bin"));
  auto linked = args("ec-import-external-fence", path("link.jsonl"));
  linked.insert(linked.end(), {"--evidence", path("link.bin")});
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, linked)), StatusCode::kIOError);
  auto badBinding = args("ec-prepare-external-fence", path("binding.jsonl"));
  replace(badBinding, "--binding-sha256", std::string(64, '0'));
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, badBinding)), StatusCode::kInvalidArg);
  EXPECT_EQ(getters_, 0u);
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 0u);
  client_ = newClient(Uuid::random());
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-external-fence", path("namespace.jsonl")))),
               StatusCode::kInvalidArg);
  EXPECT_EQ(read(path("namespace.jsonl")).size(), 1);
  EXPECT_EQ(calls_->queries.load(), 0u);
}

TEST_F(TestEcExternalFenceCommands, WrongIdentityModeOrIncompleteEvidenceNeverConfirms) {
  for (unsigned variant = 1; variant <= 18; ++variant) {
    calls_->mismatch = variant;
    const auto file = path("wrong-" + std::to_string(variant) + ".jsonl");
    ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-external-fence", file))),
                 StorageClientCode::kProtocolMismatch);
    auto rows = read(file);
    ASSERT_EQ(rows.size(), 2);
    EXPECT_FALSE(rows[1]["meta_intent_confirmed"].asBool());
    EXPECT_FALSE(rows[1]["host_execution_fenced"].asBool());
    EXPECT_FALSE(rows[1]["physical_capacity_returned"].asBool());
  }
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 18u);
  calls_->mismatch = 0;
  calls_->queryError = MetaCode::kNotFound;
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-external-fence", path("missing.jsonl")))),
               MetaCode::kNotFound);
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_FALSE(read(path("missing.jsonl"))[1]["host_execution_fenced"].asBool());
  calls_->queryError = 0;
  calls_->prepared = true;
  const auto proof = writeProof("prepared-proof.bin", calls_->proof);
  auto incompleteImport = args("ec-import-external-fence", path("incomplete-import.jsonl"));
  incompleteImport.insert(incompleteImport.end(), {"--evidence", proof});
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, incompleteImport)), StorageClientCode::kProtocolMismatch);
  EXPECT_EQ(calls_->prepares.load(), 1u); // No retry can promote Prepared into completion.
  auto incomplete = read(path("incomplete-import.jsonl"));
  ASSERT_EQ(incomplete.size(), 2);
  EXPECT_FALSE(incomplete[1]["meta_intent_confirmed"].asBool());
  EXPECT_FALSE(incomplete[1]["host_execution_fenced"].asBool());
}
} // namespace
} // namespace hf3fs::client::cli
