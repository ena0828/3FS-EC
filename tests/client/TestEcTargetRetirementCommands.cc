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
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "client/cli/admin/AdminClientIdentity.h"
#include "client/cli/admin/AdminEnv.h"
#include "client/cli/admin/EcTargetRetirementCommands.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::cli {
namespace {
using folly::coro::blockingWait;

struct Calls {
  std::atomic<size_t> prepares{0}, queries{0};
  std::atomic<unsigned> mismatch{0};
  std::atomic<bool> prepared{false};
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
// establish server authentication, FDB persistence or Storage retirement.
class TargetRetirementService : public meta::MockMetaService {
 public:
  explicit TargetRetirementService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::EcTargetRetirementRsp> prepareEcTargetRetirement(
      serde::CallContext &, const meta::PrepareEcTargetRetirementReq &req) override {
    calls_->record(req);
    if (++calls_->prepares == 1) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    co_return response(req);  // A hidden retry would incorrectly turn unknown into success.
  }
  CoTryTask<meta::EcTargetRetirementRsp> queryEcTargetRetirement(
      serde::CallContext &, const meta::QueryEcTargetRetirementReq &req) override {
    calls_->record(req);
    ++calls_->queries;
    if (const auto error = calls_->queryError.load()) co_return makeError(error);
    auto value = response(req);
    switch (calls_->mismatch.load()) {
      case 1: value.intent.endpoint.placement.node = flat::NodeId(2); break;
      case 2: value.intent.endpoint.placement.chain = storage::ChainId(2); break;
      case 3: value.intent.endpoint.placement.target = storage::TargetId(2); break;
      case 4: value.intent.endpoint.engineUuid = Uuid::random(); break;
      case 5: value.intent.endpoint.targetIncarnation = Uuid::random(); break;
      case 6: value.intent.retirementId = Uuid::random(); break;
      case 7: value.intent.owner.uid = flat::Uid(1); break;
      case 8: value.intent.owner.client = Uuid::random(); break;
      case 9: value.intent.requestId = Uuid::random(); break;
      case 10: value.intent.authority = Uuid::zero(); break;
      case 11: value.intent.version = 2; break;
      case 12: value.stage = static_cast<meta::EcTargetRetirementStage>(255); break;
      case 13: value.stage = meta::EcTargetRetirementStage::Prepared; break;
      case 14: value.completionDigest.fill(0); break;
      default: break;
    }
    co_return value;
  }
 private:
  meta::EcTargetRetirementRsp response(const meta::EcTargetRetirementReq &req) const {
    meta::EcTargetRetirementRsp value;
    value.intent.endpoint = req.endpoint;
    value.intent.authority = Uuid::from(201, 202);
    value.intent.retirementId = req.retirementId;
    value.intent.owner.uid = req.user.uid;
    value.intent.owner.client = req.client.uuid;
    value.intent.requestId = req.uuid;
    value.stage = calls_->prepared ? meta::EcTargetRetirementStage::Prepared : meta::EcTargetRetirementStage::Completed;
    if (!calls_->prepared) value.completionDigest.fill(0x5a);
    return value;
  }
  std::shared_ptr<Calls> calls_;
};

class TestEcTargetRetirementCommands : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK(blockingWait(registerEcTargetRetirementHandlers(dispatcher_)));
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
    context.setService(std::make_unique<TargetRetirementService>(calls_));
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
            "--client-namespace", namespace_.toHexString(), "--request-id", request_.toHexString(), "--output", file};
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
};

TEST_F(TestEcTargetRetirementCommands, UnknownPrepareAndNewClientQueryPreserveExactIntent) {
  const auto first = path("prepare.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-prepare-target-retirement", first))),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(calls_->prepares.load(), 1u);
  auto original = calls_->snapshot();
  ASSERT_TRUE(original);
  EXPECT_EQ(original->client.uuid, namespace_);
  EXPECT_EQ(original->uuid, request_);
  EXPECT_EQ(original->retirementId, retirement_);
  EXPECT_EQ(original->endpoint.placement.target.toUnderType(), std::numeric_limits<uint64_t>::max());
  auto rows = read(first);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[0]["phase"].asString(), "prepared");
  EXPECT_EQ(rows[0]["target_decimal"].asString(), "18446744073709551615");
  EXPECT_EQ(rows[1]["outcome"].asString(), "unknown");
  EXPECT_FALSE(rows[1]["meta_intent_confirmed"].asBool());
  EXPECT_FALSE(rows[1]["cooperative_data_drained"].asBool());
  client_ = newClient(namespace_);
  const auto second = path("query.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-query-target-retirement", second))));
  ASSERT_EQ(calls_->prepares.load(), 1u);
  ASSERT_EQ(calls_->queries.load(), 1u);
  auto queried = calls_->snapshot();
  ASSERT_TRUE(queried);
  EXPECT_EQ(queried->endpoint, original->endpoint);
  EXPECT_EQ(queried->client.uuid, original->client.uuid);
  EXPECT_EQ(queried->uuid, original->uuid);
  EXPECT_EQ(queried->retirementId, original->retirementId);
  rows = read(second);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_TRUE(rows[1]["meta_intent_confirmed"].asBool());
  EXPECT_TRUE(rows[1]["cooperative_data_drained"].asBool());
  std::string expected;
  for (size_t i = 0; i != 32; ++i) expected += "5a";
  EXPECT_EQ(rows[1]["completion_sha256"].asString(), expected);
}

TEST_F(TestEcTargetRetirementCommands, PreparedDoesNotClaimStorageDrainOrPhysicalReclamation) {
  calls_->prepared = true;
  const auto output = path("prepared-query.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-query-target-retirement", output))));
  const auto rows = read(output);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "intent_accepted");
  EXPECT_TRUE(rows[1]["meta_intent_confirmed"].asBool());
  EXPECT_FALSE(rows[1]["cooperative_data_drained"].asBool());
  EXPECT_TRUE(rows[1]["completion_sha256"].asString().empty());
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 1u);
}

TEST_F(TestEcTargetRetirementCommands, MismatchedOrContradictoryResponsesNeverConfirmRetirement) {
  for (unsigned variant = 1; variant != 15; ++variant) {
    calls_->mismatch = variant;
    const auto output = path("mismatch-" + std::to_string(variant) + ".jsonl");
    ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-target-retirement", output))),
                 StorageClientCode::kProtocolMismatch);
    const auto rows = read(output);
    ASSERT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[1]["outcome"].asString(), "not_confirmed");
    EXPECT_FALSE(rows[1]["meta_intent_confirmed"].asBool());
    EXPECT_FALSE(rows[1]["cooperative_data_drained"].asBool());
    EXPECT_TRUE(rows[1]["completion_sha256"].asString().empty());
  }
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 14u);
}

TEST_F(TestEcTargetRetirementCommands, InvalidIdentityAndExistingArchivePreventDispatch) {
  const std::vector<std::pair<std::string, std::string>> invalid{
      {"--node-id", "4294967296"}, {"--chain-id", "4294967296"}, {"--target-id", "18446744073709551616"},
      {"--target-id", "-1"}, {"--target-id", "0"}, {"--target-id", "1x"}, {"--node-id", "0"},
      {"--engine-uuid", Uuid::zero().toHexString()}, {"--retirement-id", "not-a-uuid"},
      {"--client-namespace", Uuid::zero().toHexString()}, {"--request-id", Uuid::zero().toHexString()}};
  for (size_t index = 0; index != invalid.size(); ++index) {
    const auto output = path("invalid-" + std::to_string(index) + ".jsonl");
    auto argv = args("ec-prepare-target-retirement", output);
    replace(argv, invalid[index].first, invalid[index].second);
    ASSERT_FALSE(blockingWait(dispatcher_.run(env_, argv)));
    EXPECT_FALSE(std::filesystem::exists(output));
  }
  const auto occupied = path("occupied.jsonl");
  { std::ofstream output(occupied); output << "keep original archive\n"; }
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, args("ec-prepare-target-retirement", occupied))));
  std::ifstream input(occupied);
  std::string content;
  std::getline(input, content);
  EXPECT_EQ(content, "keep original archive");
  const auto link = path("archive-link");
  std::filesystem::create_symlink(occupied, link);
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, args("ec-prepare-target-retirement", link))));
  EXPECT_EQ(getters_, 0u);
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 0u);
}

TEST_F(TestEcTargetRetirementCommands, WrongActualNamespaceAndGetterExceptionRetainPreparedIdentity) {
  client_ = newClient(Uuid::random());
  const auto wrong = path("wrong-namespace.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-prepare-target-retirement", wrong))), StatusCode::kInvalidArg);
  auto rows = read(wrong);
  ASSERT_EQ(rows.size(), 1);
  EXPECT_EQ(rows[0]["request_id"].asString(), request_.toHexString());
  EXPECT_EQ(calls_->prepares.load(), 0u);
  const auto exceptional = path("getter-error.jsonl");
  env_.metaClientGetter = []() -> std::shared_ptr<meta::client::MetaClient> { throw std::runtime_error("test getter"); };
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-prepare-target-retirement", exceptional))), StatusCode::kIOError);
  rows = read(exceptional);
  ASSERT_EQ(rows.size(), 1);
  EXPECT_EQ(rows[0]["retirement_id"].asString(), retirement_.toHexString());
  EXPECT_EQ(calls_->prepares.load(), 0u);
  struct stat info {};
  ASSERT_EQ(::stat(exceptional.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
}

TEST_F(TestEcTargetRetirementCommands, QueryErrorsNeverPrepareAndDirectClientRejectsNilRequestIds) {
  const auto output = path("unknown-query.jsonl");
  calls_->queryError = TransactionCode::kMaybeCommitted;
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-query-target-retirement", output))),
               TransactionCode::kMaybeCommitted);
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 1u);
  const auto rows = read(output);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "unknown");
  const auto original = calls_->snapshot();
  ASSERT_TRUE(original);
  meta::PrepareEcTargetRetirementReq prepare;
  static_cast<meta::EcTargetRetirementReq &>(prepare) = *original;
  prepare.uuid = Uuid::zero();
  ASSERT_FALSE(blockingWait(client_->prepareEcTargetRetirement(prepare)));
  meta::QueryEcTargetRetirementReq query;
  static_cast<meta::EcTargetRetirementReq &>(query) = *original;
  query.uuid = Uuid::zero();
  ASSERT_FALSE(blockingWait(client_->queryEcTargetRetirement(query)));
  EXPECT_EQ(calls_->prepares.load(), 0u);
  EXPECT_EQ(calls_->queries.load(), 1u);
}
}  // namespace
}  // namespace hf3fs::client::cli
