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
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::cli {
namespace {
using folly::coro::blockingWait;

struct Calls {
  std::atomic<size_t> retires{0};
  std::atomic<size_t> queries{0};
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
};

class RetirementService : public meta::MockMetaService {
 public:
  explicit RetirementService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
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
};

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
