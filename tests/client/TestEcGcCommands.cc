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
#include <mutex>
#include <sys/stat.h>

#include "client/cli/admin/AdminEnv.h"
#include "client/cli/admin/EcGcCommands.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::cli {
namespace {
using folly::coro::blockingWait;
struct Calls {
  std::atomic<size_t> collects{0};
  std::atomic<size_t> queries{0};
  std::atomic<bool> mismatch{false};
  void record(const meta::EcGcAdminReq &req) {
    std::lock_guard lock(mutex);
    last = req;
  }
  std::optional<meta::EcGcAdminReq> snapshot() {
    std::lock_guard lock(mutex);
    return last;
  }

 private:
  std::mutex mutex;
  std::optional<meta::EcGcAdminReq> last;
};
class GcService : public meta::MockMetaService {
 public:
  explicit GcService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::EcGcAdminRsp> collectEcFragmentV2(serde::CallContext &,
                                                    const meta::CollectEcFragmentV2Req &req) override {
    calls_->record(req);
    if (++calls_->collects == 1) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    co_return completed(req);  // A hidden retry would falsely turn the test green.
  }
  CoTryTask<meta::EcGcAdminRsp> queryEcFragmentGcV2(serde::CallContext &,
                                                    const meta::QueryEcFragmentGcV2Req &req) override {
    calls_->record(req);
    ++calls_->queries;
    auto rsp = completed(req);
    if (calls_->mismatch) rsp.claimId = Uuid::random();
    co_return rsp;
  }

 private:
  static meta::EcGcAdminRsp completed(const meta::EcGcAdminReq &req) {
    meta::EcGcAdminRsp rsp;
    rsp.object = req.object;
    rsp.identity = req.identity;
    rsp.claimId = req.claimId;
    rsp.claimDigest[0] = 3;
    rsp.ledgerSha256[0] = 7;
    rsp.terminalRevision = std::numeric_limits<uint64_t>::max();
    return rsp;
  }
  std::shared_ptr<Calls> calls_;
};
class TestEcGcCommands : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK(blockingWait(registerEcGcHandlers(dispatcher_)));
    config_.set_network_type(net::Address::TCP);
    // Keep ordinary retry enabled; the two actual new MetaClient methods must
    // independently use one attempt, not depend on a weakened test config.
    config_.retry_default().set_retry_init_wait(1_ms);
    config_.retry_default().set_retry_total_time(1_s);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    serde::ClientMockContext context;
    context.setService(std::make_unique<GcService>(calls_));
    client_ =
        std::make_shared<meta::client::MetaClient>(ClientId::random(),
                                                   config_,
                                                   std::make_unique<meta::client::MetaClient::StubFactory>(context),
                                                   mgmtd_,
                                                   nullptr,
                                                   false);
    env_.userInfo = {flat::Uid{0}, flat::Gid{0}, "test-token-not-for-an-actual-server"};
    env_.metaClientGetter = [&] {
      ++getters_;
      return client_;
    };
  }
  Dispatcher::Args args(std::string command, const std::string &file) const {
    return {std::move(command),
            "--inode",
            std::to_string(meta::InodeId::normalMax().u64()),
            "--object-incarnation",
            object_.toHexString(),
            "--stripe",
            "18446744073709551615",
            "--generation",
            "18446744073709551615",
            "--shard",
            "11",
            "--allocation",
            allocation_.toHexString(),
            "--claim-id",
            claim_.toHexString(),
            "--request-id",
            request_.toHexString(),
            "--output",
            file};
  }
  static void replace(Dispatcher::Args &arguments, std::string_view key, std::string value) {
    auto it = std::find(arguments.begin(), arguments.end(), key);
    ASSERT_NE(it, arguments.end());
    *++it = std::move(value);
  }
  std::vector<folly::dynamic> read(const std::string &file) const {
    std::ifstream input(file);
    std::vector<folly::dynamic> out;
    std::string line;
    while (std::getline(input, line)) out.push_back(folly::parseJson(line));
    return out;
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
  Uuid object_ = Uuid::random(), allocation_ = Uuid::random(), claim_ = Uuid::random(), request_ = Uuid::random();
};

TEST_F(TestEcGcCommands, UnknownHasOneActualMetaCallAndExplicitSameClaimQueryArchivesConfirmation) {
  const auto collectPath = path("collect.jsonl");
  auto result = blockingWait(dispatcher_.run(env_, args("ec-gc-collect", collectPath)));
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(calls_->collects.load(), 1);
  const auto last = calls_->snapshot();
  ASSERT_TRUE(last);
  ASSERT_EQ(last->claimId, claim_);
  ASSERT_EQ(last->uuid, request_);
  ASSERT_EQ(last->identity.stripe, std::numeric_limits<uint64_t>::max());
  ASSERT_EQ(last->identity.generation, std::numeric_limits<uint64_t>::max());
  auto records = read(collectPath);
  ASSERT_EQ(records.size(), 2);
  EXPECT_EQ(records[0]["phase"].asString(), "prepared");
  EXPECT_EQ(records[1]["outcome"].asString(), "unknown");
  EXPECT_EQ(records[1]["status_code"].asInt(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(records[0]["stripe_decimal"].asString(), "18446744073709551615");
  EXPECT_EQ(records[0]["inode_decimal"].asString(), std::to_string(meta::InodeId::normalMax().u64()));
  std::ifstream raw(collectPath);
  const std::string contents((std::istreambuf_iterator<char>(raw)), std::istreambuf_iterator<char>());
  EXPECT_EQ(contents.find(env_.userInfo.token), std::string::npos);
  struct stat info {};
  ASSERT_EQ(::stat(collectPath.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
  const auto queryPath = path("query.jsonl");
  auto query = blockingWait(dispatcher_.run(env_, args("ec-gc-query", queryPath)));
  ASSERT_OK(query);
  ASSERT_EQ(calls_->queries.load(), 1);
  ASSERT_EQ(calls_->collects.load(), 1);
  auto confirmed = read(queryPath);
  ASSERT_EQ(confirmed.size(), 2);
  EXPECT_EQ(confirmed[1]["outcome"].asString(), "confirmed");
  EXPECT_EQ(confirmed[1]["claim_id"].asString(), claim_.toHexString());
  EXPECT_EQ(confirmed[1]["terminal_revision_decimal"].asString(), "18446744073709551615");
  EXPECT_EQ(confirmed[1]["ledger_sha256"].asString().size(), 64);
}

TEST_F(TestEcGcCommands, ExistingArchiveInvalidNumbersAndNonRootNeverInvokeMeta) {
  const auto existing = path("existing.jsonl");
  {
    std::ofstream out(existing);
    out << "preserve-me\n";
  }
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, args("ec-gc-collect", existing))));
  EXPECT_EQ(getters_, 0);
  std::ifstream input(existing);
  std::string preserved;
  std::getline(input, preserved);
  EXPECT_EQ(preserved, "preserve-me");
  for (const auto &[key, value] : std::array<std::pair<std::string_view, std::string_view>, 5>{
           {{"--inode", "-1"},
            {"--generation", "18446744073709551616"},
            {"--stripe", "1.0"},
            {"--shard", "12"},
            {"--claim-id", "00000000-0000-0000-0000-000000000000"}}}) {
    auto command = args("ec-gc-query", path("invalid.jsonl"));
    replace(command, key, std::string(value));
    ASSERT_FALSE(blockingWait(dispatcher_.run(env_, command)));
  }
  env_.userInfo.uid = flat::Uid{1};
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-gc-query", path("nonroot.jsonl")))),
               StatusCode::kAuthenticationFail);
  EXPECT_EQ(getters_, 0);
  EXPECT_EQ(calls_->collects.load() + calls_->queries.load(), 0);
  EXPECT_FALSE(std::filesystem::exists(path("invalid.jsonl")));
}

TEST_F(TestEcGcCommands, MismatchedSuccessfulResponseIsNotAConfirmation) {
  calls_->mismatch = true;
  const auto output = path("mismatch.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-gc-query", output))), StorageClientCode::kProtocolMismatch);
  ASSERT_EQ(calls_->queries.load(), 1);
  auto records = read(output);
  ASSERT_EQ(records.size(), 2);
  EXPECT_EQ(records[1]["outcome"].asString(), "not_confirmed");
  EXPECT_EQ(records[1]["claim_id"].asString(), claim_.toHexString());
  EXPECT_TRUE(records[1]["ledger_sha256"].asString().empty());
}
}  // namespace
}  // namespace hf3fs::client::cli
