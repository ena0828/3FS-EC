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

struct AbsenceCalls {
  std::atomic<size_t> confirms{0}, queries{0};
  std::atomic<bool> queryMissing{true};
  std::atomic<unsigned> mismatch{0};
  std::mutex mutex;
  std::optional<meta::EcGcAdminReq> last;
  void record(const meta::EcGcAdminReq &req) {
    std::lock_guard lock(mutex);
    last = req;
  }
  std::optional<meta::EcGcAdminReq> snapshot() {
    std::lock_guard lock(mutex);
    return last;
  }
};

class AbsenceService : public meta::MockMetaService {
 public:
  explicit AbsenceService(std::shared_ptr<AbsenceCalls> calls)
      : calls_(std::move(calls)) {}

  CoTryTask<meta::EcAbsentAdminRsp> confirmEcFragmentAbsent(serde::CallContext &,
                                                          const meta::ConfirmEcFragmentAbsentReq &req) override {
    calls_->record(req);
    if (++calls_->confirms == 1) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    co_return completed(req);  // An automatic retry would hide the first unknown result.
  }
  CoTryTask<meta::EcAbsentAdminRsp> queryEcFragmentAbsent(serde::CallContext &,
                                                        const meta::QueryEcFragmentAbsentReq &req) override {
    calls_->record(req);
    ++calls_->queries;
    if (calls_->queryMissing) co_return makeError(MetaCode::kNotFound);
    auto rsp = completed(req);
    switch (calls_->mismatch.load()) {
      case 1: rsp.object.incarnation = Uuid::random(); break;
      case 2: rsp.identity.allocation = Uuid::random(); break;
      case 3: rsp.claimId = Uuid::random(); break;
      case 4: rsp.clientNamespace = Uuid::random(); break;
      case 5: rsp.requestId = Uuid::random(); break;
      case 6: rsp.state = static_cast<storage::EcGcAbsentState>(0); break;
      case 7: rsp.claimDigest = {}; break;
      case 8: rsp.closureDigest = {}; break;
      case 9: rsp.ledgerSha256 = {}; break;
      case 10: rsp.recordRevision = 0; break;
      case 11: rsp.candidateReservationReleaseEligible = false; break;
      case 12: rsp.collected = true; break;
      case 13: rsp.physicalReclamationConfirmed = true; break;
      case 14: rsp.recordRevision = 2; break;
      default: break;
    }
    co_return rsp;
  }

 private:
  static meta::EcAbsentAdminRsp completed(const meta::EcGcAdminReq &req) {
    meta::EcAbsentAdminRsp rsp;
    rsp.object = req.object;
    rsp.identity = req.identity;
    rsp.claimId = req.claimId;
    rsp.clientNamespace = req.client.uuid;
    rsp.requestId = req.uuid;
    rsp.state = storage::EcGcAbsentState::AbsentAfterClose;
    rsp.claimDigest[0] = 3;
    rsp.closureDigest[0] = 5;
    rsp.ledgerSha256[0] = 7;
    rsp.recordRevision = 1;
    rsp.candidateReservationReleaseEligible = true;
    rsp.collected = false;
    rsp.physicalReclamationConfirmed = false;
    return rsp;
  }
  std::shared_ptr<AbsenceCalls> calls_;
};

class TestEcAbsentCommands : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK(blockingWait(registerEcGcHandlers(dispatcher_)));
    config_.set_network_type(net::Address::TCP);
    config_.retry_default().set_retry_init_wait(1_ms);
    config_.retry_default().set_retry_total_time(1_s);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    serde::ClientMockContext context;
    context.setService(std::make_unique<AbsenceService>(calls_));
    client_ = std::make_shared<meta::client::MetaClient>(
        ClientId::random(), config_, std::make_unique<meta::client::MetaClient::StubFactory>(context),
        mgmtd_, nullptr, false);
    env_.userInfo = {flat::Uid{0}, flat::Gid{0}, "test-token-not-for-an-actual-server"};
    env_.metaClientGetter = [&] {
      ++getters_;
      return client_;
    };
  }
  Dispatcher::Args args(std::string command, const std::string &output) const {
    return {std::move(command), "--inode", std::to_string(meta::InodeId::normalMax().u64()),
            "--object-incarnation", object_.toHexString(), "--stripe", "18446744073709551615",
            "--generation", "18446744073709551615", "--shard", "11", "--allocation", allocation_.toHexString(),
            "--claim-id", claim_.toHexString(), "--request-id", request_.toHexString(),
            "--client-namespace", client_->clientId().uuid.toHexString(), "--output", output};
  }
  static void replace(Dispatcher::Args &arguments, std::string_view key, std::string value) {
    const auto it = std::find(arguments.begin(), arguments.end(), key);
    ASSERT_NE(it, arguments.end());
    *(it + 1) = std::move(value);
  }
  static std::vector<folly::dynamic> read(const std::string &file) {
    std::ifstream input(file);
    std::vector<folly::dynamic> rows;
    std::string line;
    while (std::getline(input, line)) rows.push_back(folly::parseJson(line));
    return rows;
  }
  std::string path(std::string_view file) const { return (temp_.path() / std::string(file)).string(); }
  folly::test::TemporaryDirectory temp_;
  Dispatcher dispatcher_;
  AdminEnv env_;
  meta::client::MetaClient::Config config_;
  std::shared_ptr<AbsenceCalls> calls_ = std::make_shared<AbsenceCalls>();
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<meta::client::MetaClient> client_;
  size_t getters_ = 0;
  Uuid object_ = Uuid::random(), allocation_ = Uuid::random(), claim_ = Uuid::random(), request_ = Uuid::random();
};

TEST_F(TestEcAbsentCommands, UnknownConfirmAndMissingQueryRetainIdsWithoutRetryOrFallback) {
  const auto confirm = path("confirm.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-gc-confirm-absent", confirm))),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(calls_->confirms.load(), 1);
  ASSERT_EQ(calls_->queries.load(), 0);
  auto rows = read(confirm);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[0]["phase"].asString(), "prepared");
  EXPECT_EQ(rows[1]["outcome"].asString(), "unknown");
  EXPECT_FALSE(rows[1]["candidate_reservation_release_eligible"].asBool());
  const auto saved = calls_->snapshot();
  ASSERT_TRUE(saved);
  EXPECT_EQ(saved->claimId, claim_);
  EXPECT_EQ(saved->uuid, request_);
  EXPECT_EQ(saved->client.uuid, client_->clientId().uuid);
  EXPECT_EQ(saved->identity.generation, std::numeric_limits<uint64_t>::max());

  const auto missing = path("missing.jsonl");
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-gc-query-absent", missing))), MetaCode::kNotFound);
  ASSERT_EQ(calls_->confirms.load(), 1);
  ASSERT_EQ(calls_->queries.load(), 1);
  rows = read(missing);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "not_observed");
  EXPECT_EQ(rows[1]["state"].asString(), "not_confirmed");
  EXPECT_EQ(rows[1]["claim_id"].asString(), claim_.toHexString());
  EXPECT_TRUE(rows[1]["ledger_sha256"].asString().empty());

  calls_->queryMissing = false;
  const auto query = path("query.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-gc-query-absent", query))));
  EXPECT_EQ(calls_->confirms.load(), 1);
  EXPECT_EQ(calls_->queries.load(), 2);
  rows = read(query);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "observed");
  EXPECT_EQ(rows[1]["state"].asString(), "absent_after_close");
  EXPECT_EQ(rows[1]["stripe_decimal"].asString(), "18446744073709551615");
  EXPECT_EQ(rows[1]["absence_record_revision_decimal"].asString(), "1");
  EXPECT_TRUE(rows[1]["candidate_reservation_release_eligible"].asBool());
  EXPECT_TRUE(rows[1]["storage_absence_observed"].asBool());
  EXPECT_FALSE(rows[1]["collected"].asBool());
  EXPECT_FALSE(rows[1]["physical_reclamation_confirmed"].asBool());
  EXPECT_EQ(rows[1].count("terminal_revision_decimal"), 0);
  struct stat info {};
  ASSERT_EQ(::stat(query.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
  std::ifstream input(query);
  const std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  EXPECT_EQ(raw.find(env_.userInfo.token), std::string::npos);
  const auto replay = path("confirm-replay.jsonl");
  ASSERT_OK(blockingWait(dispatcher_.run(env_, args("ec-gc-confirm-absent", replay))));
  EXPECT_EQ(calls_->confirms.load(), 2);
  EXPECT_EQ(calls_->queries.load(), 2);
  rows = read(replay);
  ASSERT_EQ(rows.size(), 2);
  EXPECT_EQ(rows[1]["outcome"].asString(), "confirmed");
  EXPECT_EQ(rows[1]["claim_id"].asString(), claim_.toHexString());
  EXPECT_EQ(rows[1]["ledger_sha256"].asString(), read(query)[1]["ledger_sha256"].asString());
}

TEST_F(TestEcAbsentCommands, WrongProofIdentityOrCollectionClaimNeverProducesEligibleArchive) {
  calls_->queryMissing = false;
  for (unsigned bad = 1; bad <= 14; ++bad) {
    SCOPED_TRACE(bad);
    calls_->mismatch = bad;
    const auto output = path("bad-" + std::to_string(bad) + ".jsonl");
    ASSERT_ERROR(blockingWait(dispatcher_.run(env_, args("ec-gc-query-absent", output))),
                 StorageClientCode::kProtocolMismatch);
    const auto rows = read(output);
    ASSERT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[1]["outcome"].asString(), "not_observed");
    EXPECT_FALSE(rows[1]["candidate_reservation_release_eligible"].asBool());
    EXPECT_FALSE(rows[1]["storage_absence_observed"].asBool());
    EXPECT_TRUE(rows[1]["closure_sha256"].asString().empty());
    EXPECT_TRUE(rows[1]["ledger_sha256"].asString().empty());
  }
  EXPECT_EQ(calls_->confirms.load(), 0);
  EXPECT_EQ(calls_->queries.load(), 14);
}

TEST_F(TestEcAbsentCommands, ExistingArchiveInvalidIdentityAndNamespaceMismatchDoNotDispatch) {
  const auto existing = path("existing.jsonl");
  { std::ofstream file(existing); file << "preserve-me\n"; }
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, args("ec-gc-confirm-absent", existing))));
  std::ifstream file(existing);
  std::string original;
  std::getline(file, original);
  EXPECT_EQ(original, "preserve-me");
  for (const auto &[key, value] : std::array<std::pair<std::string_view, std::string_view>, 5>{
           {{"--generation", "18446744073709551616"}, {"--shard", "12"}, {"--stripe", "1.0"},
            {"--claim-id", "00000000-0000-0000-0000-000000000000"},
            {"--client-namespace", "00000000-0000-0000-0000-000000000000"}}}) {
    auto command = args("ec-gc-query-absent", path("invalid.jsonl"));
    replace(command, key, std::string(value));
    ASSERT_FALSE(blockingWait(dispatcher_.run(env_, command)));
  }
  auto nul = args("ec-gc-confirm-absent", path("nul-prefix") + std::string("\0suffix", 7));
  ASSERT_FALSE(blockingWait(dispatcher_.run(env_, nul)));
  EXPECT_FALSE(std::filesystem::exists(path("nul-prefix")));
  EXPECT_EQ(getters_, 0);
  auto wrong = args("ec-gc-query-absent", path("namespace.jsonl"));
  replace(wrong, "--client-namespace", Uuid::random().toHexString());
  ASSERT_ERROR(blockingWait(dispatcher_.run(env_, wrong)), StatusCode::kInvalidConfig);
  const auto prepared = read(path("namespace.jsonl"));
  ASSERT_EQ(prepared.size(), 1);
  EXPECT_EQ(prepared[0]["outcome"].asString(), "not_confirmed");
  EXPECT_EQ(calls_->confirms.load() + calls_->queries.load(), 0);
}
}  // namespace
}  // namespace hf3fs::client::cli
