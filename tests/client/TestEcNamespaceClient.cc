#include <filesystem>
#include <fcntl.h>
#include <folly/experimental/TestUtil.h>
#include <gtest/gtest.h>

#include "client/ec/EcNamespaceClient.h"
#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
struct NamespaceState {
  meta::EcOwner owner{flat::Uid(701), Uuid::random()};
  meta::InodeId current{710};
  std::optional<meta::RemoveReq> accepted;
  std::vector<meta::RemoveReq> calls;
  bool loseReply = false, missing = false;
};
class NamespaceService : public meta::MockMetaService {
 public:
  explicit NamespaceService(std::shared_ptr<NamespaceState> state) : state_(std::move(state)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &req) override {
    auto user = req.user;
    user.token.clear();
    co_return meta::AuthRsp{user};
  }
  CoTryTask<meta::RemoveRsp> remove(serde::CallContext &, const meta::RemoveReq &req) override {
    state_->calls.push_back(req);
    if (state_->missing) co_return makeError(MetaCode::kNotFound);
    if (req.client.uuid != state_->owner.client || req.user.uid != state_->owner.uid || !req.inodeId ||
        req.recursive || !req.checkType || !req.atFlags.contains(AT_SYMLINK_NOFOLLOW))
      co_return makeError(StatusCode::kTokenMismatch);
    // Explicit mock of the existing permanent namespace semantics, not FDB evidence.
    // Replaying an accepted original request precedes resolution of a recreated name.
    if (state_->accepted) {
      const auto &old = *state_->accepted;
      if (old.uuid != req.uuid || old.inodeId != req.inodeId || serde::serialize(old.path) != serde::serialize(req.path))
        co_return makeError(StatusCode::kTokenMismatch);
      co_return meta::RemoveRsp{};
    }
    if (*req.inodeId != state_->current) co_return makeError(MetaCode::kNotFound);
    state_->accepted = req;
    state_->current = meta::InodeId(0);
    if (state_->loseReply) co_return makeError(TransactionCode::kMaybeCommitted);
    co_return meta::RemoveRsp{};
  }
 private:
  std::shared_ptr<NamespaceState> state_;
};
}  // namespace
class TestEcNamespaceClient : public testing::Test {
 protected:
  void SetUp() override {
    config_.set_network_type(net::Address::TCP);
    config_.retry_default().set_retry_init_wait(0_ms);
    state_ = std::make_shared<NamespaceState>();
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<storage::client::StorageClientInMem>(ClientId::random(), storageConfig_, *mgmtd_);
    connect();
    EcNamespaceRun run;
    run.cluster = "namespace-test";
    run.path = "/original";
    run.request = Uuid::random();
    auto &i = run.session.intent;
    i.owner = state_->owner;
    i.object = {meta::InodeId(710), Uuid::random()};
    i.birth = Uuid::random();
    i.session = Uuid::random();
    i.openRequest = Uuid::random();
    i.rights = meta::kEcSessionRead;
    run.session.state = meta::EcFileSessionState::Closed;
    auto made = EcNamespaceJournal::create(path("unlink"), run);
    ASSERT_OK(made);
    journal_ = std::move(*made);
  }
  void TearDown() override {
    client_.reset();
    if (meta_) meta_->stop();
  }
  void connect() {
    client_.reset();
    if (meta_) meta_->stop();
    serde::ClientMockContext mock;
    mock.setService(std::make_unique<NamespaceService>(state_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(state_->owner.client), config_,
        std::make_unique<meta::client::MetaClient::StubFactory>(mock), mgmtd_, storage_, false);
    auto client = EcNamespaceClient::connect(meta_, {state_->owner.uid, flat::Gid(701), "token"}, state_->owner.client);
    ASSERT_OK(client);
    client_ = std::move(*client);
  }
  EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  std::filesystem::path path(const char *name) { return std::filesystem::path(temp_.path().string()) / name; }
  folly::test::TemporaryDirectory temp_;
  meta::client::MetaClient::Config config_;
  storage::client::StorageClient::Config storageConfig_;
  std::shared_ptr<NamespaceState> state_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClientInMem> storage_;
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::unique_ptr<EcNamespaceClient> client_;
  std::unique_ptr<EcNamespaceJournal> journal_;
};
TEST_F(TestEcNamespaceClient, LostReplyResumesOriginalRequestAndDoesNotRemoveRecreatedPath) {
  state_->loseReply = true;
  const auto original = serde::serialize(journal_->record());
  auto first = client_->unlink(*journal_, control());
  ASSERT_TRUE(first.failure);
  EXPECT_FALSE(first.acknowledged);
  EXPECT_FALSE(first.revalidated);
  ASSERT_EQ(state_->calls.size(), 1u);
  EXPECT_TRUE(journal_->latest()->issued);
  state_->current = meta::InodeId(999);  // Another inode now occupies the original name.
  journal_.reset();
  connect();
  auto resumed = EcNamespaceJournal::resume(path("unlink"));
  ASSERT_OK(resumed);
  journal_ = std::move(*resumed);
  EXPECT_EQ(serde::serialize(journal_->record()), original);
  auto second = client_->unlink(*journal_, control());
  ASSERT_FALSE(second.failure);
  EXPECT_TRUE(second.acknowledged);
  EXPECT_TRUE(second.revalidated);
  EXPECT_EQ(state_->current, meta::InodeId(999));
  ASSERT_EQ(state_->calls.size(), 2u);
  EXPECT_EQ(state_->calls[0].uuid, state_->calls[1].uuid);
  EXPECT_EQ(state_->calls[1].inodeId, meta::InodeId(710));
  state_->missing = true;
  auto later = client_->unlink(*journal_, control());
  ASSERT_TRUE(later.failure);
  EXPECT_TRUE(later.acknowledged);  // Historical fact survives a failed current observation.
  EXPECT_FALSE(later.revalidated);
}
TEST_F(TestEcNamespaceClient, PersistenceFailureAfterReplyRequiresExplicitSameJournalResume) {
  const auto collision = path("unlink") / "state-00000000000000000001.data";
  std::filesystem::create_directory(collision);
  auto first = client_->unlink(*journal_, control());
  ASSERT_TRUE(first.failure);
  EXPECT_FALSE(first.acknowledged);
  EXPECT_FALSE(first.revalidated);
  EXPECT_TRUE(journal_->poisoned());
  ASSERT_EQ(state_->calls.size(), 1u);
  auto blocked = client_->unlink(*journal_, control());
  EXPECT_TRUE(blocked.failure);
  EXPECT_EQ(state_->calls.size(), 1u);
  journal_.reset();
  // Remove only the deliberately injected empty obstacle; retain all real journal bytes.
  ASSERT_TRUE(std::filesystem::remove(collision));
  auto resumed = EcNamespaceJournal::resume(path("unlink"));
  ASSERT_OK(resumed);
  journal_ = std::move(*resumed);
  auto retry = client_->unlink(*journal_, control());
  ASSERT_FALSE(retry.failure);
  EXPECT_TRUE(retry.revalidated);
  ASSERT_EQ(state_->calls.size(), 2u);
  EXPECT_EQ(state_->calls[0].uuid, state_->calls[1].uuid);
}
TEST_F(TestEcNamespaceClient, MissingReplacementAndPreDispatchCancellationNeverAcknowledge) {
  auto expired = control();
  expired.deadline = std::chrono::steady_clock::now();
  EXPECT_TRUE(client_->unlink(*journal_, expired).failure);
  folly::CancellationSource cancellation;
  cancellation.requestCancellation();
  auto cancelled = control();
  cancelled.cancellation = cancellation.getToken();
  EXPECT_TRUE(client_->unlink(*journal_, cancelled).failure);
  EXPECT_TRUE(state_->calls.empty());
  EXPECT_FALSE(journal_->latest());
  state_->current = meta::InodeId(999);
  auto missing = client_->unlink(*journal_, control());
  ASSERT_TRUE(missing.failure);
  EXPECT_EQ(missing.failure->code(), MetaCode::kNotFound);
  EXPECT_FALSE(missing.acknowledged);
  EXPECT_FALSE(missing.revalidated);
  EXPECT_EQ(state_->current, meta::InodeId(999));
  EXPECT_FALSE(state_->accepted);
  EXPECT_FALSE(EcNamespaceClient::connect(meta_, {state_->owner.uid, flat::Gid(701), "token"}, Uuid::random()));
}
}  // namespace hf3fs::client::ec
