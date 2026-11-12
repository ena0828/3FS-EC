#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <fstream>
#include <gtest/gtest.h>
#include <set>

#include "client/ec/EcFilePwriteClient.h"
#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
struct State {
  meta::EcOwner owner;
  meta::EcObjectRef object{meta::InodeId(777), Uuid::random()};
  Uuid birth = Uuid::random();
  std::optional<meta::EcFileMutationRecord> parent;
  std::optional<EcPwriteRunRecord> run;
  size_t opens = 0, begins = 0, queries = 0, advances = 0;
  bool lostBegin = true, completeOnBegin = true, wrongOwner = false, queryMissing = false, t0AlreadyClosed = false;
  std::set<Uuid> cleaned;
  std::vector<Uuid> beginIds, operations, queryIds;
};
class Service : public meta::MockMetaService {
 public:
  explicit Service(std::shared_ptr<State> state)
      : state_(std::move(state)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &r) override {
    auto u = r.user;
    u.token.clear();
    co_return meta::AuthRsp{u};
  }
  CoTryTask<meta::OpenEcFileSessionRsp> openEcFileSession(serde::CallContext &,
                                                          const meta::OpenEcFileSessionReq &r) override {
    ++state_->opens;
    meta::OpenEcFileSessionRsp rsp;
    rsp.object.object = state_->object;
    rsp.object.shardBytes = r.shardBytes;
    meta::EcManifestLayoutV1 descriptor;
    descriptor.incarnation = state_->object.incarnation;
    descriptor.shardBytes = r.shardBytes;
    meta::Layout layout;
    layout.chains = descriptor;
    rsp.inode = meta::Inode{state_->object.inode,
                            {meta::File{layout}, meta::Acl{r.user.uid, r.user.gid, meta::Permission(r.perm)}}};
    rsp.root.object = state_->object;
    rsp.root.birth = state_->birth;
    auto &i = rsp.session.intent;
    i.object = state_->object;
    i.birth = state_->birth;
    i.session = r.session;
    i.openRequest = r.uuid;
    i.owner = {r.user.uid, r.client.uuid};
    i.rights = r.rights;
    co_return rsp;
  }
  CoTryTask<meta::EcFilePwriteRsp> beginEcFilePwrite(serde::CallContext &,
                                                     const meta::BeginEcFilePwriteReq &r) override {
    ++state_->begins;
    state_->beginIds.push_back(r.uuid);
    state_->operations.push_back(r.operation);
    meta::EcFileMutationRecord p;
    p.intent.object = r.object;
    p.intent.owner = {r.user.uid, r.client.uuid};
    p.intent.session = r.session;
    p.intent.request = r.operation;
    p.intent.offset = r.offset;
    p.intent.length = r.length;
    p.intent.inputSha256 = r.inputSha256;
    p.epoch = 1;
    p.sessionSequence = 1;
    if (state_->completeOnBegin) {
      p.confirmedPrefix = r.length;
      p.state = meta::EcFileMutationState::ClosedLogical;
    }
    state_->parent = p;
    if (state_->lostBegin) co_return makeError(TransactionCode::kMaybeCommitted);
    meta::EcFilePwriteRsp rsp;
    rsp.progress.parent = p;
    co_return rsp;
  }
  meta::EcFilePwriteRsp observed(const Uuid &child) {
    meta::EcFilePwriteRsp rsp;
    if (state_->queryMissing) return rsp;
    rsp.progress.parent = state_->parent;
    if (rsp.progress.parent && state_->wrongOwner) rsp.progress.parent->intent.owner.uid = flat::Uid(999);
    if (!child.is_nil() && state_->run && state_->parent) {
      const auto &r = *state_->run;
      for (size_t n = 0; n < r.count; ++n)
        if (r.children[n].intent.child == child) {
          meta::EcFileChildProgress c;
          c.child = child;
          c.plan = r.children[n].intent.plan;
          const auto width = uint64_t(r.shardBytes) * 10;
          const auto start = r.children[n].intent.expectedPrefix;
          const auto end = n + 1 < r.count ? r.children[n + 1].intent.expectedPrefix : r.length;
          c.stripe = (r.offset + start) / width;
          c.patchOffset = (r.offset + start) % width;
          c.patchLength = end - start;
          c.targetLogicalLength = c.patchOffset + c.patchLength;
          c.state = state_->parent->confirmedPrefix >= end ? meta::EcFileChildState::Published
                                                           : meta::EcFileChildState::Planned;
          rsp.progress.child = c;
          rsp.progress.outputDrained = c.state == meta::EcFileChildState::Published;
          rsp.progress.sourceReleased = state_->cleaned.contains(child);
        }
    }
    return rsp;
  }
  CoTryTask<meta::EcFilePwriteRsp> queryEcFilePwrite(serde::CallContext &,
                                                     const meta::QueryEcFilePwriteReq &r) override {
    ++state_->queries;
    state_->queryIds.push_back(r.uuid);
    if (state_->run && (r.client.uuid != state_->run->owner.client || r.user.uid != state_->run->owner.uid ||
                        r.operation != state_->run->operation))
      co_return makeError(StatusCode::kTokenMismatch);
    co_return observed(r.child);
  }
  CoTryTask<meta::EcFilePwriteRsp> advanceEcFilePwrite(serde::CallContext &,
                                                       const meta::AdvanceEcFilePwriteReq &r) override {
    ++state_->advances;
    if (state_->t0AlreadyClosed && r.action == meta::EcFileAdvanceAction::Plan)
      co_return makeError(StatusCode::kTokenStale);
    if (state_->t0AlreadyClosed && r.action == meta::EcFileAdvanceAction::Publish) {
      for (size_t n = 0; n < state_->run->count; ++n)
        if (state_->run->children[n].intent.child == r.child) {
          if (r.uuid != state_->run->children[n].publish) co_return makeError(StatusCode::kTokenMismatch);
          state_->parent->confirmedPrefix =
              n + 1 < state_->run->count ? state_->run->children[n + 1].intent.expectedPrefix : state_->run->length;
          if (state_->parent->confirmedPrefix == state_->run->length)
            state_->parent->state = meta::EcFileMutationState::ClosedLogical;
          co_return observed(r.child);
        }
    }
    if (r.action != meta::EcFileAdvanceAction::CleanupChild) co_return makeError(MetaCode::kNoPermission);
    for (size_t n = 0; n < state_->run->count; ++n) {
      const auto &c = state_->run->children[n];
      if (c.intent.child == r.child) {
        if (r.uuid != c.cleanup || r.outputRevocation != c.outputRevocation || r.sourceRevocation != c.sourceRevocation)
          co_return makeError(StatusCode::kTokenMismatch);
        state_->cleaned.insert(r.child);
        co_return observed(r.child);
      }
    }
    co_return makeError(StatusCode::kTokenMismatch);
  }

 private:
  std::shared_ptr<State> state_;
};
class TestEcFilePwriteClient : public ::testing::Test {
 protected:
  void SetUp() override {
    metaConfig_.set_network_type(net::Address::TCP);
    metaConfig_.retry_default().set_retry_init_wait(0_ms);
    state_ = std::make_shared<State>();
    state_->owner = {flat::Uid(123), Uuid::random()};
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<storage::client::StorageClientInMem>(ClientId::random(), storageConfig_, *mgmtd_);
    rmw_ = std::make_shared<storage::client::EcRmwTransport>(netConfig_);  // No worker call in these recovery tests.
    connect();
    auto record =
        prepareEcPwriteSession(state_->owner, "test", true, "/file", {}, Uuid::zero(), 8, meta::kEcSessionWrite, 0200);
    ASSERT_OK(record);
    auto j = EcFilePwriteJournal::create(path("session"), *record);
    ASSERT_OK(j);
    session_ = std::move(*j);
    ASSERT_OK(client_->open(*session_, control()));
    inputPath_ = path("input");
    {
      std::ofstream out(inputPath_, std::ios::binary);
      out << std::string(100, 'x');
    }
    auto input = client_->readInput(inputPath_);
    ASSERT_OK(input);
    auto run = prepareEcPwrite(*session_, 7, inputPath_.string(), input->bytes());
    ASSERT_OK(run);
    state_->run = *run;
    auto opened = EcFilePwriteJournal::create(path("write"), *run);
    ASSERT_OK(opened);
    journal_ = std::move(*opened);
  }
  void TearDown() override {
    client_.reset();
    if (meta_) meta_->stop();
  }
  void connect() {
    client_.reset();
    if (meta_) meta_->stop();
    serde::ClientMockContext mock;
    mock.setService(std::make_unique<Service>(state_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(state_->owner.client),
                                                       metaConfig_,
                                                       std::make_unique<meta::client::MetaClient::StubFactory>(mock),
                                                       mgmtd_,
                                                       storage_,
                                                       false);
    auto c = EcFilePwriteClient::connect(meta_,
                                         rmw_,
                                         mgmtd_,
                                         {state_->owner.uid, flat::Gid(123), "token"},
                                         state_->owner.client);
    ASSERT_OK(c);
    client_ = std::move(*c);
  }
  EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  std::filesystem::path path(const char *name) { return std::filesystem::path(temp_.path().string()) / name; }
  EcPwriteOutcome write() {
    auto input = client_->readInput(inputPath_);
    EXPECT_TRUE(bool(input));
    if (!input) {
      EcPwriteOutcome failed;
      failed.failure = std::move(input.error());
      return failed;
    }
    return client_->pwrite(*journal_, std::move(*input), control());
  }
  folly::test::TemporaryDirectory temp_;
  meta::client::MetaClient::Config metaConfig_;
  storage::client::StorageClient::Config storageConfig_;
  net::Client::Config netConfig_;
  std::shared_ptr<State> state_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClientInMem> storage_;
  std::shared_ptr<storage::client::EcRmwTransport> rmw_;
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::unique_ptr<EcFilePwriteClient> client_;
  std::unique_ptr<EcFilePwriteJournal> session_, journal_;
  std::filesystem::path inputPath_;
};
TEST_F(TestEcFilePwriteClient, UnknownBeginReopensSameIdentityAndObservesPublishedPrefix) {
  auto first = write();
  ASSERT_TRUE(first.failure);
  EXPECT_EQ(first.failure->code(), TransactionCode::kMaybeCommitted);
  ASSERT_EQ(state_->begins, 1u);
  ASSERT_TRUE(journal_->latest()->issued);
  const auto record = serde::serialize(journal_->record());
  journal_.reset();
  connect();
  auto reopen = EcFilePwriteJournal::resume(path("write"));
  ASSERT_OK(reopen);
  journal_ = std::move(*reopen);
  EXPECT_EQ(serde::serialize(journal_->record()), record);
  auto next = write();
  ASSERT_FALSE(next.failure);
  EXPECT_EQ(next.confirmedPrefix, 100u);
  EXPECT_TRUE(next.logicalComplete);
  EXPECT_TRUE(next.allCleanupComplete);
  EXPECT_EQ(state_->begins, 1u);
  EXPECT_EQ(state_->advances, 2u);  // No new Plan/Publish; only each original source debt.
  EXPECT_EQ(state_->beginIds.front(), journal_->record().beginRequest);
  EXPECT_EQ(state_->operations.front(), journal_->record().operation);
}
TEST_F(TestEcFilePwriteClient, MissingObservationNeverCreatesAnotherIdentityOrBeginsFromQuery) {
  auto first = write();
  ASSERT_TRUE(first.failure);
  state_->queryMissing = true;
  const auto record = serde::serialize(journal_->record());
  auto query = client_->query(*journal_, control());
  ASSERT_TRUE(query.failure);
  EXPECT_EQ(state_->begins, 1u);
  EXPECT_EQ(state_->advances, 0u);
  EXPECT_TRUE(journal_->latest()->issued);
  EXPECT_EQ(serde::serialize(journal_->record()), record);
}
TEST_F(TestEcFilePwriteClient, WrongOwnerAndChangedInputCannotAdvanceMutation) {
  auto first = write();
  ASSERT_TRUE(first.failure);
  state_->wrongOwner = true;
  auto query = client_->query(*journal_, control());
  ASSERT_TRUE(query.failure);
  EXPECT_EQ(state_->advances, 0u);
  state_->wrongOwner = false;
  const auto queries = state_->queries;
  auto foreign = journal_->record();
  foreign.owner.uid = flat::Uid(998);
  auto foreignJournal = EcFilePwriteJournal::create(path("foreign"), foreign);
  ASSERT_OK(foreignJournal);
  auto rejected = client_->query(**foreignJournal, control());
  ASSERT_TRUE(rejected.failure);
  EXPECT_EQ(state_->queries, queries);
  {
    std::ofstream out(inputPath_, std::ios::binary | std::ios::trunc);
    out << std::string(100, 'y');
  }
  auto next = write();
  ASSERT_TRUE(next.failure);
  EXPECT_EQ(next.failure->code(), StatusCode::kTokenMismatch);
  EXPECT_EQ(state_->queries, queries);
  EXPECT_EQ(state_->begins, 1u);
}
TEST_F(TestEcFilePwriteClient, PublishT0RejectionResumesOriginalPublicationWithoutWorkerReupload) {
  state_->lostBegin = false;
  state_->completeOnBegin = false;
  state_->t0AlreadyClosed = true;
  const auto record = serde::serialize(journal_->record());
  auto result = write();
  ASSERT_FALSE(result.failure);
  EXPECT_TRUE(result.logicalComplete);
  EXPECT_TRUE(result.allCleanupComplete);
  EXPECT_EQ(result.confirmedPrefix, 100u);
  EXPECT_EQ(state_->begins, 1u);
  EXPECT_EQ(state_->advances, 6u);
  EXPECT_EQ(serde::serialize(journal_->record()), record);
}
TEST_F(TestEcFilePwriteClient, FixedUnalignedChildrenCodecAndExclusiveJournal) {
  const auto &r = journal_->record();
  ASSERT_EQ(r.count, 2);
  EXPECT_EQ(r.children[0].intent.expectedPrefix, 0u);
  EXPECT_EQ(r.children[1].intent.expectedPrefix, 73u);
  auto encoded = encodeEcPwriteRunRecord(r);
  ASSERT_OK(encoded);
  auto decoded = decodeEcPwriteRunRecord(*encoded);
  ASSERT_OK(decoded);
  EXPECT_TRUE(serde::serialize(*decoded) == serde::serialize(r));
  auto duplicate = EcFilePwriteJournal::create(path("write"), r);
  EXPECT_FALSE(duplicate);
  auto locked = EcFilePwriteJournal::resume(path("write"));
  EXPECT_FALSE(locked);
  auto overflow = prepareEcPwrite(*session_, UINT64_MAX, inputPath_.string(), std::span<const uint8_t>{});
  EXPECT_FALSE(overflow);
  auto bad = r;
  bad.children[1].intent.plan = bad.children[0].intent.plan;
  EXPECT_FALSE(bad.validate());
}
}  // namespace
}  // namespace hf3fs::client::ec
