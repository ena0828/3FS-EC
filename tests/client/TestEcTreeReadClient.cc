#include <algorithm>
#include <atomic>
#include <filesystem>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>

#include "client/ec/EcFileClient.h"
#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/MockService.h"
#include "storage/ec_codec/EcCodec.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
using folly::coro::blockingWait;
bool sameBytes(const auto &a, const auto &b) {
  const auto x = serde::serialize(a), y = serde::serialize(b);
  return std::string_view(x) == std::string_view(y);
}
meta::EcFileSessionRecord readSession() {
  meta::EcFileSessionRecord r;
  r.intent.object = {meta::InodeId(101), Uuid::random()};
  r.intent.birth = Uuid::random();
  r.intent.owner = {flat::Uid(123), Uuid::random()};
  r.intent.session = Uuid::random();
  r.intent.openRequest = Uuid::random();
  r.intent.rights = meta::kEcSessionRead;
  r.acceptedSequence = 1;
  return r;
}
meta::EcTreeReadRecord zeroRecord(const EcTreeReadRun &run, uint64_t eof) {
  meta::EcTreeReadRecord r;
  r.intent = run.intent;
  r.root.object = run.session.object;
  r.root.birth = run.session.birth;
  r.root.sequence = 3;
  r.root.epoch = 2;
  r.root.visibleLength = eof;
  r.shardBytes = run.shardBytes;
  auto requested = planEcFileRead(run.shardBytes, run.intent.selection.offset, run.intent.selection.length);
  EXPECT_TRUE(requested);
  auto clipped = clipEcFileRead(*requested, eof);
  EXPECT_TRUE(clipped);
  r.stripeCount = clipped->count;
  r.readableLength = clipped->length;
  for (size_t i = 0; i < r.stripeCount; ++i) r.stripes[i].slot.stripe = clipped->slices[i].stripe;
  return r;
}

TEST(TestEcTreeReadJournal, ExclusiveTypedJournalPreservesIdentityAndRejectsDrift) {
  auto session = readSession();
  auto run = prepareEcTreeRead(session, "tree-test", 8, 85, 90);
  ASSERT_OK(run);
  auto writeOnly = session;
  writeOnly.intent.rights = meta::kEcSessionWrite;
  ASSERT_ERROR(prepareEcTreeRead(writeOnly, "tree-test", 8, 0, 8), MetaCode::kNoPermission);
  auto bytes = encodeEcTreeReadRun(*run);
  ASSERT_OK(bytes);
  auto decoded = decodeEcTreeReadRun(*bytes);
  ASSERT_OK(decoded);
  EXPECT_TRUE(sameBytes(*run, *decoded));
  EXPECT_FALSE(decodeEcTreeReadRun(*bytes + "trailing"));
  EXPECT_FALSE(decodeEcTreeReadRun(std::string_view(*bytes).substr(0, bytes->size() - 1)));
  auto snapshot = zeroRecord(*run, 160);
  ASSERT_OK(validateEcTreeReadSnapshot(*run, snapshot));
  EXPECT_EQ(snapshot.stripes[0].slot.stripe, 1);
  auto bad = snapshot;
  bad.stripes[0].slot.stripe = 0;
  EXPECT_FALSE(validateEcTreeReadSnapshot(*run, bad));
  bad = snapshot;
  ++bad.root.sequence;
  EXPECT_FALSE(sameEcTreeReadSnapshot(snapshot, bad));
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "range";
  auto opened = EcTreeReadJournal::create(path, *run);
  ASSERT_OK(opened);
  auto journal = std::move(*opened);
  EXPECT_FALSE(EcTreeReadJournal::resume(path));
  EcTreeReadProgress p;
  p.acquisitionIssued = true;
  p.snapshot = snapshot;
  ASSERT_OK(journal->append(p));
  p.snapshot->state = meta::EcTreeReadState::Released;
  p.snapshot->closeAuthority = Uuid::random();
  p.releaseIssued = true;
  ASSERT_OK(journal->append(p));
  p.snapshot = snapshot;
  EXPECT_FALSE(journal->append(p));
  journal.reset();
  auto resumed = EcTreeReadJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_TRUE(sameBytes((*resumed)->record(), *run));
  ASSERT_TRUE((*resumed)->latest()->snapshot);
  EXPECT_EQ((*resumed)->latest()->snapshot->state, meta::EcTreeReadState::Released);
}

struct TreeCalls {
  meta::EcTreeReadRecord record;
  std::optional<meta::AcquireEcReadV2Rsp> data;
  std::atomic<size_t> acquire{0}, refresh{0}, query{0}, release{0}, oldAcquire{0}, oldRelease{0};
  bool unknownFirst = false, missingQuery = false;
  std::vector<meta::AcquireEcTreeReadReq> acquisitions;
  std::vector<meta::QueryEcTreeReadReq> queries;
  std::vector<meta::ReleaseEcTreeReadReq> releases;
};
class TreeService final : public meta::MockMetaService {
 public:
  explicit TreeService(std::shared_ptr<TreeCalls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &req) override {
    auto user = req.user;
    user.token.clear();
    co_return meta::AuthRsp{user};
  }
  CoTryTask<meta::EcTreeReadRsp> acquireEcTreeRead(serde::CallContext &,
                                                   const meta::AcquireEcTreeReadReq &req) override {
    calls_->acquisitions.push_back(req);
    if (!sameBytes(req.intent, calls_->record.intent) || req.client.uuid != calls_->record.intent.owner.client)
      co_return makeError(StatusCode::kTokenMismatch);
    meta::EcTreeReadRsp rsp;
    rsp.record = calls_->record;
    if (req.stripeIndex) {
      ++calls_->refresh;
      if (*req.stripeIndex != 0 || !calls_->data) co_return makeError(StatusCode::kInvalidArg);
      rsp.read = calls_->data;
    } else {
      ++calls_->acquire;
      if (calls_->unknownFirst && calls_->acquire == 1) co_return makeError(TransactionCode::kMaybeCommitted);
    }
    co_return rsp;
  }
  CoTryTask<meta::EcTreeReadRsp> queryEcTreeRead(serde::CallContext &, const meta::QueryEcTreeReadReq &req) override {
    ++calls_->query;
    calls_->queries.push_back(req);
    if (!sameBytes(req.intent, calls_->record.intent) || req.client.uuid != calls_->record.intent.owner.client)
      co_return makeError(StatusCode::kTokenMismatch);
    if (calls_->missingQuery) co_return makeError(MetaCode::kNotFound);
    meta::EcTreeReadRsp rsp;
    rsp.record = calls_->record;
    co_return rsp;
  }
  CoTryTask<meta::EcTreeReadRsp> releaseEcTreeRead(serde::CallContext &,
                                                   const meta::ReleaseEcTreeReadReq &req) override {
    ++calls_->release;
    calls_->releases.push_back(req);
    if (!sameBytes(req.intent, calls_->record.intent) || req.client.uuid != calls_->record.intent.owner.client)
      co_return makeError(StatusCode::kTokenMismatch);
    calls_->record.state = meta::EcTreeReadState::Released;
    calls_->record.closeAuthority = Uuid::random();
    calls_->record.revocations = req.revocations;
    meta::EcTreeReadRsp rsp;
    rsp.record = calls_->record;
    co_return rsp;
  }
  CoTryTask<meta::AcquireEcReadV2Rsp> acquireEcReadV2(serde::CallContext &, const meta::AcquireEcReadV2Req &) override {
    ++calls_->oldAcquire;
    co_return makeError(StatusCode::kFoundBug, "tree read must never use flat34");
  }
  CoTryTask<meta::ReleaseEcReadV2Rsp> releaseEcReadV2(serde::CallContext &, const meta::ReleaseEcReadV2Req &) override {
    ++calls_->oldRelease;
    co_return makeError(StatusCode::kFoundBug, "tree release must never use flat36");
  }

 private:
  std::shared_ptr<TreeCalls> calls_;
};
// Only this native StorageClient transport boundary is scripted. MetaClient,
// Serde, range journal, NativeEcBlockTransport, quorum, codec and SHA are real;
// unsigned fixture claims are not a server-authentication or TCP proof.
class TreeStorage final : public storage::client::StorageClientInMem {
 public:
  using StorageClientInMem::StorageClientInMem;
  storage::EcCodec::Shards shards;
  std::atomic<unsigned> active{0}, calls{0}, mask{0};
  CoTryTask<storage::EcReadBlockResultV2> readEcBlockV2Controlled(storage::EcReadBlockV2Req wire,
                                                                  storage::client::EcRequestControl) override {
    ++active;
    SCOPE_EXIT { --active; };
    ++calls;
    const auto &req = wire.request;
    mask.fetch_or(1u << req.identity.shard);
    // Two actual candidate errors require parity, rather than returning ten
    // unconstrained data buffers directly to the range client.
    if (req.identity.shard < 2) co_return makeError(StorageClientCode::kChunkNotFound);
    storage::EcReadBlockResultV2 rsp;
    rsp.receipt.identity = req.identity;
    rsp.receipt.operationId = req.operationId;
    rsp.receipt.engineUuid = wire.grant.claims.engineUuid;
    rsp.receipt.targetIncarnation = wire.grant.claims.targetIncarnation;
    rsp.receipt.vChainId = req.vChainId;
    rsp.receipt.targetId = req.targetId;
    rsp.receipt.length = req.integrity.wholeLength;
    rsp.receipt.crc32c = req.integrity.wholeCrc32c;
    rsp.receipt.integrityRoot = req.integrity.root;
    rsp.blockIndex = wire.blockIndex;
    rsp.payload.data = shards[req.identity.shard].substr(size_t(wire.blockIndex) * storage::kEcIntegrityBlockBytes,
                                                         req.integrity.blocks[wire.blockIndex].validLength);
    co_return rsp;
  }
};
class TestEcTreeReadClient : public ::testing::Test {
 protected:
  void SetUp() override {
    metaConfig_.set_network_type(net::Address::TCP);
    metaConfig_.retry_default().set_retry_init_wait(0_ms);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<TreeStorage>(ClientId::random(), storageConfig_, *mgmtd_);
    session_ = readSession();
    open();
  }
  void TearDown() override {
    if (client_) blockingWait(client_->close());
    if (meta_) meta_->stop();
  }
  void open() {
    if (client_) blockingWait(client_->close());
    client_.reset();
    if (meta_) meta_->stop();
    meta_.reset();
    serde::ClientMockContext mock;
    mock.setService(std::make_unique<TreeService>(calls_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(session_.intent.owner.client),
                                                       metaConfig_,
                                                       std::make_unique<meta::client::MetaClient::StubFactory>(mock),
                                                       mgmtd_,
                                                       storage_,
                                                       false);
    auto connected =
        blockingWait(EcFileClient::connect(meta_,
                                           storage_,
                                           mgmtd_,
                                           flat::UserInfo{session_.intent.owner.uid, flat::Gid(123), "test-token"},
                                           session_.intent.owner.client,
                                           pool_));
    ASSERT_OK(connected);
    client_ = std::move(*connected);
  }
  EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  void create(uint64_t offset, uint64_t length, uint64_t eof) {
    auto run = prepareEcTreeRead(session_, "tree-client-test", 8, offset, length);
    ASSERT_OK(run);
    path_ = std::filesystem::path(temporary_.path().string()) / "range";
    auto opened = EcTreeReadJournal::create(path_, *run);
    ASSERT_OK(opened);
    journal_ = std::shared_ptr<EcTreeReadJournal>(std::move(*opened));
    calls_->record = zeroRecord(*run, eof);
  }
  void installData() {
    ASSERT_EQ(calls_->record.stripeCount, 1);
    const std::string logical = "0123456789abcdefXYZ";
    auto encoded = storage::EcCodec::encode(logical, 8);
    ASSERT_OK(encoded);
    storage_->shards = std::move(*encoded);
    auto &r = calls_->record;
    r.root.root = Uuid::random();
    calls_->data.emplace();
    auto &read = *calls_->data;
    auto &m = read.manifest;
    m.object = session_.intent.object;
    m.stripe = r.stripes[0].slot.stripe;
    m.revision = 3;
    m.generation = 4;
    m.logicalLength = logical.size();
    std::array<std::string_view, 10> input{};
    input[0] = logical;
    auto hash = meta::computeEcLogicalSha256(input, logical.size());
    ASSERT_OK(hash);
    read.contentSha256 = *hash;
    auto &s = read.snapshot;
    s.object = m.object;
    s.owner = session_.intent.owner;
    s.pin = journal_->record().intent.selection.pins[0].pin;
    s.stripe = m.stripe;
    s.revision = m.revision;
    s.generation = m.generation;
    auto routing = mgmtd_->cloneRoutingInfo();
    std::array<storage::EcScopeEndpoint, 12> endpoints;
    for (size_t n = 0; n < 12; ++n) {
      flat::NodeInfo node;
      node.app.nodeId = flat::NodeId(100 + n);
      node.type = flat::NodeType::STORAGE;
      node.status = flat::NodeStatus::HEARTBEAT_CONNECTED;
      routing->raw()->nodes[node.app.nodeId] = node;
      flat::TargetInfo target;
      target.nodeId = node.app.nodeId;
      target.targetId = flat::TargetId(200 + n);
      target.chainId = flat::ChainId(300 + n);
      target.publicState = flat::PublicTargetState::SERVING;
      routing->raw()->targets[target.targetId] = target;
      flat::ChainInfo chain;
      chain.chainId = target.chainId;
      chain.chainVersion = flat::ChainVersion(1);
      flat::ChainTargetInfo member;
      member.targetId = target.targetId;
      member.publicState = flat::PublicTargetState::SERVING;
      chain.targets = {member};
      routing->raw()->chains[chain.chainId] = chain;
      auto &f = m.fragments[n];
      f.identity.object = m.object.incarnation;
      f.identity.stripe = m.stripe;
      f.identity.generation = m.generation;
      f.identity.shard = n;
      f.identity.allocation = Uuid::random();
      f.operation = Uuid::random();
      f.placement = {target.chainId, target.targetId, node.app.nodeId};
      auto integrity = storage::computeEcIntegrity(f.identity, storage_->shards[n]);
      ASSERT_OK(integrity);
      f.integrity = *integrity;
      auto &e = s.endpoints[n];
      e.identity = f.identity;
      e.operation = f.operation;
      e.endpoint = {f.placement, Uuid::random(), Uuid::random()};
      endpoints[n] = e.endpoint.controlEndpoint();
      read.readGrants[n].emplace();
      auto &c = read.readGrants[n]->claims;
      c.identity = f.identity;
      c.fragmentOperationId = f.operation;
      c.engineUuid = e.endpoint.engineUuid;
      c.targetIncarnation = e.endpoint.targetIncarnation;
      c.nodeId = node.app.nodeId;
      c.chainId = target.chainId;
      c.targetId = target.targetId;
      c.expectedLength = 8;
      c.expectedCrc32c = f.integrity.wholeCrc32c;
      auto digest = storage::digestEcIntegrityV2(f.identity, f.integrity);
      ASSERT_OK(digest);
      c.integrityDigest = *digest;
      c.ownerUid = s.owner.uid;
      c.clientNamespace = s.owner.client;
      c.scopeObject = m.object.incarnation;
      c.scopeKind = storage::EcGrantScope::ReadPin;
      c.scopeId = s.pin;
      c.grantId = Uuid::random();
      c.rights = uint16_t(storage::EcGrantRightV2::ReadBlock);
      c.issuedAtSeconds = 1000;
      c.expiresAtSeconds = 1100;
    }
    auto digest = storage::computeEcScopeEndpointDigest(endpoints);
    ASSERT_OK(digest);
    s.endpointSetDigest = *digest;
    mgmtd_->setRoutingInfo(routing);
    auto &slot = r.stripes[0].slot;
    slot.kind = meta::EcTreeSlotKind::Data;
    slot.revision = m.revision;
    slot.generation = m.generation;
    slot.logicalLength = m.logicalLength;
    slot.contentSha256 = *hash;
    r.stripes[0].snapshot = s;
    ASSERT_OK(validateEcTreeReadSnapshot(journal_->record(), r));
  }
  folly::test::TemporaryDirectory temporary_;
  folly::CPUThreadPoolExecutor pool_{2};
  meta::client::MetaClient::Config metaConfig_;
  storage::client::StorageClient::Config storageConfig_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<TreeStorage> storage_;
  std::shared_ptr<TreeCalls> calls_ = std::make_shared<TreeCalls>();
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<EcFileClient> client_;
  meta::EcFileSessionRecord session_;
  std::filesystem::path path_;
  std::shared_ptr<EcTreeReadJournal> journal_;
};

TEST_F(TestEcTreeReadClient, ZeroRangeClipsEofAndReleasesThrough55Only) {
  create(85, 90, 160);
  auto output = blockingWait(client_->readTree(journal_, control()));
  ASSERT_OK(output);
  ASSERT_EQ(output->data.size(), 75);
  EXPECT_TRUE(std::all_of(output->data.bytes().begin(), output->data.bytes().end(), [](auto b) { return b == 0; }));
  EXPECT_EQ(storage_->calls, 0);
  auto released = blockingWait(client_->releaseTree(journal_, control()));
  ASSERT_OK(released);
  EXPECT_EQ(released->state, meta::EcTreeReadState::Released);
  ASSERT_EQ(calls_->releases.size(), 1);
  for (const auto &id : calls_->releases[0].revocations) EXPECT_TRUE(id.is_nil());
  EXPECT_EQ(calls_->oldAcquire, 0);
  EXPECT_EQ(calls_->oldRelease, 0);
  EXPECT_FALSE(blockingWait(client_->readTree(journal_, control())));
  EXPECT_EQ(calls_->acquire, 1);
}

TEST_F(TestEcTreeReadClient, UnknownAndMissingResumeNeverCreateAnotherSnapshot) {
  create(85, 20, 160);
  calls_->unknownFirst = true;
  ASSERT_ERROR(blockingWait(client_->readTree(journal_, control())), TransactionCode::kMaybeCommitted);
  const auto original = journal_->record();
  journal_.reset();
  open();
  auto resumed = EcTreeReadJournal::resume(path_);
  ASSERT_OK(resumed);
  journal_ = std::shared_ptr<EcTreeReadJournal>(std::move(*resumed));
  calls_->missingQuery = true;
  ASSERT_ERROR(blockingWait(client_->readTree(journal_, control())), MetaCode::kNotFound);
  EXPECT_EQ(calls_->acquire, 1);
  calls_->missingQuery = false;
  auto output = blockingWait(client_->readTree(journal_, control()));
  ASSERT_OK(output);
  EXPECT_EQ(calls_->acquire, 1);
  EXPECT_TRUE(sameBytes(journal_->record(), original));
  for (const auto &q : calls_->queries) {
    EXPECT_EQ(q.uuid, original.queryRequest);
    EXPECT_TRUE(sameBytes(q.intent, original.intent));
  }
  ++calls_->record.root.sequence;
  EXPECT_FALSE(blockingWait(client_->readTree(journal_, control())));
  EXPECT_EQ(calls_->acquire, 1);
}

TEST_F(TestEcTreeReadClient, DataUsesNativeQuorumParityAndZeroFillsLogicalTail) {
  create(0, 80, 80);
  installData();
  auto output = blockingWait(client_->readTree(journal_, control()));
  ASSERT_OK(output);
  std::string expected = "0123456789abcdefXYZ";
  expected.resize(80, '\0');
  EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(output->data.bytes().data()), output->data.size()),
            expected);
  EXPECT_EQ(storage_->active, 0);
  EXPECT_EQ(storage_->mask.load() & ((1u << 10) | (1u << 11)), (1u << 10) | (1u << 11));
  EXPECT_EQ(calls_->acquire, 1);
  EXPECT_EQ(calls_->refresh, 1);
  EXPECT_EQ(calls_->oldAcquire, 0);
  EXPECT_EQ(calls_->oldRelease, 0);
  auto released = blockingWait(client_->releaseTree(journal_, control()));
  ASSERT_OK(released);
  ASSERT_EQ(calls_->releases.size(), 1);
  EXPECT_EQ(calls_->releases[0].revocations[0], journal_->record().revocations[0]);
  for (size_t n = 1; n < 8; ++n) EXPECT_TRUE(calls_->releases[0].revocations[n].is_nil());
  const auto count = storage_->calls.load();
  ASSERT_ERROR(blockingWait(client_->readTree(journal_, control())), StatusCode::kTokenStale);
  EXPECT_EQ(storage_->calls, count);
  EXPECT_EQ(calls_->oldRelease, 0);
}
}  // namespace
}  // namespace hf3fs::client::ec
