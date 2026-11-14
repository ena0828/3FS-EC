#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/json.h>
#include <gtest/gtest.h>

#include "client/ec/EcFileClient.h"
#include "client/ec/EcAllocationExport.h"
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

// Real immutable journal bytes, including the existing lock. Export must not
// create, replace or append any entry, even after the read has been released.
std::string fileBytes(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::map<std::string, std::string> journalBytes(const std::filesystem::path &path) {
  std::map<std::string, std::string> result;
  for (const auto &entry : std::filesystem::directory_iterator(path))
    result.emplace(entry.path().filename().string(), fileBytes(entry.path()));
  return result;
}
std::string bytesDigest(std::string_view bytes) {
  std::array<std::string_view, 10> parts{};
  parts[0] = bytes;
  auto digest = meta::computeEcLogicalSha256(parts, bytes.size());
  EXPECT_TRUE(digest);
  return digest ? serde::SerdeMethod<storage::EcSha256>::serdeToReadable(*digest) : "";
}

TEST(TestEcTreeReadJournal, ReadOnlyExportRejectsMissingLockIncompleteAndConflictingOutput) {
  folly::test::TemporaryDirectory temporary;
  const auto parent = std::filesystem::canonical(temporary.path().string());
  const auto path = parent / "range", output = parent / "export.json";
  auto run = prepareEcTreeRead(readSession(), "export-test", 8, 0, 80);
  ASSERT_OK(run);
  auto opened = EcTreeReadJournal::create(path, *run);
  ASSERT_OK(opened);
  auto journal = std::move(*opened);
  auto before = journalBytes(path);
  EXPECT_FALSE(exportEcTreeReadAllocations(path, output));  // live lock, no output
  EXPECT_FALSE(std::filesystem::exists(output));
  EXPECT_EQ(journalBytes(path), before);
  journal.reset();
  EXPECT_FALSE(exportEcTreeReadAllocations(path, output));  // no successful snapshot
  EXPECT_FALSE(std::filesystem::exists(output));
  auto inspected = EcTreeReadJournal::inspectExisting(path);
  ASSERT_OK(inspected);
  EcTreeReadProgress progress;
  progress.acquisitionIssued = true;
  progress.snapshot = zeroRecord(*run, 80);
  progress.dataReady = progress.localComplete = true;
  EXPECT_FALSE((*inspected)->append(progress));
  inspected->reset();
  EXPECT_EQ(journalBytes(path), before);
  ASSERT_TRUE(std::filesystem::remove(path / ".lock"));
  before = journalBytes(path);
  EXPECT_FALSE(EcTreeReadJournal::inspectExisting(path));
  EXPECT_FALSE(exportEcTreeReadAllocations(path, output));
  EXPECT_EQ(journalBytes(path), before);
  EXPECT_FALSE(std::filesystem::exists(path / ".lock"));
  // Ordinary resume retains its old API. Inspection never performs this repair.
  auto resumed = EcTreeReadJournal::resume(path);
  ASSERT_OK(resumed);
  progress.errorCode = StatusCode::kIOError;
  ASSERT_OK((*resumed)->append(progress));
  resumed->reset();
  EXPECT_FALSE(exportEcTreeReadAllocations(path, output));
  resumed = EcTreeReadJournal::resume(path);
  ASSERT_OK(resumed);
  progress.errorCode = 0;
  ASSERT_OK((*resumed)->append(progress));
  resumed->reset();
  before = journalBytes(path);
  EXPECT_FALSE(exportEcTreeReadAllocations(path, path / "inside.json"));
  ASSERT_OK(exportEcTreeReadAllocations(path, output));
  const auto saved = fileBytes(output);
  EXPECT_FALSE(exportEcTreeReadAllocations(path, output));
  EXPECT_EQ(fileBytes(output), saved);
  EXPECT_EQ(journalBytes(path), before);
  // Existing-state corruption must not become a plausible partial export.
  {
    std::ofstream altered(path / "record.data", std::ios::binary | std::ios::app);
    altered << "trailing";
  }
  EXPECT_FALSE(exportEcTreeReadAllocations(path, parent / "bad.json"));
  EXPECT_FALSE(std::filesystem::exists(parent / "bad.json"));
}

TEST(TestEcTreeReadJournal, SnapshotExportBoundsZeroEofAndEightDistinctRevisions) {
  folly::test::TemporaryDirectory temporary;
  const auto parent = std::filesystem::canonical(temporary.path().string());
  auto run = prepareEcTreeRead(readSession(), "export-bound-test", 8, 0, 640);
  ASSERT_OK(run);
  EXPECT_FALSE(prepareEcTreeRead(readSession(), "too-many", 8, 0, 641));
  for (auto eof : {uint64_t{0}, uint64_t{1}, uint64_t{640}}) {
    const auto path = parent / ("zero-" + std::to_string(eof));
    auto opened = EcTreeReadJournal::create(path, *run);
    ASSERT_OK(opened);
    EcTreeReadProgress progress;
    progress.acquisitionIssued = true;
    progress.snapshot = zeroRecord(*run, eof);
    progress.snapshot->state = meta::EcTreeReadState::Released;
    progress.snapshot->closeAuthority = Uuid::random();
    progress.releaseIssued = progress.dataReady = progress.localComplete = true;
    ASSERT_OK((*opened)->append(progress));
    opened->reset();
    const auto before = journalBytes(path);
    const auto output = parent / ("zero-" + std::to_string(eof) + ".json");
    ASSERT_OK(exportEcTreeReadAllocations(path, output));
    const auto value = folly::parseJson(fileBytes(output));
    EXPECT_EQ(value["selection"]["readable_length_decimal"].asString(), std::to_string(eof));
    EXPECT_EQ(value["slots"].size(), eof == 0 ? 0u : eof == 1 ? 1u : 8u);
    EXPECT_TRUE(value["revisions"].empty());
    EXPECT_EQ(journalBytes(path), before);
  }
  // A bounded, valid on-disk metadata fixture, not a network/data-read proof.
  auto snapshot = zeroRecord(*run, 640);
  snapshot.root.root = Uuid::random();
  std::array<std::string_view, 10> logical{};
  logical[0] = "x";
  auto hash = meta::computeEcLogicalSha256(logical, 1);
  ASSERT_OK(hash);
  for (size_t stripe = 0; stripe < 8; ++stripe) {
    auto &entry = snapshot.stripes[stripe];
    entry.slot.kind = meta::EcTreeSlotKind::Data;
    entry.slot.revision = 3;  // equal numeric revisions on distinct stripes stay distinct
    entry.slot.generation = 4;
    entry.slot.logicalLength = 1;
    entry.slot.contentSha256 = *hash;
    entry.snapshot.emplace();
    auto &pin = *entry.snapshot;
    pin.object = run->session.object;
    pin.owner = run->session.owner;
    pin.pin = run->intent.selection.pins[stripe].pin;
    pin.stripe = stripe;
    pin.revision = 3;
    pin.generation = 4;
    std::array<storage::EcScopeEndpoint, 12> endpoints;
    for (size_t shard = 0; shard < 12; ++shard) {
      auto &endpoint = pin.endpoints[shard];
      endpoint.identity.object = run->session.object.incarnation;
      endpoint.identity.stripe = stripe;
      endpoint.identity.generation = 4;
      endpoint.identity.shard = shard;
      endpoint.identity.allocation = Uuid::random();
      endpoint.operation = Uuid::random();
      endpoint.endpoint = {{flat::ChainId(200 + shard), flat::TargetId(300 + shard), flat::NodeId(100 + shard)},
                           Uuid::random(), Uuid::random()};
      endpoints[shard] = endpoint.endpoint.controlEndpoint();
    }
    auto digest = storage::computeEcScopeEndpointDigest(endpoints);
    ASSERT_OK(digest);
    pin.endpointSetDigest = *digest;
  }
  EcTreeReadProgress progress;
  progress.acquisitionIssued = progress.dataReady = progress.localComplete = true;
  progress.snapshot = snapshot;
  const auto path = parent / "eight", output = parent / "eight.json";
  auto opened = EcTreeReadJournal::create(path, *run);
  ASSERT_OK(opened);
  ASSERT_OK((*opened)->append(progress));
  opened->reset();
  ASSERT_OK(exportEcTreeReadAllocations(path, output));
  const auto bytes = fileBytes(output);
  EXPECT_LT(bytes.size(), 256u << 10);
  const auto value = folly::parseJson(bytes);
  ASSERT_EQ(value["revisions"].size(), 8u);
  for (size_t stripe = 0; stripe < 8; ++stripe) {
    const auto &revision = value["revisions"][stripe];
    EXPECT_EQ(revision["stripe_decimal"].asString(), std::to_string(stripe));
    EXPECT_EQ(revision["revision_decimal"].asString(), "3");
    EXPECT_EQ(revision["allocations"].size(), 12u);
  }
  // Per-stripe validation alone does not catch one UUID reused on two stripes.
  progress.snapshot->stripes[1].snapshot->endpoints[0].identity.allocation =
      progress.snapshot->stripes[0].snapshot->endpoints[0].identity.allocation;
  opened = EcTreeReadJournal::create(parent / "duplicate", *run);
  ASSERT_OK(opened);
  ASSERT_OK((*opened)->append(progress));
  opened->reset();
  EXPECT_FALSE(exportEcTreeReadAllocations(parent / "duplicate", parent / "duplicate.json"));
  EXPECT_FALSE(std::filesystem::exists(parent / "duplicate.json"));
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
  std::atomic<unsigned> transportMask{0};
  CoTryTask<storage::EcReadBlockResultV2> readEcBlockV2Controlled(storage::EcReadBlockV2Req wire,
                                                                  storage::client::EcRequestControl control) override {
    transportMask.fetch_or(control.transport == EcStorageTransportPolicy::TcpOnly ? 1u :
                           control.transport == EcStorageTransportPolicy::RdmaOnly ? 2u : 4u);
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
  EXPECT_EQ(storage_->transportMask.load(), 1u);
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

TEST_F(TestEcTreeReadClient, ReleasedReadExportPreservesTwelveIdentitiesAndJournalBytes) {
  create(0, 80, 80);
  installData();
  ASSERT_OK(blockingWait(client_->readTree(journal_, control())));
  ASSERT_OK(blockingWait(client_->releaseTree(journal_, control())));
  ASSERT_TRUE(journal_->latest());
  ASSERT_TRUE(journal_->latest()->snapshot);
  ASSERT_EQ(journal_->latest()->snapshot->state, meta::EcTreeReadState::Released);
  const auto sequence = journal_->latest()->sequence;
  const auto expected = *journal_->latest()->snapshot->stripes[0].snapshot;
  const auto run = journal_->record();
  journal_.reset();
  blockingWait(client_->close());
  client_.reset();
  meta_->stop();
  meta_.reset();  // export must not require even the mock services to remain live
  const auto before = journalBytes(path_);
  const auto storageCalls = storage_->calls.load();
  const auto acquire = calls_->acquire.load(), query = calls_->query.load(), release = calls_->release.load();
  const auto output = path_.parent_path() / "read-allocations.json";
  ASSERT_OK(exportEcTreeReadAllocations(path_, output));
  const auto bytes = fileBytes(output);
  const auto value = folly::parseJson(bytes);
  EXPECT_EQ(value["kind"].asString(), "ec_tree_read_allocations");
  EXPECT_EQ(value["scope"].asString(), "captured_read_snapshot");
  EXPECT_FALSE(value["gc_authorized"].asBool());
  EXPECT_FALSE(value["network_io_performed"].asBool());
  EXPECT_EQ(value["object"]["incarnation"].asString(), run.session.object.incarnation.toHexString());
  EXPECT_EQ(value["birth"].asString(), run.session.birth.toHexString());
  EXPECT_EQ(value["range"].asString(), run.intent.range.toHexString());
  EXPECT_EQ(value["journal"]["snapshot_state"].asString(), "released");
  EXPECT_EQ(value["journal"]["record_sha256"].asString(), bytesDigest(before.at("record.data")));
  EXPECT_EQ(value["journal"]["latest_state_sha256"].asString(),
            bytesDigest(before.at(fmt::format("state-{:020}.data", sequence))));
  ASSERT_EQ(value["revisions"].size(), 1u);
  const auto &revision = value["revisions"][0];
  ASSERT_EQ(revision["allocations"].size(), 12u);
  ASSERT_EQ(revision["endpoints"].size(), 12u);
  for (size_t shard = 0; shard < 12; ++shard) {
    const auto &identity = expected.endpoints[shard].identity;
    const auto &physical = expected.endpoints[shard].endpoint;
    const auto &item = revision["allocations"][shard];
    EXPECT_EQ(item["version"].asInt(), identity.version);
    EXPECT_EQ(item["object"].asString(), identity.object.toHexString());
    EXPECT_EQ(item["stripe_decimal"].asString(), std::to_string(identity.stripe));
    EXPECT_EQ(item["generation_decimal"].asString(), std::to_string(identity.generation));
    EXPECT_EQ(item["shard"].asInt(), shard);
    EXPECT_EQ(item["allocation"].asString(), identity.allocation.toHexString());
    const auto &endpoint = revision["endpoints"][shard];
    EXPECT_EQ(endpoint["origin_operation"].asString(), expected.endpoints[shard].operation.toHexString());
    EXPECT_EQ(endpoint["node_decimal"].asString(), std::to_string(physical.placement.node.toUnderType()));
    EXPECT_EQ(endpoint["chain_decimal"].asString(), std::to_string(physical.placement.chain.toUnderType()));
    EXPECT_EQ(endpoint["target_decimal"].asString(), std::to_string(physical.placement.target.toUnderType()));
    EXPECT_EQ(endpoint["engine_uuid"].asString(), physical.engineUuid.toHexString());
    EXPECT_EQ(endpoint["target_incarnation"].asString(), physical.targetIncarnation.toHexString());
  }
  EXPECT_EQ(bytes.find("test-token"), std::string::npos);
  EXPECT_EQ(bytes.find("readGrants"), std::string::npos);
  EXPECT_EQ(journalBytes(path_), before);
  EXPECT_EQ(storage_->calls.load(), storageCalls);
  EXPECT_EQ(calls_->acquire.load(), acquire);
  EXPECT_EQ(calls_->query.load(), query);
  EXPECT_EQ(calls_->release.load(), release);
  ASSERT_OK(exportEcTreeReadAllocations(path_, path_.parent_path() / "repeat.json"));
  EXPECT_EQ(fileBytes(path_.parent_path() / "repeat.json"), bytes);
}

TEST_F(TestEcTreeReadClient, ExplicitRdmaPolicyReachesEveryNativeBlockRead) {
  create(0, 80, 80);
  installData();
  auto selected = control();
  selected.transport = EcStorageTransportPolicy::RdmaOnly;
  auto output = blockingWait(client_->readTree(journal_, selected));
  ASSERT_OK(output);
  EXPECT_GT(storage_->calls.load(), 0u);
  EXPECT_EQ(storage_->transportMask.load(), 2u);
  EXPECT_EQ(storage_->active.load(), 0u);
  std::string expected = "0123456789abcdefXYZ";
  expected.resize(80, '\0');
  EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(output->data.bytes().data()), output->data.size()), expected);
  ASSERT_OK(blockingWait(client_->releaseTree(journal_, selected)));
}

TEST_F(TestEcTreeReadClient, InvalidStoragePolicyHasNoRangeOrStorageSideEffect) {
  create(0, 80, 80);
  ASSERT_FALSE(journal_->latest());
  for (auto policy : {EcStorageTransportPolicy::Automatic, static_cast<EcStorageTransportPolicy>(255)}) {
    auto selected = control();
    selected.transport = policy;
    ASSERT_ERROR(blockingWait(client_->readTree(journal_, selected)), StatusCode::kInvalidArg);
    EXPECT_EQ(calls_->acquire.load(), 0u);
    EXPECT_EQ(calls_->query.load(), 0u);
    EXPECT_EQ(calls_->refresh.load(), 0u);
    EXPECT_EQ(storage_->calls.load(), 0u);
    EXPECT_FALSE(journal_->latest());
  }
}
}  // namespace
}  // namespace hf3fs::client::ec
