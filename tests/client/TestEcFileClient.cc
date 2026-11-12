#include <atomic>
#include <filesystem>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <stdexcept>

#include "client/ec/EcFileRunFactory.h"
#include "client/ec/detail/EcFileClientCore.h"
#include "client/ec/detail/EcFileValidation.h"
#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"
namespace hf3fs::client::ec {
namespace detail {
struct EcFileCompletionTestAccess {
  static std::shared_ptr<EcFileClientCore> core(EcFileClient &client) { return client.core_; }
};
}  // namespace detail
namespace {
using folly::coro::blockingWait;
struct Calls {
  std::atomic<size_t> auth{0}, acquire{0}, query{0}, reads{0}, releases{0}, begins{0}, gets{0}, ownedQueries{0};
  std::vector<meta::QueryEcOwnedMutationV2Req> observations;
  unsigned observationFault = 0;
  std::vector<meta::AcquireEcRangeV2Req> acquisitions;
  std::vector<Uuid> releaseIds;
  meta::EcRangeSnapshot range;
  std::array<meta::EcV2MutationRsp, 2> published;
  bool unknownFirst = false, missingFirstQuery = false, partialFirstRelease = false, denySecondGet = false;
};
class FileService : public meta::MockMetaService {
 public:
  explicit FileService(std::shared_ptr<Calls> c)
      : c_(std::move(c)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &r) override {
    ++c_->auth;
    auto user = r.user;
    user.token.clear();
    co_return meta::AuthRsp{user};
  }
  CoTryTask<meta::EcRangeRsp> acquireEcRangeV2(serde::CallContext &, const meta::AcquireEcRangeV2Req &r) override {
    ++c_->acquire;
    c_->acquisitions.push_back(r);
    if (c_->unknownFirst && c_->acquire == 1) co_return makeError(TransactionCode::kMaybeCommitted);
    meta::EcRangeRsp rsp;
    rsp.snapshot = c_->range;
    co_return rsp;
  }
  CoTryTask<meta::EcRangeRsp> queryEcRangeV2(serde::CallContext &, const meta::QueryEcRangeV2Req &r) override {
    ++c_->query;
    if (r.uuid != c_->range.requestId || r.client.uuid != c_->range.owner.client)
      co_return makeError(StatusCode::kTokenMismatch);
    if (c_->missingFirstQuery && c_->query == 1) co_return makeError(StatusCode::kKVStoreNotFound);
    meta::EcRangeRsp rsp;
    rsp.snapshot = c_->range;
    co_return rsp;
  }
  CoTryTask<meta::AcquireEcReadV2Rsp> acquireEcReadV2(serde::CallContext &, const meta::AcquireEcReadV2Req &) override {
    ++c_->reads;
    co_return makeError(StatusCode::kIOError, "controlled read failure before Storage data");
  }
  CoTryTask<meta::ReleaseEcReadV2Rsp> releaseEcReadV2(serde::CallContext &,
                                                      const meta::ReleaseEcReadV2Req &r) override {
    ++c_->releases;
    c_->releaseIds.push_back(r.pin);
    for (size_t i = 0; i != c_->range.stripeCount; ++i)
      if (c_->range.stripes[i].snapshot.pin == r.pin) {
        meta::ReleaseEcReadV2Rsp rsp;
        rsp.pin = r.pin;
        rsp.drain.expectedEndpoints = 12;
        rsp.drain.revocation = Uuid::random();
        const bool pending = c_->partialFirstRelease && c_->releases == 2;
        rsp.drain.state = pending ? meta::EcV2DrainState::Closing : meta::EcV2DrainState::ReadReleased;
        rsp.drain.acknowledgedEndpoints = pending ? 11 : 12;
        c_->range.stripes[i].state = pending ? meta::EcRangePinState::Closing : meta::EcRangePinState::Released;
        co_return rsp;
      }
    co_return makeError(StatusCode::kTokenMismatch);
  }
  CoTryTask<meta::EcV2MutationRsp> getEcOperationV2(serde::CallContext &, const meta::GetEcOperationV2Req &) override {
    ++c_->gets;
    co_return makeError(MetaCode::kNoPermission, "legacy33 requires current READ");
  }
  CoTryTask<meta::EcOwnedMutationRsp> queryEcOwnedMutationV2(serde::CallContext &,
                                                             const meta::QueryEcOwnedMutationV2Req &r) override {
    ++c_->ownedQueries;
    c_->observations.push_back(r);
    for (size_t i = 0; i != 2; ++i)
      if (c_->published[i].record.intent.operation == r.operation) {
        if (c_->denySecondGet && i == 1) co_return makeError(MetaCode::kNoPermission);
        const auto &source = c_->published[i];
        meta::EcOwnedMutationRsp result;
        result.requestId = r.uuid;
        result.clientNamespace = r.client.uuid;
        result.record = source.record;
        result.contentSha256 = source.reservation->contentSha256;
        result.shardBytes = source.object.shardBytes;
        result.drain = source.drain;
        result.publishedContentConfirmed = true;
        switch (c_->observationFault) {
          case 1:
            result.requestId = Uuid::random();
            break;
          case 2:
            result.clientNamespace = Uuid::random();
            break;
          case 3:
            result.record.owner.uid = flat::Uid(777);
            break;
          case 4:
            result.contentSha256[0] ^= 1;
            break;
          case 5:
            result.publishedContentConfirmed = false;
            break;
          case 6:
            ++result.record.candidate.fragments[0].identity.generation;
            break;
          case 7:
            ++result.record.intent.expectedEpoch;
            break;
          default:
            break;
        }
        co_return result;
      }
    co_return makeError(StatusCode::kKVStoreNotFound);
  }
  CoTryTask<meta::EcV2MutationRsp> beginEcMutationV2(serde::CallContext &,
                                                     const meta::BeginEcMutationV2Req &) override {
    ++c_->begins;
    co_return makeError(StatusCode::kFoundBug);
  }

 private:
  std::shared_ptr<Calls> c_;
};
class TestEcFileClient : public ::testing::Test {
 protected:
  void SetUp() override {
    metaConfig_.set_network_type(net::Address::TCP);
    metaConfig_.retry_default().set_retry_init_wait(0_ms);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<storage::client::StorageClientInMem>(ClientId::random(), storageConfig_, *mgmtd_);
    owner_ = {flat::Uid(123), Uuid::random()};
    file_.object = {meta::InodeId(101), Uuid::random()};
    file_.layout.incarnation = file_.object.incarnation;
    file_.layout.shardBytes = 8;
    file_.length = 160;
    file_.epoch = 1;
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
    mock.setService(std::make_unique<FileService>(calls_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(owner_.client),
                                                       metaConfig_,
                                                       std::make_unique<meta::client::MetaClient::StubFactory>(mock),
                                                       mgmtd_,
                                                       storage_,
                                                       false);
    auto result = blockingWait(EcFileClient::connect(meta_,
                                                     storage_,
                                                     mgmtd_,
                                                     flat::UserInfo{owner_.uid, flat::Gid(123), "test-token"},
                                                     owner_.client,
                                                     pool_));
    ASSERT_OK(result);
    client_ = std::move(*result);
  }
  EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  void createRead(uint64_t offset, uint64_t length) {
    auto r = prepareEcFileRead(file_, owner_, "file-client-test", offset, length, Uuid::random());
    ASSERT_OK(r);
    path_ = std::filesystem::path(temp_.path().string()) / "run";
    auto j = EcFileRunJournal::create(path_, *r);
    ASSERT_OK(j);
    journal_ = std::shared_ptr<EcFileRunJournal>(std::move(*j));
    auto &s = calls_->range;
    s.owner = owner_;
    s.requestId = r->rangeRequest;
    s.rangeId = r->rangeId;
    s.selection = detail::fileSelection(*r);
    s.file = file_;
    // The first Acquire epoch belongs to that transaction, not prior Describe.
    s.file.epoch = 9;
    auto plan = planEcFileRead(r->shardBytes, offset, length);
    ASSERT_OK(plan);
    auto clipped = clipEcFileRead(*plan, file_.length);
    ASSERT_OK(clipped);
    s.readableLength = clipped->length;
    s.stripeCount = clipped->count;
    for (size_t i = 0; i != s.stripeCount; ++i) {
      auto &entry = s.stripes[i];
      entry.state = meta::EcRangePinState::Active;
      entry.logicalLength = 80;
      entry.contentSha256[0] = 1;
      auto &pin = entry.snapshot;
      pin.object = r->object;
      pin.pin = r->slots[i].pin;
      pin.stripe = r->slots[i].stripe;
      pin.revision = 10 + i;
      pin.generation = 20 + i;
      pin.owner = owner_;
      std::array<storage::EcScopeEndpoint, 12> endpoints;
      for (size_t j = 0; j != 12; ++j) {
        auto &e = pin.endpoints[j];
        e.identity.object = r->object.incarnation;
        e.identity.stripe = pin.stripe;
        e.identity.generation = pin.generation;
        e.identity.shard = j;
        e.identity.allocation = Uuid::random();
        e.operation = Uuid::random();
        e.endpoint = {{storage::ChainId(100 + j), storage::TargetId(200 + j), flat::NodeId(9)},
                      Uuid::random(),
                      Uuid::random()};
        endpoints[j] = e.endpoint.controlEndpoint();
      }
      auto hash = storage::computeEcScopeEndpointDigest(endpoints);
      ASSERT_OK(hash);
      pin.endpointSetDigest = *hash;
    }
  }
  void publishedFor(const EcFileRunRecord &r, size_t index) {
    auto &rsp = calls_->published[index];
    const auto &slot = r.slots[index];
    rsp.object.object = r.object;
    rsp.object.shardBytes = r.shardBytes;
    rsp.object.epoch = r.epoch;
    auto &op = rsp.record;
    op.owner = r.owner;
    op.state = meta::EcOperationState::Published;
    auto &intent = op.intent;
    intent.object = r.object;
    intent.operation = slot.mutation.operation;
    intent.stripe = slot.stripe;
    intent.expectedEpoch = r.epoch;
    intent.logicalLength = 80;
    intent.kind = meta::EcMutationKind::Write;
    auto &m = op.candidate;
    m.object = r.object;
    m.stripe = slot.stripe;
    m.generation = 20 + index;
    m.revision = 30 + index;
    m.logicalLength = 80;
    rsp.reservation.emplace();
    rsp.allocations.emplace();
    auto &reserved = *rsp.reservation;
    reserved.contentSha256 = slot.contentSha256;
    reserved.operationEndpoints.count = 12;
    std::array<storage::EcScopeEndpoint, 12> endpoints;
    for (size_t j = 0; j != 12; ++j) {
      auto &binding = (*rsp.allocations)[j];
      binding.object = r.object;
      binding.writer = r.owner;
      binding.engineUuid = Uuid::random();
      binding.targetIncarnation = Uuid::random();
      auto &f = binding.fragment;
      f.identity.object = r.object.incarnation;
      f.identity.stripe = slot.stripe;
      f.identity.generation = m.generation;
      f.identity.shard = j;
      f.identity.allocation = Uuid::random();
      f.operation = slot.mutation.operation;
      f.placement = {storage::ChainId(100 + j), storage::TargetId(200 + j), flat::NodeId(9)};
      auto integrity = storage::computeEcIntegrity(f.identity, std::string(8, 'x'));
      ASSERT_OK(integrity);
      f.integrity = *integrity;
      intent.placements[j] = f.placement;
      intent.fragmentCrc32c[j] = f.integrity.wholeCrc32c;
      m.fragments[j] = f;
      reserved.candidates[j] = {f.identity, f.operation, binding.endpoint(), binding.writer};
      reserved.operationEndpoints.endpoints[j] = binding.endpoint();
      endpoints[j] = binding.endpoint().controlEndpoint();
    }
    auto digest = meta::computeEcRequestDigest(intent, r.shardBytes, slot.contentSha256);
    ASSERT_OK(digest);
    intent.requestDigest = *digest;
    auto setDigest = storage::computeEcScopeEndpointDigest(endpoints);
    ASSERT_OK(setDigest);
    reserved.operationEndpoints.digest = *setDigest;
    rsp.drain.emplace();
    rsp.drain->state = meta::EcV2DrainState::Published;
    rsp.drain->revocation = Uuid::random();
    rsp.drain->expectedEndpoints = 12;
    rsp.drain->acknowledgedEndpoints = 12;
    reserved.original = op;
    reserved.original.state = meta::EcOperationState::Preparing;
    for (auto &f : reserved.original.candidate.fragments) f.integrity = {};
  }
  folly::test::TemporaryDirectory temp_;
  std::filesystem::path path_;
  folly::CPUThreadPoolExecutor pool_{2};
  meta::client::MetaClient::Config metaConfig_;
  storage::client::StorageClient::Config storageConfig_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClientInMem> storage_;
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<EcFileClient> client_;
  std::shared_ptr<Calls> calls_ = std::make_shared<Calls>();
  std::shared_ptr<EcFileRunJournal> journal_;
  meta::EcOwner owner_;
  meta::EcFileState file_;
};
TEST_F(TestEcFileClient, UnknownAcquireMissingQueryAndRestartKeepEveryOriginalIdentity) {
  createRead(UINT64_MAX, 0);
  calls_->unknownFirst = true;
  calls_->missingFirstQuery = true;
  auto first = blockingWait(client_->read(journal_, control()));
  ASSERT_ERROR(first, TransactionCode::kMaybeCommitted);
  EXPECT_TRUE(journal_->latest()->acquisitionIssued);
  EXPECT_FALSE(journal_->latest()->snapshotObserved);
  const auto original = journal_->record().rangeId;
  blockingWait(client_->close());
  client_.reset();
  journal_.reset();
  auto reopened = EcFileRunJournal::resume(path_);
  ASSERT_OK(reopened);
  journal_ = std::shared_ptr<EcFileRunJournal>(std::move(*reopened));
  open();
  auto second = blockingWait(client_->read(journal_, control()));
  ASSERT_OK(second);
  EXPECT_EQ(second->data.size(), 0);
  ASSERT_EQ(calls_->acquisitions.size(), 2);
  EXPECT_EQ(calls_->acquisitions[0].uuid, calls_->acquisitions[1].uuid);
  EXPECT_EQ(calls_->acquisitions[1].rangeId, original);
  EXPECT_EQ(calls_->acquisitions[1].client.uuid, owner_.client);
  EXPECT_TRUE(journal_->latest()->allPinsReleased());  // Zero-pin range is confirmed and locally complete.
  auto released = blockingWait(client_->releaseRead(journal_, control()));
  EXPECT_TRUE(released.allReleased);
  EXPECT_EQ(calls_->releases.load(), 0);
}
TEST_F(TestEcFileClient, FailedFirstStripeStillReleasesNeverReadPinsAndPendingT2IsNotSuccess) {
  createRead(0, 160);
  calls_->partialFirstRelease = true;
  auto read = blockingWait(client_->read(journal_, control()));
  ASSERT_FALSE(read);
  EXPECT_EQ(calls_->reads.load(), 1);
  EXPECT_TRUE(journal_->latest()->localComplete);
  EXPECT_EQ(client_->payloadBytes(), 0);
  auto first = blockingWait(client_->releaseRead(journal_, control()));
  EXPECT_FALSE(first.allReleased);
  EXPECT_EQ(first.releasedMask, 1);
  ASSERT_EQ(calls_->releaseIds.size(), 2);
  EXPECT_EQ(calls_->releaseIds[1], journal_->record().slots[1].pin);
  auto second = blockingWait(client_->releaseRead(journal_, control()));
  EXPECT_TRUE(second.allReleased);
  EXPECT_EQ(calls_->releases.load(), 3);
}
TEST_F(TestEcFileClient, AlteredSnapshotIsRejectedAndReleasedPinIsNeverReacquired) {
  createRead(0, 160);
  auto first = blockingWait(client_->read(journal_, control()));
  ASSERT_FALSE(first);
  const auto issued = calls_->acquire.load();
  const auto reads = calls_->reads.load();
  const auto original = calls_->range.stripes[0].snapshot.endpoints[0].identity.allocation;
  calls_->range.stripes[0].snapshot.endpoints[0].identity.allocation = Uuid::random();
  auto second = blockingWait(client_->read(journal_, control()));
  ASSERT_ERROR(second, StatusCode::kDataCorruption);
  EXPECT_EQ(calls_->acquire.load(), issued);
  EXPECT_EQ(calls_->reads.load(), reads);
  calls_->range.stripes[0].snapshot.endpoints[0].identity.allocation = original;
  auto released = blockingWait(client_->releaseRead(journal_, control()));
  EXPECT_TRUE(released.allReleased);
  auto again = blockingWait(client_->read(journal_, control()));
  ASSERT_ERROR(again, StatusCode::kTokenStale);
  EXPECT_EQ(calls_->acquire.load(), issued);
  EXPECT_EQ(calls_->reads.load(), reads);
}
TEST_F(TestEcFileClient, AppendRecoveryRevalidatesPublishedPrefixBeforeAnyLaterBegin) {
  auto input = client_->allocatePayload(160);
  ASSERT_OK(input);
  std::fill(input->bytes().begin(), input->bytes().end(), 7);
  auto r =
      prepareEcFileAppend(file_, owner_, "file-client-test", 160, "/original-input", input->bytes(), Uuid::random());
  ASSERT_OK(r);
  path_ = std::filesystem::path(temp_.path().string()) / "append";
  auto j = EcFileRunJournal::create(path_, *r);
  ASSERT_OK(j);
  journal_ = std::shared_ptr<EcFileRunJournal>(std::move(*j));
  EcFileRunProgress p;
  p.appendStates[0] = EcFileAppendState::Issued;
  ASSERT_OK(journal_->append(p));
  p.appendStates[0] = EcFileAppendState::Published;
  ASSERT_OK(journal_->append(p));
  p.appendStates[1] = EcFileAppendState::Issued;
  ASSERT_OK(journal_->append(p));
  publishedFor(*r, 0);
  publishedFor(*r, 1);
  calls_->denySecondGet = true;
  auto outcome = blockingWait(client_->appendAt(journal_, std::move(*input), control()));
  EXPECT_FALSE(outcome.complete);
  EXPECT_EQ(outcome.confirmedPrefixBytes, 80);
  EXPECT_EQ(outcome.revalidatedPrefixBytes, 80);
  ASSERT_TRUE(outcome.failure);
  EXPECT_EQ(outcome.failure->code(), MetaCode::kNoPermission);
  EXPECT_EQ(calls_->ownedQueries.load(), 2);
  EXPECT_EQ(calls_->gets.load(), 0);
  EXPECT_EQ(calls_->begins.load(), 0);
  const auto validDrain = calls_->published[0].drain;
  for (unsigned variant = 0; variant != 4; ++variant) {
    SCOPED_TRACE(variant);
    calls_->published[0].drain = validDrain;
    if (variant == 0) calls_->published[0].drain.reset();
    if (variant == 1) calls_->published[0].drain->state = meta::EcV2DrainState::Closing;
    if (variant == 2) calls_->published[0].drain->acknowledgedEndpoints = 11;
    if (variant == 3) calls_->published[0].drain->revocation = Uuid::zero();
    auto retry = client_->allocatePayload(160);
    ASSERT_OK(retry);
    std::fill(retry->bytes().begin(), retry->bytes().end(), 7);
    auto rejected = blockingWait(client_->appendAt(journal_, std::move(*retry), control()));
    ASSERT_TRUE(rejected.failure);
    EXPECT_EQ(rejected.failure->code(), StatusCode::kDataCorruption);
    EXPECT_EQ(rejected.confirmedPrefixBytes, 80);
    EXPECT_EQ(rejected.revalidatedPrefixBytes, 0);
    EXPECT_EQ(calls_->begins.load(), 0);
  }
  calls_->published[0].drain = validDrain;
  for (unsigned variant = 1; variant != 8; ++variant) {
    SCOPED_TRACE(variant);
    calls_->observationFault = variant;
    auto retry = client_->allocatePayload(160);
    ASSERT_OK(retry);
    std::fill(retry->bytes().begin(), retry->bytes().end(), 7);
    auto rejected = blockingWait(client_->appendAt(journal_, std::move(*retry), control()));
    ASSERT_TRUE(rejected.failure);
    EXPECT_EQ(rejected.failure->code(), StatusCode::kDataCorruption);
    EXPECT_EQ(rejected.confirmedPrefixBytes, 80);
    EXPECT_EQ(rejected.revalidatedPrefixBytes, 0);
  }
  EXPECT_EQ(calls_->gets.load(), 0);
  EXPECT_EQ(calls_->begins.load(), 0);
  for (const auto &req : calls_->observations) {
    const size_t index = req.operation == r->slots[0].mutation.operation ? 0 : 1;
    EXPECT_EQ(req.uuid, r->slots[index].mutation.getRequest);
    EXPECT_EQ(req.client.uuid, owner_.client);
    EXPECT_EQ(req.user.uid, owner_.uid);
    EXPECT_EQ(req.object, r->object);
  }
}
TEST_F(TestEcFileClient, WrongEffectiveOwnerAndForeignPayloadNeverDispatchRangeOrBegin) {
  createRead(0, 160);
  auto r = journal_->record();
  r.owner.uid = flat::Uid(777);
  auto other = EcFileRunJournal::create(std::filesystem::path(temp_.path().string()) / "other", r);
  ASSERT_OK(other);
  auto bad = blockingWait(client_->read(std::shared_ptr<EcFileRunJournal>(std::move(*other)), control()));
  ASSERT_ERROR(bad, StatusCode::kTokenMismatch);
  EXPECT_EQ(calls_->acquire.load(), 0);
  EXPECT_EQ(calls_->query.load(), 0);
  auto budget = EcFilePayloadBudget::create();
  ASSERT_OK(budget);
  auto payload = (*budget)->allocate(160);
  ASSERT_OK(payload);
  auto outcome = blockingWait(client_->appendAt(journal_, std::move(*payload), control()));
  ASSERT_TRUE(outcome.failure);
  EXPECT_EQ(calls_->begins.load(), 0);
}

struct FileCloseProbe {
  unsigned factories = 0;
  unsigned failures = 0;
  static CoTask<void> make(void *context, EcStripeClient &stripe) {
    auto &self = *static_cast<FileCloseProbe *>(context);
    ++self.factories;
    if (self.failures) {
      --self.failures;
      throw std::bad_alloc{};
    }
    return stripe.close();  // Every non-injected join is the actual lower manager.
  }
};
CoTryTask<Void> exceptionalFileBusiness(std::atomic<size_t> &executed) {
  ++executed;
  throw std::runtime_error("controlled business exception before completion");
  co_return Void{};
}
TEST_F(TestEcFileClient, BusinessExceptionAndCloseFactoryFailureSettleBeforeRetryingSameCore) {
  auto core = detail::EcFileCompletionTestAccess::core(*client_);
  FileCloseProbe probe{0, 1};
  core->stripeCloseFactoryForTest = &FileCloseProbe::make;
  core->stripeCloseFactoryContextForTest = &probe;
  SCOPE_EXIT {
    core->stripeCloseFactoryForTest = nullptr;
    blockingWait(client_->close());
  };
  std::atomic<size_t> executed{0};
  auto result = blockingWait(
      core->launch<Result<Void>>([&] { return exceptionalFileBusiness(executed); },
                                 [](Status error) -> Result<Void> { return makeError(std::move(error)); }));
  ASSERT_ERROR(result, StatusCode::kIOError);
  EXPECT_EQ(executed.load(), 1);
  EXPECT_EQ(probe.factories, 1);
  EXPECT_FALSE(core->activeCall);
  EXPECT_TRUE(core->closing);
  EXPECT_FALSE(core->stripeJoinStarted);
  EXPECT_FALSE(core->stripeJoined);
  EXPECT_EQ(core->unconfirmedJoinLease.get(), core.get());
  EXPECT_TRUE(client_->localJoinUnconfirmed());
  auto refused = blockingWait(
      core->launch<Result<Void>>([&] { return exceptionalFileBusiness(executed); },
                                 [](Status error) -> Result<Void> { return makeError(std::move(error)); }));
  ASSERT_ERROR(refused, StorageClientCode::kResourceBusy);
  EXPECT_EQ(executed.load(), 1);
  blockingWait(client_->close());
  EXPECT_EQ(probe.factories, 2);
  EXPECT_TRUE(core->tasksJoined);
  EXPECT_TRUE(core->stripeJoined);
  EXPECT_TRUE(core->closeComplete);
  EXPECT_FALSE(core->unconfirmedJoinLease);
  EXPECT_FALSE(client_->localJoinUnconfirmed());
  blockingWait(client_->close());
  EXPECT_EQ(probe.factories, 2);
}
TEST_F(TestEcFileClient, PreAdmissionFallbackSurvivesASecondCompletionException) {
  auto core = detail::EcFileCompletionTestAccess::core(*client_);
  std::atomic<size_t> executed{0};
  unsigned failureConstructions = 0;
  auto result = blockingWait(core->launch<Result<Void>>([&] { return exceptionalFileBusiness(executed); },
                                                        [&](Status error) -> Result<Void> {
                                                          if (++failureConstructions != 1) throw std::bad_alloc{};
                                                          return makeError(std::move(error));
                                                        }));
  ASSERT_ERROR(result, StatusCode::kNotEnoughMemory);
  EXPECT_EQ(executed.load(), 1);
  EXPECT_EQ(failureConstructions, 2);
  EXPECT_FALSE(core->activeCall);
  EXPECT_TRUE(core->stripeJoined);
  blockingWait(client_->close());
  EXPECT_TRUE(core->closeComplete);
}
TEST_F(TestEcFileClient, CloseFactoryFailureAfterScopeJoinCanRetryWithoutRepeatingThatJoin) {
  auto core = detail::EcFileCompletionTestAccess::core(*client_);
  FileCloseProbe probe{0, 1};
  core->stripeCloseFactoryForTest = &FileCloseProbe::make;
  core->stripeCloseFactoryContextForTest = &probe;
  SCOPE_EXIT {
    core->stripeCloseFactoryForTest = nullptr;
    blockingWait(client_->close());
  };
  EXPECT_THROW(blockingWait(client_->close()), std::bad_alloc);
  EXPECT_TRUE(core->tasksJoinStarted);
  EXPECT_TRUE(core->tasksJoined);
  EXPECT_FALSE(core->stripeJoinStarted);
  EXPECT_FALSE(core->closeComplete);
  EXPECT_FALSE(core->closeAttempt);
  EXPECT_EQ(core->unconfirmedJoinLease.get(), core.get());
  blockingWait(client_->close());
  EXPECT_EQ(probe.factories, 2);
  EXPECT_TRUE(core->closeComplete);
  EXPECT_FALSE(core->unconfirmedJoinLease);
  // Folly forbids a second AsyncScope::joinAsync(); this successful replay
  // passes only because the completed first stage is retained and skipped.
  blockingWait(client_->close());
  EXPECT_EQ(probe.factories, 2);
}
}  // namespace
}  // namespace hf3fs::client::ec
