#include <algorithm>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <new>

#include "client/ec/EcFileRunFactory.h"
#include "client/ec/EcReadDispatcher.h"
#include "client/ec/detail/EcFileClientCore.h"
#include "client/ec/detail/EcReadDispatcherCore.h"
#include "client/ec/detail/EcReadSpoolArchive.h"
#include "client/storage/StorageClientInMem.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace detail {
struct EcReadDispatcherTestAccess {
  static std::shared_ptr<EcReadDispatcherCore> core(const std::shared_ptr<EcReadDispatcher> &value) {
    return value->core_;
  }
};
struct EcReadSpoolTestAccess {
  static void markPriorPersistenceUncertain(EcReadSpool &spool) { spool.poisoned_.store(true); }
  static Result<std::shared_ptr<EcReadSpool>> loadWithOwnershipHook(const std::filesystem::path &path,
                                                                    void (*hook)(void *, unsigned, int, int),
                                                                    void *context) {
    return EcReadSpool::load(path, "dispatch-test", {}, false, hook, context);
  }
};
// Identical test-access definition to F3's test translation unit (ODR).
struct EcFileCompletionTestAccess {
  static std::shared_ptr<EcFileClientCore> core(EcFileClient &client) { return client.core_; }
};
}  // namespace detail
namespace {
using folly::coro::blockingWait;
struct DispatchCalls {
  std::atomic<size_t> authenticate{0}, describe{0}, acquire{0}, query{0}, release{0};
  bool uncertainFirst = false, denyQueries = false, closingRelease = false, incompleteAck = false;
  meta::EcFileState file;
  std::vector<meta::AcquireEcRangeV2Req> acquisitions;
  std::map<Uuid, meta::EcRangeSnapshot> ranges;
  std::shared_ptr<folly::coro::Baton> describeEntered, describeContinue;
};
class DispatchService : public meta::MockMetaService {
 public:
  explicit DispatchService(std::shared_ptr<DispatchCalls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &req) override {
    ++calls_->authenticate;
    if (req.user.token != "owner-token" || req.user.uid != flat::Uid(123))
      co_return makeError(StatusCode::kAuthenticationFail);
    auto user = req.user;
    user.token.clear();
    co_return meta::AuthRsp{user};
  }
  CoTryTask<meta::DescribeEcFileV2Rsp> describeEcFileV2(serde::CallContext &,
                                                        const meta::DescribeEcFileV2Req &req) override {
    ++calls_->describe;
    if (calls_->describeEntered) calls_->describeEntered->post();
    if (calls_->describeContinue) co_await *calls_->describeContinue;
    if (req.object != calls_->file.object || req.access != meta::AccessType::READ || req.uuid.is_nil())
      co_return makeError(StatusCode::kTokenMismatch);
    meta::DescribeEcFileV2Rsp rsp;
    rsp.file = calls_->file;
    co_return rsp;
  }
  CoTryTask<meta::EcRangeRsp> acquireEcRangeV2(serde::CallContext &, const meta::AcquireEcRangeV2Req &req) override {
    ++calls_->acquire;
    calls_->acquisitions.push_back(req);
    if (calls_->uncertainFirst && calls_->acquire == 1) co_return makeError(TransactionCode::kMaybeCommitted);
    // Nonempty variants deliberately fail the lower read: this mock supplies
    // metadata lifecycle observations, never simulated successful Storage data.
    meta::EcRangeSnapshot s;
    s.owner = {req.user.uid, req.client.uuid};
    s.requestId = req.uuid;
    s.rangeId = req.rangeId;
    s.selection = req.selection;
    s.file = calls_->file;
    if (req.selection.length && req.selection.offset < s.file.length) {
      s.readableLength = std::min(req.selection.length, s.file.length - req.selection.offset);
      s.stripeCount = 1;
      auto &entry = s.stripes[0];
      entry.state = meta::EcRangePinState::Active;
      entry.logicalLength = 80;
      entry.contentSha256[0] = 1;
      auto &pin = entry.snapshot;
      pin.object = req.selection.object;
      pin.pin = req.selection.pins[0].pin;
      pin.stripe = 0;
      pin.revision = 3;
      pin.generation = 2;
      pin.owner = s.owner;
      std::array<storage::EcScopeEndpoint, 12> endpoints;
      for (size_t i = 0; i != 12; ++i) {
        auto &e = pin.endpoints[i];
        e.identity.object = req.selection.object.incarnation;
        e.identity.stripe = 0;
        e.identity.generation = 2;
        e.identity.shard = i;
        e.identity.allocation = Uuid::random();
        e.operation = Uuid::random();
        e.endpoint = {{storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(9)},
                      Uuid::random(),
                      Uuid::random()};
        endpoints[i] = e.endpoint.controlEndpoint();
      }
      auto digest = storage::computeEcScopeEndpointDigest(endpoints);
      CO_RETURN_ON_ERROR(digest);
      pin.endpointSetDigest = *digest;
    }
    calls_->ranges[req.rangeId] = s;
    meta::EcRangeRsp rsp;
    rsp.snapshot = s;
    co_return rsp;
  }
  CoTryTask<meta::EcRangeRsp> queryEcRangeV2(serde::CallContext &, const meta::QueryEcRangeV2Req &req) override {
    ++calls_->query;
    if (calls_->denyQueries || !calls_->ranges.count(req.rangeId)) co_return makeError(StatusCode::kKVStoreNotFound);
    const auto &s = calls_->ranges.at(req.rangeId);
    if (s.requestId != req.uuid || s.owner.client != req.client.uuid || s.owner.uid != req.user.uid ||
        !serde::equals(s.selection, req.selection))
      co_return makeError(StatusCode::kTokenMismatch);
    meta::EcRangeRsp rsp;
    rsp.snapshot = s;
    co_return rsp;
  }
  CoTryTask<meta::AcquireEcReadV2Rsp> acquireEcReadV2(serde::CallContext &, const meta::AcquireEcReadV2Req &) override {
    co_return makeError(StatusCode::kIOError, "controlled failure; no mock Storage success");
  }
  CoTryTask<meta::ReleaseEcReadV2Rsp> releaseEcReadV2(serde::CallContext &,
                                                      const meta::ReleaseEcReadV2Req &req) override {
    ++calls_->release;
    for (auto &[id, range] : calls_->ranges) {
      if (!range.stripeCount || range.stripes[0].snapshot.pin != req.pin) continue;
      meta::ReleaseEcReadV2Rsp rsp;
      rsp.pin = req.pin;
      rsp.drain.revocation = Uuid::random();
      rsp.drain.expectedEndpoints = 12;
      rsp.drain.acknowledgedEndpoints = calls_->closingRelease || calls_->incompleteAck ? 11 : 12;
      rsp.drain.state = calls_->closingRelease ? meta::EcV2DrainState::Closing : meta::EcV2DrainState::ReadReleased;
      range.stripes[0].state =
          calls_->closingRelease ? meta::EcRangePinState::Closing : meta::EcRangePinState::Released;
      co_return rsp;
    }
    co_return makeError(StatusCode::kFoundBug, "zero-pin test must not invent pin release");
  }

 private:
  std::shared_ptr<DispatchCalls> calls_;
};
class TestEcReadDispatcher : public ::testing::Test {
 protected:
  void SetUp() override {
    config_.set_network_type(net::Address::TCP);
    config_.retry_default().set_retry_init_wait(0_ms);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    storage_ = std::make_shared<storage::client::StorageClientInMem>(ClientId::random(), storageConfig_, *mgmtd_);
    calls_->file.object = {meta::InodeId(101), Uuid::random()};
    calls_->file.layout.incarnation = calls_->file.object.incarnation;
    calls_->file.layout.shardBytes = 8;
    calls_->file.epoch = 1;
    calls_->file.length = 0;
    auto made = EcReadSpool::create(path("spool"), "dispatch-test", {2, 1, 6u << 20});
    ASSERT_OK(made);
    spool_ = std::move(*made);
    ASSERT_NO_FATAL_FAILURE(connect());
  }
  void TearDown() override {
    if (dispatcher_) blockingWait(dispatcher_->stop());
    dispatcher_.reset();
    if (meta_) meta_->stop();
  }
  void connect() {
    if (meta_) meta_->stop();
    serde::ClientMockContext mock;
    mock.setService(std::make_unique<DispatchService>(calls_));
    meta_ = std::make_shared<meta::client::MetaClient>(ClientId(spool_->clientNamespace()),
                                                       config_,
                                                       std::make_unique<meta::client::MetaClient::StubFactory>(mock),
                                                       mgmtd_,
                                                       storage_,
                                                       false);
    auto connected = EcReadDispatcher::connect(spool_, meta_, storage_, mgmtd_, pool_, {});
    ASSERT_OK(connected);
    dispatcher_ = std::move(*connected);
  }
  static EcStripeControl control() { return {std::chrono::steady_clock::now() + std::chrono::seconds(30), {}}; }
  std::filesystem::path path(std::string name) const { return std::filesystem::path(temp_.path().string()) / name; }
  Result<EcReadHandle> open() { return blockingWait(dispatcher_->openRead(calls_->file.object, user_, control())); }
  folly::test::TemporaryDirectory temp_;
  folly::CPUThreadPoolExecutor pool_{2};
  meta::client::MetaClient::Config config_;
  storage::client::StorageClient::Config storageConfig_;
  flat::UserInfo user_{flat::Uid(123), flat::Gid(123), "owner-token"};
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<storage::client::StorageClientInMem> storage_;
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<EcReadSpool> spool_;
  std::shared_ptr<EcReadDispatcher> dispatcher_;
  std::shared_ptr<DispatchCalls> calls_ = std::make_shared<DispatchCalls>();
};

TEST_F(TestEcReadDispatcher, AuthenticationActualNamespaceAndSharedHandleCannotBypassAdmission) {
  auto construction = EcReadSpool::create(path("construction"), "dispatch-test", {});
  ASSERT_OK(construction);
  const auto constructionNamespace = (*construction)->clientNamespace();
  construction->reset();
  struct OwnershipProbe {
    unsigned failedStage;
    int directory = -1, lock = -1;
    static void inject(void *context, unsigned stage, int directory, int lock) {
      auto &probe = *static_cast<OwnershipProbe *>(context);
      probe.directory = directory;
      probe.lock = lock;
      if (stage == probe.failedStage) throw std::bad_alloc();
    }
  };
  for (unsigned stage = 0; stage != 2; ++stage) {
    SCOPED_TRACE(stage);
    OwnershipProbe probe{stage};
    auto failed =
        detail::EcReadSpoolTestAccess::loadWithOwnershipHook(path("construction"), &OwnershipProbe::inject, &probe);
    ASSERT_ERROR(failed, StatusCode::kNotEnoughMemory);
    ASSERT_GE(probe.directory, 0);
    ASSERT_GE(probe.lock, 0);
    errno = 0;
    EXPECT_EQ(::fcntl(probe.directory, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    errno = 0;
    EXPECT_EQ(::fcntl(probe.lock, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    auto retried = EcReadSpool::open(path("construction"), "dispatch-test", {});
    ASSERT_OK(retried);
    EXPECT_EQ((*retried)->clientNamespace(), constructionNamespace);
  }
  ASSERT_ERROR(EcReadSpool::create(path(std::string("bad\0spool", 9)), "dispatch-test", {}), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcReadSpool::create(path("bad-cluster"), std::string("bad\0cluster", 11), {}), StatusCode::kInvalidArg);
  auto wrong = user_;
  wrong.token = "wrong";
  ASSERT_ERROR(blockingWait(dispatcher_->openRead(calls_->file.object, wrong, control())),
               StatusCode::kAuthenticationFail);
  wrong = user_;
  wrong.uid = flat::Uid(0);
  ASSERT_ERROR(blockingWait(dispatcher_->openRead(calls_->file.object, wrong, control())),
               StatusCode::kAuthenticationFail);
  EXPECT_EQ(calls_->describe.load(), 0);
  EXPECT_EQ(calls_->acquire.load(), 0);
  ASSERT_ERROR(EcReadDispatcher::connect(spool_, meta_, storage_, mgmtd_, pool_, {}), StorageClientCode::kResourceBusy);
  ASSERT_ERROR(EcReadSpool::open(path("spool"), "dispatch-test", spool_->limits()), StorageClientCode::kResourceBusy);
  auto handle = open();
  ASSERT_OK(handle);
  EXPECT_EQ(calls_->describe.load(), 1);
  auto oldNamespace = spool_->clientNamespace();
  auto stopped = blockingWait(dispatcher_->stop());
  EXPECT_TRUE(stopped.localJoined);
  EXPECT_TRUE(stopped.inventoryVerified);
  dispatcher_.reset();
  spool_.reset();
  auto wrongCluster = EcReadSpool::open(path("spool"), "another-cluster", {});
  ASSERT_ERROR(wrongCluster, StatusCode::kTokenMismatch);
  auto reopened = EcReadSpool::open(path("spool"), "dispatch-test", {});
  ASSERT_OK(reopened);
  spool_ = std::move(*reopened);
  EXPECT_EQ(spool_->clientNamespace(), oldNamespace);
  ASSERT_NO_FATAL_FAILURE(connect());
  ASSERT_ERROR(blockingWait(dispatcher_->read(*handle, user_, 0, 0, control())), StatusCode::kTokenMismatch);
}
TEST_F(TestEcReadDispatcher, UnknownAcquireMissingQueryRestartKeepOriginalIdsAndNeverRetireDebt) {
  calls_->uncertainFirst = true;
  auto handle = open();
  ASSERT_OK(handle);
  auto first = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
  ASSERT_OK(first);
  EXPECT_TRUE(first->localJoined);
  EXPECT_TRUE(first->cleanup.localJoined);
  ASSERT_TRUE(first->readFailure);
  EXPECT_EQ(first->readFailure->code(), TransactionCode::kMaybeCommitted);
  EXPECT_FALSE(first->cleanup.allReleased);
  ASSERT_EQ(calls_->acquisitions.size(), 1);
  const auto original = calls_->acquisitions.front();
  const auto receipt = first->receipt;
  ASSERT_FALSE(blockingWait(dispatcher_->retire(receipt, user_, path("unknown.json"), control())));
  EXPECT_FALSE(std::filesystem::exists(path("unknown.json")));
  ASSERT_TRUE(blockingWait(dispatcher_->stop()).inventoryVerified);
  dispatcher_.reset();
  spool_.reset();
  auto reopened = EcReadSpool::open(path("spool"), "dispatch-test", {2, 1, 6u << 20});
  ASSERT_OK(reopened);
  spool_ = std::move(*reopened);
  ASSERT_NO_FATAL_FAILURE(connect());
  auto second = blockingWait(dispatcher_->resumeRead(receipt, user_, control()));
  ASSERT_OK(second);
  ASSERT_TRUE(second->data);
  EXPECT_TRUE(second->data->bytes().empty());
  EXPECT_TRUE(second->cleanup.allReleased);
  ASSERT_EQ(calls_->acquisitions.size(), 2);
  EXPECT_TRUE(serde::equals(original, calls_->acquisitions.back()));
  EXPECT_EQ(calls_->release.load(), 0);
  auto held = blockingWait(dispatcher_->retire(receipt, user_, path("complete.json"), control()));
  ASSERT_ERROR(held, StorageClientCode::kResourceBusy);
  second->data.reset();
  calls_->denyQueries = true;
  ASSERT_ERROR(blockingWait(dispatcher_->retire(receipt, user_, path("complete.json"), control())),
               StatusCode::kKVStoreNotFound);
  EXPECT_FALSE(std::filesystem::exists(path("complete.json")));  // Missing is never terminal proof.
  calls_->denyQueries = false;
  auto retired = blockingWait(dispatcher_->retire(receipt, user_, path("complete.json"), control()));
  ASSERT_OK(retired);
  EXPECT_TRUE(retired->localFilesRemoved);
  auto local = blockingWait(dispatcher_->inspectReceipt(receipt));
  ASSERT_OK(local);
  EXPECT_EQ(local->evidence, EcReadLocalEvidence::NotRetained);
  const auto issued = calls_->acquire.load();
  ASSERT_ERROR(blockingWait(dispatcher_->resumeRead(receipt, user_, control())), StatusCode::kKVStoreNotFound);
  EXPECT_EQ(calls_->acquire.load(), issued);
}
TEST_F(TestEcReadDispatcher, ExplicitRetirementReclaimsQuotaWithoutReusingReceiptOrOutputBudget) {
  auto handle = open();
  ASSERT_OK(handle);
  uint64_t previous = 0;
  for (unsigned iteration = 0; iteration != 12; ++iteration) {
    auto result = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
    ASSERT_OK(result);
    ASSERT_TRUE(result->data);
    ASSERT_TRUE(result->cleanup.allReleased);
    EXPECT_GT(result->receipt.sequence, previous);
    previous = result->receipt.sequence;
    ASSERT_ERROR(blockingWait(dispatcher_->read(*handle, user_, 0, 0, control())), StorageClientCode::kResourceBusy);
    result->data.reset();
    auto retired = blockingWait(
        dispatcher_->retire(result->receipt, user_, path("summary-" + std::to_string(iteration)), control()));
    ASSERT_OK(retired);
    auto snapshot = blockingWait(dispatcher_->inspect());
    ASSERT_OK(snapshot);
    EXPECT_EQ(snapshot->retainedRuns, 0);
    EXPECT_EQ(snapshot->outstandingRuns, 0);
    EXPECT_LT(snapshot->logicalFileBytes, 4096);
  }
  EXPECT_EQ(calls_->acquire.load(), 12);
  auto a = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
  ASSERT_OK(a);
  a->data.reset();
  auto b = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
  ASSERT_OK(b);
  b->data.reset();
  const auto beforeRejected = calls_->acquire.load();
  ASSERT_ERROR(blockingWait(dispatcher_->read(*handle, user_, 0, 0, control())), StorageClientCode::kResourceBusy);
  EXPECT_EQ(calls_->acquire.load(), beforeRejected);
  ASSERT_OK(blockingWait(dispatcher_->retire(a->receipt, user_, path("quota-a"), control())));
  auto c = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
  ASSERT_OK(c);
  c->data.reset();
  EXPECT_GT(c->receipt.sequence, b->receipt.sequence);
  ASSERT_OK(blockingWait(dispatcher_->retire(b->receipt, user_, path("quota-b"), control())));
  ASSERT_OK(blockingWait(dispatcher_->retire(c->receipt, user_, path("quota-c"), control())));
}
TEST_F(TestEcReadDispatcher, DroppedWaiterStillOwnsWorkAndStopClosesAdmissionBeforeJoin) {
  calls_->describeEntered = std::make_shared<folly::coro::Baton>();
  calls_->describeContinue = std::make_shared<folly::coro::Baton>();
  { auto dropped = dispatcher_->openRead(calls_->file.object, user_, control()); }
  blockingWait([&]() -> CoTask<void> { co_await *calls_->describeEntered; }());
  ASSERT_ERROR(open(), StorageClientCode::kResourceBusy);
  { auto unawaitedStop = dispatcher_->stop(); }
  auto stopping = dispatcher_->stop();
  ASSERT_ERROR(open(), StorageClientCode::kResourceBusy);
  calls_->describeContinue->post();
  auto stopped = blockingWait(std::move(stopping));
  EXPECT_TRUE(stopped.localJoined);
  EXPECT_TRUE(stopped.inventoryVerified);
  EXPECT_EQ(calls_->describe.load(), 1);
}
TEST_F(TestEcReadDispatcher, DurableRetirementMarkerResumesPartialLocalDeletionWithoutAnotherAcquire) {
  auto handle = open();
  ASSERT_OK(handle);
  auto result = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
  ASSERT_OK(result);
  ASSERT_TRUE(result->cleanup.allReleased);
  result->data.reset();
  const auto receipt = result->receipt;
  ASSERT_TRUE(blockingWait(dispatcher_->stop()).inventoryVerified);
  dispatcher_.reset();
  const auto runPath = spool_->directory() / detail::spoolRunName(receipt.sequence);
  auto reopened = EcFileRunJournal::resume(runPath);
  ASSERT_OK(reopened);
  ASSERT_TRUE((*reopened)->latest());
  detail::EcReadArchive archive{receipt, (*reopened)->record(), *(*reopened)->latest()};
  auto encoded = detail::encodeReadArchive(archive);
  ASSERT_OK(encoded);
  auto digest = detail::readArchiveDigest(*encoded);
  ASSERT_OK(digest);
  const auto target = path("interrupted-summary.json");
  const auto save = [](const std::filesystem::path &p, const std::string &text) {
    return saveEcFileReadOutput(p, {reinterpret_cast<const uint8_t *>(text.data()), text.size()});
  };
  ASSERT_OK(save(target, *encoded));
  auto marker = detail::encodeReadRetirementMarker({receipt, target, *digest});
  ASSERT_OK(marker);
  ASSERT_OK(save(spool_->directory() / detail::readRetirementMarkerName(receipt.sequence), *marker));
  reopened = makeError(StatusCode::kInterrupted);
  const auto retiring = spool_->directory() / detail::spoolRunName(receipt.sequence, true);
  // Fault-state construction, not a process-kill claim: marker/export durable,
  // directory renamed and its record removed, as after interrupted unlink.
  std::filesystem::rename(runPath, retiring);
  ASSERT_TRUE(std::filesystem::remove(retiring / "record.json"));
  spool_.reset();
  auto restored = EcReadSpool::open(path("spool"), "dispatch-test", {});
  ASSERT_OK(restored);
  spool_ = std::move(*restored);
  ASSERT_NO_FATAL_FAILURE(connect());
  auto observed = blockingWait(dispatcher_->inspectReceipt(receipt));
  ASSERT_OK(observed);
  ASSERT_EQ(observed->evidence, EcReadLocalEvidence::RetirementPending);
  const auto acquired = calls_->acquire.load(), queried = calls_->query.load();
  ASSERT_ERROR(blockingWait(dispatcher_->resumeRead(receipt, user_, control())), StatusCode::kKVStoreNotFound);
  ASSERT_ERROR(blockingWait(dispatcher_->retire(receipt, user_, path("wrong-summary"), control())),
               StatusCode::kTokenMismatch);
  // Explicit prior-failure state injection, not a simulated filesystem failure:
  // this otherwise recoverable marker cannot clear another attempt's poison.
  detail::EcReadSpoolTestAccess::markPriorPersistenceUncertain(*spool_);
  ASSERT_ERROR(blockingWait(dispatcher_->retire(receipt, user_, target, control())), StatusCode::kIOError);
  ASSERT_TRUE(spool_->poisoned());
  ASSERT_TRUE(std::filesystem::exists(retiring));
  ASSERT_TRUE(std::filesystem::exists(spool_->directory() / detail::readRetirementMarkerName(receipt.sequence)));
  ASSERT_TRUE(blockingWait(dispatcher_->stop()).localJoined);
  dispatcher_.reset();
  spool_.reset();
  restored = EcReadSpool::open(path("spool"), "dispatch-test", {});
  ASSERT_OK(restored);
  spool_ = std::move(*restored);
  ASSERT_FALSE(spool_->poisoned());
  ASSERT_NO_FATAL_FAILURE(connect());
  auto done = blockingWait(dispatcher_->retire(receipt, user_, target, control()));
  ASSERT_OK(done);
  EXPECT_EQ(calls_->acquire.load(), acquired);
  EXPECT_EQ(calls_->query.load(), queried);
  EXPECT_FALSE(std::filesystem::exists(retiring));
  EXPECT_TRUE(std::filesystem::exists(target));
  observed = blockingWait(dispatcher_->inspectReceipt(receipt));
  ASSERT_OK(observed);
  EXPECT_EQ(observed->evidence, EcReadLocalEvidence::NotRetained);
}
TEST_F(TestEcReadDispatcher, ClosingAndIncompleteTerminalAckNeverAuthorizeRetirement) {
  calls_->file.length = 80;
  calls_->closingRelease = true;
  auto handle = open();
  ASSERT_OK(handle);
  auto read = blockingWait(dispatcher_->read(*handle, user_, 0, 1, control()));
  ASSERT_OK(read);
  ASSERT_TRUE(read->readFailure);
  ASSERT_FALSE(read->data);
  ASSERT_FALSE(read->cleanup.allReleased);
  ASSERT_FALSE(blockingWait(dispatcher_->retire(read->receipt, user_, path("not-terminal"), control())));
  EXPECT_FALSE(std::filesystem::exists(path("not-terminal")));
  calls_->closingRelease = false;
  auto cleanup = blockingWait(dispatcher_->retryCleanup(read->receipt, user_, control()));
  ASSERT_TRUE(cleanup.allReleased);
  calls_->incompleteAck = true;
  ASSERT_ERROR(blockingWait(dispatcher_->retire(read->receipt, user_, path("bad-ack"), control())),
               StatusCode::kDataCorruption);
  EXPECT_FALSE(std::filesystem::exists(path("bad-ack")));
  calls_->incompleteAck = false;
  auto retired = blockingWait(dispatcher_->retire(read->receipt, user_, path("terminal"), control()));
  ASSERT_OK(retired);
  EXPECT_TRUE(retired->localFilesRemoved);
  EXPECT_EQ(calls_->acquire.load(), 1);
}
TEST_F(TestEcReadDispatcher, CloseFactoryAndDeliveryExceptionsSettleWaitersAndKeepUnconfirmedResources) {
  EcReadReceipt lastReceipt;
  std::weak_ptr<detail::EcReadDispatcherCore> previousCore;
  for (unsigned variant = 0; variant != 2; ++variant) {
    SCOPED_TRACE(variant);
    if (variant != 0) {
      // dismiss() keeps the guard's captures until the previous iteration ends.
      ASSERT_TRUE(previousCore.expired());
      ASSERT_NO_FATAL_FAILURE(connect());
    }
    auto handle = open();
    ASSERT_OK(handle);
    auto seed = blockingWait(dispatcher_->read(*handle, user_, 0, 0, control()));
    ASSERT_OK(seed);
    ASSERT_TRUE(seed->data);
    seed->data.reset();
    lastReceipt = seed->receipt;
    auto core = detail::EcReadDispatcherTestAccess::core(dispatcher_);
    previousCore = core;
    unsigned closeCalls = 0;
    const unsigned failedFactories = variant == 0 ? 2 : 1;
    core->closeFactoryForTesting = [&](std::shared_ptr<EcFileClient> file) -> CoTask<void> {
      if (++closeCalls <= failedFactories) throw std::bad_alloc();
      return file->close();
    };
    auto restoreHooks = folly::makeGuard([core, ownedDispatcher = dispatcher_] {
      core->beforeBusinessForTesting = {};
      core->beforeDeliveryForTesting = {};
      core->closeFactoryForTesting = {};
      blockingWait(ownedDispatcher->stop());
    });
    if (variant == 0)
      core->beforeBusinessForTesting = [] { throw std::bad_alloc(); };
    else
      core->beforeDeliveryForTesting = [] { throw std::bad_alloc(); };
    auto settled = blockingWait(dispatcher_->inspect());
    ASSERT_FALSE(settled);
    core->beforeBusinessForTesting = {};
    core->beforeDeliveryForTesting = {};
    ASSERT_TRUE(core->file);
    ASSERT_TRUE(core->retainedAfterJoinFailure);
    ASSERT_ERROR(open(), StorageClientCode::kResourceBusy);
    auto failedStop = blockingWait(dispatcher_->stop());
    ASSERT_FALSE(failedStop.localJoined);
    ASSERT_TRUE(failedStop.dispatcherTasksJoined);
    ASSERT_FALSE(failedStop.lowerJoinConfirmed);
    ASSERT_TRUE(failedStop.joinFailure);
    ASSERT_FALSE(failedStop.inventoryVerified);
    ASSERT_TRUE(core->file);
    ASSERT_ERROR(EcReadSpool::open(path("spool"), "dispatch-test", {}), StorageClientCode::kResourceBusy);
    auto retry = blockingWait(dispatcher_->stop());
    ASSERT_TRUE(retry.localJoined);
    ASSERT_TRUE(retry.lowerJoinConfirmed);
    ASSERT_FALSE(retry.joinFailure);
    ASSERT_TRUE(retry.inventoryVerified);
    ASSERT_EQ(retry.retainedOutputLeases, 0u);
    ASSERT_FALSE(core->file);
    ASSERT_FALSE(core->retainedAfterJoinFailure);
    EXPECT_EQ(closeCalls, failedFactories + 1);
    core->closeFactoryForTesting = {};
    restoreHooks.dismiss();
    dispatcher_.reset();
    core.reset();
  }
  ASSERT_TRUE(previousCore.expired());
  ASSERT_NO_FATAL_FAILURE(connect());
  auto existing = blockingWait(dispatcher_->retryCleanup(lastReceipt, user_, control()));
  ASSERT_TRUE(existing.localJoined);
  ASSERT_TRUE(existing.allReleased);
  auto dispatcherCore = detail::EcReadDispatcherTestAccess::core(dispatcher_);
  auto fileCore = detail::EcFileCompletionTestAccess::core(*dispatcherCore->file);
  struct Probe {
    unsigned calls = 0;
    static CoTask<void> factory(void *context, EcStripeClient &stripe) {
      if (++static_cast<Probe *>(context)->calls == 1) throw std::bad_alloc();
      return stripe.close();
    }
  } probe;
  fileCore->stripeCloseFactoryForTest = &Probe::factory;
  fileCore->stripeCloseFactoryContextForTest = &probe;
  SCOPE_EXIT {
    fileCore->stripeCloseFactoryForTest = nullptr;
    blockingWait(dispatcher_->stop());
  };
  auto exceptional = []() -> CoTryTask<Void> {
    throw std::bad_alloc();
    co_return Void{};
  };
  auto lowerFailure =
      blockingWait(fileCore->launch<Result<Void>>([&] { return exceptional(); },
                                                  [](Status e) -> Result<Void> { return makeError(std::move(e)); }));
  ASSERT_FALSE(lowerFailure);
  ASSERT_TRUE(dispatcherCore->file->localJoinUnconfirmed());
  // The lower call returned Result<error>, not a C++ exception. The adapter
  // must still propagate the separate unconfirmed-join state.
  auto propagated = blockingWait(dispatcher_->retryCleanup(lastReceipt, user_, control()));
  ASSERT_FALSE(propagated.localJoined);
  ASSERT_FALSE(propagated.allReleased);
  ASSERT_TRUE(propagated.failure);
  ASSERT_TRUE(dispatcherCore->retainedAfterJoinFailure);
  auto stopped = blockingWait(dispatcher_->stop());
  ASSERT_TRUE(stopped.localJoined);
  ASSERT_EQ(probe.calls, 2);
}
}  // namespace
}  // namespace hf3fs::client::ec
