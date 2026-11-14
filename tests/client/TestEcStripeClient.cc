#include <atomic>
#include <barrier>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Collect.h>
#include <gtest/gtest.h>
#include <thread>

#include "client/ec/detail/EcStripeClientCore.h"
#include "client/storage/StorageClientInMem.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec::test {
namespace {
using folly::coro::blockingWait;
using Core = detail::EcStripeClientCore;

std::shared_ptr<Core> manager(folly::CPUThreadPoolExecutor &pool, size_t bytes, size_t operations = 4) {
  EcStripeClient::Limits limits;
  limits.maxOperations = operations;
  limits.maxApplicationBytes = bytes;
  // This suite tests the actual ownership/admission core, without claiming
  // authentication or network integration. The separate native fixture uses
  // real Meta/Storage TCP and private FDB for those boundaries.
  return std::make_shared<Core>(nullptr, nullptr, nullptr, flat::UserInfo{}, Uuid::random(), pool, limits);
}
CoTask<int> gated(folly::coro::Baton &entered, folly::coro::Baton &release, std::shared_ptr<int> owned) {
  entered.post();
  co_await release;
  co_return *owned;
}

TEST(TestEcStripeClient, AdmissionIsSynchronousAndAbandonedWaiterDoesNotReleaseInput) {
  folly::CPUThreadPoolExecutor pool(2);
  auto core = manager(pool, 100, 1);
  folly::coro::Baton entered, release;
  SCOPE_EXIT {
    release.post();
    blockingWait(Core::close(core));
  };
  auto payload = std::make_shared<int>(17);
  std::weak_ptr<int> weak = payload;
  auto call = core->launch<int>(
      100,
      [&, payload = std::move(payload)](const auto &) { return gated(entered, release, payload); },
      [](Status) { return -1; });
  ASSERT_OK(call);
  blockingWait([&]() -> CoTask<void> { co_await entered; }());
  {
    auto abandoned = Core::take(*call);
    // The lazy waiter is deliberately never awaited.
  }
  EXPECT_FALSE(weak.expired());
  EXPECT_EQ(core->budget->bytes.load(), 100);
  auto rejected = core->launch<int>(
      1,
      [](const auto &) { return Core::immediate(1); },
      [](Status) { return -1; });
  ASSERT_ERROR(rejected, StorageClientCode::kResourceBusy);
  release.post();
  blockingWait(Core::close(core));
  EXPECT_TRUE(weak.expired());
  EXPECT_EQ(core->budget->bytes.load(), 0);
  EXPECT_EQ(core->activeOperations, 0);
}

struct Output {
  std::shared_ptr<const detail::EcReadReservation> lease;
  std::string data;
};
CoTask<Output> splitOutput(std::shared_ptr<detail::EcReadReservation> lease) {
  Output result;
  result.data.assign(40, 'x');
  result.lease = lease->split(40);
  co_return result;
}
TEST(TestEcStripeClient, ReturnedOutputKeepsChargeAcrossCloseAndAffectsNewAdmissions) {
  folly::CPUThreadPoolExecutor pool(2);
  auto core = manager(pool, 100);
  SCOPE_EXIT { blockingWait(Core::close(core)); };
  auto call = core->launch<Output>(
      100,
      [](auto lease) { return splitOutput(std::move(lease)); },
      [](Status) { return Output{}; });
  ASSERT_OK(call);
  auto output = blockingWait(Core::take(*call));
  EXPECT_EQ(output.data.size(), 40);
  EXPECT_EQ(core->budget->bytes.load(), 40);
  auto tooLarge = core->launch<int>(
      61,
      [](const auto &) { return Core::immediate(1); },
      [](Status) { return -1; });
  ASSERT_ERROR(tooLarge, StorageClientCode::kResourceBusy);
  auto fits = core->launch<int>(
      60,
      [](const auto &) { return Core::immediate(9); },
      [](Status) { return -1; });
  ASSERT_OK(fits);
  EXPECT_EQ(blockingWait(Core::take(*fits)), 9);
  blockingWait(Core::close(core));
  EXPECT_EQ(core->budget->bytes.load(), 40);
  output.data.clear();
  output.data.shrink_to_fit();
  output.lease.reset();
  EXPECT_EQ(core->budget->bytes.load(), 0);
}

TEST(TestEcStripeClient, ConcurrentStartsCannotSpendTheSameByteBudget) {
  folly::CPUThreadPoolExecutor pool(2);
  auto core = manager(pool, 100);
  folly::coro::Baton entered, release;
  std::barrier rendezvous(3);
  std::atomic<size_t> admitted{0}, denied{0};
  auto contender = [&] {
    rendezvous.arrive_and_wait();
    auto result = core->launch<int>(
        100,
        [&](const auto &) { return gated(entered, release, std::make_shared<int>(1)); },
        [](Status) { return -1; });
    if (result)
      ++admitted;
    else if (result.error().code() == StorageClientCode::kResourceBusy)
      ++denied;
  };
  std::thread a(contender), b(contender);
  rendezvous.arrive_and_wait();
  a.join();
  b.join();
  EXPECT_EQ(admitted.load(), 1);
  EXPECT_EQ(denied.load(), 1);
  EXPECT_EQ(core->budget->bytes.load(), 100);
  release.post();
  blockingWait(Core::close(core));
  EXPECT_EQ(core->budget->bytes.load(), 0);
}

TEST(TestEcStripeClient, FixedRequestIdsAndManagerDeadlineAreMandatory) {
  folly::CPUThreadPoolExecutor pool(1);
  auto core = manager(pool, 100);
  EXPECT_FALSE(core->validIds({}));
  EXPECT_FALSE(core->validPin({}));
  EXPECT_FALSE(core->validControl({std::chrono::steady_clock::time_point::max(), {}}));
  EXPECT_FALSE(core->validControl({std::chrono::steady_clock::now(), {}}));
  EXPECT_TRUE(core->validControl({std::chrono::steady_clock::now() + std::chrono::seconds(1), {}}));
  blockingWait(Core::close(core));
  auto rejected = core->launch<int>(
      0,
      [](const auto &) { return Core::immediate(0); },
      [](Status) { return -1; });
  ASSERT_ERROR(rejected, StorageClientCode::kResourceBusy);
}

TEST(TestEcStripeClient, InvalidRepairDeliveryIsRejectedBeforeAnyMetadataCall) {
  folly::CPUThreadPoolExecutor pool(1);
  auto core = manager(pool, 1u << 20);
  EcStripeRepair input;
  EXPECT_EQ(input.delivery, EcRepairDelivery::ClientAppend);
  input.object.object = {meta::InodeId(123), Uuid::random()};
  input.object.epoch = 1;
  input.object.shardBytes = 4096;
  input.expectedRevision = 1;
  input.ids = {Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random()};
  input.baseRead = {input.object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
  input.planId = Uuid::random();
  input.sources = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  input.replacementMask = (1u << 10) | (1u << 11);
  const EcStripeControl control{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}};
  ASSERT_TRUE(core->validIds(input.ids));
  ASSERT_TRUE(core->validPin(input.baseRead));
  ASSERT_TRUE(core->validControl(control));
  for (const auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline,
                          static_cast<EcRepairMode>(255)}) {
    input.mode = mode;
    input.delivery = EcRepairDelivery::HelperDirect;
    const auto result = blockingWait(core->repairOwned(input, control));
    ASSERT_TRUE(result.failure);
    EXPECT_EQ(result.failure->code(), StatusCode::kInvalidArg);
    EXPECT_EQ(result.phase, EcStripePhase::Validate);
    EXPECT_FALSE(result.observation);
  }
  input.mode = EcRepairMode::HelperChain;
  input.delivery = static_cast<EcRepairDelivery>(255);
  const auto result = blockingWait(core->repairOwned(input, control));
  ASSERT_TRUE(result.failure);
  EXPECT_EQ(result.failure->code(), StatusCode::kInvalidArg);
  EXPECT_EQ(result.phase, EcStripePhase::Validate);
  // core intentionally has null Meta/Storage clients: reaching an RPC is a test failure.
  blockingWait(Core::close(core));
}

TEST(TestEcStripeClient, CancelledCloseWaiterStillJoinsItsStartedWork) {
  folly::CPUThreadPoolExecutor pool(2);
  auto core = manager(pool, 100);
  folly::coro::Baton entered, release;
  auto call = core->launch<int>(
      100,
      [&](const auto &) { return gated(entered, release, std::make_shared<int>(3)); },
      [](Status) { return -1; });
  ASSERT_OK(call);
  CancellationSource cancelled;
  cancelled.requestCancellation();
  std::thread unblock([&] {
    while (!core->stop.isCancellationRequested()) std::this_thread::yield();
    release.post();
  });
  blockingWait(folly::coro::co_withCancellation(cancelled.getToken(), Core::close(core)));
  unblock.join();
  EXPECT_TRUE(core->closed.ready());
  EXPECT_EQ(core->activeOperations, 0);
  EXPECT_EQ(core->budget->bytes.load(), 0);
}

TEST(TestEcStripeClient, JoinedFragmentErrorsPreserveFirstDurableUnknownAcrossIndices) {
  for (size_t unknownIndex : {size_t(0), size_t(10)}) {
    std::vector<Result<storage::EcStageStateV2>> results(12, storage::EcStageStateV2{});
    results[0] = makeError(StorageClientCode::kTimeout, "ordinary timeout");
    results[unknownIndex] = makeError(StorageCode::kEcSealOutcomeUnknown, "first unknown");
    results[11] = makeError(StorageCode::kEcSealOutcomeUnknown, "second unknown");
    const auto expected = results[unknownIndex].error();
    EcStripeMutationOutcome out;
    out.operation = Uuid::random();
    const auto operation = out.operation;
    auto failure = Core::collectStageResults(out, results);
    ASSERT_TRUE(failure);
    EXPECT_EQ(failure->code(), StorageCode::kEcSealOutcomeUnknown);
    EXPECT_EQ(failure->describe(), expected.describe());
    EXPECT_TRUE(out.stages[1]);
    EXPECT_FALSE(out.stages[11]);
    EXPECT_EQ(out.operation, operation);
  }
}

CoTryTask<storage::EcStageStateV2> lateUnknown(folly::coro::Baton &entered, folly::coro::Baton &release) {
  entered.post();
  co_await release;
  co_return makeError(StorageCode::kEcSealOutcomeUnknown, "late dispatched mutation has unknown outcome");
}

TEST(TestEcStripeClient, WindowedWritesJoinLateUnknownInsteadOfReturningEarlierTimeout) {
  folly::coro::Baton entered, release;
  std::atomic<bool> completed{false};
  std::optional<Status> failure;
  EcStripeMutationOutcome out;
  std::thread runner([&] {
    blockingWait([&]() -> CoTask<void> {
      std::vector<CoTryTask<storage::EcStageStateV2>> jobs;
      for (size_t i = 0; i != 11; ++i) {
        jobs.push_back(Core::immediate<Result<storage::EcStageStateV2>>(
            makeError(StorageClientCode::kTimeout, "earlier ordinary failure")));
      }
      jobs.push_back(lateUnknown(entered, release));
      auto results = co_await folly::coro::collectAllWindowed(std::move(jobs), 2);
      failure = Core::collectStageResults(out, results);
      completed.store(true);
    }());
  });
  blockingWait([&]() -> CoTask<void> { co_await entered; }());
  EXPECT_FALSE(completed.load());
  release.post();
  runner.join();
  ASSERT_TRUE(failure);
  EXPECT_EQ(failure->code(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_TRUE(completed.load());
}

// Only the StorageClient boundary is scripted. These tests execute the actual
// writeFragment -> writeFragmentImpl recovery loop, routing checks, descriptor
// checks and reply validation. They do not claim TCP or durable Engine faults.
class ScriptedStageClient : public storage::client::StorageClientInMem {
 public:
  using StorageClientInMem::StorageClientInMem;
  using State = storage::EcStageStateV2;
  using Access = storage::EcFragmentAccessV2;
  std::function<Result<State>(const Access &)> onBegin, onQuery, onReconcile;
  std::function<Result<State>(const storage::EcAppendStageV2Req &)> onAppend;
  std::function<Result<storage::EcFragmentReceiptV2>(const Access &)> onSeal;
  std::vector<std::string> calls;

  CoTryTask<State> beginEcStageV2Controlled(storage::EcBeginStageV2Req req,
                                            storage::client::EcRequestControl) override {
    calls.push_back("begin");
    co_return onBegin(req.request);
  }
  CoTryTask<State> queryEcStageV2Controlled(storage::EcQueryStageV2Req req,
                                            storage::client::EcRequestControl) override {
    calls.push_back("query");
    co_return onQuery(req.request);
  }
  CoTryTask<State> reconcileEcStageV2Controlled(storage::EcReconcileStageV2Req req,
                                                storage::client::EcRequestControl) override {
    calls.push_back("reconcile");
    co_return onReconcile(req.request);
  }
  CoTryTask<State> appendEcStageV2Controlled(storage::EcAppendStageV2Req req,
                                             storage::client::EcRequestControl) override {
    calls.push_back("append");
    co_return onAppend(req);
  }
  CoTryTask<storage::EcFragmentReceiptV2> sealEcStageV2Controlled(storage::EcSealStageV2Req req,
                                                                  storage::client::EcRequestControl) override {
    calls.push_back("seal");
    co_return onSeal(req.request);
  }
};

class TestEcStripeFragmentRecovery : public ::testing::Test {
 protected:
  void SetUp() override {
    mgmtd_ = std::make_shared<hf3fs::tests::FakeMgmtdClient>();
    auto routing = mgmtd_->cloneRoutingInfo();
    flat::NodeInfo node;
    node.app.nodeId = flat::NodeId(101);
    node.type = flat::NodeType::STORAGE;
    node.status = flat::NodeStatus::HEARTBEAT_CONNECTED;
    routing->raw()->nodes[node.app.nodeId] = node;
    flat::TargetInfo target;
    target.targetId = flat::TargetId(201);
    target.chainId = flat::ChainId(301);
    target.nodeId = node.app.nodeId;
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
    mgmtd_->setRoutingInfo(routing);

    storage_ = std::make_shared<ScriptedStageClient>(ClientId{Uuid::random()}, config_, *mgmtd_);
    flat::UserInfo user;
    user.uid = flat::Uid(123);
    const auto writer = Uuid::random();
    EcStripeClient::Limits limits;
    limits.recoveryAttempts = 2;
    core_ = std::make_shared<Core>(nullptr, storage_, mgmtd_, user, writer, pool_, limits);
    allocation_.object = {meta::InodeId(401), Uuid::random()};
    allocation_.fragment.identity.object = allocation_.object.incarnation;
    allocation_.fragment.identity.generation = 1;
    allocation_.fragment.identity.allocation = Uuid::random();
    allocation_.fragment.operation = Uuid::random();
    allocation_.fragment.placement = {target.chainId, target.targetId, node.app.nodeId};
    auto integrity = storage::computeEcIntegrity(allocation_.fragment.identity, bytes_);
    ASSERT_OK(integrity);
    allocation_.fragment.integrity = *integrity;
    allocation_.engineUuid = Uuid::random();
    allocation_.targetIncarnation = Uuid::random();
    allocation_.writer = {user.uid, writer};
    auto digest = storage::digestEcIntegrityV2(allocation_.fragment.identity, *integrity);
    ASSERT_OK(digest);
    auto &claims = grant_.claims;
    claims.identity = allocation_.fragment.identity;
    claims.fragmentOperationId = allocation_.fragment.operation;
    claims.engineUuid = allocation_.engineUuid;
    claims.targetIncarnation = allocation_.targetIncarnation;
    claims.chainId = target.chainId;
    claims.targetId = target.targetId;
    claims.nodeId = node.app.nodeId;
    claims.expectedLength = static_cast<uint32_t>(bytes_.size());
    claims.expectedCrc32c = integrity->wholeCrc32c;
    claims.integrityDigest = *digest;
    claims.scopeKind = storage::EcGrantScope::WriteOperation;
    claims.scopeObject = allocation_.object.incarnation;
    claims.scopeId = allocation_.fragment.operation;
    claims.ownerUid = user.uid;
    claims.clientNamespace = writer;
    claims.rights = storage::kEcGrantAllRightsV2;
    // The substitute supplies transport results; it does not authenticate this
    // unsigned test capability. Real MAC/UID tests live in the native fixtures.
    storage_->onBegin = [&](const auto &req) -> Result<ScriptedStageClient::State> { return state(req); };
    storage_->onQuery = storage_->onBegin;
    storage_->onReconcile = storage_->onBegin;
    storage_->onAppend = [&](const auto &req) -> Result<ScriptedStageClient::State> {
      EXPECT_EQ(req.blockIndex, 0);
      EXPECT_EQ(req.payload.data, bytes_);
      return state(req.request, static_cast<uint32_t>(bytes_.size()));
    };
    storage_->onSeal = [&](const auto &req) -> Result<storage::EcFragmentReceiptV2> { return state(req).receipt; };
  }
  void TearDown() override {
    if (core_) blockingWait(Core::close(core_));
  }
  storage::EcStageStateV2 state(const storage::EcFragmentAccessV2 &req,
                                uint32_t prefix = 0,
                                bool pending = false,
                                bool unknown = false,
                                uint8_t phase = 1) const {
    storage::EcStageStateV2 result;
    auto &receipt = result.receipt;
    receipt.identity = req.identity;
    receipt.operationId = req.operationId;
    receipt.engineUuid = allocation_.engineUuid;
    receipt.targetIncarnation = allocation_.targetIncarnation;
    receipt.vChainId = req.vChainId;
    receipt.targetId = req.targetId;
    receipt.length = req.integrity.wholeLength;
    receipt.crc32c = req.integrity.wholeCrc32c;
    receipt.integrityRoot = req.integrity.root;
    result.state = phase;
    result.prefixBytes = prefix;
    result.pendingBlock = pending;
    result.needsReconcile = unknown;
    result.revision = 1;
    return result;
  }
  Result<storage::EcStageStateV2> run() {
    return blockingWait(
        core_->writeFragment(allocation_,
                             grant_,
                             bytes_,
                             {std::chrono::steady_clock::now() + std::chrono::seconds(5), cancelled_.getToken()}));
  }
  folly::CPUThreadPoolExecutor pool_{1};
  storage::client::StorageClient::Config config_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<ScriptedStageClient> storage_;
  std::shared_ptr<Core> core_;
  meta::EcV2AllocationBinding allocation_;
  storage::EcCapabilityV2 grant_;
  std::string bytes_ = "fixed repairable tail";
  CancellationSource cancelled_;
};

TEST_F(TestEcStripeFragmentRecovery, BeginUnknownSurvivesQueryTimeoutAndRetryExhaustion) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Begin");
  };
  storage_->onQuery = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageClientCode::kTimeout);
  };
  storage_->onReconcile = storage_->onQuery;
  ASSERT_ERROR(run(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query", "reconcile", "begin", "query", "reconcile"}));
}

TEST_F(TestEcStripeFragmentRecovery, MissingQueryStillReconcilesTheSameHeldReservation) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "reservation log was not confirmed");
  };
  storage_->onQuery = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageClientCode::kChunkNotFound);
  };
  storage_->onReconcile = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    EXPECT_TRUE(serde::equals(req.identity, allocation_.fragment.identity));
    EXPECT_EQ(req.operationId, allocation_.fragment.operation);
    EXPECT_EQ(req.targetId, allocation_.fragment.placement.target);
    return state(req);
  };
  auto result = run();
  ASSERT_OK(result);
  EXPECT_EQ(result->state, 2);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query", "reconcile", "append", "seal"}));
}

TEST_F(TestEcStripeFragmentRecovery, AppendUnknownSurvivesCancellationBeforeNextAttempt) {
  storage_->onAppend = [&](const auto &) -> Result<ScriptedStageClient::State> {
    cancelled_.requestCancellation();
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Append");
  };
  ASSERT_ERROR(run(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "append"}));
}

TEST_F(TestEcStripeFragmentRecovery, SealUnknownSurvivesCancellationBeforeNextAttempt) {
  storage_->onSeal = [&](const auto &) -> Result<storage::EcFragmentReceiptV2> {
    cancelled_.requestCancellation();
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Seal");
  };
  ASSERT_ERROR(run(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "append", "seal"}));
}

TEST_F(TestEcStripeFragmentRecovery, NewBeginAndQuerySealedDoNotErasePreviousUnknown) {
  size_t begins = 0;
  storage_->onBegin = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    if (++begins == 1) return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Begin");
    return state(req, static_cast<uint32_t>(bytes_.size()), false, false, 2);
  };
  storage_->onQuery = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    return state(req, static_cast<uint32_t>(bytes_.size()), false, false, 2);
  };
  storage_->onReconcile = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageClientCode::kTimeout);
  };
  ASSERT_ERROR(run(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query", "reconcile", "begin", "query", "reconcile"}));
}

TEST_F(TestEcStripeFragmentRecovery, ConfirmedPendingIntentResendsBoundBytesThenSeals) {
  storage_->onBegin = [&](const auto &req) -> Result<ScriptedStageClient::State> { return state(req, 0, true, true); };
  storage_->onQuery = storage_->onBegin;
  storage_->onReconcile = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    return state(req, 0, true, false);
  };
  auto result = run();
  ASSERT_OK(result);
  EXPECT_EQ(result->state, 2);
  EXPECT_EQ(result->prefixBytes, bytes_.size());
  EXPECT_FALSE(result->needsReconcile);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query", "reconcile", "append", "seal"}));
}

TEST_F(TestEcStripeFragmentRecovery, ValidatedReconcileClearsPriorUnknownBeforeANewCancellation) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Begin");
  };
  storage_->onAppend = [&](const auto &) -> Result<ScriptedStageClient::State> {
    // The explicit Reconcile has already returned its confirmed prefix. This
    // new Append is rejected before dispatch after a later cancellation.
    cancelled_.requestCancellation();
    return makeError(StorageClientCode::kRequestCanceled);
  };
  ASSERT_ERROR(run(), StorageClientCode::kRequestCanceled);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query", "reconcile", "append"}));
}

TEST_F(TestEcStripeFragmentRecovery, UnknownSurvivesRoutingLossBeforeNextAttempt) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Begin");
  };
  storage_->onQuery = [&](const auto &) -> Result<ScriptedStageClient::State> {
    mgmtd_->clearNodes();
    return makeError(StorageClientCode::kTimeout);
  };
  ASSERT_ERROR(run(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query"}));
}

TEST_F(TestEcStripeFragmentRecovery, MutationBoundaryAllocationExceptionIsOutcomeUnknown) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> { throw std::bad_alloc(); };
  auto result = run();  // Calls the actual writeFragment wrapper, not Impl alone.
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_NE(result.error().message().find("std::bad_alloc"), std::string_view::npos);
  EXPECT_NE(result.error().message().find("NotEnoughMemory"), std::string_view::npos);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin"}));
}

TEST_F(TestEcStripeFragmentRecovery, UnknownMutationSurvivesObserverAllocationException) {
  storage_->onBegin = [](const auto &) -> Result<ScriptedStageClient::State> {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "unknown Begin before observer allocation failure");
  };
  storage_->onQuery = [](const auto &) -> Result<ScriptedStageClient::State> { throw std::bad_alloc(); };
  auto result = run();
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_NE(result.error().message().find("std::bad_alloc"), std::string_view::npos);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "query"}));
}

TEST_F(TestEcStripeFragmentRecovery, InvalidPositiveBeginReplyCannotProveNoMutation) {
  storage_->onBegin = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    auto result = state(req);
    result.receipt.engineUuid = Uuid::random();
    return result;
  };
  auto result = run();
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_NE(result.error().message().find(std::to_string(StorageClientCode::kProtocolMismatch)),
            std::string_view::npos);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin"}));
}

TEST_F(TestEcStripeFragmentRecovery, InvalidPositiveAppendReplyCannotProveNoMutation) {
  storage_->onAppend = [&](const auto &req) -> Result<ScriptedStageClient::State> {
    auto result = state(req.request, static_cast<uint32_t>(bytes_.size()));
    result.receipt.targetIncarnation = Uuid::random();
    return result;
  };
  auto result = run();
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_NE(result.error().message().find(std::to_string(StorageClientCode::kProtocolMismatch)),
            std::string_view::npos);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "append"}));
}

TEST_F(TestEcStripeFragmentRecovery, InvalidPositiveSealReplyCannotProveNoMutation) {
  storage_->onSeal = [&](const auto &req) -> Result<storage::EcFragmentReceiptV2> {
    auto result = state(req).receipt;
    result.operationId = Uuid::random();
    return result;
  };
  auto result = run();
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_NE(result.error().message().find(std::to_string(StorageClientCode::kProtocolMismatch)),
            std::string_view::npos);
  EXPECT_EQ(storage_->calls, (std::vector<std::string>{"begin", "append", "seal"}));
}
}  // namespace
}  // namespace hf3fs::client::ec::test
