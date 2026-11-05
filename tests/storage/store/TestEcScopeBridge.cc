#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/CancellationToken.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/WithCancellation.h>
#include <future>
#include <iterator>
#include <new>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include "storage/ec_scope/EcScope.h"
#include "storage/ec_scope/EcScopeLoadBudget.h"
#include "storage/store/StorageTargets.h"
#include "storage/update/EcAdmissionJob.h"
#include "storage/update/UpdateWorker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
class EcJobCompletionTestAccess {
 public:
  template <typename Job>
  static void failBeforeAwait(Job &job, void (*callback)()) {
    job.completion_.beforeAwait_ = callback;
  }
};
namespace {
thread_local std::promise<void> *waitFailureEntered = nullptr;
void throwWaitAllocation() {
  if (waitFailureEntered) waitFailureEntered->set_value();
  throw std::bad_alloc();
}

using namespace std::chrono_literals;
static_assert(!std::is_copy_constructible_v<EcScopeTicket>);
static_assert(std::is_nothrow_move_constructible_v<EcScopeTicket>);

struct WorkerBarrier {
  std::promise<void> entered;
  std::promise<void> resume;
  std::shared_future<void> released = resume.get_future().share();
  std::atomic<bool> called{false};
  std::atomic<bool> resumed{false};
  Result<Void> wait() {
    if (!called.exchange(true)) {
      entered.set_value();
      released.wait();
    }
    return Void{};
  }
  void release() {
    if (!resumed.exchange(true)) resume.set_value();
  }
  ~WorkerBarrier() { release(); }
};

class TestEcScopeBridge : public ::testing::Test {
 protected:
  void SetUp() override {
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    targets = std::make_unique<StorageTargets>(config, map);
    ASSERT_OK(targets->load(executor));
    CreateTargetReq target;
    target.chainId = ChainId{91};
    target.targetId = TargetId{92};
    target.onlyChunkEngine = true;
    ASSERT_OK(targets->create(target, true));
    auto found = map.getByTargetId(target.targetId);
    ASSERT_OK(found);
    store = (*found)->storageTarget;
    ASSERT_OK(store->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
    auto state = store->ecScopeState();
    ASSERT_OK(state);
    scope = state->first;
    identity = state->second;
    workerConfig.set_num_threads(1);
    workerConfig.set_bg_num_threads(1);
    workerConfig.set_queue_size(1);
    worker = std::make_unique<UpdateWorker>(workerConfig);
    ASSERT_OK(worker->start(1));

    create.identity.object = Uuid::from(101, 102);
    create.identity.allocation = Uuid::from(103, 104);
    create.identity.generation = 1;
    create.identity.stripe = 0;
    create.identity.shard = 0;
    create.vChainId = VersionedChainId{target.chainId, ChainVer{1}};
    create.targetId = target.targetId;
    create.operationId = Uuid::from(105, 106);
    create.payload.data = std::string(4096, 'K');
    create.payload.data[17] = '\0';
    create.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                           reinterpret_cast<const uint8_t *>(create.payload.data.data()),
                                           create.payload.data.size());
    read.identity = create.identity;
    read.vChainId = create.vChainId;
    read.targetId = create.targetId;
    read.operationId = create.operationId;
    read.expectedLength = create.payload.data.size();
    read.checksum = create.checksum;
  }
  void TearDown() override {
    if (worker) worker->stopAndJoin();
    worker.reset();
    scope.reset();
    store.reset();
    map.release().reset();
    targets.reset();
  }
  EcScopeBinding binding(uint8_t suffix = 1, uint8_t kind = 1) const {
    EcScopeBinding result{};
    result.target = identity;
    std::copy(std::begin(create.identity.object.data), std::end(create.identity.object.data), result.object.begin());
    result.kind = kind;
    result.scope.fill(suffix);
    result.owner_uid = 1000;
    result.client_namespace.fill(9);
    return result;
  }
  EcScopeRevocation revokeRequest(const EcScopeBinding &value) const {
    EcScopeRevocation result{};
    result.binding = value;
    result.id.fill(7);
    result.endpoint_set_digest.fill(8);
    return result;
  }
  Result<EcScopeTicket> admit(const EcScopeBinding &value) {
    RETURN_ON_ERROR(scope->prepare(value));
    return scope->tryAdmit(value);
  }
  void expectPending(const EcScopeRevocation &request, uint64_t count) {
    auto result = scope->revoke(request);
    ASSERT_OK(result);
    EXPECT_TRUE(result->durable);
    EXPECT_FALSE(result->drained);
    EXPECT_EQ(result->inflight, count);
  }
  void expectDrained(const EcScopeRevocation &request) {
    auto result = scope->drainStatus(request);
    ASSERT_OK(result);
    EXPECT_TRUE(result->durable);
    EXPECT_TRUE(result->drained);
    EXPECT_EQ(result->inflight, 0);
  }
  static Result<Void> valid() { return Void{}; }
  folly::test::TemporaryDirectory directory;
  CPUExecutorGroup executor{1, "EcScopeTest"};
  StorageTargets::Config config;
  AtomicallyTargetMap map;
  std::unique_ptr<StorageTargets> targets;
  std::shared_ptr<StorageTarget> store;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity identity{};
  UpdateWorker::Config workerConfig;
  std::unique_ptr<UpdateWorker> worker;
  EcCreateReq create;
  EcReadReq read;
};

TEST_F(TestEcScopeBridge, MoveAndDestroyCompleteExactlyOnceAcrossHandles) {
  auto second = EcScope::open(*targets->engines()[0]);
  ASSERT_OK(second);
  ASSERT_RESULT_EQ(identity, (*second)->loadTarget(identity.chain, identity.target));
  const auto value = binding();
  const auto request = revokeRequest(value);
  {
    auto admitted = admit(value);
    ASSERT_OK(admitted);
    EcScopeTicket moved = std::move(*admitted);
    ASSERT_ERROR(admitted->checkExecution(), StatusCode::kInvalidArg);
    ASSERT_OK(moved.checkExecution());
    auto denied = (*second)->revoke(request);
    ASSERT_OK(denied);
    EXPECT_EQ(denied->inflight, 1);
    ASSERT_ERROR(moved.checkExecution(), StatusCode::kTokenStale);
    ASSERT_ERROR(scope->tryAdmit(value), StatusCode::kTokenStale);
  }
  expectDrained(request);
}

TEST_F(TestEcScopeBridge, InvalidKindAndTargetNeverProduceTickets) {
  auto value = binding();
  value.kind = 3;
  ASSERT_ERROR(scope->prepare(value), StatusCode::kInvalidArg);
  ASSERT_ERROR(scope->tryAdmit(value), StatusCode::kInvalidArg);
  value = binding();
  value.target.engine[0] ^= 1;
  ASSERT_ERROR(scope->prepare(value), StatusCode::kTokenMismatch);
  ASSERT_ERROR(scope->tryAdmit(value), StatusCode::kTokenMismatch);
  value = binding();
  value.target.incarnation[0] ^= 1;
  ASSERT_ERROR(scope->prepare(value), StatusCode::kTokenMismatch);
}

TEST_F(TestEcScopeBridge, ColdAdmissionRunsOnRealWorker) {
  const auto value = binding();
  ASSERT_ERROR(scope->tryAdmit(value), StorageClientCode::kResourceBusy);
  auto session = worker->acquireEcSession();
  ASSERT_OK(session);
  EcAdmissionJob job(value, scope, *session, store, valid);
  ASSERT_ERROR(job.takeTicket(), StorageClientCode::kResourceBusy);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  {
    auto ticket = job.takeTicket();
    ASSERT_OK(ticket);
    ASSERT_OK(ticket->checkExecution());
    expectPending(revokeRequest(value), 1);
  }
  session->reset();
  expectDrained(revokeRequest(value));
}

TEST_F(TestEcScopeBridge, ScopeTicketCannotRunAnotherRequestObject) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  auto other = read;
  other.identity.object = Uuid::from(200, 201);
  EcReadJob job(std::move(*ticket), *session, other, store, valid);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_ERROR(job.takeResult(), StatusCode::kTokenMismatch);
  auto denied = scope->revoke(revokeRequest(binding()));
  ASSERT_OK(denied);
  EXPECT_TRUE(denied->drained);
}

TEST_F(TestEcScopeBridge, QueuedRevocationWaitsUntilOperatorPostcheck) {
  ASSERT_OK(store->createEcFragment(create));
  const auto value = binding();
  const auto request = revokeRequest(value);
  auto ticket = admit(value);
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  WorkerBarrier barrier;
  auto entered = barrier.entered.get_future();
  EcReadJob job(std::move(*ticket), *session, read, store, [&] { return barrier.wait(); });
  folly::coro::blockingWait(worker->enqueue(&job));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(job.complete());
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  expectPending(request, 1);
  ASSERT_ERROR(job.takeResult(), StorageClientCode::kResourceBusy);
  barrier.release();
  folly::coro::blockingWait(job.complete());
  expectPending(request, 1);
  ASSERT_ERROR(job.takeResult(), StatusCode::kTokenStale);
  expectDrained(request);
}

TEST_F(TestEcScopeBridge, OwnedReadSurvivesTicketRelease) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcReadJob job(std::move(*ticket), *session, read, store, valid);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  auto output = job.takeResult();
  ASSERT_OK(output);
  auto denied = scope->revoke(revokeRequest(binding()));
  ASSERT_OK(denied);
  EXPECT_TRUE(denied->drained);
  EXPECT_EQ(output->payload.data, create.payload.data);
  ASSERT_ERROR(job.takeResult(), StorageClientCode::kResourceBusy);
}

TEST_F(TestEcScopeBridge, CancelledWaitStillRetainsBorrowedJobAndTicket) {
  ASSERT_OK(store->createEcFragment(create));
  const auto request = revokeRequest(binding());
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  WorkerBarrier barrier;
  auto entered = barrier.entered.get_future();
  EcReadJob job(std::move(*ticket), *session, read, store, [&] { return barrier.wait(); });
  folly::coro::blockingWait(worker->enqueue(&job));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(job.complete());
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  folly::CancellationSource cancellation;
  std::atomic<bool> completed{false};
  std::thread waiter([&] {
    folly::coro::blockingWait(folly::coro::co_withCancellation(cancellation.getToken(), job.complete()));
    completed.store(true);
  });
  SCOPE_EXIT {
    barrier.release();
    waiter.join();
  };
  cancellation.requestCancellation();
  EXPECT_FALSE(completed.load());
  expectPending(request, 1);
  barrier.release();
  folly::coro::blockingWait(job.complete());
  ASSERT_ERROR(job.takeResult(), StatusCode::kTokenStale);
  expectDrained(request);
}

TEST_F(TestEcScopeBridge, ExpiryBeforeExecutionRejectsWithoutReleasingEarly) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  // Local validator models an elapsed deadline; this is not a v2 MAC test.
  EcReadJob job(std::move(*ticket), *session, read, store, []() -> Result<Void> {
    return makeError(StatusCode::kTokenStale, "test deadline elapsed");
  });
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  expectPending(revokeRequest(binding()), 1);
  ASSERT_ERROR(job.takeResult(), StatusCode::kTokenStale);
  expectDrained(revokeRequest(binding()));
}

TEST_F(TestEcScopeBridge, ExpiryAfterDurableCreateReturnsUnknownAndDrains) {
  auto ticket = admit(binding(1, 2));
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  std::atomic<bool> expired{false};
  auto validate = [&]() -> Result<Void> {
    if (expired.load()) return makeError(StatusCode::kTokenStale, "test deadline elapsed");
    return Void{};
  };
  EcCreateJob job(std::move(*ticket), *session, create, store, validate);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_OK(job.result());
  expired.store(true);
  expectPending(revokeRequest(binding(1, 2)), 1);
  ASSERT_ERROR(job.takeResult(), StorageCode::kEcSealOutcomeUnknown);
  expectDrained(revokeRequest(binding(1, 2)));
  ASSERT_OK(store->readEcFragment(read));
}

TEST_F(TestEcScopeBridge, PostcheckExceptionReleasesOnlyAfterActualCompletion) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  std::atomic<bool> throwNow{false};
  EcReadJob job(std::move(*ticket), *session, read, store, [&]() -> Result<Void> {
    if (throwNow.load()) throw std::bad_alloc();
    return Void{};
  });
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_OK(job.result());
  throwNow.store(true);
  expectPending(revokeRequest(binding()), 1);
  EXPECT_THROW(job.takeResult(), std::bad_alloc);
  expectDrained(revokeRequest(binding()));
}

TEST_F(TestEcScopeBridge, WorkerExceptionRetainsTicketUntilResultConsumed) {
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  std::atomic<unsigned> calls{0};
  EcReadJob job(std::move(*ticket), *session, read, store, [&]() -> Result<Void> {
    if (calls.fetch_add(1) == 0) throw std::runtime_error("test worker failure");
    return Void{};
  });
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  expectPending(revokeRequest(binding()), 1);
  ASSERT_ERROR(job.takeResult(), StorageCode::kChunkMetadataGetError);
  expectDrained(revokeRequest(binding()));
}

TEST_F(TestEcScopeBridge, StopWaitsForAdmittedSessionsBeforeSendingSentinel) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  std::promise<void> stopping;
  std::promise<void> stopped;
  auto stoppedFuture = stopped.get_future();
  std::thread stopper([&] {
    stopping.set_value();
    worker->stopAndJoin();
    stopped.set_value();
  });
  stopping.get_future().wait();
  // The pre-existing session is allowed to enqueue even after entry closes.
  EcReadJob job(std::move(*ticket), *session, read, store, valid);
  SCOPE_EXIT {
    folly::coro::blockingWait(job.complete());
    (void)job.takeResult();
    session->reset();
    stopper.join();
  };
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_OK(job.takeResult());
  EXPECT_EQ(stoppedFuture.wait_for(0ms), std::future_status::timeout);
  session->reset();
  ASSERT_EQ(stoppedFuture.wait_for(5s), std::future_status::ready);
  ASSERT_ERROR(worker->acquireEcSession(), StorageClientCode::kResourceBusy);
  auto denied = scope->revoke(revokeRequest(binding()));
  ASSERT_OK(denied);
  EXPECT_TRUE(denied->drained);
}

TEST_F(TestEcScopeBridge, SessionFromAnotherWorkerCannotEnterQueue) {
  auto ticket = admit(binding());
  ASSERT_OK(ticket);
  UpdateWorker other(workerConfig);
  ASSERT_OK(other.start(1));
  auto session = other.acquireEcSession();
  ASSERT_OK(session);
  EcReadJob job(std::move(*ticket), *session, read, store, valid);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_ERROR(job.takeResult(), StatusCode::kInvalidArg);
  session->reset();
  other.stopAndJoin();
}

TEST_F(TestEcScopeBridge, RevokedJobActuallyQueuedBehindAnotherDiskJob) {
  ASSERT_OK(store->createEcFragment(create));
  WorkerBarrier barrier;
  auto entered = barrier.entered.get_future();
  EcReadJob blocker(EcLegacyV1Admission{}, read, store, [&] { return barrier.wait(); });
  folly::coro::blockingWait(worker->enqueue(&blocker));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(blocker.complete());
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcReadJob queued(std::move(*ticket), *session, read, store, valid);
  folly::coro::blockingWait(worker->enqueue(&queued));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(queued.complete());
  };
  expectPending(revokeRequest(binding()), 1);
  barrier.release();
  folly::coro::blockingWait(queued.complete());
  expectPending(revokeRequest(binding()), 1);
  ASSERT_ERROR(queued.takeResult(), StatusCode::kTokenStale);
  expectDrained(revokeRequest(binding()));
}

TEST_F(TestEcScopeBridge, ReadPinCannotAuthorizeDurableQueueOperation) {
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcCreateJob job(std::move(*ticket), *session, create, store, valid);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_ERROR(job.takeResult(), StatusCode::kInvalidArg);
  ASSERT_FALSE(store->readEcFragment(read));
  auto denied = scope->revoke(revokeRequest(binding()));
  ASSERT_OK(denied);
  EXPECT_TRUE(denied->drained);
}

TEST_F(TestEcScopeBridge, FullQueueRejectsBeforeSubmissionAndPreservesExistingWork) {
  ASSERT_OK(store->createEcFragment(create));
  WorkerBarrier barrier;
  auto entered = barrier.entered.get_future();
  EcReadJob blocker(EcLegacyV1Admission{}, read, store, [&] { return barrier.wait(); });
  folly::coro::blockingWait(worker->enqueue(&blocker));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(blocker.complete());
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  EcReadJob queued(EcLegacyV1Admission{}, read, store, valid);
  folly::coro::blockingWait(worker->enqueue(&queued));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(queued.complete());
  };
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcReadJob third(std::move(*ticket), *session, read, store, valid);
  folly::CancellationSource cancellation;
  cancellation.requestCancellation();
  // No coroutine semaphore wait is registered: capacity one is already full.
  folly::coro::blockingWait(folly::coro::co_withCancellation(cancellation.getToken(), worker->enqueue(&third)));
  folly::coro::blockingWait(third.complete());
  EXPECT_FALSE(third.queued());
  EXPECT_TRUE(blocker.queued());
  EXPECT_TRUE(queued.queued());
  ASSERT_ERROR(third.takeResult(), StorageClientCode::kResourceBusy);
  auto denied = scope->revoke(revokeRequest(binding()));
  ASSERT_OK(denied);
  EXPECT_TRUE(denied->drained);  // Rejected job has relinquished its ticket.
  barrier.release();
  folly::coro::blockingWait(blocker.complete());
  folly::coro::blockingWait(queued.complete());
  ASSERT_OK(blocker.result());
  ASSERT_OK(queued.result());
}

TEST_F(TestEcScopeBridge, AdmissionAwaitFailureStillJoinsTheActualWorker) {
  WorkerBarrier barrier;
  auto entered = barrier.entered.get_future();
  auto session = worker->acquireEcSession();
  ASSERT_OK(session);
  const auto value = binding();
  auto job = std::make_unique<EcAdmissionJob>(value, scope, *session, store, [&] { return barrier.wait(); });
  EcJobCompletionTestAccess::failBeforeAwait(*job, throwWaitAllocation);
  folly::coro::blockingWait(worker->enqueue(job.get()));
  SCOPE_EXIT { barrier.release(); };
  ASSERT_TRUE(job->queued());
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  std::promise<void> injected;
  auto injectedFuture = injected.get_future();
  std::promise<void> returned;
  auto returnedFuture = returned.get_future();
  std::thread waiter([&] {
    waitFailureEntered = &injected;
    folly::coro::blockingWait(job->complete());
    waitFailureEntered = nullptr;
    returned.set_value();
  });
  SCOPE_EXIT {
    barrier.release();
    waiter.join();
  };
  ASSERT_EQ(injectedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(returnedFuture.wait_for(20ms), std::future_status::timeout);
  barrier.release();
  ASSERT_EQ(returnedFuture.wait_for(5s), std::future_status::ready);
  ASSERT_ERROR(job->takeTicket(), StatusCode::kNotEnoughMemory);
  expectPending(revokeRequest(value), 1);
  job.reset();
  expectDrained(revokeRequest(value));
}

TEST_F(TestEcScopeBridge, NestedSubmissionFromOwningWorkerRejectsBeforeQueueCommit) {
  ASSERT_OK(store->createEcFragment(create));
  std::atomic<bool> tested{false};
  std::atomic<uint16_t> nestedCode{0};
  std::atomic<bool> nestedQueued{true};
  EcReadJob outer(EcLegacyV1Admission{}, read, store, [&]() -> Result<Void> {
    if (!tested.exchange(true)) {
      EcReadJob nested(EcLegacyV1Admission{}, read, store, valid);
      folly::coro::blockingWait(worker->enqueue(&nested));
      folly::coro::blockingWait(nested.complete());
      nestedQueued.store(nested.queued());
      auto result = nested.takeResult();
      nestedCode.store(result ? 0 : result.error().code());
    }
    return Void{};
  });
  folly::coro::blockingWait(worker->enqueue(&outer));
  folly::coro::blockingWait(outer.complete());
  ASSERT_OK(outer.result());
  EXPECT_TRUE(tested.load());
  EXPECT_FALSE(nestedQueued.load());
  EXPECT_EQ(nestedCode.load(), StatusCode::kInvalidArg);
}

TEST_F(TestEcScopeBridge, DuplicateSubmissionToDifferentWorkerFailsBeforePostingAnotherResult) {
  ASSERT_OK(store->createEcFragment(create));
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcReadJob job(std::move(*ticket), *session, read, store, valid);
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  ASSERT_OK(job.takeResult());
  const auto priorStyle = ::testing::GTEST_FLAG(death_test_style);
  ::testing::GTEST_FLAG(death_test_style) = "threadsafe";
  SCOPE_EXIT { ::testing::GTEST_FLAG(death_test_style) = priorStyle; };
  ASSERT_DEATH({
    UpdateWorker other(workerConfig);
    folly::coro::blockingWait(other.enqueue(&job));
  }, "");
}
TEST(TestEcScopeLoadBudget, RejectsInvalidLimitAndExpiredGrant) {
  const auto start = EcScopeLoadBudget::Clock::time_point{};
  EcScopeLoadBudget budget{1001, start, std::nullopt};
  ASSERT_ERROR(budget.remaining(start, 1030, 1000), StatusCode::kInvalidConfig);
  budget.milliseconds = 250;
  ASSERT_ERROR(budget.remaining(start, 1000, 1000), StatusCode::kAuthenticationFail);
}

TEST(TestEcScopeLoadBudget, QueuedTimeConsumesOnlyExtraWaitBudget) {
  const auto start = EcScopeLoadBudget::Clock::time_point{};
  EcScopeLoadBudget budget{250, start, std::nullopt};
  ASSERT_RESULT_EQ(250u, budget.remaining(start, 1030, 1000));
  ASSERT_RESULT_EQ(150u, budget.remaining(start + 100ms, 1030, 1000));
  ASSERT_RESULT_EQ(0u, budget.remaining(start + 250ms, 1030, 1000));
  ASSERT_RESULT_EQ(0u, budget.remaining(start + 1s, 1030, 1000));
}

TEST(TestEcScopeLoadBudget, ZeroIsNonwaitingButDoesNotIgnoreActualDeadlineOrExpiry) {
  const auto start = EcScopeLoadBudget::Clock::time_point{};
  EcScopeLoadBudget budget{0, start, std::nullopt};
  ASSERT_RESULT_EQ(0u, budget.remaining(start + 1s, 1030, 1000));
  budget.requestDeadline = start + 2s;
  ASSERT_ERROR(budget.remaining(start + 2s, 1030, 1000), StorageClientCode::kTimeout);
  ASSERT_ERROR(budget.remaining(start, 1000, 1000), StatusCode::kAuthenticationFail);
}

TEST(TestEcScopeLoadBudget, KnownHelperDeadlineRemainsDistinctFromExtraWaitBudget) {
  const auto start = EcScopeLoadBudget::Clock::time_point{};
  EcScopeLoadBudget budget{250, start, start + 100ms};
  ASSERT_RESULT_EQ(60u, budget.remaining(start + 40ms, 1030, 1000));
  ASSERT_ERROR(budget.remaining(start + 100ms, 1030, 1000), StorageClientCode::kTimeout);
  budget.requestDeadline.reset();
  ASSERT_RESULT_EQ(0u, budget.remaining(start + 251ms, 1030, 1000));
}

TEST_F(TestEcScopeBridge, QueuedWaitBudgetDoesNotBecomeAnAdmissionDeadline) {
  auto session = worker->acquireEcSession();
  ASSERT_OK(session);
  const auto start = EcScopeLoadBudget::Clock::time_point{};
  EcScopeLoadBudget budget{250, start, std::nullopt};
  // A deterministic queue barrier consumes the local waiting allowance. Test
  // both an already loaded scope and the unchanged synchronous first loader.
  for (const bool warm : {true, false}) {
    const auto value = binding(warm ? 10 : 11);
    if (warm) {
      ASSERT_OK(scope->prepare(value));
    }
    WorkerBarrier barrier;
    std::atomic<int64_t> elapsedMillis{0};
    std::atomic<uint32_t> observedWait{1001};
    EcAdmissionJob blocker(binding(warm ? 8 : 9), scope, *session, store, [&] { return barrier.wait(); });
    EcAdmissionJob queued(value, scope, *session, store, valid, [&]() -> Result<uint32_t> {
      CHECK_RESULT(wait, budget.remaining(start + std::chrono::milliseconds(elapsedMillis.load()), 1030, 1000));
      observedWait.store(wait);
      return wait;
    });
    folly::coro::blockingWait(worker->enqueue(&blocker));
    barrier.entered.get_future().wait();
    folly::coro::blockingWait(worker->enqueue(&queued));
    elapsedMillis.store(251);
    barrier.release();
    folly::coro::blockingWait(blocker.complete());
    folly::coro::blockingWait(queued.complete());
    auto blockerTicket = blocker.takeTicket();
    auto queuedTicket = queued.takeTicket();
    ASSERT_OK(blockerTicket);
    ASSERT_EQ(observedWait.load(), 0u);
    ASSERT_OK(queuedTicket);
    ASSERT_OK(queuedTicket->checkExecution());
  }
}

}  // namespace
}  // namespace hf3fs::storage
