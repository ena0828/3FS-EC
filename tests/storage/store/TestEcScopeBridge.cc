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
#include "storage/store/StorageTargets.h"
#include "storage/update/EcAdmissionJob.h"
#include "storage/update/UpdateWorker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
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

TEST_F(TestEcScopeBridge, CancellationWhileQueueIsFullRetainsAdmissionUntilRealCompletion) {
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
  // One worker is blocked and the queue of capacity one is already full.
  auto ticket = admit(binding());
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcReadJob third(std::move(*ticket), *session, read, store, valid);
  folly::CancellationSource cancellation;
  std::promise<void> started;
  std::promise<void> enqueued;
  auto enqueuedFuture = enqueued.get_future();
  std::atomic<bool> enqueueFailed{false};
  std::thread caller([&] {
    started.set_value();
    try {
      folly::coro::blockingWait(folly::coro::co_withCancellation(cancellation.getToken(), worker->enqueue(&third)));
    } catch (...) {
      enqueueFailed.store(true);
    }
    enqueued.set_value();
  });
  SCOPE_EXIT {
    barrier.release();
    caller.join();
    if (!enqueueFailed.load()) folly::coro::blockingWait(third.complete());
  };
  started.get_future().wait();
  cancellation.requestCancellation();
  EXPECT_EQ(enqueuedFuture.wait_for(20ms), std::future_status::timeout);
  EXPECT_FALSE(enqueueFailed.load());
  expectPending(revokeRequest(binding()), 1);
  barrier.release();
  ASSERT_EQ(enqueuedFuture.wait_for(5s), std::future_status::ready);
  ASSERT_FALSE(enqueueFailed.load());
  folly::coro::blockingWait(third.complete());
  expectPending(revokeRequest(binding()), 1);
  ASSERT_ERROR(third.takeResult(), StatusCode::kTokenStale);
  expectDrained(revokeRequest(binding()));
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
}  // namespace
}  // namespace hf3fs::storage
