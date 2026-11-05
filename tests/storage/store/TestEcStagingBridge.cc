#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/CancellationToken.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <future>
#include <new>
#include <stdexcept>
#include <thread>

#include "storage/store/StorageTargets.h"
#include "storage/update/EcStageJob.h"
#include "storage/update/UpdateWorker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
using namespace std::chrono_literals;

struct StageBarrier {
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
  ~StageBarrier() { release(); }
};

class TestEcStagingBridge : public ::testing::Test {
 protected:
  void SetUp() override {
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    map = std::make_unique<AtomicallyTargetMap>();
    targets = std::make_unique<StorageTargets>(config, *map);
    ASSERT_OK(targets->load(executor));
    CreateTargetReq target;
    target.chainId = ChainId{121};
    target.targetId = TargetId{122};
    target.onlyChunkEngine = true;
    ASSERT_OK(targets->create(target, true));
    ASSERT_NO_FATAL_FAILURE(loadState());
    workerConfig.set_num_threads(1);
    workerConfig.set_bg_num_threads(1);
    workerConfig.set_queue_size(1);
    worker = std::make_unique<UpdateWorker>(workerConfig);
    ASSERT_OK(worker->start(1));
    request.operation = EcStageOperation::Begin;
    request.identity.object = Uuid::from(151, 152);
    request.identity.allocation = Uuid::from(153, 154);
    request.identity.generation = 1;
    request.vChainId = VersionedChainId{target.chainId, ChainVer{3}};
    request.targetId = target.targetId;
    request.operationId = Uuid::from(155, 156);
    request.writerNamespace = Uuid::from(157, 158);
    data.resize(65543);
    for (size_t i = 0; i != data.size(); ++i) data[i] = static_cast<char>((i * 37 + 19) & 255);
    auto descriptor = computeEcIntegrity(request.identity, data);
    ASSERT_OK(descriptor);
    request.integrity = *descriptor;
  }
  void TearDown() override {
    if (worker) worker->stopAndJoin();
    worker.reset();
    closeStore();
  }
  void loadState() {
    auto found = map->getByTargetId(TargetId{122});
    ASSERT_OK(found);
    store = (*found)->storageTarget;
    ASSERT_TRUE(store->usesEcStagingEngine());
    auto opened = store->ecScopeState();
    ASSERT_OK(opened);
    scope = opened->first;
    targetIdentity = opened->second;
  }
  void closeStore() {
    scope.reset();
    store.reset();
    targets.reset();
    // A process restart constructs a new map; neither release() followed by
    // reuse nor physical target removal models that lifecycle correctly.
    map.reset();
  }
  void reopen() {
    const auto old = targetIdentity;
    closeStore();
    map = std::make_unique<AtomicallyTargetMap>();
    targets = std::make_unique<StorageTargets>(config, *map);
    ASSERT_OK(targets->load(executor));
    ASSERT_NO_FATAL_FAILURE(loadState());
    ASSERT_EQ(targetIdentity, old);
  }
  EcScopeBinding binding(bool read = false) const {
    EcScopeBinding out{};
    out.target = targetIdentity;
    std::copy(std::begin(request.identity.object.data), std::end(request.identity.object.data), out.object.begin());
    out.kind = read ? 1 : 2;
    out.scope.fill(read ? 21 : 22);
    out.owner_uid = 1000;
    std::copy(std::begin(request.writerNamespace.data),
              std::end(request.writerNamespace.data),
              out.client_namespace.begin());
    if (read) out.client_namespace.fill(51);
    return out;
  }
  Result<EcStageResult> run(
      EcStageRequest input,
      std::function<Result<Void>()> route = [] { return Result<Void>{Void{}}; }) {
    auto value = binding(input.operation == EcStageOperation::ReadBlock);
    RETURN_ON_ERROR(scope->prepare(value));
    CHECK_RESULT(ticket, scope->tryAdmit(value));
    CHECK_RESULT(session, worker->acquireEcSession());
    EcStageJob job(std::move(ticket), std::move(session), std::move(input), store, std::move(route));
    folly::coro::blockingWait(worker->enqueue(&job));
    folly::coro::blockingWait(job.complete());
    return job.takeResult();
  }
  EcStageRequest op(EcStageOperation kind) const {
    auto result = request;
    result.operation = kind;
    return result;
  }
  Result<EcStageResult> append(uint8_t index) {
    auto input = op(EcStageOperation::Append);
    input.blockIndex = index;
    const size_t offset = size_t(index) * kEcIntegrityBlockBytes;
    input.payload = data.substr(offset, kEcIntegrityBlockBytes);
    return run(std::move(input));
  }
  void writeAll() {
    ASSERT_OK(run(request));
    for (uint8_t i = 0; i != request.integrity.blockCount; ++i) ASSERT_OK(append(i));
  }

  folly::test::TemporaryDirectory directory;
  CPUExecutorGroup executor{1, "EcStageTest"};
  StorageTargets::Config config;
  std::unique_ptr<AtomicallyTargetMap> map;
  std::unique_ptr<StorageTargets> targets;
  std::shared_ptr<StorageTarget> store;
  std::shared_ptr<EcScope> scope;
  EcScopeTargetIdentity targetIdentity{};
  UpdateWorker::Config workerConfig;
  std::unique_ptr<UpdateWorker> worker;
  EcStageRequest request;
  std::string data;
};

TEST_F(TestEcStagingBridge, RealWorkerSealsBoundedBlocksAndRejectsLegacyAccess) {
  ASSERT_NO_FATAL_FAILURE(writeAll());
  auto result = run(op(EcStageOperation::Seal));
  ASSERT_OK(result);
  ASSERT_TRUE(result->sealed);
  EXPECT_EQ(result->sealed->length, data.size());
  EXPECT_EQ(result->sealed->operationId, request.operationId);
  EXPECT_FALSE(result->state);
  const auto accounted = store->usedSize();
  EXPECT_GE(accounted, data.size());
  auto repeated = run(op(EcStageOperation::Seal));
  ASSERT_OK(repeated);
  EXPECT_EQ(store->usedSize(), accounted);
  std::string read;
  for (uint8_t i = 0; i != request.integrity.blockCount; ++i) {
    auto input = op(EcStageOperation::ReadBlock);
    input.writerNamespace = Uuid::from(300, 301);  // Reader is not the original writer metadata.
    input.blockIndex = i;
    auto block = run(std::move(input));
    ASSERT_OK(block);
    EXPECT_LE(block->data.size(), kEcIntegrityBlockBytes);
    EXPECT_FALSE(block->sealed);
    read += block->data;
  }
  EXPECT_EQ(read, data);
  EcReadReq legacy;
  legacy.identity = request.identity;
  legacy.operationId = request.operationId;
  legacy.vChainId = request.vChainId;
  legacy.targetId = request.targetId;
  legacy.expectedLength = data.size();
  legacy.checksum = ChecksumInfo{ChecksumType::CRC32C, ~request.integrity.wholeCrc32c};
  EXPECT_FALSE(store->readEcFragment(legacy));
  EXPECT_FALSE(store->createEcFragment(EcCreateReq{}));
  EXPECT_FALSE(store->reconcileEcFragment(EcReconcileReq{}));
  EXPECT_TRUE(targets->engines().empty());  // No hidden legacy Engine escape hatch.
}

TEST_F(TestEcStagingBridge, ExactTailAndTrustedBlockProofAreRequired) {
  ASSERT_OK(run(request));
  ASSERT_OK(append(0));
  ASSERT_OK(append(0));
  auto wrong = op(EcStageOperation::Append);
  wrong.blockIndex = 1;
  wrong.payload = data.substr(65536);
  wrong.payload[0] ^= 1;
  EXPECT_FALSE(run(wrong));
  wrong.payload = data.substr(65536) + "padding";
  EXPECT_FALSE(run(wrong));
  wrong.payload.assign(65537, 'x');
  EXPECT_FALSE(run(wrong));
  auto status = run(op(EcStageOperation::Query));
  ASSERT_OK(status);
  ASSERT_TRUE(status->state);
  EXPECT_EQ(status->state->prefix_bytes, 65536);
  ASSERT_OK(append(1));
  ASSERT_OK(run(op(EcStageOperation::Seal)));
}

TEST_F(TestEcStagingBridge, ReopenKeepsReservationAndRequiresExplicitReconciliation) {
  ASSERT_OK(run(request));
  ASSERT_OK(append(0));
  ASSERT_NO_FATAL_FAILURE(reopen());
  auto queried = run(op(EcStageOperation::Query));
  ASSERT_OK(queried);
  ASSERT_TRUE(queried->state);
  EXPECT_TRUE(queried->state->needs_reconcile);
  EXPECT_FALSE(queried->sealed);
  EXPECT_EQ(queried->state->prefix_bytes, 65536);
  ASSERT_OK(run(op(EcStageOperation::Reconcile)));
  ASSERT_OK(append(1));
  ASSERT_OK(run(op(EcStageOperation::Seal)));
  ASSERT_NO_FATAL_FAILURE(reopen());
  ASSERT_OK(run(op(EcStageOperation::Reconcile)));
  auto input = op(EcStageOperation::ReadBlock);
  input.blockIndex = 1;
  auto read = run(input);
  ASSERT_OK(read);
  EXPECT_EQ(read->data, data.substr(65536));
}

TEST_F(TestEcStagingBridge, FinalRouteFailureSuppressesSealReceiptButKeepsData) {
  ASSERT_NO_FATAL_FAILURE(writeAll());
  unsigned checks = 0;
  auto failed = run(op(EcStageOperation::Seal), [&]() -> Result<Void> {
    if (++checks > 1) return makeError(StatusCode::kTokenMismatch, "route changed after disk completion");
    return Void{};
  });
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error().code(), StorageCode::kEcSealOutcomeUnknown);
  auto retry = run(op(EcStageOperation::Seal));
  ASSERT_OK(retry);
  ASSERT_TRUE(retry->sealed);
  unsigned throwingChecks = 0;
  auto uncertain = run(op(EcStageOperation::Seal), [&]() -> Result<Void> {
    if (++throwingChecks > 1) throw std::runtime_error("postcheck allocation or verification failure");
    return Void{};
  });
  ASSERT_ERROR(uncertain, StorageCode::kEcSealOutcomeUnknown);
}

TEST_F(TestEcStagingBridge, WriterNamespaceConflictDoesNotReplaceStage) {
  ASSERT_OK(run(request));
  auto changed = request;
  changed.writerNamespace = Uuid::from(998, 999);
  EXPECT_FALSE(run(changed));                    // Admission rejects the conflicting writer.
  EXPECT_FALSE(store->executeEcStage(changed));  // Persistent spec independently rejects it.
  auto changedRoute = request;
  changedRoute.vChainId.chainVer = ChainVer{4};
  ASSERT_OK(run(changedRoute));  // Route checks external; stable stored chain_ver remains zero.
}

TEST_F(TestEcStagingBridge, EmptyStageSealsWithoutInventingReadableBlock) {
  data.clear();
  auto integrity = computeEcIntegrity(request.identity, data);
  ASSERT_OK(integrity);
  request.integrity = *integrity;
  ASSERT_OK(run(request));
  auto result = run(op(EcStageOperation::Seal));
  ASSERT_OK(result);
  ASSERT_TRUE(result->sealed);
  EXPECT_EQ(result->sealed->length, 0);
  EXPECT_FALSE(run(op(EcStageOperation::ReadBlock)));
}

TEST_F(TestEcStagingBridge, V1AndLegacyModesRejectV2RootBeforeOpeningData) {
  StorageTargets::Config wrong;
  wrong.set_target_paths({directory.path()});
  wrong.set_allow_disk_without_uuid(true);
  AtomicallyTargetMap unused;
  StorageTargets legacy(wrong, unused);
  EXPECT_FALSE(legacy.init(executor));
  wrong.set_ec_only(true);
  StorageTargets v1(wrong, unused);
  EXPECT_FALSE(v1.init(executor));
  EXPECT_TRUE(store->usesEcStagingEngine());
}

TEST_F(TestEcStagingBridge, SealTicketRemainsLiveThroughFinalRevocationCheck) {
  ASSERT_NO_FATAL_FAILURE(writeAll());
  const auto value = binding();
  ASSERT_OK(scope->prepare(value));
  auto ticket = scope->tryAdmit(value);
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  EcStageJob job(std::move(*ticket), std::move(*session), op(EcStageOperation::Seal), store, [] {
    return Result<Void>{Void{}};
  });
  folly::coro::blockingWait(worker->enqueue(&job));
  folly::coro::blockingWait(job.complete());
  EcScopeRevocation revoke{};
  revoke.binding = value;
  revoke.id.fill(41);
  revoke.endpoint_set_digest.fill(42);
  auto pending = scope->revoke(revoke);
  ASSERT_OK(pending);
  EXPECT_TRUE(pending->durable);
  EXPECT_FALSE(pending->drained);
  EXPECT_EQ(pending->inflight, 1);
  ASSERT_ERROR(job.takeResult(), StorageCode::kEcSealOutcomeUnknown);
  auto drained = scope->drainStatus(revoke);
  ASSERT_OK(drained);
  EXPECT_TRUE(drained->drained);
  // Trusted local observation only: revocation is not deletion permission.
  auto observed = store->executeEcStage(op(EcStageOperation::Query));
  ASSERT_OK(observed);
  ASSERT_TRUE(observed->state);
  EXPECT_EQ(observed->state->state, 2);
}

TEST_F(TestEcStagingBridge, FullStageQueueRejectsBeforeMutationAndPreservesEarlierTickets) {
  ASSERT_NO_FATAL_FAILURE(writeAll());
  ASSERT_OK(run(op(EcStageOperation::Seal)));
  const auto value = binding(true);
  ASSERT_OK(scope->prepare(value));
  const auto make = [&](std::function<Result<Void>()> route) -> std::unique_ptr<EcStageJob> {
    auto ticket = scope->tryAdmit(value);
    auto session = worker->acquireEcSession();
    if (!ticket || !session) return nullptr;
    return std::make_unique<EcStageJob>(std::move(*ticket),
                                        std::move(*session),
                                        op(EcStageOperation::ReadBlock),
                                        store,
                                        std::move(route));
  };
  StageBarrier barrier;
  auto entered = barrier.entered.get_future();
  auto first = make([&] { return barrier.wait(); });
  ASSERT_TRUE(first);
  folly::coro::blockingWait(worker->enqueue(first.get()));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(first->complete());
    (void)first->takeResult();
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  auto second = make([] { return Result<Void>{Void{}}; });
  ASSERT_TRUE(second);
  folly::coro::blockingWait(worker->enqueue(second.get()));
  SCOPE_EXIT {
    barrier.release();
    folly::coro::blockingWait(second->complete());
    (void)second->takeResult();
  };
  auto third = make([] { return Result<Void>{Void{}}; });
  ASSERT_TRUE(third);
  folly::CancellationSource cancellation;
  cancellation.requestCancellation();
  folly::coro::blockingWait(folly::coro::co_withCancellation(cancellation.getToken(), worker->enqueue(third.get())));
  folly::coro::blockingWait(third->complete());
  EXPECT_FALSE(third->queued());
  ASSERT_ERROR(third->takeResult(), StorageClientCode::kResourceBusy);
  EcScopeRevocation revoke{};
  revoke.binding = value;
  revoke.id.fill(44);
  revoke.endpoint_set_digest.fill(45);
  auto pending = scope->revoke(revoke);
  ASSERT_OK(pending);
  EXPECT_EQ(pending->inflight, 2);  // Only the already submitted jobs remain.
  barrier.release();
  folly::coro::blockingWait(first->complete());
  folly::coro::blockingWait(second->complete());
  (void)first->takeResult();
  (void)second->takeResult();
  auto drained = scope->drainStatus(revoke);
  ASSERT_OK(drained);
  EXPECT_TRUE(drained->drained);
}

TEST_F(TestEcStagingBridge, ExceptionBeforeCreatingCompletionTaskRetainsSealUntilRealFinish) {
  ASSERT_NO_FATAL_FAILURE(writeAll());
  const auto value = binding();
  ASSERT_OK(scope->prepare(value));
  auto ticket = scope->tryAdmit(value);
  auto session = worker->acquireEcSession();
  ASSERT_OK(ticket);
  ASSERT_OK(session);
  StageBarrier barrier;
  auto entered = barrier.entered.get_future();
  std::promise<void> unwinding;
  auto unwindingFuture = unwinding.get_future();
  std::promise<void> caught;
  auto caughtFuture = caught.get_future();
  std::atomic<bool> wasQueued{false};
  std::atomic<bool> unexpected{false};
  std::thread caller([&] {
    try {
      EcStageJob job(std::move(*ticket), std::move(*session), op(EcStageOperation::Seal), store, [&] {
        return barrier.wait();
      });
      folly::coro::blockingWait(worker->enqueue(&job));
      wasQueued.store(job.queued());
      unwinding.set_value();
      // Deterministic simulation of failure constructing complete()'s Task.
      // No global allocator is changed, and no real resource exhaustion claimed.
      throw std::bad_alloc();
    } catch (const std::bad_alloc &) {
      caught.set_value();
    } catch (...) {
      unexpected.store(true);
      caught.set_value();
    }
  });
  SCOPE_EXIT {
    barrier.release();
    caller.join();
  };
  ASSERT_EQ(entered.wait_for(5s), std::future_status::ready);
  ASSERT_EQ(unwindingFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(wasQueued.load());
  EXPECT_EQ(caughtFuture.wait_for(20ms), std::future_status::timeout);
  barrier.release();
  ASSERT_EQ(caughtFuture.wait_for(5s), std::future_status::ready);
  EXPECT_FALSE(unexpected.load());
  auto observed = store->executeEcStage(op(EcStageOperation::Query));
  ASSERT_OK(observed);
  ASSERT_TRUE(observed->state);
  EXPECT_EQ(observed->state->state, 2);  // Seal actually completed, despite the lost waiter.
  EcScopeRevocation revoke{};
  revoke.binding = value;
  revoke.id.fill(46);
  revoke.endpoint_set_digest.fill(47);
  auto drained = scope->revoke(revoke);
  ASSERT_OK(drained);
  EXPECT_TRUE(drained->drained);  // Destructor released the original ticket only after Seal.
}

}  // namespace
}  // namespace hf3fs::storage
