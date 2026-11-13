#include <atomic>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/CurrentExecutor.h>
#include <folly/experimental/coro/Sleep.h>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include "client/ec/EcRepairPipeline.h"
#include "common/utils/SemaphoreGuard.h"
#include "fbs/storage/Common.h"
#include "tests/EcRepairTestData.h"

namespace hf3fs::client::ec {
namespace {
using namespace hf3fs::storage;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

// Scheduler-only transport. Helper mode computes in this test process and is
// deliberately not evidence of native RPC, authentication, durability or drain.
class TestTransport final : public EcRepairTransport {
 public:
  explicit TestTransport(repair_test::Data value)
      : data(std::move(value)) {}
  enum class FaultAt { None, Begin, Read, Append, Seal, Direct };
  enum class FaultKind { BadAlloc, Standard, Status, NonStandard };
  repair_test::Data data;
  std::atomic<size_t> begun{0}, reads{0}, helperCalls{0}, seals{0}, active{0}, appends{0}, faults{0};
  std::atomic<size_t> directCalls{0}, directWrites{0};
  bool allowDirect = false;
  bool holdDirectAcrossException = false;
  folly::coro::Baton secondDirectEntered, releaseSecondDirect;
  FaultAt faultAt = FaultAt::None;
  FaultKind faultKind = FaultKind::BadAlloc;
  bool holdReadAcrossAppendException = false;
  folly::coro::Baton secondReadEntered, releaseSecondRead, exceptionEntered;
  void inject(FaultAt point) {
    if (point != faultAt) return;
    ++faults;
    exceptionEntered.post();
    switch (faultKind) {
      case FaultKind::BadAlloc:
        throw std::bad_alloc();
      case FaultKind::Standard:
        throw std::runtime_error("injected mutation completion exception");
      case FaultKind::Status:
        throw StatusException(Status(StatusCode::kDataCorruption, "injected status exception"));
      case FaultKind::NonStandard:
        throw 17;
    }
  }
  std::atomic<uint32_t> startedBlocks{0};
  std::atomic<bool> holdFirstAppend{false}, firstAppendEntered{false};
  std::atomic<bool> holdSecondRead{false}, corruptFirstAfterSecondStarts{false};
  std::atomic<bool> failAppend{false};
  bool allowHelper = true;
  bool readFailureBeforeUnknownAppend = false;
  folly::coro::Baton appendWaiting, readFailureReturning;
  std::mutex mutex;
  std::array<std::string, 2> written;

  bool supportsHelperChain() const override { return allowHelper; }
  bool supportsHelperDirect() const override { return allowDirect; }
  CoTryTask<void> begin(Plan, uint8_t, EcRepairControl) override {
    ++begun;  // Models an entered mutation, not evidence of a real remote commit.
    inject(FaultAt::Begin);
    co_return Void{};
  }
  CoTryTask<std::string> read(Plan plan, uint8_t source, uint32_t block, EcRepairControl control) override {
    ++active;
    SCOPE_EXIT { --active; };
    ++reads;
    if (holdReadAcrossAppendException && block == 1 && source == 0) {
      secondReadEntered.post();
      co_await releaseSecondRead;
    }
    inject(FaultAt::Read);
    startedBlocks.fetch_or(uint32_t{1} << block);
    if (readFailureBeforeUnknownAppend && block == 1 && source == 0) {
      co_await appendWaiting;
      readFailureReturning.post();
      co_return makeError(StorageClientCode::kTimeout, "read failed before append settled");
    }
    if (source == 0 && block == 0 && corruptFirstAfterSecondStarts) {
      while (!(startedBlocks.load() & 2)) {
        if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
        co_await folly::coro::sleep(1ms);
      }
    }
    while (block == 1 && source == 0 && holdSecondRead) {
      if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
      co_await folly::coro::sleep(1ms);
    }
    auto bytes = repair_test::blockBytes(data, plan->input().sources[source], block);
    if (source == 0 && block == 0 && corruptFirstAfterSecondStarts) bytes[0] ^= 1;
    co_return bytes;
  }
  CoTryTask<void> append(Plan plan,
                         uint8_t target,
                         uint32_t block,
                         std::string bytes,
                         EcRepairControl control) override {
    ++active;
    SCOPE_EXIT { --active; };
    if (block == 0 && target == 0) firstAppendEntered = true;
    if (holdReadAcrossAppendException && block == 0 && target == 0) co_await secondReadEntered;
    if (readFailureBeforeUnknownAppend && block == 0 && target == 0) {
      appendWaiting.post();
      co_await readFailureReturning;
      // The single-thread executor processes the read's synchronous return and
      // error aggregation before this suspended append can complete.
      co_await folly::coro::co_reschedule_on_current_executor;
      co_return makeError(StorageCode::kEcSealOutcomeUnknown, "append completion was not acknowledged");
    }
    while (block == 0 && target == 0 && holdFirstAppend) {
      if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
      co_await folly::coro::sleep(1ms);
    }
    if (failAppend) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    const auto &fragment = plan->input().targets[target];
    CO_RETURN_ON_ERROR(verifyEcIntegrityBlock(fragment.identity, fragment.integrity, block, bytes));
    std::lock_guard lock(mutex);
    if (written[target].size() != size_t(block) * kEcIntegrityBlockBytes) co_return makeError(StatusCode::kInvalidArg);
    written[target] += bytes;
    ++appends;  // Mutate the scheduler substitute before throwing its completion.
    inject(FaultAt::Append);
    co_return Void{};
  }
  CoTryTask<EcFragmentReceiptV2> seal(Plan plan, uint8_t target, EcRepairControl) override {
    ++seals;
    std::lock_guard lock(mutex);
    if (written[target] != data.shards[plan->input().targets[target].identity.shard])
      co_return makeError(StatusCode::kDataCorruption);
    inject(FaultAt::Seal);
    co_return repair_test::receipt(plan->input().targets[target]);
  }
  CoTryTask<EcRepairBlock> helperBlock(Plan plan, uint32_t index, EcRepairControl) override {
    ++helperCalls;
    auto result = EcRepairBlockCore::begin(*plan, index);
    CO_RETURN_ON_ERROR(result);
    for (uint8_t hop = 0; hop != 10; ++hop) {
      result = EcRepairBlockCore::advance(*plan,
                                          hop,
                                          std::move(*result),
                                          repair_test::blockBytes(data, plan->input().sources[hop], index));
      CO_RETURN_ON_ERROR(result);
    }
    co_return std::move(*result);
  }
  CoTryTask<void> helperDirectBlock(Plan plan, uint32_t index, EcRepairControl control) override {
    ++directCalls;
    ++active;
    SCOPE_EXIT { --active; };
    if (holdDirectAcrossException && index == 1) {
      secondDirectEntered.post();
      co_await releaseSecondDirect;
    }
    if (holdDirectAcrossException && index == 0) co_await secondDirectEntered;
    auto block = co_await helperBlock(plan, index, control);
    CO_RETURN_ON_ERROR(block);
    // A scheduler substitute for target-side prefix arbitration. It is not
    // evidence of native direct RPC, target persistence or capability checks.
    for (uint8_t target = 0; target != block->targetCount; ++target) {
      bool writtenBlock = false;
      while (!writtenBlock) {
        if (control.cancellation.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
        if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
        {
          std::lock_guard lock(mutex);
          const size_t offset = size_t(index) * kEcIntegrityBlockBytes;
          if (written[target].size() == offset) {
            written[target] += block->outputs[target];
            ++directWrites;
            writtenBlock = true;
          } else if (written[target].size() > offset) {
            if (written[target].substr(offset, block->outputs[target].size()) != block->outputs[target])
              co_return makeError(StatusCode::kDataCorruption);
            writtenBlock = true;
          }
        }
        if (!writtenBlock) co_await folly::coro::sleep(1ms);
      }
      inject(FaultAt::Direct);
    }
    co_return Void{};
  }
};

EcRepairControl control() { return {Clock::now() + 5s, {}}; }
bool waitFor(const std::function<bool()> &predicate) {
  const auto until = Clock::now() + 2s;
  while (!predicate() && Clock::now() < until) std::this_thread::sleep_for(1ms);
  return predicate();
}

void mutationExceptionCase(TestTransport::FaultAt point) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(31, {0});
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
    for (auto kind : {TestTransport::FaultKind::BadAlloc,
                      TestTransport::FaultKind::Standard,
                      TestTransport::FaultKind::Status,
                      TestTransport::FaultKind::NonStandard}) {
      auto transport = std::make_shared<TestTransport>(data);
      transport->faultAt = point;
      transport->faultKind = kind;
      auto result = folly::coro::blockingWait(EcRepairPipeline::run(*plan, transport, mode, control(), executor));
      ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
      ASSERT_TRUE(result.error().hasPayload());
      const auto cause = result.error().payload<Status>();
      ASSERT_NE(cause, nullptr);
      EXPECT_EQ(cause->code(),
                kind == TestTransport::FaultKind::BadAlloc ? StatusCode::kNotEnoughMemory
                : kind == TestTransport::FaultKind::Status ? StatusCode::kDataCorruption
                                                           : StatusCode::kIOError);
      EXPECT_FALSE(cause->message().empty());
      EXPECT_EQ(transport->faults.load(), 1);
      EXPECT_EQ(transport->begun.load(), 1);
      EXPECT_EQ(transport->active.load(), 0);
      EXPECT_EQ(transport->appends.load(), point == TestTransport::FaultAt::Begin ? 0 : 1);
      EXPECT_EQ(transport->seals.load(), point == TestTransport::FaultAt::Seal ? 1 : 0);
    }
  }
}

TEST(TestEcRepairPipeline, EnteredBeginExceptionsRetainUnknownOutcomeAndCause) {
  mutationExceptionCase(TestTransport::FaultAt::Begin);
}
TEST(TestEcRepairPipeline, EnteredAppendExceptionsRetainUnknownOutcomeAndCause) {
  mutationExceptionCase(TestTransport::FaultAt::Append);
}
TEST(TestEcRepairPipeline, EnteredSealExceptionsRetainUnknownOutcomeAndCause) {
  mutationExceptionCase(TestTransport::FaultAt::Seal);
}

TEST(TestEcRepairPipeline, ReadAllocationFailureIsNotClassifiedAsUnknownMutation) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(31, {0});
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline}) {
    auto transport = std::make_shared<TestTransport>(data);
    transport->faultAt = TestTransport::FaultAt::Read;
    auto result = folly::coro::blockingWait(EcRepairPipeline::run(*plan, transport, mode, control(), executor));
    ASSERT_ERROR(result, StatusCode::kNotEnoughMemory);
    EXPECT_EQ(transport->begun.load(), 1);  // This earlier Begin returned a known success.
    EXPECT_EQ(transport->appends.load(), 0);
    EXPECT_EQ(transport->seals.load(), 0);
    EXPECT_EQ(transport->active.load(), 0);
  }
}

TEST(TestEcRepairPipeline, AppendExceptionStillJoinsAnotherStartedRead) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->faultAt = TestTransport::FaultAt::Append;
  transport->holdReadAcrossAppendException = true;
  EcRepairObservation observation;
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor, &observation));
    done = true;
  });
  SCOPE_EXIT {
    transport->releaseSecondRead.post();
    runner.join();
  };
  folly::coro::blockingWait([&]() -> CoTask<void> { co_await transport->exceptionEntered; }());
  EXPECT_FALSE(done);
  EXPECT_GE(transport->active.load(), 1);
  transport->releaseSecondRead.post();
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  const auto sample = observation.snapshot();
  EXPECT_FALSE(sample.overflow);
  EXPECT_FALSE(sample.clockAnomaly);
  for (const auto &point : sample.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.entered, point.finished);
  }
  const auto &actors = sample.at(EcRepairPoint::BlockActor);
  EXPECT_LE(actors.peakActive, 2);
  EXPECT_GE(actors.entered, 1);
  ASSERT_ERROR(*result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(transport->active.load(), 0);
  EXPECT_EQ(transport->seals.load(), 0);
}

TEST(TestEcRepairPipeline, AllThreeModesMatchIndependentSingleAndDoubleTargets) {
  folly::CPUThreadPoolExecutor executor(2);
  for (auto missing : {std::vector<uint16_t>{10}, std::vector<uint16_t>{0, 11}}) {
    const auto data = repair_test::makeData(kEcIntegrityBlockBytes + 13, missing);
    auto plan = EcRepairPlan::create(data.input);
    ASSERT_OK(plan);
    for (const auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline, EcRepairMode::HelperChain}) {
      auto transport = std::make_shared<TestTransport>(data);
      EcRepairObservation observation;
      auto result = folly::coro::blockingWait(EcRepairPipeline::run(*plan, transport, mode, control(), executor, &observation));
      ASSERT_OK(result);
      const auto sample = observation.snapshot();
      const auto &actors = sample.at(EcRepairPoint::BlockActor);
      EXPECT_EQ(actors.entered, mode == EcRepairMode::CentralSerial ? 0 : 2);
      EXPECT_EQ(actors.finished, actors.entered);
      EXPECT_EQ(actors.succeeded, actors.entered);
      EXPECT_EQ(actors.active, 0);
      EXPECT_EQ(sample.at(EcRepairPoint::CentralCodecRecover).entered, mode == EcRepairMode::CentralSerial ? 1 : 0);
      EXPECT_EQ(sample.at(EcRepairPoint::ClientBlockAdvance).entered, mode == EcRepairMode::ClientPipeline ? 20 : 0);
      for (auto point : {EcRepairPoint::CentralCodecRecover, EcRepairPoint::ClientBlockAdvance}) {
        EXPECT_EQ(sample.at(point).succeeded, sample.at(point).entered);
        EXPECT_EQ(sample.at(point).finished, sample.at(point).entered);
        EXPECT_EQ(sample.at(point).active, 0);
      }
      EXPECT_EQ(sample.at(EcRepairPoint::NativeRead).apiInvocations, 0); // Fake transport is not native RPC evidence.
      EXPECT_EQ(result->mode, mode);
      EXPECT_EQ(result->targetCount, missing.size());
      EXPECT_EQ(transport->seals.load(), missing.size());
      EXPECT_EQ(transport->active.load(), 0);
      EXPECT_EQ(transport->helperCalls.load(), mode == EcRepairMode::HelperChain ? 2 : 0);
      EXPECT_EQ(transport->reads.load(), mode == EcRepairMode::HelperChain ? 0 : 20);
      for (size_t target = 0; target != missing.size(); ++target)
        EXPECT_EQ(transport->written[target], data.shards[missing[target]]);
    }
  }
}

TEST(TestEcRepairPipeline, WindowOverlapsReadWithAppendAndBoundsLaterBlocks) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(2 * kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->holdFirstAppend = true;
  EcRepairObservation observation;
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor, &observation));
    done = true;
  });
  SCOPE_EXIT {
    transport->holdFirstAppend = false;
    runner.join();
  };
  ASSERT_TRUE(waitFor([&] { return transport->firstAppendEntered && (transport->startedBlocks.load() & 2); }));
  EXPECT_FALSE(done);
  EXPECT_EQ(observation.snapshot().at(EcRepairPoint::BlockActor).active, 2);
  EXPECT_EQ(transport->startedBlocks.load(), 3);  // Block 2 has no window slot yet.
  transport->holdFirstAppend = false;
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  const auto sample = observation.snapshot();
  EXPECT_FALSE(sample.overflow);
  EXPECT_FALSE(sample.clockAnomaly);
  for (const auto &point : sample.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.entered, point.finished);
  }
  const auto &actors = sample.at(EcRepairPoint::BlockActor);
  EXPECT_LE(actors.peakActive, 2);
  EXPECT_GE(actors.entered, 1);
  ASSERT_OK(*result);
  EXPECT_EQ(actors.entered, 3);
  EXPECT_EQ(actors.succeeded, 3);
  EXPECT_EQ(actors.peakActive, 2);
  EXPECT_EQ(sample.at(EcRepairPoint::OrderedAppendWait).entered, 3);
}

TEST(TestEcRepairPipeline, CancellationRetainsSubmittedAppendAndDoesNotSeal) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->holdFirstAppend = true;
  CancellationSource stop;
  auto options = control();
  options.cancellation = stop.getToken();
  EcRepairObservation observation;
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, options, executor, &observation));
    done = true;
  });
  SCOPE_EXIT {
    transport->holdFirstAppend = false;
    runner.join();
  };
  ASSERT_TRUE(waitFor([&] { return transport->firstAppendEntered.load(); }));
  stop.requestCancellation();
  std::this_thread::sleep_for(10ms);
  EXPECT_FALSE(done);
  EXPECT_GE(transport->active.load(), 1);
  EXPECT_GE(observation.snapshot().at(EcRepairPoint::BlockActor).active, 1);
  transport->holdFirstAppend = false;
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  const auto sample = observation.snapshot();
  EXPECT_FALSE(sample.overflow);
  EXPECT_FALSE(sample.clockAnomaly);
  for (const auto &point : sample.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.entered, point.finished);
  }
  const auto &actors = sample.at(EcRepairPoint::BlockActor);
  EXPECT_LE(actors.peakActive, 2);
  EXPECT_GE(actors.entered, 1);
  ASSERT_FALSE(result->hasValue());
  EXPECT_LT(actors.succeeded, actors.entered);
  EXPECT_EQ(transport->seals.load(), 0);
  EXPECT_EQ(transport->active.load(), 0);
}

TEST(TestEcRepairPipeline, CorruptionFailureStillJoinsOtherInFlightRead) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->corruptFirstAfterSecondStarts = true;
  transport->holdSecondRead = true;
  EcRepairObservation observation;
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor, &observation));
    done = true;
  });
  SCOPE_EXIT {
    transport->holdSecondRead = false;
    runner.join();
  };
  ASSERT_TRUE(waitFor([&] { return transport->startedBlocks.load() == 3; }));
  std::this_thread::sleep_for(10ms);
  EXPECT_FALSE(done);
  transport->holdSecondRead = false;
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  const auto sample = observation.snapshot();
  EXPECT_FALSE(sample.overflow);
  EXPECT_FALSE(sample.clockAnomaly);
  for (const auto &point : sample.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.entered, point.finished);
  }
  const auto &actors = sample.at(EcRepairPoint::BlockActor);
  EXPECT_LE(actors.peakActive, 2);
  EXPECT_GE(actors.entered, 1);
  ASSERT_ERROR(*result, StatusCode::kDataCorruption);
  EXPECT_EQ(transport->seals.load(), 0);
  EXPECT_EQ(transport->active.load(), 0);
}

TEST(TestEcRepairPipeline, UnsupportedHelperAndExpiredDeadlineMakeNoStorageMutation) {
  folly::CPUThreadPoolExecutor executor(1);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->allowHelper = false;
  auto result = folly::coro::blockingWait(
      EcRepairPipeline::run(*plan, transport, EcRepairMode::HelperChain, control(), executor));
  ASSERT_ERROR(result, StatusCode::kNotImplemented);
  EXPECT_EQ(transport->begun.load(), 0);
  auto expired = control();
  expired.deadline = Clock::now();
  result = folly::coro::blockingWait(
      EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, expired, executor));
  ASSERT_ERROR(result, StorageClientCode::kTimeout);
  EXPECT_EQ(transport->begun.load(), 0);
}

TEST(TestEcRepairPipeline, LaterUnknownAppendOutranksEarlierReadFailure) {
  folly::CPUThreadPoolExecutor executor(1);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->readFailureBeforeUnknownAppend = true;
  auto result = folly::coro::blockingWait(
      EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor));
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_TRUE(transport->firstAppendEntered.load());
  EXPECT_EQ(transport->startedBlocks.load(), 3);
  EXPECT_EQ(transport->seals.load(), 0);
  EXPECT_EQ(transport->active.load(), 0);
}

TEST(TestEcRepairPipeline, UnknownAppendOutcomeDoesNotSealOrDeleteAnyAllocation) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->failAppend = true;
  auto result = folly::coro::blockingWait(
      EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor));
  ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(transport->begun.load(), 2);
  EXPECT_EQ(transport->seals.load(), 0);
  EXPECT_EQ(transport->active.load(), 0);
}

TEST(TestEcRepairPipeline, DirectDeliveryUsesWindowAndSealsWithoutClientAppend) {
  folly::CPUThreadPoolExecutor executor(2);
  for (const auto window : {1, 2, 4}) {
    for (const auto &missing : {std::vector<uint16_t>{0}, std::vector<uint16_t>{0, 11}}) {
      auto data = repair_test::makeData(4 * kEcIntegrityBlockBytes + 7, missing, window);
      auto plan = EcRepairPlan::create(data.input);
      ASSERT_OK(plan);
      auto transport = std::make_shared<TestTransport>(data);
      transport->allowDirect = true;
      EcRepairObservation observation;
      auto result = folly::coro::blockingWait(EcRepairPipeline::run(
          *plan, transport, EcRepairMode::HelperChain, control(), executor, &observation, EcRepairDelivery::HelperDirect));
      ASSERT_OK(result);
      EXPECT_EQ(result->delivery, EcRepairDelivery::HelperDirect);
      EXPECT_EQ(result->mode, EcRepairMode::HelperChain);
      EXPECT_EQ(transport->begun.load(), missing.size());
      EXPECT_EQ(transport->seals.load(), missing.size());
      EXPECT_EQ(transport->directCalls.load(), 5);
      EXPECT_EQ(transport->directWrites.load(), 5 * missing.size());
      EXPECT_EQ(transport->reads.load(), 0);
      EXPECT_EQ(transport->appends.load(), 0);
      EXPECT_EQ(transport->active.load(), 0);
      for (size_t target = 0; target != missing.size(); ++target)
        EXPECT_EQ(transport->written[target], data.shards[missing[target]]);
      const auto sample = observation.snapshot();
      EXPECT_EQ(sample.at(EcRepairPoint::BlockActor).entered, 5);
      EXPECT_LE(sample.at(EcRepairPoint::BlockActor).peakActive, window);
      EXPECT_EQ(sample.at(EcRepairPoint::OrderedAppendWait).entered, 0);
      EXPECT_EQ(sample.at(EcRepairPoint::ClientBlockAdvance).entered, 0);
      for (const auto &point : sample.points) {
        EXPECT_EQ(point.active, 0);
        EXPECT_EQ(point.entered, point.finished);
      }
    }
  }
}

TEST(TestEcRepairPipeline, DirectDeliveryRequiresExplicitSupportedHelperBeforeBegin) {
  folly::CPUThreadPoolExecutor executor(1);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  auto result = folly::coro::blockingWait(EcRepairPipeline::run(
      *plan, transport, EcRepairMode::HelperChain, control(), executor, nullptr, EcRepairDelivery::HelperDirect));
  ASSERT_ERROR(result, StatusCode::kNotImplemented);
  transport->allowDirect = true;
  for (auto mode : {EcRepairMode::CentralSerial, EcRepairMode::ClientPipeline}) {
    result = folly::coro::blockingWait(EcRepairPipeline::run(
        *plan, transport, mode, control(), executor, nullptr, EcRepairDelivery::HelperDirect));
    ASSERT_ERROR(result, StatusCode::kInvalidArg);
  }
  result = folly::coro::blockingWait(EcRepairPipeline::run(
      *plan, transport, EcRepairMode::HelperChain, control(), executor, nullptr, static_cast<EcRepairDelivery>(99)));
  ASSERT_ERROR(result, StatusCode::kInvalidArg);
  EXPECT_EQ(transport->begun.load(), 0);
  EXPECT_EQ(transport->directCalls.load(), 0);
  EXPECT_EQ(transport->appends.load(), 0);
}

TEST(TestEcRepairPipeline, PartialDirectMutationExceptionsStayUnknownAndDoNotSeal) {
  folly::CPUThreadPoolExecutor executor(1);
  auto data = repair_test::makeData(31);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  for (auto kind : {TestTransport::FaultKind::BadAlloc,
                    TestTransport::FaultKind::Standard,
                    TestTransport::FaultKind::Status,
                    TestTransport::FaultKind::NonStandard}) {
    auto transport = std::make_shared<TestTransport>(data);
    transport->allowDirect = true;
    transport->faultAt = TestTransport::FaultAt::Direct;
    transport->faultKind = kind;
    auto result = folly::coro::blockingWait(EcRepairPipeline::run(
        *plan, transport, EcRepairMode::HelperChain, control(), executor, nullptr, EcRepairDelivery::HelperDirect));
    ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
    EXPECT_TRUE(result.error().hasPayload());
    EXPECT_EQ(transport->begun.load(), 2);
    EXPECT_EQ(transport->directWrites.load(), 1);
    EXPECT_FALSE(transport->written[0].empty());
    EXPECT_TRUE(transport->written[1].empty());
    EXPECT_EQ(transport->seals.load(), 0);
    EXPECT_EQ(transport->appends.load(), 0);
    EXPECT_EQ(transport->active.load(), 0);
  }
}

TEST(TestEcRepairPipeline, DirectMutationFailureJoinsOtherStartedDirectBlock) {
  folly::CPUThreadPoolExecutor executor(2);
  auto data = repair_test::makeData(kEcIntegrityBlockBytes + 7, {0}, 2);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto transport = std::make_shared<TestTransport>(data);
  transport->allowDirect = true;
  transport->holdDirectAcrossException = true;
  transport->faultAt = TestTransport::FaultAt::Direct;
  EcRepairObservation observation;
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(EcRepairPipeline::run(
        *plan, transport, EcRepairMode::HelperChain, control(), executor, &observation, EcRepairDelivery::HelperDirect));
    done = true;
  });
  SCOPE_EXIT {
    transport->releaseSecondDirect.post();
    runner.join();
  };
  ASSERT_TRUE(waitFor([&] { return transport->faults.load() != 0; }));
  EXPECT_FALSE(done.load());
  EXPECT_GE(transport->active.load(), 1);
  transport->releaseSecondDirect.post();
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  ASSERT_ERROR(*result, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(transport->directCalls.load(), 2);
  EXPECT_EQ(transport->seals.load(), 0);
  EXPECT_EQ(transport->appends.load(), 0);
  EXPECT_EQ(transport->active.load(), 0);
  const auto sample = observation.snapshot();
  EXPECT_EQ(sample.at(EcRepairPoint::BlockActor).peakActive, 2);
  for (const auto &point : sample.points) {
    EXPECT_EQ(point.active, 0);
    EXPECT_EQ(point.entered, point.finished);
  }
}

TEST(TestEcRepairPipeline, ObservationSaturatesAndKeepsIndependentCallsSeparate) {
  EcRepairObservation observation;
  {
    EcRepairObservation::Scope scope(&observation, EcRepairPoint::NativeAppend);
    scope.noteInvocation(std::numeric_limits<uint64_t>::max());
    scope.noteInvocation(7);
    scope.success();
  }
  const auto first = observation.snapshot();
  EXPECT_TRUE(first.overflow);
  EXPECT_EQ(first.at(EcRepairPoint::NativeAppend).submittedPayloadBytes, std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(first.at(EcRepairPoint::NativeAppend).apiInvocations, 2);
  EXPECT_EQ(first.at(EcRepairPoint::NativeAppend).active, 0);
  EcRepairObservation nextCall;
  const auto next = nextCall.snapshot();
  EXPECT_FALSE(next.overflow);
  for (const auto &point : next.points) EXPECT_EQ(point.entered, 0);
}

TEST(TestEcRepairPipeline, RpcObservationSeparatesHostClocksMissingErrorsAndOverflow) {
  using storage::client::EcRpcMethod;
  using storage::client::EcRpcObservation;
  static_assert(!std::is_copy_constructible_v<EcRepairObservation>);
  static_assert(!std::is_move_constructible_v<EcRepairObservation>);
  static_assert(!std::is_copy_constructible_v<EcRpcObservation>);
  static_assert(!std::is_move_constructible_v<EcRpcObservation>);
  serde::Timestamp ts;
  ts.clientCalled = 1000;
  ts.clientSerialized = 1010;
  ts.clientReceived = 1050;
  ts.clientWaked = 1060;
  // Deliberate cross-host offset: only each host's own sequence is relevant.
  ts.serverReceived = 900000;
  ts.serverWaked = 900005;
  ts.serverProcessed = 900015;
  ts.serverSerialized = 900020;
  EcRepairObservation phases;
  auto &observation = phases.selectedRepairRpc();
  {
    EcRpcObservation::Scope frame(&observation, EcRpcMethod::Read);
    EXPECT_EQ(observation.snapshot().at(EcRpcMethod::Read).active, 1);
    frame.messengerInvocation();
    frame.returned(false, ts);  // A decoded outer error can carry valid times.
  }
  auto sample = observation.snapshot();
  EXPECT_FALSE(sample.clockAnomaly);
  EXPECT_FALSE(sample.overflow);
  const auto &read = sample.at(EcRpcMethod::Read);
  EXPECT_EQ(read.entered, 1);
  EXPECT_EQ(read.finished, 1);
  EXPECT_EQ(read.active, 0);
  EXPECT_EQ(read.outerOk, 0);
  EXPECT_EQ(read.outerError, 1);
  EXPECT_EQ(read.messengerInvocations, 1);
  EXPECT_EQ(read.withoutMessenger, 0);
  EXPECT_EQ(read.client.valid, 1);
  EXPECT_EQ(read.server.valid, 1);
  EXPECT_EQ(read.client.spanNs, (std::array<uint64_t, 3>{10000, 40000, 10000}));
  EXPECT_EQ(read.server.spanNs, (std::array<uint64_t, 3>{5000, 10000, 5000}));

  {
    EcRpcObservation::Scope frame(&observation, EcRpcMethod::Append);
    // Exercise the SAME macro branch contract as callMessengerMethod. Release
    // builds disable injected errors, so their actual invocation must count.
    size_t calls = 0;
    const auto actual = [&] {
      frame.messengerInvocation();
      frame.callSizes()->request = {64, true, false};
      ++calls;
      return 7;
    };
    const auto result = FAULT_INJECTION_POINT(true, 5, actual());
#ifndef NDEBUG
    EXPECT_EQ(result, 5);
    EXPECT_EQ(calls, 0);
#else
    EXPECT_EQ(result, 7);
    EXPECT_EQ(calls, 1);
#endif
    frame.returned(false, serde::Timestamp{});  // Fault/no response is missing.
  }
  { EcRpcObservation::Scope localReject(&observation, EcRpcMethod::Append); }
  sample = observation.snapshot();
  const auto &append = sample.at(EcRpcMethod::Append);
  EXPECT_EQ(append.outerError, 1);
  EXPECT_EQ(append.withoutResult, 1);
  EXPECT_EQ(append.client.missing, 2);
  EXPECT_EQ(append.server.missing, 2);
  EXPECT_EQ(append.client.valid, 0);
  EXPECT_EQ(append.server.valid, 0);
  EXPECT_EQ(append.client.spanNs, (std::array<uint64_t, 3>{}));
#ifndef NDEBUG
  EXPECT_EQ(append.messengerInvocations, 0);
  EXPECT_EQ(append.withoutMessenger, 2);
  EXPECT_EQ(append.observedEncodedRequestFrames, 0);
  EXPECT_EQ(append.missingEncodedRequestFrames, 2);
#else
  EXPECT_EQ(append.messengerInvocations, 1);
  EXPECT_EQ(append.withoutMessenger, 1);
  EXPECT_EQ(append.observedEncodedRequestFrames, 1);
  EXPECT_EQ(append.requestFrameBytes, 64);
  EXPECT_EQ(append.missingEncodedRequestFrames, 1);
#endif
  EXPECT_EQ(append.observedEncodedResponseFrames, 0);
  EXPECT_EQ(append.missingEncodedResponseFrames, 2);

  using storage::client::EcRpcLimiter;
  Semaphore semaphore(1, 1);
  {
    EcRpcObservation::LimiterScope metric(&observation, EcRpcMethod::Read, EcRpcLimiter::PerServer);
    SemaphoreGuard permit(semaphore);  // Must be destroyed BEFORE metric.
    folly::coro::blockingWait(permit.coWait());
    metric.acquired();
    EXPECT_FALSE(semaphore.try_wait());
    const auto during = observation.snapshot().at(EcRpcMethod::Read).limiters[0];
    EXPECT_EQ(during.entered, 1);
    EXPECT_EQ(during.acquired, 1);
    EXPECT_EQ(during.active, 1);
    EXPECT_EQ(during.finished, 0);
  }
  ASSERT_TRUE(semaphore.try_wait());  // Real permit release, not just a counter.
  semaphore.signal();
  try {
    EcRpcObservation::LimiterScope metric(&observation, EcRpcMethod::Read, EcRpcLimiter::PerServer);
    SemaphoreGuard unacquired(semaphore);
    throw std::runtime_error("before acquire completed");
  } catch (const std::runtime_error &) {
  }
  const auto permit = observation.snapshot().at(EcRpcMethod::Read).limiters[0];
  EXPECT_EQ(permit.entered, 2);
  EXPECT_EQ(permit.acquired, 1);
  EXPECT_EQ(permit.finished, 2);
  EXPECT_EQ(permit.withoutPermit, 1);
  EXPECT_EQ(permit.active, 0);
  EXPECT_EQ(permit.peakActive, 1);
  {
    EcRpcObservation::LimiterScope disabled(nullptr, EcRpcMethod::Read, EcRpcLimiter::PerServer);
    disabled.acquired();
    EcRpcObservation::LimiterScope notApplicable(&observation, EcRpcMethod::Helper, EcRpcLimiter::PerServer);
    notApplicable.acquired();
  }
  EXPECT_EQ(observation.snapshot().at(EcRpcMethod::Helper).limiters[0].entered, 0);
  EXPECT_EQ(observation.snapshot().at(EcRpcMethod::Read).limiters[0].entered, 2);

  auto reversed = ts;
  reversed.clientSerialized = ts.clientCalled - 1;
  {
    EcRpcObservation::Scope frame(&observation, EcRpcMethod::Query);
    frame.returned(true, reversed);
  }
  sample = observation.snapshot();
  EXPECT_TRUE(sample.clockAnomaly);
  EXPECT_EQ(sample.at(EcRpcMethod::Query).client.reversed, 1);
  EXPECT_EQ(sample.at(EcRpcMethod::Query).client.valid, 0);
  EXPECT_EQ(sample.at(EcRpcMethod::Query).server.valid, 1);

  auto huge = ts;
  huge.serverSerialized = std::numeric_limits<int64_t>::max();
  {
    EcRpcObservation::Scope frame(&observation, EcRpcMethod::Seal);
    frame.returned(true, huge);
  }
  sample = observation.snapshot();
  EXPECT_TRUE(sample.overflow);
  EXPECT_EQ(sample.at(EcRpcMethod::Seal).server.outOfRange, 1);
  EXPECT_EQ(sample.at(EcRpcMethod::Seal).server.valid, 0);
  EXPECT_EQ(sample.at(EcRpcMethod::Seal).client.valid, 1);

  // Each duration is representable; only their aggregate saturates.
  EcRepairObservation summed;
  auto longSpan = ts;
  longSpan.clientCalled = 1;
  longSpan.clientSerialized = int64_t(1 + std::numeric_limits<uint64_t>::max() / 1000);
  longSpan.clientReceived = longSpan.clientSerialized;
  longSpan.clientWaked = longSpan.clientSerialized;
  for (auto *group : {&summed.selectedRepairRpc(), &summed.healthyCopyRpc()}) {
    EcRpcObservation::Scope frame(group, EcRpcMethod::Helper);
    frame.returned(true, longSpan);
  }
  const auto sum = summed.storageRpc().snapshot();
  EXPECT_TRUE(sum.overflow);
  EXPECT_FALSE(summed.selectedRepairRpc().snapshot().overflow);
  EXPECT_FALSE(summed.healthyCopyRpc().snapshot().overflow);
  EXPECT_EQ(sum.at(EcRpcMethod::Helper).client.valid, 2);
  EXPECT_EQ(sum.at(EcRpcMethod::Helper).client.outOfRange, 0);
  EXPECT_EQ(sum.at(EcRpcMethod::Helper).client.spanNs[0], std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(sum.at(EcRpcMethod::Helper).client.spanNs[1], 0);  // Valid equal timestamps.
  EXPECT_EQ(sum.at(EcRpcMethod::Helper).active, 0);
  // The same method belongs to two actual caller phases. It is not classified
  // by method name, and a returned error retains the selected-repair sample.
  {
    EcRpcObservation::Scope copy(&phases.healthyCopyRpc(), EcRpcMethod::Read);
    copy.messengerInvocation();
    copy.returned(true, ts);
  }
  const auto grouped = phases.snapshot();
  const auto &totalRead = grouped.storageRpc.at(EcRpcMethod::Read);
  EXPECT_EQ(totalRead.entered, 2);
  EXPECT_EQ(totalRead.finished, 2);
  EXPECT_EQ(totalRead.active, 0);
  EXPECT_EQ(totalRead.outerError, 1);
  EXPECT_EQ(totalRead.outerOk, 1);
  EXPECT_EQ(grouped.selectedRepairRpc.at(EcRpcMethod::Read).outerError, 1);
  EXPECT_EQ(grouped.healthyCopyRpc.at(EcRpcMethod::Read).outerError, 0);
  EXPECT_EQ(grouped.healthyCopyRpc.at(EcRpcMethod::Read).outerOk, 1);
  EXPECT_EQ(totalRead.client.spanNs, (std::array<uint64_t, 3>{20000, 80000, 20000}));
  EXPECT_EQ(totalRead.server.spanNs, (std::array<uint64_t, 3>{10000, 20000, 10000}));
  // Fault, missing result, bad clocks and permit exits above update both sinks
  // once. Healthy copy has not entered any of these method/limiter slots.
  const auto &totalAppend = grouped.storageRpc.at(EcRpcMethod::Append);
  EXPECT_EQ(totalAppend.outerError, append.outerError);
  EXPECT_EQ(totalAppend.withoutResult, append.withoutResult);
  EXPECT_EQ(totalAppend.withoutMessenger, append.withoutMessenger);
  EXPECT_EQ(totalAppend.missingEncodedRequestFrames, append.missingEncodedRequestFrames);
  EXPECT_EQ(totalAppend.client.missing, append.client.missing);
  EXPECT_TRUE(grouped.storageRpc.clockAnomaly);
  EXPECT_TRUE(grouped.storageRpc.overflow);
  EXPECT_FALSE(grouped.healthyCopyRpc.clockAnomaly);
  EXPECT_FALSE(grouped.healthyCopyRpc.overflow);
  const auto &totalPermit = totalRead.limiters[0];
  EXPECT_EQ(totalPermit.entered, permit.entered);
  EXPECT_EQ(totalPermit.finished, permit.finished);
  EXPECT_EQ(totalPermit.acquiredWaitNs, permit.acquiredWaitNs);
  EXPECT_EQ(totalPermit.unacquiredSpanNs, permit.unacquiredSpanNs);
  EXPECT_EQ(totalPermit.heldNs, permit.heldNs);

  EcRepairObservation peaks;
  // Each phase has a peak of two, but their non-overlapping peaks must not be
  // summed to four. Both sinks receive the identical per-event clock sample.
  for (auto *group : {&peaks.selectedRepairRpc(), &peaks.healthyCopyRpc()}) {
    EcRpcObservation::LimiterScope first(group, EcRpcMethod::Read, EcRpcLimiter::Global);
    EcRpcObservation::LimiterScope second(group, EcRpcMethod::Read, EcRpcLimiter::Global);
    first.acquired();
  }
  // Conversely, simultaneous scopes in distinct phases are counted together.
  {
    EcRpcObservation::LimiterScope repair(&peaks.selectedRepairRpc(), EcRpcMethod::Begin, EcRpcLimiter::Global);
    EcRpcObservation::LimiterScope copy(&peaks.healthyCopyRpc(), EcRpcMethod::Begin, EcRpcLimiter::Global);
    EXPECT_EQ(peaks.storageRpc().snapshot().at(EcRpcMethod::Begin).limiters[1].active, 2);
  }
  const auto peakSamples = peaks.snapshot();
  for (auto method : {EcRpcMethod::Read, EcRpcMethod::Begin}) {
    const auto &total = peakSamples.storageRpc.at(method).limiters[1];
    const auto &repair = peakSamples.selectedRepairRpc.at(method).limiters[1];
    const auto &copy = peakSamples.healthyCopyRpc.at(method).limiters[1];
    EXPECT_EQ(total.active, 0);
    EXPECT_EQ(total.peakActive, 2);
    EXPECT_EQ(repair.peakActive, method == EcRpcMethod::Read ? 2 : 1);
    EXPECT_EQ(copy.peakActive, method == EcRpcMethod::Read ? 2 : 1);
    EXPECT_EQ(total.entered, repair.entered + copy.entered);
    EXPECT_EQ(total.finished, repair.finished + copy.finished);
    EXPECT_EQ(total.acquiredWaitNs, repair.acquiredWaitNs + copy.acquiredWaitNs);
    EXPECT_EQ(total.unacquiredSpanNs, repair.unacquiredSpanNs + copy.unacquiredSpanNs);
    EXPECT_EQ(total.heldNs, repair.heldNs + copy.heldNs);
  }
  EcRpcObservation nextCall;
  for (const auto &method : nextCall.snapshot().methods) EXPECT_EQ(method.entered, 0);
}

TEST(TestEcRepairPipeline, RpcFrameObservationCountsMissingErrorsExceptionsAndSaturates) {
  using storage::client::EcRpcMethod;
  using storage::client::EcRpcObservation;
  EcRepairObservation phases;
  auto &observation = phases.selectedRepairRpc();
  {
    EcRpcObservation::Scope disabled(nullptr, EcRpcMethod::Read);
    EcRpcObservation::Scope invalid(&observation, EcRpcMethod::Count);
    EXPECT_EQ(disabled.callSizes(), nullptr);
    EXPECT_EQ(invalid.callSizes(), nullptr);
  }
  { EcRpcObservation::Scope localReject(&observation, EcRpcMethod::Read); }
  {
    EcRpcObservation::Scope requestOnly(&observation, EcRpcMethod::Read);
    requestOnly.messengerInvocation();
    requestOnly.callSizes()->request = {100, true, true};
    requestOnly.returned(false, {});
  }
  {
    EcRpcObservation::Scope errorResponse(&observation, EcRpcMethod::Read);
    errorResponse.messengerInvocation();
    *errorResponse.callSizes() = {{120, true, false}, {40, true, true}};
    errorResponse.returned(false, {});
    errorResponse.returned(false, {});  // Result observation is idempotent; sizes gather on exit only.
  }
  for (bool encoded : {false, true}) {
    try {
      EcRpcObservation::Scope failed(&observation, EcRpcMethod::Read);
      failed.messengerInvocation();
      if (encoded) failed.callSizes()->request = {130, true, false};
      throw std::runtime_error("joined call exception");
    } catch (const std::runtime_error &) {
    }
  }
  auto read = observation.snapshot().at(EcRpcMethod::Read);
  EXPECT_EQ(read.finished, 5);
  EXPECT_EQ(read.active, 0);
  EXPECT_EQ(read.outerError, 2);
  EXPECT_EQ(read.withoutResult, 3);
  EXPECT_EQ(read.messengerInvocations, 4);
  EXPECT_EQ(read.withoutMessenger, 1);
  EXPECT_EQ(read.observedEncodedRequestFrames, 3);
  EXPECT_EQ(read.missingEncodedRequestFrames, 2);
  EXPECT_EQ(read.requestFrameBytes, 350);
  EXPECT_EQ(read.compressedRequestFrames, 1);
  EXPECT_EQ(read.observedEncodedResponseFrames, 1);
  EXPECT_EQ(read.missingEncodedResponseFrames, 4);
  EXPECT_EQ(read.responseFrameBytes, 40);
  EXPECT_EQ(read.compressedResponseFrames, 1);
  {
    EcRpcObservation::Scope copy(&phases.healthyCopyRpc(), EcRpcMethod::Read);
    copy.messengerInvocation();
    *copy.callSizes() = {{77, true, true}, {88, true, false}};
    copy.returned(true, {});
  }
  const auto grouped = phases.snapshot();
  const auto &total = grouped.storageRpc.at(EcRpcMethod::Read);
  const auto &copy = grouped.healthyCopyRpc.at(EcRpcMethod::Read);
  EXPECT_EQ(copy.entered, 1);
  EXPECT_EQ(copy.outerOk, 1);
  EXPECT_EQ(copy.withoutResult, 0);
  EXPECT_EQ(copy.requestFrameBytes, 77);
  EXPECT_EQ(copy.responseFrameBytes, 88);
  EXPECT_EQ(total.entered, 6);
  EXPECT_EQ(total.finished, 6);
  EXPECT_EQ(total.active, 0);
  EXPECT_EQ(total.outerError, 2);
  EXPECT_EQ(total.outerOk, 1);
  EXPECT_EQ(total.withoutResult, 3);
  EXPECT_EQ(total.messengerInvocations, 5);
  EXPECT_EQ(total.withoutMessenger, 1);
  EXPECT_EQ(total.observedEncodedRequestFrames, 4);
  EXPECT_EQ(total.observedEncodedResponseFrames, 2);
  EXPECT_EQ(total.missingEncodedRequestFrames, 2);
  EXPECT_EQ(total.missingEncodedResponseFrames, 4);
  EXPECT_EQ(total.requestFrameBytes, 427);
  EXPECT_EQ(total.responseFrameBytes, 128);
  EXPECT_EQ(total.compressedRequestFrames, 2);
  EXPECT_EQ(total.compressedResponseFrames, 1);
  for (auto bytes : {std::numeric_limits<uint64_t>::max(), uint64_t{1}}) {
    EcRpcObservation::Scope frame(&observation, EcRpcMethod::Helper);
    *frame.callSizes() = {{bytes, true, false}, {bytes, true, false}};
  }
  const auto saturated = observation.snapshot();
  EXPECT_TRUE(saturated.overflow);
  EXPECT_EQ(saturated.at(EcRpcMethod::Helper).requestFrameBytes, std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(saturated.at(EcRpcMethod::Helper).responseFrameBytes, std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(saturated.at(EcRpcMethod::Helper).observedEncodedRequestFrames, 2);
  EXPECT_EQ(saturated.at(EcRpcMethod::Helper).observedEncodedResponseFrames, 2);
  EXPECT_TRUE(phases.storageRpc().snapshot().overflow);
  EXPECT_FALSE(phases.healthyCopyRpc().snapshot().overflow);
  EXPECT_EQ(phases.storageRpc().snapshot().at(EcRpcMethod::Helper).requestFrameBytes,
            std::numeric_limits<uint64_t>::max());
  // Neither phase overflows, but their combined frame-byte total does.
  EcRepairObservation combined;
  {
    EcRpcObservation::Scope repair(&combined.selectedRepairRpc(), EcRpcMethod::Append);
    repair.callSizes()->request = {std::numeric_limits<uint64_t>::max() - 3, true, false};
  }
  {
    EcRpcObservation::Scope healthy(&combined.healthyCopyRpc(), EcRpcMethod::Append);
    healthy.callSizes()->request = {4, true, false};
  }
  const auto combinedSample = combined.snapshot();
  EXPECT_FALSE(combinedSample.selectedRepairRpc.overflow);
  EXPECT_FALSE(combinedSample.healthyCopyRpc.overflow);
  EXPECT_TRUE(combinedSample.storageRpc.overflow);
  EXPECT_EQ(combinedSample.storageRpc.at(EcRpcMethod::Append).requestFrameBytes,
            std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(combinedSample.storageRpc.at(EcRpcMethod::Append).observedEncodedRequestFrames, 2);
}

}  // namespace
}  // namespace hf3fs::client::ec
