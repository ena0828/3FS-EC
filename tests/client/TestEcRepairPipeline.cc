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

#include "client/ec/EcRepairPipeline.h"
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
  enum class FaultAt { None, Begin, Read, Append, Seal };
  enum class FaultKind { BadAlloc, Standard, Status, NonStandard };
  repair_test::Data data;
  std::atomic<size_t> begun{0}, reads{0}, helperCalls{0}, seals{0}, active{0}, appends{0}, faults{0};
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
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor));
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
      auto result = folly::coro::blockingWait(EcRepairPipeline::run(*plan, transport, mode, control(), executor));
      ASSERT_OK(result);
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
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor));
    done = true;
  });
  SCOPE_EXIT {
    transport->holdFirstAppend = false;
    runner.join();
  };
  ASSERT_TRUE(waitFor([&] { return transport->firstAppendEntered && (transport->startedBlocks.load() & 2); }));
  EXPECT_FALSE(done);
  EXPECT_EQ(transport->startedBlocks.load(), 3);  // Block 2 has no window slot yet.
  transport->holdFirstAppend = false;
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  ASSERT_OK(*result);
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
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, options, executor));
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
  transport->holdFirstAppend = false;
  ASSERT_TRUE(waitFor([&] { return done.load(); }));
  ASSERT_TRUE(result.has_value());
  ASSERT_FALSE(result->hasValue());
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
  std::optional<Result<EcRepairSealed>> result;
  std::atomic<bool> done{false};
  std::thread runner([&] {
    result = folly::coro::blockingWait(
        EcRepairPipeline::run(*plan, transport, EcRepairMode::ClientPipeline, control(), executor));
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

}  // namespace
}  // namespace hf3fs::client::ec
