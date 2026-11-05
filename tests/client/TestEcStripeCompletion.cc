#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Collect.h>
#include <future>
#include <gtest/gtest.h>
#include <thread>

#include "client/ec/detail/EcStripeClientCore.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec::test {
namespace {
using Core = detail::EcStripeClientCore;
using folly::coro::blockingWait;
using namespace std::chrono_literals;

struct CompletionFault {};

CoTask<void> failingActor(folly::coro::Baton &lateStarted, std::promise<void> &throwing, bool allocationFailure) {
  co_await lateStarted;
  throwing.set_value();
  if (allocationFailure) throw std::bad_alloc();
  throw CompletionFault{};
}
CoTask<void> lateActor(folly::coro::Baton &lateStarted,
                       folly::coro::Baton &release,
                       std::shared_ptr<int> owned,
                       std::atomic<bool> &finished) {
  lateStarted.post();
  co_await release;
  finished.store(*owned == 17);
}
CoTask<EcStripeMutationOutcome> joinedActors(folly::coro::Baton &lateStarted,
                                             folly::coro::Baton &release,
                                             std::promise<void> &throwing,
                                             std::shared_ptr<int> owned,
                                             std::atomic<bool> &finished,
                                             bool allocationFailure) {
  std::vector<CoTask<void>> children;
  children.push_back(failingActor(lateStarted, throwing, allocationFailure));
  children.push_back(lateActor(lateStarted, release, std::move(owned), finished));
  co_await folly::coro::collectAllWindowed(std::move(children), 2);
  co_return EcStripeMutationOutcome{};
}

TEST(TestEcStripeCompletion, TaskExceptionWaitsForStartedChildAndPublishesFixedIdentity) {
  for (const bool allocationFailure : {false, true}) {
    SCOPED_TRACE(allocationFailure);
    folly::CPUThreadPoolExecutor pool(2);
    EcStripeClient::Limits limits;
    limits.maxApplicationBytes = 100;
    auto core = std::make_shared<Core>(nullptr, nullptr, nullptr, flat::UserInfo{}, Uuid::random(), pool, limits);
    folly::coro::Baton lateStarted, release;
    std::promise<void> throwing;
    auto thrown = throwing.get_future();
    std::atomic<bool> finished{false};
    auto owned = std::make_shared<int>(17);
    std::weak_ptr<int> weak = owned;
    const meta::EcObjectRef object{meta::InodeId(91821), Uuid::random()};
    const auto operation = Uuid::random();
    auto call = core->launch<EcStripeMutationOutcome>(
        100,
        [&, owned = std::move(owned)](const auto &) {
          return joinedActors(lateStarted, release, throwing, owned, finished, allocationFailure);
        },
        [object, operation](Status error) {
          EcStripeMutationOutcome result;
          result.object = object;
          result.operation = operation;
          result.phase = EcStripePhase::Indeterminate;
          result.failure = std::move(error);
          return result;
        });
    SCOPE_EXIT {
      release.post();
      blockingWait(Core::close(core));
    };
    ASSERT_OK(call);
    ASSERT_EQ(thrown.wait_for(5s), std::future_status::ready);
    EXPECT_FALSE((*call)->ready.ready());
    EXPECT_FALSE(finished.load());
    EXPECT_FALSE(weak.expired());
    EXPECT_EQ(core->budget->bytes.load(), 100);
    release.post();
    blockingWait(Core::close(core));
    ASSERT_TRUE((*call)->ready.ready());
    auto outcome = blockingWait(Core::take(*call));
    EXPECT_EQ(outcome.object, object);
    EXPECT_EQ(outcome.operation, operation);
    EXPECT_EQ(outcome.phase, EcStripePhase::Indeterminate);
    ASSERT_TRUE(outcome.failure);
    EXPECT_EQ(outcome.failure->code(), allocationFailure ? StatusCode::kNotEnoughMemory : StatusCode::kUnknown);
    EXPECT_TRUE(finished.load());
    EXPECT_TRUE(weak.expired());
    EXPECT_EQ(core->activeOperations, 0);
    EXPECT_EQ(core->budget->bytes.load(), 0);
  }
}

class ThrowingAcquire final : public meta::DummyMetaServiceStub {
 public:
  explicit ThrowingAcquire(bool allocationFailure)
      : allocationFailure_(allocationFailure) {}
  CoTryTask<meta::AcquireEcReadV2Rsp> acquireEcReadV2(const meta::AcquireEcReadV2Req &) override {
    if (allocationFailure_) throw std::bad_alloc();
    throw CompletionFault{};
    co_return makeError(StatusCode::kUnknown);
  }

 private:
  bool allocationFailure_;
};

TEST(TestEcStripeCompletion, AcquireExceptionCompletesReadReadyAndCleanup) {
  // This injects at the Meta stub boundary and executes the actual MetaClient
  // and readOwned completion path. It is not an authentication or TCP test.
  for (const bool allocationFailure : {false, true}) {
    SCOPED_TRACE(allocationFailure);
    folly::CPUThreadPoolExecutor pool(2);
    auto routing = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
    meta::client::MetaClient::Config metaConfig;
    auto holder = std::make_shared<meta::MockMetaStubHolder>();
    holder->setStub(std::make_unique<ThrowingAcquire>(allocationFailure));
    meta::client::MetaClient::StubFactory::MockContext context{holder};
    const ClientId namespaceId = ClientId::random();
    auto metadata =
        std::make_shared<meta::client::MetaClient>(namespaceId,
                                                   metaConfig,
                                                   std::make_unique<meta::client::MetaClient::StubFactory>(context),
                                                   routing,
                                                   nullptr,
                                                   false);
    EcStripeClient::Limits limits;
    limits.maxApplicationBytes = 64u << 20;
    auto core = std::make_shared<Core>(metadata, nullptr, routing, flat::UserInfo{}, namespaceId.uuid, pool, limits);
    SCOPE_EXIT { blockingWait(Core::close(core)); };
    EcStripePinIds pin;
    pin.object = {meta::InodeId(91822), Uuid::random()};
    pin.pin = Uuid::random();
    pin.acquireRequest = Uuid::random();
    pin.releaseRequest = Uuid::random();
    auto session = core->startRead(pin, {std::chrono::steady_clock::now() + 5s, {}});
    ASSERT_OK(session);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while ((!session->ready() || !session->localCleanupComplete()) && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(1ms);
    ASSERT_TRUE(session->ready());
    ASSERT_TRUE(session->localCleanupComplete());
    auto result = blockingWait(session->takeReady());
    ASSERT_ERROR(result, allocationFailure ? StatusCode::kNotEnoughMemory : StatusCode::kIOError);
    EXPECT_EQ(session->pin().object, pin.object);
    EXPECT_EQ(session->pin().pin, pin.pin);
    blockingWait(session->waitLocalCleanup());
    blockingWait(Core::close(core));
    EXPECT_EQ(core->activeOperations, 0);
    EXPECT_EQ(core->budget->bytes.load(), 0);
  }
}

}  // namespace
}  // namespace hf3fs::client::ec::test
