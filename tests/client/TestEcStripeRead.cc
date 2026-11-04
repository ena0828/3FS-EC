#include <atomic>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Sleep.h>
#include <gtest/gtest.h>
#include <thread>

#include "client/ec/EcStripeRead.h"

namespace hf3fs::client::ec::test {
namespace {
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// A controlled, owned transport; these tests do not claim RPC authentication
// or native-service coverage. In-flight cancellation models TCP: a dispatched
// response remains alive until its gate opens or its finite deadline expires.
class GatedTransport final : public EcReadTransport {
 public:
  std::atomic<uint16_t> blocked{0};
  std::atomic<uint16_t> failed{0};
  std::atomic<uint16_t> corrupt{0};
  std::atomic<size_t> started{0};
  std::atomic<size_t> active{0};
  size_t releaseAfter = 11;

  static std::string bytes(uint16_t shard) { return std::string(128, char('a' + shard)); }

  CoTryTask<storage::EcReadResult> read(storage::EcAuthorizedReadReq wire, EcReadControl control) override {
    ++active;
    SCOPE_EXIT { --active; };
    ++started;
    const auto &request = wire.request;
    const uint16_t bit = uint16_t(1u << request.identity.shard);
    while (started.load() < releaseAfter || (blocked.load() & bit)) {
      if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
      co_await folly::coro::sleep(1ms);
    }
    if (failed.load() & bit) co_return makeError(StorageClientCode::kCommError);
    storage::EcReadResult result;
    result.receipt.identity = request.identity;
    result.receipt.vChainId = request.vChainId;
    result.receipt.targetId = request.targetId;
    result.receipt.operationId = request.operationId;
    result.receipt.length = request.expectedLength;
    result.receipt.checksum = request.checksum;
    result.payload.data = bytes(request.identity.shard);
    if (corrupt.load() & bit) result.payload.data[0] ^= 1;
    co_return result;
  }
};

EcStripeReadInput input() {
  EcStripeReadInput result;
  auto &manifest = result.manifest;
  manifest.object.inode = meta::InodeId(12345);
  manifest.object.incarnation = Uuid::random();
  manifest.stripe = 3;
  manifest.generation = 7;
  manifest.revision = 9;
  manifest.logicalLength = 1280;
  for (size_t index = 0; index != 12; ++index) {
    auto &fragment = manifest.fragments[index];
    fragment.identity.object = manifest.object.incarnation;
    fragment.identity.stripe = manifest.stripe;
    fragment.identity.generation = manifest.generation;
    fragment.identity.shard = uint16_t(index);
    fragment.identity.allocation = Uuid::random();
    fragment.operation = Uuid::random();
    fragment.placement.chain = storage::ChainId(100 + index);
    fragment.placement.target = storage::TargetId(200 + index);
    fragment.placement.node = flat::NodeId(300 + index);
    auto descriptor = storage::computeEcIntegrity(fragment.identity, GatedTransport::bytes(uint16_t(index)));
    EXPECT_TRUE(descriptor);
    fragment.integrity = *descriptor;
    auto &request = result.requests[index].request;
    request.identity = fragment.identity;
    request.operationId = fragment.operation;
    request.vChainId = {fragment.placement.chain, storage::ChainVer(1)};
    request.targetId = fragment.placement.target;
    request.expectedLength = 128;
    request.checksum.type = storage::ChecksumType::CRC32C;
    request.checksum.value = ~fragment.integrity.wholeCrc32c;
  }
  return result;
}

EcStripeReadOptions options(std::chrono::milliseconds timeout = 2s) {
  EcStripeReadOptions value;
  value.deadline = Clock::now() + timeout;
  value.hedgeAfter = 500ms;
  return value;
}

bool waitStarted(const GatedTransport &transport, size_t count) {
  const auto deadline = Clock::now() + 1s;
  while (transport.started.load() < count && Clock::now() < deadline) std::this_thread::sleep_for(1ms);
  return transport.started.load() >= count;
}

TEST(TestEcStripeRead, TenValidReturnWhileEleventhOwnsItsBuffers) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  transport->blocked = 1u << 10;
  EcStripeRead reader(transport, executor, {});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  auto started = reader.start(input(), options());
  ASSERT_TRUE(started);
  auto handle = std::move(*started);
  {
    auto result = folly::coro::blockingWait(handle.takeReady());
    ASSERT_TRUE(result);
    EXPECT_EQ(result->attempted, 11);
    EXPECT_EQ(result->rejected, 0);
    EXPECT_TRUE(handle.ready());
    EXPECT_FALSE(handle.localCleanupComplete());
    EXPECT_EQ(transport->active.load(), 1);
    EXPECT_EQ(reader.snapshot().activeOperations, 1);
    EXPECT_EQ(reader.snapshot().activeRequests, 1);
    for (const auto &shard : result->shards) {
      EXPECT_LT(shard.index, 10);
      EXPECT_EQ(shard.result.payload.data, GatedTransport::bytes(shard.index));
    }
    transport->blocked = 0;
    folly::coro::blockingWait(handle.waitLocalCleanup());
    EXPECT_TRUE(handle.localCleanupComplete());
    EXPECT_EQ(reader.snapshot().activeOperations, 0);
    EXPECT_EQ(reader.snapshot().activeRequests, 0);
    EXPECT_GT(reader.snapshot().reservedPayloadBytes, 0);  // Output still owns bytes.
  }
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

TEST(TestEcStripeRead, InvalidFastResponseStartsTwelfthAndNeverCountsAsValid) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  transport->blocked = 1u << 10;
  transport->corrupt = 1u << 0;
  EcStripeRead reader(transport, executor, {});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  auto started = reader.start(input(), options());
  ASSERT_TRUE(started);
  auto handle = std::move(*started);
  auto result = folly::coro::blockingWait(handle.takeReady());
  ASSERT_TRUE(result);
  EXPECT_EQ(result->attempted, 12);
  EXPECT_EQ(result->rejected, 1);
  bool sawTwelfth = false;
  for (const auto &shard : result->shards) {
    EXPECT_NE(shard.index, 0);
    EXPECT_NE(shard.index, 10);
    sawTwelfth |= shard.index == 11;
  }
  EXPECT_TRUE(sawTwelfth);
  EXPECT_FALSE(handle.localCleanupComplete());
  transport->blocked = 0;
  folly::coro::blockingWait(handle.waitLocalCleanup());
}

TEST(TestEcStripeRead, DeadlineRetainsAttemptsUntilTheirFiniteCompletion) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  transport->blocked = 0xfff;
  EcStripeRead reader(transport, executor, {});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  auto config = options(100ms);
  config.hedgeAfter = 10ms;
  auto started = reader.start(input(), config);
  ASSERT_TRUE(started);
  auto handle = std::move(*started);
  auto result = folly::coro::blockingWait(handle.takeReady());
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageClientCode::kTimeout);
  folly::coro::blockingWait(handle.waitLocalCleanup());
  EXPECT_EQ(transport->active.load(), 0);
  EXPECT_EQ(reader.snapshot().activeRequests, 0);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

TEST(TestEcStripeRead, CancelDoesNotDropAlreadyDispatchedRequestFrames) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  transport->blocked = 0xfff;
  EcStripeRead reader(transport, executor, {});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  auto started = reader.start(input(), options());
  ASSERT_TRUE(started);
  auto handle = std::move(*started);
  ASSERT_TRUE(waitStarted(*transport, 11));
  handle.cancel();
  auto result = folly::coro::blockingWait(handle.takeReady());
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageClientCode::kRequestCanceled);
  EXPECT_FALSE(handle.localCleanupComplete());
  EXPECT_EQ(transport->active.load(), 11);
  transport->blocked = 0;
  folly::coro::blockingWait(handle.waitLocalCleanup());
  EXPECT_EQ(reader.snapshot().activeRequests, 0);
}

TEST(TestEcStripeRead, DroppedHandleAndCloseJoinManagerOwnedAttempts) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  transport->blocked = 0xfff;
  EcStripeRead reader(transport, executor, {});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  {
    auto started = reader.start(input(), options(150ms));
    ASSERT_TRUE(started);
    ASSERT_TRUE(waitStarted(*transport, 11));
  }
  EXPECT_GT(reader.snapshot().activeOperations, 0);
  folly::coro::blockingWait(reader.close());
  EXPECT_EQ(reader.snapshot().activeRequests, 0);
  EXPECT_EQ(reader.snapshot().activeOperations, 0);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
  auto rejected = reader.start(input(), options());
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error().code(), StorageClientCode::kResourceBusy);
}

TEST(TestEcStripeRead, RejectsMixedManifestAndAdmissionBudgetBeforeDispatch) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<GatedTransport>();
  EcStripeRead reader(transport, executor, {1, 1, 60s});
  SCOPE_EXIT { folly::coro::blockingWait(reader.close()); };
  auto mixed = input();
  ++mixed.requests[0].request.identity.generation;
  auto invalid = reader.start(std::move(mixed), options());
  ASSERT_FALSE(invalid);
  EXPECT_EQ(invalid.error().code(), StatusCode::kInvalidArg);
  auto exhausted = reader.start(input(), options());
  ASSERT_FALSE(exhausted);
  EXPECT_EQ(exhausted.error().code(), StorageClientCode::kResourceBusy);
  EXPECT_EQ(transport->started.load(), 0);
}

}  // namespace
}  // namespace hf3fs::client::ec::test
