#include <atomic>
#include <barrier>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/Sleep.h>
#include <gtest/gtest.h>
#include <optional>
#include <thread>

#include "client/ec/EcBlockRead.h"

namespace hf3fs::client::ec::test {
namespace {
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
using folly::coro::blockingWait;

// Owned, controlled responses, not an authentication or TCP substitute. These
// descriptors/grant claims are trusted test inputs; the native fixture signs
// actual grants and traverses StorageSerde separately.
class BlockTransport final : public EcBlockReadTransport {
 public:
  enum class Corruption { None, Bytes, Instance, Operation, Block, Length, Root };
  std::atomic<uint16_t> blocked{1u << 10};
  Corruption corruptFirst = Corruption::None;
  std::atomic<size_t> started{0}, active{0};
  static std::string bytes(uint16_t shard, size_t length) { return std::string(length, char('a' + shard)); }
  CoTryTask<storage::EcReadBlockResultV2> read(storage::EcReadBlockV2Req wire, EcReadControl control) override {
    ++active;
    SCOPE_EXIT { --active; };
    ++started;
    const auto &request = wire.request;
    const auto shard = request.identity.shard;
    while (started.load() < 11 || (blocked.load() & (1u << shard))) {
      if (Clock::now() >= control.deadline) co_return makeError(StorageClientCode::kTimeout);
      co_await folly::coro::sleep(1ms);
    }
    storage::EcReadBlockResultV2 result;
    result.receipt.identity = request.identity;
    result.receipt.operationId = request.operationId;
    result.receipt.engineUuid = wire.grant.claims.engineUuid;
    result.receipt.targetIncarnation = wire.grant.claims.targetIncarnation;
    result.receipt.vChainId = request.vChainId;
    result.receipt.targetId = request.targetId;
    result.receipt.length = request.integrity.wholeLength;
    result.receipt.crc32c = request.integrity.wholeCrc32c;
    result.receipt.integrityRoot = request.integrity.root;
    result.blockIndex = wire.blockIndex;
    result.payload.data = bytes(shard, request.integrity.blocks[wire.blockIndex].validLength);
    if (shard == 0) {
      switch (corruptFirst) {
        case Corruption::None:
          break;
        case Corruption::Bytes:
          result.payload.data[0] ^= 1;
          break;
        case Corruption::Instance:
          result.receipt.engineUuid = Uuid::random();
          break;
        case Corruption::Operation:
          result.receipt.operationId = Uuid::random();
          break;
        case Corruption::Block:
          ++result.blockIndex;
          break;
        case Corruption::Length:
          result.payload.data.push_back('x');
          break;
        case Corruption::Root:
          result.receipt.integrityRoot[0] ^= 1;
          break;
      }
    }
    co_return result;
  }
};

EcBlockReadInput input(uint32_t length = 128, uint32_t block = 0) {
  meta::EcV2PinnedRead pinned;
  auto &manifest = pinned.manifest;
  manifest.object.inode = meta::InodeId(12345);
  manifest.object.incarnation = Uuid::random();
  manifest.stripe = 3;
  manifest.generation = 7;
  manifest.revision = 9;
  manifest.logicalLength = uint64_t(length) * 10;
  auto &snapshot = pinned.snapshot;
  snapshot.object = manifest.object;
  snapshot.pin = Uuid::random();
  snapshot.stripe = manifest.stripe;
  snapshot.generation = manifest.generation;
  snapshot.revision = manifest.revision;
  snapshot.owner = {flat::Uid(1000), Uuid::random()};
  std::array<storage::EcCapabilityV2, 12> grants;
  std::array<storage::VersionedChainId, 12> routes;
  std::array<storage::EcScopeEndpoint, 12> endpoints;
  for (size_t i = 0; i != 12; ++i) {
    auto &fragment = manifest.fragments[i];
    fragment.identity.object = manifest.object.incarnation;
    fragment.identity.stripe = manifest.stripe;
    fragment.identity.generation = manifest.generation;
    fragment.identity.shard = uint16_t(i);
    fragment.identity.allocation = Uuid::random();
    fragment.operation = Uuid::random();
    fragment.placement = {storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(300 + i)};
    auto descriptor = storage::computeEcIntegrity(fragment.identity, BlockTransport::bytes(uint16_t(i), length));
    EXPECT_TRUE(descriptor);
    fragment.integrity = *descriptor;
    auto &mapping = snapshot.endpoints[i];
    mapping.identity = fragment.identity;
    mapping.operation = fragment.operation;
    mapping.endpoint = {fragment.placement, Uuid::random(), Uuid::random()};
    endpoints[i] = mapping.endpoint.controlEndpoint();
    routes[i] = {fragment.placement.chain, storage::ChainVer(1)};
    auto &claims = grants[i].claims;
    claims.identity = fragment.identity;
    claims.fragmentOperationId = fragment.operation;
    claims.engineUuid = endpoints[i].engineUuid;
    claims.targetIncarnation = endpoints[i].targetIncarnation;
    claims.chainId = endpoints[i].chainId;
    claims.targetId = endpoints[i].targetId;
    claims.nodeId = endpoints[i].nodeId;
    claims.expectedLength = length;
    claims.expectedCrc32c = fragment.integrity.wholeCrc32c;
    claims.integrityDigest = *storage::digestEcIntegrityV2(fragment.identity, fragment.integrity);
    claims.ownerUid = snapshot.owner.uid;
    claims.clientNamespace = snapshot.owner.client;
    claims.scopeObject = manifest.object.incarnation;
    claims.scopeKind = storage::EcGrantScope::ReadPin;
    claims.scopeId = snapshot.pin;
    claims.grantId = Uuid::random();
    claims.rights = uint16_t(storage::EcGrantRightV2::ReadBlock);
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = 1100;
  }
  snapshot.endpointSetDigest = *storage::computeEcScopeEndpointDigest(endpoints);
  auto result = makeEcBlockReadInput(std::move(pinned), grants, routes, block);
  EXPECT_TRUE(result);
  return std::move(*result);
}
EcStripeReadOptions options(std::chrono::milliseconds timeout = 3s) {
  EcStripeReadOptions value;
  value.deadline = Clock::now() + timeout;
  value.hedgeAfter = 500ms;
  return value;
}
bool waitStarted(const BlockTransport &transport, size_t count) {
  const auto limit = Clock::now() + 1s;
  while (transport.started.load() < count && Clock::now() < limit) std::this_thread::sleep_for(1ms);
  return transport.started.load() >= count;
}

TEST(TestEcBlockRead, OutputAndLateCleanupOwnSeparateContinuousCharges) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<BlockTransport>();
  EcBlockRead reader(transport, executor, {});
  SCOPE_EXIT {
    transport->blocked = 0;
    blockingWait(reader.close());
  };
  auto started = reader.start(input(), options());
  ASSERT_TRUE(started);
  auto handle = std::move(*started);
  {
    auto result = blockingWait(handle.takeReady());
    ASSERT_TRUE(result);
    EXPECT_EQ(result->attempted, 11);
    EXPECT_FALSE(handle.localCleanupComplete());
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 128);
    EXPECT_EQ(reader.snapshot().activeRequests, 1);
    for (const auto &block : result->shards)
      EXPECT_EQ(block.result.payload.data, BlockTransport::bytes(block.index, 128));
  }
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 2 * 128);
  transport->blocked = 0;
  blockingWait(handle.waitLocalCleanup());
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

TEST(TestEcBlockRead, CleanupFirstRetainsOnlyTenOutputBlocksIncludingShortTail) {
  folly::CPUThreadPoolExecutor executor(2);
  for (const auto [length, block, expected] : {std::array<uint32_t, 3>{65536, 0, 65536}, {65543, 1, 7}}) {
    auto transport = std::make_shared<BlockTransport>();
    EcBlockRead reader(transport, executor, {});
    SCOPE_EXIT {
      transport->blocked = 0;
      blockingWait(reader.close());
    };
    auto started = reader.start(input(length, block), options());
    ASSERT_TRUE(started);
    {
      auto result = blockingWait(started->takeReady());
      ASSERT_TRUE(result);
      EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * expected);
      transport->blocked = 0;
      blockingWait(started->waitLocalCleanup());
      EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 10 * expected);
      for (const auto &shard : result->shards) EXPECT_EQ(shard.result.payload.data.size(), expected);
      EcBlockSelection replacement;
      replacement = std::move(*result);
      EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 10 * expected);
    }
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
  }
}

TEST(TestEcBlockRead, ConcurrentAdmissionCannotPassThroughLeaseSplitOrDoubleRelease) {
  folly::CPUThreadPoolExecutor executor(4);
  auto transport = std::make_shared<BlockTransport>();
  EcBlockRead reader(transport, executor, {3, 14 * 128, 60s});
  SCOPE_EXIT {
    transport->blocked = 0;
    blockingWait(reader.close());
  };
  auto fixed = input();
  auto started = reader.start(fixed, options());
  ASSERT_TRUE(started);
  {
    auto output = blockingWait(started->takeReady());
    ASSERT_TRUE(output);
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 128);
    EXPECT_FALSE(reader.start(fixed, options()));  // Output plus in-flight loser still occupy twelve.
  }
  ASSERT_EQ(reader.snapshot().reservedPayloadBytes, 2 * 128);
  transport->blocked = 0xfff;
  std::barrier go(3);
  std::array<std::optional<Result<EcBlockReadHandle>>, 2> races;
  auto compete = [&](size_t index) {
    go.arrive_and_wait();
    races[index].emplace(reader.start(fixed, options()));
  };
  std::thread first(compete, 0), second(compete, 1);
  go.arrive_and_wait();
  first.join();
  second.join();
  const unsigned accepted = unsigned(bool(*races[0])) + unsigned(bool(*races[1]));
  ASSERT_EQ(accepted, 1);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 14 * 128);
  for (auto &race : races) {
    if (!*race) EXPECT_EQ(race->error().code(), StorageClientCode::kResourceBusy);
  }
  // Closing joins the still-owned attempts; no result/pin is released by a
  // transport cancellation alone. Destruction after join must not double-free.
  transport->blocked = 0;
  blockingWait(reader.close());
  races = {};
  started = makeError(StatusCode::kUnknown);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
  EXPECT_EQ(reader.snapshot().activeRequests, 0);
}

TEST(TestEcBlockRead, EveryInvalidResponseIsExcludedBeforeQuorum) {
  folly::CPUThreadPoolExecutor executor(2);
  for (const auto corruption : {BlockTransport::Corruption::Bytes,
                                BlockTransport::Corruption::Instance,
                                BlockTransport::Corruption::Operation,
                                BlockTransport::Corruption::Block,
                                BlockTransport::Corruption::Length,
                                BlockTransport::Corruption::Root}) {
    auto transport = std::make_shared<BlockTransport>();
    transport->corruptFirst = corruption;
    EcBlockRead reader(transport, executor, {});
    SCOPE_EXIT {
      transport->blocked = 0;
      blockingWait(reader.close());
    };
    auto started = reader.start(input(), options());
    ASSERT_TRUE(started);
    auto result = blockingWait(started->takeReady());
    ASSERT_TRUE(result);
    EXPECT_EQ(result->attempted, 12);
    EXPECT_EQ(result->rejected, 1);
    bool twelfth = false;
    for (const auto &block : result->shards) {
      EXPECT_NE(block.index, 0);
      EXPECT_NE(block.index, 10);
      twelfth |= block.index == 11;
    }
    EXPECT_TRUE(twelfth);
  }
}

TEST(TestEcBlockRead, RejectsChangedScopeInstanceDescriptorAndRangeBeforeDispatch) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<BlockTransport>();
  EcBlockRead reader(transport, executor, {});
  SCOPE_EXIT { blockingWait(reader.close()); };
  auto fixed = input();
  for (size_t kind = 0; kind != 7; ++kind) {
    auto changed = fixed;
    switch (kind) {
      case 0:
        changed.pinned.snapshot.endpoints[0].endpoint.engineUuid = Uuid::random();
        break;
      case 1:
        changed.pinned.snapshot.endpointSetDigest[0] ^= 1;
        break;
      case 2:
        changed.requests[0].grant.claims.scopeId = Uuid::random();
        break;
      case 3:
        changed.requests[0].request.integrity.root[0] ^= 1;
        break;
      case 4:
        ++changed.blockIndex;
        break;
      case 5:
        changed.requests[0].request.operationId = Uuid::random();
        break;
      case 6:
        changed.requests[0].grant.claims.rights = uint16_t(storage::EcGrantRightV2::Append);
        break;
    }
    EXPECT_FALSE(reader.start(std::move(changed), options()));
  }
  EXPECT_EQ(transport->started.load(), 0);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

TEST(TestEcBlockRead, CancelAndAbandonedOutputKeepRequestsUntilLocalJoin) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<BlockTransport>();
  transport->blocked = 0xfff;
  EcBlockRead reader(transport, executor, {});
  SCOPE_EXIT {
    transport->blocked = 0;
    blockingWait(reader.close());
  };
  {
    auto started = reader.start(input(), options());
    ASSERT_TRUE(started);
    ASSERT_TRUE(waitStarted(*transport, 11));
    started->cancel();
    auto result = blockingWait(started->takeReady());
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), StorageClientCode::kRequestCanceled);
    EXPECT_FALSE(started->localCleanupComplete());
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 128);
  }
  transport->blocked = 0;
  blockingWait(reader.close());
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
  EXPECT_EQ(reader.snapshot().activeOperations, 0);
}

TEST(TestEcBlockRead, FiniteDeadlineAndDroppedReadyHandleReleaseAllLeases) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<BlockTransport>();
  transport->blocked = 0xfff;
  EcBlockRead reader(transport, executor, {});
  SCOPE_EXIT {
    transport->blocked = 0;
    blockingWait(reader.close());
  };
  {
    auto config = options(100ms);
    config.hedgeAfter = 10ms;
    auto started = reader.start(input(), config);
    ASSERT_TRUE(started);
    auto result = blockingWait(started->takeReady());
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), StorageClientCode::kTimeout);
    blockingWait(started->waitLocalCleanup());
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
  }
  transport->blocked = 1u << 10;
  {
    auto started = reader.start(input(), options());
    ASSERT_TRUE(started);
    const auto limit = Clock::now() + 1s;
    while (!started->ready() && Clock::now() < limit) std::this_thread::sleep_for(1ms);
    ASSERT_TRUE(started->ready());
    EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 128);
  }
  transport->blocked = 0;
  blockingWait(reader.close());
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 0);
}

TEST(TestEcBlockRead, ConcurrentStartObservesFullChargeWhileQuorumPublishes) {
  folly::CPUThreadPoolExecutor executor(2);
  auto transport = std::make_shared<BlockTransport>();
  transport->blocked = 0xfff;
  EcBlockRead reader(transport, executor, {2, 12 * 128, 60s});
  SCOPE_EXIT {
    transport->blocked = 0;
    blockingWait(reader.close());
  };
  auto fixed = input();
  auto started = reader.start(fixed, options());
  ASSERT_TRUE(started);
  ASSERT_TRUE(waitStarted(*transport, 11));
  std::atomic<bool> stop{false};
  std::atomic<size_t> probes{0}, admitted{0}, badCharge{0};
  std::thread contender([&] {
    while (!stop.load()) {
      auto attempted = reader.start(fixed, options());
      if (attempted) ++admitted;
      if (reader.snapshot().reservedPayloadBytes != 12 * 128) ++badCharge;
      ++probes;
      std::this_thread::yield();
    }
  });
  SCOPE_EXIT {
    stop = true;
    if (contender.joinable()) contender.join();
  };
  const auto limit = Clock::now() + 1s;
  while (probes.load() == 0 && Clock::now() < limit) std::this_thread::sleep_for(1ms);
  transport->blocked = 1u << 10;
  auto result = blockingWait(started->takeReady());
  ASSERT_TRUE(result);
  stop = true;
  contender.join();
  EXPECT_GT(probes.load(), 0);
  EXPECT_EQ(admitted.load(), 0);
  EXPECT_EQ(badCharge.load(), 0);
  EXPECT_EQ(reader.snapshot().reservedPayloadBytes, 12 * 128);
}

TEST(TestEcBlockRead, FixedRepairSourceKeepsOriginalFragmentOperation) {
  auto fixed = input();
  const auto &fragment = fixed.pinned.manifest.fragments[0];
  EcBlockBinding binding{fragment.identity,
                         fragment.operation,
                         fixed.pinned.snapshot.endpoints[0].endpoint.controlEndpoint(),
                         fragment.integrity};
  auto grant = fixed.requests[0].grant;
  grant.claims.scopeKind = storage::EcGrantScope::WriteOperation;
  grant.claims.scopeId = Uuid::random();  // Repair scope differs from healthy fragment operation.
  auto request = makeEcReadBlockRequest(binding, grant, fixed.requests[0].request.vChainId, 0);
  ASSERT_TRUE(request);
  EXPECT_EQ(request->request.operationId, fragment.operation);
  grant.claims.fragmentOperationId = grant.claims.scopeId;
  EXPECT_FALSE(makeEcReadBlockRequest(binding, grant, fixed.requests[0].request.vChainId, 0));
}
}  // namespace
}  // namespace hf3fs::client::ec::test
