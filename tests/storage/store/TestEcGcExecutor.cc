#include <algorithm>
#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <folly/CancellationToken.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/experimental/coro/WithCancellation.h>
#include <future>
#include <openssl/hmac.h>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <vector>

#include "storage/ec_gc/EcGcExecutor.h"
#include "storage/store/StorageTarget.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
using Codec = ec_gc_control_detail::Codec;
using namespace std::chrono_literals;
thread_local bool gcTestCaller = false;
template <typename T>
void expectOk(T &&result) {
  EXPECT_TRUE(result) << result.error().describe();
}

// Uses the actual StorageTarget constructor/create/load and shared Rust facade.
// This is a test assembly seam, not an unauthenticated production GC opener.
class GcTestTarget final : public StorageTarget {
 public:
  GcTestTarget(const Config &config, GlobalFileStore &files, std::shared_ptr<EcStagingEngine> engine)
      : StorageTarget(config, files, 0, nullptr, std::move(engine)) {}
};

void writeFile(const Path &path, std::string_view bytes) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) throw std::runtime_error("test create failed");
  SCOPE_EXIT { ::close(fd); };
  while (!bytes.empty()) {
    const auto count = ::write(fd, bytes.data(), bytes.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) throw std::runtime_error("test write failed");
    bytes.remove_prefix(count);
  }
  if (::fsync(fd)) throw std::runtime_error("test file sync failed");
}
void syncDirectory(const Path &path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) throw std::runtime_error("test directory open failed");
  SCOPE_EXIT { ::close(fd); };
  if (::fsync(fd)) throw std::runtime_error("test directory sync failed");
}
struct ClockBarrier {
  std::promise<void> entered;
  std::promise<void> resume;
  std::shared_future<void> resumed = resume.get_future().share();
  std::atomic<bool> seen{false};
  std::atomic<bool> released{false};
  void release() {
    if (!released.exchange(true)) resume.set_value();
  }
  uint64_t clock() {
    if (!gcTestCaller && !seen.exchange(true)) {
      entered.set_value();
      resumed.wait();
    }
    return 1000;
  }
  ~ClockBarrier() { release(); }
};

class TestEcGcExecutor : public ::testing::Test {
 protected:
  void SetUp() override {
    // The real Engine opens thousands of allocator files. Do not silently skip
    // or convert a host resource failure into a successful authorization test.
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_max, 8192u);
    if (limit.rlim_cur < 8192) {
      limit.rlim_cur = 8192;
      ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &limit), 0);
    }
    struct statfs fs {};
    ASSERT_EQ(::statfs(directory.path().c_str(), &fs), 0);
    ASSERT_EQ(fs.f_type, 0xef53) << "use an existing ext4 TMPDIR for real Engine tests";
    writeFile(directory.path() / "engine", "3FS_EC_ENGINE_ROOT_V3_GC\n");
    writeFile(directory.path() / "engine-ec-v1", "3FS_EC_ENGINE_V1_BLOCKED_BY_V3_GC\n");
    syncDirectory(directory.path());
    keyBytes.fill(0x39);
    writeFile(directory.path() / "gc.key", {reinterpret_cast<const char *>(keyBytes.data()), keyBytes.size()});
    auto loadedKey = EcGcKey::loadFile(std::filesystem::path((directory.path() / "gc.key").string()), keyId, {});
    ASSERT_OK(loadedKey);
    key = std::shared_ptr<const EcGcKey>(std::move(*loadedKey));
    ASSERT_NO_FATAL_FAILURE(open(true));
    request.operation = EcStageOperation::Begin;
    request.identity.object = Uuid::from(601, 602);
    request.identity.allocation = Uuid::from(603, 604);
    request.identity.generation = 1;
    request.vChainId = {ChainId{701}, ChainVer{9}};
    request.targetId = TargetId{702};
    request.operationId = Uuid::from(605, 606);
    request.writerNamespace = Uuid::from(607, 608);
    data.resize(65543);
    for (size_t i = 0; i != data.size(); ++i) data[i] = static_cast<char>((i * 19 + 31) & 255);
    auto integrity = computeEcIntegrity(request.identity, data);
    ASSERT_OK(integrity);
    request.integrity = *integrity;
    ASSERT_NO_FATAL_FAILURE(start());
  }
  void TearDown() override {
    if (executor) expectOk(executor->stopAndJoin());
    executor.reset();
    target.reset();
    engine.reset();
  }
  void open(bool create) {
    auto opened = EcStagingEngine::openExactGc(directory.path() / "engine-ec-v2", create, {8, 4, 2});
    ASSERT_OK(opened);
    engine = *opened;
    ASSERT_EQ(engine->actualDiskFormat().value(), 3);
    target = std::make_shared<GcTestTarget>(config, files, engine);
    if (create) {
      PhysicalConfig physical;
      physical.path = directory.path() / "target";
      physical.target_id = 702;
      physical.chain_id = 701;
      physical.allow_disk_without_uuid = true;
      physical.only_chunk_engine = true;
      physical.ec_only = true;
      physical.ec_staging_v2 = true;
      physical.ec_exact_gc = true;  // Explicit dependency on ec-storage-gc-format.
      ASSERT_OK(target->create(physical));
    } else {
      ASSERT_OK(target->load(directory.path() / "target"));
    }
    ASSERT_OK(target->initializeEcScope(create ? StorageTarget::EcScopeOpenMode::RegisterNew
                                               : StorageTarget::EcScopeOpenMode::LoadExisting));
    auto state = target->ecScopeState();
    ASSERT_OK(state);
    actual = state->second;
  }
  void start(
      EcGcExecutor::Clock clock = [] { return 1000; },
      EcGcExecutor::ReadOnly readOnly = [] { return false; }) {
    if (executor) ASSERT_OK(executor->stopAndJoin());
    executor.reset();
    auto started = EcGcExecutor::create(key, authority, node, std::move(clock), std::move(readOnly));
    ASSERT_OK(started);
    executor = std::move(*started);
  }
  EcStageRequest op(EcStageOperation operation) const {
    auto value = request;
    value.operation = operation;
    return value;
  }
  void seal() {
    ASSERT_OK(target->executeEcStage(request));
    for (uint8_t i = 0; i != request.integrity.blockCount; ++i) {
      auto append = op(EcStageOperation::Append);
      append.blockIndex = i;
      append.payload = data.substr(size_t(i) * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
      ASSERT_OK(target->executeEcStage(append));
    }
    ASSERT_OK(target->executeEcStage(op(EcStageOperation::Seal)));
  }
  EcGcRequestClaims claims(EcGcAction action) const {
    EcGcRequestClaims claims;
    claims.action = action;
    claims.keyId = keyId;
    claims.authority = authority;
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = 1000;
    claims.expiresAtSeconds = 1100;
    auto &c = claims.certificate;
    c.claimId = claimId;
    c.objectInode = 9;
    c.objectIncarnation = request.identity.object;
    c.creatorUid = flat::Uid{1000};
    c.creatorClient = Uuid::from(611, 612);
    c.createRequest = Uuid::from(613, 614);
    c.fragment = request.identity;
    c.fragmentOperation = request.operationId;
    c.endpoint.nodeId = node;
    c.endpoint.chainId = ChainId{actual.chain};
    c.endpoint.targetId = TargetId{actual.target};
    std::copy(actual.engine.begin(), actual.engine.end(), std::begin(c.endpoint.engineUuid.data));
    std::copy(actual.incarnation.begin(), actual.incarnation.end(), std::begin(c.endpoint.targetIncarnation.data));
    c.writerUid = flat::Uid{1000};
    c.writerClient = request.writerNamespace;
    c.integrity = request.integrity;
    c.registeredScopes = c.releasedScopes = 2;
    c.releaseHistory.fill(11);
    c.originDrainEvidence.fill(12);
    c.eligibilityDigest.fill(13);
    return claims;
  }
  // Test-only independent OpenSSL issuer with known fixture key material.
  // Synthetic Meta evidence is not a real FDB claim/authorization proof.
  EcGcRequest sign(const EcGcRequestClaims &claims) const {
    const auto body = Codec::encode(claims);
    EcSha256 signature{};
    unsigned size = 0;
    if (!HMAC(EVP_sha256(), keyBytes.data(), keyBytes.size(), body.data(), body.size(), signature.data(), &size) ||
        size != 32) {
      throw std::runtime_error("fixture HMAC failed");
    }
    auto value = Codec::decodeRequest({reinterpret_cast<const char *>(body.data()), body.size()},
                                      {reinterpret_cast<const char *>(signature.data()), signature.size()});
    if (!value) throw std::runtime_error("fixture canonical request rejected");
    return std::move(*value);
  }
  Result<EcGcAck> run(EcGcAction action, EcGcRequest token) {
    const bool before = gcTestCaller;
    gcTestCaller = true;
    SCOPE_EXIT { gcTestCaller = before; };
    return folly::coro::blockingWait(executor->execute(action, std::move(token), target));
  }
  uint64_t used() { return engine->committedSize(ChainId{701}).value(); }
  folly::test::TemporaryDirectory directory;
  ChunkStore::Config config;
  GlobalFileStore files;
  std::shared_ptr<EcStagingEngine> engine;
  std::shared_ptr<GcTestTarget> target;
  EcScopeTargetIdentity actual{};
  std::array<uint8_t, 32> keyBytes{};
  std::shared_ptr<const EcGcKey> key;
  Uuid keyId = Uuid::from(615, 616);
  Uuid authority = Uuid::from(617, 618);
  Uuid claimId = Uuid::from(619, 620);
  NodeId node{703};
  std::unique_ptr<EcGcExecutor> executor;
  EcStageRequest request;
  std::string data;
};

TEST_F(TestEcGcExecutor, CollectAndQueryUseSameHandleAndSurviveCleanReopen) {
  ASSERT_NO_FATAL_FAILURE(seal());
  ASSERT_GT(used(), 0);
  const auto collect = sign(claims(EcGcAction::Collect));
  auto first = run(EcGcAction::Collect, collect);
  ASSERT_OK(first);
  expectOk(Codec::verifyAck(*key, *first, collect));
  EXPECT_EQ(used(), 0);
  const auto query = sign(claims(EcGcAction::Query));
  auto observed = run(EcGcAction::Query, query);
  ASSERT_OK(observed);
  EXPECT_EQ(observed->claims.ledgerSha256, first->claims.ledgerSha256);
  EXPECT_EQ(observed->claims.terminalRevision, first->claims.terminalRevision);
  EXPECT_EQ(used(), 0);
  ASSERT_OK(executor->stopAndJoin());
  executor.reset();
  target.reset();
  engine.reset();
  ASSERT_NO_FATAL_FAILURE(open(false));
  ASSERT_NO_FATAL_FAILURE(start());
  auto reopened = run(EcGcAction::Query, query);
  ASSERT_OK(reopened);
  expectOk(Codec::verifyAck(*key, *reopened, query));
  EXPECT_EQ(reopened->claims.ledgerSha256, first->claims.ledgerSha256);
  EXPECT_EQ(used(), 0);
  expectOk(run(EcGcAction::Collect, collect));
  EXPECT_EQ(used(), 0);
  auto changedClaim = claims(EcGcAction::Collect);
  changedClaim.certificate.claimId = Uuid::random();
  EXPECT_FALSE(run(EcGcAction::Collect, sign(changedClaim)));
  EXPECT_EQ(used(), 0);
}

TEST_F(TestEcGcExecutor, QueryMissingNeverStartsCollectionOrChangesAccounting) {
  auto missing = run(EcGcAction::Query, sign(claims(EcGcAction::Query)));
  ASSERT_FALSE(missing);
  EXPECT_EQ(missing.error().code(), 4001);
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  auto sealedNoLedger = run(EcGcAction::Query, sign(claims(EcGcAction::Query)));
  ASSERT_FALSE(sealedNoLedger);
  EXPECT_EQ(sealedNoLedger.error().code(), 4001);
  EXPECT_EQ(used(), before);
  expectOk(target->executeEcStage(op(EcStageOperation::ReadBlock)));
}

TEST_F(TestEcGcExecutor, ActualInstanceAndOriginalWriterCannotBeSubstituted) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  for (int changed = 0; changed != 5; ++changed) {
    auto c = claims(EcGcAction::Collect);
    if (changed == 0) c.certificate.endpoint.targetId = TargetId{999};
    if (changed == 1) c.certificate.endpoint.engineUuid = Uuid::random();
    if (changed == 2) c.certificate.endpoint.targetIncarnation = Uuid::random();
    if (changed == 3) c.certificate.writerClient = Uuid::random();
    if (changed == 4) c.certificate.fragmentOperation = Uuid::random();
    EXPECT_FALSE(run(EcGcAction::Collect, sign(c)));
    EXPECT_EQ(used(), before);
  }
  auto another = claims(EcGcAction::Collect);
  another.certificate.fragment.allocation = Uuid::random();
  // The sole key is derived from this different signed identity. It must not
  // remove the existing allocation even though chain, length and CRC match.
  auto result = run(EcGcAction::Collect, sign(another));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), 4001);
  EXPECT_EQ(used(), before);
  expectOk(run(EcGcAction::Collect, sign(claims(EcGcAction::Collect))));
}

TEST_F(TestEcGcExecutor, AnotherLoadedTargetOnSameChainCannotUseThisCertificate) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  auto other = std::make_shared<GcTestTarget>(config, files, engine);
  PhysicalConfig physical;
  physical.path = directory.path() / "other-target";
  physical.target_id = 704;
  physical.chain_id = 701;
  physical.allow_disk_without_uuid = true;
  physical.only_chunk_engine = physical.ec_only = physical.ec_staging_v2 = physical.ec_exact_gc = true;
  ASSERT_OK(other->create(physical));
  ASSERT_OK(other->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
  const auto token = sign(claims(EcGcAction::Collect));
  auto result = folly::coro::blockingWait(executor->execute(EcGcAction::Collect, token, other));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StatusCode::kTokenMismatch);
  EXPECT_EQ(used(), before);
  // Same native chain prefix is insufficient; target incarnation is real and distinct.
  auto otherIdentity = other->ecScopeState();
  ASSERT_OK(otherIdentity);
  EXPECT_NE(otherIdentity->second.incarnation, actual.incarnation);
  EXPECT_EQ(otherIdentity->second.engine, actual.engine);
}

TEST_F(TestEcGcExecutor, Format2IsNotUpgradedOrInferredFromSignedFormat3) {
  auto token = sign(claims(EcGcAction::Collect));
  ASSERT_OK(executor->stopAndJoin());
  executor.reset();
  target.reset();
  engine.reset();  // Never require two 5632-file Engines simultaneously.
  folly::test::TemporaryDirectory oldFormat;
  writeFile(oldFormat.path() / "engine", "3FS_EC_ENGINE_ROOT_V2\n");
  writeFile(oldFormat.path() / "engine-ec-v1", "3FS_EC_ENGINE_V1_BLOCKED_BY_V2\n");
  syncDirectory(oldFormat.path());
  auto opened = EcStagingEngine::open(oldFormat.path() / "engine-ec-v2", true, {8, 4, 2});
  ASSERT_OK(opened);
  engine = std::move(*opened);
  target = std::make_shared<GcTestTarget>(config, files, engine);
  // Ensure destruction precedes this local temporary directory on every path.
  auto cleanup = folly::makeGuard([&] {
    if (executor) expectOk(executor->stopAndJoin());
    executor.reset();
    target.reset();
    engine.reset();
  });
  PhysicalConfig physical;
  physical.path = oldFormat.path() / "target";
  physical.target_id = 702;
  physical.chain_id = 701;
  physical.allow_disk_without_uuid = true;
  physical.only_chunk_engine = physical.ec_only = physical.ec_staging_v2 = true;
  physical.ec_exact_gc = false;
  ASSERT_OK(target->create(physical));
  ASSERT_OK(target->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
  ASSERT_EQ(engine->actualDiskFormat().value(), 2);
  ASSERT_NO_FATAL_FAILURE(start());
  auto result = run(EcGcAction::Collect, token);
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageCode::kTargetStateInvalid);
  EXPECT_EQ(engine->actualDiskFormat().value(), 2);
}

TEST_F(TestEcGcExecutor, WorkerExpiryIsPreMutationButPostCollectionExpiryIsUnknown) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  ASSERT_NO_FATAL_FAILURE(start([] { return gcTestCaller ? 1000 : 1100; }));
  auto rejected = run(EcGcAction::Collect, sign(claims(EcGcAction::Collect)));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error().code(), StatusCode::kAuthenticationFail);
  EXPECT_EQ(used(), before);
  auto stillSealed = target->executeEcStage(op(EcStageOperation::Query));
  ASSERT_OK(stillSealed);
  ASSERT_TRUE(stillSealed->state);
  EXPECT_EQ(stillSealed->state->state, 2);
  std::atomic<bool> observedTerminal{false};
  ASSERT_NO_FATAL_FAILURE(start([&] {
    auto state = target->executeEcStage(op(EcStageOperation::Query));
    if (state && state->state && state->state->state == 3) {
      observedTerminal = true;
      return uint64_t{1100};
    }
    return uint64_t{1000};
  }));
  auto unknown = run(EcGcAction::Collect, sign(claims(EcGcAction::Collect)));
  ASSERT_FALSE(unknown);
  EXPECT_EQ(unknown.error().code(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_TRUE(observedTerminal);
  EXPECT_EQ(used(), 0);
  ASSERT_NO_FATAL_FAILURE(start());
  expectOk(run(EcGcAction::Query, sign(claims(EcGcAction::Query))));
  EXPECT_EQ(used(), 0);
}

TEST_F(TestEcGcExecutor, PostCollectionExceptionRetainsUnknownAndSameClaimCanReconfirm) {
  ASSERT_NO_FATAL_FAILURE(seal());
  std::atomic<bool> threw{false};
  ASSERT_NO_FATAL_FAILURE(start([&]() -> uint64_t {
    auto state = target->executeEcStage(op(EcStageOperation::Query));
    if (state && state->state && state->state->state == 3) {
      threw = true;
      throw std::bad_alloc();
    }
    return 1000;
  }));
  auto unknown = run(EcGcAction::Collect, sign(claims(EcGcAction::Collect)));
  ASSERT_FALSE(unknown);
  EXPECT_EQ(unknown.error().code(), StorageCode::kEcSealOutcomeUnknown);
  EXPECT_TRUE(threw);
  EXPECT_EQ(used(), 0);
  ASSERT_NO_FATAL_FAILURE(start());
  expectOk(run(EcGcAction::Query, sign(claims(EcGcAction::Query))));
}

TEST_F(TestEcGcExecutor, WorkerCannotSynchronouslyJoinItself) {
  std::atomic<bool> rejected{false};
  std::atomic<bool> nestedRejected{false};
  const auto token = sign(claims(EcGcAction::Query));
  ASSERT_NO_FATAL_FAILURE(start([&] {
    if (!gcTestCaller) {
      auto selfJoin = executor->stopAndJoin();
      rejected = !selfJoin && selfJoin.error().code() == StatusCode::kInvalidArg;
      auto nested = folly::coro::blockingWait(executor->execute(EcGcAction::Query, token, target));
      nestedRejected = !nested && nested.error().code() == StatusCode::kInvalidArg;
    }
    return 1000;
  }));
  auto result = run(EcGcAction::Query, sign(claims(EcGcAction::Query)));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), 4001);
  EXPECT_TRUE(rejected);
  EXPECT_TRUE(nestedRejected);
  expectOk(executor->stopAndJoin());
}

TEST_F(TestEcGcExecutor, ReleasedTargetDoesNotRemainAnAdmissionSource) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  ASSERT_OK(target->release());  // Sequential, after all previous data work.
  auto result = run(EcGcAction::Collect, sign(claims(EcGcAction::Collect)));
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code(), StorageCode::kTargetStateInvalid);
  EXPECT_EQ(used(), before);
}

TEST_F(TestEcGcExecutor, SubmittedRequestKeepsTargetAndEngineAliveAfterCallerReleasesThem) {
  ASSERT_NO_FATAL_FAILURE(seal());
  ClockBarrier barrier;
  ASSERT_NO_FATAL_FAILURE(start([&] { return barrier.clock(); }));
  auto token = sign(claims(EcGcAction::Collect));
  std::weak_ptr<StorageTarget> weakTarget = target;
  std::weak_ptr<EcStagingEngine> weakEngine = engine;
  auto pending =
      std::async(std::launch::async, [this, token, owned = std::shared_ptr<StorageTarget>(target)]() mutable {
        gcTestCaller = true;
        return folly::coro::blockingWait(executor->execute(EcGcAction::Collect, token, std::move(owned)));
      });
  auto release = folly::makeGuard([&] { barrier.release(); });
  ASSERT_EQ(barrier.entered.get_future().wait_for(5s), std::future_status::ready);
  target.reset();
  engine.reset();
  EXPECT_FALSE(weakTarget.expired());
  EXPECT_FALSE(weakEngine.expired());
  barrier.release();
  auto result = pending.get();
  ASSERT_OK(result);
  expectOk(Codec::verifyAck(*key, *result, token));
  ASSERT_OK(executor->stopAndJoin());
  EXPECT_TRUE(weakTarget.expired());
  EXPECT_TRUE(weakEngine.expired());
  // Clean reopening is a separate observation, not an injected power loss.
  ASSERT_NO_FATAL_FAILURE(open(false));
  ASSERT_NO_FATAL_FAILURE(start());
  expectOk(run(EcGcAction::Query, sign(claims(EcGcAction::Query))));
}

TEST_F(TestEcGcExecutor, BoundedQueueOwnsCancelledRequestsUntilCompletionAndStopJoins) {
  ASSERT_NO_FATAL_FAILURE(seal());
  ClockBarrier barrier;
  ASSERT_NO_FATAL_FAILURE(start([&] { return barrier.clock(); }));
  const auto token = sign(claims(EcGcAction::Query));
  folly::CancellationSource cancellation;
  std::vector<std::future<Result<EcGcAck>>> pending;
  // Cleanup is registered after futures so all assertion paths unblock the
  // worker before std::future destructors join the caller threads.
  auto release = folly::makeGuard([&] { barrier.release(); });
  for (size_t i = 0; i != EcGcExecutor::kCapacity; ++i) {
    pending.push_back(std::async(std::launch::async, [&, i] {
      gcTestCaller = true;
      if (i == 1) {
        return folly::coro::blockingWait(
            folly::coro::co_withCancellation(cancellation.getToken(),
                                             executor->execute(EcGcAction::Query, token, target)));
      }
      return folly::coro::blockingWait(executor->execute(EcGcAction::Query, token, target));
    }));
  }
  ASSERT_EQ(barrier.entered.get_future().wait_for(5s), std::future_status::ready);
  const auto until = std::chrono::steady_clock::now() + 5s;
  while (executor->activeRequests() != 64 && std::chrono::steady_clock::now() < until) std::this_thread::yield();
  ASSERT_EQ(executor->activeRequests(), 64);
  cancellation.requestCancellation();
  auto extra = run(EcGcAction::Query, token);
  ASSERT_FALSE(extra);
  EXPECT_EQ(extra.error().code(), StorageClientCode::kResourceBusy);
  EXPECT_EQ(pending[1].wait_for(20ms), std::future_status::timeout);
  std::promise<void> stopStarted;
  auto stopper = std::async(std::launch::async, [&] {
    stopStarted.set_value();
    return executor->stopAndJoin();
  });
  stopStarted.get_future().wait();
  EXPECT_EQ(stopper.wait_for(20ms), std::future_status::timeout);
  barrier.release();
  for (auto &future : pending) {
    auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), 4001);  // Query still did not delete sealed data.
  }
  expectOk(stopper.get());
  EXPECT_EQ(executor->activeRequests(), 0);
  EXPECT_GT(used(), 0);
  EXPECT_FALSE(run(EcGcAction::Query, token));
}
TEST_F(TestEcGcExecutor, ReadOnlyRejectsCollectButAllowsMissingAndConfirmedQuery) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  auto readOnly = std::make_shared<std::atomic<bool>>(true);
  ASSERT_NO_FATAL_FAILURE(start([] { return 1000; }, [readOnly] { return readOnly->load(); }));
  ASSERT_ERROR(run(EcGcAction::Collect, sign(claims(EcGcAction::Collect))), StatusCode::kReadOnlyMode);
  EXPECT_EQ(used(), before);
  ASSERT_ERROR(run(EcGcAction::Query, sign(claims(EcGcAction::Query))), StorageCode::kChunkMetadataNotFound);
  expectOk(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  readOnly->store(false);
  auto collected = run(EcGcAction::Collect, sign(claims(EcGcAction::Collect)));
  ASSERT_OK(collected);
  EXPECT_EQ(used(), 0);
  readOnly->store(true);
  auto queried = run(EcGcAction::Query, sign(claims(EcGcAction::Query)));
  ASSERT_OK(queried);
  EXPECT_EQ(queried->claims.ledgerSha256, collected->claims.ledgerSha256);
  EXPECT_EQ(queried->claims.terminalRevision, collected->claims.terminalRevision);
  ASSERT_ERROR(run(EcGcAction::Collect, sign(claims(EcGcAction::Collect))), StatusCode::kReadOnlyMode);
  EXPECT_EQ(used(), 0);
}

TEST_F(TestEcGcExecutor, ReadOnlyHotUpdateAfterQueueAdmissionPreventsActualMutation) {
  ASSERT_NO_FATAL_FAILURE(seal());
  const auto before = used();
  auto readOnly = std::make_shared<std::atomic<bool>>(false);
  auto barrier = std::make_shared<ClockBarrier>();
  auto entered = barrier->entered.get_future();
  ASSERT_NO_FATAL_FAILURE(start([barrier] { return barrier->clock(); }, [readOnly] { return readOnly->load(); }));
  const auto token = sign(claims(EcGcAction::Collect));
  auto pending = std::async(std::launch::async, [this, token] { return run(EcGcAction::Collect, token); });
  // Release before the future's destructor on every assertion path. The
  // caller thread skips this existing clock barrier; only the real worker
  // reaches it after queue admission, before its mutation-policy recheck.
  SCOPE_EXIT { barrier->release(); };
  ASSERT_EQ(entered.wait_for(10s), std::future_status::ready);
  readOnly->store(true);
  barrier->release();
  auto rejected = pending.get();
  ASSERT_ERROR(rejected, StatusCode::kReadOnlyMode);
  EXPECT_EQ(used(), before);
  ASSERT_OK(target->executeEcStage(op(EcStageOperation::ReadBlock)));
  ASSERT_ERROR(run(EcGcAction::Query, sign(claims(EcGcAction::Query))), StorageCode::kChunkMetadataNotFound);
}

}  // namespace
}  // namespace hf3fs::storage
