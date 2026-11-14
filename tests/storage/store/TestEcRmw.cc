#include <atomic>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <future>
#include <thread>

#include "storage/ec_codec/EcCodec.h"
#include "tests/GtestHelpers.h"
#include "tests/storage/EcRmwTestAccess.h"

namespace hf3fs::storage {
namespace {
using namespace ec_rmw_detail;
using folly::coro::blockingWait;
class MemoryIo : public EcRmwIo {
 public:
  explicit MemoryIo(std::shared_ptr<const EcRmwPlan> p)
      : plan(std::move(p)) {}
  Result<Void> check() const override { return Void{}; }
  CoTryTask<std::string> readSource(uint8_t i) override {
    ++reads;
    if (throwRead) throw std::bad_alloc();
    if (i < missing) co_return makeError(StorageClientCode::kTimeout);
    co_return sources[i];
  }
  CoTryTask<Void> bindOutput(const EcRmwOutputCommitment &c) override {
    ++binds;
    commitment = c;
    if (delay) {
      entered.set_value();
      co_await resume;
    }
    co_return Void{};
  }
  CoTryTask<EcFragmentReceiptV2> writeTarget(uint8_t i, const EcIntegrityDescriptor &d, std::string bytes) override {
    ++writes;
    if (throwWrite && i == 1) throw std::bad_alloc();
    output[i] = std::move(bytes);
    const auto &p = plan->input();
    const auto &t = p.targets[i];
    EcFragmentReceiptV2 r;
    r.identity = t.identity;
    r.operationId = p.operationId;
    r.engineUuid = t.endpoint.engineUuid;
    r.targetIncarnation = t.endpoint.targetIncarnation;
    r.vChainId = {t.endpoint.chainId, ChainVer(1)};
    r.targetId = t.endpoint.targetId;
    r.length = p.shardBytes;
    r.crc32c = d.wholeCrc32c;
    r.integrityRoot = d.root;
    co_return r;
  }
  std::shared_ptr<const EcRmwPlan> plan;
  EcCodec::Shards sources, output;
  EcRmwOutputCommitment commitment;
  size_t reads = 0, binds = 0, writes = 0;
  uint8_t missing = 0;
  bool throwRead = false, throwWrite = false, delay = false;
  std::promise<void> entered;
  folly::coro::Baton resume;
};
Result<VerifiedEcRmwPlan> execution(const EcRmwKey &key, std::shared_ptr<const EcRmwPlan> plan) {
  CHECK_RESULT(grant, AuthorizationTestAccess::grant(key, *plan));
  return EcRmwAuthorization::verify(key, grant, plan, plan->worker(), Uuid::from(91, 92), EcRmwRight::Execute, 1000);
}
TEST(TestEcRmw, ExactPlanRightsPatchAndSparseTail) {
  const std::string patch = "replacement";
  auto p = zeroPlan(patch);
  p.lengthAtPlan = 1000;
  p.targetLogicalLength = 1000;
  auto plan = EcRmwPlan::create(p);
  ASSERT_OK(plan);
  auto truncated = p;
  truncated.targetLogicalLength = p.patchOffset + p.patchLength;
  EXPECT_FALSE(EcRmwPlan::create(truncated));
  auto reused = p;
  reused.targets[1].identity.allocation = reused.targets[0].identity.allocation;
  EXPECT_FALSE(EcRmwPlan::create(reused));
  auto key = AuthorizationTestAccess::key();
  auto upload = AuthorizationTestAccess::grant(*key, **plan, uint16_t(EcRmwRight::Upload));
  ASSERT_OK(upload);
  EXPECT_FALSE(EcRmwAuthorization::verify(*key,
                                          *upload,
                                          *plan,
                                          (*plan)->worker(),
                                          Uuid::from(91, 92),
                                          EcRmwRight::Execute,
                                          1000));
  auto other = (*plan)->worker();
  other.targetIncarnation = Uuid::from(999, 1);
  EXPECT_FALSE(EcRmwAuthorization::verify(*key, *upload, *plan, other, Uuid::from(91, 92), EcRmwRight::Upload, 1000));
  EXPECT_FALSE(EcRmwAuthorization::verify(*key,
                                          *upload,
                                          *plan,
                                          (*plan)->worker(),
                                          Uuid::from(91, 92),
                                          EcRmwRight::Upload,
                                          1100));
  const auto wire = EcRmwWireCodec::encode(EcRmwPlanWire{p});
  ASSERT_EQ(wire.size(), kEcRmwPlanWireBytes);
  auto decoded = EcRmwWireCodec::plan(wire);
  ASSERT_OK(decoded);
  auto roundtrip = EcRmwPlan::create(decoded->input);
  ASSERT_OK(roundtrip);
  EXPECT_EQ((*roundtrip)->digest(), (*plan)->digest());
  EXPECT_FALSE(EcRmwWireCodec::plan(wire + "x"));
  EXPECT_FALSE(EcRmwWireCodec::plan(std::string_view(wire).substr(1)));
  auto grantWire = EcRmwWireCodec::encode(*upload);
  ASSERT_EQ(grantWire.size(), kEcRmwGrantWireBytes);
  grantWire.back() ^= 1;
  auto corrupt = EcRmwWireCodec::grant(grantWire);
  ASSERT_OK(corrupt);
  EXPECT_FALSE(EcRmwAuthorization::verify(*key,
                                          *corrupt,
                                          *plan,
                                          (*plan)->worker(),
                                          Uuid::from(91, 92),
                                          EcRmwRight::Upload,
                                          1000));
  EcRmwInstallReq install;
  install.plan.input = p;
  install.grant = *upload;
  auto binary = serde::serialize(install);
  EcRmwInstallReq parsed;
  ASSERT_OK(serde::deserialize(parsed, binary));  // Zero omits source grants, not invalid nil credentials.
  auto buffer = EcRmwPatchBuffer::create(*plan);
  ASSERT_OK(buffer);
  ASSERT_OK((*buffer)->put(0, patch));
  ASSERT_OK((*buffer)->put(0, patch));
  EXPECT_FALSE((*buffer)->put(0, std::string(patch.size(), 'x')));
  auto bytes = (*buffer)->finish();
  ASSERT_OK(bytes);
  auto auth = execution(*key, *plan);
  ASSERT_OK(auth);
  auto io = std::make_shared<MemoryIo>(*plan);
  auto result = blockingWait(EcRmwExecution::run(*auth, std::move(*bytes), io));
  ASSERT_OK(result);
  std::string expected(1000, '\0');
  expected.replace(3, patch.size(), patch);
  auto encoded = EcCodec::encode(expected, p.shardBytes);
  ASSERT_OK(encoded);
  EXPECT_EQ(io->output, *encoded);
  EXPECT_EQ(io->reads, 0);
  EXPECT_EQ(io->writes, 12);
}
TEST(TestEcRmw, DataRecoveryUsesParityAndKeepsReadOomDistinctFromMutationUnknown) {
  const std::string patch = "patch";
  auto p = zeroPlan(patch, 31);
  std::string source(301, 'o');
  auto encoded = EcCodec::encode(source, 31);
  ASSERT_OK(encoded);
  p.sourceKind = EcRmwSourceKind::Data;
  p.sourceRoot = Uuid::from(20, 1);
  p.sourcePin = Uuid::from(21, 1);
  p.sourceRevision = 1;
  p.sourceGeneration = 1;
  p.sourceLogicalLength = source.size();
  p.sourceLogicalSha256 = *sha256(source);
  p.lengthAtPlan = source.size();
  p.targetLogicalLength = source.size();
  p.targetRevision = 2;
  p.targetGeneration = 2;
  for (size_t i = 0; i < 12; ++i) {
    auto &f = p.sources[i];
    f.identity = p.targets[i].identity;
    f.endpoint = p.targets[i].endpoint;
    f.operationId = Uuid::from(22, 1);
    f.writerNamespace = p.clientNamespace;
    f.integrity = *computeEcIntegrity(f.identity, (*encoded)[i]);
    p.targets[i].identity.generation = 2;
    p.targets[i].identity.allocation = Uuid::from(500 + i, 1);
  }
  auto plan = EcRmwPlan::create(p);
  ASSERT_OK(plan);
  auto key = AuthorizationTestAccess::key();
  auto dataWire = EcRmwWireCodec::encode(EcRmwPlanWire{p});
  ASSERT_EQ(dataWire.size(), kEcRmwPlanWireBytes);
  auto dataDecoded = EcRmwWireCodec::plan(dataWire);
  ASSERT_OK(dataDecoded);
  auto dataPlan = EcRmwPlan::create(dataDecoded->input);
  ASSERT_OK(dataPlan);
  EXPECT_EQ((*dataPlan)->digest(), (*plan)->digest());

  auto auth = execution(*key, *plan);
  ASSERT_OK(auth);
  auto io = std::make_shared<MemoryIo>(*plan);
  io->sources = *encoded;
  io->missing = 2;
  auto result = blockingWait(EcRmwExecution::run(*auth, patch, io));
  ASSERT_OK(result);
  source.replace(3, patch.size(), patch);
  auto expected = EcCodec::encode(source, 31);
  ASSERT_OK(expected);
  EXPECT_EQ(io->output, *expected);
  EXPECT_EQ(io->reads, 12);
  auto tail = p;
  tail.action = EcRmwAction::TruncateTail;
  tail.patchOffset = 0;
  tail.patchLength = 0;
  tail.patchSha256 = *sha256({});
  tail.targetLogicalLength = 117;
  auto tailPlan = EcRmwPlan::create(tail);
  ASSERT_OK(tailPlan);
  auto tailAuth = execution(*key, *tailPlan);
  ASSERT_OK(tailAuth);
  auto tailIo = std::make_shared<MemoryIo>(*tailPlan);
  tailIo->sources = *encoded;
  tailIo->missing = 2;
  auto tailResult = blockingWait(EcRmwExecution::run(*tailAuth, {}, tailIo));
  ASSERT_OK(tailResult);
  auto tailBytes = EcCodec::encode(std::string(117, 'o'), 31);
  ASSERT_OK(tailBytes);
  EXPECT_EQ(tailIo->output, *tailBytes);
  auto stamp = AuthorizationTestAccess::computed(*key, **tailPlan, tailResult->commitment);
  ASSERT_OK(stamp);
  const auto stampWire = EcRmwWireCodec::encode(*stamp);
  ASSERT_EQ(stampWire.size(), kEcRmwComputedWireBytes);
  auto stampRead = EcRmwWireCodec::computed(stampWire);
  ASSERT_OK(stampRead);
  ASSERT_OK(EcRmwComputationAuthorization::verify(*key, *tailPlan, *stampRead));

  io->throwRead = true;
  auto readFailed = blockingWait(EcRmwExecution::run(*auth, patch, io));
  ASSERT_FALSE(readFailed);
  EXPECT_EQ(readFailed.error().code(), StatusCode::kNotEnoughMemory);
  io->throwRead = false;
  io->throwWrite = true;
  auto writeFailed = blockingWait(EcRmwExecution::run(*auth, patch, io));
  ASSERT_FALSE(writeFailed);
  EXPECT_EQ(writeFailed.error().code(), StorageCode::kEcSealOutcomeUnknown);
}
TEST(TestEcRmw, ShortSubmitAndStopJoinTheActualOwnedTask) {
  const std::string patch = "owned";
  auto plan = EcRmwPlan::create(zeroPlan(patch));
  ASSERT_OK(plan);
  auto key = AuthorizationTestAccess::key();
  auto grant = AuthorizationTestAccess::grant(*key, **plan);
  ASSERT_OK(grant);
  auto runtime = EcRmwRuntime::create(key, Uuid::from(91, 92), (*plan)->worker().nodeId, [] { return uint64_t(1000); });
  ASSERT_OK(runtime);
  auto io = std::make_shared<MemoryIo>(*plan);
  io->delay = true;
  auto entered = io->entered.get_future();
  auto cleanup = folly::makeGuard([&] {
    io->resume.post();
    auto joined = (*runtime)->stopAndJoin();
    EXPECT_TRUE(bool(joined)) << (joined ? "" : joined.error().describe());
  });
  ASSERT_OK(RuntimeTestAccess::install(**runtime, *plan, *grant, io));
  ASSERT_OK((*runtime)->put((*plan)->input().planId, *grant, 0, patch));
  ASSERT_OK((*runtime)->submit((*plan)->input().planId, *grant));
  ASSERT_EQ(entered.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  auto running = (*runtime)->query((*plan)->input().planId, *grant);
  ASSERT_OK(running);
  EXPECT_EQ(running->state, EcRmwLocalState::Running);
  auto stopped = std::async(std::launch::async, [&] { return (*runtime)->stopAndJoin(); });
  EXPECT_EQ(stopped.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
  io->resume.post();
  ASSERT_OK(stopped.get());
  auto done = (*runtime)->query((*plan)->input().planId, *grant);
  ASSERT_OK(done);
  EXPECT_EQ(done->state, EcRmwLocalState::Complete);
  EXPECT_EQ(done->error, StatusCode::kOK);
  ASSERT_TRUE(done->sealed);
  EXPECT_EQ(io->binds, 1);
  EXPECT_EQ(io->writes, 12);
  std::atomic<uint64_t> clock{1000};
  auto idle = EcRmwRuntime::create(key, Uuid::from(91, 92), (*plan)->worker().nodeId, [&] { return clock.load(); });
  ASSERT_OK(idle);
  auto closeIdle = folly::makeGuard([&] {
    auto joined = (*idle)->stopAndJoin();
    EXPECT_TRUE(bool(joined)) << (joined ? "" : joined.error().describe());
  });
  auto held = std::make_shared<MemoryIo>(*plan);
  std::weak_ptr<EcRmwIo> lifetime = held;
  ASSERT_OK(RuntimeTestAccess::install(**idle, *plan, *grant, held));
  held.reset();
  clock.store(1101);
  auto renewed = AuthorizationTestAccess::grant(*key, **plan, kEcRmwAllRights, 1101);
  ASSERT_OK(renewed);
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  for (;;) {
    auto observed = (*idle)->query((*plan)->input().planId, *renewed);
    ASSERT_OK(observed);
    if (observed->state == EcRmwLocalState::Complete) {
      EXPECT_NE(observed->error, StatusCode::kOK);
      break;
    }
    ASSERT_LT(std::chrono::steady_clock::now(), until);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  EXPECT_TRUE(lifetime.expired());  // Receiving never submitted: old scope/lease no longer retained.
}

TEST(TestEcRmw, TransportAffinityRejectsMutationsButKeepsQueryAndJoin) {
  using Policy = EcRmwRuntime::TransportPolicy;
  const std::string patch = "transport-owned";
  auto plan = EcRmwPlan::create(zeroPlan(patch));
  ASSERT_OK(plan);
  auto key = AuthorizationTestAccess::key();
  auto grant = AuthorizationTestAccess::grant(*key, **plan);
  ASSERT_OK(grant);
  auto runtime = EcRmwRuntime::create(key, Uuid::from(91, 92), (*plan)->worker().nodeId, [] { return uint64_t(1000); });
  ASSERT_OK(runtime);
  auto io = std::make_shared<MemoryIo>(*plan);
  io->delay = true;
  auto entered = io->entered.get_future();
  auto cleanup = folly::makeGuard([&] {
    io->resume.post();
    EXPECT_TRUE(bool((*runtime)->stopAndJoin()));
  });
  // Real Runtime worker/session state with memory IO, not an RDMA network test.
  ASSERT_OK(RuntimeTestAccess::install(**runtime, *plan, *grant, io, Policy::RdmaOnly));
  ASSERT_ERROR((*runtime)->prepareInstall(*plan, *grant, Policy::TcpOnly), StatusCode::kTokenMismatch);
  ASSERT_ERROR((*runtime)->put((*plan)->input().planId, *grant, 0, patch), StatusCode::kTokenMismatch);
  auto receiving = (*runtime)->query((*plan)->input().planId, *grant);
  ASSERT_OK(receiving);
  EXPECT_EQ(receiving->state, EcRmwLocalState::Receiving);
  EXPECT_EQ(receiving->received.count(), 0);
  ASSERT_OK((*runtime)->put((*plan)->input().planId, *grant, 0, patch, Policy::RdmaOnly));
  ASSERT_ERROR((*runtime)->submit((*plan)->input().planId, *grant), StatusCode::kTokenMismatch);
  ASSERT_OK((*runtime)->submit((*plan)->input().planId, *grant, Policy::RdmaOnly));
  ASSERT_EQ(entered.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  ASSERT_ERROR((*runtime)->prepareInstall(*plan, *grant), StatusCode::kTokenMismatch);
  auto replay = (*runtime)->prepareInstall(*plan, *grant, Policy::RdmaOnly);
  ASSERT_OK(replay);
  EXPECT_FALSE(*replay);  // Matching replay observes; it cannot start another job.
  auto running = (*runtime)->query((*plan)->input().planId, *grant);
  ASSERT_OK(running);
  EXPECT_EQ(running->state, EcRmwLocalState::Running);
  auto stopped = std::async(std::launch::async, [&] { return (*runtime)->stopAndJoin(); });
  EXPECT_EQ(stopped.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
  io->resume.post();
  ASSERT_OK(stopped.get());
  auto done = (*runtime)->query((*plan)->input().planId, *grant);
  ASSERT_OK(done);
  EXPECT_EQ(done->state, EcRmwLocalState::Complete);
  EXPECT_EQ(done->error, StatusCode::kOK);
  EXPECT_EQ(io->binds, 1);
  EXPECT_EQ(io->writes, 12);
}

TEST(TestEcRmw, TransportInstallReservationSurvivesAdmissionGap) {
  using Policy = EcRmwRuntime::TransportPolicy;
  const std::string patch = "reserved";
  auto first = EcRmwPlan::create(zeroPlan(patch));
  ASSERT_OK(first);
  auto input = zeroPlan(patch);
  input.planId = Uuid::from(205, 206);
  input.operationId = Uuid::from(211, 212);
  auto second = EcRmwPlan::create(input);
  ASSERT_OK(second);
  auto key = AuthorizationTestAccess::key();
  auto firstGrant = AuthorizationTestAccess::grant(*key, **first);
  auto secondGrant = AuthorizationTestAccess::grant(*key, **second);
  ASSERT_OK(firstGrant);
  ASSERT_OK(secondGrant);
  auto runtime = EcRmwRuntime::create(key, Uuid::from(91, 92), (*first)->worker().nodeId, [] { return uint64_t(1000); });
  ASSERT_OK(runtime);
  auto firstIo = std::make_shared<MemoryIo>(*first);
  auto secondIo = std::make_shared<MemoryIo>(*second);
  ASSERT_OK(RuntimeTestAccess::install(**runtime, *first, *firstGrant, firstIo));
  std::promise<Result<bool>> prepared;
  auto atGap = prepared.get_future();
  std::promise<void> resume;
  auto resumeFuture = resume.get_future();
  std::future<Result<Void>> late;
  bool unblocked = false;
  auto cleanup = folly::makeGuard([&] {
    if (!unblocked) resume.set_value();
    if (late.valid()) late.wait();
    EXPECT_TRUE(bool((*runtime)->stopAndJoin()));
  });
  // An actual concurrent installer pauses after Runtime has released its idle
  // Entry, at the production admission-await boundary (no synthetic result).
  late = std::async(std::launch::async, [&]() -> Result<Void> {
    auto wanted = (*runtime)->prepareInstall(*first, *firstGrant, Policy::TcpOnly);
    const bool continueInstall = wanted && *wanted;
    prepared.set_value(std::move(wanted));
    resumeFuture.wait();
    if (!continueInstall) return makeError(StatusCode::kInvalidArg);
    return RuntimeTestAccess::install(**runtime, *first, *firstGrant, firstIo);
  });
  ASSERT_EQ(atGap.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  auto preparedFirst = atGap.get();
  ASSERT_OK(preparedFirst);
  ASSERT_TRUE(*preparedFirst);
  ASSERT_ERROR((*runtime)->query((*first)->input().planId, *firstGrant), StatusCode::kKVStoreNotFound);
  ASSERT_ERROR((*runtime)->prepareInstall(*first, *firstGrant, Policy::RdmaOnly), StatusCode::kTokenMismatch);
  auto preparedSecond = (*runtime)->prepareInstall(*second, *secondGrant, Policy::RdmaOnly);
  ASSERT_OK(preparedSecond);
  ASSERT_TRUE(*preparedSecond);
  ASSERT_OK(RuntimeTestAccess::install(**runtime, *second, *secondGrant, secondIo, Policy::RdmaOnly));
  resume.set_value();
  unblocked = true;
  ASSERT_ERROR(late.get(), StatusCode::kTokenMismatch);
  auto retained = (*runtime)->query((*second)->input().planId, *secondGrant);
  ASSERT_OK(retained);
  EXPECT_EQ(retained->state, EcRmwLocalState::Receiving);
  EXPECT_EQ(retained->received.count(), 0);
  ASSERT_ERROR((*runtime)->put((*second)->input().planId, *secondGrant, 0, patch), StatusCode::kTokenMismatch);
  ASSERT_OK((*runtime)->put((*second)->input().planId, *secondGrant, 0, patch, Policy::RdmaOnly));
  EXPECT_EQ(firstIo->binds, 0);
  EXPECT_EQ(secondIo->binds, 0);
}
}  // namespace
}  // namespace hf3fs::storage
