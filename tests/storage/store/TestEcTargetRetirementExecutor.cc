#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <functional>
#include <future>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>
#include <type_traits>

#include "fbs/storage/EcTargetRetirementControl.h"
#include "storage/ec_scope/EcTargetRetirementExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
class EcTargetRetirementExecutorTestAccess {
 public:
  static CoTryTask<EcTargetRetirementObservation> execute(EcTargetRetirementExecutor &executor,
                                                          EcTargetRetirementAction action,
                                                          EcTargetRetirementRequest request,
                                                          std::shared_ptr<StorageTarget> target,
                                                          void (*beforeAwait)()) {
    return executor.executeImpl(action, std::move(request), std::move(target), beforeAwait);
  }
};
namespace {
constexpr uint64_t issued = 1700000000;
Uuid uuid(uint8_t first) {
  Uuid value;
  for (size_t i = 0; i != 16; ++i) value.data[i] = first + i;
  return value;
}
Uuid uuid(const std::array<uint8_t, 16> &bytes) {
  Uuid value;
  std::copy(bytes.begin(), bytes.end(), std::begin(value.data));
  return value;
}
Result<std::unique_ptr<EcScopeControlKey>> testKey(const Path &directory, uint8_t offset = 0) {
  const auto path = directory / ("control-" + std::to_string(offset) + ".key");
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i != key.size(); ++i) key[i] = i + offset;
  std::ofstream output(path.string(), std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(key.data()), key.size());
  output.close();
  if (!output.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  return EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
}
EcTargetRetirementClaims claims() {
  EcTargetRetirementClaims value;
  value.clusterAuthority = uuid(1);
  value.nodeId = NodeId(61);
  value.chainId = ChainId(91);
  value.targetId = TargetId(92);
  value.engineUuid = uuid(21);
  value.targetIncarnation = uuid(41);
  value.retirementId = uuid(61);
  value.nonce = uuid(81);
  value.issuedAtSeconds = issued;
  value.expiresAtSeconds = issued + 60;
  return value;
}
EcScopeBinding readBinding(const EcScopeTargetIdentity &identity, uint8_t scopeId) {
  EcScopeBinding value{};
  value.target = identity;
  value.kind = 1;  // ReadPin; no target retirement substitutes its scope fence.
  value.object.fill(7);
  value.scope.fill(scopeId);
  value.owner_uid = 1000;
  value.client_namespace.fill(9);
  return value;
}
class TestEcTargetRetirementExecutor : public ::testing::Test {
 protected:
  void SetUp() override {
    auto loaded = testKey(keys.path());
    ASSERT_OK(loaded);
    key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    targets = std::make_unique<StorageTargets>(config, map);
    ASSERT_OK(targets->load(cpu));
    CreateTargetReq create;
    create.chainId = ChainId(91);
    create.targetId = TargetId(92);
    create.onlyChunkEngine = true;
    ASSERT_OK(targets->create(create, true));
    auto found = map.getByTargetId(create.targetId);
    ASSERT_OK(found);
    target = (*found)->storageTarget;
    ASSERT_TRUE(target->usesEcStagingEngine());
    auto state = target->ecScopeState();
    ASSERT_OK(state);
    scope = state->first;
    original = claims();
    original.chainId = create.chainId;
    original.targetId = create.targetId;
    original.engineUuid = uuid(state->second.engine);
    original.targetIncarnation = uuid(state->second.incarnation);
    binding = readBinding(state->second, 1);
    auto created =
        EcTargetRetirementExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
    ASSERT_OK(created);
    control = std::move(*created);
  }
  void TearDown() override {
    control.reset();
    scope.reset();
    target.reset();
    map.release().reset();
    targets.reset();
    key.reset();
  }
  Result<EcTargetRetirementObservation> execute(const EcTargetRetirementRequest &request, EcTargetRetirementAction action) {
    return folly::coro::blockingWait(control->execute(action, request, target));
  }
  folly::test::TemporaryDirectory directory;
  folly::test::TemporaryDirectory keys;
  CPUExecutorGroup cpu{1, "EcControlTest"};
  StorageTargets::Config config;
  AtomicallyTargetMap map;
  std::unique_ptr<StorageTargets> targets;
  std::shared_ptr<StorageTarget> target;
  std::shared_ptr<EcScope> scope;
  std::shared_ptr<const EcScopeControlKey> key;
  std::unique_ptr<EcTargetRetirementExecutor> control;
  EcTargetRetirementClaims original;
  EcScopeBinding binding{};
};

TEST_F(TestEcTargetRetirementExecutor, HeldScopesProducePendingThenLocalDataDrained) {
  auto second = readBinding(binding.target, 2);
  ASSERT_OK(scope->prepare(binding));
  ASSERT_OK(scope->prepare(second));
  auto request = signEcTargetRetirement(*key, original, issued);
  ASSERT_OK(request);
  {
    auto firstTicket = scope->tryAdmit(binding);
    auto secondTicket = scope->tryAdmit(second);
    ASSERT_OK(firstTicket);
    ASSERT_OK(secondTicket);
    auto pending = execute(*request, EcTargetRetirementAction::Prepare);
    ASSERT_OK(pending);
    ASSERT_OK(verifyEcTargetRetirementObservation(*key, *pending, *request));
    EXPECT_EQ(pending->claims.state, EcTargetRetirementState::Pending);
    EXPECT_TRUE(pending->claims.durable);
    EXPECT_EQ(pending->claims.inflight, 2);
    ASSERT_ERROR(firstTicket->checkExecution(), StatusCode::kTokenStale);
    ASSERT_ERROR(secondTicket->checkExecution(), StatusCode::kTokenStale);
    ASSERT_ERROR(scope->tryAdmit(binding), StatusCode::kTokenStale);
    ASSERT_ERROR(scope->prepare(readBinding(binding.target, 3)), StatusCode::kTokenStale);
  }
  auto intent = original;
  intent.action = EcTargetRetirementAction::Query;
  intent.nonce.data[0] ^= 1;
  auto query = signEcTargetRetirement(*key, intent, issued);
  ASSERT_OK(query);
  auto drained = execute(*query, EcTargetRetirementAction::Query);
  ASSERT_OK(drained);
  ASSERT_OK(verifyEcTargetRetirementObservation(*key, *drained, *query));
  EXPECT_EQ(drained->claims.state, EcTargetRetirementState::LocalDataDrained);
  EXPECT_TRUE(drained->claims.durable);
  EXPECT_EQ(drained->claims.inflight, 0);
  auto replay = execute(*request, EcTargetRetirementAction::Prepare);
  ASSERT_OK(replay);
  EXPECT_EQ(drained->claims.retirementDigest, replay->claims.retirementDigest);
  // A local target observation did not manufacture a scope T0/T2 record.
  EcScopeRevocation revocation{};
  revocation.binding = binding;
  revocation.id.fill(11);
  revocation.endpoint_set_digest.fill(12);
  ASSERT_ERROR(scope->drainStatus(revocation), StorageClientCode::kResourceBusy);
}

TEST_F(TestEcTargetRetirementExecutor, MissingAndMismatchedIntentNeverSigns) {
  auto query = original;
  query.action = EcTargetRetirementAction::Query;
  auto signedQuery = signEcTargetRetirement(*key, query, issued);
  ASSERT_OK(signedQuery);
  ASSERT_FALSE(execute(*signedQuery, EcTargetRetirementAction::Query));
  auto wrong = original;
  wrong.engineUuid.data[0] ^= 1;
  auto signedWrong = signEcTargetRetirement(*key, wrong, issued);
  ASSERT_OK(signedWrong);
  ASSERT_ERROR(execute(*signedWrong, EcTargetRetirementAction::Prepare), StatusCode::kTokenMismatch);
  auto request = signEcTargetRetirement(*key, original, issued);
  ASSERT_OK(request);
  ASSERT_ERROR(execute(*request, EcTargetRetirementAction::Query), StatusCode::kTokenMismatch);
  ASSERT_OK(scope->prepare(binding));
  ASSERT_OK(scope->tryAdmit(binding));
}

TEST_F(TestEcTargetRetirementExecutor, SameIdReplayCannotResurrectAdmission) {
  auto request = signEcTargetRetirement(*key, original, issued);
  ASSERT_OK(request);
  auto first = execute(*request, EcTargetRetirementAction::Prepare);
  ASSERT_OK(first);
  auto replay = execute(*request, EcTargetRetirementAction::Prepare);
  ASSERT_OK(replay);
  EXPECT_EQ(first->claims.retirementDigest, replay->claims.retirementDigest);
  auto changed = original;
  changed.retirementId.data[0] ^= 1;
  auto second = signEcTargetRetirement(*key, changed, issued);
  ASSERT_OK(second);
  ASSERT_ERROR(execute(*second, EcTargetRetirementAction::Prepare), StatusCode::kTokenMismatch);
  ASSERT_ERROR(scope->registerTarget(binding.target.chain, binding.target.target), StatusCode::kTokenStale);
  ASSERT_OK(scope->loadTarget(binding.target.chain, binding.target.target));
  ASSERT_ERROR(scope->prepare(binding), StatusCode::kTokenStale);
}

TEST_F(TestEcTargetRetirementExecutor, ColdReopenPreservesIdentityAndRetirement) {
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  CPUExecutorGroup cpu(1, "EcControlReopen");
  auto original = claims();
  original.chainId = ChainId(91);
  original.targetId = TargetId(92);
  Uuid priorBoot = Uuid::zero();
  for (unsigned reopen = 0; reopen != 2; ++reopen) {
    AtomicallyTargetMap map;
    StorageTargets targets(config, map);
    ASSERT_OK(targets.load(cpu));
    if (reopen == 0) {
      CreateTargetReq request;
      request.chainId = original.chainId;
      request.targetId = original.targetId;
      request.onlyChunkEngine = true;
      ASSERT_OK(targets.create(request, true));
    }
    auto target = map.getByTargetId(original.targetId);
    ASSERT_OK(target);
    auto state = (*target)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    if (reopen == 0) {
      original.engineUuid = uuid(state->second.engine);
      original.targetIncarnation = uuid(state->second.incarnation);
    } else {
      EXPECT_EQ(original.engineUuid, uuid(state->second.engine));
      EXPECT_EQ(original.targetIncarnation, uuid(state->second.incarnation));
      original.action = EcTargetRetirementAction::Query;
      original.nonce.data[0] ^= 1;
    }
    auto control =
        EcTargetRetirementExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
    ASSERT_OK(control);
    auto request = signEcTargetRetirement(*key, original, issued);
    ASSERT_OK(request);
    auto result = folly::coro::blockingWait((*control)->execute(original.action, *request, (*target)->storageTarget));
    ASSERT_OK(result);
    ASSERT_OK(verifyEcTargetRetirementObservation(*key, *result, *request));
    EXPECT_EQ(result->claims.state, EcTargetRetirementState::LocalDataDrained);
    if (reopen) EXPECT_NE(result->claims.bootNonce, priorBoot);
    priorBoot = result->claims.bootNonce;
    control->reset();
    // No ticket or scope handle crosses the physical close/reopen boundary.
  }
}

TEST_F(TestEcTargetRetirementExecutor, LegacyTargetCannotIssueObservation) {
  folly::test::TemporaryDirectory directory, keys;
  auto loaded = testKey(keys.path());
  ASSERT_OK(loaded);
  auto key = std::shared_ptr<const EcScopeControlKey>(std::move(*loaded));
  StorageTargets::Config config;
  config.set_target_paths({directory.path()});
  config.set_allow_disk_without_uuid(true);
  config.set_ec_only(true);
  CPUExecutorGroup cpu(1, "EcControlLegacy");
  AtomicallyTargetMap map;
  StorageTargets targets(config, map);
  ASSERT_OK(targets.load(cpu));
  CreateTargetReq create;
  create.chainId = ChainId(91);
  create.targetId = TargetId(92);
  create.onlyChunkEngine = true;
  ASSERT_OK(targets.create(create, true));
  auto target = map.getByTargetId(create.targetId);
  ASSERT_OK(target);
  ASSERT_OK((*target)->storageTarget->initializeEcScope(StorageTarget::EcScopeOpenMode::RegisterNew));
  auto state = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(state);
  auto original = claims();
  original.chainId = create.chainId;
  original.targetId = create.targetId;
  original.engineUuid = uuid(state->second.engine);
  original.targetIncarnation = uuid(state->second.incarnation);
  auto request = signEcTargetRetirement(*key, original, issued);
  ASSERT_OK(request);
  auto control =
      EcTargetRetirementExecutor::create(key, original.clusterAuthority, original.nodeId, [] { return issued + 1; });
  ASSERT_OK(control);
  ASSERT_ERROR(folly::coro::blockingWait((*control)->execute(original.action, *request, (*target)->storageTarget)),
               StorageCode::kTargetStateInvalid);
}

thread_local bool retirementTestCaller = false;
thread_local std::promise<void> *retirementWaitInjection = nullptr;
void throwRetirementAwaitBadAlloc() {
  retirementWaitInjection->set_value();
  throw std::bad_alloc();
}
void throwRetirementAwaitError() {
  retirementWaitInjection->set_value();
  throw std::runtime_error("test await construction");
}

TEST_F(TestEcTargetRetirementExecutor, PostEnqueueFailureAndStopWaitForRealWorker) {
  using namespace std::chrono_literals;
  for (bool badAlloc : {true, false}) {
    auto intent = original;
    // The second failure replays the same immutable retirement ID.
    auto request = signEcTargetRetirement(*key, intent, issued);
    ASSERT_OK(request);
    std::promise<void> entered, resume, injected;
    auto resumed = resume.get_future().share();
    std::atomic<bool> blocked{false};
    auto isolated = EcTargetRetirementExecutor::create(key, intent.clusterAuthority, intent.nodeId, [&] {
      if (!retirementTestCaller && !blocked.exchange(true)) {
        entered.set_value();
        resumed.wait();
      }
      return issued + 1;
    });
    ASSERT_OK(isolated);
    auto pending = std::async(std::launch::async, [&] {
      retirementTestCaller = true;
      retirementWaitInjection = &injected;
      SCOPE_EXIT { retirementWaitInjection = nullptr; };
      return folly::coro::blockingWait(
          EcTargetRetirementExecutorTestAccess::execute(**isolated,
                                                        EcTargetRetirementAction::Prepare,
                                                        *request,
                                                        target,
                                                        badAlloc ? throwRetirementAwaitBadAlloc : throwRetirementAwaitError));
    });
    auto unblock = folly::makeGuard([&] { resume.set_value(); });
    ASSERT_EQ(entered.get_future().wait_for(5s), std::future_status::ready);
    ASSERT_EQ(injected.get_future().wait_for(5s), std::future_status::ready);
    EXPECT_EQ(pending.wait_for(20ms), std::future_status::timeout);
    std::promise<void> stopStarted;
    auto stopper = std::async(std::launch::async, [&] {
      stopStarted.set_value();
      (*isolated)->stopAndJoin();
    });
    stopStarted.get_future().wait();
    EXPECT_EQ(stopper.wait_for(20ms), std::future_status::timeout);
    resume.set_value();
    unblock.dismiss();
    auto result = pending.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), StorageCode::kEcSealOutcomeUnknown);
    stopper.get();
    // Observe the actual durable deny through a normal separately-owned query;
    // the failed await must not be mistaken for "Prepare never executed".
    intent.action = EcTargetRetirementAction::Query;
    intent.nonce.data[0] ^= 1;
    auto query = signEcTargetRetirement(*key, intent, issued);
    ASSERT_OK(query);
    auto ack = execute(*query, EcTargetRetirementAction::Query);
    ASSERT_OK(ack);
    ASSERT_OK(verifyEcTargetRetirementObservation(*key, *ack, *query));
    EXPECT_EQ(ack->claims.state, EcTargetRetirementState::LocalDataDrained);
    EXPECT_TRUE(ack->claims.durable);
  }
}

TEST_F(TestEcTargetRetirementExecutor, ExpiredAfterPersistenceReturnsUnknown) {
  auto request = signEcTargetRetirement(*key, original, issued);
  ASSERT_OK(request);
  // Caller precheck + worker precheck are valid; the third clock read is the
  // post-persistence signing check. No extra RPC or persistence test seam.
  std::atomic<unsigned> calls{0};
  auto isolated = EcTargetRetirementExecutor::create(key, original.clusterAuthority, original.nodeId, [&] {
    return ++calls <= 2 ? issued + 1 : original.expiresAtSeconds;
  });
  ASSERT_OK(isolated);
  ASSERT_ERROR(folly::coro::blockingWait((*isolated)->execute(original.action, *request, target)),
               StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(calls.load(), 3u);
  auto intent = original;
  intent.action = EcTargetRetirementAction::Query;
  auto query = signEcTargetRetirement(*key, intent, issued);
  ASSERT_OK(query);
  auto observed = execute(*query, EcTargetRetirementAction::Query);
  ASSERT_OK(observed);
  EXPECT_EQ(observed->claims.state, EcTargetRetirementState::LocalDataDrained);
  ASSERT_ERROR(scope->prepare(binding), StatusCode::kTokenStale);
}
}  // namespace
}  // namespace hf3fs::storage
