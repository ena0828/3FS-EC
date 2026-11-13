#include "EcTargetRetirementExecutor.h"

#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
namespace {
thread_local const EcTargetRetirementExecutor *currentRetirementWorker = nullptr;
template <size_t N>
std::array<uint8_t, N> bytes(const Uuid &id) {
  static_assert(N == 16);
  std::array<uint8_t, N> result{};
  std::copy(std::begin(id.data), std::end(id.data), result.begin());
  return result;
}
EcTargetRetirement retirementBinding(const EcTargetRetirementClaims &claims) {
  EcTargetRetirement result{};
  result.target.engine = bytes<16>(claims.engineUuid);
  result.target.incarnation = bytes<16>(claims.targetIncarnation);
  result.target.chain = claims.chainId.toUnderType();
  result.target.target = claims.targetId.toUnderType();
  result.id = bytes<16>(claims.retirementId);
  return result;
}

}  // namespace

struct EcTargetRetirementExecutor::Job {
  struct Completion {
    folly::coro::Baton ready;
    std::atomic<bool> finished{false};
  };
  EcTargetRetirementAction action;
  EcTargetRetirementRequest request;
  std::shared_ptr<StorageTarget> target;
  Result<EcTargetRetirementObservation> result{makeError(StorageClientCode::kNotInitialized)};
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  bool submitted = false;
  bool observedCompletion = false;
  ~Job() {
    if (submitted && !observedCompletion) std::terminate();
  }
};

EcTargetRetirementExecutor::EcTargetRetirementExecutor(std::shared_ptr<const EcScopeControlKey> key,
                                                       Uuid authority,
                                                       NodeId node,
                                                       Clock clock)
    : key_(std::move(key)),
      authority_(authority),
      node_(node),
      clock_(std::move(clock)) {
  executor_.add([this] { run(); });
}
Result<std::unique_ptr<EcTargetRetirementExecutor>>
EcTargetRetirementExecutor::create(std::shared_ptr<const EcScopeControlKey> key, Uuid authority, NodeId node, Clock clock) {
  if (!key || authority.is_nil() || node == NodeId{} || !clock) {
    return makeError(StatusCode::kInvalidConfig,
                     "EC control executor requires explicit key, authority, node and clock");
  }
  return std::unique_ptr<EcTargetRetirementExecutor>(
      new EcTargetRetirementExecutor(std::move(key), authority, node, std::move(clock)));
}
EcTargetRetirementExecutor::~EcTargetRetirementExecutor() { stopAndJoin(); }
Result<Void> EcTargetRetirementExecutor::validateRequest(EcTargetRetirementAction action,
                                                         const EcTargetRetirementRequest &request) const {
  return verifyEcTargetRetirement(*key_, request, authority_, node_, action, clock_());
}
void EcTargetRetirementExecutor::stopAndJoin() {
  if (stopped_.test_and_set()) return;
  // The calling coordinator thread must leave coroutine executors runnable.
  sessions_->closeAndWait();
  queue_.enqueue(nullptr);
  executor_.join();
}
CoTryTask<EcTargetRetirementObservation> EcTargetRetirementExecutor::execute(EcTargetRetirementAction action,
                                                                             EcTargetRetirementRequest request,
                                                                             std::shared_ptr<StorageTarget> target) {
  return executeImpl(action, std::move(request), std::move(target), nullptr);
}
CoTryTask<EcTargetRetirementObservation> EcTargetRetirementExecutor::executeImpl(EcTargetRetirementAction action,
                                                                                 EcTargetRetirementRequest request,
                                                                                 std::shared_ptr<StorageTarget> target,
                                                                                 void (*beforeAwait)()) {
  if (currentRetirementWorker == this) {
    co_return makeError(StatusCode::kInvalidArg, "control worker cannot admit a reentrant request");
  }
  auto session = sessions_->acquire();
  if (!session) co_return makeError(session.error());
  if (!budget_.try_wait()) co_return makeError(StorageClientCode::kResourceBusy, "EC control admission limit reached");
  auto releaseBudget = folly::makeGuard([this] { budget_.signal(); });
  auto verified = verifyEcTargetRetirement(*key_, request, authority_, node_, action, clock_());
  if (!verified) co_return makeError(verified.error());
  if (!target || !target->usesEcStagingEngine()) {
    co_return makeError(StorageCode::kTargetStateInvalid,
                        "Target retirement observation requires a loaded V2-only target with no legacy data bypass");
  }
  Job job{action, std::move(request), std::move(target)};
  // No cancellable semaphore wait between submitted and actual queue entry.
  // The independent control budget and queue both have capacity 64.
  if (!queue_.try_enqueue(&job)) co_return makeError(StorageClientCode::kResourceBusy, "EC control queue is full");
  job.submitted = true;
  bool waitFailed = false;
  try {
    if (beforeAwait) beforeAwait();
    co_await job.completion->ready;
  } catch (...) {
    // A ViaIfAsync allocation failure is not permission to abandon borrowed
    // work. Target retirement may already be durable; retain the request for exact Query.
    while (!job.completion->finished.load(std::memory_order_acquire)) {
      job.completion->finished.wait(false, std::memory_order_acquire);
    }
    waitFailed = true;
  }
  job.observedCompletion = true;
  if (waitFailed) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  co_return std::move(job.result);
}
Result<EcTargetRetirementObservation> EcTargetRetirementExecutor::process(const Job &job) {
  RETURN_ON_ERROR(verifyEcTargetRetirement(*key_, job.request, authority_, node_, job.action, clock_()));
  if (!job.target->usesEcStagingEngine()) {
    return makeError(StorageCode::kTargetStateInvalid, "EC control target is not a V2-only instance");
  }
  const auto retirement = retirementBinding(job.request.claims);
  RETURN_ON_ERROR(job.target->checkEcScopeTarget(retirement.target));
  CHECK_RESULT(state, job.target->ecScopeState());
  auto &scope = state.first;
  auto observation = job.action == EcTargetRetirementAction::Prepare
                         ? scope->prepareTargetRetirement(retirement)
                         : scope->queryTargetRetirement(retirement);
  if (!observation) return makeError(observation.error());
  if (observation->dataDrained != (observation->durable && observation->inflight == 0)) {
    return makeError(StatusCode::kFoundBug, "contradictory target observation; no signature issued");
  }
  // Persistent denial may already exist. A late identity/time failure is not
  // evidence of rollback; keep the original intent for authenticated Query.
  if (!job.target->checkEcScopeTarget(retirement.target))
    return makeError(StorageCode::kEcSealOutcomeUnknown);
  const auto now = clock_();
  if (!verifyEcTargetRetirement(*key_, job.request, authority_, node_, job.action, now))
    return makeError(StorageCode::kEcSealOutcomeUnknown);
  auto signedObservation = ec_target_retirement_detail::Codec::signObserved(*key_,
                                                                            job.request,
                                                                            bootNonce_,
                                                                            observation->durable,
                                                                            observation->inflight,
                                                                            now);
  if (!signedObservation) return makeError(StorageCode::kEcSealOutcomeUnknown);
  return signedObservation;
}
void EcTargetRetirementExecutor::run() {
  currentRetirementWorker = this;
  SCOPE_EXIT { currentRetirementWorker = nullptr; };
  while (auto *job = queue_.dequeue()) {
    auto completion = job->completion;
    try {
      job->result = process(*job);
    } catch (...) {
      job->result = makeError(StorageCode::kEcSealOutcomeUnknown);
    }
    // No Job access after release publication. Inline or fallback waiters may
    // destroy it; this independent shared owner keeps the Baton alive.
    completion->finished.store(true, std::memory_order_release);
    completion->finished.notify_all();
    completion->ready.post();
  }
}
}  // namespace hf3fs::storage
