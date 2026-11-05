#include "EcScopeControlExecutor.h"

#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
namespace {
thread_local const EcScopeControlExecutor *currentControlWorker = nullptr;
template <size_t N>
std::array<uint8_t, N> bytes(const Uuid &id) {
  static_assert(N == 16);
  std::array<uint8_t, N> result{};
  std::copy(std::begin(id.data), std::end(id.data), result.begin());
  return result;
}
EcScopeRevocation revokeBinding(const EcScopeControlClaims &claims) {
  EcScopeRevocation result{};
  result.binding.target.engine = bytes<16>(claims.engineUuid);
  result.binding.target.incarnation = bytes<16>(claims.targetIncarnation);
  result.binding.target.chain = claims.chainId.toUnderType();
  result.binding.target.target = claims.targetId.toUnderType();
  result.binding.object = bytes<16>(claims.object);
  result.binding.kind = static_cast<uint8_t>(claims.scopeKind);
  result.binding.scope = bytes<16>(claims.scopeId);
  result.binding.owner_uid = claims.ownerUid.toUnderType();
  result.binding.client_namespace = bytes<16>(claims.clientNamespace);
  result.id = bytes<16>(claims.revocationId);
  result.endpoint_set_digest = claims.endpointSetDigest;
  return result;
}
}  // namespace

struct EcScopeControlExecutor::Job {
  struct Completion {
    folly::coro::Baton ready;
    std::atomic<bool> finished{false};
  };
  EcScopeControlAction action;
  EcScopeControlRequest request;
  std::shared_ptr<StorageTarget> target;
  Result<EcScopeControlAck> result{makeError(StorageClientCode::kNotInitialized)};
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  bool submitted = false;
  bool observedCompletion = false;
  ~Job() {
    if (submitted && !observedCompletion) std::terminate();
  }
};

EcScopeControlExecutor::EcScopeControlExecutor(std::shared_ptr<const EcScopeControlKey> key,
                                               Uuid authority,
                                               NodeId node,
                                               Clock clock)
    : key_(std::move(key)),
      authority_(authority),
      node_(node),
      clock_(std::move(clock)) {
  executor_.add([this] { run(); });
}
Result<std::unique_ptr<EcScopeControlExecutor>>
EcScopeControlExecutor::create(std::shared_ptr<const EcScopeControlKey> key, Uuid authority, NodeId node, Clock clock) {
  if (!key || authority.is_nil() || node == NodeId{} || !clock) {
    return makeError(StatusCode::kInvalidConfig,
                     "EC control executor requires explicit key, authority, node and clock");
  }
  return std::unique_ptr<EcScopeControlExecutor>(
      new EcScopeControlExecutor(std::move(key), authority, node, std::move(clock)));
}
EcScopeControlExecutor::~EcScopeControlExecutor() { stopAndJoin(); }
Result<Void> EcScopeControlExecutor::validateRequest(EcScopeControlAction action,
                                                     const EcScopeControlRequest &request) const {
  return verifyEcScopeControl(*key_, request, authority_, node_, action, clock_());
}
void EcScopeControlExecutor::stopAndJoin() {
  if (stopped_.test_and_set()) return;
  // The calling coordinator thread must leave coroutine executors runnable.
  sessions_->closeAndWait();
  queue_.enqueue(nullptr);
  executor_.join();
}
CoTryTask<EcScopeControlAck> EcScopeControlExecutor::execute(EcScopeControlAction action,
                                                             EcScopeControlRequest request,
                                                             std::shared_ptr<StorageTarget> target) {
  return executeImpl(action, std::move(request), std::move(target), nullptr);
}
CoTryTask<EcScopeControlAck> EcScopeControlExecutor::executeImpl(EcScopeControlAction action,
                                                                 EcScopeControlRequest request,
                                                                 std::shared_ptr<StorageTarget> target,
                                                                 void (*beforeAwait)()) {
  if (currentControlWorker == this) {
    co_return makeError(StatusCode::kInvalidArg, "control worker cannot admit a reentrant request");
  }
  auto session = sessions_->acquire();
  if (!session) co_return makeError(session.error());
  if (!budget_.try_wait()) co_return makeError(StorageClientCode::kResourceBusy, "EC control admission limit reached");
  auto releaseBudget = folly::makeGuard([this] { budget_.signal(); });
  auto verified = verifyEcScopeControl(*key_, request, authority_, node_, action, clock_());
  if (!verified) co_return makeError(verified.error());
  if (!target || !target->usesEcStagingEngine()) {
    co_return makeError(StorageCode::kTargetStateInvalid,
                        "EC drain ACK requires a loaded V2-only target with no legacy data bypass");
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
    // work. Revoke may already be durable; retain the request for exact Query.
    while (!job.completion->finished.load(std::memory_order_acquire)) {
      job.completion->finished.wait(false, std::memory_order_acquire);
    }
    waitFailed = true;
  }
  job.observedCompletion = true;
  if (waitFailed) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  co_return std::move(job.result);
}
Result<EcScopeControlAck> EcScopeControlExecutor::process(const Job &job) {
  RETURN_ON_ERROR(verifyEcScopeControl(*key_, job.request, authority_, node_, job.action, clock_()));
  if (!job.target->usesEcStagingEngine()) {
    return makeError(StorageCode::kTargetStateInvalid, "EC control target is not a V2-only instance");
  }
  const auto revocation = revokeBinding(job.request.claims);
  RETURN_ON_ERROR(job.target->checkEcScopeTarget(revocation.binding.target));
  CHECK_RESULT(state, job.target->ecScopeState());
  auto &scope = state.first;
  Result<EcScopeDrainStatus> observation = makeError(StorageClientCode::kNotInitialized);
  if (job.action == EcScopeControlAction::Revoke) {
    observation = scope->revoke(revocation);
  } else {
    // Cold query restores a durable deny. Never register a missing target and
    // never translate an absent/failed fence lookup into Drained.
    auto loaded = scope->prepare(revocation.binding);
    if (!loaded && loaded.error().code() != StatusCode::kTokenStale) return makeError(loaded.error());
    observation = scope->drainStatus(revocation);
  }
  if (!observation) return makeError(observation.error());
  if (observation->drained != (observation->durable && observation->inflight == 0)) {
    return makeError(StatusCode::kFoundBug, "contradictory local EC drain observation; no ACK issued");
  }
  RETURN_ON_ERROR(job.target->checkEcScopeTarget(revocation.binding.target));
  const auto now = clock_();
  RETURN_ON_ERROR(verifyEcScopeControl(*key_, job.request, authority_, node_, job.action, now));
  return ec_scope_control_detail::Codec::signObserved(*key_,
                                                      job.request,
                                                      bootNonce_,
                                                      observation->durable,
                                                      observation->inflight,
                                                      now);
}
void EcScopeControlExecutor::run() {
  currentControlWorker = this;
  SCOPE_EXIT { currentControlWorker = nullptr; };
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
