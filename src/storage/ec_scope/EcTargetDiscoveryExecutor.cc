#include "EcTargetDiscoveryExecutor.h"

#include <algorithm>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <new>

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
namespace {
thread_local const EcTargetDiscoveryExecutor *currentDiscoveryWorker = nullptr;
}
struct EcTargetDiscoveryExecutor::Job {
  struct Completion {
    folly::coro::Baton ready;
    std::atomic<bool> finished{false};
  };
  EcTargetDiscoveryRequest request;
  std::shared_ptr<StorageTarget> target;
  Result<EcTargetDiscoveryObservation> result{makeError(StorageClientCode::kNotInitialized)};
  // Allocated before enqueue; the worker retains it after its last Job use.
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  bool submitted = false;
  bool observedCompletion = false;
  ~Job() {
    if (submitted && !observedCompletion) std::terminate();
  }
};

EcTargetDiscoveryExecutor::EcTargetDiscoveryExecutor(std::shared_ptr<const EcScopeControlKey> key,
                                                     Uuid authority,
                                                     NodeId node,
                                                     Clock clock)
    : key_(std::move(key)),
      authority_(authority),
      node_(node),
      clock_(std::move(clock)) {
  executor_.add([this] { run(); });
}
Result<std::unique_ptr<EcTargetDiscoveryExecutor>> EcTargetDiscoveryExecutor::create(
    std::shared_ptr<const EcScopeControlKey> key,
    Uuid authority,
    NodeId node,
    Clock clock) {
  if (!key || authority.is_nil() || node == NodeId{} || !clock) {
    return makeError(StatusCode::kInvalidConfig,
                     "EC discovery executor requires explicit key, authority, node and clock");
  }
  return std::unique_ptr<EcTargetDiscoveryExecutor>(
      new EcTargetDiscoveryExecutor(std::move(key), authority, node, std::move(clock)));
}
EcTargetDiscoveryExecutor::~EcTargetDiscoveryExecutor() { stopAndJoin(); }
Result<Void> EcTargetDiscoveryExecutor::validateRequest(const EcTargetDiscoveryRequest &request) const {
  return verifyEcTargetDiscovery(*key_, request, authority_, node_, clock_());
}
void EcTargetDiscoveryExecutor::stopAndJoin() {
  if (stopped_.test_and_set()) return;
  // The calling coordinator thread must leave coroutine executors runnable.
  sessions_->closeAndWait();
  queue_.enqueue(nullptr);
  executor_.join();
}
CoTryTask<EcTargetDiscoveryObservation> EcTargetDiscoveryExecutor::execute(EcTargetDiscoveryRequest request,
                                                                           std::shared_ptr<StorageTarget> target) {
  return executeImpl(std::move(request), std::move(target), nullptr);
}
CoTryTask<EcTargetDiscoveryObservation> EcTargetDiscoveryExecutor::executeImpl(EcTargetDiscoveryRequest request,
                                                                               std::shared_ptr<StorageTarget> target,
                                                                               void (*beforeAwait)()) {
  if (currentDiscoveryWorker == this) {
    co_return makeError(StatusCode::kInvalidArg, "discovery worker cannot admit a reentrant request");
  }
  auto session = sessions_->acquire();
  if (!session) co_return makeError(session.error());
  if (!budget_.try_wait())
    co_return makeError(StorageClientCode::kResourceBusy, "EC discovery admission limit reached");
  auto releaseBudget = folly::makeGuard([this] { budget_.signal(); });
  auto verified = verifyEcTargetDiscovery(*key_, request, authority_, node_, clock_());
  if (!verified) co_return makeError(verified.error());
  if (!target || !target->usesEcStagingEngine()) {
    co_return makeError(StorageCode::kTargetStateInvalid, "EC discovery requires an already-loaded V2-only target");
  }
  Job job{std::move(request), std::move(target)};
  // No cancellable semaphore wait between submitted and actual queue entry.
  // The independent discovery budget and queue both have capacity 64.
  if (!queue_.try_enqueue(&job)) co_return makeError(StorageClientCode::kResourceBusy, "EC discovery queue is full");
  job.submitted = true;
  uint16_t waitError = 0;
  try {
    if (beforeAwait) beforeAwait();
    co_await job.completion->ready;
  } catch (const std::bad_alloc &) {
    waitError = StatusCode::kNotEnoughMemory;
  } catch (...) {
    waitError = StorageCode::kChunkMetadataGetError;
  }
  if (waitError) {
    // ViaIfAsync may allocate after enqueue. Do not unwind a borrowed Job.
    // This independent worker can finish while the caller waits synchronously;
    // worker reentry was rejected before admission to avoid self-wait.
    while (!job.completion->finished.load(std::memory_order_acquire)) {
      job.completion->finished.wait(false, std::memory_order_acquire);
    }
  }
  job.observedCompletion = true;
  if (waitError) co_return makeError(waitError);
  co_return std::move(job.result);
}
Result<EcTargetDiscoveryObservation> EcTargetDiscoveryExecutor::process(const Job &job) {
  RETURN_ON_ERROR(verifyEcTargetDiscovery(*key_, job.request, authority_, node_, clock_()));
  if (!job.target->usesEcStagingEngine())
    return makeError(StorageCode::kTargetStateInvalid, "discovery requires an initialized V2 target");
  CHECK_RESULT(state, job.target->ecScopeState());
  const auto &r = job.request.claims;
  if (state.second.chain != r.chainId.toUnderType() || state.second.target != r.targetId.toUnderType())
    return makeError(StatusCode::kTokenMismatch, "discovery logical target differs from actual instance");
  // loadTarget confirms existing metadata through the actual WAL; never call
  // registerTarget or open/create another Engine to satisfy a discovery.
  CHECK_RESULT(actual, state.first->loadTarget(r.chainId.toUnderType(), r.targetId.toUnderType()));
  RETURN_ON_ERROR(job.target->checkEcScopeTarget(actual));
  EcScopeEndpoint endpoint;
  endpoint.nodeId = node_;
  endpoint.chainId = ChainId(actual.chain);
  endpoint.targetId = TargetId(actual.target);
  std::copy(actual.engine.begin(), actual.engine.end(), std::begin(endpoint.engineUuid.data));
  std::copy(actual.incarnation.begin(), actual.incarnation.end(), std::begin(endpoint.targetIncarnation.data));
  RETURN_ON_ERROR(verifyEcTargetDiscovery(*key_, job.request, authority_, node_, clock_()));
  return ec_target_discovery_detail::Codec::signObserved(*key_, job.request, endpoint, clock_());
}
void EcTargetDiscoveryExecutor::run() {
  currentDiscoveryWorker = this;
  SCOPE_EXIT { currentDiscoveryWorker = nullptr; };
  while (auto *job = queue_.dequeue()) {
    auto completion = job->completion;
    try {
      job->result = process(*job);
    } catch (...) {
      // Keep the failure reporter allocation-free as well.
      job->result = makeError(StorageCode::kChunkMetadataGetError);
    }
    // No subsequent Job access: a synchronous fallback can now destroy it.
    completion->finished.store(true, std::memory_order_release);
    completion->finished.notify_all();
    completion->ready.post();
  }
}
}  // namespace hf3fs::storage
