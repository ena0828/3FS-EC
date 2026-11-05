#include "EcGcExecutor.h"

#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/WithCancellation.h>

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
namespace {
// In the exception path even error-message allocation can fail. This status
// intentionally does not format/copy an exception string after dispatch.
Result<EcGcAck> unknown() noexcept { return makeError(StorageCode::kEcSealOutcomeUnknown); }
}  // namespace

struct EcGcExecutor::Job {
  struct Completion {
    folly::coro::Baton ready;
    std::atomic<bool> finished{false};
  };
  EcGcAction action;
  EcGcRequest request;
  std::shared_ptr<StorageTarget> target;
  Result<EcGcAck> result{makeError(StorageClientCode::kNotInitialized)};
  // All allocation precedes enqueue. The worker retains this independent
  // owner after its final Job access, including across inline Baton resumes.
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  bool submitted = false;
  bool observedCompletion = false;
  folly::coro::Task<void> wait() {
    auto owned = completion;
    co_await owned->ready;
  }
  ~Job() {
    if (submitted && !observedCompletion) std::terminate();
  }
};

EcGcExecutor::EcGcExecutor(std::shared_ptr<const EcGcKey> key,
                           Uuid authority,
                           NodeId node,
                           Clock clock,
                           ReadOnly readOnly)
    : key_(std::move(key)),
      authority_(authority),
      node_(node),
      clock_(std::move(clock)),
      readOnly_(std::move(readOnly)),
      worker_([this] { run(); }),
      workerId_(worker_.get_id()) {}

Result<std::unique_ptr<EcGcExecutor>> EcGcExecutor::create(std::shared_ptr<const EcGcKey> key,
                                                           Uuid authority,
                                                           NodeId node,
                                                           Clock clock,
                                                           ReadOnly readOnly) {
  if (!key || authority.is_nil() || node == NodeId{} || !clock || !readOnly) {
    return makeError(StatusCode::kInvalidConfig, "GC executor requires explicit G key, authority, node and clock");
  }
  return std::unique_ptr<EcGcExecutor>(
      new EcGcExecutor(std::move(key), authority, node, std::move(clock), std::move(readOnly)));
}

EcGcExecutor::~EcGcExecutor() {
  // Failing fast on a violated ownership contract is preferable to deadlock
  // or detaching a worker that still references this object's queue and key.
  if (!stopAndJoin()) std::terminate();
}

Result<Void> EcGcExecutor::stopAndJoin() {
  if (std::this_thread::get_id() == workerId_) {
    return makeError(StatusCode::kInvalidArg, "GC worker cannot join its own requests");
  }
  std::unique_lock lock(stopMutex_);
  if (stopped_) return Void{};
  acceptingObservations_.store(false, std::memory_order_release);
  sessions_->closeAndWait();
  // Every admitted coroutine has observed its actual completion before the
  // sentinel. This is not a detached task or a timeout-based drain assertion.
  queue_.enqueue(nullptr);
  worker_.join();
  stopped_ = true;
  return Void{};
}

Result<Void> EcGcExecutor::validateDiscoveryRequest(const EcGcDiscoveryRequest &request) const {
  if (!acceptingObservations_.load(std::memory_order_acquire))
    return makeError(StorageClientCode::kResourceBusy, "GC executor is closing");
  return verifyEcGcDiscovery(*key_, request, authority_, node_, clock_());
}

Result<EcGcDiscoveryObservation> EcGcExecutor::observeCapabilities(
    const EcGcDiscoveryRequest &request,
    std::shared_ptr<StorageTarget> target,
    const std::function<Result<Void>()> &validateLoadedTarget) {
  try {
    if (std::this_thread::get_id() == workerId_ || !target || !validateLoadedTarget)
      return makeError(StatusCode::kInvalidArg);
    auto session = sessions_->acquire();
    RETURN_ON_ERROR(session);
    if (!budget_.try_wait()) return makeError(StorageClientCode::kResourceBusy);
    active_.fetch_add(1);
    auto release = folly::makeGuard([this] {
      active_.fetch_sub(1);
      budget_.signal();
    });
    RETURN_ON_ERROR(validateDiscoveryRequest(request));
    RETURN_ON_ERROR(validateLoadedTarget());
    const bool readOnly = readOnly_();
    CHECK_RESULT(actual, target->gcLocalTarget(node_));
    CHECK_RESULT(
        observed,
        ec_gc_discovery_detail::Codec::signObserved(*key_,
                                                    request,
                                                    actual,
                                                    authority_,
                                                    bootNonce_,
                                                    readOnly ? kEcGcDiscoveryQueryOnly : kEcGcDiscoveryCollectQuery,
                                                    clock_()));
    CHECK_RESULT(after, target->gcLocalTarget(node_));
    const auto &a = actual.endpoint;
    const auto &b = after.endpoint;
    if (a.nodeId != b.nodeId || a.chainId != b.chainId || a.targetId != b.targetId || a.engineUuid != b.engineUuid ||
        a.targetIncarnation != b.targetIncarnation || !after.enabled || after.dataProtocol != 2 ||
        after.diskFormat != 3 || after.gcProtocol != 1)
      return makeError(StorageCode::kTargetStateInvalid);
    // Keep the same session/target through the map fence and final fresh
    // authority/expiry/closing check. A later stop cannot invalidate an already
    // observed point in time, but every subsequent GC28 validates afresh.
    RETURN_ON_ERROR(validateLoadedTarget());
    if (readOnly_() != readOnly) return makeError(StorageClientCode::kResourceBusy, "GC admission policy changed");
    RETURN_ON_ERROR(validateDiscoveryRequest(request));
    return observed;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}

CoTryTask<EcGcAck> EcGcExecutor::execute(EcGcAction action,
                                         EcGcRequest request,
                                         std::shared_ptr<StorageTarget> target) {
  if (std::this_thread::get_id() == workerId_) {
    // A resumed caller may execute inline in Baton::post. Do not admit a new
    // request on this thread: its allocation-failure fallback could otherwise
    // synchronously wait for work that this same thread has not dequeued yet.
    co_return makeError(StatusCode::kInvalidArg, "GC worker cannot admit a reentrant request");
  }
  auto session = sessions_->acquire();
  if (!session) co_return makeError(session.error());
  if (!budget_.try_wait()) co_return makeError(StorageClientCode::kResourceBusy, "GC admission limit reached");
  active_.fetch_add(1);
  auto release = folly::makeGuard([this] {
    active_.fetch_sub(1);
    budget_.signal();
  });
  if (!target) co_return makeError(StorageCode::kTargetStateInvalid, "GC requires an actual loaded target");
  auto local = target->gcLocalTarget(node_);
  if (!local) co_return makeError(local.error());
  auto admitted = ec_gc_control_detail::Codec::verifyRequest(*key_, request, authority_, action, *local, clock_());
  if (!admitted) co_return makeError(admitted.error());
  if (action == EcGcAction::Collect && readOnly_()) co_return makeError(StatusCode::kReadOnlyMode);
  Job job{action, std::move(request), std::move(target)};
  // Capacity admission uses try_wait and enqueue uses try_enqueue: no
  // cancellable queue semaphore can strand a submitted stack-borrowing job.
  if (!queue_.try_enqueue(&job)) co_return makeError(StorageClientCode::kResourceBusy, "GC queue is full");
  job.submitted = true;
  // Baton itself is noncancellable. Make the ownership policy explicit for
  // future waiter changes: expiry/cancellation cannot discard submitted work.
  try {
    co_await folly::coro::co_withCancellation(folly::CancellationToken{}, job.wait());
  } catch (...) {
    // Creating the Task or its via-awaiter may allocate after enqueue. The
    // job is already borrowed: never unwind/destroy it until the real worker
    // finishes. atomic::wait is noexcept and needs no coroutine allocation.
    // This fallback cannot deadlock on this worker: finished is set before
    // posting the Baton, and the worker never touches Job after that store.
    while (!job.completion->finished.load(std::memory_order_acquire)) {
      job.completion->finished.wait(false, std::memory_order_acquire);
    }
    job.observedCompletion = true;
    co_return unknown();
  }
  job.observedCompletion = true;
  co_return std::move(job.result);
}

Result<EcGcAck> EcGcExecutor::process(const Job &job) {
  CHECK_RESULT(local, job.target->gcLocalTarget(node_));
  CHECK_RESULT(verified,
               ec_gc_control_detail::Codec::verifyRequest(*key_, job.request, authority_, job.action, local, clock_()));
  // No independent key, allocator position, bool "authorized", or synthetic
  // receipt crosses this boundary. Query selects the dedicated WAL-confirming
  // Rust query; it cannot execute Collect as a fallback when a ledger is absent.
  // A hot policy change while queued must be observed on the actual GC
  // worker immediately before mutation. Query only reconfirms a ledger.
  if (job.action == EcGcAction::Collect && readOnly_()) return makeError(StatusCode::kReadOnlyMode);
  auto receipt = job.target->executeGc(verified, node_);
  if (!receipt) return makeError(std::move(receipt.error()));
  auto after = job.target->gcLocalTarget(node_);
  if (!after) return unknown();
  // signConfirmed repeats auth/expiry/actual-instance checks. Anything failing
  // after the durable operation, including clock/sign allocation, is unknown.
  return ec_gc_control_detail::AckSigner::sign(*key_,
                                               verified,
                                               std::move(receipt),
                                               *after,
                                               authority_,
                                               bootNonce_,
                                               clock_());
}

void EcGcExecutor::run() noexcept {
  while (auto *job = queue_.dequeue()) {
    auto completion = job->completion;
    try {
      job->result = process(*job);
    } catch (...) {
      job->result = unknown();
    }
    // No Job access after publication: a fallback waiter may destroy Job
    // immediately. Completion keeps its Baton alive while post resumes normal
    // waiters inline, or while a fallback has already returned 4085.
    completion->finished.store(true, std::memory_order_release);
    completion->finished.notify_all();
    completion->ready.post();
  }
}
}  // namespace hf3fs::storage
