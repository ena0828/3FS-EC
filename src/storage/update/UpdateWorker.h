#pragma once

#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/experimental/coro/WithCancellation.h>
#include <variant>

#include "common/utils/BoundedQueue.h"
#include "storage/store/StorageTargets.h"
#include "storage/update/EcAdmissionJob.h"
#include "storage/update/EcJob.h"
#include "storage/update/EcStageJob.h"
#include "storage/update/UpdateJob.h"

namespace hf3fs::storage {

class UpdateWorker {
 public:
  class Config : public ConfigBase<Config> {
    CONFIG_ITEM(queue_size, 4096u);
    CONFIG_ITEM(num_threads, 32ul);
    CONFIG_ITEM(bg_num_threads, 8ul);
  };

  UpdateWorker(const Config &config)
      : config_(config),
        executors_(std::make_pair(config_.num_threads(), config_.num_threads()),
                   std::make_shared<folly::NamedThreadFactory>("Update")),
        bgExecutors_(std::make_pair(config_.bg_num_threads(), config_.bg_num_threads()),
                     std::make_shared<folly::NamedThreadFactory>("Recycle")) {}
  ~UpdateWorker() { stopAndJoin(); }

  Result<Void> start(uint32_t numberOfDisks);
  void stopAndJoin();
  Result<std::shared_ptr<EcWorkerSession>> acquireEcSession() { return ecSessions_->acquire(); }

  CoTask<void> enqueue(EcAdmissionJob *job) {
    job->claimSubmission();
    if (!job->sessionMatches(ecSessions_)) {
      job->reject(Status(StatusCode::kInvalidArg, "EC admission session belongs to another worker"));
      co_return;
    }
    assert(job->target()->diskIndex() < queueVec_.size());
    // Once claimed, this borrowed job must either enqueue and complete or
    // remain owned. Semaphore::co_wait is cancellation-aware, unlike Baton.
    co_await folly::coro::co_withCancellation(folly::CancellationToken{},
                                              queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job}));
  }

  CoTask<void> enqueue(EcStageJob *job) {
    job->claimSubmission();
    if (!job->sessionMatches(ecSessions_)) {
      job->setResult(makeError(StatusCode::kInvalidArg, "stage session belongs to another worker"));
      co_return;
    }
    auto valid = job->validateSubmission();
    if (!valid) {
      job->setResult(makeError(valid.error()));
      co_return;
    }
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await folly::coro::co_withCancellation(folly::CancellationToken{},
                                              queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job}));
  }

  CoTask<void> enqueue(UpdateJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
  }

  CoTask<void> enqueue(EcCreateJob *job) {
    job->claimSubmission();
    if (!job->sessionMatches(ecSessions_)) {
      job->setResult(makeError(StatusCode::kInvalidArg, "scoped EC session belongs to another worker"));
      co_return;
    }
    assert(job->target()->diskIndex() < queueVec_.size());
    // Once claimed, this borrowed job must either enqueue and complete or
    // remain owned. Semaphore::co_wait is cancellation-aware, unlike Baton.
    co_await folly::coro::co_withCancellation(folly::CancellationToken{},
                                              queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job}));
  }

  CoTask<void> enqueue(EcReadJob *job) {
    job->claimSubmission();
    if (!job->sessionMatches(ecSessions_)) {
      job->setResult(makeError(StatusCode::kInvalidArg, "scoped EC session belongs to another worker"));
      co_return;
    }
    assert(job->target()->diskIndex() < queueVec_.size());
    // Once claimed, this borrowed job must either enqueue and complete or
    // remain owned. Semaphore::co_wait is cancellation-aware, unlike Baton.
    co_await folly::coro::co_withCancellation(folly::CancellationToken{},
                                              queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job}));
  }

  CoTask<void> enqueue(EcReconcileJob *job) {
    job->claimSubmission();
    if (!job->sessionMatches(ecSessions_)) {
      job->setResult(makeError(StatusCode::kInvalidArg, "scoped EC session belongs to another worker"));
      co_return;
    }
    assert(job->target()->diskIndex() < queueVec_.size());
    // Once claimed, this borrowed job must either enqueue and complete or
    // remain owned. Semaphore::co_wait is cancellation-aware, unlike Baton.
    co_await folly::coro::co_withCancellation(folly::CancellationToken{},
                                              queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job}));
  }

 protected:
  using QueueItem = std::variant<std::monostate,
                                 UpdateJob *,
                                 EcCreateJob *,
                                 EcReadJob *,
                                 EcReconcileJob *,
                                 EcAdmissionJob *,
                                 EcStageJob *>;
  using Queue = BoundedQueue<QueueItem>;
  void run(Queue &queue);

 private:
  ConstructLog<"storage::UpdateWorker"> constructLog_;
  const Config &config_;
  std::vector<std::unique_ptr<Queue>> queueVec_;
  folly::CPUThreadPoolExecutor executors_;
  folly::CPUThreadPoolExecutor bgExecutors_;
  std::shared_ptr<EcWorkerSessions> ecSessions_ = std::make_shared<EcWorkerSessions>();
  std::atomic_flag stopped_;
};

}  // namespace hf3fs::storage
