#pragma once

#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/experimental/coro/WithCancellation.h>
#include <new>
#include <type_traits>
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

  // EC admission is deliberately non-waiting. Full queues reject before any
  // worker owns the job; callers retain the same operation identity on retry.
  CoTask<void> enqueue(EcAdmissionJob *job) { return enqueueEc(job); }
  CoTask<void> enqueue(EcStageJob *job) { return enqueueEc(job); }
  CoTask<void> enqueue(EcCreateJob *job) { return enqueueEc(job); }
  CoTask<void> enqueue(EcReadJob *job) { return enqueueEc(job); }
  CoTask<void> enqueue(EcReconcileJob *job) { return enqueueEc(job); }

  CoTask<void> enqueue(UpdateJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
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
  bool isCurrentWorkerThread() const noexcept;
  template <typename Job>
  static void rejectBeforeQueue(Job *job, uint16_t code) {
    if constexpr (std::is_same_v<Job, EcAdmissionJob>) {
      job->reject(Status(code));
    } else {
      job->setResult(makeError(code));
    }
  }
  template <typename Job>
  CoTask<void> enqueueEc(Job *job) {
    // Must precede every rejection: a duplicate submission never completes or
    // wakes the original request as a side effect of its validation failure.
    job->claimSubmission();
    try {
      if (isCurrentWorkerThread() || !job->sessionMatches(ecSessions_) || !job->target() ||
          job->target()->diskIndex() >= queueVec_.size()) {
        rejectBeforeQueue(job, StatusCode::kInvalidArg);
        co_return;
      }
      if constexpr (std::is_same_v<Job, EcStageJob>) {
        auto valid = job->validateSubmission();
        if (!valid) {
          job->setResult(makeError(std::move(valid.error())));
          co_return;
        }
      }
      auto &queue = *queueVec_[job->target()->diskIndex()];
      if (!queue.try_enqueueWithCommit(QueueItem{job}, [job]() noexcept { job->commitQueued(); })) {
        rejectBeforeQueue(job, StorageClientCode::kResourceBusy);
      }
    } catch (const std::bad_alloc &) {
      if (job->queued()) {
        job->awaitSubmittedAfterFailure();
      } else {
        rejectBeforeQueue(job, StatusCode::kNotEnoughMemory);
      }
    } catch (...) {
      if (job->queued()) {
        job->awaitSubmittedAfterFailure();
      } else {
        rejectBeforeQueue(job, StorageCode::kChunkMetadataGetError);
      }
    }
  }
  ConstructLog<"storage::UpdateWorker"> constructLog_;
  const Config &config_;
  std::vector<std::unique_ptr<Queue>> queueVec_;
  folly::CPUThreadPoolExecutor executors_;
  folly::CPUThreadPoolExecutor bgExecutors_;
  std::shared_ptr<EcWorkerSessions> ecSessions_ = std::make_shared<EcWorkerSessions>();
  std::atomic_flag stopped_;
};

}  // namespace hf3fs::storage
