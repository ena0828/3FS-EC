#pragma once

#include <folly/executors/CPUThreadPoolExecutor.h>
#include <variant>

#include "common/utils/BoundedQueue.h"
#include "storage/store/StorageTargets.h"
#include "storage/update/EcJob.h"
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

  CoTask<void> enqueue(UpdateJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
  }

  CoTask<void> enqueue(EcCreateJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
  }

  CoTask<void> enqueue(EcReadJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
  }

  CoTask<void> enqueue(EcReconcileJob *job) {
    assert(job->target()->diskIndex() < queueVec_.size());
    co_await queueVec_[job->target()->diskIndex()]->co_enqueue(QueueItem{job});
  }

 protected:
  using QueueItem = std::variant<std::monostate, UpdateJob *, EcCreateJob *, EcReadJob *, EcReconcileJob *>;
  using Queue = BoundedQueue<QueueItem>;
  void run(Queue &queue);

 private:
  ConstructLog<"storage::UpdateWorker"> constructLog_;
  const Config &config_;
  std::vector<std::unique_ptr<Queue>> queueVec_;
  folly::CPUThreadPoolExecutor executors_;
  folly::CPUThreadPoolExecutor bgExecutors_;
  std::atomic_flag stopped_;
};

}  // namespace hf3fs::storage
