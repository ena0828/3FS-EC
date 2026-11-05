#include "storage/update/UpdateWorker.h"

#include <folly/ScopeGuard.h>

namespace hf3fs::storage {
namespace {
thread_local const UpdateWorker *currentEcUpdateWorker = nullptr;
}
bool UpdateWorker::isCurrentWorkerThread() const noexcept { return currentEcUpdateWorker == this; }

Result<Void> UpdateWorker::start(uint32_t numberOfDisks) {
  if (config_.num_threads() < numberOfDisks) {
    return makeError(StatusCode::kInvalidConfig,
                     fmt::format("too few update worker threads, {} < {}", config_.num_threads(), numberOfDisks));
  }

  queueVec_.reserve(numberOfDisks);
  for (auto i = 0u; i < numberOfDisks; ++i) {
    queueVec_.emplace_back(std::make_unique<Queue>(config_.queue_size()));
  }

  for (auto i = 0u; i < config_.num_threads(); ++i) {
    executors_.add([this, i] { run(*queueVec_[i % queueVec_.size()]); });
  }
  return Void{};
}

void UpdateWorker::stopAndJoin() {
  if (stopped_.test_and_set()) {
    return;
  }

  // Must run outside disk/proc workers. Existing sessions may still enqueue
  // their admitted jobs; wait before stop sentinels, not behind them.
  ecSessions_->closeAndWait();
  for (auto i = 0u; i < config_.num_threads() && !queueVec_.empty(); ++i) {
    queueVec_[i % queueVec_.size()]->enqueue(QueueItem{});
  }
  executors_.join();
  bgExecutors_.join();
}

void UpdateWorker::run(Queue &queue) {
  currentEcUpdateWorker = this;
  SCOPE_EXIT { currentEcUpdateWorker = nullptr; };
  while (true) {
    auto job = queue.dequeue();
    if (UNLIKELY(std::holds_alternative<std::monostate>(job))) {
      XLOGF(DBG, "Storage worker {} stop...", fmt::ptr(this));
      break;
    }

    if (auto *legacy = std::get_if<UpdateJob *>(&job)) {
      (*legacy)->target()->updateChunk(**legacy, bgExecutors_);
      continue;
    }
    if (auto *admission = std::get_if<EcAdmissionJob *>(&job)) {
      (*admission)->execute();
      continue;
    }
    if (auto *stage = std::get_if<EcStageJob *>(&job)) {
      (*stage)->execute();
      continue;
    }
    const auto execute = [](auto *ecJob, auto operation, bool durableOperation) {
      try {
        auto route = ecJob->validateRoute();
        if (route) route = ecJob->validateAdmission();
        if (!route) {
          ecJob->setResult(makeError(route.error()));
          return;
        }
        ecJob->setResult((ecJob->target().get()->*operation)(ecJob->request()));
      } catch (...) {
        ecJob->setResult(
            makeError(durableOperation ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError));
      }
    };
    if (auto *create = std::get_if<EcCreateJob *>(&job)) {
      execute(*create, &StorageTarget::createEcFragment, true);
    } else if (auto *read = std::get_if<EcReadJob *>(&job)) {
      execute(*read, &StorageTarget::readEcFragment, false);
    } else {
      execute(std::get<EcReconcileJob *>(job), &StorageTarget::reconcileEcFragment, true);
    }
  }
}

}  // namespace hf3fs::storage
