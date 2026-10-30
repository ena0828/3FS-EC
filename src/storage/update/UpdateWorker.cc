#include "storage/update/UpdateWorker.h"

namespace hf3fs::storage {

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

  for (auto i = 0u; i < config_.num_threads() && !queueVec_.empty(); ++i) {
    queueVec_[i % queueVec_.size()]->enqueue(QueueItem{});
  }
  executors_.join();
  bgExecutors_.join();
}

void UpdateWorker::run(Queue &queue) {
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
    const auto execute = [](auto *ecJob, auto operation, bool durableOperation) {
      try {
        auto route = ecJob->validateRoute();
        if (!route) {
          ecJob->setResult(makeError(route.error()));
          return;
        }
        ecJob->setResult((ecJob->target().get()->*operation)(ecJob->request()));
      } catch (const std::exception &error) {
        ecJob->setResult(makeError(
            durableOperation ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError,
            fmt::format("{}: {}",
                        durableOperation ? "EC durable worker operation failed; retain allocation and reconcile outcome"
                                         : "EC read worker failed",
                        error.what())));
      } catch (...) {
        ecJob->setResult(
            makeError(durableOperation ? StorageCode::kEcSealOutcomeUnknown : StorageCode::kChunkMetadataGetError,
                      durableOperation ? "EC durable worker operation failed; retain allocation and reconcile outcome"
                                       : "EC read worker failed"));
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
