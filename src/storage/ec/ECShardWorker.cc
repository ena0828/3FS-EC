#include "storage/ec/ECShardWorker.h"

namespace hf3fs::storage::ec {

Result<Void> ECShardWorker::start(uint32_t numberOfDisks) {
  std::lock_guard stopLock(stopMutex_);
  std::unique_lock lock(mutex_);
  if (state_ != State::New) return makeError(StatusCode::kInvalidArg, "EC worker is one-shot");
  if (numberOfDisks == 0 || queueCapacity_ == 0 || queueCapacity_ > 8)
    return makeError(StatusCode::kInvalidConfig, "EC worker needs disks and 1..8 queue slots per disk");
  try {
    queues_.reserve(numberOfDisks);
    threads_.reserve(numberOfDisks);
    for (uint32_t i = 0; i < numberOfDisks; ++i)
      queues_.push_back(std::make_unique<DiskQueue>(queueCapacity_));
    state_ = State::Running;
    for (uint32_t i = 0; i < numberOfDisks; ++i)
      threads_.emplace_back([this, i] { run(i); });
  } catch (...) {
    // No enqueue can observe partial startup: mutex_ is still held here.
    state_ = State::Stopping;
    lock.unlock();
    cv_.notify_all();
    for (auto &thread : threads_) thread.join();
    lock.lock();
    threads_.clear();
    queues_.clear();
    state_ = State::Stopped;
    return makeError(StatusCode::kOSError, "EC worker startup failed");
  }
  return Void{};
}

Result<Void> ECShardWorker::enqueue(std::shared_ptr<ECShardJob> job) {
  std::lock_guard lock(mutex_);
  if (state_ != State::Running) return makeError(RPCCode::kRequestRefused, "EC worker is not running");
  if (!job || !job->target_ || job->target_->diskIndex() >= queues_.size())
    return makeError(StatusCode::kInvalidArg, "EC job has no local disk queue");
  if (job->type_ == ECShardJob::Type::Write && job->payload_.size() != erasure::ECLayout::kShardSize)
    return makeError(StatusCode::kInvalidArg, "EC job payload must be one complete shard");
  auto &queue = *queues_[job->target_->diskIndex()];
  if (queue.count == queueCapacity_) return makeError(StatusCode::kQueueFull);
  if (!job->claim()) return makeError(StatusCode::kQueueConflict, "EC job already submitted");
  // Preallocated ring: no allocation/throw between claiming and publishing Job.
  queue.slots[(queue.head + queue.count) % queueCapacity_] = std::move(job);
  ++queue.count;
  cv_.notify_all();
  return Void{};
}

void ECShardWorker::stopAndJoin() {
  std::lock_guard stopLock(stopMutex_);
  {
    std::lock_guard lock(mutex_);
    if (state_ == State::Stopped) return;
    state_ = State::Stopping;
  }
  cv_.notify_all();
  for (auto &thread : threads_) thread.join();
  {
    std::lock_guard lock(mutex_);
    threads_.clear();
    queues_.clear();
    state_ = State::Stopped;
  }
}

void ECShardWorker::run(size_t disk) {
  for (;;) {
    std::shared_ptr<ECShardJob> job;
    {
      std::unique_lock lock(mutex_);
      auto &queue = *queues_[disk];
      cv_.wait(lock, [&] { return queue.count != 0 || state_ != State::Running; });
      if (queue.count == 0) return;  // Stopping: all this disk's accepted Jobs drained.
      job = std::move(queue.slots[queue.head]);
      queue.head = (queue.head + 1) % queueCapacity_;
      --queue.count;
    }
    execute(job);  // Never hold queue/admission mutex during I/O or notification.
  }
}

void ECShardWorker::execute(const std::shared_ptr<ECShardJob> &job) {
  try {
    if (beforeExecuteForTest_) beforeExecuteForTest_(job);
    if (job->type_ == ECShardJob::Type::Write) {
      job->finish(ECShardJob::Completion(std::in_place_type<ECShardJob::WriteResult>,
          job->target_->writeECShard(job->key_, job->version_, job->validBytes_, job->payload_,
                                    job->scheme_, job->format_)));
    } else {
      job->finish(ECShardJob::Completion(std::in_place_type<ECShardJob::ReadResult>,
          job->target_->readECShard(job->key_, job->version_, job->scheme_, job->format_)));
    }
  } catch (...) {
    // Includes non-std exceptions. Preserve the completion alternative even when
    // no Target result was produced. Do not allocate an exception message here.
    if (job->type_ == ECShardJob::Type::Write)
      job->finish(ECShardJob::Completion(std::in_place_type<ECShardJob::WriteResult>,
                                       makeError(StatusCode::kUnknown)));
    else
      job->finish(ECShardJob::Completion(std::in_place_type<ECShardJob::ReadResult>,
                                       makeError(StatusCode::kUnknown)));
  }
}

}  // namespace hf3fs::storage::ec
