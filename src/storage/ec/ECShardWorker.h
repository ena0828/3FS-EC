#pragma once

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "storage/ec/ECShardJob.h"

namespace hf3fs::test {
struct ECShardWorkerTestHelper;
}

namespace hf3fs::storage::ec {

// Local one-shot worker. One consumer per disk, at most eight waiting Jobs per
// disk (the executing Job is additional). No retries, cancellation or RPCs.
class ECShardWorker {
 public:
  explicit ECShardWorker(size_t queueCapacity = 8) : queueCapacity_(queueCapacity) {}
  ~ECShardWorker() { stopAndJoin(); }
  ECShardWorker(const ECShardWorker &) = delete;
  ECShardWorker &operator=(const ECShardWorker &) = delete;

  Result<Void> start(uint32_t numberOfDisks);
  // QueueFull/RequestRefused/InvalidArg/QueueConflict mean NOT accepted: the
  // caller retains the Job and may retry a rejected, previously unsubmitted Job.
  Result<Void> enqueue(std::shared_ptr<ECShardJob> job);
  // Control threads only, never call from a worker. Stops admission, drains all
  // accepted Jobs, joins consumers, then frees queue resources. Concurrent stops
  // are serialized without holding the queue/admission lock while joining.
  void stopAndJoin();

 private:
  friend struct hf3fs::test::ECShardWorkerTestHelper;
  enum class State { New, Running, Stopping, Stopped };
  struct DiskQueue {
    explicit DiskQueue(size_t capacity) : slots(capacity) {}
    std::vector<std::shared_ptr<ECShardJob>> slots;
    size_t head = 0;
    size_t count = 0;
  };
  void run(size_t disk);
  void execute(const std::shared_ptr<ECShardJob> &job);

  const size_t queueCapacity_;
  std::mutex stopMutex_;  // start/stop/join serialization, never taken by consumers
  std::mutex mutex_;      // same admission gate for enqueue AND stop
  std::condition_variable cv_;
  State state_ = State::New;
  std::vector<std::unique_ptr<DiskQueue>> queues_;
  std::vector<std::thread> threads_;
  // Friend-configured before start only. Never invoked under mutex_.
  std::function<void(const std::shared_ptr<ECShardJob> &)> beforeExecuteForTest_;
};

}  // namespace hf3fs::storage::ec
