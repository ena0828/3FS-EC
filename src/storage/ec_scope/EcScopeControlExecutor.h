#pragma once

#include <atomic>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <functional>

#include "common/utils/BoundedQueue.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Semaphore.h"
#include "fbs/storage/EcScopeControl.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// Separate bounded control executor: it never waits for in-flight data to
// drain and cannot be starved by a full data admission/UpdateWorker queue.
class EcScopeControlExecutor final {
 public:
  using Clock = std::function<uint64_t()>;
  static Result<std::unique_ptr<EcScopeControlExecutor>> create(std::shared_ptr<const EcScopeControlKey> key,
                                                                Uuid clusterAuthority,
                                                                NodeId localNode,
                                                                Clock clock);
  ~EcScopeControlExecutor();
  CoTryTask<EcScopeControlAck> execute(EcScopeControlAction action,
                                       EcScopeControlRequest request,
                                       std::shared_ptr<StorageTarget> target);
  Result<Void> validateRequest(EcScopeControlAction action, const EcScopeControlRequest &request) const;
  void stopAndJoin();

 private:
  struct Job;
  EcScopeControlExecutor(std::shared_ptr<const EcScopeControlKey> key, Uuid authority, NodeId node, Clock clock);
  Result<EcScopeControlAck> process(const Job &job);
  void run();
  std::shared_ptr<const EcScopeControlKey> key_;
  Uuid authority_;
  NodeId node_;
  Clock clock_;
  Uuid bootNonce_ = Uuid::random();
  BoundedQueue<Job *> queue_{64};
  Semaphore budget_{64, 64};
  std::shared_ptr<EcWorkerSessions> sessions_ = std::make_shared<EcWorkerSessions>();
  folly::CPUThreadPoolExecutor executor_{1};
  std::atomic_flag stopped_{};
};
}  // namespace hf3fs::storage
