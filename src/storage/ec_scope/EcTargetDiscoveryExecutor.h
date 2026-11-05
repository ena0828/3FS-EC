#pragma once

#include <atomic>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <functional>

#include "common/utils/BoundedQueue.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Semaphore.h"
#include "fbs/storage/EcTargetDiscovery.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// Bounded disk observation worker. It never registers or changes an identity,
// and its observations carry no drain or data-access authority.
class EcTargetDiscoveryExecutor final {
 public:
  using Clock = std::function<uint64_t()>;
  static Result<std::unique_ptr<EcTargetDiscoveryExecutor>> create(std::shared_ptr<const EcScopeControlKey> key,
                                                                   Uuid clusterAuthority,
                                                                   NodeId localNode,
                                                                   Clock clock);
  ~EcTargetDiscoveryExecutor();
  CoTryTask<EcTargetDiscoveryObservation> execute(EcTargetDiscoveryRequest request,
                                                  std::shared_ptr<StorageTarget> target);
  Result<Void> validateRequest(const EcTargetDiscoveryRequest &request) const;
  void stopAndJoin();

 private:
  friend class EcDiscoveryExecutorTestAccess;
  struct Job;
  // Private deterministic exception seam; public calls always pass nullptr.
  // No global allocator hook or user-request-controlled injection exists.
  CoTryTask<EcTargetDiscoveryObservation> executeImpl(EcTargetDiscoveryRequest,
                                                      std::shared_ptr<StorageTarget>,
                                                      void (*beforeAwait)());
  EcTargetDiscoveryExecutor(std::shared_ptr<const EcScopeControlKey> key, Uuid authority, NodeId node, Clock clock);
  Result<EcTargetDiscoveryObservation> process(const Job &job);
  void run();
  std::shared_ptr<const EcScopeControlKey> key_;
  Uuid authority_;
  NodeId node_;
  Clock clock_;
  BoundedQueue<Job *> queue_{64};
  Semaphore budget_{64, 64};
  std::shared_ptr<EcWorkerSessions> sessions_ = std::make_shared<EcWorkerSessions>();
  folly::CPUThreadPoolExecutor executor_{1};
  std::atomic_flag stopped_{};
};
}  // namespace hf3fs::storage
