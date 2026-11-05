#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

#include "common/utils/BoundedQueue.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Semaphore.h"
#include "fbs/storage/EcGcControl.h"
#include "fbs/storage/EcGcDiscovery.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// An internal executor, not RPC registration or a claim issuer. The caller
// supplies the actual loaded target and configured local node/authority/key.
// At most 64 admitted requests own a target, fixed-size certificate and result.
// No data queue/session is used and no task waits for scope drain here.
//
// stopAndJoin must run outside this worker and outside an executor needed by
// its waiting callers. Keep this owner alive until it succeeds; dropping an
// execute waiter is not permission to destroy the owner or its coroutine.
// Admission from this same worker is rejected before enqueue, including an
// inline resumed caller attempting a second request without changing executor.
class EcGcExecutor final {
 public:
  using Clock = std::function<uint64_t()>;
  // A deny-only policy, not authorization. The production owner supplies
  // its hot read_only getter and keeps that owner alive through stop/join.
  using ReadOnly = std::function<bool()>;
  static constexpr uint32_t kCapacity = 64;
  static Result<std::unique_ptr<EcGcExecutor>> create(
      std::shared_ptr<const EcGcKey>,
      Uuid authority,
      NodeId actualLocalNode,
      Clock,
      ReadOnly readOnly = [] { return false; });
  ~EcGcExecutor();
  CoTryTask<EcGcAck> execute(EcGcAction, EcGcRequest request, std::shared_ptr<StorageTarget> target);
  // Synchronous bounded observation of immutable, already-loaded fields; no
  // disk I/O or worker enqueue. The callback fences the operator's target map,
  // never replaces the independently checked actual target or G authority.
  Result<EcGcDiscoveryObservation> observeCapabilities(const EcGcDiscoveryRequest &,
                                                       std::shared_ptr<StorageTarget>,
                                                       const std::function<Result<Void>()> &validateLoadedTarget);
  Result<Void> validateDiscoveryRequest(const EcGcDiscoveryRequest &) const;
  Result<Void> stopAndJoin();
  uint32_t activeRequests() const { return active_.load(); }

 private:
  struct Job;
  EcGcExecutor(std::shared_ptr<const EcGcKey>, Uuid, NodeId, Clock, ReadOnly);
  Result<EcGcAck> process(const Job &);
  void run() noexcept;
  std::shared_ptr<const EcGcKey> key_;
  Uuid authority_;
  NodeId node_;
  Clock clock_;
  ReadOnly readOnly_;
  Uuid bootNonce_ = Uuid::random();
  BoundedQueue<Job *> queue_{kCapacity};
  Semaphore budget_{kCapacity, kCapacity};
  std::shared_ptr<EcWorkerSessions> sessions_ = std::make_shared<EcWorkerSessions>();
  std::atomic<uint32_t> active_{0};
  std::atomic<bool> acceptingObservations_{true};
  std::mutex stopMutex_;
  bool stopped_ = false;
  std::thread worker_;
  const std::thread::id workerId_;
};
}  // namespace hf3fs::storage
