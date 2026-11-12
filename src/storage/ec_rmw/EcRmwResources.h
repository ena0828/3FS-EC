#pragma once

#include "common/utils/Semaphore.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class EcRmwResources;
class EcRmwJobLease final {
 public:
  ~EcRmwJobLease();
  EcRmwJobLease(const EcRmwJobLease &) = delete;
  EcRmwJobLease &operator=(const EcRmwJobLease &) = delete;
  static constexpr size_t kBytes = 96u << 20;

 private:
  friend class EcRmwResources;
  EcRmwJobLease(std::shared_ptr<EcRmwResources> resources, std::shared_ptr<EcWorkerSession> session)
      : resources_(std::move(resources)),
        session_(std::move(session)) {}
  std::shared_ptr<EcRmwResources> resources_;
  std::shared_ptr<EcWorkerSession> session_;
};
// First implementation deliberately admits one owned job per runtime, charged
// as a whole 96MiB application reservation before patch/source/codec buffers.
// This is not an RSS cap. Rejection never waits on the data UpdateWorker queue.
class EcRmwResources final : public std::enable_shared_from_this<EcRmwResources> {
 public:
  static std::shared_ptr<EcRmwResources> create() { return std::shared_ptr<EcRmwResources>(new EcRmwResources); }
  Result<std::shared_ptr<EcRmwJobLease>> acquire();
  // Outside network/worker executors. Never call while holding an own lease.
  void closeAndWait() { sessions_->closeAndWait(); }

 private:
  friend class EcRmwJobLease;
  EcRmwResources() = default;
  Semaphore budget_{1, 1};
  std::shared_ptr<EcWorkerSessions> sessions_ = std::make_shared<EcWorkerSessions>();
};
}  // namespace hf3fs::storage
