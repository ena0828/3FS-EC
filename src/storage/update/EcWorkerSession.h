#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/utils/Result.h"

namespace hf3fs::storage {
class UpdateWorker;
class EcWorkerSession;

// This is a queue-lifetime gate, not data authorization. Close before sending
// worker stop sentinels, then wait outside the worker/proc executor. A session
// covers cold admission, chunk-lock wait, data work and response postchecks.
// At most 4096 sessions are retained; callers also need payload/global budgets.
class EcWorkerSessions : public std::enable_shared_from_this<EcWorkerSessions> {
 public:
  Result<std::shared_ptr<EcWorkerSession>> acquire();
  void closeAndWait();

 private:
  friend class EcWorkerSession;
  std::mutex mutex_;
  std::condition_variable drained_;
  bool closing_ = false;
  uint64_t active_ = 0;
};

class EcWorkerSession {
 public:
  EcWorkerSession(const EcWorkerSession &) = delete;
  EcWorkerSession &operator=(const EcWorkerSession &) = delete;
  ~EcWorkerSession();
  bool belongsTo(const std::shared_ptr<EcWorkerSessions> &sessions) const { return sessions_ == sessions; }

 private:
  friend class EcWorkerSessions;
  explicit EcWorkerSession(std::shared_ptr<EcWorkerSessions> sessions)
      : sessions_(std::move(sessions)) {}
  std::shared_ptr<EcWorkerSessions> sessions_;
};
}  // namespace hf3fs::storage
