#include "EcWorkerSession.h"

namespace hf3fs::storage {
Result<std::shared_ptr<EcWorkerSession>> EcWorkerSessions::acquire() {
  // Allocate before taking the mutex: allocation failure cannot leak a count.
  auto session = std::shared_ptr<EcWorkerSession>(new EcWorkerSession({}));
  std::unique_lock lock(mutex_);
  if (closing_ || active_ == 4096) {
    // An uncounted session must not invoke the completion path.
    session->sessions_.reset();
    return makeError(StorageClientCode::kResourceBusy, "EC worker is closing or at its session limit");
  }
  session->sessions_ = shared_from_this();
  ++active_;
  return session;
}
void EcWorkerSessions::closeAndWait() {
  std::unique_lock lock(mutex_);
  closing_ = true;
  drained_.wait(lock, [this] { return active_ == 0; });
}
EcWorkerSession::~EcWorkerSession() {
  if (!sessions_) return;
  std::lock_guard lock(sessions_->mutex_);
  assert(sessions_->active_ != 0);
  if (--sessions_->active_ == 0) sessions_->drained_.notify_all();
}
}  // namespace hf3fs::storage
