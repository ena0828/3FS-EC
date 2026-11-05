#pragma once

#include <atomic>
#include <exception>
#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <memory>

#include "common/utils/Coroutine.h"
#include "storage/ec_scope/EcScope.h"
#include "storage/update/EcJobCompletion.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// Cold metadata lookup/admission only. The job owns all binding bytes and does
// no fragment I/O. Its callback is local validation, not a wire authority flag.
class EcAdmissionJob {
 public:
  EcAdmissionJob(EcScopeBinding binding,
                 std::shared_ptr<EcScope> scope,
                 std::shared_ptr<EcWorkerSession> session,
                 std::shared_ptr<StorageTarget> target,
                 std::function<Result<Void>()> validate,
                 std::function<Result<uint32_t>()> waitBudget = {})
      : binding_(binding),
        scope_(std::move(scope)),
        session_(std::move(session)),
        target_(std::move(target)),
        validate_(std::move(validate)),
        waitBudget_(std::move(waitBudget)) {}
  EcAdmissionJob(const EcAdmissionJob &) = delete;
  EcAdmissionJob &operator=(const EcAdmissionJob &) = delete;
  ~EcAdmissionJob() { completion_.retainUntilFinished(); }
  void claimSubmission() { completion_.claim(); }
  const auto &target() const { return target_; }
  bool sessionMatches(const std::shared_ptr<EcWorkerSessions> &sessions) const {
    return session_ && session_->belongsTo(sessions);
  }
  void execute();
  void reject(Status status);
  CoTask<void> complete() const { return completion_.observe(); }
  void commitQueued() noexcept { completion_.commitQueued(); }
  bool queued() const noexcept { return completion_.queued(); }
  void awaitSubmittedAfterFailure() noexcept {
    completion_.failedWait();
    completion_.waitFinished();
  }
  Result<EcScopeTicket> takeTicket();

 private:
  EcScopeBinding binding_;
  std::shared_ptr<EcScope> scope_;
  std::shared_ptr<EcWorkerSession> session_;
  std::shared_ptr<StorageTarget> target_;
  std::function<Result<Void>()> validate_;
  std::function<Result<uint32_t>()> waitBudget_;
  Result<EcScopeTicket> result_{makeError(StorageClientCode::kNotInitialized)};
  friend class EcJobCompletionTestAccess;
  EcJobCompletion completion_;
  bool consumed_ = false;
};
}  // namespace hf3fs::storage
