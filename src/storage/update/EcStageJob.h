#pragma once

#include <atomic>
#include <exception>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <optional>

#include "storage/ec_stage/EcStagingEngine.h"
#include "storage/update/EcJobCompletion.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// Owns the bounded input and the persistent-scope admission. The coroutine
// frame owning this job must await complete() even after client cancellation.
// No LegacyV1 constructor exists: every queued V2 job requires a ticket.
class EcStageJob {
 public:
  EcStageJob(EcScopeTicket ticket,
             std::shared_ptr<EcWorkerSession> session,
             EcStageRequest request,
             std::shared_ptr<StorageTarget> target,
             std::function<Result<Void>()> validateRoute)
      : request_(std::move(request)),
        target_(std::move(target)),
        validateRoute_(std::move(validateRoute)),
        ticket_(std::move(ticket)),
        session_(std::move(session)) {}
  EcStageJob(const EcStageJob &) = delete;
  EcStageJob &operator=(const EcStageJob &) = delete;
  ~EcStageJob() { completion_.retainUntilFinished(); }
  void claimSubmission() { completion_.claim(); }
  const auto &target() const { return target_; }
  const auto &request() const { return request_; }
  bool sessionMatches(const std::shared_ptr<EcWorkerSessions> &sessions) const {
    return session_ && session_->belongsTo(sessions);
  }
  Result<Void> validateSubmission() const {
    if (!target_) return makeError(StatusCode::kInvalidArg, "stage job has no target");
    return request_.validate();
  }
  Result<Void> validateAdmission() const;
  Result<Void> validateRoute() const {
    if (!validateRoute_) return makeError(StatusCode::kInvalidArg, "stage job requires current route and grant checks");
    return validateRoute_();
  }
  void execute();
  void setResult(Result<EcStageResult> result) {
    result_ = std::move(result);
    completion_.finish();
  }
  CoTask<void> complete() const { return completion_.observe(); }
  void commitQueued() noexcept { completion_.commitQueued(); }
  bool queued() const noexcept { return completion_.queued(); }
  void awaitSubmittedAfterFailure() noexcept {
    completion_.failedWait();
    completion_.waitFinished();
  }
  Result<EcStageResult> takeResult();

 private:
  EcStageRequest request_;
  std::shared_ptr<StorageTarget> target_;
  std::function<Result<Void>()> validateRoute_;
  std::optional<EcScopeTicket> ticket_;
  std::shared_ptr<EcWorkerSession> session_;
  Result<EcStageResult> result_{makeError(StorageClientCode::kNotInitialized)};
  EcJobCompletion completion_;
  bool consumed_ = false;
};
}  // namespace hf3fs::storage
