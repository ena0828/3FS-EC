#pragma once

#include <atomic>
#include <exception>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>

#include "fbs/storage/Ec.h"
#include "storage/ec_scope/EcScope.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {
class StorageTarget;

// Legacy v1 authorization has no persistent instance binding. An explicit tag
// prevents accidental fallback when a scoped admission is unavailable.
struct EcLegacyV1Admission {};
Result<Void> checkEcJobTarget(const StorageTarget &, const EcScopeTicket &, uint32_t, uint64_t, const Uuid &);

// The caller must retain this borrowed job/request until complete(), including
// cancellation. A ticket remains owned through response conversion/postchecks.
template <typename Request, typename Response>
class EcJob {
 public:
  EcJob(EcLegacyV1Admission,
        const Request &request,
        std::shared_ptr<StorageTarget> target,
        std::function<Result<Void>()> validateRoute)
      : request_(request),
        target_(std::move(target)),
        validateRoute_(std::move(validateRoute)) {}
  EcJob(EcScopeTicket ticket,
        std::shared_ptr<EcWorkerSession> session,
        const Request &request,
        std::shared_ptr<StorageTarget> target,
        std::function<Result<Void>()> validateRoute)
      : request_(request),
        target_(std::move(target)),
        validateRoute_(std::move(validateRoute)),
        ticket_(std::move(ticket)),
        session_(std::move(session)),
        scoped_(true) {}
  EcJob(const EcJob &) = delete;
  EcJob &operator=(const EcJob &) = delete;
  ~EcJob() {
    // Destroying a borrowed queued frame is a programming-contract violation.
    // Never silently drop the count and advertise drain while the worker owns it.
    if (scoped_ && submitted_.load() && !completed_.load()) std::terminate();
  }
  void claimSubmission() {
    // A second completion must not wake the first, still-running operation.
    if (submitted_.exchange(true)) std::terminate();
  }

  const auto &request() const { return request_; }
  const auto &target() const { return target_; }
  auto &result() { return result_; }
  bool scoped() const { return scoped_; }
  bool sessionMatches(const std::shared_ptr<EcWorkerSessions> &sessions) const {
    return !scoped_ || (session_ && session_->belongsTo(sessions));
  }
  Result<Void> validateRoute() const {
    if (!validateRoute_) return makeError(StatusCode::kInvalidArg, "EC job requires routing validation");
    return validateRoute_();
  }
  Result<Void> validateAdmission() const {
    if (!scoped_) return Void{};
    if (!ticket_) return makeError(StatusCode::kInvalidArg, "scoped EC ticket was already consumed");
    if (!session_) return makeError(StatusCode::kInvalidArg, "scoped EC job requires an active worker session");
    if constexpr (!std::is_same_v<Request, EcReadReq>) {
      if (ticket_->binding().kind != 2) {
        return makeError(StatusCode::kInvalidArg, "durable EC jobs require write-operation scope");
      }
    }
    RETURN_ON_ERROR(ticket_->checkExecution());
    return checkEcJobTarget(*target_, *ticket_, request_.vChainId.chainId, request_.targetId, request_.identity.object);
  }
  CoTask<void> complete() const {
    co_await baton_;
    completed_.store(true, std::memory_order_release);
  }
  void setResult(Result<Response> result) {
    result_ = std::move(result);
    baton_.post();
  }
  // Only call after complete(). This keeps the owning response, route/expiry
  // postcheck and final ticket release in one operation. Failure before disk
  // completion never drops a ticket. Retrying takeResult is rejected.
  Result<Response> takeResult() {
    if (!completed_.load(std::memory_order_acquire) || consumed_) {
      return makeError(StorageClientCode::kResourceBusy, "EC result is incomplete or already consumed");
    }
    consumed_ = true;
    auto finish = folly::makeGuard([this] {
      ticket_.reset();
      session_.reset();
    });
    auto output = std::move(result_);
    auto access = validateRoute();
    if (access) access = validateAdmission();
    if (!access && output) {
      if constexpr (std::is_same_v<Request, EcReadReq>) {
        return makeError(access.error());
      } else {
        return makeError(StorageCode::kEcSealOutcomeUnknown,
                         "EC durable operation completed but final access check failed; reconcile allocation");
      }
    }
    return output;
  }

 private:
  const Request &request_;
  std::shared_ptr<StorageTarget> target_;
  std::function<Result<Void>()> validateRoute_;
  std::optional<EcScopeTicket> ticket_;
  std::shared_ptr<EcWorkerSession> session_;
  Result<Response> result_{makeError(StorageClientCode::kNotInitialized)};
  std::atomic<bool> submitted_{false};
  const bool scoped_ = false;
  mutable std::atomic<bool> completed_{false};
  bool consumed_ = false;
  folly::coro::Baton baton_;
};
using EcCreateJob = EcJob<EcCreateReq, EcFragmentReceipt>;
using EcReadJob = EcJob<EcReadReq, EcReadResult>;
using EcReconcileJob = EcJob<EcReconcileReq, EcFragmentReceipt>;
}  // namespace hf3fs::storage
