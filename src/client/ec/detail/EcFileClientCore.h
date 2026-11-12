#pragma once
#include <atomic>
#include <exception>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/AsyncScope.h>
#include <folly/experimental/coro/Baton.h>
#include <mutex>
#include <new>

#include "EcFileValidation.h"
#include "client/ec/EcFileClient.h"
namespace hf3fs::client::ec::detail {
enum class EcTruncateClientAction { Advance, Query, CloseDebt };
template <typename T>
struct EcFileCall {
  T fallback;  // Constructed before any task is admitted.
  std::optional<T> result;
  folly::coro::Baton ready{};
  explicit EcFileCall(T value)
      : fallback(std::move(value)) {}
};
struct EcFileCloseAttempt {
  std::exception_ptr error;
  folly::coro::Baton ready{};
};
struct EcFileClientCore : std::enable_shared_from_this<EcFileClientCore> {
  std::shared_ptr<meta::client::MetaClient> meta;
  std::shared_ptr<EcStripeClient> stripe;
  std::shared_ptr<EcFilePayloadBudget> budget;
  flat::UserInfo credentials;
  meta::EcOwner owner;
  std::chrono::seconds maximumTime;
  folly::Executor::KeepAlive<> executor;
  std::mutex mutex;
  bool activeCall = false, closing = false, dataClosed = false;
  CancellationSource stop;
  folly::coro::AsyncScope tasks;
  bool tasksJoinStarted = false, tasksJoined = false;
  bool stripeJoinStarted = false, stripeJoined = false, closeComplete = false;
  std::exception_ptr tasksJoinError, stripeJoinError;
  std::shared_ptr<EcFileCloseAttempt> closeAttempt;
  // A failed lower join must not release its manager/budget/executor merely
  // because the public owner drops its waiter. Only confirmed close clears it.
  std::shared_ptr<EcFileClientCore> unconfirmedJoinLease;
  std::atomic_bool localJoinUnconfirmed{false};
  // Internal deterministic test seam; production leaves it null. The test
  // factory must delegate to the real StripeClient close after any injected error.
  CoTask<void> (*stripeCloseFactoryForTest)(void *, EcStripeClient &) = nullptr;
  void *stripeCloseFactoryContextForTest = nullptr;
  EcFileClientCore(std::shared_ptr<meta::client::MetaClient> m,
                   std::shared_ptr<EcStripeClient> s,
                   std::shared_ptr<EcFilePayloadBudget> b,
                   flat::UserInfo u,
                   std::chrono::seconds maximum,
                   folly::CPUThreadPoolExecutor &pool)
      : meta(std::move(m)),
        stripe(std::move(s)),
        budget(std::move(b)),
        credentials(std::move(u)),
        owner(stripe->owner()),
        maximumTime(maximum),
        executor(folly::getKeepAliveToken(pool)) {}
  Result<Void> active(const EcStripeControl &) const;
  Result<Void> validateRun(const EcFileRunJournal &, EcFileRunKind) const;
  void request(meta::ReqBase &, const Uuid &) const;
  Result<Void> beginAttempt(EcFileRunJournal &);
  Result<Void> finishAttempt(EcFileRunJournal &, const std::optional<Status> &);
  Result<meta::EcRangeSnapshot> rememberRange(EcFileRunJournal &, meta::EcRangeSnapshot);
  CoTryTask<meta::EcRangeSnapshot> range(std::shared_ptr<EcFileRunJournal>,
                                         bool mayAcquireSameIdentity,
                                         EcStripeControl);
  CoTryTask<meta::EcFileState> describeOwned(meta::EcObjectRef, Uuid, meta::AccessType, EcStripeControl);
  CoTryTask<EcFileReadOutput> readOwned(std::shared_ptr<EcFileRunJournal>, EcStripeControl);
  CoTryTask<EcFileTreeReadOutput> readTreeOwned(std::shared_ptr<EcTreeReadJournal>, EcStripeControl);
  CoTryTask<meta::EcTreeReadRecord> releaseTreeOwned(std::shared_ptr<EcTreeReadJournal>, EcStripeControl);
  CoTryTask<meta::EcTreeReadRecord> treeRange(std::shared_ptr<EcTreeReadJournal>, bool mayCreate, EcStripeControl);
  CoTask<EcFileAppendOutcome> appendOwned(std::shared_ptr<EcFileRunJournal>, EcFilePayload, EcStripeControl);
  CoTask<EcFileReleaseOutcome> releaseOwned(std::shared_ptr<EcFileRunJournal>, EcStripeControl);
  CoTryTask<meta::EcFileTruncateProgress> truncateOwned(std::shared_ptr<EcTruncateJournal>,
                                                        EcStripeControl,
                                                        EcTruncateClientAction);
  static CoTask<void> close(std::shared_ptr<EcFileClientCore>);
  static CoTask<void> closeStripe(std::shared_ptr<EcFileClientCore>);
  template <typename T>
  static CoTask<T> immediate(T value) {
    co_return std::move(value);
  }
  template <typename T>
  static CoTask<T> take(std::shared_ptr<EcFileCall<T>> call) {
    co_await call->ready;
    if (call->result) co_return std::move(*call->result);
    co_return std::move(call->fallback);
  }
  template <typename T, typename MakeTask, typename Failure>
  CoTask<T> launch(MakeTask makeTask, Failure failure) {
    std::shared_ptr<EcFileCall<T>> call;
    try {
      std::lock_guard lock(mutex);
      if (closing || activeCall) return immediate(failure(Status(StorageClientCode::kResourceBusy)));
      call = std::make_shared<EcFileCall<T>>(failure(Status(StatusCode::kNotEnoughMemory)));
      auto task = makeTask();
      activeCall = true;
      try {
        tasks.add(run(shared_from_this(), call, std::move(task), failure).scheduleOn(executor));
      } catch (...) {
        activeCall = false;
        throw;
      }
    } catch (const std::bad_alloc &) {
      return immediate(failure(Status(StatusCode::kNotEnoughMemory)));
    }
    return take(std::move(call));
  }
  template <typename T, typename Failure>
  static CoTask<void> run(std::shared_ptr<EcFileClientCore> core,
                          std::shared_ptr<EcFileCall<T>> call,
                          CoTask<T> task,
                          Failure failure) {
    // Notification cannot depend on a second successful allocation after a
    // business failure. A fallback already exists in the accepted call.
    SCOPE_EXIT {
      {
        std::lock_guard lock(core->mutex);
        core->activeCall = false;
      }
      call->ready.post();
    };
    std::optional<Status> exception;
    try {
      auto result = co_await folly::coro::co_withCancellation(CancellationToken{}, std::move(task));
      call->result.emplace(std::move(result));
    } catch (const std::bad_alloc &) {
      exception.emplace(StatusCode::kNotEnoughMemory);
    } catch (...) {
      exception.emplace(StatusCode::kIOError);
    }
    if (exception) {
      // A successful lower close proves local ownership settled. A failed
      // close does not: reject new work, retain the whole core and allow an
      // explicit close attempt to report/retry only its unstarted stages.
      {
        std::lock_guard lock(core->mutex);
        core->closing = true;
        core->dataClosed = true;
        core->unconfirmedJoinLease = core;
        core->localJoinUnconfirmed.store(true);
      }
      core->stop.requestCancellation();
      try {
        co_await folly::coro::co_withCancellation(CancellationToken{}, closeStripe(core));
      } catch (...) {
        std::lock_guard lock(core->mutex);
        core->unconfirmedJoinLease = core;
        core->localJoinUnconfirmed.store(true);
      }
      try {
        call->result.emplace(failure(std::move(*exception)));
      } catch (...) {
        call->result.reset();
      }  // take() uses the pre-admission fallback.
    }
  }
};
EcFileAppendOutcome fileAppendOutcome(const EcFileRunJournal &, std::optional<Status> = std::nullopt);
}  // namespace hf3fs::client::ec::detail
