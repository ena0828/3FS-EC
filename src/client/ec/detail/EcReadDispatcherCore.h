#pragma once

#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/AsyncScope.h>
#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <mutex>
#include <new>
#include <type_traits>

#include "EcFileValidation.h"
#include "client/ec/EcReadDispatcher.h"

namespace hf3fs::client::ec::detail {
template <typename T>
struct EcReadCall {
  explicit EcReadCall(T value)
      : fallback(std::move(value)) {}
  std::optional<T> result;
  T fallback;  // Constructed before accepting/scheduling work.
  std::optional<EcReadReceipt> receipt;
  bool localJoined = false;
  folly::coro::Baton ready{};
};
struct EcReadStopCall {
  EcReadShutdownReport report;
  bool done = false;  // Protected by core.mutex.
  folly::coro::Baton ready{};
};
struct EcReadDispatcherCore : std::enable_shared_from_this<EcReadDispatcherCore> {
  std::shared_ptr<EcReadSpool> spool;
  std::shared_ptr<meta::client::MetaClient> meta;
  std::shared_ptr<storage::client::StorageClient> storage;
  std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd;
  folly::CPUThreadPoolExecutor &pool;
  folly::Executor::KeepAlive<> executor;
  EcReadDispatcher::Limits limits;
  Uuid instance = Uuid::random();
  std::mutex mutex;
  bool activeCall = false, closing = false;
  bool tasksJoinStarted = false, tasksJoined = false, lowerJoinUnconfirmed = false, stopped = false;
  size_t outputLeases = 0;
  std::shared_ptr<EcFileClient> file;
  flat::UserInfo fileCredentials;
  std::optional<EcReadReceipt> activeReceipt;
  CancellationSource cancellation;
  folly::coro::AsyncScope tasks;
  std::shared_ptr<EcReadStopCall> stopAttempt;
  std::shared_ptr<EcReadDispatcherCore> retainedAfterJoinFailure;
  // Internal deterministic test seams; absent in all normal construction.
  // They introduce no wire/config flag or alternative production authority.
  std::function<void()> beforeBusinessForTesting, beforeDeliveryForTesting;
  std::function<CoTask<void>(std::shared_ptr<EcFileClient>)> closeFactoryForTesting;
  EcReadDispatcherCore(std::shared_ptr<EcReadSpool> s,
                       std::shared_ptr<meta::client::MetaClient> m,
                       std::shared_ptr<storage::client::StorageClient> d,
                       std::shared_ptr<hf3fs::client::ICommonMgmtdClient> g,
                       folly::CPUThreadPoolExecutor &p,
                       EcReadDispatcher::Limits l)
      : spool(std::move(s)),
        meta(std::move(m)),
        storage(std::move(d)),
        mgmtd(std::move(g)),
        pool(p),
        executor(folly::getKeepAliveToken(p)),
        limits(l) {}
  ~EcReadDispatcherCore() { spool->attached_.store(false); }
  Result<Void> active(const EcStripeControl &) const;
  size_t heldOutputs();
  CoTryTask<flat::UserInfo> authenticate(flat::UserInfo, EcStripeControl);
  CoTryTask<Void> manager(const flat::UserInfo &, EcStripeControl);
  void request(meta::ReqBase &, const flat::UserInfo &, const Uuid &) const;
  CoTryTask<EcReadHandle> openOwned(meta::EcObjectRef, flat::UserInfo, EcStripeControl);
  CoTryTask<EcDispatchReadOutcome> newReadOwned(EcReadHandle, flat::UserInfo, uint64_t, uint64_t, EcStripeControl);
  CoTryTask<EcDispatchReadOutcome> resumeOwned(EcReadReceipt, flat::UserInfo, EcStripeControl);
  CoTryTask<EcDispatchReadOutcome> readRun(EcReadSpool::Run, EcStripeControl);
  CoTask<EcDispatchCleanupOutcome> cleanupOwned(EcReadReceipt, flat::UserInfo, EcStripeControl);
  CoTryTask<EcReadRetirementOutcome> retireOwned(EcReadReceipt, flat::UserInfo, std::filesystem::path, EcStripeControl);
  CoTryTask<Void> confirmTerminal(const EcReadSpool::Run &, const flat::UserInfo &, EcStripeControl);
  CoTryTask<EcReadSpoolSnapshot> inspectOwned();
  CoTryTask<EcReadReceiptObservation> receiptOwned(EcReadReceipt);
  CoTask<void> lowerClose() { return closeFactoryForTesting ? closeFactoryForTesting(file) : file->close(); }
  void retainUnconfirmedJoin() noexcept {
    std::lock_guard lock(mutex);
    lowerJoinUnconfirmed = true;
    closing = true;
    retainedAfterJoinFailure = shared_from_this();
  }
  bool unconfirmedJoin() {
    std::lock_guard lock(mutex);
    return lowerJoinUnconfirmed;
  }
  static CoTask<EcReadShutdownReport> finishStop(std::shared_ptr<EcReadDispatcherCore>);
  Result<EcDispatchReadOutcome> failedRead(Status error) {
    if (!activeReceipt) return makeError(std::move(error));
    EcDispatchReadOutcome result;
    result.receipt = *activeReceipt;
    result.localJoined = !unconfirmedJoin();
    result.cleanup.localJoined = result.localJoined;
    result.readFailure.emplace(error.code());
    result.cleanup.failure = std::move(error);
    return result;
  }
  template <typename T>
  static CoTask<T> immediate(T value) {
    co_return std::move(value);
  }
  template <typename T>
  static CoTask<T> take(std::shared_ptr<EcReadCall<T>> call) {
    co_await call->ready;
    if (call->result) co_return std::move(*call->result);
    if constexpr (std::is_same_v<T, Result<EcDispatchReadOutcome>>) {
      if (call->receipt) {
        EcDispatchReadOutcome out;
        out.receipt = *call->receipt;
        out.localJoined = call->localJoined;
        out.cleanup.localJoined = out.localJoined;
        out.readFailure.emplace(StatusCode::kIOError);
        out.cleanup.failure.emplace(StatusCode::kIOError);
        co_return out;
      }
    }
    co_return std::move(call->fallback);
  }
  template <typename T, typename MakeTask, typename Failure>
  CoTask<T> launch(MakeTask make, Failure failure) {
    std::shared_ptr<EcReadCall<T>> call;
    try {
      std::lock_guard lock(mutex);
      if (closing || activeCall) return immediate(failure(Status(StorageClientCode::kResourceBusy)));
      call = std::make_shared<EcReadCall<T>>(failure(Status(StatusCode::kIOError)));
      auto task = make();
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
  static CoTask<void> run(std::shared_ptr<EcReadDispatcherCore> core,
                          std::shared_ptr<EcReadCall<T>> call,
                          CoTask<T> task,
                          Failure failure) {
    // This guard also covers close factory/body and result delivery failures.
    // The preconstructed fallback lets the waiter settle without allocating a
    // second diagnostic message after an allocation exception.
    auto settle = folly::makeGuard([&] {
      {
        std::lock_guard lock(core->mutex);
        call->receipt = core->activeReceipt;
        call->localJoined = !core->lowerJoinUnconfirmed;
        core->activeReceipt.reset();
        core->activeCall = false;
      }
      call->ready.post();
    });
    try {
      std::optional<T> result;
      std::optional<Status> error;
      try {
        if (core->beforeBusinessForTesting) core->beforeBusinessForTesting();
        result.emplace(co_await folly::coro::co_withCancellation(CancellationToken{}, std::move(task)));
      } catch (const std::bad_alloc &) {
        error.emplace(StatusCode::kNotEnoughMemory);
      } catch (...) {
        error.emplace(StatusCode::kIOError);
      }
      if (error) {
        if (core->file) {
          try {
            co_await folly::coro::co_withCancellation(CancellationToken{}, core->lowerClose());
            core->file.reset();
          } catch (...) {
            core->retainUnconfirmedJoin();
          }
        }
        if constexpr (std::is_same_v<T, Result<EcDispatchReadOutcome>>)
          result.emplace(core->failedRead(std::move(*error)));
        else
          result.emplace(failure(std::move(*error)));
      }
      if (core->beforeDeliveryForTesting) core->beforeDeliveryForTesting();
      call->result.emplace(std::move(*result));
    } catch (...) {
      // No exception may escape a task submitted to AsyncScope. Conservatively
      // keep lower resources when delivery itself failed; explicit stop owns
      // the next close attempt. A missing result selects call.fallback.
      if (core->file) core->retainUnconfirmedJoin();
    }
  }
};
struct EcReadOutputLease {
  std::shared_ptr<EcReadDispatcherCore> core;
  explicit EcReadOutputLease(std::shared_ptr<EcReadDispatcherCore> value)
      : core(std::move(value)) {
    std::lock_guard lock(core->mutex);
    ++core->outputLeases;
  }
  ~EcReadOutputLease() {
    std::lock_guard lock(core->mutex);
    --core->outputLeases;
  }
};
}  // namespace hf3fs::client::ec::detail
