#pragma once

#include <span>

#include "client/ec/EcStripeClient.h"
#include "client/ec/detail/EcQuorumRead.h"
#include "fbs/storage/EcStageValidationV2.h"

namespace hf3fs::client::ec::detail {
template <typename T>
struct EcManagedCall {
  std::shared_ptr<EcReadReservation> reservation;
  std::mutex mutex;
  std::optional<T> result;
  bool taken = false;
  folly::coro::Baton ready;
};

struct EcStripeClientReadState : EcManagedCall<Result<EcStripeReadOutput>> {
  EcStripePinIds pin;
  std::optional<meta::AcquireEcReadV2Rsp> suppliedRead;
  bool externalRange = false;
  EcStripeControl control;
  CancellationSource stop;
  folly::coro::Baton cleaned;
};

struct EcStripeClientCore : std::enable_shared_from_this<EcStripeClientCore> {
  std::shared_ptr<meta::client::MetaClient> meta;
  std::shared_ptr<storage::client::StorageClient> storage;
  std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd;
  flat::UserInfo credentials;
  meta::EcOwner owner;
  EcStripeClient::Limits limits;
  folly::CPUThreadPoolExecutor &executor;
  folly::Executor::KeepAlive<> executorLease;
  std::shared_ptr<EcReadBudget> budget = std::make_shared<EcReadBudget>();
  mutable std::mutex mutex;
  size_t activeOperations = 0;
  bool closing = false;
  CancellationSource stop;
  folly::coro::AsyncScope tasks;
  folly::coro::Baton closed;

  EcStripeClientCore(std::shared_ptr<meta::client::MetaClient> metadata,
                     std::shared_ptr<storage::client::StorageClient> data,
                     std::shared_ptr<hf3fs::client::ICommonMgmtdClient> routing,
                     flat::UserInfo user,
                     Uuid clientNamespace,
                     folly::CPUThreadPoolExecutor &pool,
                     EcStripeClient::Limits bounds)
      : meta(std::move(metadata)),
        storage(std::move(data)),
        mgmtd(std::move(routing)),
        credentials(std::move(user)),
        owner{credentials.uid, clientNamespace},
        limits(bounds),
        executor(pool),
        executorLease(folly::getKeepAliveToken(pool)) {}

  Result<Void> active(const EcStripeControl &) const;
  Result<Void> validControl(const EcStripeControl &) const;
  Result<storage::VersionedChainId> route(const storage::EcScopeEndpoint &) const;
  Result<Void> validOwner(const meta::EcOwner &) const;
  Result<Void> validPin(const EcStripePinIds &) const;
  Result<Void> validIds(const EcStripeMutationIds &) const;
  void request(meta::ReqBase &base, const Uuid &requestId) const;

  // These non-coroutine entrypoints admit synchronously before retaining owned
  // input in a lazy task frame. All started tasks belong to this manager, so
  // dropping a waiter cannot destroy an in-flight network frame or its budget.
  template <typename T, typename MakeTask, typename Failure>
  Result<std::shared_ptr<EcManagedCall<T>>> launch(size_t bytes, MakeTask makeTask, Failure failure) {
    try {
      std::lock_guard lock(mutex);
      const auto used = budget->bytes.load();
      if (closing || activeOperations >= limits.maxOperations || bytes > limits.maxApplicationBytes ||
          used > limits.maxApplicationBytes - bytes) {
        return makeError(StorageClientCode::kResourceBusy,
                         "stripe client operation or application-byte budget exhausted");
      }
      auto call = std::make_shared<EcManagedCall<T>>();
      call->reservation = std::make_shared<EcReadReservation>(budget, bytes);
      auto task = makeTask(call->reservation);
      ++activeOperations;
      try {
        tasks.add(runManaged(shared_from_this(), call, std::move(task), std::move(failure)).scheduleOn(executorLease));
      } catch (...) {
        --activeOperations;
        throw;
      }
      return call;
    } catch (const std::bad_alloc &) {
      return makeError(StatusCode::kNotEnoughMemory);
    }
  }

  template <typename T>
  static CoTask<T> take(std::shared_ptr<EcManagedCall<T>> state) {
    co_await state->ready;
    std::lock_guard lock(state->mutex);
    // Internal waiters are created once by the public wrapper.
    XCHECK(!state->taken);
    state->taken = true;
    co_return std::move(*state->result);
  }
  template <typename T, typename Failure>
  static CoTask<void> runManaged(std::shared_ptr<EcStripeClientCore> core,
                                 std::shared_ptr<EcManagedCall<T>> state,
                                 CoTask<T> task,
                                 Failure failure) {
    std::optional<T> result;
    try {
      result.emplace(co_await folly::coro::co_withCancellation(CancellationToken{}, std::move(task)));
    } catch (const std::bad_alloc &) {
      result.emplace(failure(Status(StatusCode::kNotEnoughMemory)));
    } catch (const OperationCancelled &) {
      result.emplace(failure(Status(StorageClientCode::kRequestCanceled)));
    } catch (...) {
      result.emplace(failure(Status(StatusCode::kUnknown)));
    }
    {
      std::lock_guard lock(state->mutex);
      state->result.emplace(std::move(*result));
      state->reservation.reset();
    }
    {
      std::lock_guard lock(core->mutex);
      --core->activeOperations;
    }
    state->ready.post();
  }
  template <typename T>
  static CoTask<T> immediate(T value) {
    co_return std::move(value);
  }
  static CoTask<void> close(std::shared_ptr<EcStripeClientCore>);

  CoTryTask<meta::CreateEcFileRsp> createOwned(meta::CreateEcFileV2Req, EcStripeControl);
  CoTask<EcStripeMutationOutcome> writeOwned(EcStripeWrite, EcStripeControl);
  CoTask<EcStripeMutationOutcome> repairOwned(EcStripeRepair, EcStripeControl);
  // Called only after all fragment tasks have joined. A durable unknown from
  // any fragment takes precedence over a different fragment's ordinary error.
  static std::optional<Status> collectStageResults(EcStripeMutationOutcome &,
                                                   std::span<Result<storage::EcStageStateV2>>);
  CoTryTask<meta::ReleaseEcReadV2Rsp> releaseOwned(EcStripePinIds, EcStripeControl);
  Result<EcStripeReadSession> startRead(EcStripePinIds,
                                        EcStripeControl,
                                        std::optional<meta::AcquireEcReadV2Rsp> = std::nullopt);
  static CoTask<void> readOwned(std::shared_ptr<EcStripeClientCore>, std::shared_ptr<EcStripeClientReadState>);

  Result<Void> validateObservation(const meta::EcV2MutationRsp &, const meta::BeginEcMutationV2Req &) const;
  CoTryTask<meta::EcV2MutationRsp> getOperation(const meta::EcObjectRef &,
                                                const EcStripeMutationIds &,
                                                EcStripeControl);
  CoTryTask<meta::EcV2MutationRsp> publish(const meta::EcObjectRef &, const EcStripeMutationIds &, EcStripeControl);
  CoTryTask<meta::EcV2MutationRsp> begin(meta::BeginEcMutationV2Req, const EcStripeMutationIds &, EcStripeControl);
  CoTryTask<meta::EcV2MutationRsp> bind(const meta::BeginEcMutationV2Req &,
                                        const EcStripeMutationIds &,
                                        const std::array<storage::EcIntegrityDescriptor, 12> &,
                                        EcStripeControl);
  Result<storage::EcBeginStageV2Req> stageRequest(const meta::EcV2AllocationBinding &,
                                                  const storage::EcCapabilityV2 &,
                                                  const Uuid &operation) const;
  CoTryTask<storage::EcStageStateV2> writeFragment(const meta::EcV2AllocationBinding &,
                                                   const storage::EcCapabilityV2 &,
                                                   std::string_view bytes,
                                                   EcStripeControl);
  CoTryTask<storage::EcStageStateV2> writeFragmentImpl(const meta::EcV2AllocationBinding &,
                                                       const storage::EcCapabilityV2 &,
                                                       std::string_view,
                                                       EcStripeControl);
};
}  // namespace hf3fs::client::ec::detail
