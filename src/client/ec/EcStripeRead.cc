#include "EcStripeRead.h"

#include <algorithm>
#include <atomic>
#include <folly/experimental/coro/AsyncScope.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/Collect.h>
#include <folly/experimental/coro/Sleep.h>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "common/utils/BoundedQueue.h"

namespace hf3fs::client::ec {
namespace detail {

struct EcReadBudget {
  std::atomic<size_t> bytes{0};
};

struct EcReadReservation {
  std::shared_ptr<EcReadBudget> budget;
  size_t bytes;
  EcReadReservation(std::shared_ptr<EcReadBudget> value, size_t count)
      : budget(std::move(value)),
        bytes(count) {
    budget->bytes.fetch_add(bytes);
  }
  ~EcReadReservation() { budget->bytes.fetch_sub(bytes); }
};

struct EcReadState {
  EcStripeReadInput input;
  EcStripeReadOptions options;
  std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
  CancellationSource stop;
  folly::coro::AsyncScope attempts;
  BoundedQueue<uint16_t> completed{12};
  std::mutex mutex;
  std::array<std::optional<Result<storage::EcReadResult>>, 12> responses;
  std::optional<Result<EcStripeSelection>> result;
  bool resultTaken = false;
  folly::coro::Baton ready;
  folly::coro::Baton cleaned;
  std::shared_ptr<const EcReadReservation> reservation;
};

}  // namespace detail
namespace {
using State = detail::EcReadState;
using Clock = std::chrono::steady_clock;

Result<Void> validateInput(const EcStripeReadInput &input) {
  const auto &manifest = input.manifest;
  if (manifest.version != meta::kEcCatalogVersion || manifest.object.incarnation.is_nil() || manifest.generation == 0 ||
      manifest.revision == 0) {
    return makeError(StatusCode::kInvalidArg, "EC selector requires a fixed manifest");
  }
  const auto length = manifest.fragments[0].integrity.wholeLength;
  if (length == 0 || length > storage::kEcFragmentRpcMaxBytes || manifest.logicalLength > uint64_t(length) * 10) {
    return makeError(StatusCode::kInvalidArg, "invalid EC stripe extent");
  }
  for (size_t index = 0; index != 12; ++index) {
    const auto &fragment = manifest.fragments[index];
    const auto &request = input.requests[index].request;
    RETURN_ON_ERROR(request.validate());
    RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
    if (fragment.identity.object != manifest.object.incarnation || fragment.identity.stripe != manifest.stripe ||
        fragment.identity.generation != manifest.generation || fragment.identity.shard != index ||
        fragment.integrity.wholeLength != length || !serde::equals(request.identity, fragment.identity) ||
        request.operationId != fragment.operation || request.vChainId.chainId != fragment.placement.chain ||
        request.targetId != fragment.placement.target || request.expectedLength != length ||
        ~request.checksum.value != fragment.integrity.wholeCrc32c) {
      return makeError(StatusCode::kInvalidArg, "EC read candidate differs from pinned manifest");
    }
  }
  return Void{};
}

Result<Void> validateResponse(const State &state, uint16_t index, const storage::EcReadResult &result) {
  const auto &request = state.input.requests[index].request;
  const auto &receipt = result.receipt;
  if (receipt.version != storage::kEcFragmentProtocolVersion || !serde::equals(receipt.identity, request.identity) ||
      receipt.operationId != request.operationId || receipt.vChainId != request.vChainId ||
      receipt.targetId != request.targetId || receipt.length != request.expectedLength ||
      receipt.checksum != request.checksum || result.payload.data.size() != request.expectedLength) {
    return makeError(StorageClientCode::kProtocolMismatch, "EC read response differs from pinned request");
  }
  auto actual = storage::computeEcIntegrity(request.identity, result.payload.data);
  RETURN_ON_ERROR(actual);
  if (*actual != state.input.manifest.fragments[index].integrity) {
    return makeError(StorageClientCode::kChecksumMismatch, "EC read differs from authoritative integrity descriptor");
  }
  return Void{};
}

void publish(const std::shared_ptr<State> &state, Result<EcStripeSelection> result) {
  {
    std::lock_guard lock(state->mutex);
    if (state->result) return;
    if (result && state->stop.isCancellationRequested()) result = makeError(StorageClientCode::kRequestCanceled);
    if (result && Clock::now() >= state->options.deadline) result = makeError(StorageClientCode::kTimeout);
    state->result.emplace(std::move(result));
  }
  state->ready.post();
}

CoTryTask<EcStripeSelection> takeReady(std::shared_ptr<State> state) {
  if (!state) co_return makeError(StatusCode::kInvalidArg, "empty EC read handle");
  co_await state->ready;
  std::lock_guard lock(state->mutex);
  if (state->resultTaken) co_return makeError(StatusCode::kInvalidArg, "EC selection already consumed");
  state->resultTaken = true;
  co_return std::move(*state->result);
}

CoTask<void> waitCleanup(std::shared_ptr<State> state) {
  if (state) co_await state->cleaned;
}

CoTask<std::optional<uint16_t>> waitCompletion(std::shared_ptr<State> state, Clock::duration duration) {
  auto [timer, response] = co_await folly::coro::collectAnyNoDiscard(
      folly::coro::sleep(std::chrono::ceil<std::chrono::microseconds>(duration)),
      state->completed.co_dequeue());
  if (response.hasValue()) co_return *response;
  if (response.hasException() && !response.template hasException<OperationCancelled>()) response.value();
  if (timer.hasException() && !timer.template hasException<OperationCancelled>()) timer.value();
  co_return std::nullopt;
}

}  // namespace

struct EcStripeRead::Impl {
  std::shared_ptr<EcReadTransport> transport;
  folly::Executor::KeepAlive<> executor;
  Limits limits;
  std::shared_ptr<detail::EcReadBudget> budget = std::make_shared<detail::EcReadBudget>();
  mutable std::mutex mutex;
  std::unordered_map<State *, std::shared_ptr<State>> active;
  std::atomic<size_t> requests{0};
  folly::coro::AsyncScope operations;
  bool closing = false;
  folly::coro::Baton closed;

  Impl(std::shared_ptr<EcReadTransport> reader, folly::CPUThreadPoolExecutor &pool, Limits value)
      : transport(std::move(reader)),
        executor(folly::getKeepAliveToken(pool)),
        limits(value) {}

  CoTask<void> readOne(std::shared_ptr<State> state, uint16_t index) {
    Result<storage::EcReadResult> result = makeError(StorageClientCode::kRequestCanceled);
    try {
      if (!state->stop.isCancellationRequested() && Clock::now() < state->options.deadline) {
        result =
            co_await transport->read(state->input.requests[index], {state->options.deadline, state->stop.getToken()});
        if (result) {
          auto valid = validateResponse(*state, index, *result);
          if (!valid) result = makeError(valid.error());
        }
        if (Clock::now() >= state->options.deadline) result = makeError(StorageClientCode::kTimeout);
      }
    } catch (const OperationCancelled &) {
      result = makeError(StorageClientCode::kRequestCanceled);
    } catch (const std::exception &error) {
      result = makeError(StatusCode::kUnknown, error.what());
    } catch (...) {
      result = makeError(StatusCode::kUnknown, "EC read transport failed");
    }
    {
      std::lock_guard lock(state->mutex);
      state->responses[index].emplace(std::move(result));
    }
    requests.fetch_sub(1);
    // Exactly one completion per candidate; the queue has twelve slots and
    // never blocks a loser while the coordinator is joining its task.
    XCHECK(state->completed.try_enqueue(index));
  }

  void launch(const std::shared_ptr<State> &state, uint16_t index) {
    requests.fetch_add(1);
    try {
      state->attempts.add(readOne(state, index).scheduleOn(executor));
    } catch (...) {
      requests.fetch_sub(1);
      throw;
    }
  }

  CoTask<void> select(std::shared_ptr<State> state) {
    size_t launched = 0, inflight = 0, wanted = 11, accepted = 0, rejected = 0;
    std::array<EcSelectedShard, 10> selected;
    auto progress = Clock::now();
    while (true) {
      if (state->stop.isCancellationRequested()) {
        publish(state, makeError(StorageClientCode::kRequestCanceled));
        co_return;
      }
      const auto now = Clock::now();
      if (now >= state->options.deadline) {
        publish(state, makeError(StorageClientCode::kTimeout));
        co_return;
      }
      while (inflight < wanted && launched < 12) {
        launch(state, state->options.order[launched++]);
        ++inflight;
      }
      if (accepted + inflight + 12 - launched < 10) {
        publish(state, makeError(StorageClientCode::kChecksumMismatch, "fewer than ten valid EC sources remain"));
        co_return;
      }
      const bool canHedge = launched < 12 && inflight < 12;
      const auto hedgeAt = progress + state->options.hedgeAfter;
      if (canHedge && now >= hedgeAt) {
        wanted = inflight + 1;
        progress = now;
        continue;
      }
      const auto wakeAt = canHedge ? std::min(hedgeAt, state->options.deadline) : state->options.deadline;
      auto index = co_await folly::coro::co_withCancellation(state->stop.getToken(),
                                                             waitCompletion(state, wakeAt - Clock::now()));
      if (!index) continue;
      --inflight;
      Result<storage::EcReadResult> response = makeError(StatusCode::kUnknown);
      {
        std::lock_guard lock(state->mutex);
        response = std::move(*state->responses[*index]);
        state->responses[*index].reset();
      }
      if (!response) {
        ++rejected;
        continue;
      }
      if (state->stop.isCancellationRequested() || Clock::now() >= state->options.deadline) continue;
      selected[accepted++] = {*index, std::move(*response)};
      --wanted;
      progress = Clock::now();
      if (accepted == 10) {
        EcStripeSelection output;
        output.manifest = state->input.manifest;
        output.shards = std::move(selected);
        output.attempted = launched;
        output.rejected = rejected;
        output.quorumElapsed = Clock::now() - state->started;
        output.payloadReservation = state->reservation;
        publish(state, std::move(output));
        co_return;
      }
    }
  }

  CoTask<void> run(std::shared_ptr<State> state) {
    try {
      co_await select(state);
    } catch (const OperationCancelled &) {
      publish(state, makeError(StorageClientCode::kRequestCanceled));
    } catch (const std::exception &error) {
      publish(state, makeError(StatusCode::kUnknown, error.what()));
    } catch (...) {
      publish(state, makeError(StatusCode::kUnknown, "EC selection failed"));
    }
    state->stop.requestCancellation();
    // This join is after publishing ready, in the manager-owned operation.
    // It is deliberately not cancelled by a caller waiting for ten sources.
    co_await state->attempts.joinAsync();
    {
      std::lock_guard lock(state->mutex);
      for (auto &response : state->responses) response.reset();
      state->input.requests = {};
      state->reservation.reset();
    }
    {
      std::lock_guard lock(mutex);
      active.erase(state.get());
    }
    state->cleaned.post();
  }

  CoTask<void> close() {
    std::vector<std::shared_ptr<State>> states;
    bool first = false;
    {
      std::lock_guard lock(mutex);
      first = !closing;
      if (first) {
        states.reserve(active.size());
        for (const auto &entry : active) states.push_back(entry.second);
        closing = true;
      }
    }
    if (!first) {
      co_await closed;
      co_return;
    }
    for (const auto &state : states) state->stop.requestCancellation();
    co_await operations.joinAsync();
    closed.post();
  }
};

EcStripeReadHandle::EcStripeReadHandle(std::shared_ptr<State> state)
    : state_(std::move(state)) {}
EcStripeReadHandle::EcStripeReadHandle(EcStripeReadHandle &&) noexcept = default;
EcStripeReadHandle &EcStripeReadHandle::operator=(EcStripeReadHandle &&other) noexcept {
  if (this != &other) {
    cancel();
    state_ = std::move(other.state_);
  }
  return *this;
}
EcStripeReadHandle::~EcStripeReadHandle() { cancel(); }
CoTryTask<EcStripeSelection> EcStripeReadHandle::takeReady() { return ec::takeReady(state_); }
CoTask<void> EcStripeReadHandle::waitLocalCleanup() { return waitCleanup(state_); }
bool EcStripeReadHandle::ready() const { return state_ && state_->ready.ready(); }
bool EcStripeReadHandle::localCleanupComplete() const { return state_ && state_->cleaned.ready(); }
void EcStripeReadHandle::cancel() {
  if (state_) state_->stop.requestCancellation();
}

EcStripeRead::EcStripeRead(std::shared_ptr<EcReadTransport> transport,
                           folly::CPUThreadPoolExecutor &executor,
                           Limits limits)
    : impl_(std::make_unique<Impl>(std::move(transport), executor, limits)) {}
EcStripeRead::~EcStripeRead() = default;

Result<EcStripeReadHandle> EcStripeRead::start(EcStripeReadInput input, EcStripeReadOptions options) {
  RETURN_ON_ERROR(validateInput(input));
  std::array<bool, 12> seen{};
  for (auto index : options.order) {
    if (index >= 12 || seen[index]) return makeError(StatusCode::kInvalidArg, "invalid EC candidate order");
    seen[index] = true;
  }
  const auto now = Clock::now();
  if (!impl_->transport || options.deadline <= now || options.deadline - now > impl_->limits.maxOperationTime ||
      options.hedgeAfter <= std::chrono::milliseconds::zero()) {
    return makeError(StatusCode::kInvalidArg, "EC read needs a finite future deadline and positive hedge interval");
  }
  try {
    auto state = std::make_shared<State>();
    state->input = std::move(input);
    state->options = options;
    const auto bytes = size_t(state->input.manifest.fragments[0].integrity.wholeLength) * 12;
    std::lock_guard lock(impl_->mutex);
    const auto used = impl_->budget->bytes.load();
    if (impl_->closing || impl_->active.size() >= impl_->limits.maxOperations ||
        bytes > impl_->limits.maxPayloadBytes || used > impl_->limits.maxPayloadBytes - bytes) {
      return makeError(StorageClientCode::kResourceBusy, "EC selector admission budget exhausted or closing");
    }
    state->reservation = std::make_shared<detail::EcReadReservation>(impl_->budget, bytes);
    impl_->active.emplace(state.get(), state);
    try {
      impl_->operations.add(impl_->run(state).scheduleOn(impl_->executor));
    } catch (...) {
      impl_->active.erase(state.get());
      throw;
    }
    return EcStripeReadHandle(std::move(state));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

CoTask<void> EcStripeRead::close() { return impl_->close(); }
EcStripeRead::Snapshot EcStripeRead::snapshot() const {
  std::lock_guard lock(impl_->mutex);
  return {impl_->active.size(), impl_->requests.load(), impl_->budget->bytes.load()};
}

}  // namespace hf3fs::client::ec
