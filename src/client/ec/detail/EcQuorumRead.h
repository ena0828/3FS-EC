#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/experimental/coro/AsyncScope.h>
#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/Collect.h>
#include <folly/experimental/coro/Sleep.h>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <unordered_map>
#include <vector>

#include "common/utils/BoundedQueue.h"
#include "common/utils/Coroutine.h"

namespace hf3fs::client::ec::detail {

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

  // The coordinator exclusively owns this mutable lease before publication.
  // Adopt part of its existing charge: never subtract then re-admit, and never
  // double-charge the split. Allocation failure leaves the original intact.
  std::shared_ptr<const EcReadReservation> split(size_t count) {
    XCHECK_LE(count, bytes);
    // Both the object and shared_ptr control block must exist before adopting
    // charge; a throwing allocation must not run a charged destructor.
    auto part = std::make_shared<EcReadReservation>(budget, 0);
    bytes -= count;
    part->bytes = count;
    return part;
  }
};

struct EcQuorumOptions {
  std::chrono::steady_clock::time_point deadline;
  std::chrono::milliseconds hedgeAfter{10};
  std::array<uint16_t, 12> order{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
};
struct EcQuorumLimits {
  size_t maxOperations;
  size_t maxPayloadBytes;
  std::chrono::seconds maxOperationTime;
};
struct EcQuorumSnapshot {
  size_t activeOperations, activeRequests, reservedPayloadBytes;
};

template <typename Response>
struct EcQuorumSelection {
  // Declared before payloads so destruction releases bytes before their charge.
  std::shared_ptr<const EcReadReservation> reservation;
  struct Shard {
    uint16_t index = 0;
    Response result;
  };
  std::array<Shard, 10> shards;
  size_t attempted = 0, rejected = 0;
  std::chrono::steady_clock::duration quorumElapsed{};
  EcQuorumSelection() = default;
  EcQuorumSelection(EcQuorumSelection &&) noexcept = default;
  EcQuorumSelection(const EcQuorumSelection &) = delete;
  EcQuorumSelection &operator=(const EcQuorumSelection &) = delete;
  EcQuorumSelection &operator=(EcQuorumSelection &&other) noexcept {
    if (this != &other) {
      shards = std::move(other.shards);
      reservation = std::move(other.reservation);
      attempted = other.attempted;
      rejected = other.rejected;
      quorumElapsed = other.quorumElapsed;
    }
    return *this;
  }
};

// One scheduling/ownership implementation for full-shard and V2 block reads.
// A policy supplies fixed input validation, actual-response verification and
// an owned transport call. No response counts toward quorum before validation.
template <typename Policy>
class EcQuorumRead {
  using Input = typename Policy::Input;
  using Response = typename Policy::Response;
  using Clock = std::chrono::steady_clock;

 public:
  using Selection = EcQuorumSelection<Response>;

 private:
  struct State {
    Input input;
    EcQuorumOptions options;
    Clock::time_point started = Clock::now();
    CancellationSource stop;
    folly::coro::AsyncScope attempts;
    BoundedQueue<uint16_t> completed{12};
    std::mutex mutex;
    std::array<std::optional<Result<Response>>, 12> responses;
    std::optional<Result<Selection>> result;
    bool resultTaken = false;
    folly::coro::Baton ready, cleaned;
    std::shared_ptr<EcReadReservation> reservation;
    size_t shardBytes = 0;
  };
  static void publish(const std::shared_ptr<State> &state, Result<Selection> result) {
    {
      std::lock_guard lock(state->mutex);
      if (state->result) return;
      if (result && state->stop.isCancellationRequested()) result = makeError(StorageClientCode::kRequestCanceled);
      if (result && Clock::now() >= state->options.deadline) result = makeError(StorageClientCode::kTimeout);
      state->result.emplace(std::move(result));
    }
    state->ready.post();
  }
  static CoTryTask<Selection> take(std::shared_ptr<State> state) {
    if (!state) co_return makeError(StatusCode::kInvalidArg, "empty EC quorum handle");
    co_await state->ready;
    std::lock_guard lock(state->mutex);
    if (state->resultTaken) co_return makeError(StatusCode::kInvalidArg, "EC selection already consumed");
    state->resultTaken = true;
    co_return std::move(*state->result);
  }
  static CoTask<void> wait(std::shared_ptr<State> state) {
    if (state) co_await state->cleaned;
  }
  static CoTask<std::optional<uint16_t>> completion(std::shared_ptr<State> state, Clock::duration duration) {
    auto [timer, response] = co_await folly::coro::collectAnyNoDiscard(
        folly::coro::sleep(std::chrono::ceil<std::chrono::microseconds>(duration)),
        state->completed.co_dequeue());
    if (response.hasValue()) co_return *response;
    if (response.hasException() && !response.template hasException<OperationCancelled>()) response.value();
    if (timer.hasException() && !timer.template hasException<OperationCancelled>()) timer.value();
    co_return std::nullopt;
  }

 public:
  class Handle {
   public:
    explicit Handle(std::shared_ptr<State> state)
        : state_(std::move(state)) {}
    Handle(Handle &&) noexcept = default;
    Handle &operator=(Handle &&other) noexcept {
      if (this != &other) {
        cancel();
        state_ = std::move(other.state_);
      }
      return *this;
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    ~Handle() { cancel(); }
    CoTryTask<Selection> takeReady() { return take(state_); }
    CoTask<void> waitLocalCleanup() { return wait(state_); }
    bool ready() const { return state_ && state_->ready.ready(); }
    bool localCleanupComplete() const { return state_ && state_->cleaned.ready(); }
    void cancel() {
      if (state_) state_->stop.requestCancellation();
    }

   private:
    std::shared_ptr<State> state_;
  };

  EcQuorumRead(std::shared_ptr<Policy> policy, folly::CPUThreadPoolExecutor &executor, EcQuorumLimits limits)
      : policy_(std::move(policy)),
        executor_(folly::getKeepAliveToken(executor)),
        limits_(limits) {}
  EcQuorumRead(const EcQuorumRead &) = delete;
  EcQuorumRead &operator=(const EcQuorumRead &) = delete;
  // close() must finish before destruction, exactly as required by AsyncScope.
  ~EcQuorumRead() = default;

  Result<Handle> start(Input input, EcQuorumOptions options) {
    if (!policy_) return makeError(StatusCode::kInvalidArg, "missing EC quorum policy");
    RETURN_ON_ERROR(policy_->validateInput(input));
    std::array<bool, 12> seen{};
    for (auto index : options.order) {
      if (index >= 12 || seen[index]) return makeError(StatusCode::kInvalidArg, "invalid EC candidate order");
      seen[index] = true;
    }
    const auto now = Clock::now();
    if (!policy_->available() || options.deadline <= now || options.deadline - now > limits_.maxOperationTime ||
        options.hedgeAfter <= std::chrono::milliseconds::zero()) {
      return makeError(StatusCode::kInvalidArg, "EC read needs a finite future deadline and positive hedge interval");
    }
    const auto length = policy_->payloadLength(input);
    if (length == 0 || length > std::numeric_limits<size_t>::max() / 12) {
      return makeError(StatusCode::kInvalidArg, "invalid EC response extent");
    }
    try {
      auto state = std::make_shared<State>();
      state->input = std::move(input);
      state->options = options;
      state->shardBytes = length;
      const size_t bytes = length * 12;
      std::lock_guard lock(mutex_);
      const auto used = budget_->bytes.load();
      if (closing_ || active_.size() >= limits_.maxOperations || bytes > limits_.maxPayloadBytes ||
          used > limits_.maxPayloadBytes - bytes) {
        return makeError(StorageClientCode::kResourceBusy, "EC selector admission budget exhausted or closing");
      }
      state->reservation = std::make_shared<EcReadReservation>(budget_, bytes);
      active_.emplace(state.get(), state);
      try {
        operations_.add(run(state).scheduleOn(executor_));
      } catch (...) {
        active_.erase(state.get());
        throw;
      }
      return Handle(std::move(state));
    } catch (const std::bad_alloc &) {
      return makeError(StatusCode::kNotEnoughMemory);
    }
  }
  CoTask<void> close() {
    std::vector<std::shared_ptr<State>> states;
    bool first = false;
    {
      std::lock_guard lock(mutex_);
      first = !closing_;
      if (first) {
        states.reserve(active_.size());
        for (const auto &entry : active_) states.push_back(entry.second);
        closing_ = true;
      }
    }
    if (!first) {
      co_await closed_;
      co_return;
    }
    for (const auto &state : states) state->stop.requestCancellation();
    co_await operations_.joinAsync();
    closed_.post();
  }
  EcQuorumSnapshot snapshot() const {
    std::lock_guard lock(mutex_);
    return {active_.size(), requests_.load(), budget_->bytes.load()};
  }

 private:
  CoTask<void> readOne(std::shared_ptr<State> state, uint16_t index) {
    Result<Response> result = makeError(StorageClientCode::kRequestCanceled);
    try {
      if (!state->stop.isCancellationRequested() && Clock::now() < state->options.deadline) {
        result = co_await policy_->read(state->input, index, state->options.deadline, state->stop.getToken());
        if (result) {
          auto valid = policy_->validateResponse(state->input, index, *result);
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
    requests_.fetch_sub(1);
    XCHECK(state->completed.try_enqueue(index));
  }
  void launch(const std::shared_ptr<State> &state, uint16_t index) {
    requests_.fetch_add(1);
    try {
      state->attempts.add(readOne(state, index).scheduleOn(executor_));
    } catch (...) {
      requests_.fetch_sub(1);
      throw;
    }
  }
  CoTask<void> select(std::shared_ptr<State> state) {
    size_t launched = 0, inflight = 0, wanted = 11, accepted = 0, rejected = 0;
    std::array<typename Selection::Shard, 10> selected;
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
      auto index =
          co_await folly::coro::co_withCancellation(state->stop.getToken(), completion(state, wakeAt - Clock::now()));
      if (!index) continue;
      --inflight;
      Result<Response> response = makeError(StatusCode::kUnknown);
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
        Selection output;
        output.shards = std::move(selected);
        output.attempted = launched;
        output.rejected = rejected;
        output.quorumElapsed = Clock::now() - state->started;
        if constexpr (Policy::splitOutputReservation)
          output.reservation = state->reservation->split(state->shardBytes * 10);
        else
          output.reservation = state->reservation;  // Preserve legacy full-shard metric behavior.
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
    co_await state->attempts.joinAsync();
    {
      std::lock_guard lock(state->mutex);
      for (auto &response : state->responses) response.reset();
      policy_->clearInput(state->input);
      state->reservation.reset();
    }
    {
      std::lock_guard lock(mutex_);
      active_.erase(state.get());
    }
    state->cleaned.post();
  }

  std::shared_ptr<Policy> policy_;
  folly::Executor::KeepAlive<> executor_;
  EcQuorumLimits limits_;
  std::shared_ptr<EcReadBudget> budget_ = std::make_shared<EcReadBudget>();
  mutable std::mutex mutex_;
  std::unordered_map<State *, std::shared_ptr<State>> active_;
  std::atomic<size_t> requests_{0};
  folly::coro::AsyncScope operations_;
  bool closing_ = false;
  folly::coro::Baton closed_;
};
}  // namespace hf3fs::client::ec::detail
