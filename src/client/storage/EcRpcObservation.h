#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "common/serde/MessagePacket.h"

namespace hf3fs::storage::client {

// Local, opt-in observations of the client -> Storage first hop. No wire or
// journal fields, payloads, credentials, callbacks or allocations. Optional
// local permit intervals use steady_clock, separately from RPC host timestamps.
enum class EcRpcMethod : size_t { Read, Begin, Append, Query, Reconcile, Seal, Helper, Count };
inline constexpr std::array<const char *, size_t(EcRpcMethod::Count)> kEcRpcMethodNames{
    "read_block", "begin_stage", "append_stage", "query_stage", "reconcile_stage", "seal_stage", "helper"};

struct EcRpcClockSample {
  uint64_t valid = 0, missing = 0, reversed = 0, outOfRange = 0;
  std::array<uint64_t, 3> spanNs{};
};
enum class EcRpcLimiter : size_t { PerServer, Global, Count };
struct EcRpcLimiterSample {
  uint64_t entered = 0, acquired = 0, finished = 0, withoutPermit = 0;
  uint64_t active = 0, peakActive = 0;
  uint64_t acquiredWaitNs = 0, unacquiredSpanNs = 0, heldNs = 0;
};
struct EcRpcMethodSample {
  uint64_t entered = 0, finished = 0, active = 0;
  uint64_t outerOk = 0, outerError = 0, withoutResult = 0;
  uint64_t messengerInvocations = 0, withoutMessenger = 0;
  // Helper uses separate non-waiting admission, not these stage limiters.
  std::array<EcRpcLimiterSample, size_t(EcRpcLimiter::Count)> limiters{};
  EcRpcClockSample client, server;
};
struct EcRpcSample {
  bool overflow = false, clockAnomaly = false;
  std::array<EcRpcMethodSample, size_t(EcRpcMethod::Count)> methods{};
  const EcRpcMethodSample &at(EcRpcMethod method) const { return methods[size_t(method)]; }
};

class EcRpcObservation {
  using Clock = std::chrono::steady_clock;
  struct LimiterCounter {
    std::atomic<uint64_t> entered{}, acquired{}, finished{}, withoutPermit{};
    std::atomic<uint64_t> active{}, peakActive{};
    std::atomic<uint64_t> acquiredWaitNs{}, unacquiredSpanNs{}, heldNs{};
  };
  struct ClockCounter {
    std::atomic<uint64_t> valid{}, missing{}, reversed{}, outOfRange{};
    std::array<std::atomic<uint64_t>, 3> spanNs{};
  };
  struct Counter {
    std::atomic<uint64_t> entered{}, finished{}, active{};
    std::atomic<uint64_t> outerOk{}, outerError{}, withoutResult{};
    std::atomic<uint64_t> messengerInvocations{}, withoutMessenger{};
    std::array<LimiterCounter, size_t(EcRpcLimiter::Count)> limiters{};
    ClockCounter client, server;
  };
  std::array<Counter, size_t(EcRpcMethod::Count)> counters_{};
  std::atomic<bool> overflow_{false}, clockAnomaly_{false};

  uint64_t add(std::atomic<uint64_t> &value, uint64_t amount) noexcept {
    auto old = value.load(std::memory_order_relaxed);
    for (;;) {
      constexpr auto limit = std::numeric_limits<uint64_t>::max();
      const bool exceeds = amount > limit - old;
      const auto next = exceeds ? limit : old + amount;
      if (value.compare_exchange_weak(old, next, std::memory_order_relaxed)) {
        if (exceeds) overflow_.store(true, std::memory_order_relaxed);
        return next;
      }
    }
  }
  uint64_t elapsed(Clock::time_point start, Clock::time_point end) noexcept {
    if (end < start) {
      clockAnomaly_.store(true, std::memory_order_relaxed);
      return 0;
    }
    const auto nanos = std::chrono::duration<long double, std::nano>(end - start).count();
    if (nanos >= std::numeric_limits<uint64_t>::max()) {
      overflow_.store(true, std::memory_order_relaxed);
      return std::numeric_limits<uint64_t>::max();
    }
    return uint64_t(nanos);
  }
  void observe(ClockCounter &counter, const std::array<int64_t, 4> &points) noexcept {
    // Each group belongs to ONE host. Never compare client and server epochs.
    for (auto point : points) {
      if (point <= 0) {
        add(counter.missing, 1);
        return;
      }
    }
    std::array<uint64_t, 3> spans{};
    for (size_t i = 0; i != spans.size(); ++i) {
      if (points[i + 1] < points[i]) {
        add(counter.reversed, 1);
        clockAnomaly_.store(true, std::memory_order_relaxed);
        return;
      }
      const auto micros = uint64_t(points[i + 1]) - uint64_t(points[i]);
      if (micros > std::numeric_limits<uint64_t>::max() / 1000) {
        add(counter.outOfRange, 1);
        overflow_.store(true, std::memory_order_relaxed);
        return;
      }
      spans[i] = micros * 1000;
    }
    add(counter.valid, 1);
    for (size_t i = 0; i != spans.size(); ++i) add(counter.spanNs[i], spans[i]);
  }
  static EcRpcClockSample snapshot(const ClockCounter &counter) noexcept {
    EcRpcClockSample out;
    out.valid = counter.valid.load(std::memory_order_relaxed);
    out.missing = counter.missing.load(std::memory_order_relaxed);
    out.reversed = counter.reversed.load(std::memory_order_relaxed);
    out.outOfRange = counter.outOfRange.load(std::memory_order_relaxed);
    for (size_t i = 0; i != out.spanNs.size(); ++i)
      out.spanNs[i] = counter.spanNs[i].load(std::memory_order_relaxed);
    return out;
  }

 public:
  // Declare BEFORE the matching SemaphoreGuard. Its destructor then observes
  // exit AFTER the real guard releases. Entry includes the fast acquire path;
  // active/peakActive cover waiting AND holding, never queue depth. Unacquired
  // exits are censored separately. nullptr performs no clock/atomic operations.
  class LimiterScope {
    EcRpcObservation *owner_ = nullptr;
    LimiterCounter *counter_ = nullptr;
    Clock::time_point start_{}, acquiredAt_{};
    bool acquired_ = false;

   public:
    LimiterScope(EcRpcObservation *owner, EcRpcMethod method, EcRpcLimiter limiter) noexcept {
      if (!owner || size_t(method) >= size_t(EcRpcMethod::Count) || method == EcRpcMethod::Helper ||
          size_t(limiter) >= size_t(EcRpcLimiter::Count))
        return;
      owner_ = owner;
      counter_ = &owner->counters_[size_t(method)].limiters[size_t(limiter)];
      start_ = Clock::now();
      owner_->add(counter_->entered, 1);
      const auto active = owner_->add(counter_->active, 1);
      auto peak = counter_->peakActive.load(std::memory_order_relaxed);
      while (peak < active && !counter_->peakActive.compare_exchange_weak(peak, active, std::memory_order_relaxed)) {}
    }
    LimiterScope(const LimiterScope &) = delete;
    LimiterScope &operator=(const LimiterScope &) = delete;
    void acquired() noexcept {
      if (!owner_ || acquired_) return;
      acquiredAt_ = Clock::now();
      acquired_ = true;
      owner_->add(counter_->acquired, 1);
      owner_->add(counter_->acquiredWaitNs, owner_->elapsed(start_, acquiredAt_));
    }
    ~LimiterScope() noexcept {
      if (!owner_) return;
      const auto end = Clock::now();
      if (acquired_) {
        owner_->add(counter_->heldNs, owner_->elapsed(acquiredAt_, end));
      } else {
        owner_->add(counter_->withoutPermit, 1);
        owner_->add(counter_->unacquiredSpanNs, owner_->elapsed(start_, end));
      }
      owner_->add(counter_->finished, 1);
      counter_->active.fetch_sub(1, std::memory_order_relaxed);
    }
  };

  // Borrowed ONLY by the joined callMessengerMethod frame, never by a Waiter,
  // WriteItem or network task. The owner must outlive every local child join.
  class Scope {
    EcRpcObservation *owner_ = nullptr;
    Counter *counter_ = nullptr;
    bool recorded_ = false;
    bool messengerInvoked_ = false;

   public:
    Scope(EcRpcObservation *owner, EcRpcMethod method) noexcept {
      if (!owner || size_t(method) >= size_t(EcRpcMethod::Count)) return;
      owner_ = owner;
      counter_ = &owner->counters_[size_t(method)];
      owner_->add(counter_->entered, 1);
      owner_->add(counter_->active, 1);
    }
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
    ~Scope() noexcept {
      if (!owner_) return;
      if (!messengerInvoked_) owner_->add(counter_->withoutMessenger, 1);
      if (!recorded_) {
        // Local rejection or exception before the await expression produced a
        // Result. This is not evidence of a network dispatch or remote failure.
        owner_->add(counter_->withoutResult, 1);
        owner_->add(counter_->client.missing, 1);
        owner_->add(counter_->server.missing, 1);
      }
      owner_->add(counter_->finished, 1);
      counter_->active.fetch_sub(1, std::memory_order_relaxed);
    }
    // Immediately before the actual std::invoke expression, inside the
    // non-injected branch. This is an API call, NOT serialization, dispatch,
    // retry, bytes accepted by a socket, or proof of a remote operation.
    void messengerInvocation() noexcept {
      if (!owner_) return;
      messengerInvoked_ = true;
      owner_->add(counter_->messengerInvocations, 1);
    }
    void returned(bool outerOk, const serde::Timestamp &timestamp) noexcept {
      if (!owner_ || recorded_) return;
      recorded_ = true;
      owner_->add(outerOk ? counter_->outerOk : counter_->outerError, 1);
      // An outer error can carry a valid timestamp. Conversely fault injection
      // or a local/transport failure can return a Result without any timestamp.
      owner_->observe(counter_->client, {timestamp.clientCalled, timestamp.clientSerialized,
                                         timestamp.clientReceived, timestamp.clientWaked});
      owner_->observe(counter_->server, {timestamp.serverReceived, timestamp.serverWaked,
                                         timestamp.serverProcessed, timestamp.serverSerialized});
    }
  };

  // Final snapshots are taken after all local frames finish. Concurrent
  // snapshots are diagnostic; finished never means remote commit or T2.
  EcRpcSample snapshot() const noexcept {
    EcRpcSample out;
    out.overflow = overflow_.load(std::memory_order_relaxed);
    out.clockAnomaly = clockAnomaly_.load(std::memory_order_relaxed);
    for (size_t i = 0; i != counters_.size(); ++i) {
      const auto &c = counters_[i];
      auto &s = out.methods[i];
      s.entered = c.entered.load(std::memory_order_relaxed);
      s.finished = c.finished.load(std::memory_order_relaxed);
      s.active = c.active.load(std::memory_order_relaxed);
      s.outerOk = c.outerOk.load(std::memory_order_relaxed);
      s.outerError = c.outerError.load(std::memory_order_relaxed);
      s.withoutResult = c.withoutResult.load(std::memory_order_relaxed);
      s.messengerInvocations = c.messengerInvocations.load(std::memory_order_relaxed);
      s.withoutMessenger = c.withoutMessenger.load(std::memory_order_relaxed);
      for (size_t j = 0; j != s.limiters.size(); ++j) {
        const auto &l = c.limiters[j];
        s.limiters[j] = {l.entered.load(std::memory_order_relaxed), l.acquired.load(std::memory_order_relaxed),
                         l.finished.load(std::memory_order_relaxed), l.withoutPermit.load(std::memory_order_relaxed),
                         l.active.load(std::memory_order_relaxed), l.peakActive.load(std::memory_order_relaxed),
                         l.acquiredWaitNs.load(std::memory_order_relaxed),
                         l.unacquiredSpanNs.load(std::memory_order_relaxed), l.heldNs.load(std::memory_order_relaxed)};
      }
      s.client = snapshot(c.client);
      s.server = snapshot(c.server);
    }
    return out;
  }
};

}  // namespace hf3fs::storage::client
