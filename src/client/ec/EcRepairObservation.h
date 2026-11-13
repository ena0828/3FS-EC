#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace hf3fs::client::ec {

// Local, opt-in observations, never serialized into an operation journal.
// Spans overlap and include scheduling/await time; their sum is NOT wall time.
// Invocations count entry into client/adapter methods, not dispatch, retry
// attempts or network packets. NativeRead enters NativeEcBlockTransport::read;
// it may reject locally before invoking StorageClient.
enum class EcRepairPoint : size_t {
  Query, Begin, Prepare, SelectedRepair, HealthyCopy, Publish, CloseDebt, Journal,
  NativeBegin, NativeRead, NativeAppend, NativeSeal, NativeHelper,
  CopyRead, CopyBegin, CopyReconcile, CopyAppend, CopySeal,
  BlockActor, OrderedAppendWait, Count
};
inline constexpr std::array<const char *, size_t(EcRepairPoint::Count)> kEcRepairPointNames{
    "query_rpc", "begin_rpc", "prepare_rpc", "selected_repair", "healthy_copy", "publish_rpc",
    "close_debt_rpc", "journal_append", "native_begin", "native_read", "native_append", "native_seal",
    "native_helper", "copy_read", "copy_begin", "copy_reconcile", "copy_append", "copy_seal",
    "block_actor", "ordered_append_wait"};

struct EcRepairPointSample {
  uint64_t entered = 0, finished = 0, succeeded = 0, spanNs = 0;
  uint64_t active = 0, peakActive = 0, apiInvocations = 0;
  uint64_t submittedPayloadBytes = 0, validatedReturnedPayloadBytes = 0;
};
struct EcRepairSample {
  bool available = false;
  uint8_t action = 0;  // query=0, repair=1, closeDebt=2
  bool journalStateObserved = false, hadJournalState = false;
  uint64_t priorJournalSequence = 0, elapsedNs = 0;
  uint16_t configuredWindow = 0;
  // CentralSerial retains whole source fragments, not these window actors.
  bool blockActorsApplicable = false;
  bool cancellationRequested = false, deadlineExpired = false;
  bool overflow = false, clockAnomaly = false;
  std::array<EcRepairPointSample, size_t(EcRepairPoint::Count)> points{};
  const EcRepairPointSample &at(EcRepairPoint point) const { return points[size_t(point)]; }
};

// Caller owns this fixed-size object until all instrumented children join.
// No allocation, I/O, callback or error conversion occurs in this observer.
// nullptr at every call site disables all observer clock/atomic operations.
class EcRepairObservation {
  using Clock = std::chrono::steady_clock;
  struct Counter {
    std::atomic<uint64_t> entered{}, finished{}, succeeded{}, spanNs{};
    std::atomic<uint64_t> active{}, peakActive{}, apiInvocations{};
    std::atomic<uint64_t> submittedPayloadBytes{}, validatedReturnedPayloadBytes{};
  };
  std::array<Counter, size_t(EcRepairPoint::Count)> counters_{};
  std::atomic<bool> overflow_{false}, clockAnomaly_{false};
  Clock::time_point start_ = Clock::now();

  uint64_t add(std::atomic<uint64_t> &value, uint64_t amount) noexcept {
    auto old = value.load(std::memory_order_relaxed);
    for (;;) {
      const auto limit = std::numeric_limits<uint64_t>::max();
      const bool exceeds = amount > limit - old;
      const auto next = exceeds ? limit : old + amount;
      if (value.compare_exchange_weak(old, next, std::memory_order_relaxed)) {
        if (exceeds) overflow_.store(true, std::memory_order_relaxed);
        return next;
      }
    }
  }
  uint64_t elapsed(Clock::time_point start) noexcept {
    const auto end = Clock::now();
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

 public:
  class Scope {
    EcRepairObservation *owner_;
    Counter *counter_ = nullptr;
    Clock::time_point start_{};
    bool succeeded_ = false;

   public:
    Scope(EcRepairObservation *owner, EcRepairPoint point) noexcept : owner_(owner) {
      if (!owner_) return;
      counter_ = &owner_->counters_[size_t(point)];
      start_ = Clock::now();
      owner_->add(counter_->entered, 1);
      const auto active = owner_->add(counter_->active, 1);
      auto peak = counter_->peakActive.load(std::memory_order_relaxed);
      while (peak < active && !counter_->peakActive.compare_exchange_weak(peak, active, std::memory_order_relaxed)) {}
    }
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
    ~Scope() noexcept { finish(); }
    void success() noexcept { succeeded_ = true; }
    void noteInvocation(uint64_t submittedPayload = 0) noexcept {
      if (!owner_) return;
      owner_->add(counter_->apiInvocations, 1);
      owner_->add(counter_->submittedPayloadBytes, submittedPayload);
    }
    void validated(uint64_t bytes) noexcept {
      if (owner_) owner_->add(counter_->validatedReturnedPayloadBytes, bytes);
    }
    void finish() noexcept {
      if (!owner_) return;
      owner_->add(counter_->spanNs, owner_->elapsed(start_));
      if (succeeded_) owner_->add(counter_->succeeded, 1);
      owner_->add(counter_->finished, 1);
      counter_->active.fetch_sub(1, std::memory_order_relaxed);
      owner_ = nullptr;
    }
  };

  // Concurrent snapshots are diagnostic only. A final snapshot is taken AFTER
  // real local joins; finished means local scope exit, never remote commit/T2.
  EcRepairSample snapshot() noexcept {
    EcRepairSample out;
    out.available = true;
    out.elapsedNs = elapsed(start_);
    out.overflow = overflow_.load(std::memory_order_relaxed);
    out.clockAnomaly = clockAnomaly_.load(std::memory_order_relaxed);
    for (size_t i = 0; i != counters_.size(); ++i) {
      const auto &c = counters_[i];
      out.points[i] = {c.entered.load(std::memory_order_relaxed), c.finished.load(std::memory_order_relaxed),
                       c.succeeded.load(std::memory_order_relaxed), c.spanNs.load(std::memory_order_relaxed),
                       c.active.load(std::memory_order_relaxed), c.peakActive.load(std::memory_order_relaxed),
                       c.apiInvocations.load(std::memory_order_relaxed),
                       c.submittedPayloadBytes.load(std::memory_order_relaxed),
                       c.validatedReturnedPayloadBytes.load(std::memory_order_relaxed)};
    }
    return out;
  }
};

}  // namespace hf3fs::client::ec
