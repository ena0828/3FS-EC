#pragma once

#include <atomic>
#include <exception>
#include <folly/experimental/coro/Baton.h>
#include <memory>

#include "common/utils/Coroutine.h"

namespace hf3fs::storage {
class EcJobCompletionTestAccess;

// Only EC borrowed jobs use this owner. Ordinary UpdateJob stays unchanged.
// Construction allocates before claim/queue admission. Once claimed, either
// the producer publishes a pre-enqueue failure or a worker publishes completion.
class EcJobCompletion {
 public:
  EcJobCompletion() = default;
  EcJobCompletion(const EcJobCompletion &) = delete;
  EcJobCompletion &operator=(const EcJobCompletion &) = delete;
  void claim() noexcept {
    if (state_->claimed.exchange(true)) std::terminate();
  }
  void commitQueued() noexcept { state_->queued.store(true, std::memory_order_release); }
  bool queued() const noexcept { return state_->queued.load(std::memory_order_acquire); }
  bool observed() const noexcept { return state_->observed.load(std::memory_order_acquire); }
  bool waitFailed() const noexcept { return state_->waitFailed.load(std::memory_order_acquire); }
  void failedWait() noexcept { state_->waitFailed.store(true, std::memory_order_release); }

  // Call only after the final result write. Neither caller nor worker may
  // access the borrowed job after this: ready.post may resume inline and
  // destroy it. This local strong reference keeps the completion object alive.
  void finish() noexcept {
    auto owned = state_;
    if (owned->finished.exchange(true, std::memory_order_acq_rel)) std::terminate();
    owned->finished.notify_all();
    owned->ready.post();
  }
  void waitFinished() const noexcept {
    auto owned = state_;
    while (!owned->finished.load(std::memory_order_acquire)) {
      owned->finished.wait(false, std::memory_order_acquire);
    }
  }
  // Called in the containing Job destructor before its result/target/ticket
  // members are destroyed. This covers failure creating observe()'s Task at
  // the call site, which cannot be caught inside that coroutine's body.
  void retainUntilFinished() const noexcept {
    if (state_->claimed.load(std::memory_order_acquire)) waitFinished();
  }
  CoTask<void> observe() const {
    auto owned = state_;
    try {
      if (beforeAwait_) beforeAwait_();
      co_await owned->ready;
    } catch (...) {
      owned->waitFailed.store(true, std::memory_order_release);
      while (!owned->finished.load(std::memory_order_acquire)) {
        owned->finished.wait(false, std::memory_order_acquire);
      }
    }
    owned->observed.store(true, std::memory_order_release);
  }

 private:
  friend class EcJobCompletionTestAccess;
  struct State {
    std::atomic<bool> claimed{false};
    std::atomic<bool> queued{false};
    std::atomic<bool> finished{false};
    std::atomic<bool> observed{false};
    std::atomic<bool> waitFailed{false};
    folly::coro::Baton ready;
  };
  std::shared_ptr<State> state_ = std::make_shared<State>();
  // Deterministic private test seam, never set by production requests/config.
  void (*beforeAwait_)() = nullptr;
};
}  // namespace hf3fs::storage
