#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Sleep.h>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "common/kv/IKVEngine.h"
#include "common/utils/SerDeser.h"
#include "fbs/meta/EcFileTruncate.h"
#include "meta/store/detail/EcFileTreeKeys.h"

namespace hf3fs::meta::server::detail {
// Test-owned fault and trace. A selected real FDB transaction first reads a
// private sentinel. An independent raw transaction changes that sentinel and
// commits before the original commit. No transaction result is synthesized.
class EcMountedTruncateFault {
 public:
  enum class Method : uint8_t { Query, Begin, Advance, Close };
  // Bounded above the RPC count admitted by the 4096-state journal, including
  // slow successful Planned polling. Overflow still invalidates the trace.
  static constexpr size_t kCapacity = 2048;
  static constexpr size_t kIgnored = kCapacity;
  struct Event {
    Method method = Method::Query;
    Uuid request = Uuid::zero();
    status_code_t status = StatusCode::kOK;
    bool finished = false;
  };
  struct Snapshot {
    std::array<Event, kCapacity> events{};
    size_t count = 0;
    std::optional<EcFileTruncateIntent> intent;
    std::array<Uuid, 4> requests{};
    bool changed = false;
    bool overflow = false;
    size_t injections = 0;
    size_t competingCommits = 0;
    size_t conflicts = 0;
    size_t originalCommits = 0;
    size_t setupErrors = 0;
    status_code_t lastSetupError = StatusCode::kOK;
  };

  void arm(const EcObjectRef &object,
           EcFileTruncateState state,
           size_t count,
           std::chrono::milliseconds delay = std::chrono::milliseconds{0}) {
    if ((state != EcFileTruncateState::Planned && state != EcFileTruncateState::Published) ||
        count > 64 || delay.count() < 0 || delay > std::chrono::seconds(5))
      throw std::invalid_argument("invalid bounded truncate fault");
    std::lock_guard lock(mutex_);
    if (activeFrames_ || activeInjections_) throw std::logic_error("truncate fault still has owned work");
    if (generation_ == UINT64_MAX) throw std::overflow_error("truncate fault generation overflow");
    ++generation_;
    objectBytes_ = bytes(object);
    state_ = state;
    remaining_ = count;
    delay_ = delay;
    snapshot_ = {};
    snapshot_.requests.fill(Uuid::zero());
    intentBytes_.clear();
    key_.clear();
    // The random suffix is test-private and never a production record key.
    sentinel_ = "test/ec-mounted-truncate-conflict/";
    sentinel_.append(Uuid::random().asStringView());
    armed_ = true;
  }

  size_t enter(Method method, const EcFileTruncateIntent &intent, const Uuid &request) {
    std::lock_guard lock(mutex_);
    if (!armed_ || bytes(intent.object) != objectBytes_) return kIgnored;
    const auto slot = static_cast<size_t>(method);
    if (slot >= snapshot_.requests.size()) {
      snapshot_.changed = true;
      return kIgnored;
    }
    if (!snapshot_.intent) {
      if (method != Method::Query) snapshot_.changed = true;
      snapshot_.intent = intent;
      intentBytes_ = bytes(intent);
      key_ = ec_tree_detail::idKey(kv::KeyPrefix::EcFileTruncate, intent.object, intent.operation);
    } else if (bytes(intent) != intentBytes_) {
      snapshot_.changed = true;
    }
    auto &fixed = snapshot_.requests[slot];
    if (request.is_nil()) snapshot_.changed = true;
    if (fixed.is_nil()) fixed = request;
    else if (fixed != request) snapshot_.changed = true;
    if (snapshot_.count == kCapacity) {
      snapshot_.overflow = true;
      return kIgnored;
    }
    const auto index = snapshot_.count++;
    snapshot_.events[index] = {method, request, StatusCode::kOK, false};
    ++activeFrames_;
    return index;
  }

  void finish(size_t index, status_code_t status) {
    if (index == kIgnored) return;
    std::lock_guard lock(mutex_);
    if (index >= snapshot_.count || snapshot_.events[index].finished || !activeFrames_) {
      snapshot_.changed = true;
      return;
    }
    snapshot_.events[index].status = status;
    snapshot_.events[index].finished = true;
    --activeFrames_;
  }

  Snapshot snapshot() const {
    std::lock_guard lock(mutex_);
    return snapshot_;
  }

  // Unrelated writes leave the selection unchanged. A later write to the
  // exact selected key replaces it, including clearing an ineligible state.
  std::optional<uint64_t> selectSet(std::string_view key, std::string_view value) const {
    std::lock_guard lock(mutex_);
    if (!armed_ || key_ != key || !snapshot_.intent) return std::nullopt;
    if (!remaining_ || snapshot_.changed) return 0;
    EcFileTruncateRecord record;
    if (!serde::deserialize(record, value) || record.version != kEcFileTruncateVersion ||
        record.state != state_ || bytes(record.intent) != intentBytes_)
      return 0;
    return generation_;
  }

  CoTryTask<bool> beforeCommit(kv::IReadWriteTransaction &original,
                              kv::IKVEngine &rawEngine,
                              uint64_t token) {
    std::string sentinel;
    std::chrono::milliseconds delay{0};
    size_t ordinal = 0;
    {
      std::lock_guard lock(mutex_);
      if (!token || token != generation_ || !remaining_ || snapshot_.changed) co_return false;
      --remaining_;
      ordinal = ++snapshot_.injections;
      ++activeInjections_;
      sentinel = sentinel_;
      delay = delay_;
    }
    // This guard tracks preparation; the enclosing service frame remains
    // active until the original commit returns. Setup errors are separate from
    // originalCommitted, which records only a successfully prepared conflict.
    auto finished = folly::makeGuard([&] {
      std::lock_guard lock(mutex_);
      --activeInjections_;
    });
    auto read = co_await original.get(sentinel);  // Non-snapshot read conflict.
    CO_RETURN_ON_ERROR(read);
    auto competing = rawEngine.createReadWriteTransaction();
    if (!competing) co_return makeError(StatusCode::kKVStoreNotFound);
    const auto value = std::to_string(ordinal);
    CO_RETURN_ON_ERROR(co_await competing->set(sentinel, value));
    CO_RETURN_ON_ERROR(co_await competing->commit());
    {
      std::lock_guard lock(mutex_);
      ++snapshot_.competingCommits;
    }
    if (delay.count()) co_await folly::coro::sleep(delay);
    co_return true;
  }

  void setupFailed(status_code_t status) {
    std::lock_guard lock(mutex_);
    ++snapshot_.setupErrors;
    snapshot_.lastSetupError = status;
  }
  void originalCommitted(bool injected, status_code_t status) {
    if (!injected) return;
    std::lock_guard lock(mutex_);
    ++snapshot_.originalCommits;
    if (status == TransactionCode::kConflict) ++snapshot_.conflicts;
  }

 private:
  template <class T>
  static std::string bytes(const T &value) {
    auto encoded = serde::serialize(value);
    return std::string(encoded.data(), encoded.size());
  }
  mutable std::mutex mutex_;
  Snapshot snapshot_;
  bool armed_ = false;
  EcFileTruncateState state_ = EcFileTruncateState::Planned;
  size_t remaining_ = 0, activeFrames_ = 0, activeInjections_ = 0;
  uint64_t generation_ = 0;
  std::chrono::milliseconds delay_{0};
  std::string objectBytes_, intentBytes_, key_, sentinel_;
};
}  // namespace hf3fs::meta::server::detail
