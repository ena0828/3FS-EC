#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "common/kv/IKVEngine.h"
#include "common/utils/SerDeser.h"
#include "meta/store/EcFileExecutionCatalog.h"
#include "meta/store/detail/EcFileTreeKeys.h"

namespace hf3fs::meta::server::detail {
// Test-only interception of an exact fresh output binding. Conflict modes
// commit a real competing catalog transaction, never a fabricated Conflict.
// CommitAckLost records the real successful commit separately from the error
// deliberately returned to the issuer. Nothing is installed in production.
class EcRmwBindConflictFault {
 public:
  enum class Mode : uint8_t { Conflict, CommitAckLost, CloseBeforeRetry };
  static constexpr size_t kCapacity = 8;
  struct Event {
    status_code_t rawStatus = StorageClientCode::kNotInitialized;
    status_code_t deliveredStatus = StorageClientCode::kNotInitialized;
    bool finished = false;
    bool competition = false;
  };
  struct Snapshot {
    std::array<Event, kCapacity> events{};
    size_t attempts = 0, injections = 0, competingCommits = 0, closingCommits = 0;
    size_t originalCommits = 0, originalConflicts = 0, rawSucceeded = 0, ackLost = 0;
    size_t setupErrors = 0, active = 0;
    status_code_t lastSetupError = StatusCode::kOK;
    bool changed = false, overflow = false;
    storage::EcSha256 planDigest{}, contentSha256{};
    Uuid revocation = Uuid::zero();
  };
  struct Attempt {
    uint64_t generation = 0;
    size_t index = 0;
    Mode mode = Mode::Conflict;
    bool inject = false;
    EcObjectRef object;
    EcOwner owner;
    Uuid child = Uuid::zero(), authority = Uuid::zero(), revocation = Uuid::zero();
  };

  void arm(EcObjectRef object, EcOwner owner, Uuid child, Uuid authority, Mode mode, size_t count = 1) {
    if (object.incarnation.is_nil() || owner.client.is_nil() || child.is_nil() || authority.is_nil() || !count ||
        count > 4 || (mode != Mode::Conflict && mode != Mode::CommitAckLost && mode != Mode::CloseBeforeRetry) ||
        (mode != Mode::Conflict && count != 1))
      throw std::invalid_argument("invalid bounded RMW bind fault");
    std::lock_guard lock(mutex_);
    if (snapshot_.active) throw std::logic_error("RMW bind fault still has owned work");
    if (generation_ == std::numeric_limits<uint64_t>::max()) throw std::overflow_error("RMW bind fault generation");
    ++generation_;
    object_ = object;
    owner_ = owner;
    child_ = child;
    authority_ = authority;
    mode_ = mode;
    remaining_ = count;
    snapshot_ = {};
    snapshot_.revocation = Uuid::random();
    bindingBytes_.clear();
    key_ = ec_tree_detail::idKey(kv::KeyPrefix::EcFileExecution, object, child);
    armed_ = true;
  }

  // Called for writes, not reads. The transaction also has to write ECVA to
  // qualify in beginCommit, so a plain issuance observation is not intercepted.
  std::optional<uint64_t> selectSet(std::string_view key, std::string_view value) {
    std::lock_guard lock(mutex_);
    if (!armed_ || key != key_) return std::nullopt;
    EcFileExecutionRecord record;
    if (!serde::deserialize(record, value)) {
      ++snapshot_.setupErrors;
      snapshot_.lastSetupError = StatusCode::kDataCorruption;
      return 0;
    }
    if (record.state != EcFileExecutionState::Bound || !record.allocations) return 0;
    if (record.version != kEcFileMutationVersion || record.child.intent.object != object_ ||
        record.child.intent.child != child_ || !serde::equals(record.child.owner, owner_)) {
      snapshot_.changed = true;
      return 0;
    }
    // Exclude issuanceSequence: the actual competing transaction increments it.
    const auto binding = bytes(record.child) + bytes(record.candidates) + bytes(*record.allocations);
    if (bindingBytes_.empty()) {
      bindingBytes_ = binding;
      snapshot_.planDigest = record.planDigest;
      snapshot_.contentSha256 = record.contentSha256;
    } else if (bindingBytes_ != binding || snapshot_.planDigest != record.planDigest ||
               snapshot_.contentSha256 != record.contentSha256) {
      snapshot_.changed = true;
      return 0;
    }
    return generation_;
  }

  std::optional<Attempt> beginCommit(uint64_t token, bool wroteAllocation) {
    std::lock_guard lock(mutex_);
    if (!armed_ || !token || token != generation_ || !wroteAllocation || snapshot_.changed) return std::nullopt;
    if (snapshot_.attempts == kCapacity) {
      snapshot_.overflow = true;
      return std::nullopt;
    }
    Attempt attempt{generation_, snapshot_.attempts++, mode_, remaining_ != 0,
                    object_, owner_, child_, authority_, snapshot_.revocation};
    ++snapshot_.active;
    if (attempt.inject) {
      --remaining_;
      ++snapshot_.injections;
    }
    return attempt;
  }

  CoTryTask<void> beforeCommit(kv::IKVEngine &rawEngine, Attempt attempt) {
    if (!attempt.inject || attempt.mode == Mode::CommitAckLost) co_return Void{};
    auto raw = rawEngine.createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Rmw);
    if (attempt.mode == Mode::Conflict) {
      auto competing = co_await EcFileExecutionCatalog::reserveIssuance(tx, attempt.owner, attempt.object, attempt.child);
      CO_RETURN_ON_ERROR(competing);
    } else {
      auto closed = co_await EcFileExecutionCatalog::startCancelClosing(
          tx, attempt.owner, attempt.object, attempt.child, attempt.authority, attempt.revocation);
      CO_RETURN_ON_ERROR(closed);
    }
    CO_RETURN_ON_ERROR(co_await tx.commit());
    {
      std::lock_guard lock(mutex_);
      if (attempt.generation != generation_ || attempt.index >= snapshot_.attempts)
        co_return makeError(StatusCode::kDataCorruption);
      ++snapshot_.competingCommits;
      if (attempt.mode == Mode::CloseBeforeRetry) ++snapshot_.closingCommits;
      snapshot_.events[attempt.index].competition = true;
    }
    co_return Void{};
  }

  // Returns true only after a real successful commit selected for ACK loss.
  bool finish(const Attempt &attempt, status_code_t rawStatus, bool prepared) {
    std::lock_guard lock(mutex_);
    if (attempt.generation != generation_ || attempt.index >= snapshot_.attempts ||
        snapshot_.events[attempt.index].finished || !snapshot_.active) {
      snapshot_.changed = true;
      return false;
    }
    auto &event = snapshot_.events[attempt.index];
    event.rawStatus = event.deliveredStatus = rawStatus;
    event.finished = true;
    --snapshot_.active;
    ++snapshot_.originalCommits;
    if (rawStatus == TransactionCode::kConflict) ++snapshot_.originalConflicts;
    if (rawStatus == StatusCode::kOK) ++snapshot_.rawSucceeded;
    const bool lost = prepared && attempt.inject && attempt.mode == Mode::CommitAckLost && rawStatus == StatusCode::kOK;
    if (lost) {
      ++snapshot_.ackLost;
      event.deliveredStatus = TransactionCode::kMaybeCommitted;
    }
    return lost;
  }

  void abandon(const Attempt &attempt) {
    std::lock_guard lock(mutex_);
    if (attempt.generation == generation_ && attempt.index < snapshot_.attempts &&
        !snapshot_.events[attempt.index].finished && snapshot_.active) {
      snapshot_.events[attempt.index].finished = true;
      --snapshot_.active;
      ++snapshot_.setupErrors;
      snapshot_.lastSetupError = StatusCode::kIOError;
    }
  }
  void setupFailed(status_code_t error) {
    std::lock_guard lock(mutex_);
    ++snapshot_.setupErrors;
    snapshot_.lastSetupError = error;
  }
  Snapshot snapshot() const {
    std::lock_guard lock(mutex_);
    return snapshot_;
  }

 private:
  template <class T>
  static std::string bytes(const T &value) {
    auto encoded = serde::serialize(value);
    return std::string(encoded.data(), encoded.size());
  }
  mutable std::mutex mutex_;
  Snapshot snapshot_;
  EcObjectRef object_;
  EcOwner owner_;
  Uuid child_ = Uuid::zero(), authority_ = Uuid::zero();
  Mode mode_ = Mode::Conflict;
  uint64_t generation_ = 0;
  size_t remaining_ = 0;
  bool armed_ = false;
  std::string key_, bindingBytes_;
};
}  // namespace hf3fs::meta::server::detail
