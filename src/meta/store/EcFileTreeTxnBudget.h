#pragma once

#include "common/kv/ITransaction.h"

namespace hf3fs::meta::server {
// Wrap the complete caller-owned transaction from its first operation. All W0
// reads/writes, including helper calls, use this wrapper. Limits measure actual
// application key/value/conflict bytes, not FoundationDB's internal overhead.
class EcFileTreeTxnBudget final : public kv::IReadWriteTransaction {
 public:
  // Fixed operation profiles, not caller-selected resource limits or an
  // authorization token. W0 callers retain the original default/hard cap.
  // Range/Gc/Repair/Rmw include their complete metadata workflow, from the first
  // normal conflict read through permanent request/result writes and commit.
  enum class Profile : uint8_t { W0, Range, Gc, Repair, Rmw };
  struct Limits {
    size_t bytes = 256u << 10;
    size_t keyOperations = 1024;
  };
  struct Usage {
    size_t keyOperations = 0;
    size_t readBytes = 0;
    size_t mutationBytes = 0;
    size_t conflictBytes = 0;
    size_t totalBytes() const { return readBytes + mutationBytes + conflictBytes; }
    // Application accounting only, not FoundationDB's affected-data size.
    size_t mutationAndConflictBytes() const { return mutationBytes + conflictBytes; }
  };
  enum class ObservationPoint : uint8_t { Destroy, BeforeReset };
  // Failed means a returned status error; kMaybeCommitted is still unknown,
  // not evidence that the engine made no durable change.
  enum class CommitOutcome : uint8_t { NotCalled, Rejected, Unconfirmed, Succeeded, Failed };
  struct Snapshot {
    Profile profile;
    Limits limits;
    Usage usage;
    uint64_t attempt;
    bool poisoned;
    CommitOutcome commitOutcome;
    uint32_t commitError;
    ObservationPoint point;
  };
  // Optional, per-inner-transaction diagnostics. Production FDBTransaction does
  // not implement this interface. No global registration or caller limits.
  // The observer must copy this scalar snapshot synchronously without throwing,
  // allocating, retaining a reference, or reentering either transaction.
  class SnapshotObserver {
   public:
    virtual ~SnapshotObserver() = default;
    virtual void observeEcTreeBudget(const Snapshot &) noexcept = 0;
  };
  explicit EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner);
  EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner, Limits limits);
  EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner, Profile profile);
  ~EcFileTreeTxnBudget() override;
  Profile profile() const noexcept { return profile_; }
  const Limits &limits() const noexcept { return limits_; }
  const Usage &usage() const noexcept { return usage_; }
  bool poisoned() const noexcept { return poisoned_; }
  uint64_t attempt() const noexcept { return attempt_; }
  void setReadVersion(int64_t) override;
  CoTryTask<std::optional<String>> snapshotGet(std::string_view) override;
  CoTryTask<std::optional<String>> get(std::string_view) override;
  CoTryTask<GetRangeResult> snapshotGetRange(const KeySelector &, const KeySelector &, int32_t) override;
  CoTryTask<GetRangeResult> getRange(const KeySelector &, const KeySelector &, int32_t) override;
  CoTryTask<void> cancel() override;
  void reset() override;
  CoTryTask<void> addReadConflict(std::string_view) override;
  CoTryTask<void> addReadConflictRange(std::string_view, std::string_view) override;
  CoTryTask<void> set(std::string_view, std::string_view) override;
  CoTryTask<void> clear(std::string_view) override;
  CoTryTask<void> setVersionstampedKey(std::string_view, uint32_t, std::string_view) override;
  CoTryTask<void> setVersionstampedValue(std::string_view, std::string_view, uint32_t) override;
  CoTryTask<void> commit() override;
  int64_t getCommittedVersion() override;

 private:
  void observe(ObservationPoint point) noexcept;
  static Limits profileLimits(Profile profile) noexcept;
  bool validLimits() const noexcept;
  Result<Void> charge(size_t operations, size_t read, size_t mutation, size_t conflict);
  Status unavailable();
  kv::IReadWriteTransaction &inner_;
  Limits limits_;
  Profile profile_ = Profile::W0;
  Usage usage_;
  bool poisoned_ = false;
  uint64_t attempt_ = 1;
  CommitOutcome commitOutcome_ = CommitOutcome::NotCalled;
  uint32_t commitError_ = StatusCode::kOK;
};
}  // namespace hf3fs::meta::server
