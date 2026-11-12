#pragma once

#include <filesystem>
#include <optional>

#include "EcFilePlanning.h"
#include "EcStripeClient.h"

namespace hf3fs::client::ec {
// These are local recovery records, not new RPC messages or authorization.
enum class EcFileRunKind : uint8_t { RangeRead = 1, AppendAt = 2 };
enum class EcFileAppendState : uint8_t {
  NotStarted = 0,
  Issued = 1,
  Preparing = 2,
  Published = 3,
  Aborted = 4,
  Indeterminate = 5
};
struct EcFileRunSlot {
  uint64_t stripe = 0;
  Uuid pin = Uuid::zero();
  Uuid acquireRequest = Uuid::zero();
  Uuid releaseRequest = Uuid::zero();
  EcStripeMutationIds mutation{};
  storage::EcSha256 contentSha256{};
};
struct EcFileRunRecord {
  uint16_t version = 1;
  EcFileRunKind kind = EcFileRunKind::RangeRead;
  std::string cluster;
  meta::EcOwner owner;
  meta::EcObjectRef object;
  uint64_t epoch = 0;
  uint32_t shardBytes = 0;
  uint64_t offset = 0;  // Read offset or fixed expectedEOF, never a moving cursor.
  uint64_t length = 0;
  Uuid describeRequest = Uuid::zero();
  Uuid rangeId = Uuid::zero();
  Uuid rangeRequest = Uuid::zero();
  Uuid appendId = Uuid::zero();
  std::string inputPath;
  storage::EcSha256 contentSha256{};
  uint16_t count = 0;
  std::array<EcFileRunSlot, kEcFileMaxStripes> slots{};
  Result<Void> validate() const;
};
struct EcFileRunProgress {
  uint16_t version = 1;
  uint64_t sequence = 0;  // Assigned by journal, never by the caller.
  uint64_t localAttempt = 0;
  // Persist before calling Acquire43. Query missing never clears this flag.
  bool acquisitionIssued = false;
  bool snapshotObserved = false;
  uint16_t actualPins = 0;
  uint16_t releasedMask = 0;
  // The first native snapshot's binary bytes, no grants/tokens; bounded 64 KiB.
  // This immutable historical record is not evidence of present pin state.
  std::string snapshotBytes;
  bool dataReady = false;      // Historical observation, not a promise of a live buffer.
  bool localComplete = false;  // Only for localAttempt; not a remote drain proof.
  std::array<EcFileAppendState, kEcFileMaxStripes> appendStates{};
  uint16_t errorCode = 0;
  uint16_t confirmedStripes() const;
  uint64_t confirmedPrefixBytes(const EcFileRunRecord &) const;
  bool allPinsReleased() const;
  Result<Void> validate(const EcFileRunRecord &, const EcFileRunProgress *previous = nullptr) const;
};

// Explicit local codec; every u64 is a canonical decimal string. It rejects
// omissions, extra fields, integer coercions, and arrays other than eight slots.
Result<std::string> encodeEcFileRunRecord(const EcFileRunRecord &);
Result<EcFileRunRecord> decodeEcFileRunRecord(std::string_view);
Result<std::string> encodeEcFileRunProgress(const EcFileRunProgress &);
Result<EcFileRunProgress> decodeEcFileRunProgress(std::string_view);

// Single-threaded owner, with a process-wide exclusive flock for this run.
// create() requires a new directory. A persistence error poisons this handle;
// resume() revalidates/reconfirms visible records without inventing new IDs.
class EcFileRunJournal {
 public:
  static Result<std::unique_ptr<EcFileRunJournal>> create(const std::filesystem::path &, EcFileRunRecord);
  static Result<std::unique_ptr<EcFileRunJournal>> resume(const std::filesystem::path &);
  ~EcFileRunJournal();
  EcFileRunJournal(const EcFileRunJournal &) = delete;
  EcFileRunJournal &operator=(const EcFileRunJournal &) = delete;
  const EcFileRunRecord &record() const { return record_; }
  const std::optional<EcFileRunProgress> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  Result<Void> append(EcFileRunProgress);

 private:
  EcFileRunJournal(int directory, int lock, EcFileRunRecord record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcFileRunJournal>> open(const std::filesystem::path &, std::optional<EcFileRunRecord>);
  Result<Void> writeNew(std::string_view name, std::string_view bytes);
  Result<std::string> read(std::string_view name) const;
  int directory_ = -1;
  int lock_ = -1;
  EcFileRunRecord record_;
  std::optional<EcFileRunProgress> latest_;
  bool poisoned_ = false;
};
}  // namespace hf3fs::client::ec
