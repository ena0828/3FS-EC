#pragma once

#include <filesystem>
#include <memory>

#include "fbs/meta/EcFileTruncateRpc.h"

namespace hf3fs::client::ec {
struct EcTruncateRun {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(session, meta::EcFileOpenIntent{});
  SERDE_STRUCT_FIELD(intent, meta::EcFileTruncateIntent{});
  SERDE_STRUCT_FIELD(beginRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(advanceRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(closeRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());

 public:
  Result<Void> validate() const;
};
struct EcTruncateJournalState {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(attempt, uint64_t{});
  SERDE_STRUCT_FIELD(beginIssued, false);
  SERDE_STRUCT_FIELD(advanceIssued, false);
  SERDE_STRUCT_FIELD(closeIssued, false);
  SERDE_STRUCT_FIELD(progress, (std::optional<meta::EcFileTruncateProgress>{}));
  SERDE_STRUCT_FIELD(localComplete, false);
  SERDE_STRUCT_FIELD(errorCode, uint16_t{});

 public:
  Result<Void> validate(const EcTruncateRun &, const EcTruncateJournalState *previous = nullptr) const;
};
Result<EcTruncateRun> prepareEcFileTruncate(const meta::EcFileSessionRecord &acceptedWriteSession,
                                            const meta::EcTreeRoot &capturedRoot,
                                            std::string cluster,
                                            uint64_t length);
Result<Void> validateEcTruncateProgress(const EcTruncateRun &, const meta::EcFileTruncateProgress &);
Result<Void> compareEcTruncateProgress(const meta::EcFileTruncateProgress &, const meta::EcFileTruncateProgress &);
Result<std::string> encodeEcTruncateRun(const EcTruncateRun &);
Result<EcTruncateRun> decodeEcTruncateRun(std::string_view);
Result<std::string> encodeEcTruncateState(const EcTruncateJournalState &);
Result<EcTruncateJournalState> decodeEcTruncateState(std::string_view);
class EcTruncateJournal {
 public:
  static Result<std::unique_ptr<EcTruncateJournal>> create(const std::filesystem::path &, EcTruncateRun);
  static Result<std::unique_ptr<EcTruncateJournal>> resume(const std::filesystem::path &);
  // Existing lock only; no journal writes or durability reconfirmation.
  static Result<std::unique_ptr<EcTruncateJournal>> inspectExisting(const std::filesystem::path &);
  ~EcTruncateJournal();
  EcTruncateJournal(const EcTruncateJournal &) = delete;
  EcTruncateJournal &operator=(const EcTruncateJournal &) = delete;
  const EcTruncateRun &record() const { return record_; }
  const std::optional<EcTruncateJournalState> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  // Exact bytes retained only by inspectExisting; never serialize them to a public archive.
  std::string_view inspectionRecordBytes() const { return inspectionRecordBytes_; }
  std::string_view inspectionLatestStateBytes() const { return inspectionLatestStateBytes_; }
  // Capacity only, not a durability or cleanup-completion observation.
  uint64_t remainingStates() const;
  Result<Void> append(EcTruncateJournalState);

 private:
  EcTruncateJournal(int directory, int lock, EcTruncateRun record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcTruncateJournal>> open(const std::filesystem::path &, std::optional<EcTruncateRun>, bool readOnly = false);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcTruncateRun record_;
  std::optional<EcTruncateJournalState> latest_;
  bool poisoned_ = false;
  bool readOnly_ = false;
  std::string inspectionRecordBytes_, inspectionLatestStateBytes_;
};
}  // namespace hf3fs::client::ec
