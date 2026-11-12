#pragma once
#include <filesystem>
#include <memory>

#include "EcFilePwriteJournal.h"
#include "fbs/meta/EcFileAppend.h"

namespace hf3fs::client::ec {
enum class EcAppendRunKind : uint8_t { Append = 1, Sync = 2 };
struct EcAppendRun {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(kind, EcAppendRunKind::Append);
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(session, meta::EcFileSessionRecord{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(appendIntent, meta::EcFileAppendIntent{});
  SERDE_STRUCT_FIELD(syncIntent, meta::EcFileSyncIntent{});
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(sealRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(inputPath, std::string{});
  SERDE_STRUCT_FIELD(childDirectory, std::string{});

 public:
  Result<Void> validate() const;
};
struct EcAppendJournalState {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(issued, false);
  SERDE_STRUCT_FIELD(accepted, (std::optional<meta::EcFileAppendRecord>{}));
  SERDE_STRUCT_FIELD(synced, (std::optional<meta::EcFileSyncRecord>{}));

 public:
  Result<Void> validate(const EcAppendRun &, const EcAppendJournalState *previous = nullptr) const;
};
Result<EcAppendRun> prepareEcAppend(const meta::EcFileSessionRecord &,
                                    uint32_t shardBytes,
                                    std::string cluster,
                                    std::string inputPath,
                                    std::string childDirectory,
                                    std::span<const uint8_t> input);
Result<EcAppendRun> prepareEcSync(const meta::EcFileSessionRecord &, std::string cluster);
Result<std::string> encodeEcAppendRun(const EcAppendRun &);
Result<EcAppendRun> decodeEcAppendRun(std::string_view);
Result<std::string> encodeEcAppendState(const EcAppendJournalState &);
Result<EcAppendJournalState> decodeEcAppendState(std::string_view);
class EcAppendJournal {
 public:
  static Result<std::unique_ptr<EcAppendJournal>> create(const std::filesystem::path &, EcAppendRun);
  static Result<std::unique_ptr<EcAppendJournal>> resume(const std::filesystem::path &);
  ~EcAppendJournal();
  EcAppendJournal(const EcAppendJournal &) = delete;
  EcAppendJournal &operator=(const EcAppendJournal &) = delete;
  const EcAppendRun &record() const { return record_; }
  const std::optional<EcAppendJournalState> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  Result<Void> append(EcAppendJournalState);

 private:
  EcAppendJournal(int directory, int lock, EcAppendRun record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcAppendJournal>> open(const std::filesystem::path &, std::optional<EcAppendRun>);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcAppendRun record_;
  std::optional<EcAppendJournalState> latest_;
  bool poisoned_ = false;
};
}  // namespace hf3fs::client::ec
