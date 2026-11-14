#pragma once

#include <filesystem>

#include "EcFilePlanning.h"
#include "fbs/meta/EcFileTreeRead.h"

namespace hf3fs::client::ec {
struct EcTreeReadRun {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(session, meta::EcFileOpenIntent{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(intent, meta::EcTreeReadIntent{});
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(releaseRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(refreshRequests, (std::array<Uuid, 8>{}));
  // Preassigned for requested slots; wire55 masks out Zero/unused slots.
  SERDE_STRUCT_FIELD(revocations, (std::array<Uuid, 8>{}));

 public:
  Result<Void> validate() const;
};
struct EcTreeReadProgress {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(attempt, uint64_t{});
  SERDE_STRUCT_FIELD(acquisitionIssued, false);
  SERDE_STRUCT_FIELD(releaseIssued, false);
  SERDE_STRUCT_FIELD(snapshot, (std::optional<meta::EcTreeReadRecord>{}));
  SERDE_STRUCT_FIELD(dataReady, false);
  SERDE_STRUCT_FIELD(localComplete, false);
  SERDE_STRUCT_FIELD(errorCode, uint16_t{});

 public:
  Result<Void> validate(const EcTreeReadRun &, const EcTreeReadProgress *previous = nullptr) const;
};
Result<EcTreeReadRun> prepareEcTreeRead(const meta::EcFileSessionRecord &acceptedReadSession,
                                        std::string cluster,
                                        uint32_t shardBytes,
                                        uint64_t offset,
                                        uint64_t length);
Result<Void> validateEcTreeReadSnapshot(const EcTreeReadRun &, const meta::EcTreeReadRecord &);
Result<Void> sameEcTreeReadSnapshot(const meta::EcTreeReadRecord &, const meta::EcTreeReadRecord &);
Result<std::string> encodeEcTreeReadRun(const EcTreeReadRun &);
Result<EcTreeReadRun> decodeEcTreeReadRun(std::string_view);
Result<std::string> encodeEcTreeReadProgress(const EcTreeReadProgress &);
Result<EcTreeReadProgress> decodeEcTreeReadProgress(std::string_view);

// Same exclusive owner/flock/fsync discipline as EcFileRunJournal. Explicit
// typed binary framing contains no tokens or grants. No automatic ID changes.
class EcTreeReadJournal {
 public:
  static Result<std::unique_ptr<EcTreeReadJournal>> create(const std::filesystem::path &, EcTreeReadRun);
  static Result<std::unique_ptr<EcTreeReadJournal>> resume(const std::filesystem::path &);
  // Existing lock only: never creates a lock or permits append. Retains exclusive ownership.
  static Result<std::unique_ptr<EcTreeReadJournal>> inspectExisting(const std::filesystem::path &);
  ~EcTreeReadJournal();
  EcTreeReadJournal(const EcTreeReadJournal &) = delete;
  EcTreeReadJournal &operator=(const EcTreeReadJournal &) = delete;
  const EcTreeReadRun &record() const { return record_; }
  const std::optional<EcTreeReadProgress> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  Result<Void> append(EcTreeReadProgress);

 private:
  EcTreeReadJournal(int directory, int lock, EcTreeReadRun record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcTreeReadJournal>> open(const std::filesystem::path &,
                                                                std::optional<EcTreeReadRun>,
                                                                bool readOnly = false);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcTreeReadRun record_;
  std::optional<EcTreeReadProgress> latest_;
  bool poisoned_ = false;
  bool readOnly_ = false;
};
}  // namespace hf3fs::client::ec
