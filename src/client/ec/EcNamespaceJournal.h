#pragma once

#include "EcFilePwriteJournal.h"

namespace hf3fs::client::ec {
// Local immutable recovery identity, not a new wire authority. RemoveReq has
// an expected inode; incarnation/birth come from the accepted session and the
// server's permanent EC inode/birth history, not a fictional expected-birth RPC.
struct EcNamespaceRun {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(session, meta::EcFileSessionRecord{});
  SERDE_STRUCT_FIELD(path, std::string{});
  SERDE_STRUCT_FIELD(request, Uuid::zero());

 public:
  Result<Void> validate() const;
};
struct EcNamespaceJournalState {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(issued, false);
  SERDE_STRUCT_FIELD(acknowledged, false);

 public:
  Result<Void> validate(const EcNamespaceRun &, const EcNamespaceJournalState *previous = nullptr) const;
};
Result<EcNamespaceRun> prepareEcUnlink(const EcFilePwriteJournal &acceptedSession, std::string path);
Result<std::string> encodeEcNamespaceRun(const EcNamespaceRun &);
Result<EcNamespaceRun> decodeEcNamespaceRun(std::string_view);
Result<std::string> encodeEcNamespaceState(const EcNamespaceJournalState &);
Result<EcNamespaceJournalState> decodeEcNamespaceState(std::string_view);
class EcNamespaceJournal {
 public:
  static Result<std::unique_ptr<EcNamespaceJournal>> create(const std::filesystem::path &, EcNamespaceRun);
  static Result<std::unique_ptr<EcNamespaceJournal>> resume(const std::filesystem::path &);
  ~EcNamespaceJournal();
  EcNamespaceJournal(const EcNamespaceJournal &) = delete;
  EcNamespaceJournal &operator=(const EcNamespaceJournal &) = delete;
  const EcNamespaceRun &record() const { return record_; }
  const std::optional<EcNamespaceJournalState> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  uint64_t remainingStates() const;
  Result<Void> append(EcNamespaceJournalState);

 private:
  EcNamespaceJournal(int directory, int lock, EcNamespaceRun record)
      : directory_(directory), lock_(lock), record_(std::move(record)) {}
  static Result<std::unique_ptr<EcNamespaceJournal>> open(const std::filesystem::path &,
                                                         std::optional<EcNamespaceRun>);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcNamespaceRun record_;
  std::optional<EcNamespaceJournalState> latest_;
  bool poisoned_ = false;
};
}  // namespace hf3fs::client::ec
