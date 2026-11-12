#pragma once
#include <filesystem>
#include <memory>

#include "fbs/meta/EcFileRepairRpc.h"
namespace hf3fs::client::ec {
struct EcTreeRepairRun {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(intent, meta::EcFileRepairIntent{});
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(prepareRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(publishRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(closeRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());

 public:
  Result<Void> validate() const;
};
struct EcTreeRepairState {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(issued, false);
  SERDE_STRUCT_FIELD(dataComplete, false);
  SERDE_STRUCT_FIELD(progress, meta::EcFileRepairProgress{});

 public:
  Result<Void> validate(const EcTreeRepairRun &, const EcTreeRepairState *previous = nullptr) const;
};
Result<EcTreeRepairRun> prepareEcTreeRepair(const meta::EcFileSessionRecord &,
                                            const meta::EcTreeRoot &,
                                            std::string cluster,
                                            uint64_t stripe,
                                            uint16_t replacementMask,
                                            meta::EcFileRepairMode,
                                            std::array<uint8_t, 10> sourceOrder,
                                            uint16_t maxBlocksInFlight = 2);
Result<std::string> encodeEcTreeRepairRun(const EcTreeRepairRun &);
Result<EcTreeRepairRun> decodeEcTreeRepairRun(std::string_view);
Result<std::string> encodeEcTreeRepairState(const EcTreeRepairState &);
Result<EcTreeRepairState> decodeEcTreeRepairState(std::string_view);
class EcTreeRepairJournal {
 public:
  static Result<std::unique_ptr<EcTreeRepairJournal>> create(const std::filesystem::path &, EcTreeRepairRun);
  static Result<std::unique_ptr<EcTreeRepairJournal>> resume(const std::filesystem::path &);
  ~EcTreeRepairJournal();
  EcTreeRepairJournal(const EcTreeRepairJournal &) = delete;
  EcTreeRepairJournal &operator=(const EcTreeRepairJournal &) = delete;
  const EcTreeRepairRun &record() const { return record_; }
  const std::optional<EcTreeRepairState> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  Result<Void> append(EcTreeRepairState);

 private:
  EcTreeRepairJournal(int directory, int lock, EcTreeRepairRun record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcTreeRepairJournal>> open(const std::filesystem::path &,
                                                           std::optional<EcTreeRepairRun>);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcTreeRepairRun record_;
  std::optional<EcTreeRepairState> latest_;
  bool poisoned_ = false;
};
}  // namespace hf3fs::client::ec
