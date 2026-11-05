#pragma once

#include <filesystem>

#include "EcStripeClient.h"

namespace hf3fs::client::ec {

// Local CLI recovery journal, not a storage allocation or a remote durability
// proof. It deliberately contains no user token, data grant or signing key.
struct EcStripeRunRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(clientNamespace, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedOwnerUid, (std::optional<uint32_t>{}));
  SERDE_STRUCT_FIELD(inputPath, std::string{});
  SERDE_STRUCT_FIELD(inputBytes, uint64_t{});
  SERDE_STRUCT_FIELD(inputSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(remotePath, std::string{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(object, (std::optional<meta::EcObjectRecord>{}));
  SERDE_STRUCT_FIELD(expectedRevision, uint64_t{});
  SERDE_STRUCT_FIELD(createRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(beginRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(bindRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(publishRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(getRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(prepareRepairRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(pin, Uuid::zero());
  SERDE_STRUCT_FIELD(acquireRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(releaseRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(strategy, std::string{});
  SERDE_STRUCT_FIELD(replacementMask, uint16_t{});
  SERDE_STRUCT_FIELD(sourceOrder, std::vector<uint16_t>{});
  SERDE_STRUCT_FIELD(blockWindow, uint8_t{1});
  SERDE_STRUCT_FIELD(command, std::string{});
  SERDE_STRUCT_FIELD(resumeCommand, std::string{});

 public:
  EcStripeMutationIds mutationIds() const;
  EcStripePinIds pinIds(const meta::EcObjectRef &) const;
  Result<Void> validate() const;
};

struct EcStripeRunObservation {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(ownerUid, uint32_t{});
  SERDE_STRUCT_FIELD(object, (std::optional<meta::EcObjectRecord>{}));
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(mutationPublished, false);
  SERDE_STRUCT_FIELD(state, std::string{});
  SERDE_STRUCT_FIELD(readOutput, std::string{});
  SERDE_STRUCT_FIELD(errorCode, uint16_t{});
  SERDE_STRUCT_FIELD(error, std::string{});
  SERDE_STRUCT_FIELD(coreElapsedNanoseconds, uint64_t{});
  SERDE_STRUCT_FIELD(dataPhaseElapsedNanoseconds, (std::optional<uint64_t>{}));
  SERDE_STRUCT_FIELD(logicalBytes, uint64_t{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(blocksPerShard, uint16_t{});
  SERDE_STRUCT_FIELD(acknowledgedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(expectedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(maxOperations, uint32_t{});
  SERDE_STRUCT_FIELD(applicationByteBudget, uint64_t{});
  SERDE_STRUCT_FIELD(writeFragmentWindow, uint8_t{});
  SERDE_STRUCT_FIELD(readBlockWindow, uint8_t{});
  SERDE_STRUCT_FIELD(workerThreads, uint32_t{});
  SERDE_STRUCT_FIELD(deadlineSeconds, uint32_t{});
  SERDE_STRUCT_FIELD(metaRpcTimeoutMillis, uint64_t{});
  SERDE_STRUCT_FIELD(metaRetryTotalMillis, uint64_t{});
};

// An exclusive flock spans the entire CLI attempt. New experiment directories
// must not exist; resumptions cannot overwrite an earlier observation. Files
// are written/fsynced to a fresh temporary name, linked without replacement,
// then their directory is fsynced before any next remote mutation is started.
class EcStripeRunJournal {
 public:
  static Result<std::unique_ptr<EcStripeRunJournal>> create(const std::filesystem::path &, EcStripeRunRecord);
  static Result<std::unique_ptr<EcStripeRunJournal>> resume(const std::filesystem::path &);
  ~EcStripeRunJournal();
  EcStripeRunJournal(const EcStripeRunJournal &) = delete;
  EcStripeRunJournal &operator=(const EcStripeRunJournal &) = delete;
  const EcStripeRunRecord &record() const { return record_; }
  const std::optional<EcStripeRunObservation> &latest() const { return latest_; }
  Result<Void> append(EcStripeRunObservation);
  // Never replace an existing output; its name belongs to this attempt's next
  // observation sequence. A failed remote Release leaves it as ordinary data.
  Result<std::string> saveReadOutput(std::string_view);

 private:
  EcStripeRunJournal(int directory, int lock, EcStripeRunRecord record)
      : directory_(directory),
        lock_(lock),
        record_(std::move(record)) {}
  static Result<std::unique_ptr<EcStripeRunJournal>> open(const std::filesystem::path &,
                                                          std::optional<EcStripeRunRecord>);
  Result<Void> writeNew(std::string_view name, std::string_view data);
  Result<std::string> read(std::string_view name, size_t limit) const;
  int directory_ = -1;
  int lock_ = -1;
  EcStripeRunRecord record_;
  std::optional<EcStripeRunObservation> latest_;
};

Result<std::string> readEcStripeInput(const std::filesystem::path &, size_t maximumBytes);
}  // namespace hf3fs::client::ec
