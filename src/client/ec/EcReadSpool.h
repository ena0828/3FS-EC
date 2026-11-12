#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

#include "EcFileRunJournal.h"

namespace hf3fs::client::ec {
namespace detail {
struct EcReadDispatcherCore;
struct EcReadSpoolTestAccess;
struct EcReadSpoolExclusiveTestAccess;
}  // namespace detail

// A local lookup identity, never a data grant or a proof of remote release.
struct EcReadReceipt {
  Uuid clientNamespace = Uuid::zero();
  uint64_t sequence = 0;
  uint32_t ownerUid = 0;
  Uuid rangeId = Uuid::zero();
};
struct EcReadDebt {
  EcReadReceipt receipt;
  meta::EcObjectRef object;
  uint64_t logicalFileBytes = 0;
  bool acquisitionIssued = false;
  bool snapshotObserved = false;
  bool localComplete = false;
  bool allPinsReleased = false;
  bool retirementPending = false;
  uint16_t actualPins = 0;
  uint16_t releasedMask = 0;
  uint16_t lastErrorCode = 0;
};
struct EcReadSpoolSnapshot {
  uint64_t logicalFileBytes = 0;
  size_t retainedRuns = 0;
  size_t outstandingRuns = 0;
  std::vector<EcReadDebt> records;
};

// Open this first; construct MetaClient with clientNamespace() afterwards.
// The descriptor/flock lives as long as this object, including output leases.
// Mutation methods are private to the serialized, authenticated dispatcher.
class EcReadSpool {
 public:
  struct Limits {
    size_t maximumRetainedRuns = 64;
    size_t maximumOutstandingRuns = 32;
    uint64_t maximumLogicalFileBytes = 256u << 20;
  };
  static Result<std::shared_ptr<EcReadSpool>> create(const std::filesystem::path &, std::string cluster, Limits);
  static Result<std::shared_ptr<EcReadSpool>> open(const std::filesystem::path &, std::string cluster, Limits);
  ~EcReadSpool();
  EcReadSpool(const EcReadSpool &) = delete;
  EcReadSpool &operator=(const EcReadSpool &) = delete;
  const Uuid &clientNamespace() const { return namespace_; }
  const std::string &cluster() const { return cluster_; }
  const std::filesystem::path &directory() const { return path_; }
  const Limits &limits() const { return limits_; }
  bool poisoned() const { return poisoned_.load(); }
  // Offline/local evidence only. Requires this handle to have no attached
  // dispatcher/output lease; the existing flock excludes other processes.
  Result<EcReadSpoolSnapshot> inspectExclusive();

 private:
  friend class EcReadDispatcher;
  friend struct detail::EcReadDispatcherCore;
  friend struct detail::EcReadSpoolTestAccess;
  friend struct detail::EcReadSpoolExclusiveTestAccess;
  Result<EcReadSpoolSnapshot> inspectExclusiveImpl(void (*afterAttach)(void *), void *context);
  struct Run {
    EcReadReceipt receipt;
    std::shared_ptr<EcFileRunJournal> journal;
  };
  EcReadSpool(std::filesystem::path path, std::string cluster, Limits limits, int directory, int lock)
      : path_(std::move(path)),
        cluster_(std::move(cluster)),
        limits_(limits),
        directory_(directory),
        lock_(lock) {}
  using OwnershipHook = void (*)(void *, unsigned stage, int directory, int lock);
  static Result<std::shared_ptr<EcReadSpool>> load(const std::filesystem::path &,
                                                   std::string,
                                                   Limits,
                                                   bool create,
                                                   OwnershipHook = nullptr,
                                                   void *hookContext = nullptr);
  Result<EcReadSpoolSnapshot> inspect(const Run *active = nullptr);
  Result<Run> prepare(EcFileRunRecord);
  Result<Run> resume(const EcReadReceipt &);
  Result<Void> reserveAttempt(const Run &);
  Result<uint64_t> reserveSequence();
  Result<storage::EcSha256> retire(const Run &, const std::filesystem::path &archive);
  Result<storage::EcSha256> finishRetirement(const EcReadReceipt &, const std::filesystem::path &archive);
  std::filesystem::path runPath(uint64_t sequence) const;
  Result<Void> validReceipt(const EcReadReceipt &) const;
  Result<std::string> read(std::string_view name, size_t limit) const;
  Result<Void> writeNew(std::string_view name, std::string_view bytes);
  Result<Void> writeCounter(uint64_t next);
  std::filesystem::path path_;
  std::string cluster_;
  Limits limits_;
  Uuid namespace_ = Uuid::zero();
  uint64_t nextSequence_ = 1;
  int directory_ = -1, lock_ = -1;
  std::atomic_bool poisoned_{false};  // connect may inspect a shared handle before rejecting attached_.
  std::atomic_bool attached_{false};  // Also excludes a second manager on this shared handle.
};
}  // namespace hf3fs::client::ec
