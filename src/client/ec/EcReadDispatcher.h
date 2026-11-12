#pragma once

#include "EcFileClient.h"
#include "EcReadSpool.h"

namespace hf3fs::client::ec {
namespace detail {
struct EcReadDispatcherCore;
struct EcReadOutputLease;
struct EcReadDispatcherTestAccess;
}  // namespace detail

// Immutable identity/layout learned through Describe42. This is not a server
// open session: each actual range still has the caller's current ACL checked.
class EcReadHandle {
 public:
  const meta::EcFileState &described() const { return file_; }

 private:
  friend struct detail::EcReadDispatcherCore;
  meta::EcFileState file_;
  Uuid dispatcher_ = Uuid::zero();
  Uuid describeRequest_ = Uuid::zero();
};

// The payload cannot be extracted independently of its dispatcher lease.
// Callers may borrow bytes only while this entire object remains alive.
class EcDispatchedRead {
 public:
  EcDispatchedRead() = default;
  EcDispatchedRead(EcDispatchedRead &&) noexcept;
  EcDispatchedRead &operator=(EcDispatchedRead &&) noexcept;
  EcDispatchedRead(const EcDispatchedRead &) = delete;
  EcDispatchedRead &operator=(const EcDispatchedRead &) = delete;
  std::span<const uint8_t> bytes() const { return output_.data.bytes(); }
  const meta::EcRangeSnapshot &snapshot() const { return output_.snapshot; }

 private:
  friend struct detail::EcReadDispatcherCore;
  // Reverse destruction order: data disappears before manager/spool lease.
  std::shared_ptr<detail::EcReadOutputLease> lease_;
  EcFileReadOutput output_;
};

struct EcDispatchCleanupOutcome : EcFileReleaseOutcome {
  EcDispatchCleanupOutcome() = default;
  EcDispatchCleanupOutcome(EcFileReleaseOutcome value, bool joined)
      : EcFileReleaseOutcome(std::move(value)),
        localJoined(joined) {}
  bool localJoined = false;
};
struct EcDispatchReadOutcome {
  EcReadReceipt receipt;
  bool localJoined = false;
  std::optional<EcDispatchedRead> data;
  std::optional<Status> readFailure;
  EcDispatchCleanupOutcome cleanup;
};
enum class EcReadLocalEvidence { Retained, RetirementPending, NotRetained };
struct EcReadReceiptObservation {
  EcReadLocalEvidence evidence = EcReadLocalEvidence::NotRetained;
  std::optional<EcReadDebt> record;
};
struct EcReadRetirementOutcome {
  EcReadReceipt receipt;
  std::filesystem::path archive;
  storage::EcSha256 archiveSha256{};
  bool localFilesRemoved = false;
};
struct EcReadShutdownReport {
  bool localJoined = false;
  bool dispatcherTasksJoined = false;
  bool lowerJoinConfirmed = false;
  bool inventoryVerified = false;
  size_t retainedOutputLeases = 0;
  EcReadSpoolSnapshot spool;
  std::optional<Status> observationFailure;
  std::optional<Status> joinFailure;
};

// One accepted call at a time, no detached work or hidden queue. A second call
// is rejected before Acquire43. Before stopping supplied clients/executor,
// await stop() and require report.localJoined && report.lowerJoinConfirmed.
// Merely awaiting a failed stop is insufficient: retain the same dispatcher and
// dependencies and retry stop; never replace an unconfirmed lower manager. This
// obligation also applies after a caller drops its waiter.
class EcReadDispatcher {
 public:
  struct Limits {
    std::chrono::seconds maximumOperationTime{300};
    std::chrono::seconds cleanupAttemptTime{5};
  };
  static Result<std::shared_ptr<EcReadDispatcher>> connect(std::shared_ptr<EcReadSpool>,
                                                           std::shared_ptr<meta::client::MetaClient>,
                                                           std::shared_ptr<storage::client::StorageClient>,
                                                           std::shared_ptr<hf3fs::client::ICommonMgmtdClient>,
                                                           folly::CPUThreadPoolExecutor &,
                                                           Limits);
  ~EcReadDispatcher();
  CoTryTask<EcReadHandle> openRead(meta::EcObjectRef, flat::UserInfo, EcStripeControl);
  CoTryTask<EcDispatchReadOutcome> read(EcReadHandle,
                                        flat::UserInfo,
                                        uint64_t offset,
                                        uint64_t length,
                                        EcStripeControl);
  CoTryTask<EcDispatchReadOutcome> resumeRead(EcReadReceipt, flat::UserInfo, EcStripeControl);
  CoTask<EcDispatchCleanupOutcome> retryCleanup(EcReadReceipt, flat::UserInfo, EcStripeControl);
  CoTryTask<EcReadRetirementOutcome> retire(EcReadReceipt,
                                            flat::UserInfo,
                                            std::filesystem::path explicitArchive,
                                            EcStripeControl);
  CoTryTask<EcReadSpoolSnapshot> inspect();
  CoTryTask<EcReadReceiptObservation> inspectReceipt(EcReadReceipt);
  CoTask<EcReadShutdownReport> stop();

 private:
  friend struct detail::EcReadDispatcherTestAccess;
  explicit EcReadDispatcher(std::shared_ptr<detail::EcReadDispatcherCore> core)
      : core_(std::move(core)) {}
  std::shared_ptr<detail::EcReadDispatcherCore> core_;
};
}  // namespace hf3fs::client::ec
