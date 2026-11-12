#pragma once

#include "EcFilePayload.h"
#include "EcFileRunJournal.h"
#include "EcTreeReadJournal.h"
#include "EcTruncateJournal.h"
#include "fbs/meta/EcFileRange.h"

namespace hf3fs::client::ec {
namespace detail {
struct EcFileClientCore;
struct EcFileCompletionTestAccess;
}  // namespace detail
struct EcFileReadOutput {
  meta::EcRangeSnapshot snapshot;
  EcFilePayload data;
};
struct EcFileTreeReadOutput {
  meta::EcTreeReadRecord snapshot;
  EcFilePayload data;
};
struct EcFileAppendOutcome {
  // Historical, locally persisted observations remain visible on any tail
  // error. Recovery revalidates this prefix with owner-bound RPC45 before a new
  // Begin. That observation grants no permission to resume unfinished writes.
  uint64_t confirmedPrefixBytes = 0;
  uint64_t revalidatedPrefixBytes = 0;
  uint16_t confirmedStripes = 0;
  uint16_t firstUnconfirmedIndex = 0;
  EcFileAppendState firstUnconfirmedState = EcFileAppendState::NotStarted;
  bool complete = false;
  std::optional<Status> failure;
};
struct EcFileReleaseOutcome {
  uint16_t expectedPins = 0;
  uint16_t releasedMask = 0;
  bool allReleased = false;
  std::optional<Status> failure;
};

// One file operation at a time, one exclusive shared StripeClient (64 MiB),
// and one 32 MiB file payload partition. Accepted tasks are owned by AsyncScope.
// close() must finish before manager/network/executor destruction. It joins
// local operations; it does not release remote pins or establish file fsync.
// A failed close throws, retains unconfirmed owned work and leaves admission
// closed. Retry close on the same instance: completed stages are not repeated.
// If an entered join has no completion proof, retries fail conservatively;
// callers must not destroy the supplied clients/executor as though joined.
class EcFileClient {
 public:
  static CoTryTask<std::shared_ptr<EcFileClient>> connect(std::shared_ptr<meta::client::MetaClient>,
                                                          std::shared_ptr<storage::client::StorageClient>,
                                                          std::shared_ptr<hf3fs::client::ICommonMgmtdClient>,
                                                          flat::UserInfo,
                                                          Uuid expectedNamespace,
                                                          folly::CPUThreadPoolExecutor &,
                                                          std::chrono::seconds maximumTime = std::chrono::seconds(300));
  ~EcFileClient();
  const meta::EcOwner &owner() const;
  Result<EcFilePayload> allocatePayload(size_t bytes);
  size_t payloadBytes() const;
  // A settled error response is not a lower-layer join certificate. Adapters
  // must retain this instance and its dependencies while this flag is true.
  bool localJoinUnconfirmed() const noexcept;
  CoTryTask<meta::EcFileState> describe(meta::EcObjectRef, Uuid requestId, meta::AccessType, EcStripeControl);
  // Full range ready is published only after all local stripe work joins in
  // this first implementation. Remote T2 remains a separate explicit call.
  CoTryTask<EcFileReadOutput> read(std::shared_ptr<EcFileRunJournal>, EcStripeControl);
  CoTask<EcFileAppendOutcome> appendAt(std::shared_ptr<EcFileRunJournal>, EcFilePayload, EcStripeControl);
  // Query-only recovery of range identity; never creates a missing range.
  CoTask<EcFileReleaseOutcome> releaseRead(std::shared_ptr<EcFileRunJournal>, EcStripeControl);
  // Mode4 has an independent fixed root/scope journal. These methods never
  // call legacy Acquire34/Release36; close() still joins all local work.
  CoTryTask<EcFileTreeReadOutput> readTree(std::shared_ptr<EcTreeReadJournal>, EcStripeControl);
  CoTryTask<meta::EcTreeReadRecord> releaseTree(std::shared_ptr<EcTreeReadJournal>, EcStripeControl);
  // One bounded mode4 truncate step. Planned is pending, not published.
  CoTryTask<meta::EcFileTruncateProgress> truncate(std::shared_ptr<EcTruncateJournal>, EcStripeControl);
  CoTryTask<meta::EcFileTruncateProgress> queryTruncate(std::shared_ptr<EcTruncateJournal>, EcStripeControl);
  CoTryTask<meta::EcFileTruncateProgress> closeTruncateDebt(std::shared_ptr<EcTruncateJournal>, EcStripeControl);
  CoTask<void> close();

 private:
  friend struct detail::EcFileCompletionTestAccess;
  explicit EcFileClient(std::shared_ptr<detail::EcFileClientCore>);
  std::shared_ptr<detail::EcFileClientCore> core_;
};
}  // namespace hf3fs::client::ec
