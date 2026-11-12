#pragma once
#include "EcAppendJournal.h"
#include "EcFilePwriteClient.h"

namespace hf3fs::client::ec {
struct EcAppendOutcome {
  uint64_t acceptedOffset = 0;
  meta::EcFileAppendRecord accepted;
  // Same precise distinction between historical and this-call revalidated
  // prefix as pwrite. An offset acceptance alone is never a successful write.
  EcPwriteOutcome write;
};
// Synchronous, serialized, no detached work. Use only on an ordinary owned
// caller thread. The referenced writer must outlive this facade and all calls.
class EcFileAppendClient {
 public:
  static Result<std::unique_ptr<EcFileAppendClient>> connect(std::shared_ptr<meta::client::MetaClient>,
                                                             EcFilePwriteClient &,
                                                             flat::UserInfo,
                                                             Uuid expectedNamespace);
  Result<EcAppendOutcome> append(EcAppendJournal &, EcFilePayload, EcStripeControl);
  Result<EcAppendOutcome> query(EcAppendJournal &, EcStripeControl);
  // Explicit partial-write fence. Releases EOF ownership only at confirmed
  // prefix, then performs the existing real candidate/source T2 cleanup.
  Result<EcAppendOutcome> sealAndCleanup(EcAppendJournal &, EcStripeControl);
  // Caller must first join all locally owned writes/truncates and resolve any
  // undispatched/unknown journals. Use a NEW persisted Sync run per new barrier;
  // resume the SAME run after a lost response. This is not local-journal fsync.
  Result<meta::EcFileSyncRecord> fsync(EcAppendJournal &, EcStripeControl);

 private:
  EcFileAppendClient(std::shared_ptr<meta::client::MetaClient> m, EcFilePwriteClient &w, flat::UserInfo u)
      : meta_(std::move(m)),
        writer_(w),
        user_(std::move(u)) {}
  Result<Void> check(const EcAppendJournal &, EcStripeControl) const;
  void request(meta::ReqBase &, Uuid) const;
  Result<EcAppendOutcome> execute(EcAppendJournal &, EcFilePayload *, EcStripeControl, bool seal);
  std::shared_ptr<meta::client::MetaClient> meta_;
  EcFilePwriteClient &writer_;
  flat::UserInfo user_;
  std::mutex mutex_;
};
}  // namespace hf3fs::client::ec
