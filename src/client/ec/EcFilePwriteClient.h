#pragma once
#include <mutex>

#include "EcFilePwriteJournal.h"
#include "EcStripeClient.h"
#include "client/storage/EcRmwTransport.h"

namespace hf3fs::client::ec {
struct EcPwriteOutcome {
  uint64_t confirmedPrefix = 0, revalidatedPrefix = 0;
  bool observed = false, logicalClosed = false, logicalComplete = false, allCleanupComplete = false;
  std::optional<Status> failure;
};
// Synchronous, serialized, bounded client. Call from an ordinary caller thread,
// NEVER a network/event-loop thread. Each blockingWait retains the real owned
// request through actual completion; there are no background calls after return.
// Meta/network/config lifetimes must exceed this client. The caller stops shared
// transports only after all calls have returned. Session close is a REMOTE API,
// not a substitute for source/output T2 cleanup or process runtime shutdown.
class EcFilePwriteClient final {
 public:
  static Result<std::unique_ptr<EcFilePwriteClient>> connect(std::shared_ptr<meta::client::MetaClient>,
                                                             std::shared_ptr<storage::client::EcRmwTransport>,
                                                             std::shared_ptr<hf3fs::client::ICommonMgmtdClient>,
                                                             flat::UserInfo,
                                                             Uuid expectedNamespace);
  const meta::EcOwner &owner() const { return owner_; }
  Result<EcFilePayload> readInput(const std::filesystem::path &path) { return readEcPwriteInput(*budget_, path); }
  Result<meta::EcFileSessionRecord> open(EcFilePwriteJournal &, EcStripeControl);
  Result<meta::EcFileSessionRecord> closeSession(EcFilePwriteJournal &, EcStripeControl);
  EcPwriteOutcome query(EcFilePwriteJournal &, EcStripeControl);
  EcPwriteOutcome pwrite(EcFilePwriteJournal &, EcFilePayload, EcStripeControl);
  // Explicitly stop an incomplete logical batch at its confirmed prefix, then
  // drain only its actually-created children. Never called implicitly on error.
  EcPwriteOutcome sealAndCleanup(EcFilePwriteJournal &, EcStripeControl);

 private:
  EcFilePwriteClient(std::shared_ptr<meta::client::MetaClient> m,
                     std::shared_ptr<storage::client::EcRmwTransport> t,
                     std::shared_ptr<hf3fs::client::ICommonMgmtdClient> g,
                     flat::UserInfo u,
                     std::shared_ptr<EcFilePayloadBudget> b)
      : meta_(std::move(m)),
        transport_(std::move(t)),
        mgmtd_(std::move(g)),
        credentials_(std::move(u)),
        owner_{credentials_.uid, meta_->clientId().uuid},
        budget_(std::move(b)) {}
  Result<Void> check(const EcFilePwriteJournal &, EcStripeControl) const;
  void request(meta::ReqBase &, Uuid) const;
  Result<Void> remember(EcFilePwriteJournal &, const meta::EcFilePwriteProgress &, std::optional<size_t> child);
  Result<meta::EcFilePwriteRsp> observe(EcFilePwriteJournal &, std::optional<size_t>, EcStripeControl);
  Result<meta::EcFilePwriteRsp> advance(EcFilePwriteJournal &,
                                        meta::EcFileAdvanceAction,
                                        std::optional<size_t>,
                                        EcStripeControl);
  Result<Void> upload(EcFilePwriteJournal &,
                      size_t,
                      const meta::EcFileWorkerAccess &,
                      std::span<const uint8_t>,
                      EcStripeControl);
  EcPwriteOutcome execute(EcFilePwriteJournal &, EcFilePayload *, EcStripeControl, bool seal);
  Result<Void> executeOwned(EcFilePwriteJournal &, EcFilePayload *, EcStripeControl, bool seal);
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<storage::client::EcRmwTransport> transport_;
  std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd_;
  flat::UserInfo credentials_;
  meta::EcOwner owner_;
  std::shared_ptr<EcFilePayloadBudget> budget_;
  std::mutex mutex_;
  bool observed_ = false;
  uint64_t revalidatedPrefix_ = 0;
  bool mutationInvoked_ = false;  // Serialized call-local exception classification.
};
}  // namespace hf3fs::client::ec
