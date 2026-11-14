#pragma once

#include <mutex>
#include "EcNamespaceJournal.h"
#include "EcStripeClient.h"

namespace hf3fs::client::ec {
struct EcNamespaceOutcome {
  bool acknowledged = false;  // Durable historical acknowledgement, even on a later failure.
  bool revalidated = false;   // This invocation received and durably recorded a fixed-request success.
  std::optional<Status> failure;
};
// Serialized caller-thread API. Only Meta authentication and fixed Remove RPC;
// no storage worker, RMW, IB manager, path existence query or hidden close/GC.
// Dependencies outlive calls; each blockingWait joins its owned request.
class EcNamespaceClient final {
 public:
  static Result<std::unique_ptr<EcNamespaceClient>> connect(std::shared_ptr<meta::client::MetaClient>,
                                                            flat::UserInfo, Uuid expectedNamespace);
  const meta::EcOwner &owner() const { return owner_; }
  EcNamespaceOutcome unlink(EcNamespaceJournal &, EcStripeControl);

 private:
  EcNamespaceClient(std::shared_ptr<meta::client::MetaClient> m, flat::UserInfo u)
      : meta_(std::move(m)), credentials_(std::move(u)), owner_{credentials_.uid, meta_->clientId().uuid} {}
  std::shared_ptr<meta::client::MetaClient> meta_;
  flat::UserInfo credentials_;
  meta::EcOwner owner_;
  std::mutex mutex_;
};
}  // namespace hf3fs::client::ec
