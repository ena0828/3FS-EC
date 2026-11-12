#pragma once
#include <mutex>

#include "EcStripeClient.h"
#include "EcTreeRepairJournal.h"
#include "NativeEcRepairTransport.h"
namespace hf3fs::client::ec {
struct EcTreeRepairOutcome {
  meta::EcFileRepairProgress progress;
  // A real successful query in THIS call, separately from historical journal.
  bool revalidated = false;
  std::optional<Status> failure;
};
// Serialized synchronous facade for an ordinary owned caller thread. Every
// actual RPC/pipeline child is joined before return; shared runtime outlives it.
class EcFileRepairClient final {
 public:
  static Result<std::unique_ptr<EcFileRepairClient>> connect(std::shared_ptr<meta::client::MetaClient>,
                                                             std::shared_ptr<storage::client::StorageClient>,
                                                             std::shared_ptr<hf3fs::client::ICommonMgmtdClient>,
                                                             flat::UserInfo,
                                                             Uuid expectedNamespace);
  EcTreeRepairOutcome repair(EcTreeRepairJournal &, EcStripeControl);
  EcTreeRepairOutcome query(EcTreeRepairJournal &, EcStripeControl);
  // Explicit close aborts a still-Planned operation. Published repair remains
  // published even if an unreachable original source keeps real T2 debt open.
  EcTreeRepairOutcome closeDebt(EcTreeRepairJournal &, EcStripeControl);

 private:
  EcFileRepairClient(std::shared_ptr<meta::client::MetaClient> m,
                     std::shared_ptr<storage::client::StorageClient> s,
                     std::shared_ptr<hf3fs::client::ICommonMgmtdClient> g,
                     flat::UserInfo u)
      : meta_(std::move(m)),
        storage_(std::move(s)),
        mgmtd_(std::move(g)),
        user_(std::move(u)),
        executor_(1) {}
  Result<Void> check(const EcTreeRepairJournal &, EcStripeControl) const;
  void request(meta::EcFileRepairReq &, const EcTreeRepairRun &, Uuid) const;
  EcTreeRepairOutcome execute(EcTreeRepairJournal &, EcStripeControl, uint8_t action);
  CoTryTask<Void> transfer(meta::EcFileRepairAccess, const EcTreeRepairRun &, EcStripeControl);
  CoTryTask<Void> copyOne(const meta::EcV2AllocationBinding &,
                          const meta::EcV2AllocationBinding &,
                          storage::EcCapabilityV2,
                          storage::EcCapabilityV2,
                          EcStripeControl);
  std::shared_ptr<meta::client::MetaClient> meta_;
  std::shared_ptr<storage::client::StorageClient> storage_;
  std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd_;
  flat::UserInfo user_;
  folly::CPUThreadPoolExecutor executor_;
  std::mutex mutex_;
};
}  // namespace hf3fs::client::ec
