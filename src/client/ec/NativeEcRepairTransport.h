#pragma once

#include <atomic>
#include <optional>

#include "EcRepairPipeline.h"
#include "client/storage/StorageClient.h"
#include "fbs/storage/EcHelper.h"

namespace hf3fs::client::ec {

struct EcRepairNativeBindings {
  std::array<storage::EcReadBlockV2Req, 10> sources;
  // One immutable V2 grant per target, containing Begin/Append/Query/Reconcile/Seal rights.
  // Its scope and descriptor are issued by Meta, not constructed here.
  std::array<storage::EcBeginStageV2Req, 2> targets;
};

// Real StorageClient adapter. Helper mode additionally requires ten separately
// issued helper capabilities and uses RPC46; it has no centralized fallback.
class NativeEcRepairTransport final : public EcRepairTransport {
 public:
  static Result<std::shared_ptr<NativeEcRepairTransport>> create(
      Plan plan,
      std::shared_ptr<storage::client::StorageClient> client,
      EcRepairNativeBindings bindings,
      std::optional<std::array<storage::EcHelperCapability, 10>> helpers = std::nullopt);
  bool supportsHelperChain() const override { return helpers_.has_value(); }
  CoTryTask<void> begin(Plan, uint8_t target, EcRepairControl) override;
  CoTryTask<std::string> read(Plan, uint8_t source, uint32_t block, EcRepairControl) override;
  CoTryTask<void> append(Plan, uint8_t target, uint32_t block, std::string data, EcRepairControl) override;
  CoTryTask<storage::EcFragmentReceiptV2> seal(Plan, uint8_t target, EcRepairControl) override;
  CoTryTask<storage::EcRepairBlock> helperBlock(Plan, uint32_t block, EcRepairControl) override;

 private:
  NativeEcRepairTransport(Plan plan,
                          std::shared_ptr<storage::client::StorageClient> client,
                          EcRepairNativeBindings bindings,
                          std::optional<std::array<storage::EcHelperCapability, 10>> helpers)
      : plan_(std::move(plan)),
        client_(std::move(client)),
        bindings_(std::move(bindings)),
        helpers_(std::move(helpers)) {}
  Result<Void> check(const Plan &, const EcRepairControl &) const;
  Status preserveOutcome(uint8_t target, Status error);
  Plan plan_;
  std::shared_ptr<storage::client::StorageClient> client_;
  EcRepairNativeBindings bindings_;
  std::optional<std::array<storage::EcHelperCapability, 10>> helpers_;
  std::array<std::atomic<bool>, 2> alreadySealed_{};
  // A failed observer or pre-admission check cannot resolve a previously
  // dispatched mutation. Only a verified Reconcile/Seal clears this state.
  std::array<std::atomic<bool>, 2> unconfirmed_{};
};

}  // namespace hf3fs::client::ec
