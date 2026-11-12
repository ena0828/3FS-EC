#pragma once

#include <functional>

#include "EcRmwComputation.h"
#include "EcRmwResources.h"
#include "client/storage/EcRequestControl.h"
#include "client/storage/StorageClient.h"
#include "storage/ec_scope/EcScope.h"

namespace hf3fs::storage {
class StorageTarget;
// NativeEcRmwOutputBinder supplies real Meta52 transport, which rereads/commits the
// immutable computed binding. It returns exact signed data credentials, not a
// caller boolean claiming durability. It must never expose these to clients.
class EcRmwOutputBinder {
 public:
  virtual ~EcRmwOutputBinder() = default;
  virtual CoTryTask<std::array<EcCapabilityV2, 12>> bind(const EcRmwPlan &,
                                                         const EcRmwComputedCommitment &,
                                                         client::EcRequestControl) = 0;
};
class NativeEcRmwIo final : public EcRmwIo {
 public:
  using Clock = std::function<uint64_t()>;
  using Route = std::function<Result<VersionedChainId>(const EcScopeEndpoint &)>;
  // This is an internal runtime constructor, not a wire/Meta authorization
  // factory. freshLocalFence must check the actual map/route/target identity;
  // all captured owners outlive the job via the runtime's owned stop/join.
  static Result<std::shared_ptr<NativeEcRmwIo>> create(std::shared_ptr<const EcRmwPlan>,
                                                       EcRmwGrant,
                                                       std::shared_ptr<const EcRmwKey>,
                                                       std::shared_ptr<const EcCapabilityKey> dataKey,
                                                       Uuid authority,
                                                       EcScopeEndpoint actualWorker,
                                                       std::shared_ptr<StorageTarget>,
                                                       EcScopeTicket,
                                                       std::shared_ptr<EcRmwJobLease>,
                                                       std::shared_ptr<client::StorageClient>,
                                                       std::array<EcCapabilityV2, 12> internalReads,
                                                       std::shared_ptr<EcRmwOutputBinder>,
                                                       Route,
                                                       Clock,
                                                       std::function<Result<Void>()> freshLocalFence,
                                                       client::EcRequestControl);
  const EcSha256 &planDigest() const noexcept { return plan_->digest(); }
  Result<Void> check() const override;
  CoTryTask<std::string> readSource(uint8_t) override;
  CoTryTask<Void> bindOutput(const EcRmwOutputCommitment &) override;
  CoTryTask<EcFragmentReceiptV2> writeTarget(uint8_t, const EcIntegrityDescriptor &, std::string) override;

 private:
  NativeEcRmwIo() = default;
  Status preserve(uint8_t, Status);
  EcGrantBindingV2 expected(const EcRepairFragment &, EcGrantScope, const Uuid &) const;
  // Declared first so reservations remain until buffers, credentials, target,
  // ticket and owned transport references have been destroyed.
  std::shared_ptr<EcRmwJobLease> lease_;
  std::shared_ptr<const EcRmwPlan> plan_;
  EcRmwGrant grant_;
  std::shared_ptr<const EcRmwKey> key_;
  std::shared_ptr<const EcCapabilityKey> dataKey_;
  Uuid authority_ = Uuid::zero();
  EcScopeEndpoint actual_;
  std::shared_ptr<StorageTarget> target_;
  std::optional<EcScopeTicket> ticket_;
  std::shared_ptr<client::StorageClient> client_;
  std::array<EcCapabilityV2, 12> reads_;
  std::array<EcCapabilityV2, 12> writes_;
  std::shared_ptr<EcRmwOutputBinder> binder_;
  Route route_;
  Clock clock_;
  std::function<Result<Void>()> localFence_;
  client::EcRequestControl control_;
  std::optional<EcRmwOutputCommitment> bound_;
  std::array<bool, 12> unknown_{};  // Single owned execution, never concurrent runs.
};
}  // namespace hf3fs::storage
