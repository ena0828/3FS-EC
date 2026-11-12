#pragma once
#include "NativeEcRmwIo.h"
#include "client/storage/EcRmwTransport.h"
namespace hf3fs::storage {
class NativeEcRmwOutputBinder final : public EcRmwOutputBinder {
 public:
  using MetaAddress = std::function<Result<net::Address>()>;
  NativeEcRmwOutputBinder(std::shared_ptr<client::EcRmwTransport> transport, MetaAddress address, EcRmwGrant execution)
      : transport_(std::move(transport)),
        address_(std::move(address)),
        execution_(std::move(execution)) {}
  CoTryTask<std::array<EcCapabilityV2, 12>> bind(const EcRmwPlan &,
                                                 const EcRmwComputedCommitment &,
                                                 client::EcRequestControl) override;

 private:
  std::shared_ptr<client::EcRmwTransport> transport_;
  MetaAddress address_;
  EcRmwGrant execution_;
};
}  // namespace hf3fs::storage
