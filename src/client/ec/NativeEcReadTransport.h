#pragma once

#include "EcStorageTransport.h"

#include "EcStripeRead.h"
#include "client/storage/StorageClient.h"

namespace hf3fs::client::ec {

// Uses the production StorageClient authorized wire path. The accompanying
// adapter patch adds finite local controls without changing the legacy API.
class NativeEcReadTransport final : public EcReadTransport {
 public:
  explicit NativeEcReadTransport(
      std::shared_ptr<storage::client::StorageClient> client,
      EcStorageTransportPolicy transport = EcStorageTransportPolicy::TcpOnly);
  CoTryTask<storage::EcReadResult> read(storage::EcAuthorizedReadReq request, EcReadControl control) override;

 private:
  std::shared_ptr<storage::client::StorageClient> client_;
  const EcStorageTransportPolicy transport_;
};

}  // namespace hf3fs::client::ec
