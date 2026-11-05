#pragma once

#include "client/storage/StorageClient.h"
#include "meta/components/EcGcCoordinator.h"

namespace hf3fs::meta::server {
// Actual StorageClient/Messenger TCP path. This adapter cannot create claims,
// sign GC requests, substitute instances or turn remote Missing into success.
class NativeEcGcTransport final : public EcGcTransport {
 public:
  static Result<std::shared_ptr<NativeEcGcTransport>> create(std::shared_ptr<storage::client::StorageClient>,
                                                             std::shared_ptr<const storage::EcGcKey>);
  CoTryTask<storage::EcGcAck> exchange(storage::EcGcRequest, storage::client::EcRequestControl) override;

 private:
  NativeEcGcTransport(std::shared_ptr<storage::client::StorageClient> client,
                      std::shared_ptr<const storage::EcGcKey> key)
      : client_(std::move(client)),
        key_(std::move(key)) {}
  static CoTryTask<storage::EcGcAck> exchangeOwned(std::shared_ptr<storage::client::StorageClient>,
                                                   std::shared_ptr<const storage::EcGcKey>,
                                                   storage::EcGcRequest,
                                                   storage::client::EcRequestControl);
  std::shared_ptr<storage::client::StorageClient> client_;
  std::shared_ptr<const storage::EcGcKey> key_;
};
}  // namespace hf3fs::meta::server
