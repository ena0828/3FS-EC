#pragma once
#include "client/storage/StorageClient.h"
#include "meta/components/EcGcAbsentCoordinator.h"

namespace hf3fs::meta::server {
class NativeEcGcAbsentTransport final : public EcGcAbsentTransport {
 public:
  static Result<std::shared_ptr<NativeEcGcAbsentTransport>> create(
      std::shared_ptr<storage::client::StorageClient>, std::shared_ptr<const storage::EcGcKey>);
  CoTryTask<storage::EcGcAbsentAck> exchange(storage::EcGcAbsentRequest, storage::client::EcRequestControl) override;
 private:
  NativeEcGcAbsentTransport(std::shared_ptr<storage::client::StorageClient> c,
                            std::shared_ptr<const storage::EcGcKey> k) : client_(std::move(c)), key_(std::move(k)) {}
  static CoTryTask<storage::EcGcAbsentAck> exchangeOwned(std::shared_ptr<storage::client::StorageClient>,
      std::shared_ptr<const storage::EcGcKey>, storage::EcGcAbsentRequest, storage::client::EcRequestControl);
  std::shared_ptr<storage::client::StorageClient> client_;
  std::shared_ptr<const storage::EcGcKey> key_;
};
}  // namespace hf3fs::meta::server
