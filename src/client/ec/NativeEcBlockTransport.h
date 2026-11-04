#pragma once

#include "EcBlockRead.h"
#include "client/storage/StorageClient.h"

namespace hf3fs::client::ec {
// Production StorageSerde ReadBlock40 with an owned request and a finite
// deadline. The network client must remain running until local cleanup joins.
class NativeEcBlockTransport final : public EcBlockReadTransport {
 public:
  explicit NativeEcBlockTransport(std::shared_ptr<storage::client::StorageClient> client);
  CoTryTask<storage::EcReadBlockResultV2> read(storage::EcReadBlockV2Req owned, EcReadControl control) override;

 private:
  std::shared_ptr<storage::client::StorageClient> client_;
};
}  // namespace hf3fs::client::ec
