#pragma once

#include "EcStorageTransport.h"

#include "EcBlockRead.h"
#include "client/storage/StorageClient.h"

namespace hf3fs::client::ec {
// Production StorageSerde ReadBlock40 with an owned request and a finite
// deadline. The network client must remain running until local cleanup joins.
class NativeEcBlockTransport final : public EcBlockReadTransport {
 public:
  explicit NativeEcBlockTransport(std::shared_ptr<storage::client::StorageClient> client,
                                  storage::client::EcRpcObservation *observation = nullptr,
                                  EcStorageTransportPolicy transport = EcStorageTransportPolicy::TcpOnly);
  CoTryTask<storage::EcReadBlockResultV2> read(storage::EcReadBlockV2Req owned, EcReadControl control) override;

 private:
  std::shared_ptr<storage::client::StorageClient> client_;
  // Borrowed until read() and its controlled child have joined.
  storage::client::EcRpcObservation *observation_;
  const EcStorageTransportPolicy transport_;
};
}  // namespace hf3fs::client::ec
