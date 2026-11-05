#include "meta/components/NativeEcGcTransport.h"

namespace hf3fs::meta::server {
Result<std::shared_ptr<NativeEcGcTransport>> NativeEcGcTransport::create(
    std::shared_ptr<storage::client::StorageClient> client,
    std::shared_ptr<const storage::EcGcKey> key) {
  if (!client || !key) return makeError(StatusCode::kInvalidConfig, "native GC transport requires a client and G key");
  return std::shared_ptr<NativeEcGcTransport>(new NativeEcGcTransport(std::move(client), std::move(key)));
}
CoTryTask<storage::EcGcAck> NativeEcGcTransport::exchangeOwned(std::shared_ptr<storage::client::StorageClient> client,
                                                               std::shared_ptr<const storage::EcGcKey> key,
                                                               storage::EcGcRequest request,
                                                               storage::client::EcRequestControl control) {
  co_return co_await client->exchangeEcGcControlled(std::move(request), std::move(key), std::move(control));
}
CoTryTask<storage::EcGcAck> NativeEcGcTransport::exchange(storage::EcGcRequest request,
                                                          storage::client::EcRequestControl control) {
  return exchangeOwned(client_, key_, std::move(request), std::move(control));
}
}  // namespace hf3fs::meta::server
