#include "meta/components/NativeEcGcAbsentTransport.h"

namespace hf3fs::meta::server {
Result<std::shared_ptr<NativeEcGcAbsentTransport>> NativeEcGcAbsentTransport::create(
    std::shared_ptr<storage::client::StorageClient> client, std::shared_ptr<const storage::EcGcKey> key) {
  if (!client || !key) return makeError(StatusCode::kInvalidConfig);
  return std::shared_ptr<NativeEcGcAbsentTransport>(new NativeEcGcAbsentTransport(std::move(client), std::move(key)));
}
CoTryTask<storage::EcGcAbsentAck> NativeEcGcAbsentTransport::exchangeOwned(
    std::shared_ptr<storage::client::StorageClient> client, std::shared_ptr<const storage::EcGcKey> key,
    storage::EcGcAbsentRequest request, storage::client::EcRequestControl control) {
  co_return co_await client->exchangeEcGcAbsentControlled(std::move(request), std::move(key), std::move(control));
}
CoTryTask<storage::EcGcAbsentAck> NativeEcGcAbsentTransport::exchange(
    storage::EcGcAbsentRequest request, storage::client::EcRequestControl control) {
  return exchangeOwned(client_, key_, std::move(request), std::move(control));
}
}  // namespace hf3fs::meta::server
