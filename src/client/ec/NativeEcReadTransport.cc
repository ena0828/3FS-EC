#include "NativeEcReadTransport.h"

#include "client/storage/EcRequestControl.h"

namespace hf3fs::client::ec {

NativeEcReadTransport::NativeEcReadTransport(std::shared_ptr<storage::client::StorageClient> client)
    : client_(std::move(client)) {}

CoTryTask<storage::EcReadResult> NativeEcReadTransport::read(storage::EcAuthorizedReadReq request,
                                                             EcReadControl control) {
  auto client = client_;
  if (!client) co_return makeError(StorageClientCode::kNotInitialized);
  storage::client::EcRequestControl options;
  options.deadline = control.deadline;
  options.cancellation = control.cancellation;
  options.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
  co_return co_await client->authorizedReadEcFragmentControlled(std::move(request), std::move(options));
}

}  // namespace hf3fs::client::ec
