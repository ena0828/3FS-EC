#include "NativeEcReadTransport.h"

#include "client/storage/EcRequestControl.h"

namespace hf3fs::client::ec {

NativeEcReadTransport::NativeEcReadTransport(std::shared_ptr<storage::client::StorageClient> client,
                                               EcStorageTransportPolicy transport)
    : client_(std::move(client)), transport_(transport) {}

CoTryTask<storage::EcReadResult> NativeEcReadTransport::read(storage::EcAuthorizedReadReq request,
                                                             EcReadControl control) {
  CO_RETURN_ON_ERROR(validateEcStorageTransport(transport_));
  auto client = client_;
  if (!client) co_return makeError(StorageClientCode::kNotInitialized);
  storage::client::EcRequestControl options;
  options.deadline = control.deadline;
  options.cancellation = control.cancellation;
  options.transport = transport_;
  co_return co_await client->authorizedReadEcFragmentControlled(std::move(request), std::move(options));
}

}  // namespace hf3fs::client::ec
