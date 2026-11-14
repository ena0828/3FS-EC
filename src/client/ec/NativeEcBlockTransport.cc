#include "NativeEcBlockTransport.h"

#include "client/storage/EcRequestControl.h"
#include "fbs/storage/EcStageValidationV2.h"

namespace hf3fs::client::ec {
NativeEcBlockTransport::NativeEcBlockTransport(std::shared_ptr<storage::client::StorageClient> client,
                                               storage::client::EcRpcObservation *observation,
                                               EcStorageTransportPolicy transport)
    : client_(std::move(client)), observation_(observation), transport_(transport) {}
CoTryTask<storage::EcReadBlockResultV2> NativeEcBlockTransport::read(storage::EcReadBlockV2Req request,
                                                                     EcReadControl control) {
  CO_RETURN_ON_ERROR(validateEcStorageTransport(transport_));
  auto client = client_;
  if (!client) co_return makeError(StorageClientCode::kNotInitialized);
  storage::client::EcRequestControl options;
  options.deadline = control.deadline;
  options.cancellation = control.cancellation;
  options.transport = transport_;
  options.observation = observation_;
  // Keep our own fixed request for verification; the controlled RPC receives
  // its own value and owns it until ClientContext completion.
  auto result = co_await client->readEcBlockV2Controlled(request, std::move(options));
  if (!result) co_return makeError(result.error());
  auto verified = storage::validateEcReadBlockV2(*result, request);
  if (!verified) co_return makeError(verified.error());
  co_return std::move(*result);
}
}  // namespace hf3fs::client::ec
