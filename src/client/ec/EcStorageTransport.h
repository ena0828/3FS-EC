#pragma once

#include <string_view>

#include "client/storage/EcRequestControl.h"
#include "common/utils/Result.h"

namespace hf3fs::client::ec {

using EcStorageTransportPolicy = storage::client::EcRequestControl::TransportPolicy;

// Client-originated Storage EC data policy. Meta/Mgmtd control-plane routing
// and Meta-owned data transports have independent configuration. Never serialized.
inline Result<Void> validateEcStorageTransport(EcStorageTransportPolicy policy) {
  if (!storage::client::isExplicitEcTransportPolicy(policy)) return makeError(StatusCode::kInvalidArg);
  return Void{};
}

inline Result<EcStorageTransportPolicy> parseEcStorageTransport(std::string_view value) {
  if (value == "tcp") return EcStorageTransportPolicy::TcpOnly;
  if (value == "rdma") return EcStorageTransportPolicy::RdmaOnly;
  return makeError(StatusCode::kInvalidConfig, "storage_transport must be tcp or rdma");
}

}  // namespace hf3fs::client::ec
