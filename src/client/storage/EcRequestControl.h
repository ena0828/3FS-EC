#pragma once

#include <chrono>

#include "common/utils/Coroutine.h"

namespace hf3fs::storage::client {

class EcRpcObservation;

// Local controls only; no changes to EC RPC wire or bearer authorization.
// TCP remains the default. RDMA-only calls retain the native joined timeout
// cleanup, which can outlast the request deadline; no task is detached.
struct EcRequestControl {
  enum class TransportPolicy { Automatic, TcpOnly, RdmaOnly };
  std::chrono::steady_clock::time_point deadline;
  CancellationToken cancellation;
  TransportPolicy transport = TransportPolicy::TcpOnly;
  // Local joined-frame observation only; never retained by the network layer.
  EcRpcObservation *observation = nullptr;
};

// Automatic is a legacy routing policy, never an implicit controlled-EC fallback.
constexpr bool isExplicitEcTransportPolicy(EcRequestControl::TransportPolicy policy) noexcept {
  return policy == EcRequestControl::TransportPolicy::TcpOnly ||
         policy == EcRequestControl::TransportPolicy::RdmaOnly;
}

}  // namespace hf3fs::storage::client
