#pragma once

#include <chrono>

#include "common/utils/Coroutine.h"

namespace hf3fs::storage::client {

// Local controls only; no changes to EC RPC wire or bearer authorization.
// TcpOnly is explicit because RDMA timeout cleanup has additional drain waits.
struct EcRequestControl {
  enum class TransportPolicy { Automatic, TcpOnly };
  std::chrono::steady_clock::time_point deadline;
  CancellationToken cancellation;
  TransportPolicy transport = TransportPolicy::TcpOnly;
};

}  // namespace hf3fs::storage::client
