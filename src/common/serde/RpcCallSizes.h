#pragma once

#include <cstdint>
#include <type_traits>

namespace hf3fs::serde {

// Local scalar observations only: never serialized or attached to a Transport.
// A frame includes the 8-byte MessageHeader and the actually selected compressed
// or uncompressed message. Missing is distinct from a zero-byte observation.
struct RpcFrameSize {
  uint64_t bytes = 0;
  bool available = false;
  bool compressed = false;
};

struct RpcCallSizes {
  RpcFrameSize request{};
  RpcFrameSize response{};
};
static_assert(std::is_trivially_copyable_v<RpcCallSizes>);
static_assert(std::is_nothrow_default_constructible_v<RpcCallSizes>);
static_assert(std::is_nothrow_copy_assignable_v<RpcCallSizes>);

}  // namespace hf3fs::serde
