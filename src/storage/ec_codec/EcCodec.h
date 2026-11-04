#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/utils/Result.h"

namespace hf3fs::storage {

struct EcCodecFormat {
  uint16_t codecId = 1;
  uint16_t matrixVersion = 1;
  uint16_t dataShards = 10;
  uint16_t parityShards = 2;
  uint16_t fieldPolynomial = 0x11d;
};

struct EcCodecShardView {
  uint16_t index;
  std::string_view data;
};

// Arithmetic only: callers must authenticate source identities and verify
// authoritative integrity descriptors before recovery or helper computation.
// Successful verification is not authorization or a durable publication proof.
class EcCodec {
 public:
  static constexpr uint32_t kMaxShardBytes = 1u << 20;
  using Shards = std::array<std::string, 12>;

  // Consecutive logical bytes fill data shards 0..9; the remaining tail is zero.
  // Empty input is valid arithmetic and produces a zero codeword. A publish
  // policy may reject empty stripes. Shard capacity must still be 1..1MiB.
  static Result<Shards> encode(std::string_view logicalData, uint32_t shardBytes, const EcCodecFormat &format = {});
  // All twelve distinct indexed shards are required, in any order. Checks
  // parity and every padding byte after logicalLength in the ten data shards.
  static Result<Void> verify(std::span<const EcCodecShardView> shards,
                             uint64_t logicalLength,
                             uint32_t shardBytes,
                             const EcCodecFormat &format = {});
  // Exactly ten distinct validated sources are required. Returns all twelve
  // shards in index order. This corrects erasures, not unknown corrupt sources.
  static Result<Shards> recover(std::span<const EcCodecShardView> sources,
                                uint64_t logicalLength,
                                uint32_t shardBytes,
                                const EcCodecFormat &format = {});
  // XOR exactly one result from each healthy shard with the same ordered plan,
  // generation, offset and length. Outputs follow targets order. This function
  // does not detect duplicates/omissions across separate helper invocations.
  // Empty slices are valid; a slice must not exceed 1MiB.
  static Result<std::vector<std::string>> contribute(std::span<const uint16_t> healthy,
                                                     std::span<const uint16_t> targets,
                                                     uint16_t helper,
                                                     std::string_view slice,
                                                     const EcCodecFormat &format = {});
};

}  // namespace hf3fs::storage
