#pragma once

#include "erasure/ErasureCodec.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace hf3fs::erasure {

// Logical identity only. Data generation and placement are separate attributes.
struct ECShardKey {
  uint64_t inodeId{};
  uint32_t logicalChunkIndex{};
  uint32_t stripeIndex{};
  uint8_t shardIndex{};
  bool operator==(const ECShardKey&) const = default;
};

enum class ShardRole { Data, Parity };
enum class LayoutError {
  Ok,
  InvalidIndex,
  InvalidStripe,
  OutOfRange,
  Overflow,
  TooManySegments,
  InvalidLength,
  InvalidFormat,
  InvalidShardBuffer,
  InvalidPlacement,
  CodecFailure,
};

template <typename T>
struct LayoutResult {
  LayoutError error{LayoutError::Ok};
  T value{};
  explicit operator bool() const { return error == LayoutError::Ok; }
};

struct ByteRange {
  uint32_t offset{};
  uint32_t length{};
};
struct ChunkRange {
  uint64_t begin{};
  uint64_t endExclusive{};
};
struct ByteLocation {
  uint32_t logicalChunkIndex{};
  uint32_t stripeIndex{};
  uint32_t chunkOffset{};
  uint8_t shardIndex{};
  uint32_t offsetInShard{};
};
struct ShardSlice {
  uint32_t logicalChunkIndex{};
  uint32_t stripeIndex{};
  uint8_t shardIndex{};
  uint32_t offsetInShard{};
  uint64_t fileOffset{};
  uint32_t length{};
};

// Test-only static mapping. Target identifiers are opaque; no node fault-domain claim.
struct ECStaticPlacement {
  std::array<uint64_t, ErasureCodec::kTotal> targetIds{};
  LayoutError validate() const;
  LayoutResult<uint64_t> targetForShard(uint8_t shardIndex) const;
};

struct ECStripeBuffers {
  // This is an owned, in-memory value; it is not an on-disk format.
  uint32_t encodingScheme{1};
  uint32_t formatVersion{1};
  uint32_t validBytes{};
  std::array<std::vector<uint8_t>, ErasureCodec::kTotal> shards;
};

class ECLayout {
 public:
  static constexpr uint32_t kChunkSize = 4u * 1024u * 1024u;
  static constexpr uint32_t kShardSize = (kChunkSize + ErasureCodec::kData - 1) / ErasureCodec::kData;
  static constexpr uint32_t kDataCapacity = kShardSize * ErasureCodec::kData;
  static constexpr uint32_t kFormatVersion = 1;
  static constexpr uint32_t kEncodingScheme = 1;  // ISA-L systematic Cauchy GF(256), RS(10,2).
  static constexpr uint64_t kMaxFileBytes = (uint64_t{1} << 32) * kChunkSize;
  static constexpr size_t kMaxSlicesPerCall = 4096;

  static LayoutError validateKey(const ECShardKey& key);
  static LayoutResult<ShardRole> shardRole(uint8_t shardIndex);
  static LayoutResult<ByteRange> dataShardLogicalRange(uint8_t dataShardIndex);
  static LayoutResult<ByteLocation> mapOffset(uint64_t fileOffset);
  static LayoutResult<ChunkRange> mapChunkRange(uint64_t fileOffset, uint64_t length);
  // Covers [fileOffset, fileOffset + length) in file order; callers split larger requests.
  static LayoutResult<std::vector<ShardSlice>> mapRange(uint64_t fileOffset, uint64_t length);
  static LayoutResult<uint32_t> validBytesForChunk(uint64_t fileLength, uint32_t logicalChunkIndex);
  static LayoutResult<uint32_t> zeroPadding(uint32_t validBytes);

  // Allocates and owns all 12 shards; only the first input.size() bytes are real data.
  static LayoutError splitAndEncode(std::span<const uint8_t> input,
                                    const ErasureCodec& codec,
                                    ECStripeBuffers& output);
  // Requires 10 complete data shard buffers and returns exactly validBytes bytes.
  static LayoutError reassemble(const ECStripeBuffers& input, std::vector<uint8_t>& output);
};

}  // namespace hf3fs::erasure
