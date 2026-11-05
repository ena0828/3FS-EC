#pragma once

#include <cstdint>
#include <span>

namespace hf3fs::erasure {

enum class CodecError {
  Ok,
  WrongShardCount,
  InvalidIndex,
  DuplicateIndex,
  SizeMismatch,
  InsufficientShards,
  InvalidBuffer,
  BufferOverlap,
  SizeOverflow,
  SingularMatrix,
};

struct ConstShard {
  uint8_t index;
  std::span<const uint8_t> bytes;
};

struct MutableShard {
  uint8_t index;
  std::span<uint8_t> bytes;
};

// Borrowed, synchronous buffers: the caller owns them through the call.
// No input/output aliasing is allowed. This class has no mutable shared state.
class ErasureCodec {
 public:
  static constexpr uint8_t kData = 10;
  static constexpr uint8_t kParity = 2;
  static constexpr uint8_t kTotal = 12;

  ErasureCodec();
  CodecError encode(std::span<const ConstShard> data,
                    std::span<MutableShard> parity) const;
  CodecError reconstruct(std::span<const ConstShard> available,
                         std::span<MutableShard> missing) const;

 private:
  uint8_t matrix_[kTotal * kData]{};
  uint8_t encodeTables_[32 * kData * kParity]{};
};

}  // namespace hf3fs::erasure
