#include "erasure/ECLayout.h"

#include <algorithm>
#include <array>
#include <limits>

namespace hf3fs::erasure {

LayoutError ECStaticPlacement::validate() const {
  for (size_t i = 0; i < targetIds.size(); ++i) {
    if (targetIds[i] == 0) return LayoutError::InvalidPlacement;
    for (size_t j = 0; j < i; ++j)
      if (targetIds[i] == targetIds[j]) return LayoutError::InvalidPlacement;
  }
  return LayoutError::Ok;
}

LayoutResult<uint64_t> ECStaticPlacement::targetForShard(uint8_t index) const {
  if (index >= targetIds.size()) return {LayoutError::InvalidIndex, 0};
  if (validate() != LayoutError::Ok) return {LayoutError::InvalidPlacement, 0};
  return {LayoutError::Ok, targetIds[index]};
}

LayoutError ECLayout::validateKey(const ECShardKey& key) {
  if (key.stripeIndex != 0) return LayoutError::InvalidStripe;
  if (key.shardIndex >= ErasureCodec::kTotal) return LayoutError::InvalidIndex;
  return LayoutError::Ok;
}

LayoutResult<ShardRole> ECLayout::shardRole(uint8_t index) {
  if (index >= ErasureCodec::kTotal) return {LayoutError::InvalidIndex, {}};
  return {LayoutError::Ok, index < ErasureCodec::kData ? ShardRole::Data : ShardRole::Parity};
}

LayoutResult<ByteRange> ECLayout::dataShardLogicalRange(uint8_t index) {
  if (index >= ErasureCodec::kData) return {LayoutError::InvalidIndex, {}};
  const uint32_t offset = uint32_t(index) * kShardSize;
  return {LayoutError::Ok, {offset, std::min(kShardSize, kChunkSize - offset)}};
}

LayoutResult<ByteLocation> ECLayout::mapOffset(uint64_t offset) {
  if (offset >= kMaxFileBytes) return {LayoutError::OutOfRange, {}};
  const auto chunk = static_cast<uint32_t>(offset / kChunkSize);
  const auto inChunk = static_cast<uint32_t>(offset % kChunkSize);
  const auto shard = static_cast<uint8_t>(inChunk / kShardSize);
  return {LayoutError::Ok, {chunk, 0, inChunk, shard, inChunk % kShardSize}};
}

LayoutResult<ChunkRange> ECLayout::mapChunkRange(uint64_t offset, uint64_t length) {
  if (length > std::numeric_limits<uint64_t>::max() - offset) return {LayoutError::Overflow, {}};
  if (offset > kMaxFileBytes) return {LayoutError::OutOfRange, {}};
  const uint64_t end = offset + length;
  if (end > kMaxFileBytes) return {LayoutError::OutOfRange, {}};
  const uint64_t beginChunk = offset / kChunkSize;
  if (length == 0) return {LayoutError::Ok, {beginChunk, beginChunk}};
  return {LayoutError::Ok, {beginChunk, (end - 1) / kChunkSize + 1}};
}

LayoutResult<std::vector<ShardSlice>> ECLayout::mapRange(uint64_t offset, uint64_t length) {
  auto chunks = mapChunkRange(offset, length);
  if (!chunks) return {chunks.error, {}};
  std::vector<ShardSlice> slices;
  while (length != 0) {
    if (slices.size() == kMaxSlicesPerCall) return {LayoutError::TooManySegments, {}};
    auto loc = mapOffset(offset);
    if (!loc) return {loc.error, {}};
    const uint32_t available = std::min(kChunkSize - loc.value.chunkOffset,
                                        kShardSize - loc.value.offsetInShard);
    const auto take = static_cast<uint32_t>(std::min<uint64_t>(length, available));
    slices.push_back({loc.value.logicalChunkIndex, 0, loc.value.shardIndex,
                      loc.value.offsetInShard, offset, take});
    offset += take;
    length -= take;
  }
  return {LayoutError::Ok, std::move(slices)};
}

LayoutResult<uint32_t> ECLayout::validBytesForChunk(uint64_t fileLength, uint32_t index) {
  if (fileLength > kMaxFileBytes) return {LayoutError::OutOfRange, 0};
  const uint64_t start = uint64_t(index) * kChunkSize;
  if (start >= fileLength) return {LayoutError::Ok, 0};
  return {LayoutError::Ok, static_cast<uint32_t>(std::min<uint64_t>(kChunkSize, fileLength - start))};
}

LayoutResult<uint32_t> ECLayout::zeroPadding(uint32_t validBytes) {
  if (validBytes > kChunkSize) return {LayoutError::InvalidLength, 0};
  return {LayoutError::Ok, kDataCapacity - validBytes};
}

LayoutError ECLayout::splitAndEncode(std::span<const uint8_t> input,
                                     const ErasureCodec& codec,
                                     ECStripeBuffers& output) {
  if (input.size() > kChunkSize) return LayoutError::InvalidLength;
  if (!input.empty() && input.data() == nullptr) return LayoutError::InvalidShardBuffer;
  ECStripeBuffers next;
  next.validBytes = static_cast<uint32_t>(input.size());
  std::array<ConstShard, ErasureCodec::kData> data{};
  std::array<MutableShard, ErasureCodec::kParity> parity{};
  for (uint8_t i = 0; i < ErasureCodec::kTotal; ++i) {
    next.shards[i].assign(kShardSize, 0);
    if (i < ErasureCodec::kData) {
      const size_t start = size_t(i) * kShardSize;
      if (start < input.size()) {
        const size_t take = std::min<size_t>(kShardSize, input.size() - start);
        std::copy_n(input.data() + start, take, next.shards[i].data());
      }
      data[i] = {i, next.shards[i]};
    } else {
      parity[i - ErasureCodec::kData] = {i, next.shards[i]};
    }
  }
  if (codec.encode(data, parity) != CodecError::Ok) return LayoutError::CodecFailure;
  output = std::move(next);
  return LayoutError::Ok;
}

LayoutError ECLayout::reassemble(const ECStripeBuffers& input, std::vector<uint8_t>& output) {
  if (input.encodingScheme != kEncodingScheme || input.formatVersion != kFormatVersion)
    return LayoutError::InvalidFormat;
  if (input.validBytes > kChunkSize) return LayoutError::InvalidLength;
  for (uint8_t i = 0; i < ErasureCodec::kData; ++i)
    if (input.shards[i].size() != kShardSize) return LayoutError::InvalidShardBuffer;
  // Padding is part of the format and must never be returned as file data.
  for (uint32_t position = input.validBytes; position < kDataCapacity; ++position)
    if (input.shards[position / kShardSize][position % kShardSize] != 0)
      return LayoutError::InvalidShardBuffer;
  std::vector<uint8_t> result(input.validBytes);
  for (uint8_t i = 0; i < ErasureCodec::kData; ++i) {
    const size_t start = size_t(i) * kShardSize;
    if (start >= result.size()) break;
    const size_t take = std::min<size_t>(kShardSize, result.size() - start);
    std::copy_n(input.shards[i].data(), take, result.data() + start);
  }
  output = std::move(result);
  return LayoutError::Ok;
}

}  // namespace hf3fs::erasure
