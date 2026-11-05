#include "erasure/ECLayout.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <random>
#include <vector>

using namespace hf3fs::erasure;

namespace {

TEST(ECLayout, ConstantsRangesAndRoles) {
  EXPECT_EQ(ECLayout::kChunkSize, 4u * 1024u * 1024u);
  EXPECT_EQ(ECLayout::kShardSize, 419431u);
  EXPECT_EQ(ECLayout::kDataCapacity, ECLayout::kChunkSize + 6u);
  for (uint8_t i = 0; i < 12; ++i) {
    auto role = ECLayout::shardRole(i);
    ASSERT_TRUE(role);
    EXPECT_EQ(role.value, i < 10 ? ShardRole::Data : ShardRole::Parity);
    if (i < 10) {
      auto range = ECLayout::dataShardLogicalRange(i);
      ASSERT_TRUE(range);
      EXPECT_EQ(range.value.offset, uint32_t(i) * ECLayout::kShardSize);
      EXPECT_EQ(range.value.length, i == 9 ? ECLayout::kShardSize - 6 : ECLayout::kShardSize);
    }
  }
  EXPECT_EQ(ECLayout::shardRole(12).error, LayoutError::InvalidIndex);
  EXPECT_EQ(ECLayout::dataShardLogicalRange(10).error, LayoutError::InvalidIndex);
}

TEST(ECLayout, OffsetAndShardBoundaries) {
  const auto check = [](uint64_t offset, uint32_t chunk, uint8_t shard, uint32_t inShard) {
    auto result = ECLayout::mapOffset(offset);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value.logicalChunkIndex, chunk);
    EXPECT_EQ(result.value.stripeIndex, 0u);
    EXPECT_EQ(result.value.shardIndex, shard);
    EXPECT_EQ(result.value.offsetInShard, inShard);
  };
  check(0, 0, 0, 0);
  check(ECLayout::kShardSize - 1, 0, 0, ECLayout::kShardSize - 1);
  check(ECLayout::kShardSize, 0, 1, 0);
  check(ECLayout::kChunkSize - 1, 0, 9, ECLayout::kShardSize - 7);
  check(ECLayout::kChunkSize, 1, 0, 0);
  check(ECLayout::kMaxFileBytes - 1, UINT32_MAX, 9, ECLayout::kShardSize - 7);
  EXPECT_EQ(ECLayout::mapOffset(ECLayout::kMaxFileBytes).error, LayoutError::OutOfRange);
}

TEST(ECLayout, CrossShardAndCrossChunkSlices) {
  auto a = ECLayout::mapRange(ECLayout::kShardSize - 2, 5);
  ASSERT_TRUE(a);
  ASSERT_EQ(a.value.size(), 2u);
  EXPECT_EQ(a.value[0].shardIndex, 0);
  EXPECT_EQ(a.value[0].length, 2u);
  EXPECT_EQ(a.value[1].shardIndex, 1);
  EXPECT_EQ(a.value[1].offsetInShard, 0u);
  EXPECT_EQ(a.value[1].length, 3u);

  auto b = ECLayout::mapRange(ECLayout::kChunkSize - 3, 8);
  ASSERT_TRUE(b);
  ASSERT_EQ(b.value.size(), 2u);
  EXPECT_EQ(b.value[0].logicalChunkIndex, 0u);
  EXPECT_EQ(b.value[0].shardIndex, 9);
  EXPECT_EQ(b.value[0].length, 3u);
  EXPECT_EQ(b.value[1].logicalChunkIndex, 1u);
  EXPECT_EQ(b.value[1].shardIndex, 0);
  EXPECT_EQ(b.value[1].fileOffset, ECLayout::kChunkSize);
  EXPECT_EQ(b.value[1].length, 5u);

  auto many = ECLayout::mapRange(ECLayout::kShardSize - 1, ECLayout::kChunkSize + 9);
  ASSERT_TRUE(many);
  uint64_t expectedOffset = ECLayout::kShardSize - 1;
  uint64_t total = 0;
  for (const auto& slice : many.value) {
    EXPECT_EQ(slice.fileOffset, expectedOffset);
    auto loc = ECLayout::mapOffset(slice.fileOffset);
    ASSERT_TRUE(loc);
    EXPECT_EQ(slice.shardIndex, loc.value.shardIndex);
    expectedOffset += slice.length;
    total += slice.length;
  }
  EXPECT_EQ(total, ECLayout::kChunkSize + 9u);
  auto chunks = ECLayout::mapChunkRange(ECLayout::kChunkSize - 3, 8);
  ASSERT_TRUE(chunks);
  EXPECT_EQ(chunks.value.begin, 0u);
  EXPECT_EQ(chunks.value.endExclusive, 2u);
}

TEST(ECLayout, EmptyTailAndPadding) {
  auto empty = ECLayout::mapRange(0, 0);
  ASSERT_TRUE(empty);
  EXPECT_TRUE(empty.value.empty());
  auto emptyRange = ECLayout::mapChunkRange(0, 0);
  ASSERT_TRUE(emptyRange);
  EXPECT_EQ(emptyRange.value.begin, emptyRange.value.endExclusive);
  EXPECT_EQ(ECLayout::validBytesForChunk(0, 0).value, 0u);
  EXPECT_EQ(ECLayout::validBytesForChunk(ECLayout::kChunkSize + 17, 0).value, ECLayout::kChunkSize);
  EXPECT_EQ(ECLayout::validBytesForChunk(ECLayout::kChunkSize + 17, 1).value, 17u);
  EXPECT_EQ(ECLayout::validBytesForChunk(ECLayout::kChunkSize + 17, 2).value, 0u);
  EXPECT_EQ(ECLayout::zeroPadding(ECLayout::kChunkSize).value, 6u);
  EXPECT_EQ(ECLayout::zeroPadding(17).value, ECLayout::kDataCapacity - 17u);
  EXPECT_EQ(ECLayout::zeroPadding(ECLayout::kChunkSize + 1).error, LayoutError::InvalidLength);
}

TEST(ECLayout, InvalidRangesAndOverflow) {
  EXPECT_EQ(ECLayout::mapChunkRange(UINT64_MAX - 1, 8).error, LayoutError::Overflow);
  EXPECT_EQ(ECLayout::mapChunkRange(ECLayout::kMaxFileBytes, 1).error, LayoutError::OutOfRange);
  EXPECT_EQ(ECLayout::mapRange(ECLayout::kMaxFileBytes, 1).error, LayoutError::OutOfRange);
  auto end = ECLayout::mapChunkRange(ECLayout::kMaxFileBytes - 1, 1);
  ASSERT_TRUE(end);
  EXPECT_EQ(end.value.endExclusive, uint64_t{1} << 32);
  auto empty = ECLayout::mapChunkRange(ECLayout::kMaxFileBytes, 0);
  ASSERT_TRUE(empty);
  EXPECT_EQ(empty.value.begin, uint64_t{1} << 32);
  EXPECT_EQ(ECLayout::validBytesForChunk(ECLayout::kMaxFileBytes + 1, 0).error,
            LayoutError::OutOfRange);
  EXPECT_EQ(ECLayout::mapRange(0, uint64_t(ECLayout::kMaxSlicesPerCall + 1) * ECLayout::kChunkSize)
                .error, LayoutError::TooManySegments);
}

TEST(ECLayout, StaticTwelveTargetMapping) {
  ECStaticPlacement placement;
  for (uint8_t i = 0; i < 12; ++i) placement.targetIds[i] = 500 + i;
  ASSERT_EQ(placement.validate(), LayoutError::Ok);
  for (uint8_t i = 0; i < 12; ++i) {
    auto target = placement.targetForShard(i);
    ASSERT_TRUE(target);
    EXPECT_EQ(target.value, 500u + i);
  }
  EXPECT_EQ(placement.targetForShard(12).error, LayoutError::InvalidIndex);
  placement.targetIds[11] = placement.targetIds[0];
  EXPECT_EQ(placement.validate(), LayoutError::InvalidPlacement);
  EXPECT_EQ(placement.targetForShard(1).error, LayoutError::InvalidPlacement);
  placement.targetIds[11] = 0;
  EXPECT_EQ(placement.validate(), LayoutError::InvalidPlacement);
}

TEST(ECLayout, ShardKeyIdentity) {
  ECShardKey a{100, 7, 0, 0};
  EXPECT_EQ(ECLayout::validateKey(a), LayoutError::Ok);
  EXPECT_FALSE((a == ECShardKey{101, 7, 0, 0}));
  EXPECT_FALSE((a == ECShardKey{100, 8, 0, 0}));
  EXPECT_FALSE((a == ECShardKey{100, 7, 0, 1}));
  EXPECT_EQ(ECLayout::validateKey({100, 7, 1, 0}), LayoutError::InvalidStripe);
  EXPECT_EQ(ECLayout::validateKey({100, 7, 0, 12}), LayoutError::InvalidIndex);
}

void recoverAndCompare(ECStripeBuffers original, std::vector<uint8_t> erased,
                       const std::vector<uint8_t>& input, const ErasureCodec& codec) {
  ECStripeBuffers actual = original;
  std::vector<ConstShard> available;
  std::vector<MutableShard> missing;
  for (uint8_t i = 0; i < 12; ++i) {
    if (std::find(erased.begin(), erased.end(), i) == erased.end())
      available.push_back({i, actual.shards[i]});
    else {
      std::fill(actual.shards[i].begin(), actual.shards[i].end(), 0xa5);
      missing.push_back({i, actual.shards[i]});
    }
  }
  std::reverse(available.begin(), available.end());
  ASSERT_EQ(codec.reconstruct(available, missing), CodecError::Ok);
  for (uint8_t i = 0; i < 12; ++i) EXPECT_EQ(actual.shards[i], original.shards[i]) << int(i);
  std::vector<uint8_t> decoded;
  ASSERT_EQ(ECLayout::reassemble(actual, decoded), LayoutError::Ok);
  EXPECT_EQ(decoded, input);
}

TEST(ECLayout, FullChunkEncodeAndReassemble) {
  ErasureCodec codec;
  std::vector<uint8_t> input(ECLayout::kChunkSize);
  for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<uint8_t>(i * 131u + 7u);
  ECStripeBuffers stripe;
  ASSERT_EQ(ECLayout::splitAndEncode(input, codec, stripe), LayoutError::Ok);
  EXPECT_EQ(stripe.validBytes, ECLayout::kChunkSize);
  for (const auto& shard : stripe.shards) EXPECT_EQ(shard.size(), ECLayout::kShardSize);
  for (size_t pos = ECLayout::kChunkSize; pos < ECLayout::kDataCapacity; ++pos)
    EXPECT_EQ(stripe.shards[pos / ECLayout::kShardSize][pos % ECLayout::kShardSize], 0);
  std::vector<uint8_t> decoded;
  ASSERT_EQ(ECLayout::reassemble(stripe, decoded), LayoutError::Ok);
  EXPECT_EQ(decoded, input);
  recoverAndCompare(stripe, {3}, input, codec);
  recoverAndCompare(stripe, {4, 11}, input, codec);
}

TEST(ECLayout, EmptyAndNonAlignedTailRoundTrips) {
  ErasureCodec codec;
  for (size_t len : {size_t(0), size_t(1), size_t(17), size_t(ECLayout::kShardSize - 1),
                     size_t(ECLayout::kShardSize + 3), size_t(ECLayout::kChunkSize - 1)}) {
    std::vector<uint8_t> input(len);
    for (size_t i = 0; i < len; ++i) input[i] = static_cast<uint8_t>(i * 7 + 3);
    ECStripeBuffers stripe;
    ASSERT_EQ(ECLayout::splitAndEncode(input, codec, stripe), LayoutError::Ok);
    EXPECT_EQ(stripe.validBytes, len);
    std::vector<uint8_t> decoded;
    ASSERT_EQ(ECLayout::reassemble(stripe, decoded), LayoutError::Ok);
    EXPECT_EQ(decoded, input);
    recoverAndCompare(stripe, {0, 10}, input, codec);
  }
}

TEST(ECLayout, RandomRoundTripAndTwoLosses) {
  ErasureCodec codec;
  std::mt19937 rng(0x8b102);
  for (uint32_t round = 0; round < 4; ++round) {
    const size_t len = (round * 1031 + ECLayout::kShardSize + 19) % ECLayout::kChunkSize;
    std::vector<uint8_t> input(len);
    for (auto& byte : input) byte = static_cast<uint8_t>(rng());
    ECStripeBuffers stripe;
    ASSERT_EQ(ECLayout::splitAndEncode(input, codec, stripe), LayoutError::Ok);
    std::vector<uint8_t> decoded;
    ASSERT_EQ(ECLayout::reassemble(stripe, decoded), LayoutError::Ok);
    EXPECT_EQ(decoded, input);
    recoverAndCompare(stripe, {static_cast<uint8_t>(round),
                               static_cast<uint8_t>(11 - round)}, input, codec);
  }
}

TEST(ECLayout, RejectsMalformedBuffersWithoutChangingOutput) {
  ErasureCodec codec;
  ECStripeBuffers stripe;
  std::vector<uint8_t> input(19, 0x51);
  ASSERT_EQ(ECLayout::splitAndEncode(input, codec, stripe), LayoutError::Ok);
  std::vector<uint8_t> output{0x44, 0x55};
  stripe.shards[0].resize(1);
  EXPECT_EQ(ECLayout::reassemble(stripe, output), LayoutError::InvalidShardBuffer);
  EXPECT_EQ(output, (std::vector<uint8_t>{0x44, 0x55}));
  stripe.shards[0].resize(ECLayout::kShardSize, 0);
  stripe.encodingScheme = 9;
  EXPECT_EQ(ECLayout::reassemble(stripe, output), LayoutError::InvalidFormat);
  stripe.encodingScheme = ECLayout::kEncodingScheme;
  stripe.validBytes = ECLayout::kChunkSize + 1;
  EXPECT_EQ(ECLayout::reassemble(stripe, output), LayoutError::InvalidLength);
  stripe.validBytes = 19;
  stripe.shards[9].back() = 1;
  EXPECT_EQ(ECLayout::reassemble(stripe, output), LayoutError::InvalidShardBuffer);
  EXPECT_EQ(output, (std::vector<uint8_t>{0x44, 0x55}));
  std::vector<uint8_t> tooLong(ECLayout::kChunkSize + 1, 1);
  EXPECT_EQ(ECLayout::splitAndEncode(tooLong, codec, stripe), LayoutError::InvalidLength);
  EXPECT_EQ(stripe.validBytes, 19u);
}

}  // namespace
