#include "erasure/ErasureCodec.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <random>
#include <thread>
#include <vector>

using hf3fs::erasure::CodecError;
using hf3fs::erasure::ConstShard;
using hf3fs::erasure::ErasureCodec;
using hf3fs::erasure::MutableShard;

namespace {
using Shards = std::array<std::vector<uint8_t>, 12>;

Shards makeShards(size_t len, uint32_t seed = 7) {
  Shards shards;
  std::mt19937 rng(seed);
  for (size_t i = 0; i < 10; ++i) {
    shards[i].resize(len);
    for (auto& byte : shards[i]) byte = static_cast<uint8_t>(rng());
  }
  shards[10].resize(len);
  shards[11].resize(len);
  return shards;
}

CodecError encode(ErasureCodec& codec, Shards& shards, bool reverse = false) {
  std::vector<ConstShard> data;
  std::vector<MutableShard> parity;
  for (size_t i = 0; i < 10; ++i) data.push_back({static_cast<uint8_t>(i), shards[i]});
  for (size_t i = 10; i < 12; ++i) parity.push_back({static_cast<uint8_t>(i), shards[i]});
  if (reverse) { std::reverse(data.begin(), data.end()); std::reverse(parity.begin(), parity.end()); }
  return codec.encode(data, parity);
}

void recoverAndCheck(ErasureCodec& codec, const Shards& original,
                     std::vector<uint8_t> erased) {
  Shards actual = original;
  std::vector<ConstShard> available;
  std::vector<MutableShard> missing;
  for (size_t i = 0; i < 12; ++i) {
    if (std::find(erased.begin(), erased.end(), i) == erased.end())
      available.push_back({static_cast<uint8_t>(i), actual[i]});
    else {
      std::fill(actual[i].begin(), actual[i].end(), 0xa5);
      missing.push_back({static_cast<uint8_t>(i), actual[i]});
    }
  }
  std::reverse(available.begin(), available.end());
  std::reverse(missing.begin(), missing.end());
  ASSERT_EQ(codec.reconstruct(available, missing), CodecError::Ok);
  for (size_t i = 0; i < 12; ++i) EXPECT_EQ(actual[i], original[i]) << "shard " << i;
  Shards reencoded = actual;
  ASSERT_EQ(encode(codec, reencoded), CodecError::Ok);
  EXPECT_EQ(reencoded[10], original[10]);
  EXPECT_EQ(reencoded[11], original[11]);
}

TEST(ErasureCodec, GoldenVectorFromIndependentScalarGF256) {
  // Independently computed with polynomial 0x11d, Cauchy coefficients
  // inv_GF256(row XOR col), and data[i][j]=(17*i+29*j+3)&255.
  ErasureCodec codec;
  Shards shards;
  for (size_t i = 0; i < 10; ++i) {
    shards[i].resize(8);
    for (size_t j = 0; j < 8; ++j) shards[i][j] = (17*i + 29*j + 3) & 255;
  }
  shards[10].resize(8);
  shards[11].resize(8);
  const Shards before = shards;
  ASSERT_EQ(encode(codec, shards, true), CodecError::Ok);
  EXPECT_EQ(shards[10], (std::vector<uint8_t>{0x57,0x18,0x78,0xa9,0x21,0x0a,0xaa,0x21}));
  EXPECT_EQ(shards[11], (std::vector<uint8_t>{0x1a,0x12,0x5e,0x44,0xe3,0x5c,0x68,0x46}));
  for (size_t i = 0; i < 10; ++i) EXPECT_EQ(shards[i], before[i]);
}

TEST(ErasureCodec, AllTwelveSingleErasures) {
  ErasureCodec codec;
  Shards shards = makeShards(257);
  ASSERT_EQ(encode(codec, shards), CodecError::Ok);
  for (uint8_t i = 0; i < 12; ++i) {
    SCOPED_TRACE(static_cast<int>(i));
    recoverAndCheck(codec, shards, {i});
  }
}

TEST(ErasureCodec, AllSixtySixDoubleErasures) {
  ErasureCodec codec;
  Shards shards = makeShards(259);
  ASSERT_EQ(encode(codec, shards), CodecError::Ok);
  for (uint8_t i = 0; i < 12; ++i)
    for (uint8_t j = i+1; j < 12; ++j) {
      SCOPED_TRACE(::testing::Message() << int(i) << "," << int(j));
      recoverAndCheck(codec, shards, {i,j});
    }
}

TEST(ErasureCodec, EmptyOneUnalignedZeroAndOnes) {
  ErasureCodec codec;
  for (size_t len : {size_t(0),size_t(1),size_t(3),size_t(31)}) {
    for (uint8_t pattern : {uint8_t(0),uint8_t(0xff)}) {
      Shards shards;
      for (auto& shard : shards) shard.assign(len, pattern);
      ASSERT_EQ(encode(codec, shards), CodecError::Ok);
      recoverAndCheck(codec, shards, {0,11});
    }
  }
}

TEST(ErasureCodec, FixedSeedRandomRounds) {
  ErasureCodec codec;
  for (uint32_t seed = 0; seed < 12; ++seed) {
    Shards shards = makeShards(seed * 37 + 1, 901 + seed);
    ASSERT_EQ(encode(codec, shards), CodecError::Ok);
    for (uint8_t i = 0; i < 12; ++i) recoverAndCheck(codec, shards, {i});
    for (uint8_t i = 0; i < 12; ++i)
      for (uint8_t j = i+1; j < 12; ++j) recoverAndCheck(codec, shards, {i,j});
  }
}

TEST(ErasureCodec, ElevenAvailableAndOneRequested) {
  ErasureCodec codec;
  Shards original = makeShards(123);
  ASSERT_EQ(encode(codec, original), CodecError::Ok);
  Shards actual = original;
  std::fill(actual[4].begin(), actual[4].end(), 0);
  std::vector<ConstShard> available;
  for (uint8_t i = 0; i < 12; ++i)
    if (i != 4) available.push_back({i, actual[i]});
  std::array<MutableShard, 1> missing{{{4, actual[4]}}};
  ASSERT_EQ(codec.reconstruct(available, missing), CodecError::Ok);
  EXPECT_EQ(actual, original);
}

TEST(ErasureCodec, InvalidEncodeParametersLeaveOutputsUntouched) {
  ErasureCodec codec;
  Shards shards = makeShards(16);
  std::vector<ConstShard> data;
  std::vector<MutableShard> parity;
  for (int i=0;i<10;++i) data.push_back({static_cast<uint8_t>(i),shards[i]});
  for (int i=10;i<12;++i) parity.push_back({static_cast<uint8_t>(i),shards[i]});
  auto check = [&](CodecError expected) {
    const auto before10=shards[10], before11=shards[11];
    EXPECT_EQ(codec.encode(data,parity),expected);
    EXPECT_EQ(shards[10],before10); EXPECT_EQ(shards[11],before11);
  };
  EXPECT_EQ(codec.encode(std::span(data).first(9),parity),CodecError::WrongShardCount);
  EXPECT_EQ(codec.encode(data,std::span(parity).first(1)),CodecError::WrongShardCount);
  data[0].index=12; check(CodecError::InvalidIndex); data[0].index=0;
  data[1].index=0; check(CodecError::DuplicateIndex); data[1].index=1;
  parity[0].index=9; check(CodecError::InvalidIndex); parity[0].index=10;
  parity[1].index=10; check(CodecError::DuplicateIndex); parity[1].index=11;
  data[0].bytes=data[0].bytes.first(15); check(CodecError::SizeMismatch); data[0].bytes=shards[0];
  parity[0].bytes=parity[0].bytes.first(15); check(CodecError::SizeMismatch); parity[0].bytes=shards[10];
  parity[0].bytes=shards[0]; check(CodecError::BufferOverlap); parity[0].bytes=shards[10];
  parity[1].bytes=shards[10]; check(CodecError::BufferOverlap); parity[1].bytes=shards[11];
  data[1].bytes=shards[0]; check(CodecError::BufferOverlap); data[1].bytes=shards[1];
}

TEST(ErasureCodec, InvalidReconstructionLeavesOutputUntouched) {
  ErasureCodec codec;
  Shards shards=makeShards(16);
  ASSERT_EQ(encode(codec,shards),CodecError::Ok);
  std::vector<ConstShard> available;
  for (int i=0;i<10;++i) available.push_back({static_cast<uint8_t>(i),shards[i]});
  std::vector<MutableShard> missing{{10,shards[10]},{11,shards[11]}};
  auto check=[&](CodecError error) {
    const auto a=shards[10],b=shards[11];
    EXPECT_EQ(codec.reconstruct(available,missing),error);
    EXPECT_EQ(shards[10],a); EXPECT_EQ(shards[11],b);
  };
  check(CodecError::Ok);
  EXPECT_EQ(codec.reconstruct(available,{}),CodecError::WrongShardCount);
  std::array<MutableShard, 3> tooMany{{missing[0], missing[1], {9, shards[9]}}};
  EXPECT_EQ(codec.reconstruct(available, tooMany), CodecError::WrongShardCount);
  EXPECT_EQ(codec.reconstruct(std::span(available).first(9),missing),CodecError::InsufficientShards);
  missing[0].index=12; check(CodecError::InvalidIndex); missing[0].index=10;
  missing[1].index=10; check(CodecError::DuplicateIndex); missing[1].index=11;
  missing[0].index=0; check(CodecError::DuplicateIndex); missing[0].index=10;
  available[0].index=12; check(CodecError::InvalidIndex); available[0].index=0;
  available[1].index=0; check(CodecError::DuplicateIndex); available[1].index=1;
  missing[0].bytes=missing[0].bytes.first(15); check(CodecError::SizeMismatch); missing[0].bytes=shards[10];
  available[0].bytes=available[0].bytes.first(15); check(CodecError::SizeMismatch); available[0].bytes=shards[0];
  missing[0].bytes=shards[0]; check(CodecError::BufferOverlap); missing[0].bytes=shards[10];
  missing[1].bytes=shards[10]; check(CodecError::BufferOverlap); missing[1].bytes=shards[11];
}

TEST(ErasureCodec, SharedInstanceAcrossThreads) {
  ErasureCodec codec;
  std::array<bool,8> ok{};
  std::vector<std::thread> workers;
  for (size_t t=0;t<ok.size();++t) workers.emplace_back([&,t] {
    Shards shards=makeShards(1024,t+42);
    if (encode(codec,shards)!=CodecError::Ok) return;
    Shards actual=shards;
    std::fill(actual[t].begin(),actual[t].end(),0);
    std::fill(actual[11].begin(),actual[11].end(),0);
    std::vector<ConstShard> available;
    for (size_t i=0;i<12;++i) if (i!=t && i!=11) available.push_back({static_cast<uint8_t>(i),actual[i]});
    std::array<MutableShard,2> missing{{{static_cast<uint8_t>(t),actual[t]},{11,actual[11]}}};
    ok[t]=codec.reconstruct(available,missing)==CodecError::Ok && actual==shards;
  });
  for (auto& worker:workers) worker.join();
  for (bool result:ok) EXPECT_TRUE(result);
}


// Scalar reference uses no ISA-L function or ErasureCodec matrix/table.
uint8_t scalarMultiply(uint8_t a, uint8_t b) {
  uint8_t result = 0;
  while (b != 0) {
    if (b & 1) result ^= a;
    const bool high = (a & 0x80) != 0;
    a = static_cast<uint8_t>(a << 1);
    if (high) a ^= 0x1d;
    b >>= 1;
  }
  return result;
}

uint8_t scalarInverse(uint8_t a) {
  for (int candidate = 1; candidate < 256; ++candidate)
    if (scalarMultiply(a, static_cast<uint8_t>(candidate)) == 1)
      return static_cast<uint8_t>(candidate);
  return 0;
}

TEST(ErasureCodec, IndependentParityAcrossDifferentLengths) {
  ErasureCodec codec;
  for (size_t len : {size_t(1), size_t(7), size_t(33), size_t(257), size_t(4097)}) {
    Shards shards = makeShards(len, static_cast<uint32_t>(len + 901));
    const Shards dataBefore = shards;
    ASSERT_EQ(encode(codec, shards, true), CodecError::Ok);
    for (size_t row = 10; row < 12; ++row)
      for (size_t offset = 0; offset < len; ++offset) {
        uint8_t expected = 0;
        for (size_t col = 0; col < 10; ++col)
          expected ^= scalarMultiply(scalarInverse(static_cast<uint8_t>(row ^ col)),
                                     dataBefore[col][offset]);
        ASSERT_EQ(shards[row][offset], expected) << "len=" << len << " parity=" << row
                                                 << " offset=" << offset;
      }
    for (size_t i = 0; i < 10; ++i) EXPECT_EQ(shards[i], dataBefore[i]);
  }
}

TEST(ErasureCodec, RandomAvailableOrderRepeatedReconstructionAndCanaries) {
  ErasureCodec codec;
  constexpr size_t len = 65;
  std::array<std::vector<uint8_t>,12> guarded;
  for (size_t i = 0; i < 12; ++i) guarded[i].assign(len + 2, 0xc3);
  std::mt19937 rng(0x7c012);
  for (size_t i = 0; i < 10; ++i)
    for (size_t j = 1; j <= len; ++j) guarded[i][j] = static_cast<uint8_t>(rng());
  auto view = [&](size_t i) { return std::span<uint8_t>(guarded[i].data() + 1, len); };
  std::vector<ConstShard> data;
  std::vector<MutableShard> parity;
  for (uint8_t i = 0; i < 10; ++i) data.push_back({i, view(i)});
  for (uint8_t i = 10; i < 12; ++i) parity.push_back({i, view(i)});
  ASSERT_EQ(codec.encode(data, parity), CodecError::Ok);
  const auto original = guarded;
  for (const std::array<uint8_t,2> erased : {std::array<uint8_t,2>{2,11}, {4,7}, {10,11}}) {
    for (uint8_t index : erased) std::fill(view(index).begin(), view(index).end(), 0xee);
    std::vector<ConstShard> available;
    for (uint8_t i = 0; i < 12; ++i)
      if (i != erased[0] && i != erased[1]) available.push_back({i, view(i)});
    std::shuffle(available.begin(), available.end(), rng);
    std::array<MutableShard,2> missing{{{erased[1],view(erased[1])},
                                         {erased[0],view(erased[0])}}};
    ASSERT_EQ(codec.reconstruct(available, missing), CodecError::Ok);
    EXPECT_EQ(guarded, original);
  }
}

}  // namespace
