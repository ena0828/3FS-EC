#include "erasure/ErasureCodec.h"

#include <isa-l/erasure_code.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace hf3fs::erasure {
namespace {

struct Interval {
  uintptr_t begin;
  uintptr_t end;
};

template <typename Byte>
CodecError addInterval(std::span<Byte> bytes, std::vector<Interval>& intervals) {
  if (bytes.empty()) return CodecError::Ok;
  if (bytes.data() == nullptr) return CodecError::InvalidBuffer;
  const auto begin = reinterpret_cast<uintptr_t>(bytes.data());
  if (bytes.size() > std::numeric_limits<uintptr_t>::max() - begin)
    return CodecError::InvalidBuffer;
  intervals.push_back({begin, begin + bytes.size()});
  return CodecError::Ok;
}

CodecError checkIntervals(std::vector<Interval>& intervals) {
  std::sort(intervals.begin(), intervals.end(),
            [](const Interval& a, const Interval& b) { return a.begin < b.begin; });
  for (size_t i = 1; i < intervals.size(); ++i)
    if (intervals[i].begin < intervals[i - 1].end) return CodecError::BufferOverlap;
  return CodecError::Ok;
}

}  // namespace

ErasureCodec::ErasureCodec() {
  gf_gen_cauchy1_matrix(matrix_, kTotal, kData);
  ec_init_tables(kData, kParity, matrix_ + kData * kData, encodeTables_);
}

CodecError ErasureCodec::encode(std::span<const ConstShard> data,
                               std::span<MutableShard> parity) const {
  if (data.size() != kData || parity.size() != kParity) return CodecError::WrongShardCount;
  std::array<uint8_t*, kData> input{};
  std::array<uint8_t*, kParity> output{};
  std::array<bool, kTotal> seen{};
  std::vector<Interval> intervals;
  intervals.reserve(kTotal);
  const size_t len = data[0].bytes.size();
  if (len > static_cast<size_t>(std::numeric_limits<int>::max())) return CodecError::SizeOverflow;
  for (const auto& shard : data) {
    if (shard.index >= kTotal) return CodecError::InvalidIndex;
    if (shard.index >= kData) return CodecError::InvalidIndex;
    if (seen[shard.index]) return CodecError::DuplicateIndex;
    seen[shard.index] = true;
    if (shard.bytes.size() != len) return CodecError::SizeMismatch;
    if (auto e = addInterval(shard.bytes, intervals); e != CodecError::Ok) return e;
    input[shard.index] = const_cast<uint8_t*>(shard.bytes.data());
  }
  for (const auto& shard : parity) {
    if (shard.index >= kTotal || shard.index < kData) return CodecError::InvalidIndex;
    if (seen[shard.index]) return CodecError::DuplicateIndex;
    seen[shard.index] = true;
    if (shard.bytes.size() != len) return CodecError::SizeMismatch;
    if (auto e = addInterval(shard.bytes, intervals); e != CodecError::Ok) return e;
    output[shard.index - kData] = shard.bytes.data();
  }
  if (auto e = checkIntervals(intervals); e != CodecError::Ok) return e;
  if (len == 0) return CodecError::Ok;
  // ISA-L declares its table pointer mutable; pass a per-call copy so a
  // const codec instance never exposes shared state through that C API.
  std::array<uint8_t, 32 * kData * kParity> tables{};
  std::copy_n(encodeTables_, tables.size(), tables.data());
  ec_encode_data(static_cast<int>(len), kData, kParity,
                 tables.data(), input.data(), output.data());
  return CodecError::Ok;
}

CodecError ErasureCodec::reconstruct(std::span<const ConstShard> available,
                                    std::span<MutableShard> missing) const {
  if (missing.empty() || missing.size() > kParity || available.size() > kTotal)
    return CodecError::WrongShardCount;
  if (available.size() < kData) return CodecError::InsufficientShards;
  if (available.size() + missing.size() > kTotal) return CodecError::WrongShardCount;

  std::array<const uint8_t*, kTotal> byIndex{};
  std::array<bool, kTotal> seen{};
  std::vector<Interval> intervals;
  intervals.reserve(available.size() + missing.size());
  const size_t len = available[0].bytes.size();
  if (len > static_cast<size_t>(std::numeric_limits<int>::max())) return CodecError::SizeOverflow;
  for (const auto& shard : available) {
    if (shard.index >= kTotal) return CodecError::InvalidIndex;
    if (seen[shard.index]) return CodecError::DuplicateIndex;
    seen[shard.index] = true;
    if (shard.bytes.size() != len) return CodecError::SizeMismatch;
    if (auto e = addInterval(shard.bytes, intervals); e != CodecError::Ok) return e;
    byIndex[shard.index] = shard.bytes.data();
  }
  for (const auto& shard : missing) {
    if (shard.index >= kTotal) return CodecError::InvalidIndex;
    if (seen[shard.index]) return CodecError::DuplicateIndex;
    seen[shard.index] = true;
    if (shard.bytes.size() != len) return CodecError::SizeMismatch;
    if (auto e = addInterval(shard.bytes, intervals); e != CodecError::Ok) return e;
  }
  if (auto e = checkIntervals(intervals); e != CodecError::Ok) return e;
  if (len == 0) return CodecError::Ok;

  std::array<uint8_t, kData * kData> selected{};
  std::array<uint8_t, kData * kData> inverse{};
  std::array<uint8_t*, kData> input{};
  size_t n = 0;
  for (size_t i = 0; i < kTotal && n < kData; ++i) {
    if (byIndex[i] == nullptr) continue;
    std::copy_n(matrix_ + i * kData, kData, selected.data() + n * kData);
    input[n] = const_cast<uint8_t*>(byIndex[i]);
    ++n;
  }
  if (gf_invert_matrix(selected.data(), inverse.data(), kData) != 0)
    return CodecError::SingularMatrix;

  std::array<uint8_t, kParity * kData> coefficients{};
  for (size_t row = 0; row < missing.size(); ++row) {
    for (size_t col = 0; col < kData; ++col) {
      uint8_t value = 0;
      for (size_t j = 0; j < kData; ++j)
        value ^= gf_mul(matrix_[missing[row].index * kData + j], inverse[j * kData + col]);
      coefficients[row * kData + col] = value;
    }
  }
  std::array<uint8_t, 32 * kData * kParity> tables{};
  ec_init_tables(kData, static_cast<int>(missing.size()), coefficients.data(), tables.data());
  std::array<uint8_t*, kParity> output{};
  for (size_t i = 0; i < missing.size(); ++i) output[i] = missing[i].bytes.data();
  ec_encode_data(static_cast<int>(len), kData, static_cast<int>(missing.size()),
                 tables.data(), input.data(), output.data());
  return CodecError::Ok;
}

}  // namespace hf3fs::erasure
