#pragma once

#include <array>
#include <cstring>
#include <string_view>

#include "fbs/storage/Ec.h"

namespace hf3fs::storage {

inline constexpr uint32_t kEcIntegrityBlockBytes = 64u << 10;
inline constexpr size_t kEcIntegrityMaxBlocks = 16;
using EcSha256 = std::array<uint8_t, 32>;

struct EcIntegrityBlock {
  SERDE_STRUCT_FIELD(validLength, uint32_t{});
  SERDE_STRUCT_FIELD(crc32c, uint32_t{});
  SERDE_STRUCT_FIELD(sha256, EcSha256{});
};

}  // namespace hf3fs::storage

// Fixed extents are checked before reading elements. Unlike decoding through a
// vector, an attacker-supplied count cannot request a larger allocation.
template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcSha256> {
  static std::string_view serdeTo(const storage::EcSha256 &value) {
    return {reinterpret_cast<const char *>(value.data()), value.size()};
  }
  static Result<storage::EcSha256> serdeFrom(std::string_view bytes) {
    if (bytes.size() != 32) return makeError(StatusCode::kInvalidFormat, "EC SHA-256 requires 32 bytes");
    storage::EcSha256 value{};
    std::memcpy(value.data(), bytes.data(), value.size());
    return value;
  }
  static std::string serdeToReadable(const storage::EcSha256 &value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto byte : value) {
      result.push_back(hex[byte >> 4]);
      result.push_back(hex[byte & 15]);
    }
    return result;
  }
  static Result<storage::EcSha256> serdeFromReadable(std::string_view hex) {
    if (hex.size() != 64) return makeError(StatusCode::kInvalidFormat, "EC SHA-256 requires 64 hex digits");
    storage::EcSha256 result{};
    for (size_t index = 0; index != hex.size(); ++index) {
      const char ch = hex[index];
      if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
        return makeError(StatusCode::kInvalidFormat, "EC SHA-256 requires lowercase hex");
      }
      const auto value = ch <= '9' ? ch - '0' : ch - 'a' + 10;
      result[index / 2] |= static_cast<uint8_t>(value << (index % 2 == 0 ? 4 : 0));
    }
    return result;
  }
};

template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::storage::EcIntegrityBlock, hf3fs::storage::kEcIntegrityMaxBlocks>> {
  using Blocks = std::array<storage::EcIntegrityBlock, storage::kEcIntegrityMaxBlocks>;

  static void serialize(const Blocks &blocks, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &block : blocks) serde::serialize(block, out);
    }
    out.arrayEnd(blocks.size());
  }
  static Result<Void> deserialize(Blocks &blocks, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != blocks.size()) return makeError(StatusCode::kInvalidFormat, "EC integrity table requires 16 slots");
      for (auto &block : blocks) RETURN_ON_ERROR(serde::deserialize(block, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != blocks.size()) {
        return makeError(StatusCode::kInvalidFormat, "EC integrity table requires 16 slots");
      }
      auto it = std::move(container.second);
      for (auto &block : blocks) RETURN_ON_ERROR(serde::deserialize(block, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::storage {

// Content integrity only: the caller must obtain this descriptor and its root
// from an authoritative manifest. A self-consistent descriptor is not a read
// authorization or a proof that the fragment was durably sealed.
struct EcIntegrityDescriptor {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(codecId, uint16_t{1});
  SERDE_STRUCT_FIELD(matrixVersion, uint16_t{1});
  SERDE_STRUCT_FIELD(dataShards, uint16_t{10});
  SERDE_STRUCT_FIELD(parityShards, uint16_t{2});
  SERDE_STRUCT_FIELD(fieldPolynomial, uint16_t{0x11d});
  SERDE_STRUCT_FIELD(blockBytes, kEcIntegrityBlockBytes);
  SERDE_STRUCT_FIELD(wholeLength, uint32_t{});
  // Standard CRC32C, including the final complement (empty input is zero).
  // This is ~ChecksumInfo::value, not the native RPC's uncomplemented value.
  SERDE_STRUCT_FIELD(wholeCrc32c, uint32_t{});
  SERDE_STRUCT_FIELD(blockCount, uint16_t{});
  SERDE_STRUCT_FIELD(blocks, (std::array<EcIntegrityBlock, kEcIntegrityMaxBlocks>{}));
  SERDE_STRUCT_FIELD(root, EcSha256{});
};

// Format 1: systematic Cauchy 10+2 over GF(2^8), polynomial 0x11d;
// data rows are the identity, parity G[i,j] = inverse(i XOR j), i=10,11.
// Canonical hashes use big-endian integers and raw UUID bytes, independently
// of Serde. Allocation, operation and routing are deliberately not content
// inputs, so a repaired allocation retains the same expected block hashes.
Result<EcIntegrityDescriptor> computeEcIntegrity(const EcFragmentIdentity &identity, std::string_view bytes);
Result<Void> validateEcIntegrity(const EcFragmentIdentity &identity, const EcIntegrityDescriptor &descriptor);
Result<Void> verifyEcIntegrityBlock(const EcFragmentIdentity &identity,
                                    const EcIntegrityDescriptor &descriptor,
                                    uint32_t blockIndex,
                                    std::string_view bytes);

static_assert(serde::Serializable<EcIntegrityBlock>);
static_assert(serde::Serializable<EcIntegrityDescriptor>);

}  // namespace hf3fs::storage
