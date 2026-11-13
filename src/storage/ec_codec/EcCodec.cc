#include "EcCodec.h"

#include <new>

#include "chunk_engine/src/cxx.rs.h"

namespace hf3fs::storage {
namespace {

chunk_engine::EcCodecFormat rawFormat(const EcCodecFormat &format) {
  return {format.codecId, format.matrixVersion, format.dataShards, format.parityShards, format.fieldPolynomial};
}

rust::Slice<const uint8_t> bytes(std::string_view data) {
  return {reinterpret_cast<const uint8_t *>(data.data()), data.size()};
}

Result<Void> validateShape(uint64_t logicalLength, uint32_t shardBytes) {
  if (shardBytes == 0 || shardBytes > EcCodec::kMaxShardBytes || logicalLength > uint64_t(shardBytes) * 10) {
    return makeError(StatusCode::kInvalidArg, "EC requires 1..1MiB shards and logical length <= 10 * shard bytes");
  }
  return Void{};
}

Result<Void> validateSources(std::span<const EcCodecShardView> sources, size_t count, uint32_t shardBytes) {
  if (sources.size() != count) return makeError(StatusCode::kInvalidArg, "incorrect EC input shard count");
  std::array<bool, 12> seen{};
  for (const auto &source : sources) {
    if (source.index >= seen.size() || seen[source.index] || source.data.size() != shardBytes) {
      return makeError(StatusCode::kInvalidArg, "EC source indices must be distinct and in range with exact lengths");
    }
    seen[source.index] = true;
  }
  return Void{};
}

Result<Void> checkResult(const chunk_engine::EcCodecResult &result) {
  if (result.error_code != 0) {
    return makeError(result.error_code, std::string(result.error.data(), result.error.size()));
  }
  if (!result.error.empty()) return makeError(StatusCode::kFoundBug, "EC bridge returned an error on success");
  return Void{};
}

Result<EcCodec::Shards> decodeShards(const chunk_engine::EcCodecResult &result, uint32_t shardBytes) {
  RETURN_ON_ERROR(checkResult(result));
  if (result.shards.size() != 12) return makeError(StatusCode::kFoundBug, "EC bridge returned incorrect shard count");
  EcCodec::Shards output;
  for (size_t i = 0; i != output.size(); ++i) {
    const auto &shard = result.shards[i];
    if (shard.index != i || shard.data.size() != shardBytes) {
      return makeError(StatusCode::kFoundBug, "EC bridge returned incorrect shard index or size");
    }
    output[i].assign(reinterpret_cast<const char *>(shard.data.data()), shard.data.size());
  }
  return output;
}

std::array<chunk_engine::EcCodecInput, 12> rawSources(std::span<const EcCodecShardView> sources) {
  std::array<chunk_engine::EcCodecInput, 12> result{};
  for (size_t i = 0; i != sources.size(); ++i) result[i] = {sources[i].index, bytes(sources[i].data)};
  return result;
}

}  // namespace

std::string_view EcCodec::backendName() noexcept {
  const auto name = chunk_engine::ec_codec_backend();
  return {name.data(), name.size()};
}

Result<EcCodec::Shards> EcCodec::encode(std::string_view logicalData,
                                        uint32_t shardBytes,
                                        const EcCodecFormat &format) {
  try {
    RETURN_ON_ERROR(validateShape(logicalData.size(), shardBytes));
    return decodeShards(chunk_engine::ec_codec_encode(rawFormat(format), bytes(logicalData), shardBytes), shardBytes);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<Void> EcCodec::verify(std::span<const EcCodecShardView> shards,
                             uint64_t logicalLength,
                             uint32_t shardBytes,
                             const EcCodecFormat &format) {
  try {
    RETURN_ON_ERROR(validateShape(logicalLength, shardBytes));
    RETURN_ON_ERROR(validateSources(shards, 12, shardBytes));
    auto input = rawSources(shards);
    auto result =
        chunk_engine::ec_codec_verify(rawFormat(format), {input.data(), shards.size()}, logicalLength, shardBytes);
    RETURN_ON_ERROR(checkResult(result));
    if (!result.shards.empty()) return makeError(StatusCode::kFoundBug, "EC verify unexpectedly returned data");
    return Void{};
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<EcCodec::Shards> EcCodec::recover(std::span<const EcCodecShardView> sources,
                                         uint64_t logicalLength,
                                         uint32_t shardBytes,
                                         const EcCodecFormat &format) {
  try {
    RETURN_ON_ERROR(validateShape(logicalLength, shardBytes));
    RETURN_ON_ERROR(validateSources(sources, 10, shardBytes));
    auto input = rawSources(sources);
    return decodeShards(
        chunk_engine::ec_codec_recover(rawFormat(format), {input.data(), sources.size()}, logicalLength, shardBytes),
        shardBytes);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<std::vector<std::string>> EcCodec::contribute(std::span<const uint16_t> healthy,
                                                     std::span<const uint16_t> targets,
                                                     uint16_t helper,
                                                     std::string_view slice,
                                                     const EcCodecFormat &format) {
  try {
    // Validate counts before forming Rust slices or allocating output. The Rust
    // plan validates bounds, duplicates, disjointness and helper membership.
    if (healthy.size() != 10 || targets.empty() || targets.size() > 2 || slice.size() > kMaxShardBytes) {
      return makeError(StatusCode::kInvalidArg, "invalid EC contribution count or input size");
    }
    auto result = chunk_engine::ec_codec_contribute(rawFormat(format),
                                                    {healthy.data(), healthy.size()},
                                                    {targets.data(), targets.size()},
                                                    helper,
                                                    bytes(slice));
    RETURN_ON_ERROR(checkResult(result));
    if (result.shards.size() != targets.size())
      return makeError(StatusCode::kFoundBug, "EC contribution returned incorrect count");
    std::vector<std::string> output;
    output.reserve(targets.size());
    for (size_t i = 0; i != targets.size(); ++i) {
      const auto &shard = result.shards[i];
      if (shard.index != targets[i] || shard.data.size() != slice.size()) {
        return makeError(StatusCode::kFoundBug, "EC contribution returned incorrect target or size");
      }
      output.emplace_back(reinterpret_cast<const char *>(shard.data.data()), shard.data.size());
    }
    return output;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

}  // namespace hf3fs::storage
