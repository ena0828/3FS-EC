#include <array>
#include <cstdint>
#include <dlfcn.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "chunk_engine/src/cxx.rs.h"

namespace {
using Block = std::vector<uint8_t>;

void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

// Independent polynomial convolution and long division, rather than the
// production codec's repeated shift-and-add multiplication.
uint8_t multiply(uint8_t a, uint8_t b) {
  uint16_t product = 0;
  for (unsigned bit = 0; bit < 8; ++bit) {
    if (b & (1u << bit)) product ^= uint16_t(a) << bit;
  }
  for (int bit = 14; bit >= 8; --bit) {
    if (product & (1u << bit)) product ^= uint16_t(0x11d) << (bit - 8);
  }
  return uint8_t(product);
}

uint8_t inverse(uint8_t value) {
  for (unsigned candidate = 1; candidate <= 255; ++candidate) {
    if (multiply(value, uint8_t(candidate)) == 1) return uint8_t(candidate);
  }
  throw std::runtime_error("zero coefficient has no inverse");
}

void checkShards(const chunk_engine::EcCodecResult &result, const std::array<Block, 12> &expected) {
  require(result.error_code == 0 && result.error.empty(), "bridge returned an error");
  require(result.shards.size() == expected.size(), "wrong shard count");
  for (size_t shard = 0; shard < expected.size(); ++shard) {
    require(result.shards[shard].index == shard, "wrong shard order");
    const auto &actual = result.shards[shard].data;
    require(Block(actual.begin(), actual.end()) == expected[shard], "oracle mismatch");
  }
}
}  // namespace

int main(int argc, char **argv) {
  try {
    require(argc >= 2, "specify expected scalar or isal backend");
    const std::string expectedBackend = argv[1];
    require(expectedBackend == "scalar" || expectedBackend == "isal", "unknown backend");
    require(argc == (expectedBackend == "isal" ? 3 : 2), "unexpected provider arguments");
    const auto name = chunk_engine::ec_codec_backend();
    const std::string backend(name.data(), name.size());
    require(backend == expectedBackend, "linked Rust backend differs from configuration");
    const auto symbol = dlsym(RTLD_DEFAULT, "ec_encode_data");
    std::string provider;
    if (backend == "isal") {
      require(symbol != nullptr, "ISA-L dispatcher is not dynamically linked");
      Dl_info info{};
      require(dladdr(symbol, &info) != 0 && info.dli_fname, "cannot resolve ISA-L provider");
      provider = std::filesystem::canonical(info.dli_fname).string();
      require(provider == std::filesystem::canonical(argv[2]).string(), "unexpected ISA-L provider");
    } else {
      require(symbol == nullptr, "Scalar probe unexpectedly links ISA-L");
    }

    constexpr size_t size = 257;
    const chunk_engine::EcCodecFormat format{1, 1, 10, 2, 0x11d};
    Block logical(10 * size - 3);
    for (size_t i = 0; i < logical.size(); ++i) logical[i] = uint8_t(i * 31 + 7);
    std::array<Block, 12> expected;
    for (auto &block : expected) block.resize(size, 0);
    for (size_t i = 0; i < logical.size(); ++i) expected[i / size][i % size] = logical[i];
    for (size_t parity = 10; parity < 12; ++parity) {
      for (size_t data = 0; data < 10; ++data) {
        const auto coefficient = inverse(uint8_t(parity ^ data));
        for (size_t offset = 0; offset < size; ++offset) {
          expected[parity][offset] ^= multiply(coefficient, expected[data][offset]);
        }
      }
    }
    checkShards(chunk_engine::ec_codec_encode(format, {logical.data(), logical.size()}, size), expected);
    std::array<chunk_engine::EcCodecInput, 12> inputs{};
    for (size_t i = 0; i < inputs.size(); ++i) inputs[i] = {uint16_t(i), {expected[i].data(), size}};
    const auto verified = chunk_engine::ec_codec_verify(format, {inputs.data(), inputs.size()}, logical.size(), size);
    require(verified.error_code == 0 && verified.error.empty() && verified.shards.empty(), "verify failed");

    const std::array<uint16_t, 10> healthy{10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    std::array<chunk_engine::EcCodecInput, 10> sources{};
    for (size_t i = 0; i < sources.size(); ++i) sources[i] = inputs[healthy[i]];
    checkShards(chunk_engine::ec_codec_recover(format, {sources.data(), sources.size()}, logical.size(), size), expected);
    const std::array<uint16_t, 2> targets{11, 0};
    std::array<Block, 2> sums{Block(size, 0), Block(size, 0)};
    for (auto helper : healthy) {
      const auto contribution = chunk_engine::ec_codec_contribute(
          format, {healthy.data(), healthy.size()}, {targets.data(), targets.size()},
          helper, {expected[helper].data(), size});
      require(contribution.error_code == 0 && contribution.error.empty(), "contribution failed");
      require(contribution.shards.size() == 2, "wrong contribution count");
      for (size_t row = 0; row < sums.size(); ++row) {
        require(contribution.shards[row].index == targets[row], "wrong contribution order");
        require(contribution.shards[row].data.size() == size, "wrong contribution length");
        for (size_t offset = 0; offset < size; ++offset) sums[row][offset] ^= contribution.shards[row].data[offset];
      }
    }
    require(sums[0] == expected[11] && sums[1] == expected[0], "contribution oracle mismatch");

    expected[9].back() = 1;
    const auto corrupt = chunk_engine::ec_codec_verify(format, {inputs.data(), inputs.size()}, logical.size(), size);
    require(corrupt.error_code == 2 && corrupt.shards.empty(), "nonzero padding was accepted");
    auto invalidFormat = format;
    invalidFormat.matrix_version = 2;
    const auto invalid = chunk_engine::ec_codec_encode(invalidFormat, {logical.data(), logical.size()}, size);
    require(invalid.error_code == 3 && invalid.shards.empty(), "unsupported format was accepted");
    std::cout << "{\"ec_cxx_probe\":\"passed\",\"backend\":" << std::quoted(backend)
              << ",\"provider\":" << std::quoted(provider)
              << ",\"shard_bytes\":257,\"logical_bytes\":" << logical.size()
              << ",\"oracle\":\"polynomial-convolution-long-division\"}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "EC CXX probe failed: " << error.what() << '\n';
    return 1;
  }
}
