#include <algorithm>
#include <limits>

#include "storage/ec_codec/EcCodec.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {

std::string codecPattern(size_t length) {
  std::string bytes(length, '\0');
  for (size_t i = 0; i != length; ++i) bytes[i] = static_cast<char>((i * 29 + i / 251 + 7) % 256);
  return bytes;
}

std::vector<EcCodecShardView> views(const EcCodec::Shards &shards) {
  std::vector<EcCodecShardView> result;
  for (uint16_t i = 0; i != shards.size(); ++i) result.push_back({i, shards[i]});
  return result;
}

TEST(TestEcCodec, IndependentGoldenVectorEmptyInputAndOwnedOutput) {
  // Independent carryless polynomial multiplication/long division over 0x11d,
  // inverses by exhaustive search: data bytes 1..10 give parity 53 and 170.
  std::string data;
  for (uint8_t i = 1; i <= 10; ++i) data.push_back(static_cast<char>(i));
  auto result = EcCodec::encode(data, 1);
  ASSERT_OK(result);
  for (size_t i = 0; i != 10; ++i) ASSERT_EQ((*result)[i], data.substr(i, 1));
  ASSERT_EQ(static_cast<uint8_t>((*result)[10][0]), 53);
  ASSERT_EQ(static_cast<uint8_t>((*result)[11][0]), 170);
  data.assign(10, 'z');
  ASSERT_EQ(static_cast<uint8_t>((*result)[0][0]), 1);
  ASSERT_OK(EcCodec::verify(views(*result), 10, 1));

  auto empty = EcCodec::encode({}, 1);
  ASSERT_OK(empty);
  for (const auto &shard : *empty) ASSERT_EQ(shard, std::string(1, '\0'));
  ASSERT_OK(EcCodec::verify(views(*empty), 0, 1));
}

TEST(TestEcCodec, RecoversAllSixtySixTenSourceSetsInArbitraryOrder) {
  const auto logical = codecPattern(153);
  auto encoded = EcCodec::encode(logical, 17);
  ASSERT_OK(encoded);
  for (uint16_t first = 0; first != 12; ++first) {
    for (uint16_t second = first + 1; second != 12; ++second) {
      SCOPED_TRACE(std::to_string(first) + "," + std::to_string(second));
      std::vector<EcCodecShardView> healthy;
      for (uint16_t i = 0; i != 12; ++i) {
        if (i != first && i != second) healthy.push_back({i, (*encoded)[i]});
      }
      std::reverse(healthy.begin(), healthy.end());
      auto repaired = EcCodec::recover(healthy, logical.size(), 17);
      ASSERT_OK(repaired);
      ASSERT_EQ(*repaired, *encoded);
    }
  }
}

TEST(TestEcCodec, RejectsParityCorruptionAndEvenSelfConsistentNonzeroPadding) {
  auto logical = codecPattern(613);
  auto encoded = EcCodec::encode(logical, 64);
  ASSERT_OK(encoded);
  ASSERT_OK(EcCodec::verify(views(*encoded), logical.size(), 64));
  (*encoded)[11][2] ^= 1;
  ASSERT_ERROR(EcCodec::verify(views(*encoded), logical.size(), 64), StatusCode::kDataCorruption);

  logical.resize(640, '\0');
  logical.back() = 1;
  auto hiddenTail = EcCodec::encode(logical, 64);
  ASSERT_OK(hiddenTail);
  ASSERT_OK(EcCodec::verify(views(*hiddenTail), 640, 64));
  ASSERT_ERROR(EcCodec::verify(views(*hiddenTail), 613, 64), StatusCode::kDataCorruption);
  auto healthy = views(*hiddenTail);
  healthy.resize(10);
  ASSERT_ERROR(EcCodec::recover(healthy, 613, 64), StatusCode::kDataCorruption);
}

TEST(TestEcCodec, HelperContributionsReconstructOrderedTargetsAndSlices) {
  const auto logical = codecPattern(2561);
  auto encoded = EcCodec::encode(logical, 257);
  ASSERT_OK(encoded);
  const std::array<uint16_t, 10> healthy{11, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  const std::array<uint16_t, 2> targets{10, 0};
  for (auto [offset, length] : {std::pair<size_t, size_t>{0, 257}, {33, 77}, {256, 1}, {257, 0}}) {
    std::array<std::string, 2> combined{std::string(length, '\0'), std::string(length, '\0')};
    for (auto helper : healthy) {
      auto slice = std::string_view((*encoded)[helper]).substr(offset, length);
      auto contribution = EcCodec::contribute(healthy, targets, helper, slice);
      ASSERT_OK(contribution);
      ASSERT_EQ(contribution->size(), 2);
      for (size_t target = 0; target != targets.size(); ++target) {
        ASSERT_EQ((*contribution)[target].size(), length);
        for (size_t byte = 0; byte != length; ++byte) combined[target][byte] ^= (*contribution)[target][byte];
      }
    }
    for (size_t target = 0; target != targets.size(); ++target) {
      ASSERT_EQ(combined[target], (*encoded)[targets[target]].substr(offset, length));
    }
  }
}

TEST(TestEcCodec, RejectsInvalidShapeSourcesAndUnsupportedFormats) {
  ASSERT_ERROR(EcCodec::encode({}, 0), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcCodec::encode({}, EcCodec::kMaxShardBytes + 1), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcCodec::encode("elevenbytes", 1), StatusCode::kInvalidArg);
  auto encoded = EcCodec::encode(codecPattern(31), 4);
  ASSERT_OK(encoded);
  auto all = views(*encoded);
  auto healthy = all;
  healthy.resize(10);
  ASSERT_ERROR(EcCodec::recover(all, 31, 4), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcCodec::verify(healthy, 31, 4), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcCodec::verify(all, std::numeric_limits<uint64_t>::max(), 4), StatusCode::kInvalidArg);
  auto invalid = healthy;
  invalid.pop_back();
  ASSERT_ERROR(EcCodec::recover(invalid, 31, 4), StatusCode::kInvalidArg);
  invalid = healthy;
  invalid[1].index = invalid[0].index;
  ASSERT_ERROR(EcCodec::recover(invalid, 31, 4), StatusCode::kInvalidArg);
  invalid = healthy;
  invalid[1].index = 12;
  ASSERT_ERROR(EcCodec::recover(invalid, 31, 4), StatusCode::kInvalidArg);
  invalid = healthy;
  invalid[1].data.remove_suffix(1);
  ASSERT_ERROR(EcCodec::recover(invalid, 31, 4), StatusCode::kInvalidArg);
  all[11].index = 0;
  ASSERT_ERROR(EcCodec::verify(all, 31, 4), StatusCode::kInvalidArg);

  for (size_t field = 0; field != 5; ++field) {
    EcCodecFormat format;
    switch (field) {
      case 0:
        ++format.codecId;
        break;
      case 1:
        ++format.matrixVersion;
        break;
      case 2:
        ++format.dataShards;
        break;
      case 3:
        ++format.parityShards;
        break;
      case 4:
        ++format.fieldPolynomial;
        break;
    }
    ASSERT_ERROR(EcCodec::encode({}, 1, format), StatusCode::kInvalidArg);
    ASSERT_ERROR(EcCodec::verify(views(*encoded), 31, 4, format), StatusCode::kInvalidArg);
    ASSERT_ERROR(EcCodec::recover(healthy, 31, 4, format), StatusCode::kInvalidArg);
  }
}

TEST(TestEcCodec, ContributionValidatesPlanAndOneMiBInputBound) {
  const std::array<uint16_t, 10> healthy{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  const std::array<uint16_t, 2> targets{10, 11};
  const std::array<uint16_t, 1> oneTarget{10};
  ASSERT_ERROR(EcCodec::contribute(healthy, targets, 10, "a"), StatusCode::kInvalidArg);
  auto repeated = healthy;
  repeated[9] = 0;
  ASSERT_ERROR(EcCodec::contribute(repeated, targets, 0, "a"), StatusCode::kInvalidArg);
  repeated[9] = 12;
  ASSERT_ERROR(EcCodec::contribute(repeated, targets, 0, "a"), StatusCode::kInvalidArg);
  ASSERT_ERROR(EcCodec::contribute(healthy, {}, 0, "a"), StatusCode::kInvalidArg);
  const std::array<uint16_t, 2> duplicateTargets{10, 10};
  ASSERT_ERROR(EcCodec::contribute(healthy, duplicateTargets, 0, "a"), StatusCode::kInvalidArg);
  const std::array<uint16_t, 1> overlap{9};
  ASSERT_ERROR(EcCodec::contribute(healthy, overlap, 0, "a"), StatusCode::kInvalidArg);
  const std::array<uint16_t, 1> outOfRange{12};
  ASSERT_ERROR(EcCodec::contribute(healthy, outOfRange, 0, "a"), StatusCode::kInvalidArg);
  std::string maximum(EcCodec::kMaxShardBytes, 'x');
  auto full = EcCodec::contribute(healthy, oneTarget, 0, maximum);
  auto byte = EcCodec::contribute(healthy, oneTarget, 0, "x");
  ASSERT_OK(full);
  ASSERT_OK(byte);
  ASSERT_EQ(full->size(), 1);
  ASSERT_EQ((*full)[0], std::string(EcCodec::kMaxShardBytes, (*byte)[0][0]));
  maximum.push_back('x');
  ASSERT_ERROR(EcCodec::contribute(healthy, oneTarget, 0, maximum), StatusCode::kInvalidArg);
}

}  // namespace
}  // namespace hf3fs::storage
