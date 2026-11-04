#include <limits>

#include "fbs/storage/EcIntegrity.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {

EcFragmentIdentity identity() {
  EcFragmentIdentity value;
  for (uint8_t index = 0; index != 16; ++index) {
    value.object.data[index] = index;
    value.allocation.data[index] = 0xe0 + index;
  }
  value.stripe = 0x0102030405060708;
  value.generation = 0x1112131415161718;
  value.shard = 10;
  return value;
}

std::string pattern(size_t length) {
  std::string result(length, '\0');
  for (size_t index = 0; index != length; ++index) result[index] = static_cast<char>(index * 29 + 7);
  return result;
}

std::string hex(const EcSha256 &value) { return serde::SerdeMethod<EcSha256>::serdeToReadable(value); }

TEST(TestEcIntegrity, IndependentGoldenVectors) {
  // Generated independently with Python hashlib.sha256, struct.pack big-endian
  // fields and a bitwise Castagnoli CRC (0x82f63b78), checked against 123456789.
  // The identity above and pattern byte (29*i+7)%256 completely specify input.
  struct Vector {
    std::string bytes;
    uint32_t crc;
    std::string_view root;
    std::string_view first;
    std::string_view last;
  };
  const std::array<Vector, 4> vectors{{
      {"", 0, "0f41584957d12ad477af52025a1583d00cd3478ae49eb5eec8bc79b98bcb5ccb", "", ""},
      {"123456789",
       0xe3069283,
       "b6468afe09ff1e6e139b4f6a1f9eb9211c2aea630af7d156ad869356c519c70e",
       "77230a2add149c086b66908019e8396815cf6354e7f064e8a2cab835d8f45aa1",
       "77230a2add149c086b66908019e8396815cf6354e7f064e8a2cab835d8f45aa1"},
      {pattern(65539),
       2532243541u,
       "01ce5652238dcb0c42bb0664acd066ca9a62380414d80352ea1cdefdd49082dc",
       "3710c01037e67c4f4146fb9218f77d505fee40f16d44128fdd53e042f804c287",
       "a6a8aa13f36874d757b2d30258879175ecf0a2c9110efba3d95466e2e0654fe1"},
      {pattern(1048576),
       229524619u,
       "05235b1041101bc0192008da85bfa49b7196d93b820667070665c840bb0f69b9",
       "903000f34ef9109451acee2bba144c6d89e1fbc54368a812122f9d7f85e10784",
       "176f18bc551a9c8f82660f08a42749337f5c46a6356b21706c63d6bebe33eae3"},
  }};
  for (const auto &vector : vectors) {
    SCOPED_TRACE(vector.bytes.size());
    auto descriptor = computeEcIntegrity(identity(), vector.bytes);
    ASSERT_OK(descriptor);
    ASSERT_OK(validateEcIntegrity(identity(), *descriptor));
    ASSERT_EQ(descriptor->wholeLength, vector.bytes.size());
    ASSERT_EQ(descriptor->wholeCrc32c, vector.crc);
    ASSERT_EQ(hex(descriptor->root), vector.root);
    const auto native = ChecksumInfo::create(ChecksumType::CRC32C,
                                             reinterpret_cast<const uint8_t *>(vector.bytes.data()),
                                             vector.bytes.size());
    ASSERT_EQ(descriptor->wholeCrc32c, ~native.value);
    if (descriptor->blockCount) {
      ASSERT_EQ(hex(descriptor->blocks.front().sha256), vector.first);
      ASSERT_EQ(hex(descriptor->blocks[descriptor->blockCount - 1].sha256), vector.last);
    }
    for (uint32_t index = 0; index != descriptor->blockCount; ++index) {
      auto bytes = std::string_view(vector.bytes).substr(index * kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
      ASSERT_OK(verifyEcIntegrityBlock(identity(), *descriptor, index, bytes));
    }
  }
}

TEST(TestEcIntegrity, ContentIdentitySurvivesRelocationButNotReplacement) {
  const auto data = pattern(131073);
  auto original = identity();
  auto descriptor = computeEcIntegrity(original, data);
  ASSERT_OK(descriptor);
  auto moved = original;
  moved.allocation.data[0] ^= 0x80;
  auto copied = computeEcIntegrity(moved, data);
  ASSERT_OK(copied);
  ASSERT_EQ(serde::serialize(*descriptor), serde::serialize(*copied));
  ASSERT_OK(validateEcIntegrity(moved, *descriptor));
  for (unsigned field = 0; field != 4; ++field) {
    auto changed = original;
    switch (field) {
      case 0:
        changed.object.data[0] ^= 0x80;
        break;
      case 1:
        ++changed.stripe;
        break;
      case 2:
        ++changed.generation;
        break;
      case 3:
        ++changed.shard;
        break;
    }
    ASSERT_ERROR(validateEcIntegrity(changed, *descriptor), StatusCode::kDataCorruption);
    auto different = computeEcIntegrity(changed, data);
    ASSERT_OK(different);
    ASSERT_NE(different->root, descriptor->root);
    ASSERT_NE(different->blocks[0].sha256, descriptor->blocks[0].sha256);
  }
}

TEST(TestEcIntegrity, DetectsCorruptionAndRejectsPartialOrSwappedBlocks) {
  std::string data(kEcIntegrityBlockBytes, 'a');
  data.append(kEcIntegrityBlockBytes, 'b');
  data.append("tail");
  auto descriptor = computeEcIntegrity(identity(), data);
  ASSERT_OK(descriptor);
  const auto first = std::string_view(data).substr(0, kEcIntegrityBlockBytes);
  const auto second = std::string_view(data).substr(kEcIntegrityBlockBytes, kEcIntegrityBlockBytes);
  ASSERT_OK(verifyEcIntegrityBlock(identity(), *descriptor, 0, first));
  ASSERT_OK(verifyEcIntegrityBlock(identity(), *descriptor, 1, second));
  ASSERT_OK(verifyEcIntegrityBlock(identity(), *descriptor, 2, "tail"));
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *descriptor, 0, second), StatusCode::kDataCorruption);
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *descriptor, 2, "fail"), StatusCode::kDataCorruption);
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *descriptor, 0, first.substr(1)), StatusCode::kInvalidArg);
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *descriptor, 3, ""), StatusCode::kInvalidArg);
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *descriptor, UINT32_MAX, ""), StatusCode::kInvalidArg);

  for (unsigned field = 0; field != 4; ++field) {
    auto bad = *descriptor;
    switch (field) {
      case 0:
        bad.blocks[0].sha256[0] ^= 1;
        break;
      case 1:
        bad.blocks[0].crc32c ^= 1;
        break;
      case 2:
        bad.wholeCrc32c ^= 1;
        break;
      case 3:
        std::swap(bad.blocks[0], bad.blocks[1]);
        break;
    }
    ASSERT_ERROR(validateEcIntegrity(identity(), bad), StatusCode::kDataCorruption);
  }
}

TEST(TestEcIntegrity, RejectsNoncanonicalParametersAndUnusedSlots) {
  auto valid = computeEcIntegrity(identity(), "123456789");
  ASSERT_OK(valid);
  for (unsigned field = 0; field != 14; ++field) {
    SCOPED_TRACE(field);
    auto bad = *valid;
    switch (field) {
      case 0:
        ++bad.version;
        break;
      case 1:
        ++bad.codecId;
        break;
      case 2:
        ++bad.matrixVersion;
        break;
      case 3:
        ++bad.dataShards;
        break;
      case 4:
        ++bad.parityShards;
        break;
      case 5:
        ++bad.fieldPolynomial;
        break;
      case 6:
        ++bad.blockBytes;
        break;
      case 7:
        bad.wholeLength = UINT32_MAX;
        break;
      case 8:
        bad.blockCount = UINT16_MAX;
        break;
      case 9:
        --bad.blockCount;
        break;
      case 10:
        ++bad.blocks[0].validLength;
        break;
      case 11:
        bad.blocks[15].validLength = 1;
        break;
      case 12:
        bad.blocks[15].crc32c = 1;
        break;
      case 13:
        bad.blocks[15].sha256[31] = 1;
        break;
    }
    ASSERT_ERROR(validateEcIntegrity(identity(), bad), StatusCode::kInvalidArg);
  }
  for (unsigned field = 0; field != 5; ++field) {
    auto bad = identity();
    switch (field) {
      case 0:
        bad.version = 0;
        break;
      case 1:
        bad.object = Uuid::zero();
        break;
      case 2:
        bad.generation = 0;
        break;
      case 3:
        bad.shard = 12;
        break;
      case 4:
        bad.allocation = Uuid::zero();
        break;
    }
    ASSERT_ERROR(computeEcIntegrity(bad, ""), StatusCode::kInvalidArg);
  }
  ASSERT_ERROR(computeEcIntegrity(identity(), std::string(kEcFragmentRpcMaxBytes + 1, 'x')), StatusCode::kInvalidArg);
  auto empty = computeEcIntegrity(identity(), "");
  ASSERT_OK(empty);
  ASSERT_ERROR(verifyEcIntegrityBlock(identity(), *empty, 0, ""), StatusCode::kInvalidArg);
  empty->wholeCrc32c = 1;
  ASSERT_ERROR(validateEcIntegrity(identity(), *empty), StatusCode::kInvalidArg);
}

TEST(TestEcIntegrity, FixedExtentSerializationAndRoundtrip) {
  auto original = computeEcIntegrity(identity(), pattern(65539));
  ASSERT_OK(original);
  EcIntegrityDescriptor decoded;
  ASSERT_OK(serde::deserialize(decoded, serde::serialize(*original)));
  ASSERT_EQ(serde::serialize(decoded), serde::serialize(*original));
  ASSERT_OK(validateEcIntegrity(identity(), decoded));
  ASSERT_OK(serde::fromJsonString(decoded, serde::toJsonString(*original)));
  ASSERT_EQ(serde::serialize(decoded), serde::serialize(*original));
  ASSERT_OK(serde::fromTomlString(decoded, serde::toTomlString(*original)));
  ASSERT_EQ(serde::serialize(decoded), serde::serialize(*original));

  decltype(decoded.blocks) blocks{};
  for (uint64_t count : std::array<uint64_t, 4>{0, 15, 17, std::numeric_limits<uint64_t>::max()}) {
    ASSERT_ERROR(serde::deserialize(blocks, serde::serialize(Varint64(count))), StatusCode::kInvalidFormat);
  }
  ASSERT_ERROR(serde::fromJsonString(blocks, "[]"), StatusCode::kInvalidFormat);
  EcSha256 hash{};
  for (size_t length : {0u, 31u, 33u}) {
    ASSERT_ERROR(serde::deserialize(hash, serde::serialize(std::string(length, '\0'))), StatusCode::kInvalidFormat);
  }
  ASSERT_ERROR(serde::fromJsonString(hash, "\"DEADBEEF\""), StatusCode::kInvalidFormat);
}

}  // namespace
}  // namespace hf3fs::storage
