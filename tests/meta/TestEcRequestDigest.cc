#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/Service.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta {
namespace {
TEST(TestEcRequestDigest, CanonicalGoldenAndIntentBinding) {
  EcMutationIntent intent;
  intent.object.inode = InodeId(0x010203040506);
  for (uint8_t i = 0; i != 16; ++i) intent.object.incarnation.data[i] = i;
  intent.stripe = 3;
  intent.expectedEpoch = 7;
  intent.expectedRevision = 11;
  intent.logicalLength = 3;
  for (uint32_t i = 0; i != 12; ++i) intent.fragmentCrc32c[i] = i;
  std::array<std::string_view, 10> data{};
  data[0] = "abc";
  auto content = computeEcLogicalSha256(data, 3);
  ASSERT_OK(content);
  ASSERT_EQ(serde::SerdeMethod<storage::EcSha256>::serdeToReadable(*content),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  auto request = computeEcRequestDigest(intent, 4, *content);
  ASSERT_OK(request);
  // Independently encoded with Python struct.pack('>...') and hashlib.sha256.
  ASSERT_EQ(serde::SerdeMethod<storage::EcSha256>::serdeToReadable(*request),
            "ed957123371a32ab1225df0004705d44d85ca91d02f3acd8b6c8981918f37ff8");
  for (unsigned change = 0; change != 8; ++change) {
    auto other = intent;
    switch (change) {
      case 0:
        other.object.inode = InodeId(2);
        break;
      case 1:
        other.object.incarnation.data[0] ^= 1;
        break;
      case 2:
        ++other.stripe;
        break;
      case 3:
        ++other.expectedEpoch;
        break;
      case 4:
        ++other.expectedRevision;
        break;
      case 5:
        other.logicalLength = 2;
        break;
      case 6:
        other.kind = EcMutationKind::Repair;
        break;
      case 7:
        other.fragmentCrc32c[11] ^= 1;
        break;
    }
    auto changed = computeEcRequestDigest(other, 4, *content);
    ASSERT_OK(changed);
    ASSERT_NE(*changed, *request);
  }
  auto sameRequest = intent;
  sameRequest.operation = Uuid::random();
  sameRequest.placements[0].node = flat::NodeId(999);
  ASSERT_RESULT_EQ(*request, computeEcRequestDigest(sameRequest, 4, *content));
  ASSERT_ERROR(computeEcLogicalSha256(data, 4), StatusCode::kInvalidArg);
}

TEST(TestEcRequestDigest, FixedTwelveCrcWireCount) {
  std::array<uint32_t, 12> original{};
  for (uint32_t i = 0; i != 12; ++i) original[i] = i * 17;
  auto wire = serde::serialize(original);
  std::array<uint32_t, 12> decoded{};
  ASSERT_OK(serde::deserialize(decoded, wire));
  ASSERT_EQ(decoded, original);
  for (uint8_t count : {uint8_t{0}, uint8_t{11}, uint8_t{13}, uint8_t{127}}) {
    auto malformed = wire;
    malformed[0] = static_cast<char>(count);
    ASSERT_ERROR(serde::deserialize(decoded, malformed), StatusCode::kInvalidFormat);
  }
}
}  // namespace
}  // namespace hf3fs::meta
