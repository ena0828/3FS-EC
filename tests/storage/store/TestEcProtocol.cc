#include <array>
#include <folly/ScopeGuard.h>
#include <limits>
#include <set>
#include <sys/mman.h>

#include "fbs/storage/Ec.h"
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
  value.shard = 255;
  return value;
}

TEST(TestEcProtocol, CanonicalIdentityBytesAndValidation) {
  auto value = identity();
  const std::array<uint8_t, 64> expected{0x33, 0x46, 0x53, 0x45, 0x43, 0x46, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04,
                                         0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02,
                                         0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                         0x18, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xe1, 0xe2, 0xe3,
                                         0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef};
  auto key = value.chunkId();
  ASSERT_OK(key);
  ASSERT_EQ(key->data(), std::string_view(reinterpret_cast<const char *>(expected.data()), expected.size()));
  EcFragmentIdentity decoded;
  ASSERT_OK(serde::deserialize(decoded, serde::serialize(value)));
  ASSERT_OK(decoded.chunkId());
  ASSERT_EQ(decoded.chunkId()->data(), key->data());

  std::set<std::string> keys;
  keys.emplace(key->data());
  for (unsigned field = 0; field != 5; ++field) {
    auto changed = value;
    switch (field) {
      case 0:
        changed.object.data[15] ^= 1;
        break;
      case 1:
        ++changed.stripe;
        break;
      case 2:
        ++changed.generation;
        break;
      case 3:
        --changed.shard;
        break;
      case 4:
        changed.allocation.data[15] ^= 1;
        break;
    }
    auto changedKey = changed.chunkId();
    ASSERT_OK(changedKey);
    ASSERT_TRUE(keys.emplace(changedKey->data()).second);
  }
  value.stripe = std::numeric_limits<uint64_t>::max();
  value.generation = std::numeric_limits<uint64_t>::max();
  ASSERT_OK(value.chunkId());
  for (unsigned invalid = 0; invalid != 6; ++invalid) {
    auto bad = identity();
    switch (invalid) {
      case 0:
        bad.version = 0;
        break;
      case 1:
        bad.version = 2;
        break;
      case 2:
        bad.object = Uuid::zero();
        break;
      case 3:
        bad.allocation = Uuid::zero();
        break;
      case 4:
        bad.generation = 0;
        break;
      case 5:
        bad.shard = 256;
        break;
    }
    ASSERT_FALSE(bad.validate());
    ASSERT_FALSE(bad.chunkId());
  }
}

TEST(TestEcProtocol, PayloadLimitsAndTruncatedWireLengths) {
  for (size_t size : {size_t{0}, size_t{1}, kEcFragmentRpcMaxBytes}) {
    EcPayload input{std::string(size, '\0')};
    for (size_t index = 0; index != size; ++index) input.data[index] = static_cast<char>(index * 37);
    EcPayload output;
    ASSERT_OK(serde::deserialize(output, serde::serialize(input)));
    ASSERT_EQ(output.data, input.data);
  }
  EcPayload unchanged{"unchanged"};
  const auto oversized = serde::serialize(EcPayload{std::string(kEcFragmentRpcMaxBytes + 1, 'x')});
  auto result = serde::deserialize(unchanged, oversized);
  ASSERT_FALSE(result);
  ASSERT_EQ(result.error().code(), StatusCode::kInvalidArg);
  ASSERT_EQ(unchanged.data, "unchanged");

  // A length claim alone must be rejected without reserving that many bytes.
  // This passes only the varint; no multi-gigabyte fixture is allocated.
  for (uint64_t size : {uint64_t{1}, uint64_t{kEcFragmentRpcMaxBytes}, std::numeric_limits<uint64_t>::max()}) {
    const auto missingBody = serde::serialize(Varint64{size});
    ASSERT_FALSE(serde::deserialize(unchanged, missingBody));
    ASSERT_EQ(unchanged.data, "unchanged");
  }
  const auto wire = serde::serialize(EcPayload{std::string("a\0b", 3)});
  for (size_t size = 0; size != wire.size(); ++size) {
    ASSERT_FALSE(serde::deserialize(unchanged, std::string_view(wire).substr(0, size)));
    ASSERT_EQ(unchanged.data, "unchanged");
  }
}

TEST(TestEcProtocol, OversizedViewRejectedBeforeReadingPayload) {
  const size_t length = kEcFragmentRpcMaxBytes + 1;
  void *region = ::mmap(nullptr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(region, MAP_FAILED);
  SCOPE_EXIT { ::munmap(region, length); };
  // The entire declared range is mapped but inaccessible. Copying or scanning
  // bytes before applying the bound would fault. This does not claim that the
  // outer RPC receive buffer has not already been allocated by networking.
  auto result = serde::SerdeMethod<EcPayload>::serdeFrom(std::string_view(static_cast<const char *>(region), length));
  ASSERT_FALSE(result);
  ASSERT_EQ(result.error().code(), StatusCode::kInvalidArg);
}

TEST(TestEcProtocol, RequestDefaultsCannotEnableCreationOrRead) {
  const std::string emptyTable(1, '\0');
  EcCreateReq create;
  EcReadReq read;
  ASSERT_OK(serde::deserialize(create, emptyTable));
  ASSERT_OK(serde::deserialize(read, emptyTable));
  ASSERT_FALSE(create.validate());
  ASSERT_FALSE(read.validate());
  create.identity = identity();
  create.vChainId = VersionedChainId{ChainId{81}, ChainVer{1}};
  create.targetId = TargetId{71};
  create.operationId = Uuid::from(1, 2);
  create.payload.data = std::string("binary\0payload", 14);
  create.checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                         reinterpret_cast<const uint8_t *>(create.payload.data.data()),
                                         create.payload.data.size());
  EcCreateReq copy;
  ASSERT_OK(serde::deserialize(copy, serde::serialize(create)));
  ASSERT_OK(copy.validate());
  ASSERT_EQ(copy.payload.data, create.payload.data);
  ASSERT_EQ(copy.identity.chunkId()->data(), create.identity.chunkId()->data());
  ASSERT_EQ(copy.checksum, create.checksum);
  read.identity = create.identity;
  read.vChainId = create.vChainId;
  read.targetId = create.targetId;
  read.operationId = create.operationId;
  read.expectedLength = kEcFragmentRpcMaxBytes;
  read.checksum = create.checksum;
  ASSERT_OK(read.validate());
  ++read.expectedLength;
  ASSERT_FALSE(read.validate());
  copy.operationId = Uuid::zero();
  ASSERT_FALSE(copy.validate());
  copy = create;
  copy.vChainId.chainId = ChainId{};
  ASSERT_FALSE(copy.validate());
  copy = create;
  copy.checksum.type = ChecksumType::NONE;
  ASSERT_FALSE(copy.validate());
}

}  // namespace
}  // namespace hf3fs::storage
