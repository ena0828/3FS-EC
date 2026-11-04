#pragma once

#include <algorithm>
#include <openssl/evp.h>

#include "fbs/storage/EcStageResultV2.h"
#include "storage/ec_repair/EcRepairPlan.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage::repair_test {

inline uint8_t multiply(uint8_t a, uint8_t b) {
  uint16_t product = 0;
  for (unsigned int bit = 0; bit != 8; ++bit)
    if ((b >> bit) & 1) product ^= uint16_t(a) << bit;
  for (int bit = 14; bit >= 8; --bit)
    if ((product >> bit) & 1) product ^= uint16_t(0x11d) << (bit - 8);
  return static_cast<uint8_t>(product);
}
inline uint8_t inverse(uint8_t a) {
  for (unsigned int value = 1; value != 256; ++value)
    if (multiply(a, value) == 1) return value;
  return 0;
}

struct Data {
  std::array<std::string, 12> shards;
  std::string logical;
  EcRepairPlanInput input;
};

// Independent polynomial convolution/long division oracle. Never calls the
// production encoder, recovery matrix or contribution coefficients.
inline Data makeData(uint32_t length,
                     std::vector<uint16_t> missing = {0, 11},
                     uint8_t window = 2,
                     uint64_t logicalLength = UINT64_MAX) {
  Data data;
  logicalLength = std::min<uint64_t>(logicalLength, uint64_t(length) * 10);
  for (auto &shard : data.shards) shard.resize(length);
  for (size_t shard = 0; shard != 10; ++shard) {
    for (size_t byte = 0; byte != length; ++byte) {
      data.shards[shard][byte] =
          shard * length + byte < logicalLength ? char((shard * 73 + byte * 19 + byte / 251) % 256) : '\0';
    }
    data.logical += data.shards[shard];
  }
  data.logical.resize(logicalLength);
  for (size_t parity = 10; parity != 12; ++parity) {
    for (size_t source = 0; source != 10; ++source) {
      const auto coefficient = inverse(parity ^ source);
      std::array<uint8_t, 256> table;
      for (size_t value = 0; value != table.size(); ++value) table[value] = multiply(coefficient, value);
      for (size_t byte = 0; byte != length; ++byte)
        data.shards[parity][byte] ^= char(table[uint8_t(data.shards[source][byte])]);
    }
  }
  auto &input = data.input;
  input.planId = Uuid::random();
  input.operationId = Uuid::random();
  input.ownerUid = flat::Uid(1000);
  input.clientNamespace = Uuid::random();
  input.baseEpoch = 17;
  input.baseRevision = 3;
  input.logicalLength = data.logical.size();
  unsigned int digestLength = 0;
  EXPECT_EQ(EVP_Digest(data.logical.data(),
                       data.logical.size(),
                       input.logicalSha256.data(),
                       &digestLength,
                       EVP_sha256(),
                       nullptr),
            1);
  EXPECT_EQ(digestLength, input.logicalSha256.size());
  input.maxBlocksInFlight = window;
  input.targetCount = missing.size();
  const auto object = Uuid::random();
  std::array<EcRepairFragment, 12> fragments;
  for (size_t i = 0; i != 12; ++i) {
    auto &fragment = fragments[i];
    fragment.identity.object = object;
    fragment.identity.stripe = 4;
    fragment.identity.generation = 9;
    fragment.identity.shard = i;
    fragment.identity.allocation = Uuid::random();
    fragment.operationId = Uuid::random();
    fragment.writerNamespace = Uuid::random();
    fragment.endpoint.nodeId = NodeId(100 + i);
    fragment.endpoint.chainId = ChainId(200 + i);
    fragment.endpoint.targetId = TargetId(300 + i);
    fragment.endpoint.engineUuid = Uuid::random();
    fragment.endpoint.targetIncarnation = Uuid::random();
    auto integrity = computeEcIntegrity(fragment.identity, data.shards[i]);
    EXPECT_TRUE(integrity);
    if (integrity) fragment.integrity = *integrity;
    input.operationEndpoints[i] = fragment.endpoint;
  }
  input.operationEndpointCount = 12;
  size_t source = 0;
  for (size_t i = 12; i != 0 && source != 10; --i) {
    if (std::find(missing.begin(), missing.end(), i - 1) == missing.end()) input.sources[source++] = fragments[i - 1];
  }
  for (size_t i = 0; i != missing.size(); ++i) {
    input.targets[i] = fragments[missing[i]];
    input.targets[i].operationId = input.operationId;
    input.targets[i].writerNamespace = input.clientNamespace;
  }
  return data;
}

inline std::string blockBytes(const Data &data, const EcRepairFragment &fragment, uint32_t block) {
  return data.shards[fragment.identity.shard].substr(size_t(block) * kEcIntegrityBlockBytes,
                                                     fragment.integrity.blocks[block].validLength);
}

inline EcFragmentReceiptV2 receipt(const EcRepairFragment &fragment) {
  EcFragmentReceiptV2 result;
  result.identity = fragment.identity;
  result.operationId = fragment.operationId;
  result.engineUuid = fragment.endpoint.engineUuid;
  result.targetIncarnation = fragment.endpoint.targetIncarnation;
  result.vChainId = {fragment.endpoint.chainId, ChainVer(1)};
  result.targetId = fragment.endpoint.targetId;
  result.length = fragment.integrity.wholeLength;
  result.crc32c = fragment.integrity.wholeCrc32c;
  result.integrityRoot = fragment.integrity.root;
  return result;
}

}  // namespace hf3fs::storage::repair_test
