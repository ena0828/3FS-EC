#include "storage/ec/ECShardStore.h"

#include <folly/hash/Checksum.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

using hf3fs::Path;
using hf3fs::erasure::ECLayout;
using hf3fs::erasure::ECShardKey;
using hf3fs::erasure::ECStaticPlacement;
using hf3fs::erasure::ECStripeBuffers;
using hf3fs::erasure::ErasureCodec;
using hf3fs::erasure::ConstShard;
using hf3fs::erasure::MutableShard;
using hf3fs::erasure::CodecError;
using hf3fs::storage::ec::ECShardStore;
using hf3fs::storage::ec::StoreError;
using hf3fs::kv::KVStore;

namespace {
Path newTestDirectory() {
  const char* root = std::getenv("EC_TEST_ROOT");
  if (!root || std::string_view(root).empty()) throw std::runtime_error("EC_TEST_ROOT is required");
  std::filesystem::create_directories(root);
  std::string pattern = std::string(root) + "/case-XXXXXX";
  if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp failed");
  return Path(pattern);
}

std::vector<uint8_t> payload(uint8_t seed) {
  std::vector<uint8_t> result(ECLayout::kShardSize);
  for (size_t i = 0; i < result.size(); ++i) result[i] = static_cast<uint8_t>(seed + i * 37);
  return result;
}

void mutateRaw(const Path& directory, const ECShardKey& key, uint64_t version,
               const std::function<void(std::string&)>& change) {
  KVStore::Config config;
  config.set_type(KVStore::Type::LevelDB);
  KVStore::Options options;
  options.type = KVStore::Type::LevelDB;
  options.path = directory;
  options.createIfMissing = false;
  auto raw = KVStore::create(config, options);
  ASSERT_NE(raw, nullptr);
  const auto physical = ECShardStore::physicalKey(key, version);
  auto value = raw->get(physical);
  ASSERT_TRUE(value);
  change(*value);
  ASSERT_TRUE(raw->put(physical, *value, true));
}

TEST(ECShardStore, DataParityIdentityVersionDuplicateAndReopen) {
  const Path directory = newTestDirectory() / "target-100";
  const ECShardKey data{10, 0, 0, 0};
  const ECShardKey parity{10, 0, 0, 10};
  const ECShardKey otherInode{11, 0, 0, 0};
  const ECShardKey otherChunk{10, 1, 0, 0};
  auto bytes = payload(9);
  auto opened = ECShardStore::open(directory, true);
  ASSERT_TRUE(opened);
  auto store = std::move(opened.value);
  EXPECT_EQ(store->write(data, 1, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->write(parity, 1, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->write(otherInode, 1, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->write(otherChunk, 1, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->write({10, 0, 0, 1}, 1, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->write(data, 1, 17, bytes), StoreError::AlreadyExists);
  EXPECT_EQ(store->write(data, 2, 17, bytes), StoreError::Ok);
  EXPECT_EQ(store->read(data, 3).error, StoreError::VersionMismatch);
  EXPECT_EQ(store->read({12, 0, 0, 0}, 1).error, StoreError::NotFound);
  EXPECT_EQ(store->read(data, 1, 2).error, StoreError::SchemeMismatch);
  EXPECT_EQ(store->read(data, 1, ECLayout::kEncodingScheme, 2).error, StoreError::FormatMismatch);
  EXPECT_EQ(store->write(data, 4, 17, bytes, 2), StoreError::InvalidArgument);
  EXPECT_EQ(store->write(data, 4, 17, bytes, ECLayout::kEncodingScheme, 2), StoreError::InvalidArgument);
  EXPECT_EQ(store->write(data, 4, 17, std::span(bytes).first(10)), StoreError::InvalidArgument);
  EXPECT_EQ(store->write({10, 0, 1, 0}, 4, 17, bytes), StoreError::InvalidArgument);
  EXPECT_EQ(store->write({10, 0, 0, 12}, 4, 17, bytes), StoreError::InvalidArgument);
  auto has = store->exists(data, 1);
  ASSERT_TRUE(has);
  EXPECT_TRUE(has.value);
  auto size = store->length(data, 1);
  ASSERT_TRUE(size);
  EXPECT_EQ(size.value, ECLayout::kShardSize);
  store.reset();
  auto reopened = ECShardStore::open(directory, false);
  ASSERT_TRUE(reopened);
  for (const ECShardKey key : {data, parity, otherInode, otherChunk, ECShardKey{10, 0, 0, 1}}) {
    auto record = reopened.value->read(key, 1);
    ASSERT_TRUE(record);
    EXPECT_EQ(record.value.key, key);
    EXPECT_EQ(record.value.dataVersion, 1u);
    EXPECT_EQ(record.value.validBytes, 17u);
    EXPECT_EQ(record.value.payload, bytes);
  }
  EXPECT_EQ(reopened.value->read(data, 2).value.payload, bytes);
}

TEST(ECShardStore, CorruptPayloadAndTruncatedRecordAreRejected) {
  const Path directory = newTestDirectory() / "target-101";
  const ECShardKey key{123, 4, 0, 2};
  auto opened = ECShardStore::open(directory, true);
  ASSERT_TRUE(opened);
  auto bytes = payload(3);
  ASSERT_EQ(opened.value->write(key, 1, ECLayout::kChunkSize, bytes), StoreError::Ok);
  opened.value.reset();
  mutateRaw(directory, key, 1, [](std::string& value) { value[56] ^= 1; });
  auto reopened = ECShardStore::open(directory, false);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened.value->read(key, 1).error, StoreError::CorruptRecord);
  reopened.value.reset();
  mutateRaw(directory, key, 1, [](std::string& value) { value.resize(20); });
  reopened = ECShardStore::open(directory, false);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened.value->read(key, 1).error, StoreError::CorruptRecord);
}

TEST(ECShardStore, LengthAndIdentityChecks) {
  const Path directory = newTestDirectory() / "target-102";
  const ECShardKey key{123, 5, 0, 3};
  const ECShardKey wrong{124, 5, 0, 3};
  auto opened = ECShardStore::open(directory, true);
  ASSERT_TRUE(opened);
  auto bytes = payload(6);
  ASSERT_EQ(opened.value->write(key, 7, 77, bytes), StoreError::Ok);
  opened.value.reset();
  KVStore::Config config;
  config.set_type(KVStore::Type::LevelDB);
  KVStore::Options options;
  options.type = KVStore::Type::LevelDB;
  options.path = directory;
  options.createIfMissing = false;
  auto raw = KVStore::create(config, options);
  ASSERT_NE(raw, nullptr);
  auto original = raw->get(ECShardStore::physicalKey(key, 7));
  ASSERT_TRUE(original);
  ASSERT_TRUE(raw->put(ECShardStore::physicalKey(wrong, 7), *original, true));
  raw.reset();
  auto reopened = ECShardStore::open(directory, false);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened.value->read(wrong, 7).error, StoreError::IdentityMismatch);
  reopened.value.reset();
  mutateRaw(directory, key, 7, [](std::string& value) {
    value[47] ^= 1;  // payload length, big endian, low byte
    const auto headerCrc = folly::crc32c(reinterpret_cast<const uint8_t*>(value.data()), 52, 0);
    for (int i = 0; i < 4; ++i) value[52+i] = static_cast<char>((headerCrc >> (24-8*i)) & 0xff);
  });
  reopened = ECShardStore::open(directory, false);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened.value->read(key, 7).error, StoreError::LengthMismatch);
}

void recoverFromPersisted(ECStripeBuffers stored, const std::vector<uint8_t>& input,
                          const ErasureCodec& codec, std::vector<uint8_t> erased) {
  std::vector<ConstShard> available;
  std::vector<MutableShard> missing;
  for (uint8_t i = 0; i < 12; ++i) {
    if (std::find(erased.begin(), erased.end(), i) == erased.end())
      available.push_back({i, stored.shards[i]});
    else {
      std::fill(stored.shards[i].begin(), stored.shards[i].end(), 0);
      missing.push_back({i, stored.shards[i]});
    }
  }
  ASSERT_EQ(codec.reconstruct(available, missing), CodecError::Ok);
  std::vector<uint8_t> reconstructed;
  ASSERT_EQ(ECLayout::reassemble(stored, reconstructed), hf3fs::erasure::LayoutError::Ok);
  EXPECT_EQ(reconstructed, input);
}

TEST(ECShardStore, TwelvePhysicalLevelDBStoresReopenAndAllErasures) {
  const Path base = newTestDirectory();
  ECStaticPlacement placement;
  for (uint8_t i = 0; i < 12; ++i) placement.targetIds[i] = 1000 + i;
  ASSERT_EQ(placement.validate(), hf3fs::erasure::LayoutError::Ok);
  ErasureCodec codec;
  std::vector<uint8_t> input(ECLayout::kChunkSize - 37);
  for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<uint8_t>(i * 13 + 17);
  ECStripeBuffers encoded;
  ASSERT_EQ(ECLayout::splitAndEncode(input, codec, encoded), hf3fs::erasure::LayoutError::Ok);
  const ECShardKey baseKey{9001, 5, 0, 0};
  for (uint8_t i = 0; i < 12; ++i) {
    const Path directory = base / std::to_string(placement.targetIds[i]);
    auto opened = ECShardStore::open(directory, true);
    ASSERT_TRUE(opened);
    ECShardKey key = baseKey;
    key.shardIndex = i;
    ASSERT_EQ(opened.value->write(key, 42, encoded.validBytes, encoded.shards[i]), StoreError::Ok);
  }
  ECStripeBuffers loaded;
  loaded.validBytes = encoded.validBytes;
  for (uint8_t i = 0; i < 12; ++i) {
    const Path directory = base / std::to_string(placement.targetIds[i]);
    auto reopened = ECShardStore::open(directory, false);
    ASSERT_TRUE(reopened);
    ECShardKey key = baseKey;
    key.shardIndex = i;
    auto stored = reopened.value->read(key, 42);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored.value.key, key);
    EXPECT_EQ(stored.value.validBytes, encoded.validBytes);
    loaded.shards[i] = std::move(stored.value.payload);
    EXPECT_EQ(loaded.shards[i], encoded.shards[i]);
  }
  std::vector<uint8_t> decoded;
  ASSERT_EQ(ECLayout::reassemble(loaded, decoded), hf3fs::erasure::LayoutError::Ok);
  EXPECT_EQ(decoded, input);
  for (uint8_t i = 0; i < 12; ++i) recoverFromPersisted(loaded, input, codec, {i});
  for (uint8_t i = 0; i < 12; ++i)
    for (uint8_t j = i+1; j < 12; ++j)
      recoverFromPersisted(loaded, input, codec, {i,j});
}

}  // namespace
