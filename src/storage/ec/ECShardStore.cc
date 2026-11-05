#include "storage/ec/ECShardStore.h"

#include <folly/hash/Checksum.h>

#include <algorithm>
#include <string_view>

namespace hf3fs::storage::ec {
namespace {
constexpr std::string_view kKeyMagic = "ECS1";
constexpr std::string_view kRecordMagic = "ECSR";
constexpr uint16_t kComplete = 1;  // Local record state, NOT a distributed commit.
constexpr size_t kHeaderSize = 56;
constexpr size_t kHeaderChecksumOffset = 52;

void appendBE(std::string& out, uint64_t value, unsigned width) {
  for (unsigned shift = width; shift != 0; --shift)
    out.push_back(static_cast<char>((value >> ((shift - 1) * 8)) & 0xff));
}

uint64_t readBE(std::string_view in, size_t& offset, unsigned width) {
  uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i)
    value = (value << 8) | static_cast<uint8_t>(in[offset++]);
  return value;
}

uint32_t crc(std::string_view data) {
  return folly::crc32c(reinterpret_cast<const uint8_t*>(data.data()), data.size(), 0);
}

std::string keyPrefix(const erasure::ECShardKey& key) {
  std::string result(kKeyMagic);
  appendBE(result, key.inodeId, 8);
  appendBE(result, key.logicalChunkIndex, 4);
  appendBE(result, key.stripeIndex, 4);
  appendBE(result, key.shardIndex, 1);
  return result;
}

std::string serialize(const erasure::ECShardKey& key, uint64_t version,
                      uint32_t validBytes, std::span<const uint8_t> payload,
                      uint32_t scheme, uint32_t format) {
  std::string result(kRecordMagic);
  result.reserve(kHeaderSize + payload.size());
  appendBE(result, format, 2);
  appendBE(result, kComplete, 2);
  appendBE(result, scheme, 4);
  appendBE(result, version, 8);
  appendBE(result, key.inodeId, 8);
  appendBE(result, key.logicalChunkIndex, 4);
  appendBE(result, key.stripeIndex, 4);
  appendBE(result, key.shardIndex, 1);
  appendBE(result, 0, 3);
  appendBE(result, validBytes, 4);
  appendBE(result, payload.size(), 4);
  const std::string_view bytes(reinterpret_cast<const char*>(payload.data()), payload.size());
  appendBE(result, crc(bytes), 4);
  appendBE(result, crc(result), 4);
  result.append(bytes);
  return result;
}

StoreResult<ShardRecord> parse(std::string_view encoded, const erasure::ECShardKey& key,
                               uint64_t version, uint32_t expectedScheme, uint32_t expectedFormat) {
  if (encoded.size() < kHeaderSize || encoded.substr(0, 4) != kRecordMagic)
    return {StoreError::CorruptRecord, {}};
  size_t at = 4;
  const auto format = readBE(encoded, at, 2);
  const auto state = readBE(encoded, at, 2);
  const auto scheme = readBE(encoded, at, 4);
  const auto storedVersion = readBE(encoded, at, 8);
  const auto inode = readBE(encoded, at, 8);
  const auto chunk = readBE(encoded, at, 4);
  const auto stripe = readBE(encoded, at, 4);
  const auto shard = readBE(encoded, at, 1);
  const auto reserved = readBE(encoded, at, 3);
  const auto valid = readBE(encoded, at, 4);
  const auto payloadLen = readBE(encoded, at, 4);
  const auto payloadCrc = readBE(encoded, at, 4);
  const auto headerCrc = readBE(encoded, at, 4);
  if (at != kHeaderSize || crc(encoded.substr(0, kHeaderChecksumOffset)) != headerCrc ||
      state != kComplete || reserved != 0 || valid > erasure::ECLayout::kChunkSize)
    return {StoreError::CorruptRecord, {}};
  if (inode != key.inodeId || chunk != key.logicalChunkIndex || stripe != key.stripeIndex ||
      shard != key.shardIndex)
    return {StoreError::IdentityMismatch, {}};
  if (storedVersion != version) return {StoreError::VersionMismatch, {}};
  if (format != expectedFormat) return {StoreError::FormatMismatch, {}};
  if (scheme != expectedScheme) return {StoreError::SchemeMismatch, {}};
  if (payloadLen != erasure::ECLayout::kShardSize ||
      encoded.size() != kHeaderSize + payloadLen) return {StoreError::LengthMismatch, {}};
  if (crc(encoded.substr(kHeaderSize)) != payloadCrc) return {StoreError::CorruptRecord, {}};
  ShardRecord record;
  record.key = key;
  record.dataVersion = version;
  record.encodingScheme = static_cast<uint32_t>(scheme);
  record.formatVersion = static_cast<uint32_t>(format);
  record.validBytes = static_cast<uint32_t>(valid);
  record.payloadChecksum = static_cast<uint32_t>(payloadCrc);
  record.payload.assign(encoded.begin() + kHeaderSize, encoded.end());
  return {StoreError::Ok, std::move(record)};
}
}  // namespace

StoreResult<std::unique_ptr<ECShardStore>> ECShardStore::open(const Path& directory, bool create) {
  if (directory.empty()) return {StoreError::InvalidArgument, {}};
  auto result = std::unique_ptr<ECShardStore>(new ECShardStore());
  result->config_.set_type(kv::KVStore::Type::LevelDB);
  result->config_.set_sync_when_write(true);
  kv::KVStore::Options options;
  options.type = kv::KVStore::Type::LevelDB;
  options.path = directory;
  options.createIfMissing = create;
  result->store_ = kv::KVStore::create(result->config_, options);
  if (!result->store_) return {StoreError::BackendError, {}};
  return {StoreError::Ok, std::move(result)};
}

std::string ECShardStore::physicalKey(const erasure::ECShardKey& key, uint64_t version) {
  auto result = keyPrefix(key);
  appendBE(result, version, 8);
  return result;
}

StoreError ECShardStore::write(const erasure::ECShardKey& key, uint64_t version,
                              uint32_t validBytes, std::span<const uint8_t> payload,
                              uint32_t scheme, uint32_t format) {
  if (erasure::ECLayout::validateKey(key) != erasure::LayoutError::Ok || version == 0 ||
      scheme != erasure::ECLayout::kEncodingScheme || format != erasure::ECLayout::kFormatVersion ||
      validBytes > erasure::ECLayout::kChunkSize || payload.size() != erasure::ECLayout::kShardSize)
    return StoreError::InvalidArgument;
  const auto physical = physicalKey(key, version);
  std::lock_guard guard(mutex_);
  const auto old = store_->get(physical);
  if (old) return StoreError::AlreadyExists;
  if (old.error().code() != StatusCode::kKVStoreNotFound) return StoreError::BackendError;
  const auto value = serialize(key, version, validBytes, payload, scheme, format);
  if (!store_->put(physical, value, true)) return StoreError::BackendError;
  return StoreError::Ok;
}

StoreResult<ShardRecord> ECShardStore::read(const erasure::ECShardKey& key, uint64_t version,
                                           uint32_t scheme, uint32_t format) {
  if (erasure::ECLayout::validateKey(key) != erasure::LayoutError::Ok || version == 0)
    return {StoreError::InvalidArgument, {}};
  std::lock_guard guard(mutex_);
  const auto stored = store_->get(physicalKey(key, version));
  if (!stored) {
    if (stored.error().code() != StatusCode::kKVStoreNotFound)
      return {StoreError::BackendError, {}};
    bool anyVersion = false;
    auto scanned = store_->iterateKeysWithPrefix(keyPrefix(key), 1,
        [&](std::string_view, std::string_view) -> Result<Void> {
          anyVersion = true;
          return Void{};
        });
    if (!scanned) return {StoreError::BackendError, {}};
    return {anyVersion ? StoreError::VersionMismatch : StoreError::NotFound, {}};
  }
  return parse(*stored, key, version, scheme, format);
}

StoreResult<bool> ECShardStore::exists(const erasure::ECShardKey& key, uint64_t version) {
  auto record = read(key, version);
  if (record) return {StoreError::Ok, true};
  if (record.error == StoreError::NotFound) return {StoreError::Ok, false};
  return {record.error, false};
}

StoreResult<uint32_t> ECShardStore::length(const erasure::ECShardKey& key, uint64_t version) {
  auto record = read(key, version);
  if (!record) return {record.error, 0};
  return {StoreError::Ok, static_cast<uint32_t>(record.value.payload.size())};
}

}  // namespace hf3fs::storage::ec
