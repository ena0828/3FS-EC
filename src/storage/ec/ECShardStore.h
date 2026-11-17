#pragma once

#include "erasure/ECLayout.h"
#include "kv/KVStore.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace hf3fs::storage::ec {

enum class StoreError {
  Ok,
  InvalidArgument,
  NotFound,
  AlreadyExists,
  VersionMismatch,
  SchemeMismatch,
  FormatMismatch,
  LengthMismatch,
  IdentityMismatch,
  CorruptRecord,
  BackendError,
  ContentConflict,
};

enum class IdempotentWriteDisposition { NotWritten, Created, ExistingVerified };

template <typename T>
struct StoreResult {
  StoreError error{StoreError::Ok};
  T value{};
  explicit operator bool() const { return error == StoreError::Ok; }
};

struct ShardRecord {
  erasure::ECShardKey key;
  uint64_t dataVersion{};
  uint32_t encodingScheme{};
  uint32_t formatVersion{};
  uint32_t validBytes{};
  uint32_t payloadChecksum{};
  std::vector<uint8_t> payload;
};

// Uses 3FS kv::KVStore's LevelDB implementation in a dedicated EC database.
// A process must own this database exclusively. No distributed commit is implied.
class ECShardStore {
 public:
  static StoreResult<std::unique_ptr<ECShardStore>> open(const Path& directory, bool create);
  static std::string physicalKey(const erasure::ECShardKey& key, uint64_t dataVersion);

  StoreError write(const erasure::ECShardKey& key, uint64_t dataVersion,
                   uint32_t validBytes, std::span<const uint8_t> payload,
                   uint32_t encodingScheme = erasure::ECLayout::kEncodingScheme,
                   uint32_t formatVersion = erasure::ECLayout::kFormatVersion);
  // Immutable content identity is (key, dataVersion). Both successful dispositions
  // require a synchronous Put; repeats compare all bytes, not just the CRC.
  // No caller-supplied checksum is accepted. On error the disposition is NotWritten;
  // a backend error does not prove that the database remained unchanged.
  StoreResult<IdempotentWriteDisposition> writeIdempotent(
      const erasure::ECShardKey& key, uint64_t dataVersion,
      uint32_t validBytes, std::span<const uint8_t> payload,
      uint32_t encodingScheme = erasure::ECLayout::kEncodingScheme,
      uint32_t formatVersion = erasure::ECLayout::kFormatVersion);
  StoreResult<ShardRecord> read(const erasure::ECShardKey& key, uint64_t dataVersion,
                                uint32_t expectedScheme = erasure::ECLayout::kEncodingScheme,
                                uint32_t expectedFormat = erasure::ECLayout::kFormatVersion);
  StoreResult<bool> exists(const erasure::ECShardKey& key, uint64_t dataVersion);
  StoreResult<uint32_t> length(const erasure::ECShardKey& key, uint64_t dataVersion);

 private:
  ECShardStore() = default;
  std::mutex mutex_;
  kv::KVStore::Config config_;
  std::unique_ptr<kv::KVStore> store_;
};

}  // namespace hf3fs::storage::ec
