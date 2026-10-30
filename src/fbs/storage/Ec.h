#pragma once

#include "fbs/storage/Common.h"

namespace hf3fs::storage {

// Versioned immutable-fragment RPCs. This is a storage primitive, not a
// published stripe or a claim that ordinary file layouts already support EC.
inline constexpr uint16_t kEcFragmentProtocolVersion = 1;
inline constexpr size_t kEcFragmentRpcMaxBytes = 1u << 20;

struct EcPayload {
  std::string data;

  std::string serdeToReadable() const { return fmt::format("EcPayload({} bytes)", data.size()); }
};

}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcPayload> {
  static std::string_view serdeTo(const storage::EcPayload &payload) { return payload.data; }

  // Deserializing a string_view checks the wire extent without reserving a
  // container from an untrusted count. Copy only after enforcing this limit.
  static Result<storage::EcPayload> serdeFrom(std::string_view bytes) {
    if (bytes.size() > storage::kEcFragmentRpcMaxBytes) {
      return makeError(StatusCode::kInvalidArg, "EC fragment RPC payload exceeds 1 MiB");
    }
    return storage::EcPayload{std::string(bytes)};
  }
};

namespace hf3fs::storage {

struct EcFragmentIdentity {
  SERDE_STRUCT_FIELD(version, kEcFragmentProtocolVersion);
  SERDE_STRUCT_FIELD(object, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(shard, uint16_t{});
  SERDE_STRUCT_FIELD(allocation, Uuid::zero());

 public:
  Result<Void> validate() const {
    if (version != kEcFragmentProtocolVersion || object.is_nil() || allocation.is_nil() || generation == 0 ||
        shard >= 256) {
      return makeError(StatusCode::kInvalidArg, "invalid EC fragment identity or format version");
    }
    return Void{};
  }

  // 64-byte canonical key: magic/version[8], object[16], stripe[8],
  // generation[8], shard[2], reserved-zero[6], allocation[16]. Numeric
  // components are big endian. The existing engine chain prefix is separate.
  Result<ChunkId> chunkId() const {
    RETURN_ON_ERROR(validate());
    std::string key("3FSECF\0\1", 8);
    key.append(object.asStringView());
    const auto append = [&](uint64_t value, size_t bytes) {
      for (size_t index = bytes; index != 0; --index) {
        key.push_back(static_cast<char>(value >> ((index - 1) * 8)));
      }
    };
    append(stripe, 8);
    append(generation, 8);
    append(shard, 2);
    key.append(6, '\0');
    key.append(allocation.asStringView());
    return ChunkId(std::move(key));
  }
};

struct EcCreateTargetReq {
  SERDE_STRUCT_FIELD(version, kEcFragmentProtocolVersion);
  SERDE_STRUCT_FIELD(settings, CreateTargetReq{});
};

struct EcCreateTargetRsp {
  SERDE_STRUCT_FIELD(version, kEcFragmentProtocolVersion);
  SERDE_STRUCT_FIELD(targetId, TargetId{});
};

struct EcCreateReq {
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(checksum, ChecksumInfo{});
  SERDE_STRUCT_FIELD(payload, EcPayload{});
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(userInfo, flat::UserInfo{});

 public:
  Result<Void> validate() const {
    RETURN_ON_ERROR(identity.validate());
    if (operationId.is_nil() || vChainId.chainId == ChainId{} || checksum.type != ChecksumType::CRC32C ||
        payload.data.size() > kEcFragmentRpcMaxBytes) {
      return makeError(StatusCode::kInvalidArg, "invalid immutable fragment creation request");
    }
    return Void{};
  }
};

// Creation and reconciliation responses confirm this target's synchronous
// engine commit. A read response carries the same identity fields but does
// not establish a new durability barrier. Metadata publication and cluster
// authentication remain separate contracts.
struct EcFragmentReceipt {
  SERDE_STRUCT_FIELD(version, kEcFragmentProtocolVersion);
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(length, uint32_t{});
  SERDE_STRUCT_FIELD(checksum, ChecksumInfo{});
};

struct EcCreateRsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(result, (Result<EcFragmentReceipt>{makeError(StorageClientCode::kNotInitialized)}));
};

struct EcReadReq {
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedLength, uint32_t{});
  SERDE_STRUCT_FIELD(checksum, ChecksumInfo{});
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(userInfo, flat::UserInfo{});

 public:
  Result<Void> validate() const {
    RETURN_ON_ERROR(identity.validate());
    if (operationId.is_nil() || vChainId.chainId == ChainId{} || checksum.type != ChecksumType::CRC32C ||
        expectedLength > kEcFragmentRpcMaxBytes) {
      return makeError(StatusCode::kInvalidArg, "invalid immutable fragment read request");
    }
    return Void{};
  }
};

struct EcReadResult {
  SERDE_STRUCT_FIELD(receipt, EcFragmentReceipt{});
  SERDE_STRUCT_FIELD(payload, EcPayload{});
};

struct EcReadRsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(result, (Result<EcReadResult>{makeError(StorageClientCode::kNotInitialized)}));
};

// Explicit durability reconciliation after an uncertain create response.
// This operation never creates a missing fragment or repairs a partial write.
struct EcReconcileReq {
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedLength, uint32_t{});
  SERDE_STRUCT_FIELD(checksum, ChecksumInfo{});
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(userInfo, flat::UserInfo{});

 public:
  Result<Void> validate() const {
    RETURN_ON_ERROR(identity.validate());
    if (operationId.is_nil() || vChainId.chainId == ChainId{} || checksum.type != ChecksumType::CRC32C ||
        expectedLength > kEcFragmentRpcMaxBytes) {
      return makeError(StatusCode::kInvalidArg, "invalid immutable fragment reconciliation request");
    }
    return Void{};
  }
};

struct EcReconcileRsp {
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(result, (Result<EcFragmentReceipt>{makeError(StorageClientCode::kNotInitialized)}));
};

static_assert(serde::Serializable<EcPayload>);
static_assert(serde::Serializable<EcFragmentIdentity>);
static_assert(serde::Serializable<EcCreateTargetReq>);
static_assert(serde::Serializable<EcCreateTargetRsp>);
static_assert(serde::Serializable<EcCreateReq>);
static_assert(serde::Serializable<EcFragmentReceipt>);
static_assert(serde::Serializable<EcCreateRsp>);
static_assert(serde::Serializable<EcReadReq>);
static_assert(serde::Serializable<EcReadResult>);
static_assert(serde::Serializable<EcReadRsp>);
static_assert(serde::Serializable<EcReconcileReq>);
static_assert(serde::Serializable<EcReconcileRsp>);

}  // namespace hf3fs::storage
