#pragma once

#include <cstddef>
#include <folly/hash/Checksum.h>
#include <optional>
#include <stdexcept>
#include <vector>

#include "common/serde/Serde.h"
#include "erasure/ECLayout.h"
#include "fbs/mgmtd/MgmtdTypes.h"

namespace hf3fs::storage {

// Wire protocol v1, independent of the on-disk shard format. Field declaration
// order is wire order. No disk index/path, CRAQ commit or placement is implied.
inline constexpr uint16_t kECShardRpcVersion = 1;
inline constexpr size_t kECShardPayloadLimit = erasure::ECLayout::kShardSize;
inline constexpr size_t kECShardEnvelopeLimit = kECShardPayloadLimit + 256;

// Stable domain outcomes, not global StatusCode additions or StoreError casts.
// The framework still wraps each response in Result<Rsp> for RPC errors.
// Default is a failure; a successfully decoded response is not business success.
enum class ECShardStatus : uint16_t {
  InternalError = 0,
  Created = 1,
  ExistingVerified = 2,
  Ok = 3,
  ContentConflict = 16,
  TargetUnavailable = 17,
  ECDisabled = 18,
  InvalidRequest = 19,
  QueueFull = 20,
  BackendError = 21,
  NotFound = 22,
  CorruptRecord = 23,
};

struct ECShardKeyDTO {
  SERDE_STRUCT_FIELD(inodeId, uint64_t{});
  SERDE_STRUCT_FIELD(logicalChunkIndex, uint32_t{});
  SERDE_STRUCT_FIELD(stripeIndex, uint32_t{});
  SERDE_STRUCT_FIELD(shardIndex, uint8_t{});

 public:
  bool valid() const { return stripeIndex == 0 && shardIndex < 12; }
};

struct ECShardPayload {
  std::vector<uint8_t> bytes;
  // Diagnostic output remains bounded and does not print binary payloads.
  uint64_t serdeToReadable() const { return bytes.size(); }
};

struct ECShardRecordDTO {
  SERDE_STRUCT_FIELD(key, ECShardKeyDTO{});
  SERDE_STRUCT_FIELD(version, uint64_t{});
  SERDE_STRUCT_FIELD(scheme, uint32_t{erasure::ECLayout::kEncodingScheme});
  SERDE_STRUCT_FIELD(format, uint32_t{erasure::ECLayout::kFormatVersion});
  // Original logical chunk length, NOT the physical shard length.
  SERDE_STRUCT_FIELD(validBytes, uint32_t{});
  SERDE_STRUCT_FIELD(payloadChecksum, uint32_t{});
  SERDE_STRUCT_FIELD(payload, ECShardPayload{});

 public:
  bool valid() const {
    return key.valid() && version != 0 && scheme == erasure::ECLayout::kEncodingScheme &&
           format == erasure::ECLayout::kFormatVersion && validBytes <= erasure::ECLayout::kChunkSize &&
           payload.bytes.size() == kECShardPayloadLimit &&
           payloadChecksum == folly::crc32c(payload.bytes.data(), payload.bytes.size(), 0);
  }
};

struct WriteECShardReq {
  SERDE_STRUCT_FIELD(protocolVersion, uint16_t{kECShardRpcVersion});
  SERDE_STRUCT_FIELD(targetId, flat::TargetId{});
  SERDE_STRUCT_FIELD(record, ECShardRecordDTO{});

 public:
  bool valid() const { return protocolVersion == kECShardRpcVersion && targetId != flat::TargetId{} && record.valid(); }
};

struct ReadECShardReq {
  SERDE_STRUCT_FIELD(protocolVersion, uint16_t{kECShardRpcVersion});
  SERDE_STRUCT_FIELD(targetId, flat::TargetId{});
  SERDE_STRUCT_FIELD(key, ECShardKeyDTO{});
  SERDE_STRUCT_FIELD(version, uint64_t{});
  SERDE_STRUCT_FIELD(scheme, uint32_t{erasure::ECLayout::kEncodingScheme});
  SERDE_STRUCT_FIELD(format, uint32_t{erasure::ECLayout::kFormatVersion});

 public:
  bool valid() const {
    return protocolVersion == kECShardRpcVersion && targetId != flat::TargetId{} && key.valid() && version != 0 &&
           scheme == erasure::ECLayout::kEncodingScheme && format == erasure::ECLayout::kFormatVersion;
  }
};

inline bool ecShardCommonFailure(ECShardStatus status) {
  switch (status) {
    case ECShardStatus::InternalError:
    case ECShardStatus::TargetUnavailable:
    case ECShardStatus::ECDisabled:
    case ECShardStatus::InvalidRequest:
    case ECShardStatus::QueueFull:
    case ECShardStatus::BackendError:
    case ECShardStatus::CorruptRecord:
      return true;
    default:
      return false;
  }
}

struct WriteECShardRsp {
  SERDE_STRUCT_FIELD(protocolVersion, uint16_t{kECShardRpcVersion});
  SERDE_STRUCT_FIELD(status, ECShardStatus::InternalError);

 public:
  bool succeeded() const {
    return protocolVersion == kECShardRpcVersion &&
           (status == ECShardStatus::Created || status == ECShardStatus::ExistingVerified);
  }
  bool valid() const {
    return protocolVersion == kECShardRpcVersion &&
           (succeeded() || ecShardCommonFailure(status) || status == ECShardStatus::ContentConflict);
  }
};

struct ReadECShardRsp {
  SERDE_STRUCT_FIELD(protocolVersion, uint16_t{kECShardRpcVersion});
  SERDE_STRUCT_FIELD(status, ECShardStatus::InternalError);
  SERDE_STRUCT_FIELD(record, std::optional<ECShardRecordDTO>{});

 public:
  bool succeeded() const {
    return protocolVersion == kECShardRpcVersion && status == ECShardStatus::Ok && record && record->valid();
  }
  bool valid() const {
    if (protocolVersion != kECShardRpcVersion) return false;
    if (status == ECShardStatus::Ok) return succeeded();
    return !record && (ecShardCommonFailure(status) || status == ECShardStatus::NotFound);
  }
};

}  // namespace hf3fs::storage

namespace hf3fs::serde::ec_shard_detail {

// Match the existing Varint32 length prefix, but reject overflow/noncanonical
// encodings before slicing or allocating. Never resize from an untrusted count.
inline Result<std::string_view> boundedBytes(In<std::string_view> &in, size_t limit) {
  uint32_t length = 0;
  for (unsigned i = 0; i < 5; ++i) {
    if (in.str().empty()) return makeError(StatusCode::kSerdeInsufficientLength);
    const uint8_t byte = static_cast<uint8_t>(in.str().front());
    in.str().remove_prefix(1);
    if (i == 4 && byte > 15) return makeError(StatusCode::kInvalidArg);
    length |= uint32_t(byte & 127) << (7 * i);
    if (!(byte & 128)) {
      if ((i != 0 && byte == 0) || length > limit) return makeError(StatusCode::kInvalidArg);
      if (length > in.str().size()) return makeError(StatusCode::kSerdeInsufficientLength);
      auto bytes = in.str().substr(0, length);
      in.str().remove_prefix(length);
      return bytes;
    }
  }
  return makeError(StatusCode::kInvalidArg);
}

// New EC tables require every field and reject bytes left inside the table.
// Existing RPC DTOs keep their permissive/version-extensible serde untouched.
template <class T, bool WholeMessage = false>
struct StrictTable {
  static void serialize(const T &o, auto &out) {
    auto start = out.tableBegin(false);
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      refl::Helper::iterate<T, true>([&](auto field) { serde::serialize(o.*field.getter, out); });
    } else {
      refl::Helper::iterate<T>([&](auto field) {
        out.key(field.name);
        serde::serialize(o.*field.getter, out);
      });
    }
    out.tableEnd(start);
  }

  static Result<Void> deserialize(T &o, In<std::string_view> &in) {
    auto bytes = boundedBytes(in, storage::kECShardEnvelopeLimit);
    RETURN_AND_LOG_ON_ERROR(bytes);
    In<std::string_view> table(*bytes);
    T decoded;
    auto result = refl::Helper::iterate<T>(
        [&](auto field) -> Result<Void> { return serde::deserialize(decoded.*field.getter, table); });
    RETURN_AND_LOG_ON_ERROR(result);
    if (table || !decoded.valid()) return makeError(StatusCode::kInvalidArg);
    // RPC DTOs occupy an entire payload (or the final Result value). Do not
    // accept an undersized envelope followed by unaccounted message bytes.
    if constexpr (WholeMessage) {
      if (in) return makeError(StatusCode::kInvalidArg);
    }
    o = std::move(decoded);
    return Void{};
  }
};

}  // namespace hf3fs::serde::ec_shard_detail

namespace hf3fs::serde {

template <>
struct SerdeMethod<storage::ECShardPayload> {
  static void serialize(const storage::ECShardPayload &o, auto &out) {
    // The serializer has no Result return channel; reject before narrowing to
    // the existing uint32 wire prefix, including caller-constructed bad DTOs.
    if (o.bytes.size() > storage::kECShardPayloadLimit) throw std::length_error("EC shard payload too large");
    out.value(std::string_view(reinterpret_cast<const char *>(o.bytes.data()), o.bytes.size()));
  }
  static Result<Void> deserialize(storage::ECShardPayload &o, In<std::string_view> &in) {
    auto bytes = ec_shard_detail::boundedBytes(in, storage::kECShardPayloadLimit);
    RETURN_AND_LOG_ON_ERROR(bytes);
    o.bytes.assign(bytes->begin(), bytes->end());
    return Void{};
  }
};

template <>
struct SerdeMethod<storage::ECShardKeyDTO> : ec_shard_detail::StrictTable<storage::ECShardKeyDTO> {};

template <>
struct SerdeMethod<storage::ECShardRecordDTO> : ec_shard_detail::StrictTable<storage::ECShardRecordDTO> {};

// Optional's generic binary decoder treats unknown tags as empty; the new
// record optional instead accepts exactly 0/1. This specialization is EC-only.
template <>
struct SerdeMethod<std::optional<storage::ECShardRecordDTO>> {
  static void serialize(const std::optional<storage::ECShardRecordDTO> &o, auto &out) {
    if (o) serde::serialize(*o, out);
    serde::serialize(uint8_t(o ? 1 : 0), out);
  }
  static Result<Void> deserialize(std::optional<storage::ECShardRecordDTO> &o, In<std::string_view> &in) {
    uint8_t tag = 0;
    RETURN_AND_LOG_ON_ERROR(serde::deserialize(tag, in));
    if (tag > 1) return makeError(StatusCode::kInvalidArg);
    o.reset();
    if (tag) {
      storage::ECShardRecordDTO record;
      RETURN_AND_LOG_ON_ERROR(serde::deserialize(record, in));
      o = std::move(record);
    }
    return Void{};
  }
  static void serializeReadable(const std::optional<storage::ECShardRecordDTO> &o, auto &out) {
    if (o)
      serde::serialize(*o, out);
    else
      out.value(Optional::NullOpt);
  }
};

template <>
struct SerdeMethod<storage::WriteECShardReq> : ec_shard_detail::StrictTable<storage::WriteECShardReq, true> {};
template <>
struct SerdeMethod<storage::ReadECShardReq> : ec_shard_detail::StrictTable<storage::ReadECShardReq, true> {};
template <>
struct SerdeMethod<storage::WriteECShardRsp> : ec_shard_detail::StrictTable<storage::WriteECShardRsp, true> {};
template <>
struct SerdeMethod<storage::ReadECShardRsp> : ec_shard_detail::StrictTable<storage::ReadECShardRsp, true> {};

static_assert(Serializable<storage::WriteECShardReq> && Serializable<storage::ReadECShardReq>);
static_assert(Serializable<storage::WriteECShardRsp> && Serializable<storage::ReadECShardRsp>);

}  // namespace hf3fs::serde
