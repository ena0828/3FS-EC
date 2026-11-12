#pragma once

#include <limits>

#include "common/kv/KeyPrefix.h"
#include "fbs/meta/EcFileTree.h"

namespace hf3fs::meta::server::ec_tree_detail {
inline std::string objectKey(kv::KeyPrefix prefix, const EcObjectRef &object) {
  std::string key(kv::toStr(prefix));
  key.append(object.incarnation.asStringView());
  return key;
}
inline std::string idKey(kv::KeyPrefix prefix, const EcObjectRef &object, const Uuid &id) {
  auto key = objectKey(prefix, object);
  key.append(id.asStringView());
  return key;
}
inline std::string manifestKey(kv::KeyPrefix prefix, const EcObjectRef &object, uint64_t stripe, uint64_t revision) {
  auto key = objectKey(prefix, object);
  for (auto value : {stripe, revision})
    for (int shift = 56; shift >= 0; shift -= 8) key.push_back(static_cast<char>(value >> shift));
  return key;
}
inline Result<std::string> allocationKey(kv::KeyPrefix prefix, const storage::EcFragmentIdentity &identity) {
  CHECK_RESULT(chunk, identity.chunkId());
  std::string key(kv::toStr(prefix));
  key.append(chunk.data());
  return key;
}
inline bool same(const auto &left, const auto &right) {
  const auto a = serde::serialize(left), b = serde::serialize(right);
  return std::string_view(a) == std::string_view(b);
}
template <typename T>
CoTryTask<std::optional<T>> load(kv::IReadWriteTransaction &txn, std::string key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  if ((**bytes).size() > (64u << 10)) co_return makeError(StatusCode::kDataCorruption, "oversized EC tree record");
  T record;
  if (!serde::deserialize(record, **bytes) || record.version != kEcFileTreeVersion)
    co_return makeError(StatusCode::kDataCorruption, "invalid EC tree record");
  co_return record;
}
template <typename T>
CoTryTask<T> require(kv::IReadWriteTransaction &txn, std::string key) {
  auto record = co_await load<T>(txn, std::move(key));
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return makeError(StatusCode::kDataCorruption, "missing EC tree record");
  co_return std::move(**record);
}
template <typename T>
CoTryTask<Void> store(kv::IReadWriteTransaction &txn, std::string key, const T &record) {
  const auto bytes = serde::serialize(record);
  if (bytes.size() > (64u << 10)) co_return makeError(StatusCode::kInvalidArg, "EC tree record exceeds bound");
  CO_RETURN_ON_ERROR(co_await txn.set(key, bytes));
  co_return Void{};
}
inline Result<uint64_t> stripeStart(uint64_t stripe, uint32_t shardBytes) {
  if (!shardBytes || shardBytes > storage::kEcFragmentRpcMaxBytes)
    return makeError(StatusCode::kInvalidArg, "invalid EC tree shard capacity");
  const uint64_t size = uint64_t(shardBytes) * 10;
  if (stripe > std::numeric_limits<uint64_t>::max() / size)
    return makeError(StatusCode::kInvalidArg, "EC tree stripe offset overflow");
  return stripe * size;
}
inline Result<uint64_t> rangeEnd(uint64_t offset, uint64_t length) {
  if (length > std::numeric_limits<uint64_t>::max() - offset)
    return makeError(StatusCode::kInvalidArg, "EC tree range overflow");
  return offset + length;
}
inline uint64_t prefix(uint64_t stripe, uint8_t level) {
  return level == 15 ? 0 : (stripe >> (4 * (level + 1))) << (4 * (level + 1));
}
inline size_t index(uint64_t stripe, uint8_t level) { return (stripe >> (4 * level)) & 15; }
}  // namespace hf3fs::meta::server::ec_tree_detail
