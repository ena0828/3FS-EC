#pragma once

#include <algorithm>

#include "common/kv/KeyPrefix.h"
#include "meta/store/EcV2ReservationCatalog.h"

namespace hf3fs::meta::server::ec_v2_lifecycle {
using Tx = kv::IReadWriteTransaction;

inline bool same(const auto &left, const auto &right) {
  const auto a = serde::serialize(left);
  const auto b = serde::serialize(right);
  return std::string_view(a) == std::string_view(b);
}
inline Result<Void> ownerMatches(const EcOwner &left, const EcOwner &right) {
  if (right.client.is_nil()) return makeError(StatusCode::kInvalidArg, "V2 lifecycle owner namespace is zero");
  if (left.uid != right.uid || left.client != right.client) {
    return makeError(MetaCode::kNoPermission, "V2 lifecycle belongs to a different owner or namespace");
  }
  return Void{};
}
inline Result<Void> scopeValid(storage::EcGrantScope kind, const Uuid &id) {
  if (id.is_nil() || (kind != storage::EcGrantScope::ReadPin && kind != storage::EcGrantScope::WriteOperation)) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 lifecycle scope");
  }
  return Void{};
}
inline std::string reservationKey(const EcObjectRef &object, const Uuid &operation) {
  std::string out(kv::toStr(kv::KeyPrefix::EcV2Reservation));
  out.append(object.incarnation.asStringView());
  out.append(operation.asStringView());
  return out;
}
inline std::string drainKey(const EcObjectRef &object, storage::EcGrantScope kind, const Uuid &id) {
  std::string out(kv::toStr(kv::KeyPrefix::EcV2Drain));
  out.append(object.incarnation.asStringView());
  out.push_back(static_cast<char>(kind));
  out.append(id.asStringView());
  return out;
}
inline std::string issuanceKey(const EcObjectRef &object, storage::EcGrantScope kind, const Uuid &id) {
  std::string out(kv::toStr(kv::KeyPrefix::EcV2Issuance));
  out.append(object.incarnation.asStringView());
  out.push_back(static_cast<char>(kind));
  out.append(id.asStringView());
  return out;
}
struct IssuanceSequence {
  SERDE_STRUCT_FIELD(version, kEcV2LifecycleVersion);
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
};
template <typename T>
CoTryTask<std::optional<T>> load(Tx &txn, std::string key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  if ((**bytes).size() > (64u << 10)) co_return makeError(StatusCode::kDataCorruption, "oversized V2 lifecycle record");
  T value;
  if (!serde::deserialize(value, **bytes) || value.version != kEcV2LifecycleVersion) {
    co_return makeError(StatusCode::kDataCorruption, "invalid V2 lifecycle record format");
  }
  co_return value;
}
template <typename T>
CoTryTask<Void> save(Tx &txn, std::string key, const T &value) {
  const auto bytes = serde::serialize(value);
  if (bytes.size() > (64u << 10)) co_return makeError(StatusCode::kInvalidArg, "oversized V2 lifecycle record");
  CO_RETURN_ON_ERROR(co_await txn.set(key, bytes));
  co_return Void{};
}
// Issuance conflict-reads and increments this key. Closing conflicts through
// ECVD; it deliberately does not read ECVI or wait on concurrent issuers.
// A real increment cannot be eliminated as a same-value RYW write.
inline CoTryTask<uint64_t> readIssuanceSequence(Tx &txn,
                                                const EcObjectRef &object,
                                                storage::EcGrantScope kind,
                                                const Uuid &scope) {
  auto record = co_await load<IssuanceSequence>(txn, issuanceKey(object, kind, scope));
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return uint64_t{};
  if (!(**record).sequence) co_return makeError(StatusCode::kDataCorruption, "zero V2 issuance sequence");
  co_return (**record).sequence;
}
inline Result<Void> endpointValid(const EcV2PhysicalEndpoint &endpoint) {
  if (endpoint.placement.chain == storage::ChainId{} || endpoint.placement.target == storage::TargetId{} ||
      endpoint.placement.node == flat::NodeId{} || endpoint.engineUuid.is_nil() ||
      endpoint.targetIncarnation.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "V2 lifecycle requires an explicit physical instance");
  }
  return Void{};
}
inline Result<Void> addEndpoint(EcV2OperationEndpoints &set, const EcV2PhysicalEndpoint &endpoint) {
  RETURN_ON_ERROR(endpointValid(endpoint));
  if (set.count > set.endpoints.size()) return makeError(StatusCode::kDataCorruption);
  if (std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, endpoint) !=
      set.endpoints.begin() + set.count)
    return Void{};
  if (set.count == set.endpoints.size()) return makeError(StatusCode::kInvalidArg, "more than 24 V2 instances");
  set.endpoints[set.count++] = endpoint;
  return Void{};
}
inline Result<storage::EcSha256> setDigest(const EcV2OperationEndpoints &set) {
  if (!set.count || set.count > set.endpoints.size())
    return makeError(StatusCode::kDataCorruption, "invalid V2 endpoint count");
  std::array<storage::EcScopeEndpoint, 24> endpoints{};
  for (size_t i = 0; i != set.endpoints.size(); ++i) {
    if (i >= set.count) {
      if (set.endpoints[i] != EcV2PhysicalEndpoint{})
        return makeError(StatusCode::kDataCorruption, "nonzero unused endpoint");
      continue;
    }
    RETURN_ON_ERROR(endpointValid(set.endpoints[i]));
    for (size_t j = 0; j != i; ++j) {
      if (set.endpoints[i] == set.endpoints[j])
        return makeError(StatusCode::kDataCorruption, "duplicate endpoint slot");
    }
    endpoints[i] = set.endpoints[i].controlEndpoint();
  }
  return storage::computeEcScopeEndpointDigest(std::span(endpoints).first(set.count));
}
inline Result<Void> setValid(const EcV2OperationEndpoints &set) {
  CHECK_RESULT(digest, setDigest(set));
  if (digest != set.digest) return makeError(StatusCode::kDataCorruption, "V2 endpoint digest mismatch");
  return Void{};
}
inline Result<Void> drainValid(const EcV2DrainRecord &record) {
  const auto &id = record.identity;
  RETURN_ON_ERROR(scopeValid(id.kind, id.scopeId));
  RETURN_ON_ERROR(setValid(id.endpoints));
  if (record.version != kEcV2LifecycleVersion || id.object.incarnation.is_nil() || id.owner.client.is_nil() ||
      id.clusterAuthority.is_nil() || id.revocationId.is_nil() || !id.objectEpoch || !id.generation || !id.revision ||
      (record.state != EcV2DrainState::Closing && record.state != EcV2DrainState::ReadReleased &&
       record.state != EcV2DrainState::Published && record.state != EcV2DrainState::Aborted)) {
    return makeError(StatusCode::kDataCorruption, "invalid V2 drain identity or state");
  }
  if ((id.kind == storage::EcGrantScope::ReadPin &&
       (record.verifiedManifest || record.verifiedContentSha256 != storage::EcSha256{} ||
        (record.state != EcV2DrainState::Closing && record.state != EcV2DrainState::ReadReleased))) ||
      (id.kind == storage::EcGrantScope::WriteOperation && record.state == EcV2DrainState::ReadReleased) ||
      (record.verifiedManifest.has_value() != (record.verifiedContentSha256 != storage::EcSha256{})) ||
      (record.state == EcV2DrainState::Published && !record.verifiedManifest)) {
    return makeError(StatusCode::kDataCorruption, "V2 drain terminal/evidence kind mismatch");
  }
  for (size_t i = id.endpoints.count; i != record.observations.size(); ++i) {
    if (record.observations[i]) return makeError(StatusCode::kDataCorruption, "observation beyond fixed endpoint set");
  }
  return Void{};
}
}  // namespace hf3fs::meta::server::ec_v2_lifecycle
