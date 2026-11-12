#include "meta/store/EcRangeCatalog.h"

#include <algorithm>

#include "common/kv/KeyPrefix.h"
#include "common/utils/SerDeser.h"
#include "meta/store/EcV2GcCatalog.h"
#include "meta/store/EcV2PublishedCatalog.h"

namespace hf3fs::meta::server {
namespace {
using Tx = kv::IReadWriteTransaction;

struct RequestAlias {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(rangeId, Uuid::zero());
};

EcOwner ownerOf(const EcRangeReq &req) { return {req.user.uid, req.client.uuid}; }
std::string rangeKey(const EcRangeReq &req) {
  return Serializer::serRawArgs(kv::KeyPrefix::EcFileRange, req.client.uuid, uint8_t{1}, req.rangeId);
}
std::string requestKey(const EcRangeReq &req) {
  return Serializer::serRawArgs(kv::KeyPrefix::EcFileRange, req.client.uuid, uint8_t{2}, req.uuid);
}

template <typename T>
CoTryTask<std::optional<T>> load(Tx &txn, const std::string &key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  if ((**bytes).size() > kEcFileRangeMaxRecordBytes)
    co_return makeError(StatusCode::kDataCorruption, "oversized EC range record");
  T value;
  if (!serde::deserialize(value, **bytes) || value.version != 1)
    co_return makeError(StatusCode::kDataCorruption, "invalid EC range record");
  co_return value;
}

Result<Void> validateSnapshot(const EcRangeSnapshot &value) {
  const auto &selection = value.selection;
  RETURN_ON_ERROR(selection.matchesLayout(value.file.layout));
  if (value.version != 1 || value.owner.client.is_nil() || value.requestId.is_nil() || value.rangeId.is_nil() ||
      value.file.object != selection.object || !value.file.epoch || value.stripeCount > selection.pinCount)
    return makeError(StatusCode::kDataCorruption, "invalid permanent range identity");
  const uint64_t readable =
      selection.offset >= value.file.length ? 0 : std::min(selection.length, value.file.length - selection.offset);
  const uint64_t stripeBytes = uint64_t{value.file.layout.shardBytes} * 10;
  const uint64_t count =
      readable ? ((selection.offset + readable - 1) / stripeBytes - selection.offset / stripeBytes + 1) : 0;
  if (value.readableLength != readable || value.stripeCount != count)
    return makeError(StatusCode::kDataCorruption, "range result disagrees with captured EOF");
  for (size_t i = 0; i != value.stripes.size(); ++i) {
    const auto &entry = value.stripes[i];
    if (i >= value.stripeCount) {
      if (!serde::equals(entry, EcRangeStripe{}))
        return makeError(StatusCode::kDataCorruption, "unused range result slot is not canonical");
      continue;
    }
    const auto &pin = entry.snapshot;
    const auto &requested = selection.pins[i];
    // A requested stripe was already computed by checked division in
    // matchesLayout, so its start cannot overflow uint64_t.
    const uint64_t start = requested.stripe * stripeBytes;
    const uint64_t logicalLength = std::min(stripeBytes, value.file.length - start);
    if (entry.state != EcRangePinState::Active || pin.version != kEcBindingCatalogVersion ||
        pin.object != selection.object || pin.pin != requested.pin || pin.stripe != requested.stripe || !pin.revision ||
        !pin.generation || !serde::equals(pin.owner, value.owner) || entry.logicalLength != logicalLength ||
        !logicalLength || entry.contentSha256 == storage::EcSha256{})
      return makeError(StatusCode::kDataCorruption, "invalid permanent range stripe");
  }
  return Void{};
}

CoTryTask<std::optional<EcRangeSnapshot>> previous(Tx &txn, const EcRangeReq &req) {
  auto result = co_await load<EcRangeSnapshot>(txn, rangeKey(req));
  CO_RETURN_ON_ERROR(result);
  auto alias = co_await load<RequestAlias>(txn, requestKey(req));
  CO_RETURN_ON_ERROR(alias);
  const auto owner = ownerOf(req);
  if (*result) {
    const auto &value = **result;
    if (!serde::equals(value.owner, owner))
      co_return makeError(MetaCode::kNoPermission, "range belongs to another effective owner");
    if (value.requestId != req.uuid || value.rangeId != req.rangeId || !serde::equals(value.selection, req.selection))
      co_return makeError(StatusCode::kTokenMismatch, "range identity reused with a different complete request");
    CO_RETURN_ON_ERROR(validateSnapshot(value));
  }
  if (*alias) {
    if (!serde::equals((**alias).owner, owner))
      co_return makeError(MetaCode::kNoPermission, "request belongs to another effective owner");
    if ((**alias).requestId != req.uuid || (**alias).rangeId != req.rangeId)
      co_return makeError(StatusCode::kTokenMismatch, "request UUID reused for another range");
  }
  if (bool(*result) != bool(*alias))
    co_return makeError(StatusCode::kDataCorruption, "range record and permanent request alias disagree");
  co_return *result;
}

CoTryTask<EcRangePinState> observePin(Tx &txn, const EcRangeSnapshot &range, const EcRangeStripe &entry) {
  const auto &snapshot = entry.snapshot;
  auto pin = co_await EcCatalog::getPin(txn, snapshot.object, snapshot.pin);
  CO_RETURN_ON_ERROR(pin);
  if (pin->object != snapshot.object || pin->id != snapshot.pin || pin->stripe != snapshot.stripe ||
      pin->revision != snapshot.revision || !serde::equals(pin->owner, range.owner))
    co_return makeError(StatusCode::kDataCorruption, "range pin no longer matches its permanent snapshot");

  // Read ECVP without using getPinSnapshot/acquireRead: those helpers reject
  // released pins and may establish protection. Query must only observe.
  std::string key(kv::toStr(kv::KeyPrefix::EcV2Pin));
  key.append(snapshot.object.incarnation.asStringView());
  key.append(snapshot.pin.asStringView());
  auto stored = co_await load<EcV2PinSnapshot>(txn, key);
  CO_RETURN_ON_ERROR(stored);
  if (!*stored || !serde::equals(**stored, snapshot))
    co_return makeError(StatusCode::kDataCorruption, "range ECVP snapshot differs");
  auto historical = co_await EcCatalog::getManifest(txn, snapshot.object, snapshot.stripe, snapshot.revision);
  CO_RETURN_ON_ERROR(historical);
  if (historical->manifest.generation != snapshot.generation ||
      historical->manifest.logicalLength != entry.logicalLength || historical->manifest.object != snapshot.object ||
      historical->manifest.stripe != snapshot.stripe || historical->manifest.revision != snapshot.revision)
    co_return makeError(StatusCode::kDataCorruption, "range historical revision differs");
  auto content = co_await EcV2PublishedCatalog::get(txn, snapshot.object, snapshot.stripe, snapshot.revision);
  CO_RETURN_ON_ERROR(content);
  if (content->generation != snapshot.generation || content->logicalLength != entry.logicalLength ||
      content->contentSha256 != entry.contentSha256)
    co_return makeError(StatusCode::kDataCorruption, "range historical content differs");
  auto drain =
      co_await EcV2DrainCatalog::get(txn, snapshot.object, storage::EcGrantScope::ReadPin, snapshot.pin, range.owner);
  CO_RETURN_ON_ERROR(drain);
  if (*drain) {
    const auto &identity = (**drain).identity;
    if (identity.object != snapshot.object || identity.scopeId != snapshot.pin ||
        identity.kind != storage::EcGrantScope::ReadPin || identity.generation != snapshot.generation ||
        identity.revision != snapshot.revision || !serde::equals(identity.owner, range.owner) ||
        identity.endpoints.digest != snapshot.endpointSetDigest || identity.endpoints.count != 12)
      co_return makeError(StatusCode::kDataCorruption, "range drain identity differs");
  }
  if (pin->released) {
    if (!*drain || (**drain).state != EcV2DrainState::ReadReleased)
      co_return makeError(StatusCode::kDataCorruption, "released range pin has no terminal drain");
    co_return EcRangePinState::Released;
  }
  if (!historical->pins || historical->referencesReleased)
    co_return makeError(StatusCode::kDataCorruption, "active range pin lost its manifest reference");
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::requireProtectedScope(txn,
                                                                   snapshot.object,
                                                                   storage::EcGrantScope::ReadPin,
                                                                   snapshot.pin,
                                                                   range.owner));
  if (*drain) {
    if ((**drain).state != EcV2DrainState::Closing)
      co_return makeError(StatusCode::kDataCorruption, "unreleased range pin has terminal drain state");
    co_return EcRangePinState::Closing;
  }
  co_return EcRangePinState::Active;
}

CoTryTask<EcRangeRsp> observed(Tx &txn, EcRangeSnapshot value, bool acquire) {
  CO_RETURN_ON_ERROR(co_await requireTrackedEcFile(txn, value.selection.object));
  for (size_t i = 0; i != value.stripeCount; ++i) {
    auto state = co_await observePin(txn, value, value.stripes[i]);
    CO_RETURN_ON_ERROR(state);
    if (acquire && *state != EcRangePinState::Active)
      co_return makeError(StatusCode::kTokenStale, "range pin is closing or released; it cannot be revived");
    value.stripes[i].state = *state;
  }
  EcRangeRsp rsp;
  rsp.snapshot = std::move(value);
  co_return rsp;
}
}  // namespace

CoTryTask<EcRangeRsp> EcRangeCatalog::acquire(Tx &txn, const EcRangeReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  auto old = co_await previous(txn, req);
  CO_RETURN_ON_ERROR(old);
  auto file = co_await loadV2File(txn, req.user, req.selection.object, AccessType::READ);
  CO_RETURN_ON_ERROR(file);
  CO_RETURN_ON_ERROR(co_await requireTrackedEcFile(txn, req.selection.object));
  CO_RETURN_ON_ERROR(req.selection.matchesLayout(*file->inode.asFile().layout.ecLayout()));
  if (*old) co_return co_await observed(txn, std::move(**old), true);

  EcRangeSnapshot value;
  value.owner = ownerOf(req);
  value.requestId = req.uuid;
  value.rangeId = req.rangeId;
  value.selection = req.selection;
  value.file = ecFileState(*file);
  const auto &selection = value.selection;
  const uint64_t stripeBytes = uint64_t{value.file.layout.shardBytes} * 10;
  value.readableLength =
      selection.offset >= value.file.length ? 0 : std::min(selection.length, value.file.length - selection.offset);
  value.stripeCount = value.readableLength ? (selection.offset + value.readableLength - 1) / stripeBytes -
                                                 selection.offset / stripeBytes + 1
                                           : 0;
  // Conflict-read every used pin before any pin mutation. Existing pins are
  // never adopted, even when owned by the same user and namespace.
  for (size_t i = 0; i != value.stripeCount; ++i) {
    auto oldPin = co_await EcCatalog::getPin(txn, selection.object, selection.pins[i].pin);
    if (oldPin) co_return makeError(StatusCode::kTokenDuplicated, "range requires fresh pin identities");
    if (oldPin.error().code() != StatusCode::kKVStoreNotFound) co_return makeError(oldPin.error());
    // Missing ECPN does not permit adopting orphaned ECVP/ECVD/ECGS/ECVI state.
    // In particular an old Closing drain must never become a fresh Active pin.
    for (const auto prefix :
         {kv::KeyPrefix::EcV2Pin, kv::KeyPrefix::EcV2Drain, kv::KeyPrefix::EcGcScope, kv::KeyPrefix::EcV2Issuance}) {
      std::string key(kv::toStr(prefix));
      key.append(selection.object.incarnation.asStringView());
      if (prefix != kv::KeyPrefix::EcV2Pin) key.push_back(static_cast<char>(storage::EcGrantScope::ReadPin));
      key.append(selection.pins[i].pin.asStringView());
      auto side = co_await txn.get(key);
      CO_RETURN_ON_ERROR(side);
      if (*side)
        co_return makeError(StatusCode::kTokenDuplicated, "range pin has existing snapshot, drain or GC scope state");
    }
  }
  for (size_t i = 0; i != value.stripeCount; ++i) {
    const auto &requested = selection.pins[i];
    auto pinned =
        co_await EcV2BindingCatalog::acquireRead(txn, selection.object, requested.stripe, requested.pin, value.owner);
    CO_RETURN_ON_ERROR(pinned);
    auto content =
        co_await EcV2PublishedCatalog::get(txn, selection.object, requested.stripe, pinned->manifest.revision);
    CO_RETURN_ON_ERROR(content);
    const auto expectedLength = std::min(stripeBytes, value.file.length - requested.stripe * stripeBytes);
    if (pinned->manifest.logicalLength != expectedLength || content->logicalLength != expectedLength ||
        content->generation != pinned->manifest.generation)
      co_return makeError(StatusCode::kDataCorruption, "range contains a missing or inconsistent logical tail");
    auto &entry = value.stripes[i];
    entry.snapshot = std::move(pinned->snapshot);
    entry.logicalLength = expectedLength;
    entry.contentSha256 = content->contentSha256;
    entry.state = EcRangePinState::Active;
  }
  CO_RETURN_ON_ERROR(validateSnapshot(value));
  const auto bytes = serde::serialize(value);
  if (bytes.size() > kEcFileRangeMaxRecordBytes)
    co_return makeError(StatusCode::kInvalidArg, "range record exceeds its fixed byte budget");
  RequestAlias alias;
  alias.owner = value.owner;
  alias.requestId = req.uuid;
  alias.rangeId = req.rangeId;
  CO_RETURN_ON_ERROR(co_await txn.set(rangeKey(req), bytes));
  CO_RETURN_ON_ERROR(co_await txn.set(requestKey(req), serde::serialize(alias)));
  EcRangeRsp rsp;
  rsp.snapshot = std::move(value);
  co_return rsp;
}

CoTryTask<EcRangeRsp> EcRangeCatalog::query(Tx &txn, const EcRangeReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  auto old = co_await previous(txn, req);
  CO_RETURN_ON_ERROR(old);
  // Cleanup recovery intentionally bypasses inode liveness and current ACL.
  // It still checks immutable object birth and the exact authenticated owner.
  CO_RETURN_ON_ERROR(co_await requireTrackedEcFile(txn, req.selection.object));
  if (!*old) co_return makeError(StatusCode::kKVStoreNotFound, "no range acquisition observed for this fixed identity");
  co_return co_await observed(txn, std::move(**old), false);
}
}  // namespace hf3fs::meta::server
