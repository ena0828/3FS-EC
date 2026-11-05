#include "meta/store/EcV2BindingCatalog.h"

#include <algorithm>
#include <set>

#include "common/kv/KeyPrefix.h"
#include "meta/store/EcV2GcCatalog.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcV2BindingCatalog::Transaction;
using kv::KeyPrefix;
constexpr size_t kMaximumRecordBytes = 64u << 10;

template <typename T>
bool same(const T &left, const T &right) {
  return std::string_view(serde::serialize(left)) == std::string_view(serde::serialize(right));
}
bool sameOwner(const EcOwner &left, const EcOwner &right) {
  return left.uid == right.uid && left.client == right.client;
}
Result<Void> checkOwner(const EcOwner &expected, const EcOwner &authenticated) {
  if (authenticated.client.is_nil()) return makeError(StatusCode::kInvalidArg, "V2 owner requires a retry namespace");
  if (!sameOwner(expected, authenticated)) return makeError(MetaCode::kNoPermission, "V2 binding owner differs");
  return Void{};
}
Result<Void> checkObject(const EcObjectRef &object) {
  if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax()) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 binding object");
  }
  return Void{};
}
std::string objectKey(KeyPrefix prefix, const Uuid &object) {
  std::string key(kv::toStr(prefix));
  key.append(object.asStringView());
  return key;
}
std::string idKey(KeyPrefix prefix, const Uuid &object, const Uuid &id) {
  auto key = objectKey(prefix, object);
  key.append(id.asStringView());
  return key;
}
Result<std::string> allocationKey(const storage::EcFragmentIdentity &identity) {
  CHECK_RESULT(chunk, identity.chunkId());
  std::string key(kv::toStr(KeyPrefix::EcV2Allocation));
  key.append(chunk.data());
  return key;
}
template <typename T>
CoTryTask<std::optional<T>> load(Tx &txn, std::string key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  if ((**bytes).size() > kMaximumRecordBytes)
    co_return makeError(StatusCode::kDataCorruption, "oversized V2 binding record");
  T record;
  if (!serde::deserialize(record, **bytes) || record.version != kEcBindingCatalogVersion) {
    co_return makeError(StatusCode::kDataCorruption, "invalid V2 binding side-table format");
  }
  co_return record;
}
template <typename T>
CoTryTask<Void> store(Tx &txn, std::string key, const T &record) {
  const auto bytes = serde::serialize(record);
  if (bytes.size() > kMaximumRecordBytes)
    co_return makeError(StatusCode::kInvalidArg, "V2 binding record exceeds bound");
  CO_RETURN_ON_ERROR(co_await txn.set(key, bytes));
  co_return Void{};
}
Result<Void> validEndpoint(const EcV2PhysicalEndpoint &endpoint) {
  if (endpoint.placement.chain == storage::ChainId{} || endpoint.placement.target == storage::TargetId{} ||
      endpoint.placement.node == flat::NodeId{} || endpoint.engineUuid.is_nil() ||
      endpoint.targetIncarnation.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "V2 binding requires an explicit physical endpoint");
  }
  return Void{};
}
Result<Void> validAllocation(const EcV2AllocationBinding &binding) {
  RETURN_ON_ERROR(checkObject(binding.object));
  RETURN_ON_ERROR(validEndpoint(binding.endpoint()));
  RETURN_ON_ERROR(storage::validateEcIntegrity(binding.fragment.identity, binding.fragment.integrity));
  if (binding.version != kEcBindingCatalogVersion || binding.fragment.identity.object != binding.object.incarnation ||
      binding.fragment.operation.is_nil() || binding.writer.client.is_nil()) {
    return makeError(StatusCode::kInvalidArg, "invalid V2 allocation binding");
  }
  return Void{};
}
Result<Void> matchesFragment(const EcV2AllocationBinding &binding,
                             const EcObjectRef &object,
                             const EcFragment &fragment,
                             bool fullDescriptor) {
  RETURN_ON_ERROR(validAllocation(binding));
  if (binding.object != object || !serde::equals(binding.fragment.identity, fragment.identity) ||
      binding.fragment.operation != fragment.operation || binding.fragment.placement != fragment.placement ||
      (fullDescriptor && binding.fragment.integrity != fragment.integrity)) {
    return makeError(StatusCode::kTokenMismatch, "V2 allocation differs from the reserved or published fragment");
  }
  return Void{};
}
Result<Void> validReservation(const EcOperationRecord &op, const EcObjectRecord &object) {
  const auto &intent = op.intent;
  const auto &candidate = op.candidate;
  if (op.version != kEcCatalogVersion || intent.version != kEcCatalogVersion ||
      candidate.version != kEcCatalogVersion || intent.object != object.object || candidate.object != intent.object ||
      intent.operation.is_nil() || op.owner.client.is_nil() || intent.requestDigest == storage::EcSha256{} ||
      !intent.expectedEpoch || !intent.replacementMask || (intent.replacementMask & ~kEcAllShards) ||
      (intent.kind != EcMutationKind::Write && intent.kind != EcMutationKind::Repair) ||
      (intent.kind == EcMutationKind::Write && intent.replacementMask != kEcAllShards) ||
      candidate.stripe != intent.stripe || candidate.logicalLength != intent.logicalLength ||
      !candidate.logicalLength || candidate.logicalLength > uint64_t(object.shardBytes) * 10 || !candidate.generation ||
      !candidate.revision) {
    return makeError(StatusCode::kDataCorruption, "V2 binding found an inconsistent legacy reservation");
  }
  std::set<Uuid> allocations;
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = candidate.fragments[i];
    RETURN_ON_ERROR(fragment.identity.validate());
    if (fragment.identity.object != intent.object.incarnation || fragment.identity.stripe != intent.stripe ||
        fragment.identity.generation != candidate.generation || fragment.identity.shard != i ||
        fragment.placement != intent.placements[i] || fragment.operation.is_nil() ||
        !allocations.insert(fragment.identity.allocation).second ||
        ((intent.replacementMask & (1u << i)) && fragment.operation != intent.operation)) {
      return makeError(StatusCode::kDataCorruption, "V2 reservation contains inconsistent allocation identities");
    }
  }
  return Void{};
}
Result<Void> addEndpoint(EcV2OperationEndpoints &set, const EcV2PhysicalEndpoint &endpoint) {
  RETURN_ON_ERROR(validEndpoint(endpoint));
  for (size_t i = 0; i != set.count; ++i)
    if (set.endpoints[i] == endpoint) return Void{};
  if (set.count == set.endpoints.size()) return makeError(StatusCode::kInvalidArg, "V2 operation exceeds 24 instances");
  set.endpoints[set.count++] = endpoint;
  return Void{};
}
Result<storage::EcSha256> endpointDigest(const EcV2OperationEndpoints &set) {
  if (!set.count || set.count > set.endpoints.size())
    return makeError(StatusCode::kInvalidArg, "invalid V2 endpoint count");
  std::array<storage::EcScopeEndpoint, 24> endpoints;
  for (size_t i = 0; i != set.endpoints.size(); ++i) {
    if (i < set.count) {
      RETURN_ON_ERROR(validEndpoint(set.endpoints[i]));
      for (size_t previous = 0; previous != i; ++previous) {
        if (set.endpoints[previous] == set.endpoints[i])
          return makeError(StatusCode::kDataCorruption, "duplicate V2 endpoint slot");
      }
      endpoints[i] = set.endpoints[i].controlEndpoint();
    } else if (set.endpoints[i] != EcV2PhysicalEndpoint{}) {
      return makeError(StatusCode::kDataCorruption, "nonzero unused V2 endpoint slot");
    }
  }
  return storage::computeEcScopeEndpointDigest(std::span(endpoints).first(set.count));
}
Result<Void> validateOperationBinding(const EcV2OperationBinding &binding,
                                      const EcOperationRecord &op,
                                      const EcObjectRecord &object) {
  RETURN_ON_ERROR(validReservation(op, object));
  if (binding.version != kEcBindingCatalogVersion || !same(binding.intent, op.intent) ||
      !sameOwner(binding.owner, op.owner) || binding.generation != op.candidate.generation ||
      binding.revision != op.candidate.revision) {
    return makeError(StatusCode::kDataCorruption, "V2 operation binding contradicts its catalog operation");
  }
  for (size_t i = 0; i != 12; ++i) {
    const auto &allocation = binding.allocations[i];
    RETURN_ON_ERROR(
        matchesFragment(allocation,
                        op.intent.object,
                        op.candidate.fragments[i],
                        op.state == EcOperationState::Published || op.intent.kind == EcMutationKind::Repair));
    if (allocation.fragment.integrity.wholeLength != object.shardBytes ||
        allocation.fragment.integrity.wholeCrc32c != op.intent.fragmentCrc32c[i] ||
        ((op.intent.replacementMask & (1u << i)) && !sameOwner(allocation.writer, op.owner))) {
      return makeError(StatusCode::kTokenMismatch, "V2 descriptors differ from intent length, CRC or writer");
    }
    const auto endpoint = allocation.endpoint();
    const auto &set = binding.operationEndpoints;
    if (set.count > set.endpoints.size() ||
        std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, endpoint) ==
            set.endpoints.begin() + set.count) {
      return makeError(StatusCode::kDataCorruption, "V2 operation endpoint set omits a candidate");
    }
  }
  CHECK_RESULT(digest, endpointDigest(binding.operationEndpoints));
  if (digest != binding.operationEndpoints.digest)
    return makeError(StatusCode::kDataCorruption, "V2 operation endpoint digest differs");
  return Void{};
}
}  // namespace

CoTryTask<std::optional<EcV2ObjectMode>> EcV2BindingCatalog::getObjectMode(Tx &txn, const EcObjectRef &object) {
  CO_RETURN_ON_ERROR(checkObject(object));
  auto mode = co_await load<EcV2ObjectMode>(txn, objectKey(KeyPrefix::EcV2ObjectMode, object.incarnation));
  CO_RETURN_ON_ERROR(mode);
  if (*mode && (((**mode).mode != 2 && (**mode).mode != kEcGcTrackedObjectMode) || (**mode).object != object ||
                (**mode).creator.client.is_nil() || (**mode).createRequest.is_nil())) {
    co_return makeError(StatusCode::kDataCorruption, "invalid or mismatched immutable V2 object mode");
  }
  if (*mode) CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::validateEnrollment(txn, **mode));
  co_return mode;
}

CoTryTask<EcV2ObjectMode> EcV2BindingCatalog::requireV2Mode(Tx &txn, const EcObjectRef &object) {
  auto mode = co_await getObjectMode(txn, object);
  CO_RETURN_ON_ERROR(mode);
  if (!*mode) co_return makeError(StatusCode::kNotImplemented, "unmarked/V1 object cannot use V2 bindings");
  auto existing = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(existing);
  if (!sameOwner(existing->creator, (**mode).creator) || existing->createRequest != (**mode).createRequest) {
    co_return makeError(StatusCode::kDataCorruption, "V2 mode differs from permanent object creation");
  }
  co_return **mode;
}

CoTryTask<EcObjectRecord> EcV2BindingCatalog::createV2Object(Tx &txn,
                                                             const EcObjectRef &object,
                                                             uint32_t shardBytes,
                                                             bool allowColocated,
                                                             const EcOwner &creator,
                                                             const Uuid &createRequest) {
  co_return co_await createObjectWithMode(txn, object, shardBytes, allowColocated, creator, createRequest, false);
}

CoTryTask<EcObjectRecord> EcV2BindingCatalog::createTrackedV2Object(Tx &txn,
                                                                    const EcObjectRef &object,
                                                                    uint32_t shardBytes,
                                                                    bool allowColocated,
                                                                    const EcOwner &creator,
                                                                    const Uuid &createRequest) {
  co_return co_await createObjectWithMode(txn, object, shardBytes, allowColocated, creator, createRequest, true);
}

CoTryTask<EcObjectRecord> EcV2BindingCatalog::createObjectWithMode(Tx &txn,
                                                                   const EcObjectRef &object,
                                                                   uint32_t shardBytes,
                                                                   bool allowColocated,
                                                                   const EcOwner &creator,
                                                                   const Uuid &createRequest,
                                                                   bool tracked) {
  if (creator.client.is_nil() || createRequest.is_nil())
    co_return makeError(StatusCode::kInvalidArg, "V2 creation requires permanent owner/request identity");
  auto mode = co_await getObjectMode(txn, object);
  CO_RETURN_ON_ERROR(mode);
  auto existing = co_await EcCatalog::getObject(txn, object);
  if (existing) {
    if (!*mode)
      co_return makeError(StatusCode::kNotImplemented, "existing unmarked EC object cannot be upgraded to V2");
    if (!sameOwner((**mode).creator, creator) || (**mode).createRequest != createRequest) {
      co_return makeError(StatusCode::kTokenMismatch, "V2 create identity was reused");
    }
    CO_RETURN_ON_ERROR(co_await requireV2Mode(txn, object));
    co_return co_await EcCatalog::createObject(txn, object, shardBytes, allowColocated, creator, createRequest);
  }
  if (existing.error().code() != StatusCode::kKVStoreNotFound) co_return makeError(existing.error());
  if (*mode) co_return makeError(StatusCode::kDataCorruption, "V2 mode has no object");
  auto created = co_await EcCatalog::createObject(txn, object, shardBytes, allowColocated, creator, createRequest);
  CO_RETURN_ON_ERROR(created);
  EcV2ObjectMode value;
  value.mode = tracked ? kEcGcTrackedObjectMode : 2;
  value.object = object;
  value.creator = creator;
  value.createRequest = createRequest;
  if (tracked) CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::enrollBirth(txn, value));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcV2ObjectMode, object.incarnation), value));
  co_return created;
}

CoTryTask<EcV2AllocationBinding> EcV2BindingCatalog::getAllocationBinding(Tx &txn,
                                                                          const storage::EcFragmentIdentity &identity) {
  auto key = allocationKey(identity);
  CO_RETURN_ON_ERROR(key);
  auto binding = co_await load<EcV2AllocationBinding>(txn, *key);
  CO_RETURN_ON_ERROR(binding);
  if (!*binding) co_return makeError(StatusCode::kNotImplemented, "fragment has no permanent V2 physical binding");
  CO_RETURN_ON_ERROR(validAllocation(**binding));
  if (!serde::equals((**binding).fragment.identity, identity))
    co_return makeError(StatusCode::kDataCorruption, "V2 allocation key differs");
  co_return **binding;
}

CoTryTask<EcV2OperationBinding> EcV2BindingCatalog::bindPreparing(Tx &txn,
                                                                  const EcOperationRecord &expected,
                                                                  const EcOwner &authenticatedOwner,
                                                                  const EcV2AllocationBindings &allocations) {
  const auto &object = expected.intent.object;
  CO_RETURN_ON_ERROR(co_await requireV2Mode(txn, object));
  auto op = co_await EcCatalog::getOperation(txn, object, expected.intent.operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(checkOwner(op->owner, authenticatedOwner));
  if (op->state != EcOperationState::Preparing)
    co_return makeError(StatusCode::kTokenStale, "only Preparing operations may bind V2 writes");
  if (!same(*op, expected)) co_return makeError(StatusCode::kTokenMismatch, "V2 bind differs from fixed Begin result");
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::requireProtectedScope(txn,
                                                                   object,
                                                                   storage::EcGrantScope::WriteOperation,
                                                                   expected.intent.operation,
                                                                   authenticatedOwner));
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  CO_RETURN_ON_ERROR(validReservation(*op, *file));
  if (file->deleting || file->epoch != op->intent.expectedEpoch)
    co_return makeError(StatusCode::kTokenStale, "V2 binding is fenced by object epoch");
  EcV2OperationBinding next;
  next.intent = op->intent;
  next.owner = op->owner;
  next.generation = op->candidate.generation;
  next.revision = op->candidate.revision;
  next.allocations = allocations;
  if (op->intent.kind == EcMutationKind::Repair) {
    auto base = co_await EcCatalog::getManifest(txn, object, op->intent.stripe, op->intent.expectedRevision);
    CO_RETURN_ON_ERROR(base);
    if (base->referencesReleased || !base->pins || base->manifest.generation != next.generation ||
        base->manifest.logicalLength != op->intent.logicalLength) {
      co_return makeError(StatusCode::kTokenStale, "V2 repair base lost its original implicit pin");
    }
    for (const auto &fragment : base->manifest.fragments) {
      auto binding = co_await getAllocationBinding(txn, fragment.identity);
      CO_RETURN_ON_ERROR(binding);
      CO_RETURN_ON_ERROR(matchesFragment(*binding, object, fragment, true));
      CO_RETURN_ON_ERROR(addEndpoint(next.operationEndpoints, binding->endpoint()));
    }
  }
  for (size_t i = 0; i != 12; ++i) {
    CO_RETURN_ON_ERROR(
        matchesFragment(allocations[i], object, op->candidate.fragments[i], op->intent.kind == EcMutationKind::Repair));
    CO_RETURN_ON_ERROR(addEndpoint(next.operationEndpoints, allocations[i].endpoint()));
    auto key = allocationKey(allocations[i].fragment.identity);
    CO_RETURN_ON_ERROR(key);
    auto previous = co_await load<EcV2AllocationBinding>(txn, *key);
    CO_RETURN_ON_ERROR(previous);
    if (*previous) {
      if (**previous != allocations[i])
        co_return makeError(StatusCode::kTokenMismatch, "V2 allocation cannot change physical instance or descriptor");
    } else if (!(op->intent.replacementMask & (1u << i))) {
      co_return makeError(StatusCode::kNotImplemented, "healthy V1 fragments cannot be upgraded during repair");
    }
  }
  auto digest = endpointDigest(next.operationEndpoints);
  CO_RETURN_ON_ERROR(digest);
  next.operationEndpoints.digest = *digest;
  CO_RETURN_ON_ERROR(validateOperationBinding(next, *op, *file));
  const auto key = idKey(KeyPrefix::EcV2Operation, object.incarnation, op->intent.operation);
  auto previous = co_await load<EcV2OperationBinding>(txn, key);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    if (!same(**previous, next)) co_return makeError(StatusCode::kTokenMismatch, "V2 operation binding is immutable");
    co_return **previous;
  }
  // All validation precedes writes. The transaction still must be discarded
  // if any later KV operation fails; no partial side-table commit is valid.
  for (size_t i = 0; i != 12; ++i) {
    if (!(op->intent.replacementMask & (1u << i))) continue;
    auto packed = allocationKey(allocations[i].fragment.identity);
    CO_RETURN_ON_ERROR(packed);
    CO_RETURN_ON_ERROR(co_await store(txn, *packed, allocations[i]));
  }
  CO_RETURN_ON_ERROR(co_await store(txn, key, next));
  co_return next;
}

CoTryTask<EcV2OperationBinding> EcV2BindingCatalog::getOperationBinding(Tx &txn,
                                                                        const EcObjectRef &object,
                                                                        const Uuid &operation,
                                                                        const EcOwner &authenticatedOwner) {
  CO_RETURN_ON_ERROR(co_await requireV2Mode(txn, object));
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(checkOwner(op->owner, authenticatedOwner));
  auto binding =
      co_await load<EcV2OperationBinding>(txn, idKey(KeyPrefix::EcV2Operation, object.incarnation, operation));
  CO_RETURN_ON_ERROR(binding);
  if (!*binding) co_return makeError(StatusCode::kNotImplemented, "operation has no V2 descriptor binding");
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  CO_RETURN_ON_ERROR(validateOperationBinding(**binding, *op, *file));
  for (const auto &allocation : (**binding).allocations) {
    auto current = co_await getAllocationBinding(txn, allocation.fragment.identity);
    CO_RETURN_ON_ERROR(current);
    if (*current != allocation)
      co_return makeError(StatusCode::kDataCorruption, "V2 operation lost immutable allocation binding");
  }
  co_return **binding;
}

CoTryTask<EcV2PinnedRead> EcV2BindingCatalog::acquireRead(Tx &txn,
                                                          const EcObjectRef &object,
                                                          uint64_t stripe,
                                                          const Uuid &pin,
                                                          const EcOwner &authenticatedOwner) {
  if (authenticatedOwner.client.is_nil())
    co_return makeError(StatusCode::kInvalidArg, "V2 read owner requires a namespace");
  CO_RETURN_ON_ERROR(co_await requireV2Mode(txn, object));
  auto existingPin = co_await EcCatalog::getPin(txn, object, pin);
  if (existingPin) {
    CO_RETURN_ON_ERROR(checkOwner(existingPin->owner, authenticatedOwner));
  } else if (existingPin.error().code() != StatusCode::kKVStoreNotFound) {
    co_return makeError(existingPin.error());
  }
  auto manifest = co_await EcCatalog::acquireRead(txn, object, stripe, pin, authenticatedOwner);
  CO_RETURN_ON_ERROR(manifest);
  auto originalPin = co_await EcCatalog::getPin(txn, object, pin);
  CO_RETURN_ON_ERROR(originalPin);
  CO_RETURN_ON_ERROR(checkOwner(originalPin->owner, authenticatedOwner));
  if (originalPin->released || originalPin->revision != manifest->revision || originalPin->stripe != manifest->stripe ||
      manifest->object != object || !manifest->generation)
    co_return makeError(StatusCode::kDataCorruption, "V2 pin differs from pinned manifest");
  auto historical = co_await EcCatalog::getManifest(txn, object, stripe, manifest->revision);
  CO_RETURN_ON_ERROR(historical);
  if (!historical->pins || historical->referencesReleased || historical->manifest != *manifest) {
    co_return makeError(StatusCode::kDataCorruption, "V2 pin has no live historical reference");
  }
  EcV2PinSnapshot next;
  next.object = object;
  next.pin = pin;
  next.stripe = stripe;
  next.revision = manifest->revision;
  next.generation = manifest->generation;
  next.owner = authenticatedOwner;
  std::array<storage::EcScopeEndpoint, 12> endpoints;
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = manifest->fragments[i];
    auto binding = co_await getAllocationBinding(txn, fragment.identity);
    CO_RETURN_ON_ERROR(binding);
    CO_RETURN_ON_ERROR(matchesFragment(*binding, object, fragment, true));
    if (fragment.identity.shard != i || fragment.identity.stripe != stripe ||
        fragment.identity.generation != next.generation) {
      co_return makeError(StatusCode::kDataCorruption, "V2 pin contains a mismatched indexed fragment");
    }
    next.endpoints[i] = {fragment.identity, fragment.operation, binding->endpoint()};
    endpoints[i] = binding->endpoint().controlEndpoint();
  }
  auto digest = storage::computeEcScopeEndpointDigest(endpoints);
  CO_RETURN_ON_ERROR(digest);
  next.endpointSetDigest = *digest;
  auto key = idKey(KeyPrefix::EcV2Pin, object.incarnation, pin);
  auto previous = co_await load<EcV2PinSnapshot>(txn, key);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    if (!same(**previous, next)) co_return makeError(StatusCode::kDataCorruption, "V2 pin endpoint snapshot changed");
    CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::protectRead(txn, **previous));
    co_return EcV2PinnedRead{*manifest, **previous};
  }
  CO_RETURN_ON_ERROR(co_await store(txn, key, next));
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::protectRead(txn, next));
  co_return EcV2PinnedRead{*manifest, next};
}

CoTryTask<EcV2PinSnapshot> EcV2BindingCatalog::getPinSnapshot(Tx &txn,
                                                              const EcObjectRef &object,
                                                              const Uuid &pin,
                                                              const EcOwner &authenticatedOwner) {
  CO_RETURN_ON_ERROR(co_await requireV2Mode(txn, object));
  auto original = co_await EcCatalog::getPin(txn, object, pin);
  CO_RETURN_ON_ERROR(original);
  CO_RETURN_ON_ERROR(checkOwner(original->owner, authenticatedOwner));
  if (original->released) co_return makeError(StatusCode::kTokenStale, "released V2 pin cannot be reused");
  auto previous = co_await load<EcV2PinSnapshot>(txn, idKey(KeyPrefix::EcV2Pin, object.incarnation, pin));
  CO_RETURN_ON_ERROR(previous);
  if (!*previous) co_return makeError(StatusCode::kNotImplemented, "pin has no V2 endpoint snapshot");
  // acquireRead's replay branch performs only conflict reads when both the
  // original pin and snapshot exist. It revalidates every immutable mapping.
  auto pinned = co_await acquireRead(txn, object, original->stripe, pin, authenticatedOwner);
  CO_RETURN_ON_ERROR(pinned);
  co_return pinned->snapshot;
}
}  // namespace hf3fs::meta::server
