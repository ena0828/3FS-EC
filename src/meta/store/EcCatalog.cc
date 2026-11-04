#include "meta/store/EcCatalog.h"

#include <algorithm>
#include <limits>
#include <set>

#include "common/kv/KeyPrefix.h"

namespace hf3fs::meta::server {
namespace {
using kv::KeyPrefix;
using Tx = EcCatalog::Transaction;

template <typename T>
bool same(const T &a, const T &b) {
  auto left = serde::serialize(a);
  auto right = serde::serialize(b);
  return std::string_view(left) == std::string_view(right);
}

Result<Void> validObject(const EcObjectRef &object) {
  if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax()) {
    return makeError(StatusCode::kInvalidArg, "invalid EC inode/incarnation");
  }
  return Void{};
}

void appendNumber(std::string &key, uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) key.push_back(static_cast<char>(value >> shift));
}

std::string key(KeyPrefix prefix, const Uuid &object) {
  std::string out(kv::toStr(prefix));
  out.append(object.asStringView());
  return out;
}

std::string key(KeyPrefix prefix, const Uuid &object, uint64_t stripe) {
  auto out = key(prefix, object);
  appendNumber(out, stripe);
  return out;
}

std::string manifestKey(const Uuid &object, uint64_t stripe, uint64_t revision) {
  auto out = key(KeyPrefix::EcManifest, object, stripe);
  appendNumber(out, revision);
  return out;
}

std::string idKey(KeyPrefix prefix, const Uuid &object, const Uuid &id) {
  auto out = key(prefix, object);
  out.append(id.asStringView());
  return out;
}

Result<std::string> fragmentKey(const storage::EcFragmentIdentity &identity) {
  CHECK_RESULT(chunk, identity.chunkId());
  std::string out(kv::toStr(KeyPrefix::EcFragmentRef));
  out.append(chunk.data());
  return out;
}

template <typename T>
CoTryTask<std::optional<T>> load(Tx &txn, std::string packed) {
  auto bytes = co_await txn.get(packed);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  T record;
  auto decoded = serde::deserialize(record, **bytes);
  if (!decoded) co_return makeError(StatusCode::kDataCorruption, "invalid EC catalog record");
  if constexpr (requires { record.version; }) {
    if (record.version != kEcCatalogVersion) {
      co_return makeError(StatusCode::kDataCorruption, "unknown EC catalog record version");
    }
  }
  co_return record;
}

template <typename T>
CoTryTask<T> require(Tx &txn, std::string packed) {
  auto record = co_await load<T>(txn, std::move(packed));
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return makeError(StatusCode::kKVStoreNotFound, "EC catalog record does not exist");
  co_return std::move(**record);
}

template <typename T>
CoTryTask<Void> store(Tx &txn, std::string packed, const T &record) {
  auto bytes = serde::serialize(record);
  CO_RETURN_ON_ERROR(co_await txn.set(packed, bytes));
  co_return Void{};
}

Result<Void> validManifest(const EcManifest &m) {
  RETURN_ON_ERROR(validObject(m.object));
  if (m.version != kEcCatalogVersion || !m.generation || !m.revision || m.fragments.size() != 12) {
    return makeError(StatusCode::kInvalidArg, "invalid EC manifest version or shape");
  }
  std::set<Uuid> allocations;
  for (size_t i = 0; i != 12; ++i) {
    const auto &f = m.fragments[i];
    RETURN_ON_ERROR(storage::validateEcIntegrity(f.identity, f.integrity));
    if (f.identity.object != m.object.incarnation || f.identity.stripe != m.stripe ||
        f.identity.generation != m.generation || f.identity.shard != i || f.operation.is_nil() ||
        f.placement.chain == storage::ChainId{} || f.placement.target == storage::TargetId{} ||
        f.placement.node == flat::NodeId{} || !allocations.insert(f.identity.allocation).second) {
      return makeError(StatusCode::kInvalidArg, "manifest contains inconsistent EC fragment identities");
    }
  }
  return Void{};
}

Result<Void> validReceipt(const storage::EcFragmentReceipt &receipt, const EcFragment &fragment) {
  if (receipt.version != storage::kEcFragmentProtocolVersion || !same(receipt.identity, fragment.identity) ||
      receipt.operationId != fragment.operation || receipt.targetId != fragment.placement.target ||
      receipt.vChainId.chainId != fragment.placement.chain || receipt.length != fragment.integrity.wholeLength ||
      receipt.checksum.type != storage::ChecksumType::CRC32C ||
      receipt.checksum.value != ~fragment.integrity.wholeCrc32c) {
    return makeError(StatusCode::kTokenMismatch, "storage receipt does not identify the manifest fragment");
  }
  return Void{};
}

CoTryTask<Void> releaseRepairPin(Tx &txn, const EcOperationRecord &op) {
  if (op.intent.kind != EcMutationKind::Repair) co_return Void{};
  auto packed = manifestKey(op.intent.object.incarnation, op.intent.stripe, op.intent.expectedRevision);
  auto base = co_await require<EcManifestRecord>(txn, packed);
  CO_RETURN_ON_ERROR(base);
  if (!base->pins || base->referencesReleased) {
    co_return makeError(StatusCode::kDataCorruption, "EC repair base lost its implicit pin");
  }
  --base->pins;
  co_return co_await store(txn, packed, *base);
}
}  // namespace

Result<EcVerifiedManifest> EcVerifiedManifest::fromStorageResponses(
    EcManifest manifest,
    const std::array<storage::EcReadResult, 12> &reads,
    const std::array<storage::EcFragmentReceipt, 12> &reconciled) {
  RETURN_ON_ERROR(validManifest(manifest));
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = manifest.fragments[i];
    RETURN_ON_ERROR(validReceipt(reads[i].receipt, fragment));
    RETURN_ON_ERROR(validReceipt(reconciled[i], fragment));
    CHECK_RESULT(actual, storage::computeEcIntegrity(fragment.identity, reads[i].payload.data));
    if (!same(actual, fragment.integrity)) {
      return makeError(StatusCode::kDataCorruption, "actual storage bytes differ from EC integrity descriptor");
    }
  }
  return EcVerifiedManifest(std::move(manifest));
}

CoTryTask<EcObjectRecord> EcCatalog::createObject(Tx &txn,
                                                  const EcObjectRef &object,
                                                  uint32_t shardBytes,
                                                  bool allowColocated,
                                                  const EcOwner &creator,
                                                  const Uuid &createRequest) {
  CO_RETURN_ON_ERROR(validObject(object));
  if (!shardBytes || shardBytes > storage::kEcFragmentRpcMaxBytes) {
    co_return makeError(StatusCode::kInvalidArg, "invalid EC shard capacity");
  }
  auto packed = key(KeyPrefix::EcObject, object.incarnation);
  auto previous = co_await load<EcObjectRecord>(txn, packed);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    if (!same((**previous).object, object) || (**previous).shardBytes != shardBytes ||
        (**previous).allowColocated != allowColocated || !same((**previous).creator, creator) ||
        (**previous).createRequest != createRequest) {
      co_return makeError(StatusCode::kTokenMismatch, "EC incarnation already has different immutable settings");
    }
    co_return **previous;
  }
  EcObjectRecord record;
  record.object = object;
  record.shardBytes = shardBytes;
  record.allowColocated = allowColocated;
  record.creator = creator;
  record.createRequest = createRequest;
  CO_RETURN_ON_ERROR(co_await store(txn, packed, record));
  co_return record;
}

CoTryTask<EcObjectRecord> EcCatalog::getObject(Tx &txn, const EcObjectRef &object) {
  CO_RETURN_ON_ERROR(validObject(object));
  auto record = co_await require<EcObjectRecord>(txn, key(KeyPrefix::EcObject, object.incarnation));
  CO_RETURN_ON_ERROR(record);
  if (!same(record->object, object)) co_return makeError(StatusCode::kTokenMismatch, "EC inode/incarnation mismatch");
  if (!record->shardBytes || record->shardBytes > storage::kEcFragmentRpcMaxBytes || !record->epoch ||
      !record->nextGeneration || !record->nextRevision) {
    co_return makeError(StatusCode::kDataCorruption, "invalid persisted EC object settings");
  }
  co_return record;
}

CoTryTask<EcOperationRecord> EcCatalog::getOperation(Tx &txn, const EcObjectRef &object, const Uuid &operation) {
  CO_RETURN_ON_ERROR(validObject(object));
  if (operation.is_nil()) co_return makeError(StatusCode::kInvalidArg, "zero EC operation ID");
  auto record = co_await require<EcOperationRecord>(txn, idKey(KeyPrefix::EcOperation, object.incarnation, operation));
  CO_RETURN_ON_ERROR(record);
  if (!same(record->intent.object, object) || record->intent.operation != operation) {
    co_return makeError(StatusCode::kTokenMismatch, "EC operation belongs to another inode/incarnation");
  }
  if (record->state != EcOperationState::Preparing && record->state != EcOperationState::Published &&
      record->state != EcOperationState::Aborted) {
    co_return makeError(StatusCode::kDataCorruption, "invalid persisted EC operation state");
  }
  co_return record;
}

CoTryTask<EcOperationRecord> EcCatalog::begin(Tx &txn, const EcMutationIntent &intent, const EcOwner &owner) {
  CO_RETURN_ON_ERROR(validObject(intent.object));
  if (intent.version != kEcCatalogVersion || intent.operation.is_nil() || intent.placements.size() != 12 ||
      std::all_of(intent.requestDigest.begin(), intent.requestDigest.end(), [](uint8_t byte) { return byte == 0; }) ||
      !intent.expectedEpoch || !intent.replacementMask || (intent.replacementMask & ~kEcAllShards) ||
      (intent.kind != EcMutationKind::Write && intent.kind != EcMutationKind::Repair) ||
      (intent.kind == EcMutationKind::Write && intent.replacementMask != kEcAllShards)) {
    co_return makeError(StatusCode::kInvalidArg, "invalid EC mutation intent");
  }
  auto opKey = idKey(KeyPrefix::EcOperation, intent.object.incarnation, intent.operation);
  auto duplicate = co_await load<EcOperationRecord>(txn, opKey);
  CO_RETURN_ON_ERROR(duplicate);
  if (*duplicate) {
    if (!same((**duplicate).intent, intent) || !same((**duplicate).owner, owner)) {
      co_return makeError(StatusCode::kTokenMismatch, "EC operation ID reused with different parameters");
    }
    co_return **duplicate;
  }
  auto object = co_await getObject(txn, intent.object);
  CO_RETURN_ON_ERROR(object);
  if (object->deleting || object->epoch != intent.expectedEpoch) {
    co_return makeError(StatusCode::kTokenStale, "EC file fence changed");
  }
  const uint64_t stripeBytes = uint64_t(object->shardBytes) * 10;
  if (!intent.logicalLength || intent.logicalLength > stripeBytes ||
      intent.stripe > (std::numeric_limits<uint64_t>::max() - intent.logicalLength) / stripeBytes) {
    co_return makeError(StatusCode::kInvalidArg, "EC stripe length or file offset overflows");
  }
  auto current = co_await load<EcHead>(txn, key(KeyPrefix::EcHead, intent.object.incarnation, intent.stripe));
  CO_RETURN_ON_ERROR(current);
  if ((current->has_value() ? (**current).revision : 0) != intent.expectedRevision) {
    co_return makeError(StatusCode::kTokenStale, "EC head differs from the requested base revision");
  }
  std::set<flat::NodeId> nodes;
  std::set<storage::TargetId> targets;
  std::set<storage::ChainId> chains;
  for (const auto &placement : intent.placements) {
    if (placement.node == flat::NodeId{} || placement.target == storage::TargetId{} ||
        placement.chain == storage::ChainId{} || !targets.insert(placement.target).second ||
        !chains.insert(placement.chain).second) {
      co_return makeError(StatusCode::kInvalidArg, "EC placements require distinct explicit targets and chains");
    }
    nodes.insert(placement.node);
  }
  if (!object->allowColocated && nodes.size() != 12) {
    co_return makeError(StatusCode::kInvalidArg, "EC placements require twelve distinct node fault domains");
  }
  if (object->nextRevision == std::numeric_limits<uint64_t>::max() ||
      (intent.kind == EcMutationKind::Write && object->nextGeneration == std::numeric_limits<uint64_t>::max())) {
    co_return makeError(StatusCode::kInvalidArg, "EC generation/revision exhausted");
  }
  EcOperationRecord op;
  op.intent = intent;
  op.owner = owner;
  auto &candidate = op.candidate;
  if (intent.kind == EcMutationKind::Repair) {
    if (!intent.expectedRevision) co_return makeError(StatusCode::kInvalidArg, "cannot repair an absent EC stripe");
    auto packed = manifestKey(intent.object.incarnation, intent.stripe, intent.expectedRevision);
    auto base = co_await require<EcManifestRecord>(txn, packed);
    CO_RETURN_ON_ERROR(base);
    if (base->retired || base->referencesReleased || base->manifest.logicalLength != intent.logicalLength ||
        base->pins == std::numeric_limits<uint64_t>::max()) {
      co_return makeError(StatusCode::kTokenStale, "EC repair base is not pinnable");
    }
    candidate = base->manifest;
    ++base->pins;
    CO_RETURN_ON_ERROR(co_await store(txn, packed, *base));
  } else {
    candidate.object = intent.object;
    candidate.stripe = intent.stripe;
    candidate.generation = object->nextGeneration++;
    candidate.logicalLength = intent.logicalLength;
  }
  candidate.revision = object->nextRevision++;
  for (size_t i = 0; i != 12; ++i) {
    auto &fragment = candidate.fragments[i];
    if (!(intent.replacementMask & (1u << i))) {
      if (!same(fragment.placement, intent.placements[i])) {
        co_return makeError(StatusCode::kInvalidArg, "healthy fragment placement must remain unchanged");
      }
      continue;
    }
    fragment.identity.object = intent.object.incarnation;
    fragment.identity.stripe = intent.stripe;
    fragment.identity.generation = candidate.generation;
    fragment.identity.shard = i;
    fragment.identity.allocation = Uuid::random();
    fragment.placement = intent.placements[i];
    fragment.operation = intent.operation;
    auto packed = fragmentKey(fragment.identity);
    CO_RETURN_ON_ERROR(packed);
    auto occupied = co_await load<EcFragmentRefRecord>(txn, *packed);
    CO_RETURN_ON_ERROR(occupied);
    if (*occupied) co_return makeError(StatusCode::kTokenDuplicated, "EC allocation collision");
    EcFragmentRefRecord reference;
    reference.fragment = fragment;
    reference.owner = intent.operation;
    CO_RETURN_ON_ERROR(co_await store(txn, *packed, reference));
  }
  CO_RETURN_ON_ERROR(co_await store(txn, key(KeyPrefix::EcObject, intent.object.incarnation), *object));
  CO_RETURN_ON_ERROR(co_await store(txn, opKey, op));
  co_return op;
}

CoTryTask<EcOperationRecord> EcCatalog::publish(Tx &txn,
                                                const EcObjectRef &object,
                                                const Uuid &operation,
                                                const EcVerifiedManifest &verified) {
  auto op = co_await getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  const auto &candidate = verified.manifest();
  if (op->state == EcOperationState::Published) {
    if (!same(op->candidate, candidate)) co_return makeError(StatusCode::kTokenMismatch, "EC published result differs");
    co_return *op;
  }
  if (op->state != EcOperationState::Preparing) co_return makeError(StatusCode::kTokenStale, "EC operation aborted");
  auto file = co_await getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (file->deleting || file->epoch != op->intent.expectedEpoch) {
    co_return makeError(StatusCode::kTokenStale, "EC publication fenced");
  }
  auto headKey = key(KeyPrefix::EcHead, object.incarnation, op->intent.stripe);
  auto head = co_await load<EcHead>(txn, headKey);
  CO_RETURN_ON_ERROR(head);
  if ((head->has_value() ? (**head).revision : 0) != op->intent.expectedRevision) {
    co_return makeError(StatusCode::kTokenStale, "EC publication lost revision CAS");
  }
  const auto &planned = op->candidate;
  if (!same(candidate.object, object) || candidate.stripe != planned.stripe ||
      candidate.generation != planned.generation || candidate.revision != planned.revision ||
      candidate.logicalLength != planned.logicalLength || candidate.fragments.size() != 12) {
    co_return makeError(StatusCode::kTokenMismatch, "EC publication differs from its reservation");
  }
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = candidate.fragments[i];
    const auto &reserved = planned.fragments[i];
    if (!same(fragment.identity, reserved.identity) || !same(fragment.placement, reserved.placement) ||
        fragment.operation != reserved.operation || fragment.integrity.wholeLength != file->shardBytes ||
        (op->intent.kind == EcMutationKind::Repair && !same(fragment.integrity, reserved.integrity))) {
      co_return makeError(StatusCode::kTokenMismatch, "EC fragment differs from reserved identity or repair content");
    }
    auto packed = fragmentKey(fragment.identity);
    CO_RETURN_ON_ERROR(packed);
    auto ref = co_await require<EcFragmentRefRecord>(txn, *packed);
    CO_RETURN_ON_ERROR(ref);
    const bool fresh = (op->intent.replacementMask & (1u << i)) != 0;
    if (ref->gcCandidate || ref->references == std::numeric_limits<uint64_t>::max() ||
        (fresh ? (ref->owner != operation || ref->references != 0)
               : (!ref->owner.is_nil() || !ref->references || !same(ref->fragment, fragment)))) {
      co_return makeError(StatusCode::kTokenStale, "EC fragment is not eligible for publication");
    }
    ref->fragment = fragment;
    ref->owner = Uuid::zero();
    ++ref->references;
    CO_RETURN_ON_ERROR(co_await store(txn, *packed, *ref));
  }
  CO_RETURN_ON_ERROR(co_await releaseRepairPin(txn, *op));
  if (*head) {
    auto packed = manifestKey(object.incarnation, op->intent.stripe, (**head).revision);
    auto old = co_await require<EcManifestRecord>(txn, packed);
    CO_RETURN_ON_ERROR(old);
    old->retired = true;
    CO_RETURN_ON_ERROR(co_await store(txn, packed, *old));
  }
  auto packed = manifestKey(object.incarnation, candidate.stripe, candidate.revision);
  auto occupied = co_await load<EcManifestRecord>(txn, packed);
  CO_RETURN_ON_ERROR(occupied);
  if (*occupied) co_return makeError(StatusCode::kDataCorruption, "EC reserved revision already exists");
  EcManifestRecord published;
  published.manifest = candidate;
  CO_RETURN_ON_ERROR(co_await store(txn, packed, published));
  EcHead next;
  next.revision = candidate.revision;
  next.generation = candidate.generation;
  CO_RETURN_ON_ERROR(co_await store(txn, headKey, next));
  file->length = std::max(file->length, candidate.stripe * uint64_t(file->shardBytes) * 10 + candidate.logicalLength);
  CO_RETURN_ON_ERROR(co_await store(txn, key(KeyPrefix::EcObject, object.incarnation), *file));
  op->candidate = candidate;
  op->state = EcOperationState::Published;
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcOperation, object.incarnation, operation), *op));
  co_return *op;
}

CoTryTask<EcOperationRecord> EcCatalog::cancel(Tx &txn, const EcObjectRef &object, const Uuid &operation) {
  auto op = co_await getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  if (op->state != EcOperationState::Preparing) co_return *op;
  for (size_t i = 0; i != 12; ++i) {
    if (!(op->intent.replacementMask & (1u << i))) continue;
    auto packed = fragmentKey(op->candidate.fragments[i].identity);
    CO_RETURN_ON_ERROR(packed);
    auto ref = co_await require<EcFragmentRefRecord>(txn, *packed);
    CO_RETURN_ON_ERROR(ref);
    if (ref->owner != operation || ref->references) {
      co_return makeError(StatusCode::kDataCorruption, "EC canceled allocation has unexpected ownership");
    }
    ref->owner = Uuid::zero();
    ref->gcCandidate = true;
    CO_RETURN_ON_ERROR(co_await store(txn, *packed, *ref));
  }
  CO_RETURN_ON_ERROR(co_await releaseRepairPin(txn, *op));
  op->state = EcOperationState::Aborted;
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcOperation, object.incarnation, operation), *op));
  co_return *op;
}

CoTryTask<EcManifest> EcCatalog::acquireRead(Tx &txn,
                                             const EcObjectRef &object,
                                             uint64_t stripe,
                                             const Uuid &pin,
                                             const EcOwner &owner) {
  CO_RETURN_ON_ERROR(validObject(object));
  if (pin.is_nil()) co_return makeError(StatusCode::kInvalidArg, "zero EC read pin");
  auto packed = idKey(KeyPrefix::EcPin, object.incarnation, pin);
  auto duplicate = co_await load<EcPinRecord>(txn, packed);
  CO_RETURN_ON_ERROR(duplicate);
  if (*duplicate) {
    if (!same((**duplicate).object, object) || (**duplicate).stripe != stripe || !same((**duplicate).owner, owner)) {
      co_return makeError(StatusCode::kTokenMismatch, "EC pin reused for another read");
    }
    if ((**duplicate).released) co_return makeError(StatusCode::kTokenStale, "released EC pin cannot be reactivated");
    auto manifest =
        co_await require<EcManifestRecord>(txn, manifestKey(object.incarnation, stripe, (**duplicate).revision));
    CO_RETURN_ON_ERROR(manifest);
    if (manifest->referencesReleased) co_return makeError(StatusCode::kDataCorruption, "pinned EC revision reclaimed");
    co_return manifest->manifest;
  }
  auto file = co_await getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (file->deleting) co_return makeError(StatusCode::kTokenStale, "EC object is deleting");
  auto head = co_await require<EcHead>(txn, key(KeyPrefix::EcHead, object.incarnation, stripe));
  CO_RETURN_ON_ERROR(head);
  auto mKey = manifestKey(object.incarnation, stripe, head->revision);
  auto manifest = co_await require<EcManifestRecord>(txn, mKey);
  CO_RETURN_ON_ERROR(manifest);
  if (manifest->retired || manifest->referencesReleased || manifest->pins == std::numeric_limits<uint64_t>::max()) {
    co_return makeError(StatusCode::kDataCorruption, "current EC revision cannot be pinned");
  }
  ++manifest->pins;
  EcPinRecord record;
  record.object = object;
  record.id = pin;
  record.stripe = stripe;
  record.revision = head->revision;
  record.owner = owner;
  CO_RETURN_ON_ERROR(co_await store(txn, mKey, *manifest));
  CO_RETURN_ON_ERROR(co_await store(txn, packed, record));
  co_return manifest->manifest;
}

CoTryTask<EcPinRecord> EcCatalog::getPin(Tx &txn, const EcObjectRef &object, const Uuid &pin) {
  CO_RETURN_ON_ERROR(validObject(object));
  if (pin.is_nil()) co_return makeError(StatusCode::kInvalidArg, "zero EC read pin");
  auto record = co_await require<EcPinRecord>(txn, idKey(KeyPrefix::EcPin, object.incarnation, pin));
  CO_RETURN_ON_ERROR(record);
  if (!same(record->object, object) || record->id != pin) co_return makeError(StatusCode::kTokenMismatch);
  co_return *record;
}

CoTryTask<Void> EcCatalog::releaseRead(Tx &txn, const EcObjectRef &object, const Uuid &pin) {
  CO_RETURN_ON_ERROR(validObject(object));
  auto packed = idKey(KeyPrefix::EcPin, object.incarnation, pin);
  auto record = co_await require<EcPinRecord>(txn, packed);
  CO_RETURN_ON_ERROR(record);
  if (!same(record->object, object) || record->id != pin) co_return makeError(StatusCode::kTokenMismatch);
  if (record->released) co_return Void{};
  auto mKey = manifestKey(object.incarnation, record->stripe, record->revision);
  auto manifest = co_await require<EcManifestRecord>(txn, mKey);
  CO_RETURN_ON_ERROR(manifest);
  if (!manifest->pins || manifest->referencesReleased) co_return makeError(StatusCode::kDataCorruption);
  --manifest->pins;
  record->released = true;
  CO_RETURN_ON_ERROR(co_await store(txn, mKey, *manifest));
  co_return co_await store(txn, packed, *record);
}

CoTryTask<Void> EcCatalog::retireRevision(Tx &txn, const EcObjectRef &object, uint64_t stripe, uint64_t revision) {
  CO_RETURN_ON_ERROR(co_await getObject(txn, object));
  auto packed = manifestKey(object.incarnation, stripe, revision);
  auto manifest = co_await require<EcManifestRecord>(txn, packed);
  CO_RETURN_ON_ERROR(manifest);
  if (manifest->referencesReleased) co_return Void{};
  if (!manifest->retired || manifest->pins) {
    co_return makeError(StatusCode::kTokenStale, "EC revision is current or still pinned");
  }
  auto head = co_await load<EcHead>(txn, key(KeyPrefix::EcHead, object.incarnation, stripe));
  CO_RETURN_ON_ERROR(head);
  if (*head && (**head).revision == revision) co_return makeError(StatusCode::kDataCorruption);
  for (const auto &fragment : manifest->manifest.fragments) {
    auto rKey = fragmentKey(fragment.identity);
    CO_RETURN_ON_ERROR(rKey);
    auto ref = co_await require<EcFragmentRefRecord>(txn, *rKey);
    CO_RETURN_ON_ERROR(ref);
    if (!ref->references || ref->gcCandidate || !ref->owner.is_nil() || !same(ref->fragment, fragment)) {
      co_return makeError(StatusCode::kDataCorruption, "EC manifest reference accounting is inconsistent");
    }
    if (--ref->references == 0) ref->gcCandidate = true;
    CO_RETURN_ON_ERROR(co_await store(txn, *rKey, *ref));
  }
  manifest->referencesReleased = true;
  co_return co_await store(txn, packed, *manifest);
}

CoTryTask<EcFragmentRefRecord> EcCatalog::getFragmentRef(Tx &txn, const storage::EcFragmentIdentity &identity) {
  auto packed = fragmentKey(identity);
  CO_RETURN_ON_ERROR(packed);
  auto record = co_await require<EcFragmentRefRecord>(txn, *packed);
  CO_RETURN_ON_ERROR(record);
  if (!same(record->fragment.identity, identity)) co_return makeError(StatusCode::kDataCorruption);
  co_return *record;
}

}  // namespace hf3fs::meta::server
