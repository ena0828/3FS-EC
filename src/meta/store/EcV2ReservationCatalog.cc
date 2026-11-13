#include "meta/store/EcV2ReservationCatalog.h"
#include "meta/store/EcTargetRetirementCatalog.h"

#include <limits>

#include "fbs/meta/EcRequestDigest.h"
#include "meta/store/EcV2GcCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
Result<Void> validate(const EcV2Reservation &reservation, const EcOperationRecord &current, uint32_t shardBytes) {
  const auto &original = reservation.original;
  if (reservation.version != kEcV2LifecycleVersion || original.version != kEcCatalogVersion ||
      original.intent.version != kEcCatalogVersion || original.candidate.version != kEcCatalogVersion ||
      original.state != EcOperationState::Preparing || !original.candidate.revision ||
      !original.candidate.logicalLength || original.candidate.logicalLength > uint64_t(shardBytes) * 10 ||
      !original.intent.replacementMask || (original.intent.replacementMask & ~kEcAllShards) ||
      (original.intent.kind != EcMutationKind::Write && original.intent.kind != EcMutationKind::Repair) ||
      (original.intent.kind == EcMutationKind::Write && original.intent.replacementMask != kEcAllShards) ||
      !same(original.intent, current.intent) || !same(original.owner, current.owner) ||
      original.candidate.object != current.candidate.object || original.candidate.stripe != current.candidate.stripe ||
      original.candidate.generation != current.candidate.generation ||
      original.candidate.revision != current.candidate.revision ||
      original.candidate.logicalLength != current.candidate.logicalLength ||
      reservation.contentSha256 == storage::EcSha256{}) {
    return makeError(StatusCode::kDataCorruption, "V2 reservation differs from its original operation");
  }
  CHECK_RESULT(digest, computeEcRequestDigest(current.intent, shardBytes, reservation.contentSha256));
  if (digest != current.intent.requestDigest)
    return makeError(StatusCode::kTokenMismatch, "reserved logical SHA differs from Begin");
  RETURN_ON_ERROR(setValid(reservation.operationEndpoints));
  for (size_t i = 0; i != 12; ++i) {
    const auto &slot = reservation.candidates[i];
    const auto &fragment = current.candidate.fragments[i];
    const auto &originalFragment = original.candidate.fragments[i];
    RETURN_ON_ERROR(endpointValid(slot.endpoint));
    RETURN_ON_ERROR(slot.identity.validate());
    if (!same(originalFragment.identity, fragment.identity) || originalFragment.operation != fragment.operation ||
        originalFragment.placement != fragment.placement ||
        (current.intent.kind == EcMutationKind::Repair && originalFragment.integrity != fragment.integrity) ||
        (current.intent.kind == EcMutationKind::Write &&
         originalFragment.integrity != storage::EcIntegrityDescriptor{}) ||
        !same(slot.identity, fragment.identity) || slot.operation != fragment.operation ||
        slot.endpoint.placement != fragment.placement || slot.writer.client.is_nil() || slot.identity.shard != i ||
        slot.identity.generation != current.candidate.generation ||
        slot.identity.object != current.intent.object.incarnation || slot.identity.stripe != current.intent.stripe ||
        ((current.intent.replacementMask & (1u << i)) && !same(slot.writer, current.owner))) {
      return makeError(StatusCode::kDataCorruption, "V2 reserved candidate identity or writer mismatch");
    }
    const auto &set = reservation.operationEndpoints;
    if (std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, slot.endpoint) ==
        set.endpoints.begin() + set.count) {
      return makeError(StatusCode::kDataCorruption, "V2 reservation omits a candidate endpoint");
    }
  }
  return Void{};
}
}  // namespace

CoTryTask<EcV2Reservation> EcV2ReservationCatalog::get(Transaction &txn,
                                                       const EcObjectRef &object,
                                                       const Uuid &operation,
                                                       const EcOwner &owner) {
  using namespace ec_v2_lifecycle;
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(ownerMatches(op->owner, owner));
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  auto record = co_await load<EcV2Reservation>(txn, reservationKey(object, operation));
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return makeError(StatusCode::kNotImplemented, "V2 operation has no fixed physical reservation");
  CO_RETURN_ON_ERROR(validate(**record, *op, file->shardBytes));
  co_return **record;
}

CoTryTask<EcV2Reservation> EcV2ReservationCatalog::reserve(Transaction &txn,
                                                           const EcOperationRecord &expected,
                                                           const EcOwner &owner,
                                                           const storage::EcSha256 &content,
                                                           const PhysicalPool &trustedPool) {
  using namespace ec_v2_lifecycle;
  const auto &object = expected.intent.object;
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  auto op = co_await EcCatalog::getOperation(txn, object, expected.intent.operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(ownerMatches(op->owner, owner));
  if (op->state != EcOperationState::Preparing)
    co_return makeError(StatusCode::kTokenStale, "V2 reservation requires Preparing");
  if (!same(*op, expected)) co_return makeError(StatusCode::kTokenMismatch, "V2 reservation Begin result changed");
  auto closed =
      co_await load<EcV2DrainRecord>(txn,
                                     drainKey(object, storage::EcGrantScope::WriteOperation, op->intent.operation));
  CO_RETURN_ON_ERROR(closed);
  if (*closed) co_return makeError(StatusCode::kTokenStale, "V2 operation issuance is permanently closed");
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (file->deleting || file->epoch != op->intent.expectedEpoch) co_return makeError(StatusCode::kTokenStale);
  EcV2Reservation next;
  next.original = *op;
  next.contentSha256 = content;
  if (op->intent.kind == EcMutationKind::Repair) {
    auto base = co_await EcCatalog::getManifest(txn, object, op->intent.stripe, op->intent.expectedRevision);
    CO_RETURN_ON_ERROR(base);
    if (!base->pins || base->referencesReleased)
      co_return makeError(StatusCode::kTokenStale, "repair base is not pinned");
    for (const auto &fragment : base->manifest.fragments) {
      auto allocation = co_await EcV2BindingCatalog::getAllocationBinding(txn, fragment.identity);
      CO_RETURN_ON_ERROR(allocation);
      if (allocation->object != object || allocation->fragment != fragment)
        co_return makeError(StatusCode::kTokenMismatch);
      CO_RETURN_ON_ERROR(addEndpoint(next.operationEndpoints, allocation->endpoint()));
    }
  }
  for (size_t i = 0; i != 12; ++i) {
    const auto &fragment = op->candidate.fragments[i];
    auto &slot = next.candidates[i];
    slot.identity = fragment.identity;
    slot.operation = fragment.operation;
    if (op->intent.replacementMask & (1u << i)) {
      slot.endpoint = trustedPool[i];
      slot.writer = owner;
      if (slot.endpoint.placement != fragment.placement)
        co_return makeError(StatusCode::kTokenMismatch, "trusted pool differs from reserved placement");
    } else {
      auto old = co_await EcV2BindingCatalog::getAllocationBinding(txn, fragment.identity);
      CO_RETURN_ON_ERROR(old);
      if (old->object != object || old->fragment != fragment) co_return makeError(StatusCode::kTokenMismatch);
      slot.endpoint = old->endpoint();
      slot.writer = old->writer;
    }
    CO_RETURN_ON_ERROR(addEndpoint(next.operationEndpoints, slot.endpoint));
  }
  auto digest = setDigest(next.operationEndpoints);
  CO_RETURN_ON_ERROR(digest);
  next.operationEndpoints.digest = *digest;
  CO_RETURN_ON_ERROR(validate(next, *op, file->shardBytes));
  const auto key = reservationKey(object, op->intent.operation);
  auto existing = co_await load<EcV2Reservation>(txn, key);
  CO_RETURN_ON_ERROR(existing);
  if (*existing) {
    if (!same(**existing, next))
      co_return makeError(StatusCode::kTokenMismatch, "V2 physical reservation cannot change");
    CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::protectOperation(txn, **existing));
    co_return **existing;
  }
  for (size_t i = 0; i < 12; ++i)
    if (op->intent.replacementMask & (1u << i))
      CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::requireAssignable(txn, next.candidates[i].endpoint));
  CO_RETURN_ON_ERROR(co_await save(txn, key, next));
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::protectOperation(txn, next));
  co_return next;
}

CoTryTask<Void> EcV2ReservationCatalog::checkIssuanceOpen(Transaction &txn,
                                                          const EcObjectRef &object,
                                                          storage::EcGrantScope kind,
                                                          const Uuid &scope,
                                                          const EcOwner &owner) {
  using namespace ec_v2_lifecycle;
  CO_RETURN_ON_ERROR(scopeValid(kind, scope));
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  if (kind == storage::EcGrantScope::WriteOperation) {
    auto loaded = co_await get(txn, object, scope, owner);
    CO_RETURN_ON_ERROR(loaded);
    auto op = co_await EcCatalog::getOperation(txn, object, scope);
    CO_RETURN_ON_ERROR(op);
    if (op->state != EcOperationState::Preparing) co_return makeError(StatusCode::kTokenStale);
  } else {
    auto loaded = co_await EcV2BindingCatalog::getPinSnapshot(txn, object, scope, owner);
    CO_RETURN_ON_ERROR(loaded);
  }
  auto closed = co_await load<EcV2DrainRecord>(txn, drainKey(object, kind, scope));
  CO_RETURN_ON_ERROR(closed);
  if (*closed) co_return makeError(StatusCode::kTokenStale, "V2 scope issuance is permanently closed");
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::requireProtectedScope(txn, object, kind, scope, owner));
  auto sequence = co_await readIssuanceSequence(txn, object, kind, scope);
  CO_RETURN_ON_ERROR(sequence);
  if (*sequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StatusCode::kInvalidArg, "V2 issuance sequence exhausted");
  IssuanceSequence next;
  next.sequence = *sequence + 1;
  CO_RETURN_ON_ERROR(co_await save(txn, issuanceKey(object, kind, scope), next));
  co_return Void{};
}

CoTryTask<EcV2OperationBinding> EcV2ReservationCatalog::bind(
    Transaction &txn,
    const EcObjectRef &object,
    const Uuid &operation,
    const EcOwner &owner,
    const std::array<storage::EcIntegrityDescriptor, 12> &descriptors) {
  using namespace ec_v2_lifecycle;
  CO_RETURN_ON_ERROR(co_await checkIssuanceOpen(txn, object, storage::EcGrantScope::WriteOperation, operation, owner));
  auto reservation = co_await get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  EcV2AllocationBindings allocations;
  for (size_t i = 0; i != 12; ++i) {
    const auto &reserved = reservation->candidates[i];
    auto &allocation = allocations[i];
    allocation.object = object;
    allocation.fragment = op->candidate.fragments[i];
    allocation.fragment.integrity = descriptors[i];
    allocation.engineUuid = reserved.endpoint.engineUuid;
    allocation.targetIncarnation = reserved.endpoint.targetIncarnation;
    allocation.writer = reserved.writer;
  }
  auto result = co_await EcV2BindingCatalog::bindPreparing(txn, *op, owner, allocations);
  CO_RETURN_ON_ERROR(result);
  if (!same(result->operationEndpoints, reservation->operationEndpoints)) {
    co_return makeError(StatusCode::kDataCorruption, "bound endpoints differ from permanent reservation");
  }
  co_return result;
}
}  // namespace hf3fs::meta::server
