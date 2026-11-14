#include "meta/store/EcV2RepairPlanCatalog.h"
#include "meta/store/EcTargetRetirementCatalog.h"

#include <bit>

#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
Result<Void> selectionValid(const EcV2RepairSelection &selection, uint16_t replacementMask) {
  if (selection.planId.is_nil() || !selection.maxBlocksInFlight || selection.maxBlocksInFlight > 4 ||
      !replacementMask || (replacementMask & ~kEcAllShards) || std::popcount(replacementMask) > 2)
    return makeError(StatusCode::kInvalidArg, "repair selection requires one/two replacements and window 1..4");
  uint16_t selected = 0;
  for (auto index : selection.sourceOrder) {
    if (index >= 12 || ((selected | replacementMask) & (uint16_t{1} << index)))
      return makeError(StatusCode::kInvalidArg, "repair sources must be ten distinct healthy shard indices");
    selected |= uint16_t{1} << index;
  }
  return Void{};
}
Result<Void> allocationMatches(const EcV2AllocationBinding &value,
                               const EcObjectRef &object,
                               const EcFragment &fragment,
                               uint16_t index) {
  RETURN_ON_ERROR(endpointValid(value.endpoint()));
  RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
  if (value.version != kEcBindingCatalogVersion || value.object != object || value.fragment != fragment ||
      fragment.identity.object != object.incarnation || fragment.identity.shard != index ||
      fragment.operation.is_nil() || value.writer.client.is_nil())
    return makeError(StatusCode::kDataCorruption, "repair allocation contradicts its durable manifest");
  return Void{};
}
storage::EcRepairFragment fragment(const EcV2AllocationBinding &value) {
  return {value.fragment.identity,
          value.fragment.operation,
          value.writer.client,
          value.endpoint().controlEndpoint(),
          value.fragment.integrity};
}
std::string planKey(const EcObjectRef &object, const Uuid &operation) {
  std::string key(kv::toStr(kv::KeyPrefix::EcV2RepairPlan));
  key.append(object.incarnation.asStringView());
  key.append(operation.asStringView());
  return key;
}
uint16_t planVersion(EcV2RepairDelivery delivery) {
  return delivery == EcV2RepairDelivery::HelperDirect ? kEcV2RepairDirectVersion : kEcV2LifecycleVersion;
}
CoTryTask<std::optional<EcV2RepairPlanRecord>> loadPlan(kv::IReadWriteTransaction &txn, const std::string &key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  EcV2RepairPlanRecord record;
  if ((**bytes).size() > (64u << 10) || !serde::deserialize(record, **bytes))
    co_return makeError(StatusCode::kDataCorruption, "invalid ECRP record");
  CO_RETURN_ON_ERROR(EcV2RepairPlanCatalog::validate(record));
  co_return record;
}
}  // namespace

Result<EcV2RepairPlanRecord> EcV2RepairPlanCatalog::build(
    const EcV2RepairSnapshot &snapshot, const EcV2RepairSelection &selection, EcV2RepairDelivery delivery) {
  const auto &[op, reservation, binding, base, bases, content] = snapshot;
  const auto &intent = op.intent;
  const auto &candidate = op.candidate;
  RETURN_ON_ERROR(selectionValid(selection, intent.replacementMask));
  if (op.version != kEcCatalogVersion || intent.version != kEcCatalogVersion ||
      candidate.version != kEcCatalogVersion || base.version != kEcCatalogVersion ||
      reservation.version != kEcV2LifecycleVersion || binding.version != kEcBindingCatalogVersion ||
      content.version != kEcV2LifecycleVersion || op.state != EcOperationState::Preparing ||
      intent.kind != EcMutationKind::Repair || intent.operation.is_nil() || op.owner.client.is_nil() ||
      intent.object.incarnation.is_nil() || intent.requestDigest == storage::EcSha256{} || !intent.expectedEpoch ||
      !intent.expectedRevision || !intent.logicalLength || base.object != intent.object ||
      candidate.object != intent.object || content.object != intent.object || base.stripe != intent.stripe ||
      candidate.stripe != intent.stripe || content.stripe != intent.stripe ||
      base.revision != intent.expectedRevision || content.revision != base.revision || !base.generation ||
      candidate.generation != base.generation || content.generation != base.generation ||
      candidate.revision <= base.revision || base.logicalLength != intent.logicalLength ||
      candidate.logicalLength != intent.logicalLength || content.logicalLength != intent.logicalLength ||
      content.operation.is_nil() || content.owner.client.is_nil() || content.contentSha256 == storage::EcSha256{} ||
      reservation.contentSha256 != content.contentSha256 || !same(reservation.original, op) ||
      !same(binding.intent, intent) || !same(binding.owner, op.owner) || binding.generation != candidate.generation ||
      binding.revision != candidate.revision)
    return makeError(StatusCode::kDataCorruption, "repair provenance or reservation is inconsistent");
  RETURN_ON_ERROR(setValid(reservation.operationEndpoints));
  RETURN_ON_ERROR(setValid(binding.operationEndpoints));

  EcV2OperationEndpoints expectedEndpoints;
  for (uint16_t i = 0; i != 12; ++i) {
    const auto &old = bases[i];
    const auto &next = binding.allocations[i];
    const auto &reserved = reservation.candidates[i];
    RETURN_ON_ERROR(allocationMatches(old, intent.object, base.fragments[i], i));
    RETURN_ON_ERROR(allocationMatches(next, intent.object, candidate.fragments[i], i));
    if (old.fragment.identity.stripe != base.stripe || old.fragment.identity.generation != base.generation ||
        next.fragment.identity.stripe != base.stripe || next.fragment.identity.generation != base.generation ||
        next.fragment.integrity != old.fragment.integrity ||
        next.fragment.integrity.wholeCrc32c != intent.fragmentCrc32c[i] ||
        next.fragment.placement != intent.placements[i] || !same(reserved.identity, next.fragment.identity) ||
        reserved.operation != next.fragment.operation || reserved.endpoint != next.endpoint() ||
        !same(reserved.writer, next.writer))
      return makeError(StatusCode::kDataCorruption, "repair content or physical binding changed");
    if (intent.replacementMask & (uint16_t{1} << i)) {
      if (next.fragment.identity.allocation == old.fragment.identity.allocation ||
          next.fragment.operation != intent.operation || !same(next.writer, op.owner))
        return makeError(StatusCode::kDataCorruption, "repair replacement is not the reserved new allocation");
    } else if (next != old) {
      return makeError(StatusCode::kDataCorruption, "repair changed a healthy allocation or its original writer");
    }
    RETURN_ON_ERROR(addEndpoint(expectedEndpoints, old.endpoint()));
    RETURN_ON_ERROR(addEndpoint(expectedEndpoints, next.endpoint()));
  }
  CHECK_RESULT(expectedDigest, setDigest(expectedEndpoints));
  if (expectedDigest != reservation.operationEndpoints.digest || expectedDigest != binding.operationEndpoints.digest ||
      expectedEndpoints.count != reservation.operationEndpoints.count ||
      expectedEndpoints.count != binding.operationEndpoints.count)
    return makeError(StatusCode::kDataCorruption, "repair drain set must include every base and candidate instance");

  EcV2RepairPlanRecord result;
  result.version = planVersion(delivery);
  result.object = intent.object;
  result.operation = intent.operation;
  result.owner = op.owner;
  result.selection = selection;
  auto &plan = result.plan;
  plan.planId = selection.planId;
  plan.operationId = intent.operation;
  plan.ownerUid = op.owner.uid;
  plan.clientNamespace = op.owner.client;
  plan.baseEpoch = intent.expectedEpoch;
  plan.baseRevision = intent.expectedRevision;
  plan.logicalLength = base.logicalLength;
  plan.logicalSha256 = content.contentSha256;
  plan.maxBlocksInFlight = selection.maxBlocksInFlight;
  for (size_t i = 0; i != selection.sourceOrder.size(); ++i)
    plan.sources[i] = fragment(bases[selection.sourceOrder[i]]);
  // Replacement order is canonical shard order, never caller-controlled.
  for (uint16_t i = 0; i != 12; ++i)
    if (intent.replacementMask & (uint16_t{1} << i))
      plan.targets[plan.targetCount++] = fragment(binding.allocations[i]);
  plan.operationEndpointCount = reservation.operationEndpoints.count;
  for (size_t i = 0; i != plan.operationEndpointCount; ++i)
    plan.operationEndpoints[i] = reservation.operationEndpoints.endpoints[i].controlEndpoint();
  CHECK_RESULT(compiled, storage::EcRepairPlan::create(plan));
  result.digest = compiled->digest();
  return result;
}

Result<std::shared_ptr<const storage::EcRepairPlan>> EcV2RepairPlanCatalog::validate(
    const EcV2RepairPlanRecord &record) {
  const auto &plan = record.plan;
  if ((record.version != kEcV2LifecycleVersion && record.version != kEcV2RepairDirectVersion) ||
      record.object.incarnation.is_nil() ||
      record.operation != plan.operationId || record.owner.uid != plan.ownerUid ||
      record.owner.client != plan.clientNamespace || record.selection.planId != plan.planId ||
      record.selection.maxBlocksInFlight != plan.maxBlocksInFlight || !plan.logicalLength ||
      plan.logicalSha256 == storage::EcSha256{} || plan.targetCount == 0 || plan.targetCount > 2)
    return makeError(StatusCode::kDataCorruption, "invalid persistent repair plan envelope");
  if (!plan.operationEndpointCount || plan.operationEndpointCount > plan.operationEndpoints.size())
    return makeError(StatusCode::kDataCorruption, "invalid persistent repair endpoint count");
  for (size_t i = plan.targetCount; i != plan.targets.size(); ++i)
    if (!same(plan.targets[i], storage::EcRepairFragment{}))
      return makeError(StatusCode::kDataCorruption, "nonzero unused repair target slot");
  for (size_t i = plan.operationEndpointCount; i != plan.operationEndpoints.size(); ++i)
    if (!same(plan.operationEndpoints[i], storage::EcScopeEndpoint{}))
      return makeError(StatusCode::kDataCorruption, "nonzero unused repair endpoint slot");
  uint16_t replacementMask = 0;
  for (size_t i = 0; i != plan.targetCount; ++i) {
    if (plan.targets[i].identity.shard >= 12 ||
        (i && plan.targets[i - 1].identity.shard >= plan.targets[i].identity.shard))
      return makeError(StatusCode::kDataCorruption, "repair replacement order is not canonical");
    replacementMask |= uint16_t{1} << plan.targets[i].identity.shard;
  }
  RETURN_ON_ERROR(selectionValid(record.selection, replacementMask));
  for (size_t i = 0; i != plan.sources.size(); ++i)
    if (plan.sources[i].identity.shard != record.selection.sourceOrder[i] ||
        plan.sources[i].identity.object != record.object.incarnation)
      return makeError(StatusCode::kDataCorruption, "repair source order differs from its persistent selection");
  CHECK_RESULT(compiled, storage::EcRepairPlan::create(plan));
  if (compiled->digest() != record.digest)
    return makeError(StatusCode::kDataCorruption, "persistent repair plan digest mismatch");
  return compiled;
}

CoTryTask<EcV2RepairPlanRecord> EcV2RepairPlanCatalog::prepare(
    Transaction &txn, const EcObjectRef &object, const Uuid &operation, const EcOwner &owner,
    const EcV2RepairSelection &selection, EcV2RepairDelivery delivery) {
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(ownerMatches(op->owner, owner));
  if (op->state != EcOperationState::Preparing || op->intent.kind != EcMutationKind::Repair)
    co_return makeError(StatusCode::kTokenStale, "repair plan requires a preparing repair operation");
  CO_RETURN_ON_ERROR(selectionValid(selection, op->intent.replacementMask));
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (file->deleting || file->epoch != op->intent.expectedEpoch) co_return makeError(StatusCode::kTokenStale);
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  auto binding = co_await EcV2BindingCatalog::getOperationBinding(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(binding);
  auto base = co_await EcCatalog::getManifest(txn, object, op->intent.stripe, op->intent.expectedRevision);
  CO_RETURN_ON_ERROR(base);
  if (!base->pins || base->referencesReleased)
    co_return makeError(StatusCode::kTokenStale, "repair base no longer has its implicit pin");
  auto content = co_await EcV2PublishedCatalog::get(txn, object, base->manifest.stripe, base->manifest.revision);
  CO_RETURN_ON_ERROR(content);
  EcV2AllocationBindings bases;
  for (size_t i = 0; i != bases.size(); ++i) {
    auto allocation = co_await EcV2BindingCatalog::getAllocationBinding(txn, base->manifest.fragments[i].identity);
    CO_RETURN_ON_ERROR(allocation);
    bases[i] = std::move(*allocation);
  }
  auto expected = build({*op, *reservation, *binding, base->manifest, bases, *content}, selection, delivery);
  CO_RETURN_ON_ERROR(expected);
  const auto key = planKey(object, operation);
  auto previous = co_await loadPlan(txn, key);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    CO_RETURN_ON_ERROR(validate(**previous));
    if ((**previous).version != planVersion(delivery) || !same((**previous).selection, selection))
      co_return makeError(StatusCode::kTokenMismatch, "repair operation already has a different permanent plan");
    if (!same(**previous, *expected))
      co_return makeError(StatusCode::kDataCorruption, "persistent repair plan differs from durable provenance");
  } else {
    for (auto index : selection.sourceOrder)
      CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::requireAssignable(txn, bases[index].endpoint()));
    CO_RETURN_ON_ERROR(co_await save(txn, key, *expected));
  }
  CO_RETURN_ON_ERROR(co_await EcV2ReservationCatalog::checkIssuanceOpen(txn,
                                                                        object,
                                                                        storage::EcGrantScope::WriteOperation,
                                                                        operation,
                                                                        owner));
  co_return expected;
}
CoTryTask<EcV2RepairPlanRecord> EcV2RepairPlanCatalog::observe(
    Transaction &txn, const EcObjectRef &object, const Uuid &operation, const EcOwner &owner,
    const EcV2RepairSelection &selection, EcV2RepairDelivery delivery) {
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(ownerMatches(op->owner, owner));
  if (op->intent.kind != EcMutationKind::Repair ||
      (op->state != EcOperationState::Preparing && op->state != EcOperationState::Published))
    co_return makeError(StatusCode::kTokenStale, "repair history is not observable");
  auto stored = co_await loadPlan(txn, planKey(object, operation));
  CO_RETURN_ON_ERROR(stored);
  if (!*stored) co_return makeError(StatusCode::kTokenStale, "repair history has no permanent ECRP");
  const auto &record = **stored;
  CO_RETURN_ON_ERROR(ownerMatches(record.owner, owner));
  if (record.version != planVersion(delivery) || !same(record.selection, selection))
    co_return makeError(StatusCode::kTokenMismatch, "permanent repair delivery or selection differs");
  if (record.object != object || record.operation != operation ||
      record.plan.baseEpoch != op->intent.expectedEpoch || record.plan.baseRevision != op->intent.expectedRevision ||
      record.plan.logicalLength != op->intent.logicalLength)
    co_return makeError(StatusCode::kDataCorruption, "repair history contradicts its operation");
  co_return record;
}
}  // namespace hf3fs::meta::server
