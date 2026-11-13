#include "meta/store/EcV2GcCatalog.h"
#include "meta/store/EcTerminalEvidence.h"

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <memory>
#include <openssl/evp.h>

#include "meta/store/EcFileTreeGcGuard.h"
#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
using Kind = storage::EcGrantScope;
using kv::KeyPrefix;

std::string objectKey(KeyPrefix prefix, const EcObjectRef &object) {
  std::string key(kv::toStr(prefix));
  key.append(object.incarnation.asStringView());
  return key;
}
std::string scopeKey(KeyPrefix prefix, const EcObjectRef &object, Kind kind, const Uuid &scope) {
  auto key = objectKey(prefix, object);
  key.push_back(static_cast<char>(kind));
  key.append(scope.asStringView());
  return key;
}
Result<std::string> allocationKey(KeyPrefix prefix, const storage::EcFragmentIdentity &identity) {
  CHECK_RESULT(chunk, identity.chunkId());
  std::string key(kv::toStr(prefix));
  key.append(chunk.data());
  return key;
}
Result<std::string> memberKey(const storage::EcFragmentIdentity &identity, Kind kind, const Uuid &scope) {
  CHECK_RESULT(key, allocationKey(KeyPrefix::EcGcMembership, identity));
  key.push_back(static_cast<char>(kind));
  key.append(scope.asStringView());
  return key;
}
Result<storage::EcSha256> hash(std::string_view domain, std::initializer_list<std::string_view> parts) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), domain.data(), domain.size()) != 1)
    return makeError(StatusCode::kIOError, "GC SHA256 initialization failed");
  for (const auto part : parts) {
    if (EVP_DigestUpdate(context.get(), part.data(), part.size()) != 1)
      return makeError(StatusCode::kIOError, "GC SHA256 update failed");
  }
  storage::EcSha256 out{};
  unsigned length = 0;
  if (EVP_DigestFinal_ex(context.get(), out.data(), &length) != 1 || length != out.size())
    return makeError(StatusCode::kIOError, "GC SHA256 finalization failed");
  return out;
}
Result<storage::EcSha256> hashRecord(std::string_view domain, const auto &record) {
  const auto bytes = serde::serialize(record);
  return hash(domain, {std::string_view(bytes)});
}
CoTryTask<bool> tracked(Tx &txn, const EcObjectRef &object) {
  auto mode = co_await EcV2BindingCatalog::requireV2Mode(txn, object);
  CO_RETURN_ON_ERROR(mode);
  co_return mode->mode == kEcGcTrackedObjectMode;
}
Result<Void> validSlot(const EcV2ReservedAllocation &slot, const EcObjectRef &object) {
  RETURN_ON_ERROR(slot.identity.validate());
  RETURN_ON_ERROR(endpointValid(slot.endpoint));
  if (slot.identity.object != object.incarnation || slot.identity.shard >= 12 || slot.operation.is_nil() ||
      slot.writer.client.is_nil())
    return makeError(StatusCode::kDataCorruption, "invalid GC allocation identity");
  return Void{};
}
EcV2ReservedAllocation reserved(const EcV2AllocationBinding &binding) {
  return {binding.fragment.identity, binding.fragment.operation, binding.endpoint(), binding.writer};
}
Result<Void> addSlot(EcGcScopeRecord &scope, const EcV2ReservedAllocation &slot) {
  RETURN_ON_ERROR(validSlot(slot, scope.object));
  for (size_t i = 0; i < scope.count; ++i) {
    if (same(scope.slots[i].allocation.identity, slot.identity)) {
      if (!same(scope.slots[i].allocation, slot))
        return makeError(StatusCode::kDataCorruption, "GC allocation has conflicting instance or original operation");
      return Void{};
    }
  }
  if (scope.count == scope.slots.size()) return makeError(StatusCode::kInvalidArg, "GC scope exceeds 24 allocations");
  scope.slots[scope.count++].allocation = slot;
  return Void{};
}
Result<Void> validScope(const EcGcScopeRecord &scope) {
  RETURN_ON_ERROR(scopeValid(scope.kind, scope.scopeId));
  RETURN_ON_ERROR(setValid(scope.endpoints));
  if (scope.object.incarnation.is_nil() || scope.owner.client.is_nil() || !scope.generation || !scope.revision ||
      !scope.count || scope.count > scope.slots.size() ||
      (scope.state != EcGcScopeState::Active && scope.state != EcGcScopeState::Released) ||
      ((scope.state == EcGcScopeState::Active) != (scope.releaseEvidence == storage::EcSha256{})))
    return makeError(StatusCode::kDataCorruption, "invalid GC scope record");
  EcV2OperationEndpoints endpoints;
  for (size_t i = 0; i < scope.slots.size(); ++i) {
    const auto &slot = scope.slots[i].allocation;
    if (i >= scope.count) {
      if (!same(slot, EcV2ReservedAllocation{}))
        return makeError(StatusCode::kDataCorruption, "nonzero unused GC protection slot");
      continue;
    }
    RETURN_ON_ERROR(validSlot(slot, scope.object));
    for (size_t j = 0; j < i; ++j) {
      if (same(slot.identity, scope.slots[j].allocation.identity))
        return makeError(StatusCode::kDataCorruption, "duplicate GC protection allocation");
    }
    RETURN_ON_ERROR(addEndpoint(endpoints, slot.endpoint));
  }
  CHECK_RESULT(digest, setDigest(endpoints));
  if (digest != scope.endpoints.digest)
    return makeError(StatusCode::kDataCorruption, "GC protection omits a fixed endpoint");
  return Void{};
}
Result<Void> validAllocation(const EcGcAllocationRecord &record) {
  RETURN_ON_ERROR(validSlot(record.allocation, record.object));
  if (!record.registered || record.released > record.registered ||
      record.active != record.registered - record.released ||
      ((record.released == 0) != (record.releaseHistory == storage::EcSha256{})) ||
      (!record.claimId.is_nil() && record.active != 0))
    return makeError(StatusCode::kDataCorruption, "invalid GC allocation protection accounting");
  return Void{};
}
CoTryTask<EcGcScopeRecord> requiredScope(Tx &txn,
                                         const EcObjectRef &object,
                                         Kind kind,
                                         const Uuid &scope,
                                         const EcOwner &owner) {
  auto loaded = co_await load<EcGcScopeRecord>(txn, scopeKey(KeyPrefix::EcGcScope, object, kind, scope));
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded) co_return makeError(StatusCode::kDataCorruption, "tracked object has no scope protection history");
  auto &value = **loaded;
  CO_RETURN_ON_ERROR(validScope(value));
  if (value.object != object || value.kind != kind || value.scopeId != scope)
    co_return makeError(StatusCode::kDataCorruption, "GC scope key mismatch");
  CO_RETURN_ON_ERROR(ownerMatches(value.owner, owner));
  co_return value;
}
CoTryTask<EcGcMembership> requiredMember(Tx &txn,
                                         const EcGcScopeRecord &scope,
                                         const storage::EcFragmentIdentity &identity) {
  auto key = memberKey(identity, scope.kind, scope.scopeId);
  CO_RETURN_ON_ERROR(key);
  auto loaded = co_await load<EcGcMembership>(txn, *key);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded) co_return makeError(StatusCode::kDataCorruption, "GC scope lost its allocation membership");
  const auto &value = **loaded;
  if (value.object != scope.object || !same(value.identity, identity) || value.kind != scope.kind ||
      value.scopeId != scope.scopeId || value.state != scope.state || value.releaseEvidence != scope.releaseEvidence)
    co_return makeError(StatusCode::kDataCorruption, "GC membership disagrees with scope history");
  co_return value;
}
CoTryTask<Void> protect(Tx &txn, const EcGcScopeRecord &next) {
  CO_RETURN_ON_ERROR(validScope(next));
  const auto key = scopeKey(KeyPrefix::EcGcScope, next.object, next.kind, next.scopeId);
  auto previous = co_await load<EcGcScopeRecord>(txn, key);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    if (!same(**previous, next)) co_return makeError(StatusCode::kTokenMismatch, "GC scope protection cannot change");
    co_return co_await EcV2GcCatalog::requireProtectedScope(txn, next.object, next.kind, next.scopeId, next.owner);
  }
  auto closed = co_await load<EcV2DrainRecord>(txn, drainKey(next.object, next.kind, next.scopeId));
  CO_RETURN_ON_ERROR(closed);
  if (*closed) co_return makeError(StatusCode::kTokenStale, "closed scope cannot gain GC protection");
  for (size_t i = 0; i < next.count; ++i) {
    const auto &slot = next.slots[i].allocation;
    auto allocation = allocationKey(KeyPrefix::EcGcAllocation, slot.identity);
    CO_RETURN_ON_ERROR(allocation);
    auto loaded = co_await load<EcGcAllocationRecord>(txn, *allocation);
    CO_RETURN_ON_ERROR(loaded);
    auto ref = co_await EcCatalog::getFragmentRef(txn, slot.identity);
    CO_RETURN_ON_ERROR(ref);
    if (!same(ref->fragment.identity, slot.identity) || ref->fragment.operation != slot.operation ||
        ref->fragment.placement != slot.endpoint.placement || ref->gcCandidate)
      co_return makeError(StatusCode::kTokenStale, "allocation no longer accepts protections");
    EcGcAllocationRecord record;
    if (*loaded) {
      auto checked = co_await EcV2GcCatalog::getAllocation(txn, next.object, slot.identity);
      CO_RETURN_ON_ERROR(checked);
      record = *checked;
      if (record.object != next.object || !same(record.allocation, slot))
        co_return makeError(StatusCode::kDataCorruption, "GC allocation registration changed");
      if (!record.claimId.is_nil()) co_return makeError(StatusCode::kTokenStale, "allocation is irreversibly claimed");
    } else {
      // This is the only legitimate first registration. Old allocations cannot
      // be backfilled as zero merely because their history was lost.
      if (next.kind != Kind::WriteOperation || slot.operation != next.scopeId || ref->owner != next.scopeId ||
          ref->references != 0 || !same(slot.writer, next.owner))
        co_return makeError(StatusCode::kDataCorruption, "allocation is missing its birth protection");
      record.object = next.object;
      record.allocation = slot;
    }
    auto membership = memberKey(slot.identity, next.kind, next.scopeId);
    CO_RETURN_ON_ERROR(membership);
    auto existing = co_await load<EcGcMembership>(txn, *membership);
    CO_RETURN_ON_ERROR(existing);
    if (*existing) co_return makeError(StatusCode::kDataCorruption, "membership exists without its scope");
    if (record.registered == std::numeric_limits<uint64_t>::max())
      co_return makeError(StatusCode::kInvalidArg, "GC protection counter exhausted");
    ++record.registered;
    ++record.active;
    EcGcMembership member;
    member.object = next.object;
    member.identity = slot.identity;
    member.kind = next.kind;
    member.scopeId = next.scopeId;
    CO_RETURN_ON_ERROR(co_await save(txn, *membership, member));
    CO_RETURN_ON_ERROR(co_await save(txn, *allocation, record));
  }
  CO_RETURN_ON_ERROR(co_await save(txn, key, next));
  co_return Void{};
}
CoTryTask<EcV2DrainRecord> terminalEvidence(Tx &txn,
                                            const EcGcScopeRecord &scope,
                                            const storage::EcScopeControlKey &key) {
  auto loaded = co_await EcV2DrainCatalog::get(txn, scope.object, scope.kind, scope.scopeId, scope.owner);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded) co_return makeError(StatusCode::kTokenStale, "GC protection has not completed T2");
  const auto &record = **loaded;
  CO_RETURN_ON_ERROR(drainValid(record));
  if (record.state == EcV2DrainState::Closing || record.identity.generation != scope.generation ||
      record.identity.revision != scope.revision || !same(record.identity.endpoints, scope.endpoints))
    co_return makeError(StatusCode::kTokenStale, "GC protection lacks its exact terminal drain");
  CO_RETURN_ON_ERROR(co_await verifyEcTerminalEvidence(txn, record, key,
      scope.kind == Kind::ReadPin ? EcTerminalPurpose::ReadRelease
      : record.state == EcV2DrainState::Published ? EcTerminalPurpose::Publication
                                                 : EcTerminalPurpose::FencedAbort));
  if (scope.kind == Kind::ReadPin) {
    auto pin = co_await EcCatalog::getPin(txn, scope.object, scope.scopeId);
    CO_RETURN_ON_ERROR(pin);
    if (record.state != EcV2DrainState::ReadReleased || !pin->released || pin->revision != scope.revision ||
        !same(pin->owner, scope.owner))
      co_return makeError(StatusCode::kDataCorruption, "GC read T2 mismatch");
  } else {
    auto operation = co_await EcCatalog::getOperation(txn, scope.object, scope.scopeId);
    CO_RETURN_ON_ERROR(operation);
    const auto expected =
        record.state == EcV2DrainState::Published ? EcOperationState::Published : EcOperationState::Aborted;
    if ((record.state != EcV2DrainState::Published && record.state != EcV2DrainState::Aborted) ||
        operation->state != expected || !same(operation->owner, scope.owner) ||
        operation->candidate.generation != scope.generation || operation->candidate.revision != scope.revision)
      co_return makeError(StatusCode::kDataCorruption, "GC write T2 mismatch");
  }
  co_return record;
}
}  // namespace

CoTryTask<Void> EcV2GcCatalog::enrollBirth(Transaction &txn, const EcV2ObjectMode &mode) {
  if (mode.mode != kEcGcTrackedObjectMode || mode.object.incarnation.is_nil() || mode.creator.client.is_nil() ||
      mode.createRequest.is_nil())
    co_return makeError(StatusCode::kInvalidArg);
  const auto key = objectKey(KeyPrefix::EcGcEnrollment, mode.object);
  auto old = co_await load<EcGcEnrollment>(txn, key);
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return makeError(StatusCode::kDataCorruption, "GC enrollment exists before object birth");
  EcGcEnrollment enrollment;
  enrollment.object = mode.object;
  enrollment.creator = mode.creator;
  enrollment.createRequest = mode.createRequest;
  co_return co_await save(txn, key, enrollment);
}

CoTryTask<Void> EcV2GcCatalog::validateEnrollment(Transaction &txn, const EcV2ObjectMode &mode) {
  auto enrollment = co_await load<EcGcEnrollment>(txn, objectKey(KeyPrefix::EcGcEnrollment, mode.object));
  CO_RETURN_ON_ERROR(enrollment);
  if (mode.mode == 2) {
    if (*enrollment) co_return makeError(StatusCode::kDataCorruption, "legacy V2 object cannot acquire GC enrollment");
    co_return Void{};
  }
  if (mode.mode != kEcGcTrackedObjectMode || !*enrollment || (**enrollment).object != mode.object ||
      !same((**enrollment).creator, mode.creator) || (**enrollment).createRequest != mode.createRequest)
    co_return makeError(StatusCode::kDataCorruption, "tracked object lost its creation-time GC enrollment");
  co_return Void{};
}

CoTryTask<EcGcAllocationRecord> EcV2GcCatalog::getAllocation(Transaction &txn,
                                                             const EcObjectRef &object,
                                                             const storage::EcFragmentIdentity &identity) {
  auto enabled = co_await tracked(txn, object);
  CO_RETURN_ON_ERROR(enabled);
  if (!*enabled) co_return makeError(StatusCode::kNotImplemented, "legacy V2 objects have no GC history");
  auto key = allocationKey(KeyPrefix::EcGcAllocation, identity);
  CO_RETURN_ON_ERROR(key);
  auto record = co_await load<EcGcAllocationRecord>(txn, *key);
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return makeError(StatusCode::kDataCorruption, "missing allocation protection history");
  CO_RETURN_ON_ERROR(validAllocation(**record));
  if ((**record).object != object || !same((**record).allocation.identity, identity))
    co_return makeError(StatusCode::kDataCorruption, "GC allocation key mismatch");
  auto ckey = allocationKey(KeyPrefix::EcGcClaim, identity);
  CO_RETURN_ON_ERROR(ckey);
  auto claim = co_await load<EcGcClaim>(txn, *ckey);
  CO_RETURN_ON_ERROR(claim);
  if ((**record).claimId.is_nil() == claim->has_value() ||
      (*claim && ((**claim).claimId != (**record).claimId || !same((**claim).allocation.fragment.identity, identity))))
    co_return makeError(StatusCode::kDataCorruption, "GC claim and allocation state are not atomic");
  co_return **record;
}

CoTryTask<Void> EcV2GcCatalog::protectOperation(Transaction &txn, const EcV2Reservation &reservation) {
  const auto &op = reservation.original;
  auto enabled = co_await tracked(txn, op.intent.object);
  CO_RETURN_ON_ERROR(enabled);
  if (!*enabled) co_return Void{};
  auto actual = co_await EcV2ReservationCatalog::get(txn, op.intent.object, op.intent.operation, op.owner);
  CO_RETURN_ON_ERROR(actual);
  if (!same(*actual, reservation)) co_return makeError(StatusCode::kTokenMismatch, "GC reservation changed");
  EcGcScopeRecord scope;
  scope.object = op.intent.object;
  scope.kind = Kind::WriteOperation;
  scope.scopeId = op.intent.operation;
  scope.owner = op.owner;
  scope.generation = op.candidate.generation;
  scope.revision = op.candidate.revision;
  scope.endpoints = reservation.operationEndpoints;
  if (op.intent.kind == EcMutationKind::Repair) {
    auto base = co_await EcCatalog::getManifest(txn, scope.object, op.intent.stripe, op.intent.expectedRevision);
    CO_RETURN_ON_ERROR(base);
    if (!base->pins || base->referencesReleased) co_return makeError(StatusCode::kTokenStale);
    for (const auto &fragment : base->manifest.fragments) {
      auto binding = co_await EcV2BindingCatalog::getAllocationBinding(txn, fragment.identity);
      CO_RETURN_ON_ERROR(binding);
      if (binding->object != scope.object || binding->fragment != fragment)
        co_return makeError(StatusCode::kDataCorruption, "GC repair base binding changed");
      CO_RETURN_ON_ERROR(addSlot(scope, reserved(*binding)));
    }
  }
  for (const auto &slot : reservation.candidates) CO_RETURN_ON_ERROR(addSlot(scope, slot));
  co_return co_await protect(txn, scope);
}

CoTryTask<Void> EcV2GcCatalog::protectRead(Transaction &txn, const EcV2PinSnapshot &snapshot) {
  auto enabled = co_await tracked(txn, snapshot.object);
  CO_RETURN_ON_ERROR(enabled);
  if (!*enabled) co_return Void{};
  // Do not call getPinSnapshot here: its replay validation calls acquireRead.
  // ECVP's existing key omits scope kind.
  auto pinKey = objectKey(KeyPrefix::EcV2Pin, snapshot.object);
  pinKey.append(snapshot.pin.asStringView());
  auto actual = co_await load<EcV2PinSnapshot>(txn, pinKey);
  CO_RETURN_ON_ERROR(actual);
  if (!*actual || !same(**actual, snapshot))
    co_return makeError(StatusCode::kDataCorruption, "GC read snapshot changed");
  auto pin = co_await EcCatalog::getPin(txn, snapshot.object, snapshot.pin);
  CO_RETURN_ON_ERROR(pin);
  if (pin->released || pin->revision != snapshot.revision || !same(pin->owner, snapshot.owner))
    co_return makeError(StatusCode::kTokenStale, "GC read pin is no longer active");
  EcGcScopeRecord scope;
  scope.object = snapshot.object;
  scope.kind = Kind::ReadPin;
  scope.scopeId = snapshot.pin;
  scope.owner = snapshot.owner;
  scope.generation = snapshot.generation;
  scope.revision = snapshot.revision;
  for (const auto &endpoint : snapshot.endpoints) {
    auto binding = co_await EcV2BindingCatalog::getAllocationBinding(txn, endpoint.identity);
    CO_RETURN_ON_ERROR(binding);
    if (binding->object != snapshot.object || binding->fragment.operation != endpoint.operation ||
        binding->endpoint() != endpoint.endpoint)
      co_return makeError(StatusCode::kDataCorruption);
    CO_RETURN_ON_ERROR(addSlot(scope, reserved(*binding)));
    CO_RETURN_ON_ERROR(addEndpoint(scope.endpoints, endpoint.endpoint));
  }
  auto digest = setDigest(scope.endpoints);
  CO_RETURN_ON_ERROR(digest);
  scope.endpoints.digest = *digest;
  if (*digest != snapshot.endpointSetDigest) co_return makeError(StatusCode::kDataCorruption);
  co_return co_await protect(txn, scope);
}

CoTryTask<Void> EcV2GcCatalog::requireProtectedScope(Transaction &txn,
                                                     const EcObjectRef &object,
                                                     Kind kind,
                                                     const Uuid &id,
                                                     const EcOwner &owner) {
  auto enabled = co_await tracked(txn, object);
  CO_RETURN_ON_ERROR(enabled);
  if (!*enabled) co_return Void{};
  auto scope = co_await requiredScope(txn, object, kind, id, owner);
  CO_RETURN_ON_ERROR(scope);
  if (scope->state != EcGcScopeState::Active) co_return makeError(StatusCode::kTokenStale, "GC scope already released");
  for (size_t i = 0; i < scope->count; ++i) {
    const auto &slot = scope->slots[i].allocation;
    CO_RETURN_ON_ERROR(co_await requiredMember(txn, *scope, slot.identity));
    auto allocation = co_await getAllocation(txn, object, slot.identity);
    CO_RETURN_ON_ERROR(allocation);
    if (!same(allocation->allocation, slot) || !allocation->active || !allocation->claimId.is_nil())
      co_return makeError(StatusCode::kDataCorruption, "active GC scope lost its protection");
  }
  co_return Void{};
}

CoTryTask<Void> EcV2GcCatalog::finishScope(Transaction &txn,
                                           const EcObjectRef &object,
                                           Kind kind,
                                           const Uuid &id,
                                           const EcOwner &owner,
                                           const storage::EcScopeControlKey &controlKey) {
  auto enabled = co_await tracked(txn, object);
  CO_RETURN_ON_ERROR(enabled);
  if (!*enabled) co_return Void{};
  auto scope = co_await requiredScope(txn, object, kind, id, owner);
  CO_RETURN_ON_ERROR(scope);
  auto terminal = co_await terminalEvidence(txn, *scope, controlKey);
  CO_RETURN_ON_ERROR(terminal);
  auto evidence = hashRecord(terminal->version == kEcV2LifecycleVersion ? "3FSECGC-T2-v1" : "3FSECGC-T2-v2", *terminal);
  CO_RETURN_ON_ERROR(evidence);
  const bool released = scope->state == EcGcScopeState::Released;
  if (released && scope->releaseEvidence != *evidence)
    co_return makeError(StatusCode::kDataCorruption, "GC release evidence changed");
  for (size_t i = 0; i < scope->count; ++i) {
    const auto &slot = scope->slots[i].allocation;
    auto member = co_await requiredMember(txn, *scope, slot.identity);
    CO_RETURN_ON_ERROR(member);
    auto allocation = co_await getAllocation(txn, object, slot.identity);
    CO_RETURN_ON_ERROR(allocation);
    if (!same(allocation->allocation, slot)) co_return makeError(StatusCode::kDataCorruption);
    if (released) continue;
    if (!allocation->active || !allocation->claimId.is_nil()) co_return makeError(StatusCode::kDataCorruption);
    member->state = EcGcScopeState::Released;
    member->releaseEvidence = *evidence;
    const auto memberBytes = serde::serialize(*member);
    const auto previousBytes = serde::serialize(allocation->releaseHistory);
    auto history = hash("3FSECGC-HISTORY-v1", {std::string_view(previousBytes), std::string_view(memberBytes)});
    CO_RETURN_ON_ERROR(history);
    --allocation->active;
    ++allocation->released;
    allocation->releaseHistory = *history;
    auto akey = allocationKey(KeyPrefix::EcGcAllocation, slot.identity);
    CO_RETURN_ON_ERROR(akey);
    auto mkey = memberKey(slot.identity, kind, id);
    CO_RETURN_ON_ERROR(mkey);
    CO_RETURN_ON_ERROR(co_await save(txn, *akey, *allocation));
    CO_RETURN_ON_ERROR(co_await save(txn, *mkey, *member));
  }
  if (!released) {
    scope->state = EcGcScopeState::Released;
    scope->releaseEvidence = *evidence;
    CO_RETURN_ON_ERROR(co_await save(txn, scopeKey(KeyPrefix::EcGcScope, object, kind, id), *scope));
  }
  co_return Void{};
}

CoTryTask<std::optional<EcGcClaim>> EcV2GcCatalog::getClaim(Transaction &txn,
                                                            const EcObjectRef &object,
                                                            const storage::EcFragmentIdentity &identity) {
  // This extra conflict read does not broaden legacy mode-3 eligibility.
  // A tree hold must not coexist with a new or previously irreversible claim.
  CO_RETURN_ON_ERROR(co_await EcFileTreeGcGuard::requireUnheld(txn, object, identity));
  auto allocation = co_await getAllocation(txn, object, identity);
  CO_RETURN_ON_ERROR(allocation);
  auto key = allocationKey(KeyPrefix::EcGcClaim, identity);
  CO_RETURN_ON_ERROR(key);
  auto loaded = co_await load<EcGcClaim>(txn, *key);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded) {
    if (!allocation->claimId.is_nil()) co_return makeError(StatusCode::kDataCorruption, "GC claim ledger is missing");
    co_return std::nullopt;
  }
  auto proof = **loaded;
  auto enrollment = co_await load<EcGcEnrollment>(txn, objectKey(KeyPrefix::EcGcEnrollment, object));
  CO_RETURN_ON_ERROR(enrollment);
  auto binding = co_await EcV2BindingCatalog::getAllocationBinding(txn, identity);
  CO_RETURN_ON_ERROR(binding);
  const auto expected = proof.eligibilityDigest;
  proof.eligibilityDigest = {};
  auto digest = hashRecord("3FSECGC-CLAIM-v1", proof);
  CO_RETURN_ON_ERROR(digest);
  if (expected == storage::EcSha256{} || expected != *digest || proof.claimId.is_nil() ||
      proof.claimId != allocation->claimId || !*enrollment || !same(proof.enrollment, **enrollment) ||
      !same(proof.allocation, *binding) || proof.enrollment.object != object || proof.allocation.object != object ||
      !same(reserved(proof.allocation), allocation->allocation) || proof.registeredScopes != allocation->registered ||
      proof.releasedScopes != allocation->released || proof.registeredScopes != proof.releasedScopes ||
      proof.releaseHistory != allocation->releaseHistory || proof.originDrainEvidence == storage::EcSha256{})
    co_return makeError(StatusCode::kDataCorruption, "GC claim disagrees with irreversible allocation state");
  auto origin = co_await requiredScope(txn, object, Kind::WriteOperation,
                                       binding->fragment.operation, binding->writer);
  CO_RETURN_ON_ERROR(origin);
  if (origin->state != EcGcScopeState::Released) co_return makeError(StatusCode::kDataCorruption);
  auto drain = co_await EcV2DrainCatalog::get(txn, object, Kind::WriteOperation,
                                            binding->fragment.operation, binding->writer);
  CO_RETURN_ON_ERROR(drain);
  if (!*drain || ((**drain).state != EcV2DrainState::Published && (**drain).state != EcV2DrainState::Aborted))
    co_return makeError(StatusCode::kDataCorruption, "claim lost terminal origin");
  auto terminalHash = hashRecord((**drain).version == kEcV2LifecycleVersion ? "3FSECGC-T2-v1" : "3FSECGC-T2-v2",
                                **drain);
  CO_RETURN_ON_ERROR(terminalHash);
  if (*terminalHash != origin->releaseEvidence || *terminalHash != proof.originDrainEvidence)
    co_return makeError(StatusCode::kDataCorruption, "claim origin evidence changed");
  co_return **loaded;
}

CoTryTask<EcGcClaim> EcV2GcCatalog::claim(Transaction &txn,
                                          const EcObjectRef &object,
                                          const storage::EcFragmentIdentity &identity,
                                          const Uuid &claimId,
                                          const storage::EcScopeControlKey &controlKey) {
  if (claimId.is_nil()) co_return makeError(StatusCode::kInvalidArg, "GC claim ID is required");
  auto prior = co_await getClaim(txn, object, identity);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if ((**prior).claimId != claimId) co_return makeError(StatusCode::kTokenMismatch, "GC claim ID cannot change");
    co_return **prior;
  }
  auto allocation = co_await getAllocation(txn, object, identity);
  CO_RETURN_ON_ERROR(allocation);
  auto ref = co_await EcCatalog::getFragmentRef(txn, identity);
  CO_RETURN_ON_ERROR(ref);
  if (allocation->active || allocation->registered != allocation->released || ref->references || !ref->owner.is_nil() ||
      !ref->gcCandidate)
    co_return makeError(StatusCode::kTokenStale, "GC requires zero references and every protection released");
  auto binding = co_await EcV2BindingCatalog::getAllocationBinding(txn, identity);
  CO_RETURN_ON_ERROR(binding);
  if (binding->object != object || !same(reserved(*binding), allocation->allocation) ||
      !same(ref->fragment.identity, identity) || ref->fragment.operation != binding->fragment.operation ||
      ref->fragment.placement != binding->fragment.placement)
    co_return makeError(StatusCode::kDataCorruption, "GC allocation binding differs from its reference record");
  const auto &originId = binding->fragment.operation;
  auto origin = co_await requiredScope(txn, object, Kind::WriteOperation, originId, binding->writer);
  CO_RETURN_ON_ERROR(origin);
  if (origin->state != EcGcScopeState::Released) co_return makeError(StatusCode::kTokenStale);
  CO_RETURN_ON_ERROR(co_await requiredMember(txn, *origin, identity));
  auto terminal = co_await terminalEvidence(txn, *origin, controlKey);
  CO_RETURN_ON_ERROR(terminal);
  auto terminalHash = hashRecord(terminal->version == kEcV2LifecycleVersion ? "3FSECGC-T2-v1" : "3FSECGC-T2-v2", *terminal);
  CO_RETURN_ON_ERROR(terminalHash);
  if (*terminalHash != origin->releaseEvidence) co_return makeError(StatusCode::kDataCorruption);
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, originId, binding->writer);
  CO_RETURN_ON_ERROR(reservation);
  if (!same(reservation->candidates[identity.shard], allocation->allocation) ||
      !(reservation->original.intent.replacementMask & (1u << identity.shard)))
    co_return makeError(StatusCode::kDataCorruption, "GC origin did not create this allocation");
  if (terminal->state == EcV2DrainState::Published && ref->fragment != binding->fragment)
    co_return makeError(StatusCode::kDataCorruption, "published allocation integrity differs");
  auto enrollment = co_await load<EcGcEnrollment>(txn, objectKey(KeyPrefix::EcGcEnrollment, object));
  CO_RETURN_ON_ERROR(enrollment);
  if (!*enrollment) co_return makeError(StatusCode::kDataCorruption);
  EcGcClaim result;
  result.claimId = claimId;
  result.enrollment = **enrollment;
  result.allocation = *binding;
  result.registeredScopes = allocation->registered;
  result.releasedScopes = allocation->released;
  result.releaseHistory = allocation->releaseHistory;
  result.originDrainEvidence = *terminalHash;
  auto eligibility = hashRecord("3FSECGC-CLAIM-v1", result);
  CO_RETURN_ON_ERROR(eligibility);
  result.eligibilityDigest = *eligibility;
  allocation->claimId = claimId;
  auto akey = allocationKey(KeyPrefix::EcGcAllocation, identity);
  CO_RETURN_ON_ERROR(akey);
  auto ckey = allocationKey(KeyPrefix::EcGcClaim, identity);
  CO_RETURN_ON_ERROR(ckey);
  CO_RETURN_ON_ERROR(co_await save(txn, *akey, *allocation));
  CO_RETURN_ON_ERROR(co_await save(txn, *ckey, result));
  co_return result;
}
}  // namespace hf3fs::meta::server
