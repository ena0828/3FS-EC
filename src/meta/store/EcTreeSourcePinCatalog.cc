#include "EcTreeSourcePinCatalog.h"

#include <limits>
#include <set>
#include <vector>

#include "fbs/meta/EcV2Gc.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "meta/store/detail/EcFileTreeKeys.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
namespace life = ec_v2_lifecycle;
using Tx = EcFileTreeTxnBudget;
using State = EcTreeSourcePinState;
using kv::KeyPrefix;
std::string pinKey(const EcTreeSourcePinIntent &i) { return idKey(KeyPrefix::EcTreeSourcePin, i.object, i.pin); }
Result<Void> validIntent(const EcTreeSourcePinIntent &i) {
  if (i.version != kEcFileTreeVersion || i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() ||
      i.object.inode > InodeId::normalMax() || i.owner.client.is_nil() || i.session.is_nil() || i.parent.is_nil() ||
      i.child.is_nil() || i.pin.is_nil() || i.pin == i.child || i.root.is_nil() || !i.sequence || !i.epoch ||
      i.slot.kind != EcTreeSlotKind::Data || !i.slot.revision || !i.slot.generation || !i.slot.logicalLength ||
      i.slot.contentSha256 == storage::EcSha256{})
    return makeError(StatusCode::kInvalidArg, "invalid exact tree source pin intent");
  return Void{};
}
CoTryTask<EcTreeBirth> birth(Tx &txn, const EcObjectRef &object) {
  auto b = co_await require<EcTreeBirth>(txn, objectKey(KeyPrefix::EcTreeBirth, object));
  CO_RETURN_ON_ERROR(b);
  auto mode = co_await require<EcV2ObjectMode>(txn, objectKey(KeyPrefix::EcV2ObjectMode, object));
  CO_RETURN_ON_ERROR(mode);
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (b->object != object || b->createRequest.is_nil() || b->creator.client.is_nil() || mode->mode != kEcFileTreeMode ||
      mode->object != object || mode->createRequest != b->createRequest || !same(mode->creator, b->creator) ||
      file->createRequest != b->createRequest || !same(file->creator, b->creator) ||
      file->shardBytes != b->shardBytes || file->allowColocated != b->allowColocated)
    co_return makeError(StatusCode::kDataCorruption, "source pin lost exact mode4 birth");
  CO_RETURN_ON_ERROR(stripeStart(0, b->shardBytes));
  auto legacy = co_await txn.get(objectKey(KeyPrefix::EcGcEnrollment, object));
  CO_RETURN_ON_ERROR(legacy);
  if (*legacy) co_return makeError(StatusCode::kDataCorruption, "tree source cannot use flat GC enrollment");
  // Cleanup deliberately does not depend on current inode ACL, EOF or deleting.
  co_return *b;
}
Result<EcV2OperationEndpoints> endpoints(const EcV2AllocationBindings &allocations) {
  EcV2OperationEndpoints result;
  for (const auto &a : allocations) {
    EcV2PhysicalEndpoint e;
    e.placement = a.fragment.placement;
    e.engineUuid = a.engineUuid;
    e.targetIncarnation = a.targetIncarnation;
    RETURN_ON_ERROR(life::addEndpoint(result, e));
  }
  if (result.count != 12)
    return makeError(StatusCode::kDataCorruption, "source requires twelve distinct fixed target instances");
  CHECK_RESULT(digest, life::setDigest(result));
  result.digest = digest;
  return result;
}
EcV2DrainRecord drainFor(const EcTreeSourcePinRecord &r, const Uuid &authority, const Uuid &revocation) {
  EcV2DrainRecord drain;
  auto &id = drain.identity;
  id.object = r.intent.object;
  id.kind = storage::EcGrantScope::ReadPin;
  id.scopeId = r.intent.pin;
  id.owner = r.intent.owner;
  id.objectEpoch = r.intent.epoch;
  id.generation = r.intent.slot.generation;
  id.revision = r.intent.slot.revision;
  id.clusterAuthority = authority;
  id.revocationId = revocation;
  id.endpoints = r.endpoints;
  return drain;
}
Result<Void> validRecord(const EcTreeSourcePinRecord &r, const EcTreeBirth &b) {
  RETURN_ON_ERROR(validIntent(r.intent));
  const auto &i = r.intent;
  const auto &m = r.manifest;
  CHECK_RESULT(start, stripeStart(i.slot.stripe, b.shardBytes));
  CHECK_RESULT(end, rangeEnd(start, i.slot.logicalLength));
  if (i.object != b.object || i.slot.logicalLength > uint64_t(b.shardBytes) * 10 || end > i.lengthAtPlan ||
      m.version != kEcCatalogVersion || m.object != i.object || m.stripe != i.slot.stripe ||
      m.revision != i.slot.revision || m.generation != i.slot.generation || m.logicalLength != i.slot.logicalLength)
    return makeError(StatusCode::kDataCorruption, "source manifest differs from fixed tree slot");
  std::set<Uuid> identities;
  for (size_t n = 0; n < 12; ++n) {
    const auto &a = r.allocations[n];
    const auto &f = m.fragments[n];
    RETURN_ON_ERROR(storage::validateEcIntegrity(f.identity, f.integrity));
    if (a.version != kEcBindingCatalogVersion || a.object != i.object || a.fragment != f || a.writer.client.is_nil() ||
        a.engineUuid.is_nil() || a.targetIncarnation.is_nil() || f.identity.object != i.object.incarnation ||
        f.identity.stripe != i.slot.stripe || f.identity.generation != i.slot.generation || f.identity.shard != n ||
        f.operation.is_nil() || f.integrity.wholeLength != b.shardBytes ||
        !identities.insert(f.identity.allocation).second)
      return makeError(StatusCode::kDataCorruption, "source lost fixed allocation binding");
  }
  CHECK_RESULT(expected, endpoints(r.allocations));
  if (!same(expected, r.endpoints)) return makeError(StatusCode::kDataCorruption, "source endpoint set changed");
  if (r.state == State::Active) {
    if (r.drain) return makeError(StatusCode::kDataCorruption, "active source has a drain");
  } else if (r.state == State::Closing || r.state == State::Released) {
    if (!r.drain) return makeError(StatusCode::kDataCorruption, "source drain missing");
    RETURN_ON_ERROR(life::drainValid(*r.drain));
    const auto d = drainFor(r, r.drain->identity.clusterAuthority, r.drain->identity.revocationId);
    if (!same(d.identity, r.drain->identity) ||
        r.drain->state != (r.state == State::Closing ? EcV2DrainState::Closing : EcV2DrainState::ReadReleased))
      return makeError(StatusCode::kDataCorruption, "source/drain state differs");
    if (r.state == State::Released)
      for (size_t n = 0; n < r.endpoints.count; ++n)
        if (!r.drain->observations[n]) return makeError(StatusCode::kDataCorruption, "released source lost an ACK");
  } else
    return makeError(StatusCode::kDataCorruption, "invalid source state");
  return Void{};
}
Result<Void> validAllocation(const EcTreeSourceAllocationRecord &r,
                             const EcObjectRef &o,
                             const storage::EcFragmentIdentity &identity) {
  RETURN_ON_ERROR(identity.validate());
  if (r.object != o || identity.object != o.incarnation || !same(r.identity, identity) || !r.registered ||
      r.released > r.registered || r.active != r.registered - r.released)
    return makeError(StatusCode::kDataCorruption, "invalid source protection accounting");
  return Void{};
}
CoTryTask<Void> adjust(Tx &txn,
                       const EcObjectRef &object,
                       const storage::EcFragmentIdentity &identity,
                       bool increment) {
  auto key = allocationKey(KeyPrefix::EcTreeSourceAllocation, identity);
  CO_RETURN_ON_ERROR(key);
  auto loaded = co_await load<EcTreeSourceAllocationRecord>(txn, *key);
  CO_RETURN_ON_ERROR(loaded);
  EcTreeSourceAllocationRecord r;
  r.object = object;
  r.identity = identity;
  if (*loaded) {
    r = **loaded;
    CO_RETURN_ON_ERROR(validAllocation(r, object, identity));
  }
  if (increment) {
    auto claimKey = allocationKey(KeyPrefix::EcGcClaim, identity);
    CO_RETURN_ON_ERROR(claimKey);
    auto claim = co_await txn.get(*claimKey);
    CO_RETURN_ON_ERROR(claim);
    if (*claim) co_return makeError(StatusCode::kTokenStale, "claimed allocation cannot gain source protection");
    auto oldKey = allocationKey(KeyPrefix::EcGcAllocation, identity);
    CO_RETURN_ON_ERROR(oldKey);
    auto old = co_await load<EcGcAllocationRecord>(txn, *oldKey);
    CO_RETURN_ON_ERROR(old);
    if (*old && ((**old).object != object || !same((**old).allocation.identity, identity) || !(**old).claimId.is_nil()))
      co_return makeError(StatusCode::kDataCorruption, "GC allocation conflicts with source protection");
    if (r.registered == std::numeric_limits<uint64_t>::max()) co_return makeError(StatusCode::kDataCorruption);
    ++r.registered;
    ++r.active;
  } else {
    if (!*loaded || !r.active) co_return makeError(StatusCode::kDataCorruption, "source protection underflow");
    ++r.released;
    --r.active;
  }
  co_return co_await store(txn, *key, r);
}
CoTryTask<Void> activeAccounting(Tx &txn, const EcTreeSourcePinRecord &r) {
  if (r.state == State::Released) co_return Void{};
  for (const auto &a : r.allocations) {
    auto key = allocationKey(KeyPrefix::EcTreeSourceAllocation, a.fragment.identity);
    CO_RETURN_ON_ERROR(key);
    auto count = co_await require<EcTreeSourceAllocationRecord>(txn, *key);
    CO_RETURN_ON_ERROR(count);
    CO_RETURN_ON_ERROR(validAllocation(*count, r.intent.object, a.fragment.identity));
    if (!count->active) co_return makeError(StatusCode::kDataCorruption, "live source lost physical protection");
  }
  co_return Void{};
}
}  // namespace

CoTryTask<EcTreeSourcePinRecord> EcTreeSourcePinCatalog::query(Tx &txn, const EcTreeSourcePinIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  auto b = co_await birth(txn, intent.object);
  CO_RETURN_ON_ERROR(b);
  auto r = co_await require<EcTreeSourcePinRecord>(txn, pinKey(intent));
  CO_RETURN_ON_ERROR(r);
  if (!same(r->intent.owner, intent.owner)) co_return makeError(MetaCode::kNoPermission);
  if (!same(r->intent, intent)) co_return makeError(StatusCode::kTokenMismatch, "exact source intent changed");
  CO_RETURN_ON_ERROR(validRecord(*r, *b));
  auto m = co_await EcCatalog::getManifest(txn, intent.object, intent.slot.stripe, intent.slot.revision);
  CO_RETURN_ON_ERROR(m);
  if (!same(m->manifest, r->manifest) || (r->state != State::Released && (!m->pins || m->referencesReleased)))
    co_return makeError(StatusCode::kDataCorruption, "source historical manifest lost its pin");
  CO_RETURN_ON_ERROR(co_await activeAccounting(txn, *r));
  co_return *r;
}

CoTryTask<EcTreeSourcePinEvidence> EcTreeSourcePinCatalog::pinExactSource(Tx &txn,
                                                                          const EcTreeSourcePinIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  auto prior = co_await load<EcTreeSourcePinRecord>(txn, pinKey(intent));
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    auto replay = co_await query(txn, intent);
    CO_RETURN_ON_ERROR(replay);
    if (replay->state != State::Active)
      co_return makeError(StatusCode::kTokenStale, "closed source pin cannot reactivate");
    co_return EcTreeSourcePinEvidence(std::move(*replay));
  }
  auto context = co_await EcFileTreeCatalog::open(txn, intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->root != intent.root || root->sequence != intent.sequence || root->epoch != intent.epoch ||
      root->visibleLength != intent.lengthAtPlan)
    co_return makeError(StatusCode::kTokenStale, "source root CAS changed");
  auto slot = co_await EcFileTreeCatalog::lookup(*context, intent.slot.stripe);
  CO_RETURN_ON_ERROR(slot);
  if (!same(*slot, intent.slot)) co_return makeError(StatusCode::kTokenStale, "selected source slot changed");
  // Never reinterpret an old flat scope or orphaned issuance as a fresh pin.
  std::vector<std::string> oldKeys{idKey(KeyPrefix::EcPin, intent.object, intent.pin),
                                   idKey(KeyPrefix::EcV2Pin, intent.object, intent.pin),
                                   life::drainKey(intent.object, storage::EcGrantScope::ReadPin, intent.pin),
                                   life::issuanceKey(intent.object, storage::EcGrantScope::ReadPin, intent.pin)};
  auto gcScope = objectKey(KeyPrefix::EcGcScope, intent.object);
  gcScope.push_back(static_cast<char>(storage::EcGrantScope::ReadPin));
  gcScope.append(intent.pin.asStringView());
  oldKeys.push_back(std::move(gcScope));
  for (const auto &key : oldKeys) {
    auto old = co_await txn.get(key);
    CO_RETURN_ON_ERROR(old);
    if (*old) co_return makeError(StatusCode::kTokenDuplicated, "source pin collides with permanent prior scope");
  }
  auto m = co_await EcCatalog::getManifest(txn, intent.object, intent.slot.stripe, intent.slot.revision);
  CO_RETURN_ON_ERROR(m);
  if (m->retired || m->referencesReleased || m->pins == std::numeric_limits<uint64_t>::max())
    co_return makeError(StatusCode::kTokenStale, "source manifest cannot acquire a new pin");
  EcTreeSourcePinRecord r;
  r.intent = intent;
  r.manifest = m->manifest;
  for (size_t i = 0; i < 12; ++i) {
    auto key = allocationKey(KeyPrefix::EcV2Allocation, m->manifest.fragments[i].identity);
    CO_RETURN_ON_ERROR(key);
    auto binding = co_await require<EcV2AllocationBinding>(txn, *key);
    CO_RETURN_ON_ERROR(binding);
    r.allocations[i] = std::move(*binding);
  }
  auto set = endpoints(r.allocations);
  CO_RETURN_ON_ERROR(set);
  r.endpoints = *set;
  CO_RETURN_ON_ERROR(validRecord(r, context->birth()));
  for (const auto &allocation : r.allocations)
    CO_RETURN_ON_ERROR(co_await adjust(txn, intent.object, allocation.fragment.identity, true));
  ++m->pins;
  CO_RETURN_ON_ERROR(
      co_await store(txn,
                     manifestKey(KeyPrefix::EcManifest, intent.object, intent.slot.stripe, intent.slot.revision),
                     *m));
  CO_RETURN_ON_ERROR(co_await store(txn, pinKey(intent), r));
  co_return EcTreeSourcePinEvidence(std::move(r));
}

CoTryTask<EcTreeSourcePinEvidence> EcTreeSourcePinCatalog::reserveIssuance(Tx &txn,
                                                                           const EcTreeSourcePinIntent &intent) {
  auto r = co_await query(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (r->state != State::Active) co_return makeError(StatusCode::kTokenStale, "source issuance permanently closed");
  if (r->issuanceSequence == std::numeric_limits<uint64_t>::max()) co_return makeError(StatusCode::kDataCorruption);
  ++r->issuanceSequence;
  CO_RETURN_ON_ERROR(co_await store(txn, pinKey(intent), *r));
  co_return EcTreeSourcePinEvidence(std::move(*r));
}

CoTryTask<EcV2DrainRecord> EcTreeSourcePinCatalog::startClosing(Tx &txn,
                                                                const EcTreeSourcePinIntent &intent,
                                                                const Uuid &authority,
                                                                const Uuid &revocation) {
  if (authority.is_nil() || revocation.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto r = co_await query(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (r->drain) {
    if (r->drain->identity.clusterAuthority != authority || r->drain->identity.revocationId != revocation)
      co_return makeError(StatusCode::kTokenMismatch, "source revocation identity cannot change");
    co_return *r->drain;
  }
  r->drain = drainFor(*r, authority, revocation);
  r->state = State::Closing;
  CO_RETURN_ON_ERROR(life::drainValid(*r->drain));
  CO_RETURN_ON_ERROR(co_await store(txn, pinKey(intent), *r));
  co_return *r->drain;
}

CoTryTask<EcV2DrainRecord> EcTreeSourcePinCatalog::recordAck(Tx &txn,
                                                             const EcTreeSourcePinIntent &intent,
                                                             size_t index,
                                                             const storage::EcScopeControlKey &key,
                                                             const storage::EcScopeControlRequest &request,
                                                             const storage::EcScopeControlAck &ack) {
  auto r = co_await query(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (!r->drain) co_return makeError(StatusCode::kTokenStale, "source T0 is not durable");
  auto verified = EcVerifiedDrainAck::verify(key, *r->drain, index, request, ack);
  CO_RETURN_ON_ERROR(verified);
  if (r->drain->observations[index]) co_return *r->drain;
  if (r->state != State::Closing) co_return makeError(StatusCode::kDataCorruption);
  r->drain->observations[index] = EcV2DrainObservation{request, ack};
  CO_RETURN_ON_ERROR(co_await store(txn, pinKey(intent), *r));
  co_return *r->drain;
}

CoTryTask<EcTreeSourcePinRecord> EcTreeSourcePinCatalog::finishRelease(Tx &txn,
                                                                       const EcTreeSourcePinIntent &intent,
                                                                       const storage::EcScopeControlKey &key) {
  auto r = co_await query(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (!r->drain) co_return makeError(StatusCode::kTokenStale, "source has not closed");
  for (size_t i = 0; i < r->endpoints.count; ++i) {
    if (!r->drain->observations[i])
      co_return makeError(StatusCode::kTokenStale, "source requires every fixed drained ACK");
    const auto &o = *r->drain->observations[i];
    auto verified = EcVerifiedDrainAck::verify(key, *r->drain, i, o.request, o.ack);
    CO_RETURN_ON_ERROR(verified);
  }
  if (r->state == State::Released) co_return *r;
  auto m = co_await EcCatalog::getManifest(txn, intent.object, intent.slot.stripe, intent.slot.revision);
  CO_RETURN_ON_ERROR(m);
  if (!m->pins || m->referencesReleased) co_return makeError(StatusCode::kDataCorruption);
  for (const auto &allocation : r->allocations)
    CO_RETURN_ON_ERROR(co_await adjust(txn, intent.object, allocation.fragment.identity, false));
  --m->pins;
  r->state = State::Released;
  r->drain->state = EcV2DrainState::ReadReleased;
  CO_RETURN_ON_ERROR(
      co_await store(txn,
                     manifestKey(KeyPrefix::EcManifest, intent.object, intent.slot.stripe, intent.slot.revision),
                     *m));
  CO_RETURN_ON_ERROR(co_await store(txn, pinKey(intent), *r));
  co_return *r;
}

CoTryTask<Void> EcTreeSourcePinCatalog::requireUnheld(kv::IReadWriteTransaction &txn,
                                                      const EcObjectRef &object,
                                                      const storage::EcFragmentIdentity &identity) {
  CO_RETURN_ON_ERROR(identity.validate());
  if (identity.object != object.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  auto key = allocationKey(KeyPrefix::EcTreeSourceAllocation, identity);
  CO_RETURN_ON_ERROR(key);
  auto r = co_await load<EcTreeSourceAllocationRecord>(txn, *key);
  CO_RETURN_ON_ERROR(r);
  if (*r) {
    CO_RETURN_ON_ERROR(validAllocation(**r, object, identity));
    if ((**r).active) co_return makeError(StatusCode::kTokenStale, "allocation retained by exact source scope");
  }
  co_return Void{};
}
}  // namespace hf3fs::meta::server
