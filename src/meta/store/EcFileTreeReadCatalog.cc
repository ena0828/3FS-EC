#include "EcFileTreeReadCatalog.h"

#include <algorithm>
#include <set>

#include "meta/store/detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
using State = EcTreeReadState;

std::string rangeKey(const EcTreeReadIntent &i) {
  return idKey(KeyPrefix::EcFileTreeReadRange, i.selection.object, i.range);
}
std::string requestKey(const EcTreeReadIntent &i) {
  return idKey(KeyPrefix::EcFileTreeReadRequest, i.selection.object, i.request);
}
Result<Void> validIntent(const EcTreeReadIntent &i) {
  RETURN_ON_ERROR(i.selection.valid());
  if (i.version != kEcFileTreeVersion || i.owner.client.is_nil() || i.session.is_nil() || i.request.is_nil() ||
      i.range.is_nil())
    return makeError(StatusCode::kInvalidArg, "invalid fixed tree range identity");
  for (size_t n = 0; n < i.selection.pinCount; ++n)
    if (i.selection.pins[n].pin == i.range)
      return makeError(StatusCode::kInvalidArg, "tree source pin collides with range identity");
  return Void{};
}
EcTreeSourcePinIntent sourceIntent(const EcTreeReadRecord &r, size_t n) {
  EcTreeSourcePinIntent i;
  i.object = r.intent.selection.object;
  i.owner = r.intent.owner;
  i.session = r.intent.session;
  i.parent = r.intent.request;
  i.child = r.intent.range;
  i.pin = r.intent.selection.pins[n].pin;
  i.root = r.root.root;
  i.sequence = r.root.sequence;
  i.epoch = r.root.epoch;
  i.lengthAtPlan = r.root.visibleLength;
  i.slot = r.stripes[n].slot;
  return i;
}
EcV2PinSnapshot snapshot(const EcTreeSourcePinRecord &r) {
  EcV2PinSnapshot result;
  result.object = r.intent.object;
  result.owner = r.intent.owner;
  result.pin = r.intent.pin;
  result.stripe = r.intent.slot.stripe;
  result.revision = r.intent.slot.revision;
  result.generation = r.intent.slot.generation;
  result.endpointSetDigest = r.endpoints.digest;
  for (size_t n = 0; n < 12; ++n) {
    result.endpoints[n].identity = r.allocations[n].fragment.identity;
    result.endpoints[n].operation = r.allocations[n].fragment.operation;
    result.endpoints[n].endpoint = r.allocations[n].endpoint();
  }
  return result;
}
Result<Void> validRecord(const EcTreeReadRecord &r) {
  RETURN_ON_ERROR(validIntent(r.intent));
  const auto &s = r.intent.selection;
  EcManifestLayoutV1 layout;
  layout.incarnation = s.object.incarnation;
  layout.shardBytes = r.shardBytes;
  RETURN_ON_ERROR(s.matchesLayout(layout));
  const auto available = s.offset < r.root.visibleLength ? r.root.visibleLength - s.offset : 0;
  const auto length = std::min(available, s.length);
  const uint64_t size = uint64_t(r.shardBytes) * 10;
  const auto count = length ? (s.offset + length - 1) / size - s.offset / size + 1 : 0;
  if (r.version != kEcFileTreeVersion || r.root.version != kEcFileTreeVersion || r.root.object != s.object ||
      r.root.birth.is_nil() || !r.root.sequence || !r.root.epoch || r.readableLength != length ||
      r.stripeCount != count || count > 8 ||
      (r.state != State::Active && r.state != State::Closing && r.state != State::Released))
    return makeError(StatusCode::kDataCorruption, "invalid fixed tree read snapshot");
  std::set<Uuid> revocations;
  for (size_t n = 0; n < 8; ++n) {
    const auto &entry = r.stripes[n];
    const bool data = n < count && entry.slot.kind == EcTreeSlotKind::Data;
    if (n >= count) {
      if (!same(entry, EcTreeReadStripe{}))
        return makeError(StatusCode::kDataCorruption, "unused tree read slot is nonzero");
    } else {
      if (entry.slot.stripe != s.pins[n].stripe)
        return makeError(StatusCode::kDataCorruption, "tree read slot position changed");
      if (data) {
        CHECK_RESULT(start, stripeStart(entry.slot.stripe, r.shardBytes));
        CHECK_RESULT(end, rangeEnd(start, entry.slot.logicalLength));
        if (!entry.snapshot || !entry.slot.revision || !entry.slot.generation || !entry.slot.logicalLength ||
            entry.slot.logicalLength > size || end > r.root.visibleLength ||
            entry.slot.contentSha256 == storage::EcSha256{} || r.root.root.is_nil())
          return makeError(StatusCode::kDataCorruption, "invalid Data tree range slot");
        const auto &pin = *entry.snapshot;
        if (pin.object != s.object || !same(pin.owner, r.intent.owner) || pin.pin != s.pins[n].pin ||
            pin.stripe != entry.slot.stripe || pin.revision != entry.slot.revision ||
            pin.generation != entry.slot.generation)
          return makeError(StatusCode::kDataCorruption, "tree read pin identity changed");
      } else {
        EcTreeSlot zero;
        zero.stripe = entry.slot.stripe;
        if (entry.snapshot || !same(entry.slot, zero))
          return makeError(StatusCode::kDataCorruption, "Zero tree slot contains Data state");
      }
    }
    if (r.state == State::Active || !data) {
      if (!r.revocations[n].is_nil()) return makeError(StatusCode::kDataCorruption, "unexpected tree read revocation");
    } else if (r.revocations[n].is_nil() || !revocations.insert(r.revocations[n]).second) {
      return makeError(StatusCode::kDataCorruption, "missing or repeated tree read revocation");
    }
  }
  if ((r.state == State::Active) != r.closeAuthority.is_nil())
    return makeError(StatusCode::kDataCorruption, "tree read close authority/state differs");
  return Void{};
}
CoTryTask<std::optional<EcTreeReadRecord>> previous(Tx &txn, const EcTreeReadIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  auto value = co_await load<EcTreeReadRecord>(txn, rangeKey(intent));
  CO_RETURN_ON_ERROR(value);
  auto alias = co_await load<EcTreeReadIntent>(txn, requestKey(intent));
  CO_RETURN_ON_ERROR(alias);
  if (*value) {
    CO_RETURN_ON_ERROR(owner((**value).intent.owner, intent.owner));
    CO_RETURN_ON_ERROR(validRecord(**value));
    if (!same((**value).intent, intent))
      co_return makeError(StatusCode::kTokenMismatch, "tree range retry changed fixed intent");
    if (!*alias || !same(**alias, intent))
      co_return makeError(StatusCode::kDataCorruption, "tree range lost request binding");
  } else if (*alias) {
    CO_RETURN_ON_ERROR(owner((**alias).owner, intent.owner));
    if (!same(**alias, intent)) co_return makeError(StatusCode::kTokenMismatch, "tree request changed range");
    co_return makeError(StatusCode::kDataCorruption, "tree request lost fixed range");
  }
  co_return value;
}
Result<Void> dataIndex(const EcTreeReadRecord &r, size_t n) {
  if (n >= r.stripeCount || r.stripes[n].slot.kind != EcTreeSlotKind::Data)
    return makeError(StatusCode::kInvalidArg, "tree read requires an actual Data stripe");
  return Void{};
}
CoTryTask<EcTreeReadRecord> retainedRange(Tx &txn, const EcTreeReadIntent &intent) {
  auto value = co_await previous(txn, intent);
  CO_RETURN_ON_ERROR(value);
  if (!*value) co_return makeError(MetaCode::kNotFound, "unknown tree range is not release evidence");
  auto r = std::move(**value);
  auto session = co_await EcFileSessionCatalog::get(txn, intent.selection.object, intent.session, intent.owner);
  CO_RETURN_ON_ERROR(session);
  if (!(session->intent.rights & kEcSessionRead) || session->intent.birth != r.root.birth ||
      (r.state != State::Released && (!session->activeReadRanges || session->state == EcFileSessionState::Closed)))
    co_return makeError(StatusCode::kDataCorruption, "tree range lost its READ session");
  co_return r;
}
}  // namespace

CoTryTask<EcTreeReadRecord> EcFileTreeReadCatalog::query(Tx &txn, const EcTreeReadIntent &intent) {
  auto loaded = co_await retainedRange(txn, intent);
  CO_RETURN_ON_ERROR(loaded);
  auto r = std::move(*loaded);
  for (size_t n = 0; n < r.stripeCount; ++n) {
    if (r.stripes[n].slot.kind == EcTreeSlotKind::Zero) continue;
    auto source = co_await EcTreeSourcePinCatalog::query(txn, sourceIntent(r, n));
    CO_RETURN_ON_ERROR(source);
    if (!same(snapshot(*source), *r.stripes[n].snapshot) ||
        (r.state == State::Active && source->state != EcTreeSourcePinState::Active) ||
        (r.state == State::Released && source->state != EcTreeSourcePinState::Released) ||
        (r.state == State::Closing && source->state == EcTreeSourcePinState::Active) ||
        (r.state != State::Active && (!source->drain || source->drain->identity.clusterAuthority != r.closeAuthority ||
                                      source->drain->identity.revocationId != r.revocations[n])))
      co_return makeError(StatusCode::kDataCorruption, "tree range/source state differs");
  }
  co_return r;
}

CoTryTask<EcTreeReadRecord> EcFileTreeReadCatalog::acquire(Tx &txn, const EcTreeReadIntent &intent) {
  auto old = co_await previous(txn, intent);
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return co_await query(txn, intent);
  CO_RETURN_ON_ERROR(
      co_await EcFileSessionCatalog::retainReadRange(txn, intent.selection.object, intent.session, intent.owner));
  auto context = co_await EcFileTreeCatalog::open(txn, intent.selection.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  EcTreeReadRecord r;
  r.intent = intent;
  r.root = *root;
  r.shardBytes = context->birth().shardBytes;
  const auto &s = intent.selection;
  EcManifestLayoutV1 layout;
  layout.incarnation = s.object.incarnation;
  layout.shardBytes = r.shardBytes;
  CO_RETURN_ON_ERROR(s.matchesLayout(layout));
  r.readableLength = s.offset < root->visibleLength ? std::min(s.length, root->visibleLength - s.offset) : 0;
  const uint64_t size = uint64_t(r.shardBytes) * 10;
  r.stripeCount = r.readableLength ? (s.offset + r.readableLength - 1) / size - s.offset / size + 1 : 0;
  for (size_t n = 0; n < r.stripeCount; ++n) {
    auto slot = co_await EcFileTreeCatalog::lookup(*context, s.pins[n].stripe);
    CO_RETURN_ON_ERROR(slot);
    r.stripes[n].slot = *slot;
    if (slot->kind == EcTreeSlotKind::Data) {
      auto pin = co_await EcTreeSourcePinCatalog::pinExactSource(txn, sourceIntent(r, n));
      CO_RETURN_ON_ERROR(pin);
      r.stripes[n].snapshot = snapshot(pin->record());
    } else if (slot->kind == EcTreeSlotKind::Zero) {
      r.stripes[n].slot.stripe = s.pins[n].stripe;
    }
  }
  CO_RETURN_ON_ERROR(validRecord(r));
  CO_RETURN_ON_ERROR(co_await store(txn, requestKey(intent), intent));
  CO_RETURN_ON_ERROR(co_await store(txn, rangeKey(intent), r));
  co_return r;
}

CoTryTask<EcTreeSourcePinEvidence> EcFileTreeReadCatalog::reserveRead(Tx &txn,
                                                                      const EcTreeReadIntent &intent,
                                                                      size_t stripeIndex) {
  auto r = co_await retainedRange(txn, intent);
  CO_RETURN_ON_ERROR(r);
  CO_RETURN_ON_ERROR(dataIndex(*r, stripeIndex));
  if (r->state != State::Active) co_return makeError(StatusCode::kTokenStale, "tree range issuance closed");
  auto session = co_await EcFileSessionCatalog::get(txn, intent.selection.object, intent.session, intent.owner);
  CO_RETURN_ON_ERROR(session);
  // Existing accepted reads survive chmod and a logical close request. They
  // still require their own READ session and an unclosed fixed range.
  if (!(session->intent.rights & kEcSessionRead) || session->state == EcFileSessionState::Closed)
    co_return makeError(MetaCode::kNoPermission, "session lacks accepted READ rights");
  auto evidence = co_await EcTreeSourcePinCatalog::reserveIssuance(txn, sourceIntent(*r, stripeIndex));
  CO_RETURN_ON_ERROR(evidence);
  if (!same(snapshot(evidence->record()), *r->stripes[stripeIndex].snapshot))
    co_return makeError(StatusCode::kDataCorruption, "tree range issuance changed its fixed snapshot");
  co_return evidence;
}

CoTryTask<EcTreeReadRecord> EcFileTreeReadCatalog::startClosing(Tx &txn,
                                                                const EcTreeReadIntent &intent,
                                                                const Uuid &authority,
                                                                const std::array<Uuid, 8> &revocations) {
  auto r = co_await retainedRange(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (r->state != State::Active) {
    if (r->closeAuthority != authority || r->revocations != revocations)
      co_return makeError(StatusCode::kTokenMismatch, "tree range changed closing identity");
    co_return r;
  }
  r->state = State::Closing;
  r->closeAuthority = authority;
  r->revocations = revocations;
  CO_RETURN_ON_ERROR(validRecord(*r));
  for (size_t n = 0; n < r->stripeCount; ++n) {
    if (r->stripes[n].slot.kind == EcTreeSlotKind::Zero) continue;
    auto drain = co_await EcTreeSourcePinCatalog::startClosing(txn, sourceIntent(*r, n), authority, revocations[n]);
    CO_RETURN_ON_ERROR(drain);
  }
  CO_RETURN_ON_ERROR(co_await store(txn, rangeKey(intent), *r));
  co_return r;
}

CoTryTask<EcV2DrainRecord> EcFileTreeReadCatalog::closingSource(Tx &txn,
                                                                const EcTreeReadIntent &intent,
                                                                size_t stripeIndex) {
  auto r = co_await retainedRange(txn, intent);
  CO_RETURN_ON_ERROR(r);
  CO_RETURN_ON_ERROR(dataIndex(*r, stripeIndex));
  if (r->state == State::Active) co_return makeError(StatusCode::kInvalidArg, "tree range T0 has not committed");
  auto source = co_await EcTreeSourcePinCatalog::query(txn, sourceIntent(*r, stripeIndex));
  CO_RETURN_ON_ERROR(source);
  if (!source->drain || source->drain->identity.clusterAuthority != r->closeAuthority ||
      source->drain->identity.revocationId != r->revocations[stripeIndex])
    co_return makeError(StatusCode::kDataCorruption, "tree source lost its exact drain record");
  co_return *source->drain;
}

CoTryTask<EcV2DrainRecord> EcFileTreeReadCatalog::recordAck(Tx &txn,
                                                            const EcTreeReadIntent &intent,
                                                            size_t stripeIndex,
                                                            size_t endpointIndex,
                                                            const storage::EcScopeControlKey &key,
                                                            const storage::EcScopeControlRequest &request,
                                                            const storage::EcScopeControlAck &ack) {
  auto r = co_await retainedRange(txn, intent);
  CO_RETURN_ON_ERROR(r);
  CO_RETURN_ON_ERROR(dataIndex(*r, stripeIndex));
  if (r->state == State::Active) co_return makeError(StatusCode::kInvalidArg, "tree range has not entered Closing");
  auto drain = co_await closingSource(txn, intent, stripeIndex);
  CO_RETURN_ON_ERROR(drain);
  co_return co_await EcTreeSourcePinCatalog::recordAck(txn,
                                                       sourceIntent(*r, stripeIndex),
                                                       endpointIndex,
                                                       key,
                                                       request,
                                                       ack);
}

CoTryTask<EcTreeReadRecord> EcFileTreeReadCatalog::finishRelease(Tx &txn,
                                                                 const EcTreeReadIntent &intent,
                                                                 const storage::EcScopeControlKey &key) {
  auto r = co_await query(txn, intent);
  CO_RETURN_ON_ERROR(r);
  if (r->state == State::Released) co_return r;
  if (r->state != State::Closing) co_return makeError(StatusCode::kInvalidArg, "tree range requires committed T0");
  for (size_t n = 0; n < r->stripeCount; ++n) {
    if (r->stripes[n].slot.kind == EcTreeSlotKind::Zero) continue;
    auto released = co_await EcTreeSourcePinCatalog::finishRelease(txn, sourceIntent(*r, n), key);
    CO_RETURN_ON_ERROR(released);
  }
  CO_RETURN_ON_ERROR(
      co_await EcFileSessionCatalog::releaseReadRange(txn, intent.selection.object, intent.session, intent.owner));
  r->state = State::Released;
  CO_RETURN_ON_ERROR(co_await store(txn, rangeKey(intent), *r));
  co_return r;
}

CoTryTask<EcV2DrainRecord> EcFileTreeReadCatalog::recordVerifiedAck(Tx &txn,
                                                                    const EcTreeReadIntent &intent,
                                                                    size_t stripeIndex,
                                                                    const storage::EcScopeControlKey &key,
                                                                    const EcVerifiedDrainAck &evidence) {
  auto drain = co_await closingSource(txn, intent, stripeIndex);
  CO_RETURN_ON_ERROR(drain);
  if (!same(drain->identity, evidence.identity_))
    co_return makeError(StatusCode::kTokenMismatch, "verified ACK belongs to a different tree read scope");
  co_return co_await recordAck(txn,
                               intent,
                               stripeIndex,
                               evidence.index_,
                               key,
                               evidence.observation_.request,
                               evidence.observation_.ack);
}
}  // namespace hf3fs::meta::server
