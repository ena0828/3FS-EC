#include "EcFileMutationCatalog.h"

#include <algorithm>
#include <limits>
#include <set>

#include "EcCatalog.h"
#include "EcFileAppendCatalog.h"
#include "EcFileTruncateCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
Result<Void> validChildIntent(const EcFileChildIntent &i) {
  if (i.version != kEcFileMutationVersion || i.object.incarnation.is_nil() || i.parent.is_nil() || i.child.is_nil() ||
      i.plan.is_nil() || i.sourcePin.is_nil() || i.child == i.parent || i.patchSha256 == storage::EcSha256{})
    return makeError(StatusCode::kInvalidArg, "invalid fixed pwrite child");
  std::set<Uuid> ids;
  for (const auto &id : i.nodeIds)
    if (id.is_nil() || !ids.insert(id).second)
      return makeError(StatusCode::kInvalidArg, "child COW node IDs must be fixed and unique");
  return Void{};
}
Result<Void> validChild(const EcFileChildRecord &c, const EcFileMutationRecord &p, uint32_t shardBytes) {
  RETURN_ON_ERROR(validChildIntent(c.intent));
  CHECK_RESULT(at, rangeEnd(p.intent.offset, c.intent.expectedPrefix));
  const auto width = uint64_t(shardBytes) * 10;
  const auto stripeStart = width ? (at / width) * width : 0;
  const auto oldExtent = c.lengthAtPlan > stripeStart ? std::min(width, c.lengthAtPlan - stripeStart) : 0;
  if (c.version != kEcFileMutationVersion || c.intent.object != p.intent.object ||
      c.intent.parent != p.intent.request || c.session != p.intent.session || !same(c.owner, p.intent.owner) ||
      c.birth.is_nil() || !c.epoch || c.epoch != p.epoch || !c.sourceSequence || !width || c.stripe != at / width ||
      c.patchOffset != at % width || c.intent.expectedPrefix >= p.intent.length || !c.patchLength ||
      c.patchLength != std::min(p.intent.length - c.intent.expectedPrefix, width - c.patchOffset) ||
      c.targetLogicalLength != std::max(oldExtent, uint64_t(c.patchOffset) + c.patchLength) || !c.targetGeneration ||
      !c.targetRevision ||
      (c.state != EcFileChildState::Planned && c.state != EcFileChildState::Published &&
       c.state != EcFileChildState::Fenced) ||
      ((c.state == EcFileChildState::Published) != c.publishedRoot.has_value()))
    return makeError(StatusCode::kDataCorruption, "pwrite child differs from fixed parent/range");
  return Void{};
}
CoTryTask<EcFileMutationRecord> parent(Tx &txn, const EcObjectRef &object, const Uuid &id, const EcOwner &actual) {
  auto p = co_await EcFileMutationCatalog::query(txn, object, id, actual);
  CO_RETURN_ON_ERROR(p);
  if (!*p) co_return makeError(MetaCode::kNotFound, "missing parent is not NotPublished proof");
  co_return std::move(**p);
}
CoTryTask<Void> saveParent(Tx &txn, const EcFileMutationRecord &p) {
  co_return co_await store(txn, idKey(KeyPrefix::EcFileMutation, p.intent.object, p.intent.request), p);
}
CoTryTask<Void> saveSession(Tx &txn, const EcFileSessionRecord &s) {
  co_return co_await store(txn, idKey(KeyPrefix::EcFileSession, s.intent.object, s.intent.session), s);
}
}  // namespace

CoTryTask<EcFileMutationRecord> EcFileMutationCatalog::begin(Tx &txn, const EcFilePwriteIntent &intent) {
  CO_RETURN_ON_ERROR(valid(intent));
  auto prior = co_await query(txn, intent.object, intent.request, intent.owner);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if (!same((**prior).intent, intent))
      co_return makeError(StatusCode::kTokenMismatch, "pwrite retry changed immutable intent");
    co_return std::move(**prior);
  }
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(txn, intent.object, intent.request));
  auto session =
      co_await EcFileSessionCatalog::require(txn, intent.object, intent.session, intent.owner, kEcSessionWrite, false);
  CO_RETURN_ON_ERROR(session);
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(txn, intent.object));
  if (!session->activeParent.is_nil())
    co_return makeError(StorageClientCode::kResourceBusy, "session already has an accepted mutation");
  if (session->acceptedSequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  auto context = co_await EcFileTreeCatalog::open(txn, intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  EcFileMutationRecord result;
  result.intent = intent;
  result.sessionSequence = ++session->acceptedSequence;
  result.epoch = root->epoch;
  if (!intent.length)
    result.state = EcFileMutationState::ClosedLogical;
  else
    session->activeParent = intent.request;
  CO_RETURN_ON_ERROR(co_await saveSession(txn, *session));
  CO_RETURN_ON_ERROR(co_await saveParent(txn, result));
  co_return result;
}

CoTryTask<std::optional<EcFileMutationRecord>> EcFileMutationCatalog::query(Tx &txn,
                                                                            const EcObjectRef &object,
                                                                            const Uuid &id,
                                                                            const EcOwner &actual) {
  if (id.is_nil() || actual.client.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto birth = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(birth);
  auto p = co_await load<EcFileMutationRecord>(txn, idKey(KeyPrefix::EcFileMutation, object, id));
  CO_RETURN_ON_ERROR(p);
  if (!*p) co_return std::nullopt;
  CO_RETURN_ON_ERROR(valid(**p));
  CO_RETURN_ON_ERROR(owner((**p).intent.owner, actual));
  if ((**p).intent.object != object || (**p).intent.request != id)
    co_return makeError(StatusCode::kDataCorruption, "pwrite key/body mismatch");
  auto s = co_await EcFileSessionCatalog::get(txn, object, (**p).intent.session, actual);
  CO_RETURN_ON_ERROR(s);
  if ((**p).sessionSequence > s->acceptedSequence ||
      ((**p).state == EcFileMutationState::Open && s->activeParent != id))
    co_return makeError(StatusCode::kDataCorruption, "pwrite lost its session acceptance");
  co_return std::move(*p);
}

CoTryTask<std::optional<EcFileChildRecord>> EcFileMutationCatalog::queryChild(Tx &txn,
                                                                              const EcObjectRef &object,
                                                                              const Uuid &id,
                                                                              const EcOwner &actual) {
  if (id.is_nil() || actual.client.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto birth = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(birth);
  auto c = co_await load<EcFileChildRecord>(txn, idKey(KeyPrefix::EcFileMutationChild, object, id));
  CO_RETURN_ON_ERROR(c);
  if (!*c) co_return std::nullopt;
  auto p = co_await parent(txn, object, (**c).intent.parent, actual);
  CO_RETURN_ON_ERROR(p);
  CO_RETURN_ON_ERROR(validChild(**c, *p, birth->shardBytes));
  if ((**c).intent.child != id || (**c).birth != birth->createRequest ||
      ((**c).state == EcFileChildState::Planned && p->activeChild != id))
    co_return makeError(StatusCode::kDataCorruption, "child key or active ownership differs");
  co_return std::move(*c);
}

CoTryTask<EcFileChildRecord> EcFileMutationCatalog::planChild(Tx &txn,
                                                              const EcOwner &actual,
                                                              const EcFileChildIntent &intent) {
  CO_RETURN_ON_ERROR(validChildIntent(intent));
  auto prior = co_await queryChild(txn, intent.object, intent.child, actual);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if (!same((**prior).intent, intent)) co_return makeError(StatusCode::kTokenMismatch, "child retry changed intent");
    co_return std::move(**prior);
  }
  auto p = co_await parent(txn, intent.object, intent.parent, actual);
  CO_RETURN_ON_ERROR(p);
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(txn, intent.object, intent.parent));
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(txn, intent.object));
  auto session =
      co_await EcFileSessionCatalog::require(txn, intent.object, p->intent.session, actual, kEcSessionWrite, true);
  CO_RETURN_ON_ERROR(session);
  if (p->state != EcFileMutationState::Open || p->confirmedPrefix == p->intent.length)
    co_return makeError(StatusCode::kTokenStale, "parent is logically closed");
  if (!p->activeChild.is_nil())
    co_return makeError(StorageClientCode::kResourceBusy, "previous child must be resolved by its original ID");
  if (intent.expectedPrefix != p->confirmedPrefix)
    co_return makeError(StatusCode::kTokenStale, "pwrite prefix changed");
  auto context = co_await EcFileTreeCatalog::open(txn, intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->epoch != p->epoch) co_return makeError(StatusCode::kTokenStale, "pwrite was fenced by a structural epoch");
  const uint64_t width = uint64_t(context->birth().shardBytes) * 10;
  const uint64_t at = p->intent.offset + p->confirmedPrefix;
  auto source = co_await EcFileTreeCatalog::lookup(*context, at / width);
  CO_RETURN_ON_ERROR(source);
  if (source->kind == EcTreeSlotKind::Data) {
    EcTreeSourcePinIntent pin;
    pin.object = intent.object;
    pin.owner = actual;
    pin.session = p->intent.session;
    pin.parent = intent.parent;
    pin.child = intent.child;
    pin.pin = intent.sourcePin;
    pin.root = root->root;
    pin.sequence = root->sequence;
    pin.epoch = root->epoch;
    pin.lengthAtPlan = root->visibleLength;
    pin.slot = *source;
    auto evidence = co_await EcTreeSourcePinCatalog::pinExactSource(txn, pin);
    CO_RETURN_ON_ERROR(evidence);
    // The same transaction creates the accepted child and its precise source
    // protection. The snapshot/grants stay Meta-internal, not in a write RPC.
    if (!same(evidence->record().intent, pin)) co_return makeError(StatusCode::kDataCorruption);
  } else if (source->kind != EcTreeSlotKind::Zero)
    co_return makeError(StatusCode::kDataCorruption);
  auto object = co_await EcCatalog::getObject(txn, intent.object);
  CO_RETURN_ON_ERROR(object);
  if (!object->nextGeneration || !object->nextRevision ||
      object->nextGeneration == std::numeric_limits<uint64_t>::max() ||
      object->nextRevision == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  EcFileChildRecord c;
  c.intent = intent;
  c.session = p->intent.session;
  c.owner = actual;
  c.birth = context->birth().createRequest;
  c.sourceRoot = root->root;
  c.sourceSequence = root->sequence;
  c.epoch = root->epoch;
  c.lengthAtPlan = root->visibleLength;
  c.source = *source;
  c.stripe = at / width;
  c.patchOffset = at % width;
  c.patchLength = std::min(p->intent.length - p->confirmedPrefix, width - c.patchOffset);
  // A Zero slot can describe a hole before EOF. Keep that entire visible
  // extent, not only the patch suffix; W1 fills all non-source bytes with zero.
  const uint64_t stripeStart = c.stripe * width;
  const uint64_t oldExtent = root->visibleLength > stripeStart ? std::min(width, root->visibleLength - stripeStart) : 0;
  c.targetLogicalLength = std::max<uint64_t>(oldExtent, uint64_t(c.patchOffset) + c.patchLength);
  c.targetGeneration = object->nextGeneration++;
  c.targetRevision = object->nextRevision++;
  CO_RETURN_ON_ERROR(validChild(c, *p, context->birth().shardBytes));
  p->activeChild = intent.child;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcObject, intent.object), *object));
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileMutationChild, intent.object, intent.child), c));
  CO_RETURN_ON_ERROR(co_await saveParent(txn, *p));
  co_return c;
}

CoTryTask<EcFileMutationRecord> EcFileMutationCatalog::sealPrefix(Tx &txn,
                                                                  const EcObjectRef &object,
                                                                  const Uuid &id,
                                                                  const EcOwner &actual) {
  auto p = co_await parent(txn, object, id, actual);
  CO_RETURN_ON_ERROR(p);
  if (p->state == EcFileMutationState::ClosedLogical) co_return p;
  auto s = co_await EcFileSessionCatalog::get(txn, object, p->intent.session, actual);
  CO_RETURN_ON_ERROR(s);
  if (s->activeParent != id) co_return makeError(StatusCode::kDataCorruption);
  if (!p->activeChild.is_nil()) {
    auto c = co_await queryChild(txn, object, p->activeChild, actual);
    CO_RETURN_ON_ERROR(c);
    if (!*c || (**c).state != EcFileChildState::Planned) co_return makeError(StatusCode::kDataCorruption);
    (**c).state = EcFileChildState::Fenced;
    CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileMutationChild, object, p->activeChild), **c));
    p->fencedChild = p->activeChild;
  }
  p->activeChild = Uuid::zero();
  p->state = EcFileMutationState::ClosedLogical;
  s->activeParent = Uuid::zero();
  CO_RETURN_ON_ERROR(co_await saveParent(txn, *p));
  CO_RETURN_ON_ERROR(co_await saveSession(txn, *s));
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::finishParent(txn, *p));
  if (s->state == EcFileSessionState::Closing)
    CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::close(txn, object, p->intent.session, actual));
  co_return p;
}

CoTryTask<EcFilePublicationGate> EcFileMutationCatalog::preparePublication(Tx &txn,
                                                                           const EcObjectRef &object,
                                                                           const Uuid &child,
                                                                           const EcOwner &actual) {
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(txn, object));
  auto c = co_await queryChild(txn, object, child, actual);
  CO_RETURN_ON_ERROR(c);
  if (!*c) co_return makeError(MetaCode::kNotFound);
  auto &record = **c;
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(txn, object, record.intent.parent));
  auto p = co_await parent(txn, object, record.intent.parent, actual);
  CO_RETURN_ON_ERROR(p);
  auto session = co_await EcFileSessionCatalog::require(txn, object, record.session, actual, kEcSessionWrite, true);
  CO_RETURN_ON_ERROR(session);
  if (record.state != EcFileChildState::Planned || p->state != EcFileMutationState::Open || p->activeChild != child ||
      p->confirmedPrefix != record.intent.expectedPrefix)
    co_return makeError(StatusCode::kTokenStale, "child no longer owns the next publication");
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  auto source = co_await EcFileTreeCatalog::lookup(*context, record.stripe);
  CO_RETURN_ON_ERROR(source);
  if (root->epoch != record.epoch || root->visibleLength != record.lengthAtPlan || !same(*source, record.source))
    co_return makeError(StatusCode::kTokenStale, "source extent, length, or structural epoch changed");
  co_return EcFilePublicationGate(txn, std::move(record), std::move(*root));
}

CoTryTask<EcFileMutationRecord> EcFileMutationCatalog::finishPublished(Tx &txn,
                                                                       const EcOwner &actual,
                                                                       const EcFilePublicationGate &gate,
                                                                       const EcTreeEditResult &edit) {
  if (gate.txn_ != &txn || gate.attempt_ != txn.attempt())
    co_return makeError(StatusCode::kTokenStale, "publication gate changed transaction");
  const auto &child = gate.child_.intent.child;
  const auto &object = edit.intent.object;
  auto c = co_await queryChild(txn, object, child, actual);
  CO_RETURN_ON_ERROR(c);
  if (!*c) co_return makeError(MetaCode::kNotFound);
  auto &record = **c;
  auto p = co_await parent(txn, object, record.intent.parent, actual);
  CO_RETURN_ON_ERROR(p);
  if (record.state == EcFileChildState::Published) {
    if (!record.publishedRoot || !same(*record.publishedRoot, edit.root))
      co_return makeError(StatusCode::kTokenMismatch);
    co_return p;
  }
  if (record.state != EcFileChildState::Planned || p->state != EcFileMutationState::Open || p->activeChild != child ||
      p->confirmedPrefix != record.intent.expectedPrefix)
    co_return makeError(StatusCode::kTokenStale, "logical prefix fence prevents late publication");
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto persisted = co_await EcFileTreeCatalog::queryEdit(*context, child);
  CO_RETURN_ON_ERROR(persisted);
  if (!*persisted || !same(**persisted, edit))
    co_return makeError(StatusCode::kDataCorruption, "missing exact same-transaction tree publication");
  const auto &e = edit.intent;
  const auto &slot = e.replacement;
  if (!same(record, gate.child_) || e.expectedRoot != gate.root_.root || e.expectedSequence != gate.root_.sequence ||
      e.operation != child || e.expectedEpoch != record.epoch || e.nodeIds != record.intent.nodeIds ||
      e.stripe != record.stripe || slot.kind != EcTreeSlotKind::Data || slot.revision != record.targetRevision ||
      slot.generation != record.targetGeneration || slot.logicalLength != record.targetLogicalLength ||
      slot.contentSha256 == storage::EcSha256{} ||
      e.visibleLength !=
          std::max(record.lengthAtPlan, p->intent.offset + record.intent.expectedPrefix + record.patchLength))
    co_return makeError(StatusCode::kTokenMismatch, "tree publication differs from accepted child");
  auto s = co_await EcFileSessionCatalog::get(txn, object, p->intent.session, actual);
  CO_RETURN_ON_ERROR(s);
  if (s->activeParent != p->intent.request || s->state == EcFileSessionState::Closed)
    co_return makeError(StatusCode::kTokenStale);
  record.state = EcFileChildState::Published;
  record.publishedRoot = edit.root;
  p->confirmedPrefix += record.patchLength;
  p->activeChild = Uuid::zero();
  if (p->confirmedPrefix == p->intent.length) {
    p->state = EcFileMutationState::ClosedLogical;
    s->activeParent = Uuid::zero();
  }
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileMutationChild, object, child), record));
  CO_RETURN_ON_ERROR(co_await saveParent(txn, *p));
  CO_RETURN_ON_ERROR(co_await saveSession(txn, *s));
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::finishParent(txn, *p));
  if (s->state == EcFileSessionState::Closing && s->activeParent.is_nil())
    CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::close(txn, object, p->intent.session, actual));
  co_return p;
}
}  // namespace hf3fs::meta::server
