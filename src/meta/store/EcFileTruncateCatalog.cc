#include "EcFileTruncateCatalog.h"

#include <limits>
#include <set>
#include <sys/stat.h>

#include "EcCatalog.h"
#include "EcFileAppendCatalog.h"
#include "EcFileDataInstaller.h"
#include "EcFileExecutionCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "Inode.h"
#include "detail/EcFileMutationKeys.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/EcTreeCut.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
using ec_file_mutation_detail::owner;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
using State = EcFileTruncateState;
Result<Void> validIntent(const EcFileTruncateIntent &i) {
  if (i.version != kEcFileTruncateVersion || i.action != EcFileStructuralAction::Truncate ||
      i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() || i.object.inode > InodeId::normalMax() ||
      i.owner.client.is_nil() || i.session.is_nil() || i.operation.is_nil() || i.child.is_nil() || i.plan.is_nil() ||
      i.sourcePin.is_nil() || i.child == i.operation || i.sourcePin == i.child || !i.expectedSequence ||
      i.expectedSequence >= std::numeric_limits<uint64_t>::max() - 1 || !i.expectedEpoch ||
      i.expectedEpoch == std::numeric_limits<uint64_t>::max())
    return makeError(StatusCode::kInvalidArg, "invalid fixed truncate intent");
  std::set<Uuid> ids;
  for (const auto &id : i.nodeIds)
    if (id.is_nil() || !ids.insert(id).second) return makeError(StatusCode::kInvalidArg);
  return Void{};
}
CoTryTask<EcTreeBirth> birth(Tx &txn, const EcObjectRef &object) {
  auto b = co_await require<EcTreeBirth>(txn, objectKey(KeyPrefix::EcTreeBirth, object));
  CO_RETURN_ON_ERROR(b);
  auto m = co_await require<EcV2ObjectMode>(txn, objectKey(KeyPrefix::EcV2ObjectMode, object));
  CO_RETURN_ON_ERROR(m);
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (b->object != object || b->createRequest.is_nil() || b->creator.client.is_nil() || m->mode != kEcFileTreeMode ||
      m->object != object || m->createRequest != b->createRequest || !same(m->creator, b->creator) ||
      file->createRequest != b->createRequest || !same(file->creator, b->creator) ||
      file->shardBytes != b->shardBytes || file->allowColocated != b->allowColocated)
    co_return makeError(StatusCode::kDataCorruption, "truncate lost exact mode4 birth");
  CO_RETURN_ON_ERROR(stripeStart(0, b->shardBytes));
  auto old = co_await txn.get(objectKey(KeyPrefix::EcGcEnrollment, object));
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return makeError(StatusCode::kDataCorruption);
  co_return *b;
}
Result<Void> validRecord(const EcFileTruncateRecord &r, const EcTreeBirth &b) {
  RETURN_ON_ERROR(validIntent(r.intent));
  const auto &i = r.intent;
  const auto &f = r.fencedRoot;
  if (r.birth != b.createRequest || i.object != b.object || f.object != b.object || f.birth != r.birth ||
      f.root != i.expectedRoot || f.sequence != i.expectedSequence + 1 || f.epoch != i.expectedEpoch + 1 ||
      f.visibleLength != i.expectedLength ||
      (r.state != State::Planned && r.state != State::Published && r.state != State::Aborted) ||
      (r.publishedRoot.has_value() != (r.state == State::Published)))
    return makeError(StatusCode::kDataCorruption, "invalid truncate progress/root binding");
  if (r.publishedRoot) {
    const auto &p = *r.publishedRoot;
    if (p.object != b.object || p.birth != r.birth || p.sequence != f.sequence + 1 || p.epoch != f.epoch ||
        p.visibleLength != i.length || p.root != (i.length < i.expectedLength ? i.nodeIds[15] : f.root))
      return makeError(StatusCode::kDataCorruption, "truncate published root changed");
  }
  if (r.tail) {
    const auto &c = *r.tail;
    const uint64_t width = uint64_t(b.shardBytes) * 10;
    auto empty = computeEcLogicalSha256({}, 0);
    RETURN_ON_ERROR(empty);
    if (i.length >= i.expectedLength || !(i.length % width) || c.intent.object != i.object ||
        c.intent.parent != i.operation || c.intent.child != i.child || c.intent.plan != i.plan ||
        c.intent.sourcePin != i.sourcePin || c.intent.expectedPrefix || c.intent.patchSha256 != *empty ||
        c.intent.nodeIds != i.nodeIds || c.session != i.session || !same(c.owner, i.owner) || c.birth != r.birth ||
        c.sourceRoot != f.root || c.sourceSequence != f.sequence || c.epoch != f.epoch ||
        c.lengthAtPlan != f.visibleLength || c.stripe != i.length / width || c.patchOffset || c.patchLength ||
        c.targetLogicalLength != i.length % width || !c.targetGeneration || !c.targetRevision ||
        c.source.kind != EcTreeSlotKind::Data || c.source.stripe != c.stripe ||
        c.source.logicalLength <= c.targetLogicalLength || c.source.logicalLength > width ||
        c.source.logicalLength > f.visibleLength - (i.length - i.length % width) || !c.source.revision ||
        !c.source.generation || c.targetRevision <= c.source.revision || c.targetGeneration <= c.source.generation ||
        c.source.contentSha256 == storage::EcSha256{} ||
        c.state != (r.state == State::Planned     ? EcFileChildState::Planned
                    : r.state == State::Published ? EcFileChildState::Published
                                                  : EcFileChildState::Fenced) ||
        !same(c.publishedRoot, r.publishedRoot))
      return makeError(StatusCode::kDataCorruption, "truncate tail child changed fixed plan");
  }
  return Void{};
}
CoTryTask<std::optional<EcFileStructuralGate>> gate(Tx &txn, const EcObjectRef &object) {
  auto g = co_await load<EcFileStructuralGate>(txn, objectKey(KeyPrefix::EcFileStructuralGate, object));
  CO_RETURN_ON_ERROR(g);
  if (!*g) {
    const auto first = objectKey(KeyPrefix::EcFileTruncate, object);
    auto old = co_await txn.getRange({first, true}, {kv::TransactionHelper::prefixListEndKey(first), false}, 1);
    CO_RETURN_ON_ERROR(old);
    if (!old->kvs.empty() || old->hasMore)
      co_return makeError(StatusCode::kDataCorruption, "structural gate missing beneath history");
    co_return std::nullopt;
  }
  auto b = co_await birth(txn, object);
  CO_RETURN_ON_ERROR(b);
  const auto &value = **g;
  if (value.object != object || value.birth != b->createRequest || value.operation.is_nil() || !value.epoch)
    co_return makeError(StatusCode::kDataCorruption);
  auto r = co_await require<EcFileTruncateRecord>(txn, idKey(KeyPrefix::EcFileTruncate, object, value.operation));
  CO_RETURN_ON_ERROR(r);
  CO_RETURN_ON_ERROR(validRecord(*r, *b));
  if (r->intent.operation != value.operation || r->fencedRoot.epoch != value.epoch ||
      value.active != (r->state == State::Planned))
    co_return makeError(StatusCode::kDataCorruption, "structural gate/history differs");
  co_return *g;
}
CoTryTask<EcFileTruncateRecord> required(Tx &txn,
                                         const EcOwner &actual,
                                         const EcObjectRef &object,
                                         const Uuid &operation) {
  auto r = co_await EcFileTruncateCatalog::query(txn, actual, object, operation);
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return makeError(MetaCode::kNotFound, "truncate record absent; not an execution outcome");
  co_return **r;
}
CoTryTask<EcFileTruncateRecord> byChild(Tx &txn, const EcOwner &actual, const EcObjectRef &object, const Uuid &child) {
  if (child.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto x = co_await require<EcFileTruncateChildIndex>(txn, idKey(KeyPrefix::EcFileTruncateChild, object, child));
  CO_RETURN_ON_ERROR(x);
  CO_RETURN_ON_ERROR(owner(x->owner, actual));
  if (x->object != object || x->child != child || x->operation.is_nil())
    co_return makeError(StatusCode::kDataCorruption);
  auto r = co_await required(txn, actual, object, x->operation);
  CO_RETURN_ON_ERROR(r);
  if (!r->tail || r->intent.child != child) co_return makeError(StatusCode::kDataCorruption);
  co_return *r;
}
CoTryTask<Void> current(Tx &txn, const EcFileTruncateRecord &r) {
  auto g = co_await gate(txn, r.intent.object);
  CO_RETURN_ON_ERROR(g);
  if (!*g || !(**g).active || (**g).operation != r.intent.operation || r.state != State::Planned)
    co_return makeError(StatusCode::kTokenStale, "truncate no longer owns the structural gate");
  auto context = co_await EcFileTreeCatalog::open(txn, r.intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (!same(*root, r.fencedRoot)) co_return makeError(StatusCode::kTokenStale, "truncate fenced root changed");
  co_return Void{};
}
}  // namespace

CoTryTask<std::optional<EcFileTruncateRecord>> EcFileTruncateCatalog::query(Tx &txn,
                                                                            const EcOwner &actual,
                                                                            const EcObjectRef &object,
                                                                            const Uuid &operation) {
  if (operation.is_nil() || actual.client.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto b = co_await birth(txn, object);
  CO_RETURN_ON_ERROR(b);
  auto r = co_await load<EcFileTruncateRecord>(txn, idKey(KeyPrefix::EcFileTruncate, object, operation));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  CO_RETURN_ON_ERROR(owner((**r).intent.owner, actual));
  CO_RETURN_ON_ERROR(validRecord(**r, *b));
  if ((**r).intent.operation != operation) co_return makeError(StatusCode::kDataCorruption);
  // Historical observation does not require current ACL/root/liveness.
  co_return *r;
}

CoTryTask<Void> EcFileTruncateCatalog::requireMutationOpen(Tx &txn, const EcObjectRef &object) {
  auto g = co_await gate(txn, object);
  CO_RETURN_ON_ERROR(g);
  if (*g && (**g).active) co_return makeError(StatusCode::kTokenStale, "structural mutation is active");
  co_return Void{};
}

CoTryTask<EcFileTruncateRecord> EcFileTruncateCatalog::begin(Tx &txn, const EcFileTruncateIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  auto prior = co_await query(txn, intent.owner, intent.object, intent.operation);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if (!same((**prior).intent, intent))
      co_return makeError(StatusCode::kTokenMismatch, "truncate intent changed across retry");
    co_return **prior;
  }
  CO_RETURN_ON_ERROR(co_await requireMutationOpen(txn, intent.object));
  auto session =
      co_await EcFileSessionCatalog::require(txn, intent.object, intent.session, intent.owner, kEcSessionWrite, false);
  CO_RETURN_ON_ERROR(session);
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::retainStructural(txn,
                                                                     intent.object,
                                                                     intent.session,
                                                                     intent.owner,
                                                                     intent.operation));
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(txn, intent.object, Uuid::zero()));
  auto context = co_await EcFileTreeCatalog::open(txn, intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->root != intent.expectedRoot || root->sequence != intent.expectedSequence ||
      root->epoch != intent.expectedEpoch || root->visibleLength != intent.expectedLength)
    co_return makeError(StatusCode::kTokenStale, "truncate initial root CAS failed");
  const uint64_t width = uint64_t(context->birth().shardBytes) * 10;
  EcTreeSlot source;
  if (intent.length < intent.expectedLength && intent.length % width) {
    auto loaded = co_await EcFileTreeCatalog::lookup(*context, intent.length / width);
    CO_RETURN_ON_ERROR(loaded);
    source = *loaded;
  }
  EcFileTruncateRecord r;
  r.intent = intent;
  r.birth = context->birth().createRequest;
  ++root->epoch;
  ++root->sequence;
  r.fencedRoot = *root;
  auto object = co_await EcCatalog::getObject(txn, intent.object);
  CO_RETURN_ON_ERROR(object);
  object->epoch = root->epoch;
  if (source.kind == EcTreeSlotKind::Data && source.logicalLength > intent.length % width) {
    if (object->nextGeneration == std::numeric_limits<uint64_t>::max() ||
        object->nextRevision == std::numeric_limits<uint64_t>::max())
      co_return makeError(StorageClientCode::kResourceBusy);
    EcFileChildRecord child;
    child.intent.object = intent.object;
    child.intent.parent = intent.operation;
    child.intent.child = intent.child;
    child.intent.plan = intent.plan;
    child.intent.sourcePin = intent.sourcePin;
    child.intent.nodeIds = intent.nodeIds;
    auto empty = computeEcLogicalSha256({}, 0);
    CO_RETURN_ON_ERROR(empty);
    child.intent.patchSha256 = *empty;
    child.session = intent.session;
    child.owner = intent.owner;
    child.birth = r.birth;
    child.sourceRoot = root->root;
    child.sourceSequence = root->sequence;
    child.epoch = root->epoch;
    child.lengthAtPlan = root->visibleLength;
    child.source = source;
    child.stripe = source.stripe;
    child.targetLogicalLength = intent.length % width;
    child.targetGeneration = object->nextGeneration++;
    child.targetRevision = object->nextRevision++;
    r.tail = std::move(child);
  }
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcObject, intent.object), *object));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcTreeRoot, intent.object), *root));
  if (r.tail) {
    const auto indexKey = idKey(KeyPrefix::EcFileTruncateChild, intent.object, intent.child);
    for (auto key : {indexKey,
                     idKey(KeyPrefix::EcFileMutationChild, intent.object, intent.child),
                     idKey(KeyPrefix::EcFileExecution, intent.object, intent.child)}) {
      auto old = co_await txn.get(key);
      CO_RETURN_ON_ERROR(old);
      if (*old) co_return makeError(StatusCode::kTokenDuplicated, "truncate child ID already exists");
    }
    EcTreeSourcePinIntent pin;
    pin.object = intent.object;
    pin.owner = intent.owner;
    pin.session = intent.session;
    pin.parent = intent.operation;
    pin.child = intent.child;
    pin.pin = intent.sourcePin;
    pin.root = root->root;
    pin.sequence = root->sequence;
    pin.epoch = root->epoch;
    pin.lengthAtPlan = root->visibleLength;
    pin.slot = source;
    auto pinned = co_await EcTreeSourcePinCatalog::pinExactSource(txn, pin);
    CO_RETURN_ON_ERROR(pinned);
    EcFileTruncateChildIndex x;
    x.object = intent.object;
    x.child = intent.child;
    x.operation = intent.operation;
    x.owner = intent.owner;
    CO_RETURN_ON_ERROR(co_await store(txn, indexKey, x));
  }
  CO_RETURN_ON_ERROR(validRecord(r, context->birth()));
  EcFileStructuralGate g;
  g.object = intent.object;
  g.birth = r.birth;
  g.operation = intent.operation;
  g.epoch = root->epoch;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileStructuralGate, intent.object), g));
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileTruncate, intent.object, intent.operation), r));
  co_return r;
}

CoTryTask<EcFileChildRecord> EcFileTruncateCatalog::executionChild(Tx &txn,
                                                                   const EcOwner &owner,
                                                                   const EcObjectRef &object,
                                                                   const Uuid &child) {
  auto r = co_await byChild(txn, owner, object, child);
  CO_RETURN_ON_ERROR(r);
  co_return *r->tail;
}
CoTryTask<Void> EcFileTruncateCatalog::requireExecutable(Tx &txn,
                                                         const EcOwner &owner,
                                                         const EcObjectRef &object,
                                                         const Uuid &child) {
  auto r = co_await byChild(txn, owner, object, child);
  CO_RETURN_ON_ERROR(r);
  CO_RETURN_ON_ERROR(co_await current(txn, *r));
  auto session = co_await EcFileSessionCatalog::require(txn, object, r->intent.session, owner, kEcSessionWrite, true);
  CO_RETURN_ON_ERROR(session);
  co_return Void{};
}
CoTryTask<Void> EcFileTruncateCatalog::fenceExecution(Tx &txn,
                                                      const EcOwner &owner,
                                                      const EcObjectRef &object,
                                                      const Uuid &child) {
  auto r = co_await byChild(txn, owner, object, child);
  CO_RETURN_ON_ERROR(r);
  auto stopped = co_await abort(txn, owner, object, r->intent.operation);
  CO_RETURN_ON_ERROR(stopped);
  co_return Void{};
}

CoTryTask<EcFileTruncateRecord> EcFileTruncateCatalog::abort(Tx &txn,
                                                             const EcOwner &owner,
                                                             const EcObjectRef &object,
                                                             const Uuid &operation) {
  auto r = co_await required(txn, owner, object, operation);
  CO_RETURN_ON_ERROR(r);
  if (r->state != State::Planned) co_return *r;
  CO_RETURN_ON_ERROR(co_await current(txn, *r));
  auto g = co_await gate(txn, object);
  CO_RETURN_ON_ERROR(g);
  r->state = State::Aborted;
  if (r->tail) r->tail->state = EcFileChildState::Fenced;
  (**g).active = false;
  // The epoch is never rolled back. Source/output scopes retain all debt.
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileTruncate, object, operation), *r));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileStructuralGate, object), **g));
  CO_RETURN_ON_ERROR(
      co_await EcFileSessionCatalog::releaseStructural(txn, object, r->intent.session, owner, operation));
  co_return *r;
}

CoTryTask<EcFileTruncateRecord> EcFileTruncateCatalog::publishWithoutTail(Tx &txn,
                                                                          const EcOwner &owner,
                                                                          const EcObjectRef &object,
                                                                          const Uuid &operation) {
  auto r = co_await required(txn, owner, object, operation);
  CO_RETURN_ON_ERROR(r);
  if (r->state == State::Published) co_return *r;
  if (r->tail) co_return makeError(StatusCode::kTokenStale, "Data tail requires verified RMW publication");
  co_return co_await finish(txn, *r, std::nullopt);
}

CoTryTask<EcFileTruncateRecord> EcFileTruncateCatalog::publishDataTail(Tx &txn,
                                                                       const EcOwner &owner,
                                                                       const EcObjectRef &object,
                                                                       const Uuid &operation,
                                                                       const EcRmwPublicationProof &proof) {
  auto r = co_await required(txn, owner, object, operation);
  CO_RETURN_ON_ERROR(r);
  if (!r->tail) co_return makeError(StatusCode::kTokenMismatch, "truncate has no Data tail execution");
  const auto &plan = proof.plan().input();
  if (plan.action != storage::EcRmwAction::TruncateTail || plan.object != object.incarnation ||
      plan.inode != object.inode.u64() || plan.parentId != operation || plan.operationId != r->intent.child)
    co_return makeError(StatusCode::kTokenMismatch, "proof belongs to a different structural action");
  auto validation = co_await EcFileExecutionCatalog::preparePublicationValidation(txn,
                                                                                  owner,
                                                                                  proof,
                                                                                  EcFileExecutionOwner::TruncateTail);
  CO_RETURN_ON_ERROR(validation);
  if (r->state == State::Published) {
    if (validation->record().state != EcFileExecutionState::Published)
      co_return makeError(StatusCode::kDataCorruption, "truncate root has no published execution");
    co_return *r;
  }
  CO_RETURN_ON_ERROR(co_await requireExecutable(txn, owner, object, r->intent.child));
  auto slot = co_await EcFileDataInstaller::installValidated(txn, *validation);
  CO_RETURN_ON_ERROR(slot);
  // All of these writes are in the SAME transaction. Any subsequent cut,
  // budget, inode or session failure discards the whole transaction.
  auto published = co_await finish(txn, *r, *slot);
  CO_RETURN_ON_ERROR(published);
  if (!published->publishedRoot) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(co_await EcFileExecutionCatalog::finishValidatedPublication(txn,
                                                                                 std::move(*validation),
                                                                                 *published->publishedRoot));
  co_return published;
}

CoTryTask<EcFileTruncateRecord> EcFileTruncateCatalog::finish(Tx &txn,
                                                              EcFileTruncateRecord r,
                                                              const std::optional<EcTreeSlot> &tail) {
  CO_RETURN_ON_ERROR(co_await current(txn, r));
  auto session = co_await EcFileSessionCatalog::require(txn,
                                                        r.intent.object,
                                                        r.intent.session,
                                                        r.intent.owner,
                                                        kEcSessionWrite,
                                                        true);
  CO_RETURN_ON_ERROR(session);
  if (tail.has_value() != r.tail.has_value()) co_return makeError(StatusCode::kTokenMismatch);
  if (tail && (tail->stripe != r.tail->stripe || tail->revision != r.tail->targetRevision ||
               tail->generation != r.tail->targetGeneration || tail->logicalLength != r.tail->targetLogicalLength))
    co_return makeError(StatusCode::kTokenMismatch, "verified truncate output differs from reserved child");
  auto context = co_await EcFileTreeCatalog::open(txn, r.intent.object);
  CO_RETURN_ON_ERROR(context);
  EcTreeCut cut;
  cut.object = r.intent.object;
  cut.operation = r.intent.operation;
  cut.expected = r.fencedRoot;
  cut.length = r.intent.length;
  cut.nodeIds = r.intent.nodeIds;
  cut.tail = tail;
  auto root = co_await EcFileTreeCatalog::cut(*context, cut);
  CO_RETURN_ON_ERROR(root);
  auto inode = co_await Inode::load(txn, r.intent.object.inode);
  CO_RETURN_ON_ERROR(inode);
  if (!*inode || !(**inode).isFile() || (**inode).asFile().length != r.fencedRoot.visibleLength)
    co_return makeError(StatusCode::kDataCorruption, "truncate inode length changed");
  (**inode).asFile().length = r.intent.length;
  (**inode).mtime = (**inode).ctime = UtcTime::now();
  if ((**inode).acl.uid != r.intent.owner.uid) {
    constexpr uint32_t special = S_ISUID | S_ISGID | S_ISVTX;
    (**inode).acl.perm = Permission((**inode).acl.perm.toUnderType() & ~special);
  }
  CO_RETURN_ON_ERROR(co_await (**inode).store(txn));
  r.state = State::Published;
  r.publishedRoot = *root;
  if (r.tail) {
    r.tail->state = EcFileChildState::Published;
    r.tail->publishedRoot = *root;
  }
  auto g = co_await require<EcFileStructuralGate>(txn, objectKey(KeyPrefix::EcFileStructuralGate, r.intent.object));
  CO_RETURN_ON_ERROR(g);
  g->active = false;
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileTruncate, r.intent.object, r.intent.operation), r));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileStructuralGate, r.intent.object), *g));
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::releaseStructural(txn,
                                                                      r.intent.object,
                                                                      r.intent.session,
                                                                      r.intent.owner,
                                                                      r.intent.operation));
  co_return r;
}
}  // namespace hf3fs::meta::server
