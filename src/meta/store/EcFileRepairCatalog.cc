#include "EcFileRepairCatalog.h"

#include <limits>

#include "EcCatalog.h"
#include "EcFileAppendCatalog.h"
#include "EcFileDataInstaller.h"
#include "EcFileExecutionCatalog.h"
#include "EcFileTruncateCatalog.h"
#include "EcV2LifecycleUtils.h"
#include "detail/EcFileMutationKeys.h"
#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcFileTreeTxnBudget;
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
EcTreeSourcePinIntent pin(const EcFileChildRecord &c) {
  EcTreeSourcePinIntent p;
  p.object = c.intent.object;
  p.owner = c.owner;
  p.session = c.session;
  p.parent = c.intent.parent;
  p.child = c.intent.child;
  p.pin = c.intent.sourcePin;
  p.root = c.sourceRoot;
  p.sequence = c.sourceSequence;
  p.epoch = c.epoch;
  p.lengthAtPlan = c.lengthAtPlan;
  p.slot = c.source;
  return p;
}
Result<Void> valid(const EcFileRepairRecord &r) {
  RETURN_ON_ERROR(validateEcFileRepairIntent(r.intent));
  const auto &i = r.intent;
  const auto &c = r.child;
  if (r.version != 1 || c.version != 1 || c.intent.object != i.object || c.intent.parent != i.operation ||
      c.intent.child != i.child || c.intent.plan != i.selection.planId || c.intent.sourcePin != i.sourcePin ||
      c.intent.nodeIds != i.nodeIds || c.session != i.session || !same(c.owner, i.owner) ||
      c.sourceRoot != i.expectedRoot || c.sourceSequence != i.expectedSequence || c.epoch != i.expectedEpoch ||
      c.source.kind != EcTreeSlotKind::Data || c.source.stripe != i.stripe || c.stripe != i.stripe ||
      !c.source.logicalLength || c.targetLogicalLength != c.source.logicalLength ||
      c.targetGeneration != c.source.generation || c.targetRevision <= c.source.revision || c.patchOffset ||
      c.patchLength || c.intent.expectedPrefix || c.birth.is_nil() ||
      (r.state == EcFileRepairState::Planned     ? c.state != EcFileChildState::Planned
       : r.state == EcFileRepairState::Published ? c.state != EcFileChildState::Published
       : r.state == EcFileRepairState::Aborted   ? c.state != EcFileChildState::Fenced
                                                 : true) ||
      ((r.state == EcFileRepairState::Published) != c.publishedRoot.has_value()))
    return makeError(StatusCode::kDataCorruption, "repair immutable child/state differs");
  CHECK_RESULT(empty, computeEcLogicalSha256({}, 0));
  if (c.intent.patchSha256 != empty) return makeError(StatusCode::kDataCorruption);
  return Void{};
}
std::string aliasKey(const EcFileRepairIntent &i) {
  auto k = objectKey(KeyPrefix::EcFileRepair, i.object);
  k.push_back(char{1});
  k.append(i.request.asStringView());
  return k;
}
CoTryTask<EcFileRepairRecord> required(Tx &t, const EcOwner &o, const EcObjectRef &f, const Uuid &id) {
  auto r = co_await EcFileRepairCatalog::query(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return makeError(MetaCode::kNotFound, "missing repair record is not failed-commit proof");
  co_return std::move(**r);
}
CoTryTask<Void> save(Tx &t, const EcFileRepairRecord &r) {
  co_return co_await store(t, idKey(KeyPrefix::EcFileRepair, r.intent.object, r.intent.operation), r);
}
}  // namespace
CoTryTask<std::optional<EcFileRepairRecord>> EcFileRepairCatalog::query(Tx &t,
                                                                        const EcOwner &o,
                                                                        const EcObjectRef &f,
                                                                        const Uuid &id) {
  if (id.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto birth = co_await EcFileTreeCatalog::getBirth(t, f);
  CO_RETURN_ON_ERROR(birth);
  auto r = co_await load<EcFileRepairRecord>(t, idKey(KeyPrefix::EcFileRepair, f, id));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  CO_RETURN_ON_ERROR(valid(**r));
  CO_RETURN_ON_ERROR(owner((**r).intent.owner, o));
  if ((**r).intent.object != f || (**r).intent.operation != id || (**r).child.birth != birth->createRequest)
    co_return makeError(StatusCode::kDataCorruption);
  auto session = co_await EcFileSessionCatalog::get(t, f, (**r).intent.session, o);
  CO_RETURN_ON_ERROR(session);
  if ((session->intent.rights & uint8_t{3}) != 3)
    co_return makeError(MetaCode::kNoPermission, "explicit repair requires accepted READ and WRITE rights");
  if ((**r).state == EcFileRepairState::Planned && session->activeStructural != id)
    co_return makeError(StatusCode::kDataCorruption);
  auto alias = co_await require<EcFileRepairIntent>(t, aliasKey((**r).intent));
  CO_RETURN_ON_ERROR(alias);
  if (!same(*alias, (**r).intent)) co_return makeError(StatusCode::kDataCorruption);
  co_return r;
}
CoTryTask<EcFileRepairRecord> EcFileRepairCatalog::byChild(Tx &t,
                                                           const EcOwner &o,
                                                           const EcObjectRef &f,
                                                           const Uuid &child) {
  auto index = co_await require<EcFileRepairChildIndex>(t, idKey(KeyPrefix::EcFileRepairChild, f, child));
  CO_RETURN_ON_ERROR(index);
  if (index->object != f || index->child != child) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(owner(index->owner, o));
  auto r = co_await required(t, o, f, index->operation);
  CO_RETURN_ON_ERROR(r);
  if (r->intent.child != child) co_return makeError(StatusCode::kDataCorruption);
  co_return r;
}
CoTryTask<EcFileChildRecord> EcFileRepairCatalog::executionChild(Tx &t,
                                                                 const EcOwner &o,
                                                                 const EcObjectRef &f,
                                                                 const Uuid &id) {
  auto r = co_await byChild(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  co_return std::move(r->child);
}
CoTryTask<Void> EcFileRepairCatalog::requireExecutable(Tx &t, const EcOwner &o, const EcObjectRef &f, const Uuid &id) {
  auto r = co_await byChild(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  if (r->state != EcFileRepairState::Planned) co_return makeError(StatusCode::kTokenStale);
  auto session = co_await EcFileSessionCatalog::require(t, f, r->intent.session, o, 3, true);
  CO_RETURN_ON_ERROR(session);
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(t, f, Uuid::zero()));
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(t, f));
  auto context = co_await EcFileTreeCatalog::open(t, f);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  auto slot = co_await EcFileTreeCatalog::lookup(*context, r->intent.stripe);
  CO_RETURN_ON_ERROR(slot);
  if (root->epoch != r->child.epoch || root->visibleLength != r->child.lengthAtPlan || !same(*slot, r->child.source))
    co_return makeError(StatusCode::kTokenStale, "repair source or structural epoch changed");
  co_return Void{};
}
CoTryTask<EcFileRepairRecord> EcFileRepairCatalog::begin(Tx &t, const EcFileRepairIntent &i) {
  CO_RETURN_ON_ERROR(validateEcFileRepairIntent(i));
  auto old = co_await query(t, i.owner, i.object, i.operation);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    if (!same((**old).intent, i)) co_return makeError(StatusCode::kTokenMismatch);
    co_return std::move(**old);
  }
  auto alias = co_await t.get(aliasKey(i));
  CO_RETURN_ON_ERROR(alias);
  if (*alias) co_return makeError(StatusCode::kTokenMismatch, "repair request UUID already bound");
  for (auto prefix : {KeyPrefix::EcFileMutation, KeyPrefix::EcFileTruncate}) {
    auto oldId = co_await t.get(idKey(prefix, i.object, i.operation));
    CO_RETURN_ON_ERROR(oldId);
    if (*oldId)
      co_return makeError(StatusCode::kTokenDuplicated,
                          "repair operation identity already belongs to another mutation");
  }
  auto session = co_await EcFileSessionCatalog::require(t, i.object, i.session, i.owner, 3, false);
  CO_RETURN_ON_ERROR(session);
  if (!session->activeParent.is_nil()) co_return makeError(StorageClientCode::kResourceBusy);
  CO_RETURN_ON_ERROR(co_await EcFileAppendCatalog::requireMutationOpen(t, i.object, Uuid::zero()));
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(t, i.object));
  auto context = co_await EcFileTreeCatalog::open(t, i.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->root != i.expectedRoot || root->sequence != i.expectedSequence || root->epoch != i.expectedEpoch)
    co_return makeError(StatusCode::kTokenStale);
  auto source = co_await EcFileTreeCatalog::lookup(*context, i.stripe);
  CO_RETURN_ON_ERROR(source);
  if (source->kind != EcTreeSlotKind::Data)
    co_return makeError(StatusCode::kInvalidArg, "only actual Data leaves require repair");
  auto object = co_await EcCatalog::getObject(t, i.object);
  CO_RETURN_ON_ERROR(object);
  if (object->nextRevision <= source->revision || object->nextRevision == UINT64_MAX ||
      object->nextGeneration <= source->generation)
    co_return makeError(StatusCode::kDataCorruption, "repair cannot recycle content generation or manifest revision");
  for (auto prefix : {KeyPrefix::EcFileRepairChild,
                      KeyPrefix::EcFileMutationChild,
                      KeyPrefix::EcFileTruncateChild,
                      KeyPrefix::EcFileExecution}) {
    auto v = co_await t.get(idKey(prefix, i.object, i.child));
    CO_RETURN_ON_ERROR(v);
    if (*v) co_return makeError(StatusCode::kTokenDuplicated);
  }
  EcFileRepairRecord r;
  r.intent = i;
  auto &c = r.child;
  c.intent.object = i.object;
  c.intent.parent = i.operation;
  c.intent.child = i.child;
  c.intent.plan = i.selection.planId;
  c.intent.sourcePin = i.sourcePin;
  c.intent.nodeIds = i.nodeIds;
  auto empty = computeEcLogicalSha256({}, 0);
  CO_RETURN_ON_ERROR(empty);
  c.intent.patchSha256 = *empty;
  c.owner = i.owner;
  c.session = i.session;
  c.birth = context->birth().createRequest;
  c.sourceRoot = root->root;
  c.sourceSequence = root->sequence;
  c.epoch = root->epoch;
  c.lengthAtPlan = root->visibleLength;
  c.source = *source;
  c.stripe = i.stripe;
  c.targetLogicalLength = source->logicalLength;
  c.targetGeneration = source->generation;
  c.targetRevision = object->nextRevision++;
  CO_RETURN_ON_ERROR(valid(r));
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::retainStructural(t, i.object, i.session, i.owner, i.operation));
  auto held = co_await EcTreeSourcePinCatalog::pinExactSource(t, pin(c));
  CO_RETURN_ON_ERROR(held);
  EcFileRepairChildIndex index;
  index.object = i.object;
  index.owner = i.owner;
  index.child = i.child;
  index.operation = i.operation;
  CO_RETURN_ON_ERROR(co_await store(t, idKey(KeyPrefix::EcFileRepairChild, i.object, i.child), index));
  CO_RETURN_ON_ERROR(co_await store(t, objectKey(KeyPrefix::EcObject, i.object), *object));
  CO_RETURN_ON_ERROR(co_await store(t, aliasKey(i), i));
  CO_RETURN_ON_ERROR(co_await save(t, r));
  co_return r;
}
CoTryTask<EcFileRepairRecord> EcFileRepairCatalog::abort(Tx &t,
                                                         const EcOwner &o,
                                                         const EcObjectRef &f,
                                                         const Uuid &id) {
  auto r = co_await required(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  if (r->state != EcFileRepairState::Planned) co_return r;
  r->state = EcFileRepairState::Aborted;
  r->child.state = EcFileChildState::Fenced;
  CO_RETURN_ON_ERROR(co_await save(t, *r));
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::releaseStructural(t, f, r->intent.session, o, id));
  co_return r;
}
CoTryTask<Void> EcFileRepairCatalog::fenceExecution(Tx &t, const EcOwner &o, const EcObjectRef &f, const Uuid &id) {
  auto r = co_await byChild(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  auto done = co_await abort(t, o, f, r->intent.operation);
  CO_RETURN_ON_ERROR(done);
  co_return Void{};
}
CoTryTask<EcFileRepairRecord> EcFileRepairCatalog::publish(Tx &t,
                                                           const EcOwner &o,
                                                           const EcObjectRef &f,
                                                           const Uuid &id,
                                                           const EcRmwPublicationProof &proof) {
  auto r = co_await required(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  const auto &p = proof.plan().input();
  if (p.action != storage::EcRmwAction::Repair || p.object != f.incarnation || p.inode != f.inode.u64() ||
      p.operationId != r->intent.child || p.parentId != id ||
      proof.manifest().generation != r->child.source.generation ||
      proof.drain().verifiedContentSha256 != r->child.source.contentSha256)
    co_return makeError(StatusCode::kTokenMismatch);
  auto validation =
      co_await EcFileExecutionCatalog::preparePublicationValidation(t, o, proof, EcFileExecutionOwner::Repair);
  CO_RETURN_ON_ERROR(validation);
  if (r->state == EcFileRepairState::Published) {
    if (validation->record().state != EcFileExecutionState::Published) co_return makeError(StatusCode::kDataCorruption);
    co_return r;
  }
  CO_RETURN_ON_ERROR(co_await requireExecutable(t, o, f, r->intent.child));
  auto slot = co_await EcFileDataInstaller::installValidated(t, *validation);
  CO_RETURN_ON_ERROR(slot);
  auto context = co_await EcFileTreeCatalog::open(t, f);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  EcTreeEdit e;
  e.object = f;
  e.operation = r->intent.child;
  e.expectedRoot = root->root;
  e.expectedSequence = root->sequence;
  e.expectedEpoch = root->epoch;
  e.stripe = r->intent.stripe;
  e.visibleLength = root->visibleLength;
  e.nodeIds = r->intent.nodeIds;
  e.replacement = *slot;
  auto installed = co_await EcFileTreeCatalog::replace(*context, e);
  CO_RETURN_ON_ERROR(installed);
  r->state = EcFileRepairState::Published;
  r->child.state = EcFileChildState::Published;
  r->child.publishedRoot = installed->root;
  CO_RETURN_ON_ERROR(co_await save(t, *r));
  CO_RETURN_ON_ERROR(
      co_await EcFileExecutionCatalog::finishValidatedPublication(t, std::move(*validation), installed->root));
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::releaseStructural(t, f, r->intent.session, o, id));
  co_return r;
}
CoTryTask<Void> EcFileRepairCatalog::addHelperEndpoints(Tx &t,
                                                        const EcFileChildRecord &c,
                                                        EcV2OperationEndpoints &set) {
  auto r = co_await byChild(t, c.owner, c.intent.object, c.intent.child);
  CO_RETURN_ON_ERROR(r);
  auto source = co_await EcTreeSourcePinCatalog::query(t, pin(c));
  CO_RETURN_ON_ERROR(source);
  for (auto index : r->intent.selection.sourceOrder)
    CO_RETURN_ON_ERROR(ec_v2_lifecycle::addEndpoint(set, source->allocations[index].endpoint()));
  co_return Void{};
}
CoTryTask<std::shared_ptr<const storage::EcRepairPlan>> EcFileRepairCatalog::repairPlan(Tx &t,
                                                                                        const EcOwner &o,
                                                                                        const EcObjectRef &f,
                                                                                        const Uuid &id) {
  auto r = co_await byChild(t, o, f, id);
  CO_RETURN_ON_ERROR(r);
  auto execution = co_await EcFileExecutionCatalog::get(t, o, f, id);
  CO_RETURN_ON_ERROR(execution);
  if (execution->record.ownerKind != EcFileExecutionOwner::Repair || !execution->record.allocations)
    co_return makeError(StatusCode::kTokenStale);
  const auto &p = execution->plan->input();
  storage::EcRepairPlanInput result;
  result.planId = r->intent.selection.planId;
  result.operationId = id;
  result.ownerUid = o.uid;
  result.clientNamespace = o.client;
  result.baseEpoch = p.fenceEpoch;
  result.baseRevision = p.sourceRevision;
  result.logicalLength = p.sourceLogicalLength;
  result.logicalSha256 = p.sourceLogicalSha256;
  result.maxBlocksInFlight = r->intent.selection.maxBlocksInFlight;
  for (size_t n = 0; n < 10; ++n) result.sources[n] = p.sources[r->intent.selection.sourceOrder[n]];
  for (size_t n = 0; n < 12; ++n)
    if (r->intent.replacementMask & (uint16_t{1} << n)) {
      const auto &a = (*execution->record.allocations)[n];
      auto &target = result.targets[result.targetCount++];
      target.identity = a.fragment.identity;
      target.operationId = a.fragment.operation;
      target.writerNamespace = a.writer.client;
      target.endpoint = a.endpoint().controlEndpoint();
      target.integrity = a.fragment.integrity;
    }
  result.operationEndpointCount = execution->record.endpoints.count;
  for (size_t n = 0; n < result.operationEndpointCount; ++n)
    result.operationEndpoints[n] = execution->record.endpoints.endpoints[n].controlEndpoint();
  co_return storage::EcRepairPlan::create(std::move(result));
}
}  // namespace hf3fs::meta::server
