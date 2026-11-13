#include "EcFileExecutionCatalog.h"
#include "meta/store/EcTerminalEvidence.h"

#include <limits>
#include <set>
#include <utility>

#include "EcCatalog.h"
#include "EcFileRepairCatalog.h"
#include "EcFileTruncateCatalog.h"
#include "EcV2LifecycleUtils.h"
#include "detail/EcFileMutationKeys.h"
#include "meta/components/EcRmwPublicationProof.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
namespace life = ec_v2_lifecycle;
using Tx = EcFileTreeTxnBudget;
using State = EcFileExecutionState;
using kv::KeyPrefix;
CoTryTask<EcFileChildRecord> loadChild(Tx &txn,
                                       const EcOwner &owner,
                                       const EcObjectRef &object,
                                       const Uuid &id,
                                       EcFileExecutionOwner kind) {
  if (kind == EcFileExecutionOwner::Repair)
    co_return co_await EcFileRepairCatalog::executionChild(txn, owner, object, id);
  if (kind == EcFileExecutionOwner::TruncateTail)
    co_return co_await EcFileTruncateCatalog::executionChild(txn, owner, object, id);
  if (kind != EcFileExecutionOwner::Pwrite)
    co_return makeError(StatusCode::kDataCorruption, "unknown execution owner kind");
  auto c = co_await EcFileMutationCatalog::queryChild(txn, object, id, owner);
  CO_RETURN_ON_ERROR(c);
  if (!*c) co_return makeError(MetaCode::kNotFound, "execution has no accepted child");
  co_return std::move(**c);
}
CoTryTask<Void> requireExecutable(Tx &txn,
                                  const EcOwner &owner,
                                  const EcObjectRef &object,
                                  const Uuid &id,
                                  EcFileExecutionOwner kind) {
  if (kind == EcFileExecutionOwner::Repair)
    co_return co_await EcFileRepairCatalog::requireExecutable(txn, owner, object, id);
  if (kind == EcFileExecutionOwner::TruncateTail)
    co_return co_await EcFileTruncateCatalog::requireExecutable(txn, owner, object, id);
  if (kind != EcFileExecutionOwner::Pwrite) co_return makeError(StatusCode::kDataCorruption);
  auto gate = co_await EcFileMutationCatalog::preparePublication(txn, object, id, owner);
  CO_RETURN_ON_ERROR(gate);
  co_return Void{};
}
CoTryTask<Void> fence(Tx &txn, const EcFileExecutionRecord &r) {
  const auto &c = r.child;
  if (r.ownerKind == EcFileExecutionOwner::Repair)
    co_return co_await EcFileRepairCatalog::fenceExecution(txn, c.owner, c.intent.object, c.intent.child);
  if (r.ownerKind == EcFileExecutionOwner::TruncateTail)
    co_return co_await EcFileTruncateCatalog::fenceExecution(txn, c.owner, c.intent.object, c.intent.child);
  CO_RETURN_ON_ERROR(co_await EcFileMutationCatalog::sealPrefix(txn, c.intent.object, c.intent.parent, c.owner));
  co_return Void{};
}
std::string key(const EcObjectRef &object, const Uuid &child) {
  return idKey(KeyPrefix::EcFileExecution, object, child);
}
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
CoTryTask<std::shared_ptr<const storage::EcRmwPlan>> makePlan(Tx &txn, const EcFileExecutionRecord &r) {
  const auto &c = r.child;
  auto birth = co_await EcFileTreeCatalog::getBirth(txn, c.intent.object);
  CO_RETURN_ON_ERROR(birth);
  storage::EcRmwPlanInput p;
  p.action = r.ownerKind == EcFileExecutionOwner::Repair         ? storage::EcRmwAction::Repair
             : r.ownerKind == EcFileExecutionOwner::TruncateTail ? storage::EcRmwAction::TruncateTail
                                                                 : storage::EcRmwAction::Pwrite;
  p.inode = c.intent.object.inode.u64();
  p.object = c.intent.object.incarnation;
  p.birth = c.birth;
  p.planId = c.intent.plan;
  p.sessionId = c.session;
  p.parentId = c.intent.parent;
  p.operationId = c.intent.child;
  p.ownerUid = c.owner.uid;
  p.clientNamespace = c.owner.client;
  p.fenceEpoch = c.epoch;
  p.sourceRoot = c.sourceRoot;
  p.sourceSequence = c.sourceSequence;
  p.lengthAtPlan = c.lengthAtPlan;
  p.stripe = c.stripe;
  p.shardBytes = birth->shardBytes;
  if (c.source.kind == EcTreeSlotKind::Data) {
    auto source = co_await EcTreeSourcePinCatalog::query(txn, pin(c));
    CO_RETURN_ON_ERROR(source);
    p.sourceKind = storage::EcRmwSourceKind::Data;
    p.sourcePin = c.intent.sourcePin;
    p.sourceRevision = c.source.revision;
    p.sourceGeneration = c.source.generation;
    p.sourceLogicalLength = c.source.logicalLength;
    p.sourceLogicalSha256 = c.source.contentSha256;
    for (size_t i = 0; i < 12; ++i) {
      const auto &a = source->allocations[i];
      auto &s = p.sources[i];
      s.identity = a.fragment.identity;
      s.operationId = a.fragment.operation;
      s.writerNamespace = a.writer.client;
      s.endpoint = a.endpoint().controlEndpoint();
      s.integrity = a.fragment.integrity;
    }
  } else if (c.source.kind != EcTreeSlotKind::Zero)
    co_return makeError(StatusCode::kDataCorruption);
  // Zero plans deliberately contain no pin, old binding, or read credential.
  p.targetGeneration = c.targetGeneration;
  p.targetRevision = c.targetRevision;
  p.workerIndex = r.workerIndex;
  p.patchOffset = c.patchOffset;
  p.patchLength = c.patchLength;
  p.patchSha256 = c.intent.patchSha256;
  p.targetLogicalLength = c.targetLogicalLength;
  for (size_t i = 0; i < 12; ++i) {
    p.targets[i].identity = r.candidates[i].identity;
    p.targets[i].endpoint = r.candidates[i].endpoint.controlEndpoint();
  }
  co_return storage::EcRmwPlan::create(std::move(p));
}
Result<Void> validAllocation(const EcFileExecutionAllocation &a,
                             const EcObjectRef &o,
                             const EcV2ReservedAllocation &expected) {
  if (a.version != kEcFileMutationVersion || a.object != o || a.child != expected.operation ||
      !same(a.allocation, expected))
    return makeError(StatusCode::kDataCorruption, "execution allocation key/body mismatch");
  return Void{};
}
EcManifest manifest(const EcFileExecutionRecord &r) {
  EcManifest m;
  m.object = r.child.intent.object;
  m.stripe = r.child.stripe;
  m.generation = r.child.targetGeneration;
  m.revision = r.child.targetRevision;
  m.logicalLength = r.child.targetLogicalLength;
  if (r.allocations)
    for (size_t i = 0; i < 12; ++i) m.fragments[i] = (*r.allocations)[i].fragment;
  return m;
}
EcV2DrainRecord drainFor(const EcFileExecutionRecord &r, const Uuid &authority, const Uuid &revocation) {
  EcV2DrainRecord d;
  auto &i = d.identity;
  i.object = r.child.intent.object;
  i.kind = storage::EcGrantScope::WriteOperation;
  i.scopeId = r.child.intent.child;
  i.owner = r.child.owner;
  i.objectEpoch = r.child.epoch;
  i.generation = r.child.targetGeneration;
  i.revision = r.child.targetRevision;
  i.clusterAuthority = authority;
  i.revocationId = revocation;
  i.endpoints = r.endpoints;
  return d;
}
// Only finishDrain()/finishValidatedPublication() call this after complete get()
// in the same transaction attempt. That get conflict-reads and checks every
// field of all twelve allocation records; no intervening operation writes
// those keys or resets the transaction. Reconstruct the exact checked records
// with active=false instead of reading them a second time. Never reactivate.
CoTryTask<Void> releaseValidatedAllocations(Tx &txn, const EcFileExecutionRecord &r) {
  for (const auto &s : r.candidates) {
    auto k = allocationKey(KeyPrefix::EcFileExecutionAllocation, s.identity);
    CO_RETURN_ON_ERROR(k);
    EcFileExecutionAllocation a;
    a.object = r.child.intent.object;
    a.child = s.operation;
    a.allocation = s;
    a.active = false;
    CO_RETURN_ON_ERROR(co_await store(txn, *k, a));
  }
  co_return Void{};
}
CoTryTask<Void> admissible(Tx &txn, const EcFileExecutionObservation &o) {
  if (o.record.state != State::Reserved && o.record.state != State::Bound)
    co_return makeError(StatusCode::kTokenStale, "execution issuance permanently closed");
  CO_RETURN_ON_ERROR(co_await requireExecutable(txn,
                                                o.record.child.owner,
                                                o.record.child.intent.object,
                                                o.record.child.intent.child,
                                                o.record.ownerKind));
  co_return Void{};
}
}  // namespace

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::get(Tx &txn,
                                                                  const EcOwner &owner,
                                                                  const EcObjectRef &object,
                                                                  const Uuid &child) {
  auto r = co_await require<EcFileExecutionRecord>(txn, key(object, child));
  CO_RETURN_ON_ERROR(r);
  auto current = co_await loadChild(txn, owner, object, child, r->ownerKind);
  CO_RETURN_ON_ERROR(current);
  auto frozen = *current;
  frozen.state = EcFileChildState::Planned;
  frozen.publishedRoot.reset();
  if (!same(r->child, frozen) || r->workerIndex >= 12 || r->planDigest == storage::EcSha256{} ||
      (r->state != State::Reserved && r->state != State::Bound && r->state != State::Closing &&
       r->state != State::Drained && r->state != State::Published && r->state != State::Aborted))
    co_return makeError(StatusCode::kDataCorruption, "execution changed its immutable child");
  CO_RETURN_ON_ERROR(life::setValid(r->endpoints));
  EcV2OperationEndpoints actual;
  const bool active = r->state != State::Published && r->state != State::Aborted;
  for (size_t i = 0; i < 12; ++i) {
    const auto &s = r->candidates[i];
    CO_RETURN_ON_ERROR(s.identity.validate());
    if (s.identity.object != object.incarnation || s.identity.stripe != r->child.stripe ||
        s.identity.generation != r->child.targetGeneration || s.identity.shard != i || s.operation != child ||
        !same(s.writer, owner))
      co_return makeError(StatusCode::kDataCorruption, "execution allocation differs from accepted child");
    CO_RETURN_ON_ERROR(life::addEndpoint(actual, s.endpoint));
    auto k = allocationKey(KeyPrefix::EcFileExecutionAllocation, s.identity);
    CO_RETURN_ON_ERROR(k);
    auto a = co_await require<EcFileExecutionAllocation>(txn, *k);
    CO_RETURN_ON_ERROR(a);
    CO_RETURN_ON_ERROR(validAllocation(*a, object, s));
    if (a->active != active)
      co_return makeError(StatusCode::kDataCorruption, "execution reservation lost active protection");
    if (r->allocations) {
      const auto &binding = (*r->allocations)[i];
      if (binding.object != object || !same(binding.fragment.identity, s.identity) ||
          binding.fragment.operation != child || binding.endpoint() != s.endpoint || !same(binding.writer, s.writer))
        co_return makeError(StatusCode::kDataCorruption);
      CO_RETURN_ON_ERROR(storage::validateEcIntegrity(s.identity, binding.fragment.integrity));
      auto bk = allocationKey(KeyPrefix::EcV2Allocation, s.identity);
      CO_RETURN_ON_ERROR(bk);
      auto bound = co_await require<EcV2AllocationBinding>(txn, *bk);
      CO_RETURN_ON_ERROR(bound);
      if (!same(*bound, binding)) co_return makeError(StatusCode::kDataCorruption, "execution lost permanent binding");
    }
  }
  if (r->ownerKind == EcFileExecutionOwner::Repair)
    CO_RETURN_ON_ERROR(co_await EcFileRepairCatalog::addHelperEndpoints(txn, r->child, actual));
  auto digest = life::setDigest(actual);
  CO_RETURN_ON_ERROR(digest);
  actual.digest = *digest;
  if (!same(actual, r->endpoints) ||
      (r->ownerKind == EcFileExecutionOwner::Repair ? actual.count < 12 || actual.count > 22 : actual.count != 12) ||
      (r->allocations.has_value() != (r->contentSha256 != storage::EcSha256{})) ||
      ((r->state == State::Reserved) && r->allocations) ||
      ((r->state == State::Bound || r->state == State::Drained || r->state == State::Published) && !r->allocations))
    co_return makeError(StatusCode::kDataCorruption, "invalid execution binding or endpoint set");
  if ((r->state == State::Reserved || r->state == State::Bound) != !r->drain)
    co_return makeError(StatusCode::kDataCorruption, "execution drain state mismatch");
  if (r->drain) {
    CO_RETURN_ON_ERROR(life::drainValid(*r->drain));
    CO_RETURN_ON_ERROR(co_await verifyEcStoredRetirementReferences(txn, *r->drain));
    if (r->drain->version == kEcV2RetirementDrainVersion && current->state != EcFileChildState::Fenced)
      co_return makeError(StatusCode::kDataCorruption, "retirement lost the typed child fence");
    if (!same(drainFor(*r, r->drain->identity.clusterAuthority, r->drain->identity.revocationId).identity,
              r->drain->identity) ||
        (r->drain->verifiedManifest &&
         (!same(*r->drain->verifiedManifest, manifest(*r)) || r->drain->verifiedContentSha256 != r->contentSha256)) ||
        ((r->state == State::Drained || r->state == State::Published) && !r->drain->verifiedManifest) ||
        r->drain->state != (r->state == State::Published ? EcV2DrainState::Published
                            : r->state == State::Aborted ? EcV2DrainState::Aborted
                                                         : EcV2DrainState::Closing))
      co_return makeError(StatusCode::kDataCorruption, "execution drain differs from fixed publication");
    if ((r->state == State::Drained || r->state == State::Published) &&
        r->drain->version != kEcV2LifecycleVersion)
      co_return makeError(StatusCode::kDataCorruption, "retirement cannot complete a publication drain");
    if (r->state == State::Drained || r->state == State::Published || r->state == State::Aborted)
      for (size_t i = 0; i < r->endpoints.count; ++i)
        if (!ecTerminalAt(*r->drain, i))
          co_return makeError(StatusCode::kDataCorruption, "terminal execution lost an ACK");
  }
  auto plan = co_await makePlan(txn, *r);
  CO_RETURN_ON_ERROR(plan);
  if ((*plan)->digest() != r->planDigest)
    co_return makeError(StatusCode::kDataCorruption, "execution plan digest changed");
  co_return EcFileExecutionObservation{std::move(*r), std::move(*plan)};
}

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::reserveExecution(Tx &txn,
                                                                               const EcOwner &owner,
                                                                               const EcObjectRef &object,
                                                                               const Uuid &child,
                                                                               const TrustedPool &trustedPool,
                                                                               uint8_t workerIndex,
                                                                               EcFileExecutionOwner kind) {
  auto existing = co_await txn.get(key(object, child));
  CO_RETURN_ON_ERROR(existing);
  if (*existing) {
    auto old = co_await get(txn, owner, object, child);
    CO_RETURN_ON_ERROR(old);
    if (old->record.ownerKind != kind) co_return makeError(StatusCode::kTokenMismatch, "execution owner kind changed");
    co_return old;
  }
  CO_RETURN_ON_ERROR(co_await requireExecutable(txn, owner, object, child, kind));
  auto accepted = co_await loadChild(txn, owner, object, child, kind);
  CO_RETURN_ON_ERROR(accepted);
  if (workerIndex >= 12) co_return makeError(StatusCode::kInvalidArg);
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  EcFileExecutionRecord r;
  r.child = *accepted;
  r.workerIndex = workerIndex;
  r.ownerKind = kind;
  std::set<storage::ChainId> chains;
  std::set<storage::TargetId> targets;
  std::set<flat::NodeId> nodes;
  for (size_t i = 0; i < 12; ++i) {
    const auto &ep = trustedPool[i];
    CO_RETURN_ON_ERROR(life::endpointValid(ep));
    if (!chains.insert(ep.placement.chain).second || !targets.insert(ep.placement.target).second ||
        (!context->birth().allowColocated && !nodes.insert(ep.placement.node).second))
      co_return makeError(StatusCode::kInvalidArg, "RMW placement violates fixed distinct fault domains");
    auto &s = r.candidates[i];
    s.identity.object = object.incarnation;
    s.identity.stripe = r.child.stripe;
    s.identity.generation = r.child.targetGeneration;
    s.identity.shard = i;
    s.identity.allocation = Uuid::random();
    s.operation = child;
    s.endpoint = ep;
    s.writer = owner;
    for (auto prefix : {KeyPrefix::EcFileExecutionAllocation,
                        KeyPrefix::EcV2Allocation,
                        KeyPrefix::EcFragmentRef,
                        KeyPrefix::EcGcClaim,
                        KeyPrefix::EcGcAllocation,
                        KeyPrefix::EcTreeAllocationHold,
                        KeyPrefix::EcTreeSourceAllocation}) {
      auto k = allocationKey(prefix, s.identity);
      CO_RETURN_ON_ERROR(k);
      auto old = co_await txn.get(*k);
      CO_RETURN_ON_ERROR(old);
      if (*old)
        co_return makeError(StatusCode::kTokenDuplicated, "new execution allocation collides with permanent history");
    }
    auto k = allocationKey(KeyPrefix::EcFileExecutionAllocation, s.identity);
    CO_RETURN_ON_ERROR(k);
    EcFileExecutionAllocation a;
    a.object = object;
    a.child = child;
    a.allocation = s;
    CO_RETURN_ON_ERROR(co_await store(txn, *k, a));
    CO_RETURN_ON_ERROR(life::addEndpoint(r.endpoints, ep));
  }
  if (kind == EcFileExecutionOwner::Repair)
    CO_RETURN_ON_ERROR(co_await EcFileRepairCatalog::addHelperEndpoints(txn, r.child, r.endpoints));
  for (size_t n = 0; n < r.endpoints.count; ++n)
    CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::requireAssignable(txn, r.endpoints.endpoints[n]));
  auto digest = life::setDigest(r.endpoints);
  CO_RETURN_ON_ERROR(digest);
  r.endpoints.digest = *digest;
  auto plan = co_await makePlan(txn, r);
  CO_RETURN_ON_ERROR(plan);
  r.planDigest = (*plan)->digest();
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), r));
  co_return EcFileExecutionObservation{std::move(r), std::move(*plan)};
}

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::reserveIssuance(Tx &txn,
                                                                              const EcOwner &owner,
                                                                              const EcObjectRef &object,
                                                                              const Uuid &child) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  CO_RETURN_ON_ERROR(co_await admissible(txn, *o));
  if (o->record.issuanceSequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  if (o->record.child.source.kind == EcTreeSlotKind::Data) {
    auto source = co_await EcTreeSourcePinCatalog::reserveIssuance(txn, pin(o->record.child));
    CO_RETURN_ON_ERROR(source);
  }
  ++o->record.issuanceSequence;
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return o;
}

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::bindOutput(
    Tx &txn,
    const EcOwner &owner,
    const EcObjectRef &object,
    const Uuid &child,
    const storage::VerifiedEcRmwComputation &verified) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  CO_RETURN_ON_ERROR(co_await admissible(txn, *o));
  if (o->record.ownerKind == EcFileExecutionOwner::Repair)
    co_return makeError(StatusCode::kTokenMismatch,
                        "repair outputs are bound from the exact captured content, not worker computation");
  const auto &output = verified.commitment();
  if (verified.plan().digest() != o->record.planDigest || output.planDigest != o->record.planDigest ||
      !storage::ec_rmw_detail::sameEndpoint(verified.worker(), o->plan->worker()) ||
      output.logicalSha256 == storage::EcSha256{})
    co_return makeError(StatusCode::kTokenMismatch, "computed output is not this exact committed plan/worker");
  EcV2AllocationBindings bindings;
  for (size_t i = 0; i < 12; ++i) {
    const auto &s = o->record.candidates[i];
    CO_RETURN_ON_ERROR(storage::validateEcIntegrity(s.identity, output.descriptors[i]));
    if (output.descriptors[i].wholeLength != o->plan->input().shardBytes) co_return makeError(StatusCode::kInvalidArg);
    auto &a = bindings[i];
    a.object = object;
    a.fragment.identity = s.identity;
    a.fragment.operation = child;
    a.fragment.placement = s.endpoint.placement;
    a.fragment.integrity = output.descriptors[i];
    a.writer = s.writer;
    a.engineUuid = s.endpoint.engineUuid;
    a.targetIncarnation = s.endpoint.targetIncarnation;
    auto k = allocationKey(KeyPrefix::EcV2Allocation, s.identity);
    CO_RETURN_ON_ERROR(k);
    auto old = co_await load<EcV2AllocationBinding>(txn, *k);
    CO_RETURN_ON_ERROR(old);
    if (*old && !same(**old, a)) co_return makeError(StatusCode::kTokenMismatch, "output descriptor cannot change");
    if (!*old) CO_RETURN_ON_ERROR(co_await store(txn, *k, a));
  }
  if (o->record.allocations &&
      (!same(*o->record.allocations, bindings) || o->record.contentSha256 != output.logicalSha256))
    co_return makeError(StatusCode::kTokenMismatch, "computed binding is permanent");
  o->record.allocations = std::move(bindings);
  o->record.contentSha256 = output.logicalSha256;
  o->record.state = State::Bound;
  // The same transaction already performed get + admissible above. Do not
  // reread the full twelve-descriptor record merely to increment it again:
  // those repeated bytes would consume the bounded publication transaction.
  if (o->record.issuanceSequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  if (o->record.child.source.kind == EcTreeSlotKind::Data) {
    auto source = co_await EcTreeSourcePinCatalog::reserveIssuance(txn, pin(o->record.child));
    CO_RETURN_ON_ERROR(source);
  }
  ++o->record.issuanceSequence;
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return o;
}

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::bindRepairOutput(Tx &txn,
                                                                               const EcOwner &owner,
                                                                               const EcObjectRef &object,
                                                                               const Uuid &child) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  CO_RETURN_ON_ERROR(co_await admissible(txn, *o));
  if (o->record.ownerKind != EcFileExecutionOwner::Repair || o->plan->input().action != storage::EcRmwAction::Repair)
    co_return makeError(StatusCode::kTokenMismatch);
  storage::EcRmwOutputCommitment output;
  output.planDigest = o->record.planDigest;
  output.logicalSha256 = o->plan->input().sourceLogicalSha256;
  for (size_t i = 0; i < 12; ++i) output.descriptors[i] = o->plan->input().sources[i].integrity;
  EcV2AllocationBindings bindings;
  for (size_t i = 0; i < 12; ++i) {
    const auto &s = o->record.candidates[i];
    CO_RETURN_ON_ERROR(storage::validateEcIntegrity(s.identity, output.descriptors[i]));
    if (output.descriptors[i].wholeLength != o->plan->input().shardBytes) co_return makeError(StatusCode::kInvalidArg);
    auto &a = bindings[i];
    a.object = object;
    a.fragment.identity = s.identity;
    a.fragment.operation = child;
    a.fragment.placement = s.endpoint.placement;
    a.fragment.integrity = output.descriptors[i];
    a.writer = s.writer;
    a.engineUuid = s.endpoint.engineUuid;
    a.targetIncarnation = s.endpoint.targetIncarnation;
    auto k = allocationKey(KeyPrefix::EcV2Allocation, s.identity);
    CO_RETURN_ON_ERROR(k);
    auto old = co_await load<EcV2AllocationBinding>(txn, *k);
    CO_RETURN_ON_ERROR(old);
    if (*old && !same(**old, a)) co_return makeError(StatusCode::kTokenMismatch, "output descriptor cannot change");
    if (!*old) CO_RETURN_ON_ERROR(co_await store(txn, *k, a));
  }
  if (o->record.allocations &&
      (!same(*o->record.allocations, bindings) || o->record.contentSha256 != output.logicalSha256))
    co_return makeError(StatusCode::kTokenMismatch, "computed binding is permanent");
  o->record.allocations = std::move(bindings);
  o->record.contentSha256 = output.logicalSha256;
  o->record.state = State::Bound;
  // The same transaction already performed get + admissible above. Do not
  // reread the full twelve-descriptor record merely to increment it again:
  // those repeated bytes would consume the bounded publication transaction.
  if (o->record.issuanceSequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  if (o->record.child.source.kind == EcTreeSlotKind::Data) {
    auto source = co_await EcTreeSourcePinCatalog::reserveIssuance(txn, pin(o->record.child));
    CO_RETURN_ON_ERROR(source);
  }
  ++o->record.issuanceSequence;
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return o;
}

CoTryTask<EcV2DrainRecord> EcFileExecutionCatalog::startCancelClosing(Tx &txn,
                                                                      const EcOwner &owner,
                                                                      const EcObjectRef &object,
                                                                      const Uuid &child,
                                                                      const Uuid &authority,
                                                                      const Uuid &revocation) {
  if (authority.is_nil() || revocation.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  if (o->record.drain) {
    const auto &d = *o->record.drain;
    if (d.identity.clusterAuthority != authority || d.identity.revocationId != revocation ||
        o->record.state == State::Published)
      co_return makeError(StatusCode::kTokenMismatch, "cannot change closing outcome or revocation");
    // A verified candidate may lose the parent publication race after T0.
    // Keep its original evidence/denial identity; only the logical outcome is
    // fenced. Full ACK verification below is still required before release.
    CO_RETURN_ON_ERROR(co_await fence(txn, o->record));
    co_return d;
  }
  // A candidate cancellation must first lose logical publication authority in
  // the SAME transaction; it cannot leave a late child eligible for install.
  CO_RETURN_ON_ERROR(co_await fence(txn, o->record));
  o->record.drain = drainFor(o->record, authority, revocation);
  o->record.state = State::Closing;
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return *o->record.drain;
}

CoTryTask<EcV2DrainRecord> EcFileExecutionCatalog::startPublishClosing(Tx &txn,
                                                                       const EcOwner &owner,
                                                                       const EcObjectRef &object,
                                                                       const Uuid &child,
                                                                       const EcManifest &verified,
                                                                       const storage::EcSha256 &content,
                                                                       const Uuid &authority,
                                                                       const Uuid &revocation) {
  if (authority.is_nil() || revocation.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  if (!o->record.allocations || !same(manifest(o->record), verified) || content != o->record.contentSha256)
    co_return makeError(StatusCode::kTokenMismatch, "actual verified bytes differ from bound computation");
  if (o->record.drain) {
    if (o->record.drain->version != kEcV2LifecycleVersion)
      co_return makeError(StatusCode::kTokenStale, "retirement cannot authorize publication");
    const auto &d = *o->record.drain;
    if (d.identity.clusterAuthority != authority || d.identity.revocationId != revocation || !d.verifiedManifest ||
        !same(*d.verifiedManifest, verified) || d.verifiedContentSha256 != content)
      co_return makeError(StatusCode::kTokenMismatch, "publication closing is permanent");
    co_return d;
  }
  CO_RETURN_ON_ERROR(co_await admissible(txn, *o));
  o->record.drain = drainFor(o->record, authority, revocation);
  o->record.drain->verifiedManifest = verified;
  o->record.drain->verifiedContentSha256 = content;
  o->record.state = State::Closing;
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return *o->record.drain;
}

CoTryTask<EcV2DrainRecord> EcFileExecutionCatalog::recordAck(Tx &txn,
                                                             const EcOwner &owner,
                                                             const EcObjectRef &object,
                                                             const Uuid &child,
                                                             size_t index,
                                                             const storage::EcScopeControlKey &control,
                                                             const storage::EcScopeControlRequest &request,
                                                             const storage::EcScopeControlAck &ack) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  if (!o->record.drain) co_return makeError(StatusCode::kTokenStale);
  auto verified = EcVerifiedDrainAck::verify(control, *o->record.drain, index, request, ack);
  CO_RETURN_ON_ERROR(verified);
  if (ecTerminalAt(*o->record.drain, index)) co_return *o->record.drain;
  if (o->record.state != State::Closing) co_return makeError(StatusCode::kDataCorruption);
  o->record.drain->observations[index] = EcV2DrainObservation{request, ack};
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return *o->record.drain;
}

CoTryTask<EcV2DrainRecord> EcFileExecutionCatalog::recordRetirement(Tx &txn,
                                                                    const EcOwner &owner,
                                                                    const EcObjectRef &object,
                                                                    const Uuid &child,
                                                                    size_t index,
                                                                    const storage::EcScopeControlKey &control) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  if (!o->record.drain || o->record.state == State::Published)
    co_return makeError(StatusCode::kTokenStale, "execution requires an abort T0");
  auto typed = co_await loadChild(txn, owner, object, child, o->record.ownerKind);
  CO_RETURN_ON_ERROR(typed);
  if (typed->state != EcFileChildState::Fenced)
    co_return makeError(StatusCode::kTokenStale, "retirement requires the actual typed child fence");
  auto attached = co_await attachEcCompletedRetirement(txn, *o->record.drain, index, EcV2DrainUse::AbortOnly, control);
  CO_RETURN_ON_ERROR(attached);
  if (*attached) CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return *o->record.drain;
}

CoTryTask<EcFileExecutionObservation> EcFileExecutionCatalog::finishDrain(Tx &txn,
                                                                          const EcOwner &owner,
                                                                          const EcObjectRef &object,
                                                                          const Uuid &child,
                                                                          const storage::EcScopeControlKey &control) {
  auto o = co_await get(txn, owner, object, child);
  CO_RETURN_ON_ERROR(o);
  if (!o->record.drain) co_return makeError(StatusCode::kTokenStale);
  if (o->record.drain->version == kEcV2RetirementDrainVersion) {
    auto typed = co_await loadChild(txn, owner, object, child, o->record.ownerKind);
    CO_RETURN_ON_ERROR(typed);
    if (typed->state != EcFileChildState::Fenced)
      co_return makeError(StatusCode::kDataCorruption, "retirement lost its actual typed abort fence");
  }
  CO_RETURN_ON_ERROR(co_await verifyEcTerminalEvidence(txn, *o->record.drain, control,
      o->record.drain->version == kEcV2RetirementDrainVersion ? EcTerminalPurpose::FencedAbort
                                                           : EcTerminalPurpose::Publication));
  if (o->record.state == State::Published || o->record.state == State::Aborted) co_return o;
  auto childState = co_await loadChild(txn, owner, object, child, o->record.ownerKind);
  CO_RETURN_ON_ERROR(childState);
  if (childState->state != EcFileChildState::Planned && childState->state != EcFileChildState::Fenced)
    co_return makeError(StatusCode::kDataCorruption, "unpublished execution has no matching child state");
  if (o->record.drain->verifiedManifest && childState->state == EcFileChildState::Planned) {
    // Durable drain completion is not tree publication. Keep candidate holds
    // active until the root/manifest/parent transaction actually commits.
    o->record.state = State::Drained;
  } else {
    o->record.state = State::Aborted;
    o->record.drain->state = EcV2DrainState::Aborted;
    CO_RETURN_ON_ERROR(co_await releaseValidatedAllocations(txn, o->record));
  }
  CO_RETURN_ON_ERROR(co_await store(txn, key(object, child), o->record));
  co_return o;
}

EcFileExecutionCatalog::PublicationValidation::PublicationValidation(Tx &txn,
                                                                     const EcOwner &owner,
                                                                     EcFileExecutionObservation observed)
    : txn_(&txn),
      attempt_(txn.attempt()),
      owner_(owner),
      observed_(std::move(observed)) {}

EcFileExecutionCatalog::PublicationValidation::PublicationValidation(PublicationValidation &&other) noexcept
    : txn_(std::exchange(other.txn_, nullptr)),
      attempt_(other.attempt_),
      owner_(other.owner_),
      observed_(std::move(other.observed_)),
      consumed_(std::exchange(other.consumed_, true)) {}

CoTryTask<EcFileExecutionCatalog::PublicationValidation> EcFileExecutionCatalog::preparePublicationValidation(
    Tx &txn,
    const EcOwner &owner,
    const EcRmwPublicationProof &proof,
    EcFileExecutionOwner expectedKind) {
  const auto &p = proof.plan().input();
  const EcObjectRef object{InodeId(p.inode), p.object};
  auto current = co_await get(txn, owner, object, p.operationId);
  CO_RETURN_ON_ERROR(current);
  const auto &r = current->record;
  if (r.ownerKind != expectedKind || (r.state != State::Drained && r.state != State::Published) || !r.drain ||
      !r.allocations || !r.drain->verifiedManifest || r.drain->version != kEcV2LifecycleVersion ||
      current->plan->digest() != proof.plan().digest() ||
      !same(*r.allocations, proof.allocations()) || !same(*r.drain->verifiedManifest, proof.manifest()))
    co_return makeError(StatusCode::kTokenMismatch, "publication proof differs from permanent verified execution");
  auto supplied = proof.drain();
  supplied.state = r.drain->state;
  if (!same(supplied, *r.drain) || supplied.verifiedContentSha256 != r.contentSha256)
    co_return makeError(StatusCode::kTokenMismatch, "publication proof lost exact candidate drain evidence");
  co_return PublicationValidation(txn, owner, std::move(*current));
}

CoTryTask<Void> EcFileExecutionCatalog::finishValidatedPublication(Tx &txn,
                                                                   PublicationValidation &&validation,
                                                                   const EcTreeRoot &publishedRoot) {
  if (!validation.validFor(txn))
    co_return makeError(StatusCode::kTokenStale, "publication validation changed transaction or was consumed");
  validation.consumed_ = true;
  auto &r = validation.observed_.record;
  if (r.state != State::Drained || !r.drain || !r.drain->verifiedManifest ||
      r.drain->version != kEcV2LifecycleVersion)
    co_return makeError(StatusCode::kTokenStale, "candidate has no complete verified drain");
  const auto &object = r.child.intent.object;
  const auto &child = r.child.intent.child;
  auto current = co_await loadChild(txn, validation.owner_, object, child, r.ownerKind);
  CO_RETURN_ON_ERROR(current);
  if (publishedRoot.object != object || current->state != EcFileChildState::Published || !current->publishedRoot ||
      !same(*current->publishedRoot, publishedRoot))
    co_return makeError(StatusCode::kDataCorruption, "execution lacks the exact typed publication result");
  current->state = EcFileChildState::Planned;
  current->publishedRoot.reset();
  if (!same(*current, r.child))
    co_return makeError(StatusCode::kDataCorruption, "published child changed its validated execution identity");
  // A Closing last session can retire the live root before this step. The
  // permanent typed child, not the current live tree, proves this publication.
  r.state = State::Published;
  r.drain->state = EcV2DrainState::Published;
  CO_RETURN_ON_ERROR(co_await releaseValidatedAllocations(txn, r));
  co_return co_await store(txn, key(object, child), r);
}

CoTryTask<Void> EcFileExecutionCatalog::requireUnheld(kv::IReadWriteTransaction &txn,
                                                      const EcObjectRef &object,
                                                      const storage::EcFragmentIdentity &identity) {
  CO_RETURN_ON_ERROR(identity.validate());
  if (identity.object != object.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  auto k = allocationKey(KeyPrefix::EcFileExecutionAllocation, identity);
  CO_RETURN_ON_ERROR(k);
  auto a = co_await load<EcFileExecutionAllocation>(txn, *k);
  CO_RETURN_ON_ERROR(a);
  if (*a) {
    if ((**a).object != object || (**a).child.is_nil() || (**a).child != (**a).allocation.operation ||
        !same((**a).allocation.identity, identity))
      co_return makeError(StatusCode::kDataCorruption);
    if ((**a).active) co_return makeError(StatusCode::kTokenStale, "allocation retained by unpublished execution");
  }
  co_return Void{};
}
}  // namespace hf3fs::meta::server
