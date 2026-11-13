#include "EcTreeGcCatalog.h"
#include "EcTerminalEvidence.h"

#include <limits>
#include <memory>
#include <openssl/evp.h>

#include "EcFileExecutionCatalog.h"
#include "EcFileRepairCatalog.h"
#include "EcFileTreeGcGuard.h"
#include "EcV2LifecycleUtils.h"
#include "common/utils/SerDeser.h"
#include "detail/EcFileTreeKeys.h"
#include "detail/EcGcTxnScope.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
using kv::KeyPrefix;
using TreeTxn = EcFileTreeTxnBudget;
using State = EcFileExecutionState;
namespace life = ec_v2_lifecycle;
struct TreeEligibility {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(birth, EcTreeBirth{});
  SERDE_STRUCT_FIELD(allocation, EcV2AllocationBinding{});
  SERDE_STRUCT_FIELD(executionState, State::Reserved);
  SERDE_STRUCT_FIELD(executionDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(source, (std::optional<EcTreeSourceAllocationRecord>{}));
  SERDE_STRUCT_FIELD(tree, (std::optional<EcTreeAllocationHolds>{}));
  SERDE_STRUCT_FIELD(noPublishedRef, false);
};
struct TreeClaimEvidence {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(eligibility, TreeEligibility{});
  SERDE_STRUCT_FIELD(claim, EcGcClaim{});
};
struct TreeRetirement {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(result, EcRevisionRetirementRsp{});
};
struct ReclaimRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(node, Uuid::zero());
  SERDE_STRUCT_FIELD(result, AdvanceEcTreeReclaimRsp{});
};
Result<storage::EcSha256> digest(std::string_view domain, const auto &record) {
  const auto bytes = serde::serialize(record);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  storage::EcSha256 out{};
  unsigned len = 0;
  if (!c || EVP_DigestInit_ex(c.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(c.get(), domain.data(), domain.size()) != 1 ||
      EVP_DigestUpdate(c.get(), bytes.data(), bytes.size()) != 1 ||
      EVP_DigestFinal_ex(c.get(), out.data(), &len) != 1 || len != out.size())
    return makeError(StatusCode::kIOError, "tree GC SHA256 failed");
  return out;
}
std::string retirementKey(const EcRevisionRetirementReq &r) {
  std::string k(kv::toStr(KeyPrefix::EcTreeRetirement));
  k.append(r.client.uuid.asStringView());
  k.append(r.uuid.asStringView());
  return k;
}
// Only immutable repair facts enter the permanent G2 origin digest. The
// independent source pin may later move Active -> Closing -> Released; that
// change must not invalidate an already committed claim or Query recovery.
struct RepairOriginEvidence {
  SERDE_STRUCT_FIELD(execution, EcFileExecutionRecord{});
  SERDE_STRUCT_FIELD(intent, EcFileRepairIntent{});
  SERDE_STRUCT_FIELD(sources, EcV2AllocationBindings{});
};
CoTryTask<storage::EcSha256> executionOrigin(TreeTxn &t, const EcFileExecutionRecord &r) {
  if (!r.drain || !r.allocations) co_return makeError(StatusCode::kDataCorruption);
  EcV2OperationEndpoints expected;
  // Fresh output set is always all twelve candidates, in canonical shard order.
  for (size_t n = 0; n < 12; ++n) {
    if ((*r.allocations)[n].endpoint() != r.candidates[n].endpoint ||
        !same((*r.allocations)[n].fragment.identity, r.candidates[n].identity))
      co_return makeError(StatusCode::kDataCorruption, "GC candidate binding differs");
    CO_RETURN_ON_ERROR(life::addEndpoint(expected, r.candidates[n].endpoint));
  }
  if (expected.count != 12)
    co_return makeError(StatusCode::kDataCorruption, "GC requires twelve distinct output instances");
  std::optional<RepairOriginEvidence> repairEvidence;
  if (r.ownerKind == EcFileExecutionOwner::Repair) {
    const auto &c = r.child;
    auto repair = co_await EcFileRepairCatalog::byChild(t, c.owner, c.intent.object, c.intent.child);
    CO_RETURN_ON_ERROR(repair);
    auto frozen = repair->child;
    frozen.state = EcFileChildState::Planned;
    frozen.publishedRoot.reset();
    if (!same(frozen, c) ||
        (r.state == State::Published ? repair->state != EcFileRepairState::Published
                                     : r.state != State::Aborted || repair->state != EcFileRepairState::Aborted))
      co_return makeError(StatusCode::kDataCorruption, "GC repair origin is not the same terminal child");
    EcTreeSourcePinIntent pin;
    pin.object = c.intent.object;
    pin.owner = c.owner;
    pin.session = c.session;
    pin.parent = c.intent.parent;
    pin.child = c.intent.child;
    pin.pin = c.intent.sourcePin;
    pin.root = c.sourceRoot;
    pin.sequence = c.sourceSequence;
    pin.epoch = c.epoch;
    pin.lengthAtPlan = c.lengthAtPlan;
    pin.slot = c.source;
    auto source = co_await EcTreeSourcePinCatalog::query(t, pin);
    CO_RETURN_ON_ERROR(source);
    uint16_t seen = 0;
    for (auto index : repair->intent.selection.sourceOrder) {
      if (index >= 12 || (seen & (uint16_t{1} << index)) || (repair->intent.replacementMask & (uint16_t{1} << index)))
        co_return makeError(StatusCode::kDataCorruption, "GC repair source selection differs");
      seen |= uint16_t{1} << index;
      // Query checked exact original manifest/op/writer/instance. Never replace
      // these with current route entries or with the repair's new operation.
      CO_RETURN_ON_ERROR(life::addEndpoint(expected, source->allocations[index].endpoint()));
    }
    for (const auto &output : r.candidates)
      for (const auto &original : source->allocations)
        if (same(output.identity, original.fragment.identity))
          co_return makeError(StatusCode::kDataCorruption, "repair output reused a source allocation");
    if (expected.count < 12 || expected.count > 22) co_return makeError(StatusCode::kDataCorruption);
    repairEvidence.emplace();
    repairEvidence->execution = r;
    repairEvidence->intent = repair->intent;
    repairEvidence->sources = source->allocations;
  } else if (r.ownerKind != EcFileExecutionOwner::Pwrite && r.ownerKind != EcFileExecutionOwner::TruncateTail) {
    co_return makeError(StatusCode::kDataCorruption, "unknown GC execution owner kind");
  }
  auto setHash = life::setDigest(expected);
  CO_RETURN_ON_ERROR(setHash);
  expected.digest = *setHash;
  if (!same(expected, r.endpoints) || !same(expected, r.drain->identity.endpoints))
    co_return makeError(StatusCode::kDataCorruption, "GC origin ACK scope is not the exact complete operation set");
  if (repairEvidence)
    co_return digest(r.drain->version == kEcV2LifecycleVersion ? "3FS-TREE-GC-REPAIR-EXECUTION-v2"
                                                            : "3FS-TREE-GC-REPAIR-EXECUTION-v3",
                     *repairEvidence);
  // Preserve existing Pwrite/Truncate G2 certificate bytes and the twelve-only gate.
  co_return digest(r.drain->version == kEcV2LifecycleVersion ? "3FS-TREE-GC-EXECUTION-v2"
                                                          : "3FS-TREE-GC-EXECUTION-v3", r);
}
CoTryTask<std::pair<TreeEligibility, EcV2DrainRecord>> eligible(TreeTxn &t,
                                                                const EcObjectRef &o,
                                                                const storage::EcFragmentIdentity &i) {
  CO_RETURN_ON_ERROR(i.validate());
  if (i.object != o.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  auto birth = co_await EcFileTreeCatalog::getBirth(t, o);
  CO_RETURN_ON_ERROR(birth);
  CO_RETURN_ON_ERROR(co_await EcFileTreeGcGuard::requireUnheld(t, o, i));
  auto ak = allocationKey(KeyPrefix::EcV2Allocation, i);
  CO_RETURN_ON_ERROR(ak);
  auto a = co_await require<EcV2AllocationBinding>(t, *ak);
  CO_RETURN_ON_ERROR(a);
  if (a->object != o || !same(a->fragment.identity, i) || a->fragment.operation.is_nil())
    co_return makeError(StatusCode::kDataCorruption, "GC exact bound identity differs");
  CO_RETURN_ON_ERROR(storage::validateEcIntegrity(i, a->fragment.integrity));
  auto execution = co_await EcFileExecutionCatalog::get(t, a->writer, o, a->fragment.operation);
  CO_RETURN_ON_ERROR(execution);
  const auto &r = execution->record;
  if ((r.state != State::Published && r.state != State::Aborted) || !r.allocations || !r.drain ||
      !same((*r.allocations)[i.shard], *a))
    co_return makeError(StatusCode::kTokenStale, "original bound execution has not completed exact candidate T2");
  TreeEligibility e;
  e.birth = *birth;
  e.allocation = *a;
  e.executionState = r.state;
  auto ed = co_await executionOrigin(t, r);
  CO_RETURN_ON_ERROR(ed);
  e.executionDigest = *ed;
  auto sk = allocationKey(KeyPrefix::EcTreeSourceAllocation, i);
  CO_RETURN_ON_ERROR(sk);
  auto source = co_await load<EcTreeSourceAllocationRecord>(t, *sk);
  CO_RETURN_ON_ERROR(source);
  e.source = *source;
  if (e.source && (e.source->object != o || !same(e.source->identity, i) || !e.source->registered || e.source->active ||
                   e.source->registered != e.source->released))
    co_return makeError(StatusCode::kTokenStale, "source scope still protects allocation");
  auto tk = allocationKey(KeyPrefix::EcTreeAllocationHold, i);
  CO_RETURN_ON_ERROR(tk);
  auto tree = co_await load<EcTreeAllocationHolds>(t, *tk);
  CO_RETURN_ON_ERROR(tree);
  e.tree = *tree;
  if (e.tree && (e.tree->object != o || !same(e.tree->identity, i) || e.tree->holds))
    co_return makeError(StatusCode::kTokenStale, "reachable tree allocation cannot be collected");
  auto fk = allocationKey(KeyPrefix::EcFragmentRef, i);
  CO_RETURN_ON_ERROR(fk);
  auto bytes = co_await t.get(*fk);
  CO_RETURN_ON_ERROR(bytes);
  e.noPublishedRef = !*bytes;
  if (*bytes) {
    auto ref = co_await EcCatalog::getFragmentRef(t, i);
    CO_RETURN_ON_ERROR(ref);
    if (!same(ref->fragment, a->fragment) || ref->references || !ref->owner.is_nil() || !ref->gcCandidate)
      co_return makeError(StatusCode::kTokenStale, "historical manifest still references allocation");
  } else if (r.state != State::Aborted) {
    co_return makeError(StatusCode::kDataCorruption, "published allocation lost reference history");
  }
  if (r.state == State::Published) {
    if (!e.tree || !r.drain->verifiedManifest) co_return makeError(StatusCode::kDataCorruption);
    auto m = co_await EcCatalog::getManifest(t, o, r.child.stripe, r.child.targetRevision);
    CO_RETURN_ON_ERROR(m);
    auto compact = co_await require<EcTreeManifestHolds>(
        t,
        manifestKey(KeyPrefix::EcTreeManifest, o, r.child.stripe, r.child.targetRevision));
    CO_RETURN_ON_ERROR(compact);
    if (!m->retired || !m->referencesReleased || m->pins || !compact->retired || compact->treeHolds ||
        compact->object != o || !same(m->manifest, *r.drain->verifiedManifest) ||
        !same(compact->identities[i.shard], i))
      co_return makeError(StatusCode::kTokenStale, "mode4 origin manifest has not been explicitly retired");
  }
  co_return std::pair{std::move(e), *r.drain};
}
Result<EcGcClaim> project(const TreeEligibility &e, const EcV2DrainRecord &drain, const Uuid &id) {
  if (id.is_nil()) return makeError(StatusCode::kInvalidArg);
  EcGcClaim c;
  c.version = 2;
  c.enrollment.version = 2;
  c.enrollment.object = e.birth.object;
  c.enrollment.creator = e.birth.creator;
  c.enrollment.createRequest = e.birth.createRequest;
  c.claimId = id;
  c.allocation = e.allocation;
  const uint64_t source = e.source ? e.source->registered : 0;
  if (source == std::numeric_limits<uint64_t>::max()) return makeError(StatusCode::kDataCorruption);
  // One original execution plus each cumulative exact source pin. The G2
  // releaseHistory is a typed state commitment, not the flat G1 history chain.
  c.registeredScopes = c.releasedScopes = 1 + source;
  CHECK_RESULT(history, digest("3FS-TREE-GC-PROTECTIONS-v2", e));
  c.releaseHistory = history;
  CHECK_RESULT(origin,
               digest(drain.version == kEcV2LifecycleVersion ? "3FS-TREE-GC-ORIGIN-T2-v2"
                                                           : "3FS-TREE-GC-ORIGIN-T2-v3", drain));
  c.originDrainEvidence = origin;
  CHECK_RESULT(eligibility, digest("3FS-TREE-GC-CLAIM-v2", c));
  c.eligibilityDigest = eligibility;
  return c;
}
}  // namespace

CoTryTask<bool> EcTreeGcCatalog::isTree(kv::IReadWriteTransaction &t, const EcObjectRef &o) {
  // Raw typed discriminator only. Either selected catalog then verifies the
  // complete immutable birth/enrollment; no old gate is widened here.
  auto value = co_await load<EcV2ObjectMode>(t, objectKey(KeyPrefix::EcV2ObjectMode, o));
  CO_RETURN_ON_ERROR(value);
  if (!*value) co_return false;
  if ((**value).object != o || ((**value).mode != 2 && (**value).mode != 3 && (**value).mode != 4))
    co_return makeError(StatusCode::kDataCorruption);
  co_return (**value).mode == 4;
}
CoTryTask<std::optional<EcGcClaim>> EcTreeGcCatalog::getClaim(kv::IReadWriteTransaction &raw,
                                                              const EcObjectRef &o,
                                                              const storage::EcFragmentIdentity &i) {
  EcGcTxnScope scope(raw);
  auto &t = scope.transaction();
  CO_RETURN_ON_ERROR(i.validate());
  if (i.object != o.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  CO_RETURN_ON_ERROR(co_await EcFileTreeCatalog::getBirth(t, o));
  auto ck = allocationKey(KeyPrefix::EcGcClaim, i);
  CO_RETURN_ON_ERROR(ck);
  auto ek = allocationKey(KeyPrefix::EcTreeGcEvidence, i);
  CO_RETURN_ON_ERROR(ek);
  auto bytes = co_await t.get(*ck);
  CO_RETURN_ON_ERROR(bytes);
  auto proof = co_await load<TreeClaimEvidence>(t, *ek);
  CO_RETURN_ON_ERROR(proof);
  if (!*bytes) {
    if (*proof) co_return makeError(StatusCode::kDataCorruption, "typed GC evidence lost its irreversible claim");
    co_return std::nullopt;
  }
  EcGcClaim claim;
  if (!serde::deserialize(claim, **bytes) || claim.version != 2 || !*proof || !same(claim, (**proof).claim))
    co_return makeError(StatusCode::kDataCorruption, "invalid G2 permanent claim/evidence pair");
  auto actual = co_await eligible(t, o, i);
  CO_RETURN_ON_ERROR(actual);
  if (!same(actual->first, (**proof).eligibility))
    co_return makeError(StatusCode::kDataCorruption, "G2 eligibility changed");
  auto expected = project(actual->first, actual->second, claim.claimId);
  CO_RETURN_ON_ERROR(expected);
  if (!same(*expected, claim)) co_return makeError(StatusCode::kDataCorruption, "G2 claim projection changed");
  co_return std::optional<EcGcClaim>{std::move(claim)};
}
CoTryTask<EcGcClaim> EcTreeGcCatalog::claim(kv::IReadWriteTransaction &raw,
                                            const EcObjectRef &o,
                                            const storage::EcFragmentIdentity &i,
                                            const Uuid &id,
                                            const storage::EcScopeControlKey &key) {
  if (id.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  EcGcTxnScope scope(raw);
  auto &t = scope.transaction();
  auto old = co_await getClaim(t, o, i);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    if ((**old).claimId != id)
      co_return makeError(StatusCode::kTokenMismatch, "allocation already belongs to another claim");
    co_return **old;
  }
  auto actual = co_await eligible(t, o, i);
  CO_RETURN_ON_ERROR(actual);
  // executionOrigin proved the exact typed set; verify every actual endpoint,
  // including selected helpers beyond the new output instances.
  CO_RETURN_ON_ERROR(co_await verifyEcTerminalEvidence(t, actual->second, key,
      actual->second.state == EcV2DrainState::Published ? EcTerminalPurpose::Publication
                                                       : EcTerminalPurpose::FencedAbort));
  auto next = project(actual->first, actual->second, id);
  CO_RETURN_ON_ERROR(next);
  TreeClaimEvidence proof;
  proof.eligibility = actual->first;
  proof.claim = *next;
  auto ck = allocationKey(KeyPrefix::EcGcClaim, i);
  CO_RETURN_ON_ERROR(ck);
  auto ek = allocationKey(KeyPrefix::EcTreeGcEvidence, i);
  CO_RETURN_ON_ERROR(ek);
  CO_RETURN_ON_ERROR(co_await store(t, *ek, proof));
  CO_RETURN_ON_ERROR(co_await store(t, *ck, *next));
  co_return next;
}

CoTryTask<EcRevisionRetirementRsp> EcTreeGcCatalog::retire(kv::IReadWriteTransaction &raw,
                                                           const EcRevisionRetirementReq &req,
                                                           bool query) {
  CO_RETURN_ON_ERROR(req.valid());
  EcGcTxnScope scope(raw);
  auto &t = scope.transaction();
  auto birth = co_await EcFileTreeCatalog::getBirth(t, req.object);
  CO_RETURN_ON_ERROR(birth);
  auto flat = co_await t.get(Serializer::serRawArgs(KeyPrefix::EcRevisionRetirement, req.uuid, req.client.uuid));
  CO_RETURN_ON_ERROR(flat);
  if (*flat) co_return makeError(StatusCode::kTokenMismatch, "retirement UUID already belongs to a flat request");
  auto previous = co_await load<TreeRetirement>(t, retirementKey(req));
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    const auto &r = (**previous).result;
    if ((**previous).owner.uid != req.user.uid || (**previous).owner.client != req.client.uuid ||
        r.object != req.object || r.stripe != req.stripe || r.revision != req.revision || r.requestId != req.uuid)
      co_return makeError(StatusCode::kTokenMismatch, "tree retirement request identity changed");
  }
  auto record = co_await EcCatalog::getManifest(t, req.object, req.stripe, req.revision);
  CO_RETURN_ON_ERROR(record);
  const auto &m = record->manifest;
  auto ck = manifestKey(KeyPrefix::EcTreeManifest, req.object, req.stripe, req.revision);
  auto compact = co_await require<EcTreeManifestHolds>(t, ck);
  CO_RETURN_ON_ERROR(compact);
  if (compact->object != req.object || compact->slot.stripe != req.stripe || compact->slot.revision != req.revision ||
      compact->treeHolds || record->pins)
    co_return makeError(StatusCode::kTokenStale, "tree revision remains reachable or pinned");
  EcV2AllocationBindings bindings;
  for (size_t n = 0; n < 12; ++n) {
    auto ak = allocationKey(KeyPrefix::EcV2Allocation, m.fragments[n].identity);
    CO_RETURN_ON_ERROR(ak);
    auto a = co_await require<EcV2AllocationBinding>(t, *ak);
    CO_RETURN_ON_ERROR(a);
    if (a->object != req.object || !same(a->fragment, m.fragments[n])) co_return makeError(StatusCode::kDataCorruption);
    bindings[n] = *a;
  }
  auto committed = EcFileTreeCatalog::commitment(req.object, m, bindings, compact->slot.contentSha256);
  CO_RETURN_ON_ERROR(committed);
  if (committed->manifestDigest != compact->manifestDigest || committed->bindingsDigest != compact->bindingsDigest ||
      !same(committed->slot, compact->slot) || !same(committed->identities, compact->identities))
    co_return makeError(StatusCode::kDataCorruption, "tree retirement lost immutable commitment");
  if (record->referencesReleased != record->retired || record->retired != compact->retired)
    co_return makeError(StatusCode::kDataCorruption, "tree retirement markers disagree");
  if (*previous) {
    if (!record->referencesReleased || !(**previous).result.referencesReleased ||
        (**previous).result.generation != m.generation)
      co_return makeError(StatusCode::kDataCorruption);
    co_return (**previous).result;
  }
  if (query) co_return makeError(StatusCode::kKVStoreNotFound, "tree retirement has no completion for this request");
  if (!record->referencesReleased) {
    for (const auto &f : m.fragments) {
      auto ref = co_await EcCatalog::getFragmentRef(t, f.identity);
      CO_RETURN_ON_ERROR(ref);
      if (!same(ref->fragment, f) || !ref->references || ref->gcCandidate || !ref->owner.is_nil())
        co_return makeError(StatusCode::kDataCorruption, "tree retirement reference underflow");
      --ref->references;
      ref->gcCandidate = ref->references == 0;
      auto rk = allocationKey(KeyPrefix::EcFragmentRef, f.identity);
      CO_RETURN_ON_ERROR(rk);
      CO_RETURN_ON_ERROR(co_await store(t, *rk, *ref));
    }
    record->retired = record->referencesReleased = true;
    compact->retired = true;
    CO_RETURN_ON_ERROR(
        co_await store(t, manifestKey(KeyPrefix::EcManifest, req.object, req.stripe, req.revision), *record));
    CO_RETURN_ON_ERROR(co_await store(t, ck, *compact));
  }
  TreeRetirement saved;
  saved.owner = {req.user.uid, req.client.uuid};
  auto &r = saved.result;
  r.object = req.object;
  r.stripe = req.stripe;
  r.revision = req.revision;
  r.generation = m.generation;
  r.clientNamespace = req.client.uuid;
  r.requestId = req.uuid;
  r.referencesReleased = true;
  CO_RETURN_ON_ERROR(co_await store(t, retirementKey(req), saved));
  co_return r;
}
CoTryTask<EcTreeReclaimProgress> EcTreeGcCatalog::reclaim(kv::IReadWriteTransaction &raw,
                                                          const EcObjectRef &o,
                                                          const Uuid &id) {
  EcGcTxnScope scope(raw);
  auto &t = scope.transaction();
  CO_RETURN_ON_ERROR(co_await EcFileTreeCatalog::getBirth(t, o));
  EcTreeReclaimProgress out;
  out.object = o;
  out.node = id;
  if (!id.is_nil()) {
    // Capture a leaf's bounded revision hints before reclaim removes ECNT.
    // Missing is accepted only if reclaim verifies a terminal ECNR below.
    auto body = co_await load<EcTreeNode>(t, idKey(KeyPrefix::EcTreeNode, o, id));
    CO_RETURN_ON_ERROR(body);
    auto object = co_await EcCatalog::getObject(t, o);
    CO_RETURN_ON_ERROR(object);
    if (object->deleting) {
      auto result = co_await EcFileLifecycleCatalog::reclaimRetiredNode(t, o, id);
      CO_RETURN_ON_ERROR(result);
      out.refs = *result;
    } else {
      auto context = co_await EcFileTreeCatalog::open(t, o);
      CO_RETURN_ON_ERROR(context);
      auto result = co_await EcFileTreeCatalog::reclaimNode(*context, id);
      CO_RETURN_ON_ERROR(result);
      out.refs = *result;
    }
    out.reclaimed = true;
    if (*body && !(**body).level && (**body).slots) out.revisions = *(**body).slots;
    for (size_t n = 0; n < 16; ++n) {
      const auto &slot = out.revisions[n];
      if (slot.kind != EcTreeSlotKind::Data) continue;
      auto m = co_await EcCatalog::getManifest(t, o, slot.stripe, slot.revision);
      CO_RETURN_ON_ERROR(m);
      if (m->manifest.object != o || m->manifest.stripe != slot.stripe || m->manifest.revision != slot.revision ||
          m->manifest.generation != slot.generation || m->manifest.logicalLength != slot.logicalLength)
        co_return makeError(StatusCode::kDataCorruption, "reclaimed leaf historical manifest differs");
      for (size_t shard = 0; shard < 12; ++shard) {
        const auto &identity = m->manifest.fragments[shard].identity;
        CO_RETURN_ON_ERROR(identity.validate());
        if (identity.object != o.incarnation || identity.stripe != slot.stripe ||
            identity.generation != slot.generation || identity.shard != shard)
          co_return makeError(StatusCode::kDataCorruption, "reclaimed leaf fragment identity differs");
        out.identities[n].fragments[shard] = identity;
      }
    }
  }
  const auto prefix = objectKey(KeyPrefix::EcTreeReclaim, o);
  auto work = co_await t.getRange({prefix, true}, {kv::TransactionHelper::prefixListEndKey(prefix), false}, 1);
  CO_RETURN_ON_ERROR(work);
  if (!work->kvs.empty()) {
    EcTreeReclaimWork next;
    if (!serde::deserialize(next, work->kvs.front().value) || next.version != 1 || next.object != o ||
        next.node.is_nil() || work->kvs.front().key != idKey(KeyPrefix::EcTreeReclaim, o, next.node))
      co_return makeError(StatusCode::kDataCorruption, "invalid bounded tree reclaim queue");
    out.next = next.node;
  }
  co_return out;
}
CoTryTask<EcTreeReclaimObservation> EcTreeGcCatalog::reclaimRequest(kv::IReadWriteTransaction &raw,
                                                                    const AdvanceEcTreeReclaimReq &req,
                                                                    bool readonly) {
  CO_RETURN_ON_ERROR(req.valid());
  EcGcTxnScope scope(raw);
  auto &t = scope.transaction();
  std::string key(kv::toStr(KeyPrefix::EcTreeReclaimRequest));
  key.append(req.client.uuid.asStringView());
  key.append(req.uuid.asStringView());
  auto old = co_await load<ReclaimRecord>(t, key);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    const auto &r = **old;
    if (r.owner.uid != req.user.uid || r.owner.client != req.client.uuid || r.object != req.object ||
        r.node != req.node)
      co_return makeError(StatusCode::kTokenMismatch, "reclaim request changed exact identity");
    if (r.result.progress.object != r.object || r.result.progress.node != r.node || !r.result.progress.reclaimed ||
        r.result.requestId != req.uuid || r.result.clientNamespace != req.client.uuid)
      co_return makeError(StatusCode::kDataCorruption);
    co_return EcTreeReclaimObservation{r.result, false};
  }
  // Readonly permits recovery of an existing permanent result, not a new
  // mutation. A nil-node inspection never records a successful reclamation.
  const bool mutation = !req.node.is_nil();
  if (mutation && readonly) co_return makeError(StatusCode::kReadOnlyMode);
  auto progressed = co_await reclaim(t, req.object, req.node);
  CO_RETURN_ON_ERROR(progressed);
  AdvanceEcTreeReclaimRsp rsp;
  rsp.progress = *progressed;
  rsp.requestId = req.uuid;
  rsp.clientNamespace = req.client.uuid;
  if (!mutation) co_return EcTreeReclaimObservation{std::move(rsp), false};
  ReclaimRecord record;
  record.owner = {req.user.uid, req.client.uuid};
  record.object = req.object;
  record.node = req.node;
  record.result = rsp;
  CO_RETURN_ON_ERROR(co_await store(t, key, record));
  co_return EcTreeReclaimObservation{std::move(rsp), true};
}
}  // namespace hf3fs::meta::server
