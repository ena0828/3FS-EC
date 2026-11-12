#include "EcFileTreeCatalog.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <set>

#include "EcCatalog.h"
#include "EcFileTreeGcGuard.h"
#include "detail/EcFileTreeKeys.h"
#include "fbs/meta/EcV2Gc.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
Result<Void> validBirth(const EcTreeBirth &b) {
  if (b.version != kEcFileTreeVersion || b.object.incarnation.is_nil() || b.object.inode.isTreeRoot() ||
      b.object.inode > InodeId::normalMax() || b.creator.client.is_nil() || b.createRequest.is_nil())
    return makeError(StatusCode::kInvalidArg, "invalid EC tree birth");
  RETURN_ON_ERROR(stripeStart(0, b.shardBytes));
  return Void{};
}
Result<Void> validSlot(const EcTreeSlot &slot, const EcTreeBirth &birth, uint64_t stripe) {
  if (slot.kind == EcTreeSlotKind::Zero) {
    if (!same(slot, EcTreeSlot{})) return makeError(StatusCode::kDataCorruption, "nonzero Zero extent");
    return Void{};
  }
  if (slot.kind != EcTreeSlotKind::Data || slot.stripe != stripe || !slot.revision || !slot.generation ||
      !slot.logicalLength || slot.logicalLength > uint64_t(birth.shardBytes) * 10 ||
      slot.contentSha256 == storage::EcSha256{})
    return makeError(StatusCode::kDataCorruption, "invalid EC tree Data extent");
  CHECK_RESULT(start, stripeStart(stripe, birth.shardBytes));
  RETURN_ON_ERROR(rangeEnd(start, slot.logicalLength));
  return Void{};
}
Result<Void> validNode(const EcTreeNode &n, const EcTreeBirth &birth) {
  if (n.object != birth.object || n.id.is_nil() || n.operation.is_nil() || n.level >= 16 ||
      prefix(n.prefix, n.level) != n.prefix)
    return makeError(StatusCode::kDataCorruption, "EC tree node key/path mismatch");
  if (!n.level) {
    if (!n.slots) return makeError(StatusCode::kDataCorruption, "EC leaf has no fixed slots");
    for (size_t i = 0; i < 16; ++i) {
      if (!n.children[i].is_nil()) return makeError(StatusCode::kDataCorruption, "EC leaf has a child");
      RETURN_ON_ERROR(validSlot((*n.slots)[i], birth, n.prefix | i));
    }
  } else {
    if (n.slots) return makeError(StatusCode::kDataCorruption, "EC branch contains leaf slots");
    std::set<Uuid> ids;
    for (const auto &id : n.children) {
      if (!id.is_nil() && (id == n.id || !ids.insert(id).second))
        return makeError(StatusCode::kDataCorruption, "EC branch has duplicate/self child");
    }
  }
  return Void{};
}
Result<Void> validRefs(const EcTreeNodeRefs &refs, const EcObjectRef &object, const Uuid &node) {
  if (refs.object != object || refs.node != node || node.is_nil() || refs.level >= 16 ||
      prefix(refs.prefix, refs.level) != refs.prefix ||
      (refs.state != EcTreeRefState::Live && refs.state != EcTreeRefState::Reclaimable &&
       refs.state != EcTreeRefState::Reclaimed) ||
      ((refs.state == EcTreeRefState::Live) != (refs.references != 0)))
    return makeError(StatusCode::kDataCorruption, "invalid EC node reference state");
  return Void{};
}
CoTryTask<std::pair<EcTreeNode, EcTreeNodeRefs>> node(Tx &txn, const EcTreeBirth &birth, const Uuid &id) {
  auto n = co_await require<EcTreeNode>(txn, idKey(KeyPrefix::EcTreeNode, birth.object, id));
  CO_RETURN_ON_ERROR(n);
  CO_RETURN_ON_ERROR(validNode(*n, birth));
  if (n->id != id) co_return makeError(StatusCode::kDataCorruption);
  auto refs = co_await require<EcTreeNodeRefs>(txn, idKey(KeyPrefix::EcTreeNodeRefs, birth.object, id));
  CO_RETURN_ON_ERROR(refs);
  CO_RETURN_ON_ERROR(validRefs(*refs, birth.object, id));
  if (refs->level != n->level || refs->prefix != n->prefix)
    co_return makeError(StatusCode::kDataCorruption, "EC node body/ref path differs");
  co_return std::pair{std::move(*n), std::move(*refs)};
}
CoTryTask<Void> childRef(Tx &txn,
                         const EcTreeBirth &birth,
                         const Uuid &id,
                         uint8_t level,
                         uint64_t expectedPrefix,
                         bool increment) {
  // The immutable path is copied into permanent refs in the creation batch.
  // A live child always retains its body; only terminal reclaim removes it.
  // Sibling COW therefore need not read a complete leaf to add an edge.
  auto loaded = co_await require<EcTreeNodeRefs>(txn, idKey(KeyPrefix::EcTreeNodeRefs, birth.object, id));
  CO_RETURN_ON_ERROR(loaded);
  CO_RETURN_ON_ERROR(validRefs(*loaded, birth.object, id));
  auto &refs = *loaded;
  if (refs.level != level || refs.prefix != expectedPrefix || refs.state != EcTreeRefState::Live)
    co_return makeError(StatusCode::kDataCorruption, "reclaimed/mismatched EC child cannot gain or lose a live edge");
  if (increment) {
    if (refs.references == std::numeric_limits<uint64_t>::max()) co_return makeError(StatusCode::kDataCorruption);
    ++refs.references;
  } else {
    --refs.references;
    if (!refs.references) {
      refs.state = EcTreeRefState::Reclaimable;
      EcTreeReclaimWork work;
      work.object = birth.object;
      work.node = id;
      CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeReclaim, birth.object, id), work));
    }
  }
  co_return co_await store(txn, idKey(KeyPrefix::EcTreeNodeRefs, birth.object, id), refs);
}
Result<Void> validRoot(const EcTreeRoot &root,
                       const EcTreeBirth &birth,
                       const EcObjectRecord &object,
                       bool retiredMaintenance = false) {
  if (root.object != birth.object || root.birth != birth.createRequest || !root.sequence || !root.epoch ||
      root.epoch != object.epoch || root.visibleLength != object.length || (object.deleting != retiredMaintenance) ||
      object.object != birth.object || object.shardBytes != birth.shardBytes ||
      object.allowColocated != birth.allowColocated || !same(object.creator, birth.creator) ||
      object.createRequest != birth.createRequest)
    return makeError(StatusCode::kDataCorruption, "EC tree root disagrees with immutable birth/object");
  return Void{};
}
Result<Void> validEdit(const EcTreeEdit &edit, const EcTreeBirth &birth) {
  if (edit.version != kEcFileTreeVersion || edit.object != birth.object || edit.operation.is_nil() ||
      !edit.expectedSequence || edit.expectedSequence == std::numeric_limits<uint64_t>::max() || !edit.expectedEpoch)
    return makeError(StatusCode::kInvalidArg, "invalid EC tree edit identity");
  RETURN_ON_ERROR(stripeStart(edit.stripe, birth.shardBytes));
  RETURN_ON_ERROR(validSlot(edit.replacement, birth, edit.stripe));
  if (edit.replacement.kind == EcTreeSlotKind::Data) {
    CHECK_RESULT(start, stripeStart(edit.stripe, birth.shardBytes));
    CHECK_RESULT(end, rangeEnd(start, edit.replacement.logicalLength));
    if (end > edit.visibleLength) return makeError(StatusCode::kInvalidArg, "Data extent exceeds root EOF");
  }
  std::set<Uuid> ids;
  for (const auto &id : edit.nodeIds)
    if (id.is_nil() || !ids.insert(id).second)
      return makeError(StatusCode::kInvalidArg, "fixed node IDs must be unique");
  return Void{};
}
}  // namespace

CoTryTask<EcTreeRoot> EcFileTreeCatalog::createBirth(Tx &txn, const EcTreeBirth &birth) {
  CO_RETURN_ON_ERROR(validBirth(birth));
  std::array<bool, 4> present{};
  const std::array<KeyPrefix, 4> keys{KeyPrefix::EcObject,
                                      KeyPrefix::EcV2ObjectMode,
                                      KeyPrefix::EcTreeBirth,
                                      KeyPrefix::EcTreeRoot};
  for (size_t i = 0; i < keys.size(); ++i) {
    auto value = co_await txn.get(objectKey(keys[i], birth.object));
    CO_RETURN_ON_ERROR(value);
    present[i] = value->has_value();
  }
  if (std::any_of(present.begin(), present.end(), [](bool v) { return v; })) {
    if (!std::all_of(present.begin(), present.end(), [](bool v) { return v; }))
      co_return makeError(StatusCode::kTokenMismatch, "existing objects/partial births cannot acquire tree mode");
    auto context = co_await open(txn, birth.object);
    CO_RETURN_ON_ERROR(context);
    if (!same(context->birth(), birth)) co_return makeError(StatusCode::kTokenMismatch, "tree birth intent changed");
    co_return co_await getRoot(*context);
  }
  auto mode3 = co_await txn.get(objectKey(KeyPrefix::EcGcEnrollment, birth.object));
  CO_RETURN_ON_ERROR(mode3);
  if (*mode3) co_return makeError(StatusCode::kDataCorruption, "mode-3 enrollment cannot be upgraded to a tree birth");
  // Refuse orphaned tree history rather than treating a lost root as a new object.
  for (auto keyPrefix : {KeyPrefix::EcTreeNode,
                         KeyPrefix::EcTreeNodeRefs,
                         KeyPrefix::EcTreeReclaim,
                         KeyPrefix::EcTreeEdit,
                         KeyPrefix::EcTreeManifest}) {
    const auto first = objectKey(keyPrefix, birth.object);
    const auto last = kv::TransactionHelper::prefixListEndKey(first);
    auto found = co_await txn.getRange({first, true}, {last, false}, 1);
    CO_RETURN_ON_ERROR(found);
    if (!found->kvs.empty() || found->hasMore)
      co_return makeError(StatusCode::kDataCorruption, "orphan EC tree history");
  }
  EcObjectRecord object;
  object.object = birth.object;
  object.shardBytes = birth.shardBytes;
  object.allowColocated = birth.allowColocated;
  object.creator = birth.creator;
  object.createRequest = birth.createRequest;
  EcV2ObjectMode mode;
  mode.mode = kEcFileTreeMode;
  mode.object = birth.object;
  mode.creator = birth.creator;
  mode.createRequest = birth.createRequest;
  EcTreeRoot root;
  root.object = birth.object;
  root.birth = birth.createRequest;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcObject, birth.object), object));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcV2ObjectMode, birth.object), mode));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcTreeBirth, birth.object), birth));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcTreeRoot, birth.object), root));
  co_return root;
}
CoTryTask<EcTreeBirth> EcFileTreeCatalog::getBirth(Tx &txn, const EcObjectRef &object) {
  auto birth = co_await require<EcTreeBirth>(txn, objectKey(KeyPrefix::EcTreeBirth, object));
  CO_RETURN_ON_ERROR(birth);
  CO_RETURN_ON_ERROR(validBirth(*birth));
  if (birth->object != object) co_return makeError(StatusCode::kTokenMismatch);
  auto mode = co_await require<EcV2ObjectMode>(txn, objectKey(KeyPrefix::EcV2ObjectMode, object));
  CO_RETURN_ON_ERROR(mode);
  if (mode->mode != kEcFileTreeMode || mode->object != object || !same(mode->creator, birth->creator) ||
      mode->createRequest != birth->createRequest)
    co_return makeError(StatusCode::kDataCorruption);
  auto old = co_await txn.get(objectKey(KeyPrefix::EcGcEnrollment, object));
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return makeError(StatusCode::kDataCorruption, "tree birth cannot have flat GC enrollment");
  auto record = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(record);
  if (record->shardBytes != birth->shardBytes || record->allowColocated != birth->allowColocated ||
      record->createRequest != birth->createRequest || !same(record->creator, birth->creator))
    co_return makeError(StatusCode::kDataCorruption, "permanent object and birth differ");
  co_return birth;
}
CoTryTask<EcTreeContext> EcFileTreeCatalog::open(Tx &txn, const EcObjectRef &object) {
  auto birth = co_await getBirth(txn, object);
  CO_RETURN_ON_ERROR(birth);
  EcTreeContext context(txn, std::move(*birth));
  auto checked = co_await validateContext(context);
  CO_RETURN_ON_ERROR(checked);
  co_return context;
}
CoTryTask<EcTreeRoot> EcFileTreeCatalog::validateContext(EcTreeContext &context) {
  auto &txn = *context.txn_;
  const auto &birth = context.birth_;
  if (context.attempt_ != txn.attempt() || txn.poisoned())
    co_return makeError(StatusCode::kTokenStale, "stale tree transaction context");
  auto currentBirth = co_await require<EcTreeBirth>(txn, objectKey(KeyPrefix::EcTreeBirth, birth.object));
  CO_RETURN_ON_ERROR(currentBirth);
  if (!same(*currentBirth, birth)) co_return makeError(StatusCode::kDataCorruption);
  auto mode = co_await require<EcV2ObjectMode>(txn, objectKey(KeyPrefix::EcV2ObjectMode, birth.object));
  CO_RETURN_ON_ERROR(mode);
  if (mode->mode != kEcFileTreeMode || mode->object != birth.object || !same(mode->creator, birth.creator) ||
      mode->createRequest != birth.createRequest)
    co_return makeError(StatusCode::kDataCorruption, "tree mode lacks exact creation-time evidence");
  auto oldEnrollment = co_await txn.get(objectKey(KeyPrefix::EcGcEnrollment, birth.object));
  CO_RETURN_ON_ERROR(oldEnrollment);
  if (*oldEnrollment) co_return makeError(StatusCode::kDataCorruption, "tree birth cannot reuse a flat GC enrollment");
  auto object = co_await EcCatalog::getObject(txn, birth.object);
  CO_RETURN_ON_ERROR(object);
  auto root = co_await require<EcTreeRoot>(txn, objectKey(KeyPrefix::EcTreeRoot, birth.object));
  CO_RETURN_ON_ERROR(root);
  CO_RETURN_ON_ERROR(validRoot(*root, birth, *object, context.retiredMaintenance_));
  if (!root->root.is_nil()) {
    auto top = co_await node(txn, birth, root->root);
    CO_RETURN_ON_ERROR(top);
    if (top->first.level != 15 || top->first.prefix || top->second.state != EcTreeRefState::Live)
      co_return makeError(StatusCode::kDataCorruption, "root points to a non-live top-level node");
  }
  co_return root;
}
CoTryTask<EcTreeRoot> EcFileTreeCatalog::getRoot(EcTreeContext &context) {
  co_return co_await validateContext(context);
}
CoTryTask<EcTreeSlot> EcFileTreeCatalog::lookup(EcTreeContext &context, uint64_t stripe) {
  CO_RETURN_ON_ERROR(stripeStart(stripe, context.birth_.shardBytes));
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  auto id = root->root;
  for (int level = 15; level >= 0; --level) {
    if (id.is_nil()) co_return EcTreeSlot{};
    auto current = co_await node(*context.txn_, context.birth_, id);
    CO_RETURN_ON_ERROR(current);
    const auto &body = current->first;
    if (body.level != level || body.prefix != prefix(stripe, level) || current->second.state != EcTreeRefState::Live)
      co_return makeError(StatusCode::kDataCorruption, "EC tree lookup path differs");
    if (!level) {
      const auto slot = (*body.slots)[index(stripe, 0)];
      if (slot.kind == EcTreeSlotKind::Data) {
        auto checked = co_await installed(context, slot, true);
        CO_RETURN_ON_ERROR(checked);
      }
      co_return slot;
    }
    id = body.children[index(stripe, level)];
  }
  co_return makeError(StatusCode::kDataCorruption);
}
CoTryTask<std::optional<EcTreeEditResult>> EcFileTreeCatalog::queryEdit(EcTreeContext &context, const Uuid &operation) {
  if (operation.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  auto result =
      co_await load<EcTreeEditResult>(*context.txn_, idKey(KeyPrefix::EcTreeEdit, context.birth_.object, operation));
  CO_RETURN_ON_ERROR(result);
  if (*result) {
    const auto &r = **result;
    CO_RETURN_ON_ERROR(validEdit(r.intent, context.birth_));
    if (r.intent.operation != operation || r.root.object != context.birth_.object ||
        r.root.birth != context.birth_.createRequest || r.root.root != r.intent.nodeIds[15] ||
        r.root.sequence != r.intent.expectedSequence + 1 || r.root.epoch != r.intent.expectedEpoch ||
        r.root.visibleLength != r.intent.visibleLength)
      co_return makeError(StatusCode::kDataCorruption, "EC tree permanent edit result differs");
  }
  co_return std::move(*result);
}
CoTryTask<EcTreeEditResult> EcFileTreeCatalog::replaceZero(EcTreeContext &context, const EcTreeEdit &edit) {
  if (!same(edit.replacement, EcTreeSlot{}))
    co_return makeError(StatusCode::kNotImplemented, "W0 has no production Data installer");
  co_return co_await replace(context, edit);
}
CoTryTask<EcTreeEditResult> EcFileTreeCatalog::replace(EcTreeContext &context, const EcTreeEdit &edit) {
  CO_RETURN_ON_ERROR(validEdit(edit, context.birth_));
  auto prior = co_await queryEdit(context, edit.operation);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if (!same((**prior).intent, edit))
      co_return makeError(StatusCode::kTokenMismatch, "fixed EC tree edit cannot change");
    co_return **prior;
  }
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  if (root->root != edit.expectedRoot || root->sequence != edit.expectedSequence || root->epoch != edit.expectedEpoch)
    co_return makeError(StatusCode::kTokenStale, "EC tree root CAS failed");
  if (edit.visibleLength < root->visibleLength)
    co_return makeError(StatusCode::kNotImplemented, "W0 does not implement truncate");
  auto &txn = *context.txn_;
  const auto &birth = context.birth_;
  std::array<EcTreeNode, 16> next;
  auto id = root->root;
  for (int level = 15; level >= 0; --level) {
    EcTreeNode body;
    if (!id.is_nil()) {
      auto previous = co_await node(txn, birth, id);
      CO_RETURN_ON_ERROR(previous);
      if (previous->first.level != level || previous->first.prefix != prefix(edit.stripe, level) ||
          previous->second.state != EcTreeRefState::Live)
        co_return makeError(StatusCode::kDataCorruption);
      body = std::move(previous->first);
    } else {
      body.object = birth.object;
      body.level = level;
      body.prefix = prefix(edit.stripe, level);
      if (!level) body.slots.emplace();
    }
    id = level ? body.children[index(edit.stripe, level)] : Uuid::zero();
    body.id = edit.nodeIds[level];
    body.operation = edit.operation;
    if (level)
      body.children[index(edit.stripe, level)] = edit.nodeIds[level - 1];
    else
      (*body.slots)[index(edit.stripe, 0)] = edit.replacement;
    CO_RETURN_ON_ERROR(validNode(body, birth));
    next[level] = std::move(body);
  }
  // Any persisted node ID, including a terminal tombstone, is irrevocably used.
  for (const auto &newId : edit.nodeIds)
    for (auto kind : {KeyPrefix::EcTreeNode, KeyPrefix::EcTreeNodeRefs, KeyPrefix::EcTreeReclaim}) {
      auto old = co_await txn.get(idKey(kind, birth.object, newId));
      CO_RETURN_ON_ERROR(old);
      if (*old) co_return makeError(StatusCode::kTokenDuplicated, "EC node ID cannot be reborn");
    }
  for (uint8_t level = 0; level < 16; ++level) {
    const auto &body = next[level];
    if (!level) {
      for (const auto &slot : *body.slots)
        if (slot.kind == EcTreeSlotKind::Data) CO_RETURN_ON_ERROR(co_await manifestHold(context, slot, true));
    } else {
      for (size_t i = 0; i < 16; ++i) {
        const auto &child = body.children[i];
        if (child.is_nil() || i == index(edit.stripe, level)) continue;
        CO_RETURN_ON_ERROR(
            co_await childRef(txn, birth, child, level - 1, body.prefix | (uint64_t(i) << (4 * level)), true));
      }
    }
    EcTreeNodeRefs refs;
    refs.object = birth.object;
    refs.node = body.id;
    refs.references = 1;
    refs.level = body.level;
    refs.prefix = body.prefix;
    // The new path has exactly one incoming edge per node, including the root.
    CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeNode, birth.object, body.id), body));
    CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeNodeRefs, birth.object, body.id), refs));
  }
  if (!root->root.is_nil()) CO_RETURN_ON_ERROR(co_await childRef(txn, birth, root->root, 15, 0, false));
  root->root = edit.nodeIds[15];
  root->visibleLength = edit.visibleLength;
  ++root->sequence;
  auto object = co_await EcCatalog::getObject(txn, birth.object);
  CO_RETURN_ON_ERROR(object);
  object->length = root->visibleLength;
  EcTreeEditResult result;
  result.intent = edit;
  result.root = *root;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcObject, birth.object), *object));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcTreeRoot, birth.object), *root));
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeEdit, birth.object, edit.operation), result));
  co_return result;
}
namespace {
// Versioned Meta-internal commitment to the complete immutable binary record.
// It is not a network MAC and never authorizes publication or physical GC.
Result<storage::EcSha256> recordDigest(std::string_view domain, const auto &record) {
  const auto bytes = serde::serialize(record);
  using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
  Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  storage::EcSha256 result{};
  unsigned length = 0;
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), domain.data(), domain.size()) != 1 ||
      EVP_DigestUpdate(context.get(), bytes.data(), bytes.size()) != 1 ||
      EVP_DigestFinal_ex(context.get(), result.data(), &length) != 1 || length != result.size())
    return makeError(StatusCode::kIOError, "cannot compute EC tree metadata commitment");
  return result;
}
}  // namespace
Result<EcTreeManifestHolds> EcFileTreeCatalog::commitment(const EcObjectRef &object,
                                                          const EcManifest &manifest,
                                                          const EcV2AllocationBindings &bindings,
                                                          const storage::EcSha256 &content) {
  EcTreeManifestHolds out;
  out.object = object;
  out.slot.kind = EcTreeSlotKind::Data;
  out.slot.stripe = manifest.stripe;
  out.slot.revision = manifest.revision;
  out.slot.generation = manifest.generation;
  out.slot.logicalLength = manifest.logicalLength;
  out.slot.contentSha256 = content;
  for (size_t i = 0; i < 12; ++i) out.identities[i] = manifest.fragments[i].identity;
  CHECK_RESULT(manifestHash, recordDigest("3FS-W0-MANIFEST-v1", manifest));
  out.manifestDigest = manifestHash;
  CHECK_RESULT(bindingHash, recordDigest("3FS-W0-BINDINGS-v1", bindings));
  out.bindingsDigest = bindingHash;
  return out;
}
CoTryTask<EcTreeManifestHolds> EcFileTreeCatalog::installed(EcTreeContext &context,
                                                            const EcTreeSlot &slot,
                                                            bool verifyPermanent) {
  const auto &birth = context.birth_;
  auto &txn = *context.txn_;
  CO_RETURN_ON_ERROR(validSlot(slot, birth, slot.stripe));
  if (slot.kind != EcTreeSlotKind::Data) co_return makeError(StatusCode::kInvalidArg);
  auto value = co_await require<EcTreeManifestHolds>(
      txn,
      manifestKey(KeyPrefix::EcTreeManifest, birth.object, slot.stripe, slot.revision));
  CO_RETURN_ON_ERROR(value);
  if (value->object != birth.object || value->retired || !same(value->slot, slot) ||
      value->manifestDigest == storage::EcSha256{} || value->bindingsDigest == storage::EcSha256{})
    co_return makeError(StatusCode::kDataCorruption, "Data extent lost its exact compact commitment");
  std::set<Uuid> allocationIds;
  for (size_t i = 0; i < 12; ++i) {
    const auto &identity = value->identities[i];
    CO_RETURN_ON_ERROR(identity.validate());
    if (identity.object != birth.object.incarnation || identity.stripe != slot.stripe ||
        identity.generation != slot.generation || identity.shard != i ||
        !allocationIds.insert(identity.allocation).second)
      co_return makeError(StatusCode::kDataCorruption, "EC tree compact allocation set differs");
  }
  // Positive holds prevent manifest retirement. Full verification is required
  // when first activating its allocations, and on a data lookup. COW copies
  // and final hold release update compact accounting, not descriptor replicas.
  if (verifyPermanent || !value->treeHolds) {
    auto permanent = co_await EcCatalog::getManifest(txn, birth.object, slot.stripe, slot.revision);
    CO_RETURN_ON_ERROR(permanent);
    const auto &m = permanent->manifest;
    if (permanent->retired || permanent->referencesReleased || m.version != kEcCatalogVersion ||
        m.object != birth.object || m.stripe != slot.stripe || m.revision != slot.revision ||
        m.generation != slot.generation || m.logicalLength != slot.logicalLength)
      co_return makeError(StatusCode::kDataCorruption, "installed EC tree manifest differs");
    EcV2AllocationBindings bindings;
    for (size_t i = 0; i < 12; ++i) {
      const auto &fragment = m.fragments[i];
      CO_RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
      if (!same(fragment.identity, value->identities[i]) || fragment.operation.is_nil() ||
          fragment.integrity.wholeLength != birth.shardBytes || fragment.placement.node == flat::NodeId{} ||
          fragment.placement.chain == storage::ChainId{} || fragment.placement.target == storage::TargetId{})
        co_return makeError(StatusCode::kDataCorruption, "installed EC tree fragment differs");
      auto key = allocationKey(KeyPrefix::EcV2Allocation, fragment.identity);
      CO_RETURN_ON_ERROR(key);
      auto actual = co_await require<EcV2AllocationBinding>(txn, *key);
      CO_RETURN_ON_ERROR(actual);
      auto ref = co_await EcCatalog::getFragmentRef(txn, fragment.identity);
      CO_RETURN_ON_ERROR(ref);
      if (actual->object != birth.object || actual->version != kEcBindingCatalogVersion ||
          actual->fragment != fragment || actual->writer.client.is_nil() || actual->engineUuid.is_nil() ||
          actual->targetIncarnation.is_nil() || ref->fragment != fragment || !ref->references || !ref->owner.is_nil() ||
          ref->gcCandidate)
        co_return makeError(StatusCode::kDataCorruption, "tree manifest lacks immutable allocation references");
      bindings[i] = std::move(*actual);
    }
    auto committed = commitment(birth.object, m, bindings, slot.contentSha256);
    CO_RETURN_ON_ERROR(committed);
    if (committed->manifestDigest != value->manifestDigest || committed->bindingsDigest != value->bindingsDigest)
      co_return makeError(StatusCode::kDataCorruption, "EC tree immutable metadata commitment changed");
  }
  co_return std::move(*value);
}
CoTryTask<Void> EcFileTreeCatalog::manifestHold(EcTreeContext &context, const EcTreeSlot &slot, bool increment) {
  auto value = co_await installed(context, slot);
  CO_RETURN_ON_ERROR(value);
  const bool allocationTransition = increment ? value->treeHolds == 0 : value->treeHolds == 1;
  if (increment) {
    if (value->treeHolds == std::numeric_limits<uint64_t>::max()) co_return makeError(StatusCode::kDataCorruption);
    ++value->treeHolds;
  } else {
    if (!value->treeHolds) co_return makeError(StatusCode::kDataCorruption, "manifest tree hold underflow");
    --value->treeHolds;
  }
  // ECTA counts installed manifests with nonzero treeHolds, not every COW
  // copy. This keeps updates bounded while retaining the claim conflict edge.
  if (allocationTransition)
    for (const auto &identity : value->identities)
      CO_RETURN_ON_ERROR(co_await EcFileTreeGcGuard::adjust(*context.txn_, context.birth_.object, identity, increment));
  co_return co_await store(*context.txn_,
                           manifestKey(KeyPrefix::EcTreeManifest, context.birth_.object, slot.stripe, slot.revision),
                           *value);
}
CoTryTask<EcTreeNodeRefs> EcFileTreeCatalog::reclaimNode(EcTreeContext &context, const Uuid &id) {
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  // The permanent tombstone, not a retained ECNT body, proves completion.
  const auto bodyKey = idKey(KeyPrefix::EcTreeNode, context.birth_.object, id);
  const auto refsKey = idKey(KeyPrefix::EcTreeNodeRefs, context.birth_.object, id);
  const auto workKey = idKey(KeyPrefix::EcTreeReclaim, context.birth_.object, id);
  auto terminal = co_await require<EcTreeNodeRefs>(*context.txn_, refsKey);
  CO_RETURN_ON_ERROR(terminal);
  CO_RETURN_ON_ERROR(validRefs(*terminal, context.birth_.object, id));
  if (terminal->state == EcTreeRefState::Reclaimed) {
    auto work = co_await context.txn_->get(workKey);
    CO_RETURN_ON_ERROR(work);
    if (*work || root->root == id)
      co_return makeError(StatusCode::kDataCorruption, "terminal EC node is still reachable or queued");
    // Earlier W0 binaries retained terminal bodies. Clear only a matching
    // body, without repeating any outgoing-edge or manifest decrement.
    auto oldBody = co_await load<EcTreeNode>(*context.txn_, bodyKey);
    CO_RETURN_ON_ERROR(oldBody);
    if (*oldBody) {
      CO_RETURN_ON_ERROR(validNode(**oldBody, context.birth_));
      if ((**oldBody).id != id || (**oldBody).level != terminal->level || (**oldBody).prefix != terminal->prefix)
        co_return makeError(StatusCode::kDataCorruption, "terminal EC node body/path differs");
      CO_RETURN_ON_ERROR(co_await context.txn_->clear(bodyKey));
    }
    co_return *terminal;
  }
  // A nonterminal node must still have a complete body. Missing is corruption,
  // never an implicit Zero extent or evidence that its outgoing edges drained.
  auto current = co_await node(*context.txn_, context.birth_, id);
  CO_RETURN_ON_ERROR(current);
  auto &[body, refs] = *current;
  if (refs.state != EcTreeRefState::Reclaimable || refs.references || root->root == id)
    co_return makeError(StatusCode::kTokenStale, "live EC node cannot be reclaimed");
  auto work =
      co_await require<EcTreeReclaimWork>(*context.txn_, idKey(KeyPrefix::EcTreeReclaim, context.birth_.object, id));
  CO_RETURN_ON_ERROR(work);
  if (work->object != context.birth_.object || work->node != id) co_return makeError(StatusCode::kDataCorruption);
  if (body.level) {
    for (size_t i = 0; i < 16; ++i)
      if (!body.children[i].is_nil())
        CO_RETURN_ON_ERROR(co_await childRef(*context.txn_,
                                             context.birth_,
                                             body.children[i],
                                             body.level - 1,
                                             body.prefix | (uint64_t(i) << (4 * body.level)),
                                             false));
  } else {
    for (const auto &slot : *body.slots)
      if (slot.kind == EcTreeSlotKind::Data) CO_RETURN_ON_ERROR(co_await manifestHold(context, slot, false));
  }
  refs.state = EcTreeRefState::Reclaimed;
  CO_RETURN_ON_ERROR(co_await store(*context.txn_, idKey(KeyPrefix::EcTreeNodeRefs, context.birth_.object, id), refs));
  CO_RETURN_ON_ERROR(co_await context.txn_->clear(idKey(KeyPrefix::EcTreeReclaim, context.birth_.object, id)));
  // The outgoing decrements, terminal ECNR, queue removal and body removal
  // are one transaction. Creation checks ECNR as well as ECNT, so the retained
  // tombstone permanently prevents UUID reuse even after the large body is gone.
  CO_RETURN_ON_ERROR(co_await context.txn_->clear(bodyKey));
  co_return refs;
}
CoTryTask<EcTreeRoot> EcFileTreeCatalog::detachForRetirement(EcTreeContext &context) {
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  if (root->sequence == std::numeric_limits<uint64_t>::max() || root->epoch == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy, "retirement counters exhausted");
  auto object = co_await EcCatalog::getObject(*context.txn_, context.birth_.object);
  CO_RETURN_ON_ERROR(object);
  if (!root->root.is_nil())
    CO_RETURN_ON_ERROR(co_await childRef(*context.txn_, context.birth_, root->root, 15, 0, false));
  root->root = Uuid::zero();
  ++root->sequence;
  ++root->epoch;
  object->epoch = root->epoch;
  object->deleting = true;
  // Keep immutable history and the terminal EOF/inode. No physical delete is authorized here.
  CO_RETURN_ON_ERROR(co_await store(*context.txn_, objectKey(KeyPrefix::EcObject, context.birth_.object), *object));
  CO_RETURN_ON_ERROR(co_await store(*context.txn_, objectKey(KeyPrefix::EcTreeRoot, context.birth_.object), *root));
  co_return root;
}
CoTryTask<EcTreeNodeRefs> EcFileTreeCatalog::reclaimRetired(Tx &txn, const EcObjectRef &object, const Uuid &nodeId) {
  auto birth = co_await getBirth(txn, object);
  CO_RETURN_ON_ERROR(birth);
  EcTreeContext context(txn, std::move(*birth));
  context.retiredMaintenance_ = true;
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  if (!root->root.is_nil()) co_return makeError(StatusCode::kDataCorruption, "retired root still attached");
  co_return co_await reclaimNode(context, nodeId);
}
#include "detail/EcFileTreeCut.inc"
}  // namespace hf3fs::meta::server
