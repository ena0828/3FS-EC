#include "EcFileDataInstaller.h"

#include <algorithm>
#include <sys/stat.h>

#include "EcCatalog.h"
#include "Inode.h"
#include "detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using Tx = EcFileTreeTxnBudget;
using kv::KeyPrefix;
}  // namespace

CoTryTask<EcTreeSlot> EcFileDataInstaller::installValidated(
    Tx &txn,
    const EcFileExecutionCatalog::PublicationValidation &validation) {
  if (!validation.validFor(txn))
    co_return makeError(StatusCode::kTokenStale, "manifest validation changed transaction or was consumed");
  const auto &r = validation.record();
  const auto &object = r.child.intent.object;
  if (r.state != EcFileExecutionState::Drained || !r.drain || !r.drain->verifiedManifest || !r.allocations)
    co_return makeError(StatusCode::kTokenStale, "manifest installation already completed");
  const auto &m = *r.drain->verifiedManifest;
  const auto &allocations = *r.allocations;
  const auto &c = r.child;
  if (m.object != object || m.stripe != c.stripe || m.generation != c.targetGeneration ||
      m.revision != c.targetRevision || m.logicalLength != c.targetLogicalLength)
    co_return makeError(StatusCode::kTokenMismatch);
  const auto mk = manifestKey(KeyPrefix::EcManifest, object, m.stripe, m.revision);
  const auto ck = manifestKey(KeyPrefix::EcTreeManifest, object, m.stripe, m.revision);
  // A fresh installation cannot reuse a permanent edit. Otherwise replace()
  // could take its replay path and skip the first manifest-hold activation.
  // This conflict read also covers the repair caller; truncate uses cut().
  const auto ek = idKey(KeyPrefix::EcTreeEdit, object, c.intent.child);
  for (const auto &key : {mk, ck, ek}) {
    auto old = co_await txn.get(key);
    CO_RETURN_ON_ERROR(old);
    if (*old)
      co_return makeError(StatusCode::kDataCorruption, "installation collides with permanent publication metadata");
  }
  for (size_t i = 0; i < 12; ++i) {
    const auto &f = m.fragments[i];
    const auto &a = allocations[i];
    if (a.object != object || a.fragment != f) co_return makeError(StatusCode::kTokenMismatch);
    // The private validation has already checked the exact permanent binding
    // in this transaction. The caller's first manifestHold() reads it again
    // before activating the fresh manifest; do not add a third read here.
    auto rk = allocationKey(KeyPrefix::EcFragmentRef, f.identity);
    CO_RETURN_ON_ERROR(rk);
    auto ref = co_await txn.get(*rk);
    CO_RETURN_ON_ERROR(ref);
    if (*ref) co_return makeError(StatusCode::kDataCorruption, "fresh candidate already has a fragment reference");
    auto gk = allocationKey(KeyPrefix::EcGcClaim, f.identity);
    CO_RETURN_ON_ERROR(gk);
    auto claim = co_await txn.get(*gk);
    CO_RETURN_ON_ERROR(claim);
    if (*claim) co_return makeError(StatusCode::kTokenStale, "claimed allocation cannot be installed");
    EcFragmentRefRecord created;
    created.fragment = f;
    created.references = 1;
    CO_RETURN_ON_ERROR(co_await store(txn, *rk, created));
  }
  EcManifestRecord permanent;
  permanent.manifest = m;
  CO_RETURN_ON_ERROR(co_await store(txn, mk, permanent));
  auto compact = EcFileTreeCatalog::commitment(object, m, allocations, r.contentSha256);
  CO_RETURN_ON_ERROR(compact);
  CO_RETURN_ON_ERROR(co_await store(txn, ck, *compact));
  // All callers activate this fresh manifest through replace()/cut() in this
  // same transaction. Its initial treeHolds == 0 makes manifestHold() verify
  // the complete manifest, bindings and fragment refs before adding GC holds.
  // Do not reread the same records here; no caller may commit installation
  // without that activation, and any later error discards the transaction.
  co_return compact->slot;
}

CoTryTask<EcFileMutationRecord> EcFileDataInstaller::publishPwrite(Tx &txn,
                                                                   const EcOwner &owner,
                                                                   const EcRmwPublicationProof &proof) {
  auto validation =
      co_await EcFileExecutionCatalog::preparePublicationValidation(txn, owner, proof, EcFileExecutionOwner::Pwrite);
  CO_RETURN_ON_ERROR(validation);
  const auto &c = validation->record().child;
  const auto &object = c.intent.object;
  if (validation->record().state == EcFileExecutionState::Published) {
    auto child = co_await EcFileMutationCatalog::queryChild(txn, object, c.intent.child, owner);
    CO_RETURN_ON_ERROR(child);
    if (!*child || (**child).state != EcFileChildState::Published) co_return makeError(StatusCode::kDataCorruption);
    auto parent = co_await EcFileMutationCatalog::query(txn, object, c.intent.parent, owner);
    CO_RETURN_ON_ERROR(parent);
    if (!*parent) co_return makeError(StatusCode::kDataCorruption);
    co_return std::move(**parent);
  }
  auto gate = co_await EcFileMutationCatalog::preparePublication(txn, object, c.intent.child, owner);
  CO_RETURN_ON_ERROR(gate);
  auto slot = co_await installValidated(txn, *validation);
  CO_RETURN_ON_ERROR(slot);
  EcTreeEdit edit;
  edit.object = object;
  edit.operation = c.intent.child;
  edit.expectedRoot = gate->currentRoot().root;
  edit.expectedSequence = gate->currentRoot().sequence;
  edit.expectedEpoch = c.epoch;
  edit.stripe = c.stripe;
  edit.visibleLength =
      std::max(c.lengthAtPlan,
               c.stripe * uint64_t(validation->plan().input().shardBytes) * 10 + c.patchOffset + c.patchLength);
  edit.nodeIds = c.intent.nodeIds;
  edit.replacement = *slot;
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto installed = co_await EcFileTreeCatalog::replace(*context, edit);
  CO_RETURN_ON_ERROR(installed);
  auto inode = co_await Inode::load(txn, object.inode);
  CO_RETURN_ON_ERROR(inode);
  if (!*inode || !(**inode).isFile()) co_return makeError(StatusCode::kDataCorruption);
  (**inode).asFile().length = edit.visibleLength;
  (**inode).mtime = (**inode).ctime = UtcClock::now();
  if ((**inode).acl.uid != owner.uid) {
    constexpr uint32_t special = S_ISUID | S_ISGID | S_ISVTX;
    (**inode).acl.perm = Permission((**inode).acl.perm.toUnderType() & ~special);
  }
  CO_RETURN_ON_ERROR(co_await (**inode).store(txn));
  auto result = co_await EcFileMutationCatalog::finishPublished(txn, owner, *gate, *installed);
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(
      co_await EcFileExecutionCatalog::finishValidatedPublication(txn, std::move(*validation), installed->root));
  co_return result;
}
}  // namespace hf3fs::meta::server
