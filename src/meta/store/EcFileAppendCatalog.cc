#include "EcFileAppendCatalog.h"

#include "EcFileTruncateCatalog.h"
#include "detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcFileTreeTxnBudget;
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
std::string requestKey(const EcFileAppendIntent &i) {
  auto key = objectKey(KeyPrefix::EcFileAppend, i.object);
  key.push_back(char{1});
  key.append(i.request.asStringView());
  return key;
}
CoTryTask<std::optional<EcFileAppendGate>> gate(Tx &tx, const EcObjectRef &object) {
  auto g = co_await load<EcFileAppendGate>(tx, objectKey(KeyPrefix::EcFileAppendGate, object));
  CO_RETURN_ON_ERROR(g);
  if (*g && ((**g).version != 1 || (**g).object != object || (**g).birth.is_nil() || (**g).operation.is_nil()))
    co_return makeError(StatusCode::kDataCorruption, "append gate identity changed");
  co_return g;
}
Result<Void> record(const EcFileAppendRecord &r, const EcFileAppendIntent &i) {
  RETURN_ON_ERROR(validateEcAppend(r.intent));
  RETURN_ON_ERROR(valid(r.parent));
  const auto &p = r.parent.intent;
  const auto &root = r.acceptedRoot;
  if (r.version != 1 || !same(r.intent, i) || r.birth.is_nil() || root.object != i.object || root.birth != r.birth ||
      !root.sequence || !root.epoch || p.object != i.object || !same(p.owner, i.owner) || p.session != i.session ||
      p.request != i.operation || p.offset != root.visibleLength || p.length != i.length ||
      p.inputSha256 != i.inputSha256 || r.parent.epoch != root.epoch)
    return makeError(StatusCode::kDataCorruption, "append acceptance differs from fixed EOF/parent");
  return Void{};
}
}  // namespace
CoTryTask<Void> EcFileAppendCatalog::requireMutationOpen(Tx &tx, const EcObjectRef &object, const Uuid &parent) {
  auto g = co_await gate(tx, object);
  CO_RETURN_ON_ERROR(g);
  if (*g && (**g).active && (**g).operation != parent)
    co_return makeError(StorageClientCode::kResourceBusy,
                        "another append owns the file EOF; retain original operation IDs");
  co_return Void{};
}
CoTryTask<std::optional<EcFileAppendRecord>> EcFileAppendCatalog::query(Tx &tx, const EcFileAppendIntent &i) {
  CO_RETURN_ON_ERROR(validateEcAppend(i));
  auto session = co_await EcFileSessionCatalog::get(tx, i.object, i.session, i.owner);
  CO_RETURN_ON_ERROR(session);
  if (!(session->intent.rights & kEcSessionWrite)) co_return makeError(MetaCode::kNoPermission);
  auto r = co_await load<EcFileAppendRecord>(tx, idKey(KeyPrefix::EcFileAppend, i.object, i.operation));
  CO_RETURN_ON_ERROR(r);
  auto alias = co_await load<EcFileAppendIntent>(tx, requestKey(i));
  CO_RETURN_ON_ERROR(alias);
  if (*alias && !same(**alias, i))
    co_return makeError(StatusCode::kTokenMismatch, "append request UUID was bound to another immutable intent");
  if (!*r) {
    if (*alias) co_return makeError(StatusCode::kDataCorruption, "append request alias lost its operation");
    co_return std::nullopt;
  }
  if (!*alias) co_return makeError(StatusCode::kDataCorruption, "append operation lost its request alias");
  if (!same((**r).intent, i)) co_return makeError(StatusCode::kTokenMismatch, "append retry changed body");
  CO_RETURN_ON_ERROR(record(**r, i));
  if ((**r).birth != session->intent.birth) co_return makeError(StatusCode::kDataCorruption);
  auto p = co_await EcFileMutationCatalog::query(tx, i.object, i.operation, i.owner);
  CO_RETURN_ON_ERROR(p);
  if (!*p || !same((**p).intent, (**r).parent.intent) || (**p).sessionSequence != (**r).parent.sessionSequence)
    co_return makeError(StatusCode::kDataCorruption, "accepted append lost its permanent parent");
  (**r).parent = std::move(**p);
  CO_RETURN_ON_ERROR(record(**r, i));
  auto g = co_await gate(tx, i.object);
  CO_RETURN_ON_ERROR(g);
  if ((**r).parent.state == EcFileMutationState::Open &&
      (!*g || !(**g).active || (**g).operation != i.operation || (**g).birth != (**r).birth))
    co_return makeError(StatusCode::kDataCorruption, "open append lost its exclusive EOF gate");
  co_return r;
}
CoTryTask<EcFileAppendRecord> EcFileAppendCatalog::begin(Tx &tx, const EcFileAppendIntent &i) {
  CO_RETURN_ON_ERROR(validateEcAppend(i));
  auto prior = co_await query(tx, i);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) co_return std::move(**prior);
  CO_RETURN_ON_ERROR(co_await requireMutationOpen(tx, i.object, Uuid::zero()));
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(tx, i.object));
  auto session = co_await EcFileSessionCatalog::require(tx, i.object, i.session, i.owner, kEcSessionWrite, false);
  CO_RETURN_ON_ERROR(session);
  auto context = co_await EcFileTreeCatalog::open(tx, i.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  CO_RETURN_ON_ERROR(rangeEnd(root->visibleLength, i.length));
  // A pwrite parent with this UUID cannot be adopted as an append acceptance.
  auto old = co_await tx.get(idKey(KeyPrefix::EcFileMutation, i.object, i.operation));
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return makeError(StatusCode::kTokenDuplicated, "append parent UUID already exists");
  EcFilePwriteIntent p;
  p.object = i.object;
  p.owner = i.owner;
  p.session = i.session;
  p.request = i.operation;
  p.offset = root->visibleLength;
  p.length = i.length;
  p.inputSha256 = i.inputSha256;
  auto accepted = co_await EcFileMutationCatalog::begin(tx, p);
  CO_RETURN_ON_ERROR(accepted);
  EcFileAppendRecord r;
  r.intent = i;
  r.birth = context->birth().createRequest;
  r.acceptedRoot = *root;
  r.parent = *accepted;
  CO_RETURN_ON_ERROR(record(r, i));
  EcFileAppendGate g;
  g.object = i.object;
  g.birth = r.birth;
  g.operation = i.operation;
  g.active = true;
  CO_RETURN_ON_ERROR(co_await store(tx, objectKey(KeyPrefix::EcFileAppendGate, i.object), g));
  CO_RETURN_ON_ERROR(co_await store(tx, idKey(KeyPrefix::EcFileAppend, i.object, i.operation), r));
  CO_RETURN_ON_ERROR(co_await store(tx, requestKey(i), i));
  co_return r;  // Neither inode.length nor root.visibleLength was reserved ahead.
}
CoTryTask<Void> EcFileAppendCatalog::finishParent(Tx &tx, const EcFileMutationRecord &p) {
  auto g = co_await gate(tx, p.intent.object);
  CO_RETURN_ON_ERROR(g);
  if (!*g || !(**g).active || (**g).operation != p.intent.request) co_return Void{};
  auto r = co_await load<EcFileAppendRecord>(tx, idKey(KeyPrefix::EcFileAppend, p.intent.object, p.intent.request));
  CO_RETURN_ON_ERROR(r);
  if (!*r || !same((**r).parent.intent, p.intent) || (**g).birth != (**r).birth)
    co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(record(**r, (**r).intent));
  if (p.state == EcFileMutationState::ClosedLogical) {
    (**g).active = false;
    CO_RETURN_ON_ERROR(co_await store(tx, objectKey(KeyPrefix::EcFileAppendGate, p.intent.object), **g));
  }
  co_return Void{};
}
CoTryTask<EcFileSyncRecord> EcFileAppendCatalog::sync(Tx &tx, const EcFileSyncIntent &i) {
  CO_RETURN_ON_ERROR(validateEcSync(i));
  auto s = co_await EcFileSessionCatalog::get(tx, i.object, i.session, i.owner);
  CO_RETURN_ON_ERROR(s);
  const auto key = idKey(KeyPrefix::EcFileSync, i.object, i.request);
  auto old = co_await load<EcFileSyncRecord>(tx, key);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    const auto &r = **old;
    if (!same(r.intent, i)) co_return makeError(StatusCode::kTokenMismatch);
    if (r.version != 1 || r.durabilityContract != 1 || r.root.object != i.object || r.root.birth != s->intent.birth ||
        !r.root.sequence || !r.root.epoch || r.sessionSequence > s->acceptedSequence)
      co_return makeError(StatusCode::kDataCorruption);
    co_return r;
  }
  const auto rights = s->intent.rights & kEcSessionWrite ? kEcSessionWrite : kEcSessionRead;
  CO_RETURN_ON_ERROR(co_await EcFileSessionCatalog::require(tx, i.object, i.session, i.owner, rights, false));
  if (!s->activeParent.is_nil() || !s->activeStructural.is_nil())
    co_return makeError(StorageClientCode::kResourceBusy,
                        "fsync cannot confirm an unfinished mutation or unknown publication");
  CO_RETURN_ON_ERROR(co_await requireMutationOpen(tx, i.object, Uuid::zero()));
  CO_RETURN_ON_ERROR(co_await EcFileTruncateCatalog::requireMutationOpen(tx, i.object));
  auto context = co_await EcFileTreeCatalog::open(tx, i.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  // Production Data roots can only be installed after sync_immutable_data,
  // namespace sync and synchronous RocksDB Seal, independently verified on all
  // 12 outputs, followed by this database's durable commit. There is no dirty
  // writeback cache behind the tree. This is a commit barrier, not a disk-health
  // probe or a waiver of source/output GC debts. Deferred/unsafe Seal modes may
  // not reuse contract 1.
  EcFileSyncRecord r;
  r.intent = i;
  r.sessionSequence = s->acceptedSequence;
  r.root = *root;
  CO_RETURN_ON_ERROR(co_await store(tx, key, r));
  co_return r;
}
}  // namespace hf3fs::meta::server
