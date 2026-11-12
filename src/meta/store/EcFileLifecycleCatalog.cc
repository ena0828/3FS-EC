#include "EcFileLifecycleCatalog.h"

#include <fcntl.h>
#include <limits>
#include <linux/fs.h>

#include "EcCatalog.h"
#include "EcNamespaceGuard.h"
#include "detail/EcFileMutationKeys.h"
#include "meta/components/GcManager.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
EcFileNamespaceIntent intent(const HardLinkReq &r) {
  EcFileNamespaceIntent i;
  i.action = EcFileNamespaceAction::Link;
  i.owner = {r.user.uid, r.client.uuid};
  i.request = r.uuid;
  i.oldPath = r.oldPath;
  i.newPath = r.newPath;
  i.flags = r.flags;
  return i;
}
EcFileNamespaceIntent intent(const RemoveReq &r) {
  EcFileNamespaceIntent i;
  i.action = EcFileNamespaceAction::Unlink;
  i.owner = {r.user.uid, r.client.uuid};
  i.request = r.uuid;
  i.oldPath = r.path;
  i.flags = r.atFlags;
  i.recursive = r.recursive;
  i.checkType = r.checkType;
  i.expectedInode = r.inodeId;
  return i;
}
Result<Void> validIntent(const EcFileNamespaceIntent &i) {
  if (i.request.is_nil() || i.owner.client.is_nil())
    return makeError(StatusCode::kInvalidArg, "namespace request needs durable IDs");
  return Void{};
}
std::string requestKey(const EcFileNamespaceIntent &i) {
  std::string k(kv::toStr(KeyPrefix::EcFileNamespaceRequest));
  k.append(i.owner.client.asStringView());
  k.append(i.request.asStringView());
  return k;
}
std::string renameKey(const EcOwner &o, const Uuid &id) {
  std::string k(kv::toStr(KeyPrefix::EcFileRenameRequest));
  k.append(o.client.asStringView());
  k.append(id.asStringView());
  return k;
}
struct RenameIntent {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(source, PathAt{});
  SERDE_STRUCT_FIELD(destination, PathAt{});
  SERDE_STRUCT_FIELD(moveToTrash, false);
  SERDE_STRUCT_FIELD(expectedInode, (std::optional<InodeId>{}));
};
RenameIntent renameIntent(const RenameReq &r) {
  RenameIntent i;
  i.owner = {r.user.uid, r.client.uuid};
  i.request = r.uuid;
  i.source = r.src;
  i.destination = r.dest;
  i.moveToTrash = r.moveToTrash;
  i.expectedInode = r.inodeId;
  return i;
}
struct RenameRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(intent, RenameIntent{});
  SERDE_STRUCT_FIELD(sourceId, InodeId{});
  SERDE_STRUCT_FIELD(destinationId, (std::optional<InodeId>{}));
  SERDE_STRUCT_FIELD(sourceBirth, (std::optional<EcTreeBirth>{}));
  SERDE_STRUCT_FIELD(destinationBirth, (std::optional<EcTreeBirth>{}));
  SERDE_STRUCT_FIELD(sourceParent, InodeId{});
  SERDE_STRUCT_FIELD(sourceName, String{});
  SERDE_STRUCT_FIELD(destinationParent, InodeId{});
  SERDE_STRUCT_FIELD(destinationName, String{});
  SERDE_STRUCT_FIELD(result, Inode{});
};
CoTryTask<EcFileSessionIndex> sessions(Tx &txn, const EcTreeBirth &birth) {
  auto s = co_await require<EcFileSessionIndex>(txn, objectKey(KeyPrefix::EcFileSessionIndex, birth.object));
  CO_RETURN_ON_ERROR(s);
  if (s->object != birth.object || s->birth != birth.createRequest) co_return makeError(StatusCode::kDataCorruption);
  co_return s;
}
CoTryTask<Inode> exactInode(Tx &txn, const EcObjectRef &object) {
  auto i = co_await Inode::load(txn, object.inode);
  CO_RETURN_ON_ERROR(i);
  if (!*i || !(**i).isFile()) co_return makeError(StatusCode::kDataCorruption, "permanent EC inode missing");
  auto layout = (**i).asFile().layout.ecLayout();
  if (!layout || layout->incarnation != object.incarnation) co_return makeError(StatusCode::kTokenMismatch);
  CO_RETURN_ON_ERROR(layout->valid());
  co_return std::move(**i);
}
CoTryTask<EcFileLifeRecord> life(Tx &txn, const EcTreeBirth &birth, const Inode &inode, bool initialize) {
  auto found = co_await load<EcFileLifeRecord>(txn, objectKey(KeyPrefix::EcFileLifecycle, birth.object));
  CO_RETURN_ON_ERROR(found);
  auto enrolled = co_await load<EcTreeBirth>(txn, objectKey(KeyPrefix::EcFileLifecycleEnrollment, birth.object));
  CO_RETURN_ON_ERROR(enrolled);
  if (!*found) {
    // Earlier mode-4 code had no link/unlink path. Never synthesize missing
    // zero-count history, or enroll a multiply linked legacy/flat object.
    if (!initialize || inode.nlink != 1 || *enrolled)
      co_return makeError(StatusCode::kDataCorruption, "missing lifecycle history");
    CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileLifecycleEnrollment, birth.object), birth));
    EcFileLifeRecord r;
    r.object = birth.object;
    r.birth = birth.createRequest;
    r.links = 1;
    co_return r;
  }
  if (!*enrolled || !same(**enrolled, birth))
    co_return makeError(StatusCode::kDataCorruption, "lifecycle enrollment missing or changed");
  auto r = std::move(**found);
  if (r.object != birth.object || r.birth != birth.createRequest || r.links != inode.nlink ||
      (r.state != EcFileLifeState::Linked && r.state != EcFileLifeState::Unlinked &&
       r.state != EcFileLifeState::Retired) ||
      ((r.state == EcFileLifeState::Linked) != (r.links != 0)) ||
      ((r.state == EcFileLifeState::Retired) != r.retiredRoot.has_value()) ||
      (r.state != EcFileLifeState::Linked && r.lastUnlink.is_nil()))
    co_return makeError(StatusCode::kDataCorruption, "lifecycle/inode state differs");
  co_return r;
}
CoTryTask<std::optional<EcFileNamespaceRecord>> replayRecord(Tx &txn, const EcFileNamespaceIntent &i) {
  // Nil IDs remain valid for older replicated operations. They can never
  // match or create this mode-4 permanent namespace ledger.
  if (i.request.is_nil() || i.owner.client.is_nil()) co_return std::nullopt;
  auto renamed = co_await txn.get(renameKey(i.owner, i.request));
  CO_RETURN_ON_ERROR(renamed);
  if (*renamed) co_return makeError(StatusCode::kTokenMismatch, "namespace request UUID belongs to a rename");
  auto r = co_await load<EcFileNamespaceRecord>(txn, requestKey(i));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  if (!same((**r).intent, i)) co_return makeError(StatusCode::kTokenMismatch, "namespace request parameters changed");
  auto b = co_await EcFileTreeCatalog::getBirth(txn, (**r).object);
  CO_RETURN_ON_ERROR(b);
  if ((**r).birth != b->createRequest || (**r).result.id != (**r).object.inode || !(**r).result.isFile())
    co_return makeError(StatusCode::kDataCorruption, "namespace history changed birth");
  const auto *layout = (**r).result.asFile().layout.ecLayout();
  if (!layout || layout->incarnation != (**r).object.incarnation || layout->shardBytes != b->shardBytes)
    co_return makeError(StatusCode::kDataCorruption);
  co_return r;
}
CoTryTask<Void> persist(Tx &txn,
                        const EcFileNamespaceIntent &i,
                        const EcTreeBirth &b,
                        InodeId parent,
                        const String &name,
                        const Inode &inode) {
  EcFileNamespaceRecord r;
  r.intent = i;
  r.object = b.object;
  r.birth = b.createRequest;
  r.parent = parent;
  r.name = name;
  r.result = inode;
  co_return co_await store(txn, requestKey(i), r);
}
CoTryTask<Inode> writableParent(Tx &txn, InodeId id, const flat::UserInfo &user, const ClientId &client) {
  auto p = co_await Inode::load(txn, id);
  CO_RETURN_ON_ERROR(p);
  if (!*p || !(**p).nlink) co_return makeError(MetaCode::kNotFound);
  if (!(**p).isDirectory()) co_return makeError(MetaCode::kNotDirectory);
  CO_RETURN_ON_ERROR((**p).acl.checkPermission(user, AccessType::WRITE));
  CO_RETURN_ON_ERROR((**p).asDirectory().checkLock(client));
  co_return std::move(**p);
}
}  // namespace

CoTryTask<std::optional<RenameRsp>> EcFileLifecycleCatalog::replay(Tx &txn, const RenameReq &req) {
  if (req.uuid.is_nil() || req.client.uuid.is_nil()) co_return std::nullopt;
  const auto i = renameIntent(req);
  EcFileNamespaceIntent cross;
  cross.owner = i.owner;
  cross.request = i.request;
  auto other = co_await txn.get(requestKey(cross));
  CO_RETURN_ON_ERROR(other);
  if (*other) co_return makeError(StatusCode::kTokenMismatch, "rename UUID belongs to another namespace operation");
  auto r = co_await load<RenameRecord>(txn, renameKey(i.owner, i.request));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  const auto &v = **r;
  if (!same(v.intent, i))
    co_return makeError(StatusCode::kTokenMismatch, "rename original parameters or authenticated owner changed");
  if ((!v.sourceBirth && !v.destinationBirth) || v.result.id != v.sourceId ||
      (v.sourceBirth && (v.sourceBirth->object.inode != v.sourceId || !v.result.isFile())) ||
      (v.destinationBirth && (!v.destinationId || v.destinationBirth->object.inode != *v.destinationId)))
    co_return makeError(StatusCode::kDataCorruption, "rename history lost its exact source/destination");
  for (const auto &saved : {v.sourceBirth, v.destinationBirth})
    if (saved) {
      auto b = co_await EcFileTreeCatalog::getBirth(txn, saved->object);
      CO_RETURN_ON_ERROR(b);
      if (!same(*b, *saved)) co_return makeError(StatusCode::kDataCorruption, "rename birth changed");
    }
  if (v.sourceBirth) {
    const auto *d = v.result.asFile().layout.ecLayout();
    if (!d || d->incarnation != v.sourceBirth->object.incarnation || d->shardBytes != v.sourceBirth->shardBytes)
      co_return makeError(StatusCode::kDataCorruption);
  }
  co_return std::optional<RenameRsp>{RenameRsp(v.result)};
}
CoTryTask<RenameRsp> EcFileLifecycleCatalog::rename(Tx &txn,
                                                    const RenameReq &req,
                                                    const DirEntry &resolved,
                                                    InodeId destinationParent,
                                                    const String &destinationName,
                                                    GcManager &gc) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(req.checkUuid());
  auto prior = co_await replay(txn, req);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) co_return std::move(**prior);
  auto source = co_await DirEntry::load(txn, resolved.parent, resolved.name);
  CO_RETURN_ON_ERROR(source);
  if (!*source || (**source).id != resolved.id) co_return makeError(MetaCode::kNotFound);
  auto target = co_await DirEntry::load(txn, destinationParent, destinationName);
  CO_RETURN_ON_ERROR(target);
  auto loaded = co_await (**source).loadInode(txn);
  CO_RETURN_ON_ERROR(loaded);
  auto inode = std::move(*loaded);
  if (!inode.nlink || (req.inodeId && *req.inodeId != inode.id)) co_return makeError(MetaCode::kNotFound);
  if (inode.isDirectory())
    co_return makeError(StatusCode::kNotImplemented, "tree-file rename does not recursively migrate directories");
  std::optional<Inode> replaced;
  if (*target) {
    auto d = co_await (**target).loadInode(txn);
    CO_RETURN_ON_ERROR(d);
    replaced = std::move(*d);
  }
  if (replaced && replaced->isDirectory()) co_return makeError(MetaCode::kIsDirectory);
  if (replaced && !replaced->nlink) co_return makeError(StatusCode::kDataCorruption);
  auto srcParent = co_await writableParent(txn, (**source).parent, req.user, req.client);
  CO_RETURN_ON_ERROR(srcParent);
  auto dstParent = co_await writableParent(txn, destinationParent, req.user, req.client);
  CO_RETURN_ON_ERROR(dstParent);
  const auto permission = [&](const Inode &parent, const Inode &file) -> Result<Void> {
    if ((file.acl.iflags & FS_IMMUTABLE_FL) || ((parent.acl.perm & S_ISVTX) && !req.user.isRoot() &&
                                                req.user.uid != parent.acl.uid && req.user.uid != file.acl.uid))
      return makeError(MetaCode::kNoPermission);
    return Void{};
  };
  CO_RETURN_ON_ERROR(permission(*srcParent, inode));
  if (replaced) CO_RETURN_ON_ERROR(permission(*dstParent, *replaced));
  const bool sourceEc = inode.isFile() && inode.asFile().layout.isErasureCoded();
  const bool targetEc = replaced && replaced->isFile() && replaced->asFile().layout.isErasureCoded();
  if (!sourceEc && !targetEc) co_return makeError(StatusCode::kInvalidArg, "typed rename requires a mode4 participant");
  if (inode.isFile() && !sourceEc) CO_RETURN_ON_ERROR(inode.asFile().layout.checkReplicated());
  RenameRecord record;
  record.intent = renameIntent(req);
  record.sourceId = inode.id;
  record.sourceParent = (**source).parent;
  record.sourceName = (**source).name;
  record.destinationParent = destinationParent;
  record.destinationName = destinationName;
  if (replaced) record.destinationId = replaced->id;
  // Typed preparation cannot enroll flat EC objects. It checks real live root,
  // lifecycle and original namespace registration before any directory mutation.
  const auto prepare = [&](const Inode &file) -> CoTryTask<EcTreeBirth> {
    const auto *d = file.asFile().layout.ecLayout();
    if (!d) co_return makeError(StatusCode::kDataCorruption);
    EcObjectRef o{file.id, d->incarnation};
    auto c = co_await EcFileTreeCatalog::open(txn, o);
    CO_RETURN_ON_ERROR(c);
    auto root = co_await EcFileTreeCatalog::getRoot(*c);
    CO_RETURN_ON_ERROR(root);
    if (root->visibleLength != file.asFile().length || d->shardBytes != c->birth().shardBytes)
      co_return makeError(StatusCode::kDataCorruption);
    auto l = co_await life(txn, c->birth(), file, true);
    CO_RETURN_ON_ERROR(l);
    if (l->state != EcFileLifeState::Linked) co_return makeError(StatusCode::kDataCorruption);
    CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::checkTreeFile(txn, file));
    CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileLifecycle, o), *l));
    co_return c->birth();
  };
  if (sourceEc) {
    auto b = co_await prepare(inode);
    CO_RETURN_ON_ERROR(b);
    record.sourceBirth = *b;
  }
  if (targetEc) {
    auto b = co_await prepare(*replaced);
    CO_RETURN_ON_ERROR(b);
    record.destinationBirth = *b;
  }
  const bool sameEntry = (**source).parent == destinationParent && (**source).name == destinationName;
  if (req.moveToTrash && replaced && !sameEntry) co_return makeError(MetaCode::kExists);
  // POSIX same-inode aliases are a successful no-op: preserve both links.
  if (!replaced || replaced->id != inode.id) {
    if (replaced) {
      if (targetEc) {
        auto l = co_await life(txn, *record.destinationBirth, *replaced, false);
        CO_RETURN_ON_ERROR(l);
        CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::adjustTreeLink(txn, *replaced, destinationParent, false));
        --replaced->nlink;
        --l->links;
        replaced->ctime = UtcClock::now();
        if (!replaced->nlink) {
          l->state = EcFileLifeState::Unlinked;
          l->lastUnlink = req.uuid;
        }
        CO_RETURN_ON_ERROR(co_await (**target).remove(txn));
        CO_RETURN_ON_ERROR(co_await replaced->store(txn));
        CO_RETURN_ON_ERROR(
            co_await store(txn, objectKey(KeyPrefix::EcFileLifecycle, record.destinationBirth->object), *l));
        CO_RETURN_ON_ERROR(co_await retireIfUnreferenced(txn, record.destinationBirth->object));
      } else if (replaced->isFile()) {
        CO_RETURN_ON_ERROR(replaced->asFile().layout.checkReplicated());
        CO_RETURN_ON_ERROR(co_await gc.removeEntry(txn, **target, *replaced, GcInfo{req.user.uid, (**target).name}));
      } else if (replaced->isSymlink()) {
        // Match existing Rename's cached-symlink policy (do not delete inode).
        --replaced->nlink;
        replaced->ctime = UtcClock::now();
        CO_RETURN_ON_ERROR(co_await replaced->store(txn));
        CO_RETURN_ON_ERROR(co_await (**target).remove(txn));
      } else
        co_return makeError(StatusCode::kInvalidArg);
    }
    if (sourceEc && (**source).parent != destinationParent) {
      CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::adjustTreeLink(txn, inode, (**source).parent, false));
      CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::adjustTreeLink(txn, inode, destinationParent, true));
    }
    CO_RETURN_ON_ERROR(co_await (**source).remove(txn));
    DirEntry moved(destinationParent, destinationName);
    moved.data() = (**source).data();
    moved.uuid = req.uuid;
    CO_RETURN_ON_ERROR(co_await moved.store(txn));
    inode.ctime = UtcClock::now();
    CO_RETURN_ON_ERROR(co_await inode.store(txn));
  }
  record.result = inode;
  CO_RETURN_ON_ERROR(co_await store(txn, renameKey(record.intent.owner, req.uuid), record));
  co_return RenameRsp(std::move(inode));
}
CoTryTask<std::optional<HardLinkRsp>> EcFileLifecycleCatalog::replay(Tx &txn, const HardLinkReq &req) {
  auto r = co_await replayRecord(txn, intent(req));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  co_return std::optional<HardLinkRsp>(HardLinkRsp((**r).result));
}
CoTryTask<std::optional<RemoveRsp>> EcFileLifecycleCatalog::replay(Tx &txn, const RemoveReq &req) {
  auto r = co_await replayRecord(txn, intent(req));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return std::nullopt;
  co_return std::optional<RemoveRsp>(RemoveRsp{});
}
CoTryTask<HardLinkRsp> EcFileLifecycleCatalog::link(Tx &txn,
                                                    const HardLinkReq &req,
                                                    InodeId source,
                                                    InodeId destinationParent,
                                                    const String &name) {
  const auto i = intent(req);
  CO_RETURN_ON_ERROR(validIntent(i));
  auto replayed = co_await replay(txn, req);
  CO_RETURN_ON_ERROR(replayed);
  if (*replayed) co_return std::move(**replayed);
  auto loaded = co_await Inode::load(txn, source);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded || !(**loaded).nlink) co_return makeError(MetaCode::kNotFound);
  auto inode = std::move(**loaded);
  if (!inode.isFile() || !inode.asFile().layout.ecLayout()) co_return makeError(StatusCode::kInvalidArg);
  EcObjectRef object{inode.id, inode.asFile().layout.ecLayout()->incarnation};
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->visibleLength != inode.asFile().length ||
      inode.asFile().layout.ecLayout()->shardBytes != context->birth().shardBytes)
    co_return makeError(StatusCode::kDataCorruption);
  auto state = co_await life(txn, context->birth(), inode, true);
  CO_RETURN_ON_ERROR(state);
  CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::checkTreeFile(txn, inode));
  if (state->state != EcFileLifeState::Linked || inode.nlink == std::numeric_limits<uint16_t>::max())
    co_return makeError(MetaCode::kNoPermission);
  if (inode.acl.iflags & FS_IMMUTABLE_FL) co_return makeError(MetaCode::kNoPermission);
  auto p = co_await writableParent(txn, destinationParent, req.user, req.client);
  CO_RETURN_ON_ERROR(p);
  auto exists = co_await DirEntry::load(txn, destinationParent, name);
  CO_RETURN_ON_ERROR(exists);
  if (*exists) co_return makeError(MetaCode::kExists);
  auto entry = DirEntry::newFile(destinationParent, name, inode.id);
  entry.uuid = req.uuid;
  CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::adjustTreeLink(txn, inode, destinationParent, true));
  ++inode.nlink;
  ++state->links;
  inode.ctime = UtcClock::now();
  CO_RETURN_ON_ERROR(co_await entry.store(txn));
  CO_RETURN_ON_ERROR(co_await inode.store(txn));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileLifecycle, object), *state));
  CO_RETURN_ON_ERROR(co_await persist(txn, i, context->birth(), destinationParent, name, inode));
  co_return HardLinkRsp(std::move(inode));
}
CoTryTask<RemoveRsp> EcFileLifecycleCatalog::unlink(Tx &txn, const RemoveReq &req, const DirEntry &resolved) {
  const auto i = intent(req);
  CO_RETURN_ON_ERROR(validIntent(i));
  auto replayed = co_await replay(txn, req);
  CO_RETURN_ON_ERROR(replayed);
  if (*replayed) co_return std::move(**replayed);
  auto entry = co_await DirEntry::load(txn, resolved.parent, resolved.name);
  CO_RETURN_ON_ERROR(entry);
  if (!*entry || (**entry).id != resolved.id) co_return makeError(MetaCode::kNotFound);
  if (req.inodeId && *req.inodeId != (**entry).id) co_return makeError(MetaCode::kNotFound);
  if (req.recursive || (req.checkType && req.atFlags.contains(AT_REMOVEDIR)))
    co_return makeError(MetaCode::kNotDirectory);
  auto found = co_await (**entry).loadInode(txn);
  CO_RETURN_ON_ERROR(found);
  auto inode = std::move(*found);
  if (!inode.isFile() || !inode.asFile().layout.ecLayout() || !inode.nlink) co_return makeError(MetaCode::kNotFound);
  EcObjectRef object{inode.id, inode.asFile().layout.ecLayout()->incarnation};
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  if (root->visibleLength != inode.asFile().length ||
      inode.asFile().layout.ecLayout()->shardBytes != context->birth().shardBytes)
    co_return makeError(StatusCode::kDataCorruption, "inode/tree length or layout differs");
  auto state = co_await life(txn, context->birth(), inode, true);
  CO_RETURN_ON_ERROR(state);
  if (state->state != EcFileLifeState::Linked) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::checkTreeFile(txn, inode));
  auto p = co_await writableParent(txn, (**entry).parent, req.user, req.client);
  CO_RETURN_ON_ERROR(p);
  if ((inode.acl.iflags & FS_IMMUTABLE_FL) ||
      ((p->acl.perm & S_ISVTX) && req.user.uid != p->acl.uid && !req.user.isRoot() && req.user.uid != inode.acl.uid))
    co_return makeError(MetaCode::kNoPermission);
  CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::adjustTreeLink(txn, inode, (**entry).parent, false));
  --inode.nlink;
  --state->links;
  inode.ctime = UtcClock::now();
  if (!inode.nlink) {
    state->state = EcFileLifeState::Unlinked;
    state->lastUnlink = req.uuid;
  }
  CO_RETURN_ON_ERROR(co_await (**entry).remove(txn));
  CO_RETURN_ON_ERROR(co_await inode.store(txn));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileLifecycle, object), *state));
  CO_RETURN_ON_ERROR(co_await persist(txn, i, context->birth(), (**entry).parent, (**entry).name, inode));
  CO_RETURN_ON_ERROR(co_await retireIfUnreferenced(txn, object));
  co_return RemoveRsp{};
}
CoTryTask<Void> EcFileLifecycleCatalog::requireUnlinkedSession(Tx &txn, const EcObjectRef &object) {
  auto b = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(b);
  auto inode = co_await exactInode(txn, object);
  CO_RETURN_ON_ERROR(inode);
  auto r = co_await life(txn, *b, *inode, false);
  CO_RETURN_ON_ERROR(r);
  auto s = co_await sessions(txn, *b);
  CO_RETURN_ON_ERROR(s);
  if (r->state != EcFileLifeState::Unlinked || inode->nlink || !s->openCount)
    co_return makeError(StatusCode::kTokenStale, "unlinked inode has no live session protection");
  co_return Void{};
}
CoTryTask<Void> EcFileLifecycleCatalog::retireIfUnreferenced(Tx &txn, const EcObjectRef &object) {
  auto b = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(b);
  auto inode = co_await exactInode(txn, object);
  CO_RETURN_ON_ERROR(inode);
  if (inode->nlink) co_return Void{};
  auto r = co_await life(txn, *b, *inode, false);
  CO_RETURN_ON_ERROR(r);
  auto s = co_await sessions(txn, *b);
  CO_RETURN_ON_ERROR(s);
  if (r->state == EcFileLifeState::Retired) {
    CO_RETURN_ON_ERROR(co_await historicalRoot(txn, object));
    co_return Void{};
  }
  if (s->openCount) co_return Void{};
  if (r->state != EcFileLifeState::Unlinked) co_return makeError(StatusCode::kDataCorruption);
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  auto detached = co_await EcFileTreeCatalog::detachForRetirement(*context);
  CO_RETURN_ON_ERROR(detached);
  r->retiredRoot = *root;
  r->state = EcFileLifeState::Retired;
  co_return co_await store(txn, objectKey(KeyPrefix::EcFileLifecycle, object), *r);
}
CoTryTask<EcTreeRoot> EcFileLifecycleCatalog::historicalRoot(Tx &txn, const EcObjectRef &object) {
  auto b = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(b);
  auto record = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(record);
  if (!record->deleting) {
    auto c = co_await EcFileTreeCatalog::open(txn, object);
    CO_RETURN_ON_ERROR(c);
    co_return co_await EcFileTreeCatalog::getRoot(*c);
  }
  auto inode = co_await exactInode(txn, object);
  CO_RETURN_ON_ERROR(inode);
  auto r = co_await life(txn, *b, *inode, false);
  CO_RETURN_ON_ERROR(r);
  auto s = co_await sessions(txn, *b);
  CO_RETURN_ON_ERROR(s);
  auto root = co_await require<EcTreeRoot>(txn, objectKey(KeyPrefix::EcTreeRoot, object));
  CO_RETURN_ON_ERROR(root);
  if (r->state != EcFileLifeState::Retired || !r->retiredRoot || s->openCount || !root->root.is_nil() ||
      root->object != object || root->birth != b->createRequest || root->epoch != record->epoch ||
      root->visibleLength != record->length || root->visibleLength != inode->asFile().length ||
      r->retiredRoot->object != object || r->retiredRoot->birth != b->createRequest || !r->retiredRoot->sequence ||
      !r->retiredRoot->epoch || r->retiredRoot->sequence == std::numeric_limits<uint64_t>::max() ||
      r->retiredRoot->epoch == std::numeric_limits<uint64_t>::max() || root->sequence != r->retiredRoot->sequence + 1 ||
      root->epoch != r->retiredRoot->epoch + 1 || root->visibleLength != r->retiredRoot->visibleLength)
    co_return makeError(StatusCode::kDataCorruption, "terminal lifecycle/root evidence differs");
  co_return root;
}
CoTryTask<EcTreeNodeRefs> EcFileLifecycleCatalog::reclaimRetiredNode(Tx &txn,
                                                                     const EcObjectRef &object,
                                                                     const Uuid &node) {
  CO_RETURN_ON_ERROR(co_await historicalRoot(txn, object));
  auto record = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(record);
  if (!record->deleting) co_return makeError(StatusCode::kTokenStale);
  co_return co_await EcFileTreeCatalog::reclaimRetired(txn, object, node);
}
}  // namespace hf3fs::meta::server
