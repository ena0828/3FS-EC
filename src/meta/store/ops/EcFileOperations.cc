#include "EcFileOperations.h"

#include "meta/store/EcCatalog.h"
#include "meta/store/EcCreateCatalog.h"
#include "meta/store/EcFileLifecycleCatalog.h"
#include "meta/store/EcFileSessionCatalog.h"
#include "meta/store/EcFileTreeTxnBudget.h"
#include "meta/store/EcNamespaceGuard.h"
#include "meta/store/Operation.h"

namespace hf3fs::meta::server {
namespace {
// PathResolveOp exposes snapshot reads for its read-only callers. Creation
// requires conflict reads in the same bounded transaction as the namespace
// mutation, so adapt only this resolver without relaxing the budget's ban.
class ConflictPathReads final : public kv::IReadOnlyTransaction {
 public:
  explicit ConflictPathReads(EcFileTreeTxnBudget &txn)
      : txn_(txn) {}
  void setReadVersion(int64_t version) override { txn_.setReadVersion(version); }
  CoTryTask<std::optional<String>> snapshotGet(std::string_view key) override { return txn_.get(key); }
  CoTryTask<std::optional<String>> get(std::string_view key) override { return txn_.get(key); }
  CoTryTask<GetRangeResult> snapshotGetRange(const KeySelector &begin, const KeySelector &end, int32_t limit) override {
    return txn_.getRange(begin, end, limit);
  }
  CoTryTask<GetRangeResult> getRange(const KeySelector &begin, const KeySelector &end, int32_t limit) override {
    return txn_.getRange(begin, end, limit);
  }
  CoTryTask<void> cancel() override { return txn_.cancel(); }
  void reset() override { txn_.reset(); }

 private:
  EcFileTreeTxnBudget &txn_;
};

class OpenEcFileSessionOp final : public Operation<OpenEcFileSessionRsp> {
 public:
  OpenEcFileSessionOp(MetaStore &meta, const OpenEcFileSessionReq &req)
      : Operation(meta),
        req_(req) {}
  std::string_view name() const override { return "openEcFileSession"; }
  flat::Uid user() const override { return req_.user.uid; }
  CoTryTask<OpenEcFileSessionRsp> run(kv::IReadWriteTransaction &raw) override {
    CO_RETURN_ON_ERROR(req_.valid());
    EcFileTreeTxnBudget txn(raw);
    EcOwner owner{req_.user.uid, req_.client.uuid};
    EcObjectRef ref = req_.object;
    Uuid birth = req_.birth;
    if (req_.createNew) {
      auto prior = co_await EcCreateCatalog::load(txn, req_);
      CO_RETURN_ON_ERROR(prior);
      if (*prior) {
        // Permanent identity wins over a pathname subsequently reused. A
        // previous mode-2/3 create is rejected by the typed W0 open below.
        ref = (**prior).result.object.object;
        birth = req_.uuid;
      } else {
        ConflictPathReads pathReads(txn);
        auto resolved = co_await resolve(pathReads, req_.user).path(req_.path, AtFlags(AT_SYMLINK_NOFOLLOW));
        CO_RETURN_ON_ERROR(resolved);
        auto parent = co_await Inode::load(txn, resolved->getParentId());
        CO_RETURN_ON_ERROR(parent);
        if (!*parent || !(**parent).nlink) co_return makeError(MetaCode::kNotFound);
        if (!(**parent).isDirectory()) co_return makeError(MetaCode::kNotDirectory);
        CO_RETURN_ON_ERROR((**parent).acl.checkPermission(req_.user, AccessType::WRITE));
        CO_RETURN_ON_ERROR((**parent).asDirectory().checkLock(req_.client));
        const auto name = req_.path.path->filename().native();
        auto existing = co_await DirEntry::load(txn, (**parent).id, name);
        CO_RETURN_ON_ERROR(existing);
        if (*existing) co_return makeError(MetaCode::kExists);
        if (!inodeId_) {
          auto id = co_await allocateInodeId(txn, false);
          CO_RETURN_ON_ERROR(id);
          inodeId_ = *id;
        } else {
          auto occupied = co_await Inode::load(txn, *inodeId_);
          CO_RETURN_ON_ERROR(occupied);
          if (*occupied) co_return makeError(StatusCode::kTokenDuplicated);
        }
        ref = {*inodeId_, incarnation_};
        birth = req_.uuid;
        EcManifestLayoutV1 descriptor;
        descriptor.incarnation = incarnation_;
        descriptor.shardBytes = req_.shardBytes;
        Layout layout;
        layout.chains = descriptor;
        Acl acl(req_.user.uid, req_.user.gid, Permission(req_.perm & ALLPERMS));
        if ((**parent).acl.perm & S_ISGID) acl.gid = (**parent).acl.gid;
        auto inode = Inode::newFile(*inodeId_, acl, std::move(layout), now());
        auto dentry = DirEntry::newFile((**parent).id, name, inode.id);
        dentry.uuid = req_.uuid;
        EcTreeBirth marker;
        marker.object = ref;
        marker.creator = owner;
        marker.createRequest = birth;
        marker.shardBytes = req_.shardBytes;
        marker.allowColocated = config().ec_allow_colocated_test_targets();
        auto root = co_await EcFileTreeCatalog::createBirth(txn, marker);
        CO_RETURN_ON_ERROR(root);
        CO_RETURN_ON_ERROR(co_await inode.store(txn));
        CO_RETURN_ON_ERROR(co_await dentry.store(txn));
        CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::registerFile(txn, inode, (**parent).id));
        auto object = co_await EcCatalog::getObject(txn, ref);
        CO_RETURN_ON_ERROR(object);
        CreateEcFileRsp created;
        created.inode = std::move(inode);
        created.object = std::move(*object);
        CO_RETURN_ON_ERROR(co_await EcCreateCatalog::store(txn, req_, (**parent).id, name, created));
      }
    }
    EcFileOpenIntent intent;
    intent.object = ref;
    intent.birth = birth;
    intent.owner = owner;
    intent.session = req_.session;
    intent.openRequest = req_.uuid;
    intent.rights = req_.rights;
    auto session = req_.createNew ? co_await EcFileSessionCatalog::open(txn, req_.user, intent)
                                  : co_await EcFileSessionCatalog::openExisting(txn, req_.user, req_);
    CO_RETURN_ON_ERROR(session);
    auto root = co_await EcFileLifecycleCatalog::historicalRoot(txn, ref);
    CO_RETURN_ON_ERROR(root);
    auto object = co_await EcCatalog::getObject(txn, ref);
    CO_RETURN_ON_ERROR(object);
    auto inode = co_await Inode::load(txn, ref.inode);
    CO_RETURN_ON_ERROR(inode);
    if (!*inode) co_return makeError(StatusCode::kDataCorruption);
    OpenEcFileSessionRsp rsp;
    rsp.session = std::move(*session);
    rsp.root = std::move(*root);
    rsp.object = std::move(*object);
    rsp.inode = std::move(**inode);
    co_return rsp;
  }

 private:
  const OpenEcFileSessionReq &req_;
  std::optional<InodeId> inodeId_;
  Uuid incarnation_ = Uuid::random();
};
}  // namespace
MetaStore::OpPtr<OpenEcFileSessionRsp> makeOpenEcFileSessionOp(MetaStore &meta, const OpenEcFileSessionReq &req) {
  return std::make_unique<OpenEcFileSessionOp>(meta, req);
}
}  // namespace hf3fs::meta::server
