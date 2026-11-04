#include "meta/store/ops/EcOperations.h"

#include <algorithm>
#include <limits>

#include "fbs/meta/EcRequestDigest.h"
#include "meta/components/EcCoordinator.h"
#include "meta/store/EcCreateCatalog.h"
#include "meta/store/EcNamespaceGuard.h"
#include "meta/store/EcV2BindingCatalog.h"
#include "meta/store/Operation.h"

namespace hf3fs::meta::server {
namespace {
EcOwner ownerOf(const ReqBase &req) {
  EcOwner owner;
  owner.uid = req.user.uid;
  owner.client = req.client.uuid;
  return owner;
}

Result<Void> checkOwner(const ReqBase &req, const EcOwner &owner) {
  if (owner.client.is_nil() || !serde::equals(owner, ownerOf(req))) {
    return makeError(MetaCode::kNoPermission, "EC operation or pin belongs to another user or request namespace");
  }
  return Void{};
}

Result<Void> checkConfiguration(const Config &config) {
  if (!config.enable_ec_catalog()) return makeError(StatusCode::kNotImplemented, "native EC catalog is disabled");
  if (!config.authenticate()) return makeError(StatusCode::kAuthenticationFail, "native EC requires authentication");
  return Void{};
}

struct LoadedEcFile {
  Inode inode;
  EcObjectRecord object;
};

CoTryTask<LoadedEcFile> loadEcFile(IReadWriteTransaction &txn,
                                   const UserInfo &user,
                                   const EcObjectRef &object,
                                   std::optional<AccessType> access) {
  auto v2 = co_await EcV2BindingCatalog::getObjectMode(txn, object);
  CO_RETURN_ON_ERROR(v2);
  if (*v2) co_return makeError(StatusCode::kNotImplemented, "V2 object requires V2 lifecycle methods");
  auto loaded = co_await Inode::load(txn, object.inode);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded || !(**loaded).nlink) co_return makeError(MetaCode::kNotFound, "EC inode is absent or unlinked");
  auto inode = std::move(**loaded);
  if (!inode.isFile()) co_return makeError(MetaCode::kNotFile);
  const auto *layout = inode.asFile().layout.ecLayout();
  if (!layout || layout->incarnation != object.incarnation) {
    co_return makeError(StatusCode::kTokenMismatch, "EC inode incarnation differs from the request");
  }
  CO_RETURN_ON_ERROR(layout->valid());
  if (access) {
    if (*access != AccessType::READ && (inode.acl.iflags & FS_IMMUTABLE_FL)) {
      co_return makeError(MetaCode::kNoPermission, "EC inode is immutable");
    }
    CO_RETURN_ON_ERROR(inode.acl.checkPermission(user, *access));
  }
  auto catalog = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(catalog);
  if (catalog->shardBytes != layout->shardBytes || catalog->length != inode.asFile().length) {
    co_return makeError(StatusCode::kDataCorruption, "EC catalog and inode metadata disagree");
  }
  if (catalog->deleting) co_return makeError(StatusCode::kTokenStale, "EC object is deleting");
  co_return LoadedEcFile{std::move(inode), std::move(*catalog)};
}

class CreateEcFileOp : public Operation<CreateEcFileRsp> {
 public:
  CreateEcFileOp(MetaStore &meta, const CreateEcFileReq &req)
      : Operation(meta),
        req_(req) {}
  OPERATION_TAGS(req_);

  CoTryTask<CreateEcFileRsp> run(IReadWriteTransaction &txn) override {
    CHECK_REQUEST(req_);
    CO_RETURN_ON_ERROR(checkConfiguration(config()));
    auto previous = co_await EcCreateCatalog::load(txn, req_);
    CO_RETURN_ON_ERROR(previous);
    if (*previous) {
      // Recheck the original object's liveness and current permission without
      // resolving a pathname which may now refer to a different directory.
      auto current = co_await loadEcFile(txn, req_.user, (**previous).result.object.object, AccessType::WRITE);
      CO_RETURN_ON_ERROR(current);
      co_return (**previous).result;
    }
    auto resolved = co_await resolve(txn, req_.user).path(req_.path, AtFlags(AT_SYMLINK_NOFOLLOW));
    CO_RETURN_ON_ERROR(resolved);
    auto parent = co_await Inode::load(txn, resolved->getParentId());
    CO_RETURN_ON_ERROR(parent);
    if (!*parent || !(**parent).nlink) co_return makeError(MetaCode::kNotFound);
    if (!(**parent).isDirectory()) co_return makeError(MetaCode::kNotDirectory);
    CO_RETURN_ON_ERROR((**parent).acl.checkPermission(req_.user, AccessType::WRITE));
    CO_RETURN_ON_ERROR((**parent).asDirectory().checkLock(req_.client));
    const auto name = req_.path.path->filename().native();
    auto entry = co_await DirEntry::load(txn, (**parent).id, name);
    CO_RETURN_ON_ERROR(entry);
    if (*entry) co_return makeError(MetaCode::kExists);
    if (!inodeId_) {
      auto allocated = co_await allocateInodeId(txn, false);
      CO_RETURN_ON_ERROR(allocated);
      inodeId_ = *allocated;
    } else {
      auto occupied = co_await Inode::load(txn, *inodeId_);
      CO_RETURN_ON_ERROR(occupied);
      if (*occupied) co_return makeError(StatusCode::kTokenDuplicated, "EC inode allocation is already occupied");
    }
    EcManifestLayoutV1 descriptor;
    descriptor.incarnation = incarnation_;
    descriptor.shardBytes = req_.shardBytes;
    Layout layout;
    layout.chains = descriptor;
    Acl acl(req_.user.uid, req_.user.gid, Permission(req_.perm & ALLPERMS));
    if ((**parent).acl.perm & S_ISGID) acl.gid = (**parent).acl.gid;
    auto inode = Inode::newFile(*inodeId_, acl, std::move(layout), now());
    auto newEntry = DirEntry::newFile((**parent).id, name, inode.id);
    newEntry.uuid = req_.uuid;
    EcObjectRef ref;
    ref.inode = inode.id;
    ref.incarnation = incarnation_;
    auto object = co_await EcCatalog::createObject(txn,
                                                   ref,
                                                   req_.shardBytes,
                                                   config().ec_allow_colocated_test_targets(),
                                                   ownerOf(req_),
                                                   req_.uuid);
    CO_RETURN_ON_ERROR(object);
    CO_RETURN_ON_ERROR(co_await inode.store(txn));
    CO_RETURN_ON_ERROR(co_await newEntry.store(txn));
    CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::registerFile(txn, inode, (**parent).id));
    CreateEcFileRsp rsp;
    rsp.inode = std::move(inode);
    rsp.object = std::move(*object);
    CO_RETURN_ON_ERROR(co_await EcCreateCatalog::store(txn, req_, (**parent).id, name, rsp));
    co_return rsp;
  }

 private:
  const CreateEcFileReq &req_;
  std::optional<InodeId> inodeId_;
  Uuid incarnation_ = Uuid::random();
};

template <typename Req>
class EcMutationOp : public Operation<EcOperationRsp> {
 public:
  EcMutationOp(MetaStore &meta, const Req &req)
      : Operation(meta),
        req_(req) {}
  OPERATION_TAGS(req_);
  bool isReadOnly() override {
    return std::is_same_v<Req, GetEcOperationReq> || std::is_same_v<Req, PublishEcMutationReq>;
  }

  CoTryTask<EcOperationRsp> run(IReadWriteTransaction &txn) override {
    CHECK_REQUEST(req_);
    CO_RETURN_ON_ERROR(checkConfiguration(config()));
    constexpr auto access = std::is_same_v<Req, GetEcOperationReq> ? AccessType::READ : AccessType::WRITE;
    auto file = co_await loadEcFile(txn, req_.user, req_.object, access);
    CO_RETURN_ON_ERROR(file);
    if constexpr (std::is_same_v<Req, EcBeginContext>) {
      EcMutationIntent intent;
      intent.object = req_.object;
      intent.operation = req_.operation;
      intent.stripe = req_.stripe;
      intent.expectedEpoch = req_.expectedEpoch;
      intent.expectedRevision = req_.expectedRevision;
      intent.logicalLength = req_.logicalLength;
      intent.kind = req_.kind;
      intent.replacementMask = req_.replacementMask;
      intent.fragmentCrc32c = req_.fragmentCrc32c;
      auto digest = computeEcRequestDigest(intent, file->object.shardBytes, req_.contentSha256);
      CO_RETURN_ON_ERROR(digest);
      intent.requestDigest = *digest;
      auto previous = co_await EcCatalog::getOperation(txn, req_.object, req_.operation);
      if (previous) {
        CO_RETURN_ON_ERROR(checkOwner(req_, previous->owner));
        intent.placements = previous->intent.placements;
        if (!serde::equals(intent, previous->intent)) {
          co_return makeError(StatusCode::kTokenMismatch, "EC operation UUID reused for different logical content");
        }
        EcOperationRsp rsp;
        rsp.record = std::move(*previous);
        rsp.object = file->object;
        co_return rsp;
      }
      if (previous.error().code() != StatusCode::kKVStoreNotFound) co_return makeError(previous.error());
      if (!req_.coordinator) co_return makeError(StatusCode::kInvalidArg, "EC placement coordinator is absent");
      auto placements = req_.coordinator->placements();
      CO_RETURN_ON_ERROR(placements);
      intent.placements = std::move(*placements);
      const uint64_t stripeBytes = uint64_t(file->object.shardBytes) * 10;
      if (req_.stripe > std::numeric_limits<uint64_t>::max() / stripeBytes) {
        co_return makeError(StatusCode::kInvalidArg, "EC file offset overflows");
      }
      const auto offset = req_.stripe * stripeBytes;
      if (req_.kind == EcMutationKind::Write) {
        const bool append = req_.expectedRevision == 0 && offset == file->object.length && offset % stripeBytes == 0;
        const bool replace = req_.expectedRevision != 0 && offset < file->object.length &&
                             req_.logicalLength == std::min(stripeBytes, file->object.length - offset);
        if (!append && !replace) {
          co_return makeError(StatusCode::kNotImplemented,
                              "EC stripe API supports contiguous append or same-length replacement");
        }
      }
      auto begun = co_await EcCatalog::begin(txn, intent, ownerOf(req_));
      CO_RETURN_ON_ERROR(begun);
      if (intent.kind == EcMutationKind::Repair) {
        for (size_t i = 0; i != 12; ++i) {
          if (begun->candidate.fragments[i].integrity.wholeCrc32c != intent.fragmentCrc32c[i]) {
            co_return makeError(StatusCode::kTokenMismatch, "EC repair CRC differs from the published base");
          }
        }
      }
      auto object = co_await EcCatalog::getObject(txn, req_.object);
      CO_RETURN_ON_ERROR(object);
      EcOperationRsp rsp;
      rsp.record = std::move(*begun);
      rsp.object = std::move(*object);
      co_return rsp;
    } else {
      auto record = co_await EcCatalog::getOperation(txn, req_.object, req_.operation);
      CO_RETURN_ON_ERROR(record);
      CO_RETURN_ON_ERROR(checkOwner(req_, record->owner));
      if constexpr (std::is_same_v<Req, CancelEcMutationReq>) {
        record = co_await EcCatalog::cancel(txn, req_.object, req_.operation);
        CO_RETURN_ON_ERROR(record);
      } else if constexpr (std::is_same_v<Req, EcPublishCommit>) {
        if (!req_.evidence) co_return makeError(StatusCode::kInvalidArg, "EC publication evidence is absent");
        if (record->state != EcOperationState::Published) {
          if (!serde::equals(*record, req_.evidence->snapshot())) {
            co_return makeError(StatusCode::kTokenStale, "EC operation changed while storage was verified");
          }
          record = co_await EcCatalog::publish(txn, req_.object, req_.operation, req_.evidence->verified());
          CO_RETURN_ON_ERROR(record);
          auto object = co_await EcCatalog::getObject(txn, req_.object);
          CO_RETURN_ON_ERROR(object);
          file->object = std::move(*object);
          file->inode.asFile().length = file->object.length;
          if (record->intent.kind == EcMutationKind::Write) {
            // Match ordinary write-open semantics. A physical repair does not
            // change file contents and must not alter these permission bits.
            constexpr uint32_t special = S_ISUID | S_ISGID | S_ISVTX;
            if (req_.user.uid != file->inode.acl.uid && (file->inode.acl.perm & special)) {
              file->inode.acl.perm = Permission(file->inode.acl.perm & ~special);
            }
            file->inode.mtime = now();
            file->inode.ctime = now();
          }
          CO_RETURN_ON_ERROR(co_await file->inode.store(txn));
        }
      }
      EcOperationRsp rsp;
      rsp.record = std::move(*record);
      rsp.object = std::move(file->object);
      co_return rsp;
    }
  }

 private:
  const Req &req_;
};

template <typename Req, typename Rsp>
class EcReadPinOp : public Operation<Rsp> {
 public:
  EcReadPinOp(MetaStore &meta, const Req &req)
      : Operation<Rsp>(meta),
        req_(req) {}
  OPERATION_TAGS(req_);
  bool isReadOnly() override { return std::is_same_v<Req, ReleaseEcReadReq>; }
  CoTryTask<Rsp> run(IReadWriteTransaction &txn) override {
    CHECK_REQUEST(req_);
    CO_RETURN_ON_ERROR(checkConfiguration(this->config()));
    if constexpr (std::is_same_v<Req, ReleaseEcReadReq>) {
      // The owner may release after ACL revocation, but never force release of
      // live storage reads. No wire field can manufacture drain evidence.
      auto v2 = co_await EcV2BindingCatalog::getObjectMode(txn, req_.object);
      CO_RETURN_ON_ERROR(v2);
      if (*v2) co_return makeError(StatusCode::kNotImplemented, "V2 pin requires the V2 drain lifecycle");
      auto pin = co_await EcCatalog::getPin(txn, req_.object, req_.pin);
      CO_RETURN_ON_ERROR(pin);
      CO_RETURN_ON_ERROR(checkOwner(req_, pin->owner));
      if (!pin->released) {
        co_return makeError(StatusCode::kNotImplemented, "live EC pin requires storage read-drain evidence");
      }
      co_return Rsp{};
    } else {
      auto file = co_await loadEcFile(txn, req_.user, req_.object, AccessType::READ);
      CO_RETURN_ON_ERROR(file);
      auto manifest = co_await EcCatalog::acquireRead(txn, req_.object, req_.stripe, req_.pin, ownerOf(req_));
      CO_RETURN_ON_ERROR(manifest);
      Rsp rsp;
      rsp.manifest = std::move(*manifest);
      rsp.pin = req_.pin;
      co_return rsp;
    }
  }

 private:
  const Req &req_;
};
}  // namespace

MetaStore::OpPtr<CreateEcFileRsp> MetaStore::createEcFile(const CreateEcFileReq &req) {
  return std::make_unique<CreateEcFileOp>(*this, req);
}
MetaStore::OpPtr<EcOperationRsp> MetaStore::beginEcMutation(const EcBeginContext &req) {
  return std::make_unique<EcMutationOp<EcBeginContext>>(*this, req);
}
MetaStore::OpPtr<EcOperationRsp> MetaStore::prepareEcPublish(const PublishEcMutationReq &req) {
  return std::make_unique<EcMutationOp<PublishEcMutationReq>>(*this, req);
}
MetaStore::OpPtr<EcOperationRsp> MetaStore::publishEcMutation(const EcPublishCommit &req) {
  return std::make_unique<EcMutationOp<EcPublishCommit>>(*this, req);
}
MetaStore::OpPtr<EcOperationRsp> MetaStore::getEcOperation(const GetEcOperationReq &req) {
  return std::make_unique<EcMutationOp<GetEcOperationReq>>(*this, req);
}
MetaStore::OpPtr<EcOperationRsp> MetaStore::cancelEcMutation(const CancelEcMutationReq &req) {
  return std::make_unique<EcMutationOp<CancelEcMutationReq>>(*this, req);
}
MetaStore::OpPtr<AcquireEcReadRsp> MetaStore::acquireEcRead(const AcquireEcReadReq &req) {
  return std::make_unique<EcReadPinOp<AcquireEcReadReq, AcquireEcReadRsp>>(*this, req);
}
MetaStore::OpPtr<ReleaseEcReadRsp> MetaStore::releaseEcRead(const ReleaseEcReadReq &req) {
  return std::make_unique<EcReadPinOp<ReleaseEcReadReq, ReleaseEcReadRsp>>(*this, req);
}
}  // namespace hf3fs::meta::server
