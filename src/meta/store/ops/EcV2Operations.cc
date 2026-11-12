#include "meta/store/ops/EcV2Operations.h"

#include <algorithm>
#include <limits>

#include "fbs/meta/EcRequestDigest.h"
#include "meta/components/EcV2Coordinator.h"
#include "meta/store/EcCreateCatalog.h"
#include "meta/store/EcFileAccess.h"
#include "meta/store/EcNamespaceGuard.h"
#include "meta/store/EcV2PublishedCatalog.h"
#include "meta/store/EcV2RepairPlanCatalog.h"
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
  if (!config.enable_ec_catalog() || !config.enable_ec_v2())
    return makeError(StatusCode::kNotImplemented, "native EC catalog is disabled");
  if (!config.authenticate()) return makeError(StatusCode::kAuthenticationFail, "native EC requires authentication");
  return Void{};
}

class CreateEcFileV2Op : public Operation<CreateEcFileRsp> {
 public:
  CreateEcFileV2Op(MetaStore &meta, const CreateEcFileV2Req &req)
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
      auto current = co_await loadV2File(txn, req_.user, (**previous).result.object.object, AccessType::WRITE);
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
    auto object = co_await EcV2BindingCatalog::createTrackedV2Object(txn,
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
  const CreateEcFileV2Req &req_;
  std::optional<InodeId> inodeId_;
  Uuid incarnation_ = Uuid::random();
};

EcV2DrainProgress progress(const EcV2DrainRecord &record) {
  EcV2DrainProgress value;
  value.state = record.state;
  value.revocation = record.identity.revocationId;
  value.expectedEndpoints = record.identity.endpoints.count;
  for (size_t i = 0; i != record.identity.endpoints.count; ++i)
    value.acknowledgedEndpoints += record.observations[i].has_value();
  return value;
}
class EcV2PhaseOp : public Operation<EcV2PhaseRsp> {
 public:
  EcV2PhaseOp(MetaStore &meta, const EcV2PhaseRequest &req)
      : Operation(meta),
        req_(req) {}
  std::string_view name() const override { return "ecV2Lifecycle"; }
  flat::Uid user() const override { return req_.user.uid; }
  bool isReadOnly() override { return req_.phase == EcV2Phase::Get; }
  CoTryTask<EcV2PhaseRsp> run(IReadWriteTransaction &txn) override {
    CO_RETURN_ON_ERROR(req_.valid());
    CO_RETURN_ON_ERROR(checkConfiguration(config()));
    if (!req_.coordinator) co_return makeError(StatusCode::kInvalidArg, "V2 coordinator absent");
    const auto owner = ownerOf(req_);
    std::optional<EcV2RepairPlanRecord> repairPlan;
    CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, req_.object));
    if (req_.phase == EcV2Phase::RecordAck) {
      if (!req_.observation) co_return makeError(StatusCode::kInvalidArg);
      // The evidence has a private verifier-only constructor. Check the
      // authenticated caller against the exact durable scope before storing it.
      auto old = co_await EcV2DrainCatalog::get(txn, req_.object, req_.scopeKind, req_.operation, owner);
      CO_RETURN_ON_ERROR(old);
      if (!*old) co_return makeError(StatusCode::kTokenStale);
      auto record = co_await EcV2DrainCatalog::recordAck(txn, *req_.observation);
      CO_RETURN_ON_ERROR(record);
      if (record->identity.object != req_.object || record->identity.kind != req_.scopeKind ||
          record->identity.scopeId != req_.operation)
        co_return makeError(StatusCode::kTokenMismatch);
      CO_RETURN_ON_ERROR(checkOwner(req_, record->identity.owner));
      EcV2PhaseRsp rsp;
      rsp.drain = std::move(*record);
      co_return rsp;
    }
    if (req_.scopeKind == storage::EcGrantScope::ReadPin) {
      co_return co_await readPhase(txn, owner);
    }
    std::optional<LoadedEcFile> file;
    const bool cleanup = req_.phase == EcV2Phase::StartCancel || req_.phase == EcV2Phase::FinishCancel;
    if (!cleanup) {
      auto loaded = co_await loadV2File(txn,
                                        req_.user,
                                        req_.object,
                                        req_.phase == EcV2Phase::Get ? AccessType::READ : AccessType::WRITE);
      CO_RETURN_ON_ERROR(loaded);
      file = std::move(*loaded);
    }
    if (req_.phase == EcV2Phase::Begin) {
      CO_RETURN_ON_ERROR(req_.begin.valid());
      const auto &b = req_.begin;
      EcMutationIntent intent;
      intent.object = req_.object;
      intent.operation = req_.operation;
      intent.stripe = b.stripe;
      intent.expectedEpoch = b.expectedEpoch;
      intent.expectedRevision = b.expectedRevision;
      intent.logicalLength = b.logicalLength;
      intent.kind = b.kind;
      intent.replacementMask = b.replacementMask;
      intent.fragmentCrc32c = b.fragmentCrc32c;
      auto digest = computeEcRequestDigest(intent, file->object.shardBytes, b.contentSha256);
      CO_RETURN_ON_ERROR(digest);
      intent.requestDigest = *digest;
      auto previous = co_await EcCatalog::getOperation(txn, req_.object, req_.operation);
      if (previous) {
        CO_RETURN_ON_ERROR(checkOwner(req_, previous->owner));
        intent.placements = previous->intent.placements;
        if (!serde::equals(intent, previous->intent))
          co_return makeError(StatusCode::kTokenMismatch, "V2 Begin retry changed its logical commitment");
      } else {
        if (previous.error().code() != StatusCode::kKVStoreNotFound) co_return makeError(previous.error());
        auto pool = req_.coordinator->pool(b.replacementMask);
        CO_RETURN_ON_ERROR(pool);
        for (size_t i = 0; i != 12; ++i) intent.placements[i] = (*pool)[i].placement;
        const uint64_t stripeBytes = uint64_t(file->object.shardBytes) * 10;
        if (b.stripe > std::numeric_limits<uint64_t>::max() / stripeBytes)
          co_return makeError(StatusCode::kInvalidArg, "V2 stripe offset overflows");
        const auto offset = b.stripe * stripeBytes;
        if (b.kind == EcMutationKind::Write) {
          const bool append = !b.expectedRevision && offset == file->object.length && offset % stripeBytes == 0;
          const bool replace = b.expectedRevision && offset < file->object.length &&
                               b.logicalLength == std::min(stripeBytes, file->object.length - offset);
          if (!append && !replace)
            co_return makeError(StatusCode::kNotImplemented,
                                "V2 supports contiguous full-stripe append or same-length replacement");
        } else {
          auto content = co_await EcV2PublishedCatalog::get(txn, req_.object, b.stripe, b.expectedRevision);
          CO_RETURN_ON_ERROR(content);
          if (content->contentSha256 != b.contentSha256 || content->logicalLength != b.logicalLength)
            co_return makeError(StatusCode::kTokenMismatch, "V2 repair must retain the published logical SHA");
          auto base = co_await EcCatalog::getManifest(txn, req_.object, b.stripe, b.expectedRevision);
          CO_RETURN_ON_ERROR(base);
          for (size_t i = 0; i != 12; ++i) {
            if (base->manifest.fragments[i].integrity.wholeCrc32c != b.fragmentCrc32c[i])
              co_return makeError(StatusCode::kTokenMismatch, "V2 repair CRC differs from published content");
            if (!(b.replacementMask & (1u << i))) intent.placements[i] = base->manifest.fragments[i].placement;
          }
        }
        auto begun = co_await EcCatalog::begin(txn, intent, owner);
        CO_RETURN_ON_ERROR(begun);
        CO_RETURN_ON_ERROR(co_await EcV2ReservationCatalog::reserve(txn, *begun, owner, b.contentSha256, *pool));
      }
    } else {
      auto current = co_await EcCatalog::getOperation(txn, req_.object, req_.operation);
      CO_RETURN_ON_ERROR(current);
      CO_RETURN_ON_ERROR(checkOwner(req_, current->owner));
      switch (req_.phase) {
        case EcV2Phase::PrepareRepair: {
          if (current->state != EcOperationState::Preparing || current->intent.kind != EcMutationKind::Repair ||
              current->intent.expectedEpoch != file->object.epoch)
            co_return makeError(StatusCode::kTokenStale, "V2 repair plan requires the current Preparing epoch");
          auto plan =
              co_await EcV2RepairPlanCatalog::prepare(txn, req_.object, req_.operation, owner, req_.repairSelection);
          CO_RETURN_ON_ERROR(plan);
          repairPlan = std::move(*plan);
          break;
        }
        case EcV2Phase::Bind:
          CO_RETURN_ON_ERROR(
              co_await EcV2ReservationCatalog::bind(txn, req_.object, req_.operation, owner, req_.descriptors));
          break;
        case EcV2Phase::PreparePublish: {
          auto closing = co_await EcV2DrainCatalog::get(txn,
                                                        req_.object,
                                                        storage::EcGrantScope::WriteOperation,
                                                        req_.operation,
                                                        owner);
          CO_RETURN_ON_ERROR(closing);
          if (!*closing) {
            CO_RETURN_ON_ERROR(co_await EcV2ReservationCatalog::checkIssuanceOpen(txn,
                                                                                  req_.object,
                                                                                  storage::EcGrantScope::WriteOperation,
                                                                                  req_.operation,
                                                                                  owner));
          } else if (!(**closing).verifiedManifest || (**closing).state == EcV2DrainState::Aborted) {
            co_return makeError(StatusCode::kTokenStale, "V2 scope closed without a publication proof");
          }
          break;
        }
        case EcV2Phase::StartPublish:
          if (!req_.publication) co_return makeError(StatusCode::kInvalidArg);
          if (req_.publication->operation().intent.object != req_.object ||
              req_.publication->operation().intent.operation != req_.operation)
            co_return makeError(StatusCode::kTokenMismatch);
          CO_RETURN_ON_ERROR(co_await EcV2DrainCatalog::startPublish(txn,
                                                                     *req_.publication,
                                                                     owner,
                                                                     req_.coordinator->authority(),
                                                                     req_.revocation));
          break;
        case EcV2Phase::StartCancel:
          CO_RETURN_ON_ERROR(co_await EcV2DrainCatalog::startCancel(txn,
                                                                    req_.object,
                                                                    req_.operation,
                                                                    owner,
                                                                    req_.coordinator->authority(),
                                                                    req_.revocation));
          break;
        case EcV2Phase::FinishCancel:
          CO_RETURN_ON_ERROR(co_await EcV2DrainCatalog::finishCancel(txn,
                                                                     req_.object,
                                                                     req_.operation,
                                                                     owner,
                                                                     req_.coordinator->controlKey()));
          break;
        case EcV2Phase::FinishPublish: {
          const bool changed = current->state != EcOperationState::Published;
          auto published = co_await EcV2DrainCatalog::finishPublish(txn,
                                                                    req_.object,
                                                                    req_.operation,
                                                                    owner,
                                                                    req_.coordinator->controlKey());
          CO_RETURN_ON_ERROR(published);
          CO_RETURN_ON_ERROR(co_await EcV2PublishedCatalog::record(txn, req_.object, req_.operation, owner));
          if (changed) {
            auto object = co_await EcCatalog::getObject(txn, req_.object);
            CO_RETURN_ON_ERROR(object);
            file->inode.asFile().length = object->length;
            if (published->intent.kind == EcMutationKind::Write) {
              constexpr uint32_t special = S_ISUID | S_ISGID | S_ISVTX;
              if (req_.user.uid != file->inode.acl.uid)
                file->inode.acl.perm = Permission(file->inode.acl.perm & ~special);
              file->inode.mtime = now();
              file->inode.ctime = now();
            }
            CO_RETURN_ON_ERROR(co_await file->inode.store(txn));
          }
          break;
        }
        case EcV2Phase::Get:
          break;
        default:
          co_return makeError(StatusCode::kInvalidArg, "invalid V2 operation phase");
      }
    }
    auto result = co_await mutationResult(txn, owner);
    CO_RETURN_ON_ERROR(result);
    result->repair = std::move(repairPlan);
    co_return result;
  }

 private:
  CoTryTask<EcV2PhaseRsp> mutationResult(IReadWriteTransaction &txn, const EcOwner &owner) {
    EcV2PhaseRsp rsp;
    auto record = co_await EcCatalog::getOperation(txn, req_.object, req_.operation);
    CO_RETURN_ON_ERROR(record);
    CO_RETURN_ON_ERROR(checkOwner(req_, record->owner));
    rsp.mutation.record = std::move(*record);
    auto object = co_await EcCatalog::getObject(txn, req_.object);
    CO_RETURN_ON_ERROR(object);
    rsp.mutation.object = std::move(*object);
    auto reservation = co_await EcV2ReservationCatalog::get(txn, req_.object, req_.operation, owner);
    CO_RETURN_ON_ERROR(reservation);
    rsp.mutation.reservation = std::move(*reservation);
    auto binding = co_await EcV2BindingCatalog::getOperationBinding(txn, req_.object, req_.operation, owner);
    if (binding)
      rsp.mutation.allocations = std::move(binding->allocations);
    else if (binding.error().code() != StatusCode::kNotImplemented)
      co_return makeError(binding.error());
    auto drain =
        co_await EcV2DrainCatalog::get(txn, req_.object, storage::EcGrantScope::WriteOperation, req_.operation, owner);
    CO_RETURN_ON_ERROR(drain);
    rsp.drain = std::move(*drain);
    if (rsp.drain) rsp.mutation.drain = progress(*rsp.drain);
    co_return rsp;
  }
  CoTryTask<EcV2PhaseRsp> readPhase(IReadWriteTransaction &txn, const EcOwner &owner) {
    EcV2PhaseRsp rsp;
    if (req_.phase == EcV2Phase::AcquireRead) {
      auto file = co_await loadV2File(txn, req_.user, req_.object, AccessType::READ);
      CO_RETURN_ON_ERROR(file);
      auto pinned = co_await EcV2BindingCatalog::acquireRead(txn, req_.object, req_.stripe, req_.operation, owner);
      CO_RETURN_ON_ERROR(pinned);
      auto content =
          co_await EcV2PublishedCatalog::get(txn, req_.object, pinned->snapshot.stripe, pinned->snapshot.revision);
      CO_RETURN_ON_ERROR(content);
      CO_RETURN_ON_ERROR(co_await EcV2ReservationCatalog::checkIssuanceOpen(txn,
                                                                            req_.object,
                                                                            storage::EcGrantScope::ReadPin,
                                                                            req_.operation,
                                                                            owner));
      AcquireEcReadV2Rsp read;
      read.manifest = std::move(pinned->manifest);
      read.snapshot = std::move(pinned->snapshot);
      read.contentSha256 = content->contentSha256;
      rsp.read = std::move(read);
    } else if (req_.phase == EcV2Phase::StartRelease) {
      auto original = co_await EcCatalog::getPin(txn, req_.object, req_.operation);
      CO_RETURN_ON_ERROR(original);
      CO_RETURN_ON_ERROR(checkOwner(req_, original->owner));
      if (original->stripe != req_.stripe) co_return makeError(StatusCode::kTokenMismatch);
      auto started = co_await EcV2DrainCatalog::startRead(txn,
                                                          req_.object,
                                                          req_.operation,
                                                          owner,
                                                          req_.coordinator->authority(),
                                                          req_.revocation);
      CO_RETURN_ON_ERROR(started);
      rsp.drain = std::move(*started);
    } else if (req_.phase == EcV2Phase::FinishRelease) {
      auto released = co_await EcV2DrainCatalog::finishRead(txn,
                                                            req_.object,
                                                            req_.operation,
                                                            owner,
                                                            req_.coordinator->controlKey());
      CO_RETURN_ON_ERROR(released);
      if (released->stripe != req_.stripe) co_return makeError(StatusCode::kTokenMismatch);
      auto drain =
          co_await EcV2DrainCatalog::get(txn, req_.object, storage::EcGrantScope::ReadPin, req_.operation, owner);
      CO_RETURN_ON_ERROR(drain);
      rsp.drain = std::move(*drain);
    } else
      co_return makeError(StatusCode::kInvalidArg, "invalid V2 read lifecycle phase");
    co_return rsp;
  }
  const EcV2PhaseRequest &req_;
};
}  // namespace
MetaStore::OpPtr<CreateEcFileRsp> makeCreateEcV2Op(MetaStore &meta, const CreateEcFileV2Req &req) {
  return std::make_unique<CreateEcFileV2Op>(meta, req);
}
MetaStore::OpPtr<EcV2PhaseRsp> makeEcV2PhaseOp(MetaStore &meta, const EcV2PhaseRequest &req) {
  return std::make_unique<EcV2PhaseOp>(meta, req);
}
}  // namespace hf3fs::meta::server
