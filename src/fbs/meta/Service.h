#pragma once

#include <fcntl.h>
#include <folly/logging/xlog.h>
#include <functional>
#include <optional>
#include <sys/stat.h>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/app/ClientId.h"
#include "common/app/NodeId.h"
#include "common/serde/Serde.h"
#include "common/serde/Service.h"
#include "common/utils/Result.h"
#include "common/utils/Status.h"
#include "common/utils/StrongType.h"
#include "common/utils/Uuid.h"
#include "fbs/core/user/User.h"
#include "fbs/meta/Common.h"
#include "fbs/meta/Ec.h"
#include "fbs/meta/EcFileAppend.h"
#include "fbs/meta/EcFileRange.h"
#include "fbs/meta/EcFileRepairRpc.h"
#include "fbs/meta/EcFileRpc.h"
#include "fbs/meta/EcFileTreeRead.h"
#include "fbs/meta/EcFileTruncateRpc.h"
#include "fbs/meta/EcRmw.h"
#include "fbs/meta/EcTreeGc.h"
#include "fbs/meta/EcTargetRetirement.h"
#include "fbs/meta/EcV2Grants.h"
#include "fbs/meta/EcV2Repair.h"
#include "fbs/meta/Schema.h"
#include "fbs/mgmtd/MgmtdTypes.h"

#define META_SERVICE_VERSION 1

#define CHECK_SESSION(session)             \
  do {                                     \
    if (!session.has_value()) {            \
      return INVALID(#session " not set"); \
    }                                      \
    if (!session->valid()) {               \
      return INVALID(#session " invalid"); \
    }                                      \
  } while (0)

namespace hf3fs::meta {

struct ReqBase {
  SERDE_STRUCT_FIELD(user, UserInfo{});
  SERDE_STRUCT_FIELD(client, ClientId{Uuid::zero()});
  SERDE_STRUCT_FIELD(forward, flat::NodeId(0));
  SERDE_STRUCT_FIELD(uuid, Uuid::zero());

 public:
  // set client id in unittest
  static std::optional<ClientId> &currentClientId() {
    static std::optional<ClientId> clientId;
    return clientId;
  }

  ReqBase(UserInfo user = {}, Uuid uuid = Uuid::zero())
      : user(std::move(user)),
        uuid(uuid) {
    if (currentClientId()) {
      client = *currentClientId();
    }
  }

  Result<Void> checkUuid() const {
    if (client.uuid == Uuid::zero()) return INVALID("Invalid client uuid");
    if (uuid == Uuid::zero()) return INVALID("Invalid request uuid");
    return VALID;
  }
};
struct RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});
};

// authentication
struct AuthReq : ReqBase {
  SERDE_STRUCT_FIELD(dummy, Void{});

 public:
  AuthReq() = default;
  AuthReq(UserInfo user)
      : ReqBase(std::move(user)) {}
  Result<Void> valid() const { return VALID; }
};

struct AuthRsp : RspBase {
  SERDE_STRUCT_FIELD(user, UserInfo{});

 public:
  AuthRsp() = default;
  AuthRsp(UserInfo user)
      : user(std::move(user)) {}
};

// statFs
struct StatFsReq : ReqBase {
 public:
  StatFsReq() = default;
  StatFsReq(UserInfo user)
      : ReqBase(std::move(user)) {}
  Result<Void> valid() const { return VALID; }
};
struct StatFsRsp : RspBase {
  SERDE_STRUCT_FIELD(capacity, uint64_t(0));
  SERDE_STRUCT_FIELD(used, uint64_t(0));
  SERDE_STRUCT_FIELD(free, uint64_t(0));

 public:
  StatFsRsp() = default;
  StatFsRsp(uint64_t capacity, uint64_t used, uint64_t free)
      : capacity(capacity),
        used(used),
        free(free) {}
};

// stat
struct StatReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(flags, AtFlags());

 public:
  StatReq() = default;
  StatReq(UserInfo user, PathAt path, AtFlags flags)
      : ReqBase(std::move(user)),
        path(std::move(path)),
        flags(flags) {}
  Result<Void> valid() const { return flags.valid(); }
};
struct StatRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  StatRsp() = default;
  StatRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// batchStat & batchStatByPath
struct BatchStatReq : ReqBase {
  SERDE_STRUCT_FIELD(inodeIds, std::vector<InodeId>());

 public:
  BatchStatReq() = default;
  BatchStatReq(UserInfo user, std::vector<InodeId> inodeIds)
      : ReqBase(std::move(user)),
        inodeIds(std::move(inodeIds)) {}

  Result<Void> valid() const { return VALID; }
};

struct BatchStatRsp : RspBase {
  SERDE_STRUCT_FIELD(inodes, std::vector<std::optional<Inode>>());

 public:
  BatchStatRsp() = default;
  BatchStatRsp(std::vector<std::optional<Inode>> inodes)
      : inodes(std::move(inodes)) {}
};

struct BatchStatByPathReq : ReqBase {
  SERDE_STRUCT_FIELD(paths, std::vector<PathAt>());
  SERDE_STRUCT_FIELD(flags, AtFlags());

 public:
  BatchStatByPathReq() = default;
  BatchStatByPathReq(UserInfo user, std::vector<PathAt> paths, AtFlags flags)
      : ReqBase(std::move(user)),
        paths(std::move(paths)),
        flags(flags) {}

  Result<Void> valid() const { return flags.valid(); }
};

struct BatchStatByPathRsp : RspBase {
  SERDE_STRUCT_FIELD(inodes, std::vector<Result<Inode>>());

 public:
  BatchStatByPathRsp() = default;
  BatchStatByPathRsp(std::vector<Result<Inode>> inodes)
      : inodes(std::move(inodes)) {}
};

// create
struct CreateReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(session, std::optional<SessionInfo>());
  SERDE_STRUCT_FIELD(flags, OpenFlags());
  SERDE_STRUCT_FIELD(perm, Permission());
  SERDE_STRUCT_FIELD(layout, std::optional<Layout>());
  SERDE_STRUCT_FIELD(removeChunksBatchSize, uint32_t(0));
  SERDE_STRUCT_FIELD(dynStripe, false);

 public:
  CreateReq() = default;
  CreateReq(UserInfo user,
            PathAt path,
            std::optional<SessionInfo> session,
            OpenFlags flags,
            Permission perm,
            std::optional<Layout> layout = std::nullopt,
            bool dynStripe = false)
      : ReqBase(std::move(user), Uuid::random()),
        path(std::move(path)),
        session(session),
        flags(flags),
        perm(perm),
        layout(std::move(layout)),
        removeChunksBatchSize(32),
        dynStripe(dynStripe) {}

  Result<Void> valid() const {
    RETURN_ON_ERROR(path.validForCreate());
    RETURN_ON_ERROR(flags.valid());
    if (flags.accessType() != AccessType::READ) CHECK_SESSION(session);
    if (layout.has_value()) RETURN_ON_ERROR(layout->valid(true));
    if (flags.contains(O_TRUNC) && removeChunksBatchSize == 0) return INVALID("removeChunksBatchSize == 0");
    return VALID;
  }
};
struct CreateRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());
  SERDE_STRUCT_FIELD(needTruncate, false);

 public:
  CreateRsp() = default;
  CreateRsp(Inode stat, bool needTruncate)
      : stat(std::move(stat)),
        needTruncate(needTruncate) {}
};

// mkdirs
struct MkdirsReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(perm, Permission());
  SERDE_STRUCT_FIELD(recursive, false);
  SERDE_STRUCT_FIELD(layout, std::optional<Layout>());

 public:
  MkdirsReq() = default;
  MkdirsReq(UserInfo user, PathAt path, Permission perm, bool recursive, std::optional<Layout> layout = std::nullopt)
      : ReqBase(std::move(user), Uuid::random()),
        path(std::move(path)),
        perm(perm),
        recursive(recursive),
        layout(std::move(layout)) {}
  Result<Void> valid() const {
    if (!path.path.has_value() || path.path->empty()) return INVALID("path not set");
    if (layout.has_value()) RETURN_ON_ERROR(layout->valid(true));
    return Void{};
  }
};

struct MkdirsRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  MkdirsRsp() = default;
  MkdirsRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// symlink
struct SymlinkReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(target, Path());

 public:
  SymlinkReq() = default;
  SymlinkReq(UserInfo user, PathAt path, Path target)
      : ReqBase(std::move(user), Uuid::random()),
        path(std::move(path)),
        target(std::move(target)) {}
  Result<Void> valid() const { return path.validForCreate(); }
};
struct SymlinkRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  SymlinkRsp() = default;
  SymlinkRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// hardlink
struct HardLinkReq : ReqBase {
  SERDE_STRUCT_FIELD(oldPath, PathAt());
  SERDE_STRUCT_FIELD(newPath, PathAt());
  SERDE_STRUCT_FIELD(flags, AtFlags());

 public:
  HardLinkReq() = default;
  HardLinkReq(UserInfo user, PathAt oldPath, PathAt newPath, AtFlags flags)
      : ReqBase(std::move(user), Uuid::random()),
        oldPath(std::move(oldPath)),
        newPath(std::move(newPath)),
        flags(flags) {}
  Result<Void> valid() const {
    RETURN_ON_ERROR(newPath.validForCreate());
    RETURN_ON_ERROR(flags.valid());
    return VALID;
  }
};
struct HardLinkRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  HardLinkRsp() = default;
  HardLinkRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// remove
struct RemoveReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(atFlags, AtFlags());
  SERDE_STRUCT_FIELD(recursive, false);
  SERDE_STRUCT_FIELD(checkType, false);
  SERDE_STRUCT_FIELD(inodeId, std::optional<InodeId>());

 public:
  RemoveReq() = default;
  RemoveReq(UserInfo user,
            PathAt path,
            AtFlags flags,
            bool recursive,
            bool checkType = false,
            std::optional<InodeId> inodeId = std::nullopt)
      : ReqBase(std::move(user), Uuid::random()),
        path(std::move(path)),
        atFlags(flags),
        recursive(recursive),
        checkType(checkType),
        inodeId(inodeId) {}
  Result<Void> valid() const {
    if (path.path.has_value()) RETURN_ON_ERROR(path.validForCreate());
    if (recursive) RETURN_ON_ERROR(checkUuid());
    return VALID;
  }
};

struct RemoveRsp : RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});
};

// open
struct OpenReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(session, std::optional<SessionInfo>());
  SERDE_STRUCT_FIELD(flags, OpenFlags());
  SERDE_STRUCT_FIELD(removeChunksBatchSize, uint32_t(0));
  SERDE_STRUCT_FIELD(dynStripe, false);

 public:
  OpenReq() = default;
  OpenReq(UserInfo user, PathAt path, std::optional<SessionInfo> session, OpenFlags flags, bool dynStripe = false)
      : ReqBase(std::move(user)),
        path(std::move(path)),
        session(session),
        flags(flags),
        removeChunksBatchSize(32),
        dynStripe(dynStripe) {}
  Result<Void> valid() const {
    RETURN_ON_ERROR(flags.valid());
    if (flags.accessType() != AccessType::READ) CHECK_SESSION(session);
    if (flags.accessType() == AccessType::READ && (flags.contains(O_TRUNC) || flags.contains(O_APPEND)))
      return INVALID("O_RDONLY with O_TRUNC or O_APPEND");
    if (flags.contains(O_TRUNC) && removeChunksBatchSize == 0) return INVALID("removeChunksBatchSize == 0");
    return VALID;
  }
};
struct OpenRsp : RspBase {
  SERDE_STRUCT_FIELD(_unused, (uint32_t)0);
  SERDE_STRUCT_FIELD(stat, Inode());
  SERDE_STRUCT_FIELD(needTruncate, false);

 public:
  OpenRsp() = default;
  OpenRsp(Inode stat, bool needTruncate)
      : stat(std::move(stat)),
        needTruncate(needTruncate) {}
};

// sync
struct SyncReq : ReqBase {
  SERDE_STRUCT_FIELD(inode, InodeId());
  SERDE_STRUCT_FIELD(updateLength, false);
  SERDE_STRUCT_FIELD(atime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(mtime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(truncated, false);
  SERDE_STRUCT_FIELD(lengthHint, std::optional<VersionedLength>());

 public:
  SyncReq() = default;
  SyncReq(UserInfo user,
          InodeId inode,
          bool updateLength,
          std::optional<UtcTime> atime,
          std::optional<UtcTime> mtime,
          bool truncated = false,
          std::optional<VersionedLength> hint = std::nullopt)
      : ReqBase(std::move(user)),
        inode(inode),
        updateLength(updateLength),
        atime(atime),
        mtime(mtime),
        truncated(truncated),
        lengthHint(hint) {}
  Result<Void> valid() const {
    if (truncated && !updateLength) return INVALID("truncate but not updateLength");
    return VALID;
  }
};
struct SyncRsp : RspBase {
  SERDE_STRUCT_FIELD(_unused, (uint32_t)0);
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  SyncRsp() = default;
  SyncRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// close
struct CloseReq : ReqBase {
  SERDE_STRUCT_FIELD(inode, InodeId());
  SERDE_STRUCT_FIELD(session, std::optional<SessionInfo>());
  SERDE_STRUCT_FIELD(updateLength, false);
  SERDE_STRUCT_FIELD(atime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(mtime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(lengthHint, std::optional<VersionedLength>());

 public:
  bool pruneSession = false;

  CloseReq() = default;
  CloseReq(UserInfo user,
           InodeId inode,
           std::optional<SessionInfo> session,
           bool updateLength,
           std::optional<UtcTime> atime,
           std::optional<UtcTime> mtime)
      : ReqBase(std::move(user)),
        inode(inode),
        session(session),
        updateLength(updateLength),
        atime(atime),
        mtime(mtime) {}
  Result<Void> valid() const {
    if (updateLength || mtime.has_value()) CHECK_SESSION(session);
    return VALID;
  }
};
struct CloseRsp : RspBase {
  SERDE_STRUCT_FIELD(_unused, (uint32_t)0);
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  CloseRsp() = default;
  CloseRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// rename
struct RenameReq : ReqBase {
  SERDE_STRUCT_FIELD(src, PathAt());
  SERDE_STRUCT_FIELD(dest, PathAt());
  SERDE_STRUCT_FIELD(moveToTrash, false);
  SERDE_STRUCT_FIELD(inodeId, std::optional<InodeId>());

 public:
  RenameReq() = default;
  RenameReq(UserInfo user,
            PathAt src,
            PathAt dest,
            bool moveToTrash = false,
            std::optional<InodeId> inodeId = std::nullopt)
      : ReqBase(std::move(user), Uuid::random()),
        src(std::move(src)),
        dest(std::move(dest)),
        moveToTrash(moveToTrash),
        inodeId(inodeId) {}
  Result<Void> valid() const {
    RETURN_ON_ERROR(src.validForCreate());
    RETURN_ON_ERROR(dest.validForCreate());
    if (moveToTrash) RETURN_ON_ERROR(checkUuid());
    return VALID;
  }
};
struct RenameRsp : RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});
  SERDE_STRUCT_FIELD(stat, std::optional<Inode>());

 public:
  RenameRsp() = default;
  RenameRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// list
struct ListReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(prev, std::string());
  SERDE_STRUCT_FIELD(limit, (int32_t)-1);
  SERDE_STRUCT_FIELD(status, false);

 public:
  ListReq() = default;
  ListReq(UserInfo user, PathAt path, std::string prev = {}, int32_t limit = -1, bool status = false)
      : ReqBase(std::move(user)),
        path(std::move(path)),
        prev(std::move(prev)),
        limit(limit),
        status(status) {}
  Result<Void> valid() const { return VALID; }
};
struct ListRsp : RspBase {
  SERDE_STRUCT_FIELD(entries, std::vector<DirEntry>());
  SERDE_STRUCT_FIELD(inodes, std::vector<Inode>());
  SERDE_STRUCT_FIELD(more, false);

 public:
  ListRsp() = default;
  ListRsp(std::vector<DirEntry> entries, std::vector<Inode> inodes, bool more)
      : entries(std::move(entries)),
        inodes(std::move(inodes)),
        more(more) {}
};

// truncate
struct TruncateReq : ReqBase {
  SERDE_STRUCT_FIELD(inode, InodeId(0));
  SERDE_STRUCT_FIELD(length, uint64_t(0));
  SERDE_STRUCT_FIELD(removeChunksBatchSize, uint32_t(0));

 public:
  TruncateReq() = default;
  TruncateReq(UserInfo user, InodeId inode, uint64_t length, uint32_t removeChunksBatchSize)
      : ReqBase(std::move(user)),
        inode(inode),
        length(length),
        removeChunksBatchSize(removeChunksBatchSize) {}
  Result<Void> valid() const {
    if (removeChunksBatchSize == 0) return INVALID("removeChunksBatchSize == 0");
    return VALID;
  }
};
struct TruncateRsp : RspBase {
  SERDE_STRUCT_FIELD(chunksRemoved, uint32_t(0));
  SERDE_STRUCT_FIELD(stat, Inode());
  SERDE_STRUCT_FIELD(finished, true);

 public:
  TruncateRsp() = default;
  TruncateRsp(Inode stat)
      : TruncateRsp(std::move(stat), 0, true) {}
  TruncateRsp(Inode stat, uint32_t chunksRemoved, bool finished)
      : chunksRemoved(chunksRemoved),
        stat(std::move(stat)),
        finished(finished) {}
};

// getRealPath
struct GetRealPathReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(absolute, false);

 public:
  GetRealPathReq() = default;
  GetRealPathReq(UserInfo user, PathAt path, bool absolute)
      : ReqBase(std::move(user)),
        path(std::move(path)),
        absolute(absolute) {}
  Result<Void> valid() const { return VALID; }
};
struct GetRealPathRsp : RspBase {
  SERDE_STRUCT_FIELD(path, Path());

 public:
  GetRealPathRsp() = default;
  GetRealPathRsp(Path path)
      : path(std::move(path)) {}
};

// setAttr
struct SetAttrReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(flags, AtFlags());
  SERDE_STRUCT_FIELD(uid, std::optional<Uid>());
  SERDE_STRUCT_FIELD(gid, std::optional<Gid>());
  SERDE_STRUCT_FIELD(perm, std::optional<Permission>());
  SERDE_STRUCT_FIELD(atime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(mtime, std::optional<UtcTime>());
  SERDE_STRUCT_FIELD(layout, std::optional<Layout>());
  SERDE_STRUCT_FIELD(iflags, std::optional<IFlags>());
  SERDE_STRUCT_FIELD(dynStripe, uint32_t(0));

 public:
  static SetAttrReq setLayout(UserInfo user, PathAt path, AtFlags flags, Layout layout) {
    return {std::move(user), std::move(path), flags, {}, {}, {}, {}, {}, std::move(layout)};
  }
  static SetAttrReq setPermission(UserInfo user,
                                  PathAt path,
                                  AtFlags flags,
                                  std::optional<Uid> uid,
                                  std::optional<Gid> gid,
                                  std::optional<Permission> perm,
                                  std::optional<IFlags> iflags = std::nullopt) {
    return {std::move(user), std::move(path), flags, uid, gid, perm, {}, {}, {}, iflags};
  }
  static SetAttrReq setIFlags(UserInfo user, PathAt path, IFlags iflags) {
    return {std::move(user), std::move(path), AtFlags(), {}, {}, {}, {}, {}, {}, iflags};
  }
  static SetAttrReq utimes(UserInfo user,
                           PathAt path,
                           AtFlags flags,
                           std::optional<UtcTime> atime,
                           std::optional<UtcTime> mtime) {
    return {std::move(user), std::move(path), flags, {}, {}, {}, atime, mtime, {}};
  }
  static SetAttrReq extendStripe(UserInfo user, InodeId inode, uint32_t stripe) {
    return {std::move(user), PathAt(inode), AtFlags{}, {}, {}, {}, {}, {}, {}, {}, stripe};
  }
  Result<Void> valid() const {
    if (layout.has_value()) RETURN_ON_ERROR(layout->valid(true));
    if (iflags && (*iflags & ~FS_FL_SUPPORTED)) {
      return MAKE_ERROR_F(StatusCode::kInvalidArg, "only support {:x}", (uint32_t)FS_FL_SUPPORTED);
    }
    return VALID;
  }
};

struct SetAttrRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());

 public:
  SetAttrRsp() = default;
  SetAttrRsp(Inode stat)
      : stat(std::move(stat)) {}
};

// pruneSession
struct PruneSessionReq : ReqBase {
  SERDE_STRUCT_FIELD(client, ClientId::zero());
  SERDE_STRUCT_FIELD(sessions, std::vector<Uuid>());
  SERDE_STRUCT_FIELD(needSync, std::vector<bool>());  // deperated

 public:
  PruneSessionReq() = default;
  PruneSessionReq(ClientId client, std::vector<Uuid> sessions)
      : ReqBase(),
        client(client),
        sessions(std::move(sessions)) {}
  Result<Void> valid() const { return VALID; }
};
struct PruneSessionRsp : RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});
};

// dropUserCache
struct DropUserCacheReq : ReqBase {
  SERDE_STRUCT_FIELD(uid, std::optional<Uid>());
  SERDE_STRUCT_FIELD(dropAll, false);

 public:
  DropUserCacheReq() = default;
  DropUserCacheReq(std::optional<Uid> u, bool d)
      : uid(std::move(u)),
        dropAll(d) {}
  Result<Void> valid() const { return VALID; }
};
struct DropUserCacheRsp : RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});
};

// lockDirectory
struct LockDirectoryReq : ReqBase {
  enum class LockAction : uint8_t {
    TryLock,
    PreemptLock,
    UnLock,
    Clear,
  };
  SERDE_STRUCT_FIELD(inode, InodeId());
  SERDE_STRUCT_FIELD(action, LockAction::TryLock);

 public:
  LockDirectoryReq() = default;
  LockDirectoryReq(UserInfo user, InodeId inode, LockAction action)
      : ReqBase(user),
        inode(inode),
        action(action) {}
  Result<Void> valid() const { return VALID; }
};

struct LockDirectoryRsp : RspBase {
  SERDE_STRUCT_FIELD(dummy, Void{});

 public:
  LockDirectoryRsp() = default;
};

// Experimental native EC control plane. The server computes requestDigest;
// descriptors supplied to Publish are read hints, never trusted seal receipts.
struct CreateEcFileReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt{});
  SERDE_STRUCT_FIELD(perm, Permission{0600});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{1u << 20});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    RETURN_ON_ERROR(path.validForCreate());
    if ((perm & ~ALLPERMS) != 0) return INVALID("invalid EC file permission bits");
    if (!shardBytes || shardBytes > storage::kEcFragmentRpcMaxBytes) return INVALID("invalid EC shard capacity");
    return VALID;
  }
};
struct CreateEcFileRsp : RspBase {
  SERDE_STRUCT_FIELD(inode, Inode{});
  SERDE_STRUCT_FIELD(object, EcObjectRecord{});
};

struct EcOperationReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        operation.is_nil())
      return INVALID("invalid EC object or operation");
    return VALID;
  }
};
struct BeginEcMutationReq : EcOperationReq {
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(expectedRevision, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(kind, EcMutationKind::Write);
  SERDE_STRUCT_FIELD(replacementMask, kEcAllShards);
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(fragmentCrc32c, (std::array<uint32_t, 12>{}));

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcOperationReq::valid());
    if (!expectedEpoch || !logicalLength || logicalLength > 10 * storage::kEcFragmentRpcMaxBytes || !replacementMask ||
        (replacementMask & ~kEcAllShards) || (kind != EcMutationKind::Write && kind != EcMutationKind::Repair) ||
        (kind == EcMutationKind::Write && replacementMask != kEcAllShards))
      return INVALID("invalid EC intent");
    return VALID;
  }
};
struct PublishEcMutationReq : EcOperationReq {
  SERDE_STRUCT_FIELD(descriptors, (std::array<storage::EcIntegrityDescriptor, 12>{}));
};
struct GetEcOperationReq : EcOperationReq {};
struct CancelEcMutationReq : EcOperationReq {};
struct EcOperationRsp : RspBase {
  SERDE_STRUCT_FIELD(record, EcOperationRecord{});
  SERDE_STRUCT_FIELD(object, EcObjectRecord{});
  SERDE_STRUCT_FIELD(createGrants, (std::array<std::optional<storage::EcCapability>, 12>{}));
};

struct AcquireEcReadReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(pin, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        pin.is_nil()) {
      return INVALID("invalid EC object or read pin");
    }
    return VALID;
  }
};
struct ReleaseEcReadReq : AcquireEcReadReq {};
struct AcquireEcReadRsp : RspBase {
  SERDE_STRUCT_FIELD(manifest, EcManifest{});
  SERDE_STRUCT_FIELD(pin, Uuid::zero());
  SERDE_STRUCT_FIELD(readGrants, (std::array<std::optional<storage::EcCapability>, 12>{}));
};
struct ReleaseEcReadRsp : RspBase {};

// V2 methods have independent request types and method numbers. Begin fixes
// physical instances; only Bind/Acquire produce data capabilities.
struct CreateEcFileV2Req : CreateEcFileReq {};
struct BeginEcMutationV2Req : BeginEcMutationReq {};
struct BindEcMutationV2Req : EcOperationReq {
  SERDE_STRUCT_FIELD(descriptors, (std::array<storage::EcIntegrityDescriptor, 12>{}));
};
struct PublishEcMutationV2Req : EcOperationReq {};
struct GetEcOperationV2Req : EcOperationReq {};
struct CancelEcMutationV2Req : EcOperationReq {};
struct EcV2MutationRsp : RspBase {
  SERDE_STRUCT_FIELD(reservation, (std::optional<EcV2Reservation>{}));
  SERDE_STRUCT_FIELD(record, EcOperationRecord{});
  SERDE_STRUCT_FIELD(object, EcObjectRecord{});
  SERDE_STRUCT_FIELD(allocations, (std::optional<EcV2AllocationBindings>{}));
  SERDE_STRUCT_FIELD(grants, EcV2Grants{});
  SERDE_STRUCT_FIELD(drain, (std::optional<EcV2DrainProgress>{}));
};
struct AcquireEcReadV2Req : AcquireEcReadReq {};
struct ReleaseEcReadV2Req : AcquireEcReadReq {};
struct AcquireEcReadV2Rsp : RspBase {
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(manifest, EcManifest{});
  SERDE_STRUCT_FIELD(snapshot, EcV2PinSnapshot{});
  SERDE_STRUCT_FIELD(readGrants, EcV2Grants{});
};
struct ReleaseEcReadV2Rsp : RspBase {
  SERDE_STRUCT_FIELD(pin, Uuid::zero());
  SERDE_STRUCT_FIELD(drain, EcV2DrainProgress{});
};

// The caller selects only a fixed healthy source order and bounded window.
// Physical instances, descriptors and logical SHA come from durable Meta state.
struct PrepareEcRepairV2Req : EcOperationReq {
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceOrder, (std::array<uint8_t, 10>{}));
  SERDE_STRUCT_FIELD(maxBlocksInFlight, uint8_t{1});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcOperationReq::valid());
    if (planId.is_nil() || !maxBlocksInFlight || maxBlocksInFlight > 4)
      return INVALID("invalid V2 repair plan identifier or window");
    uint16_t selected = 0;
    for (const auto shard : sourceOrder) {
      if (shard >= 12 || (selected & (uint16_t{1} << shard)))
        return INVALID("V2 repair requires ten distinct source indices");
      selected |= uint16_t{1} << shard;
    }
    return VALID;
  }
};
struct PrepareEcRepairV2Rsp : RspBase {
  SERDE_STRUCT_FIELD(mutation, EcV2MutationRsp{});
  SERDE_STRUCT_FIELD(plan, storage::EcRepairPlanInput{});
  SERDE_STRUCT_FIELD(helpers, (std::optional<std::array<storage::EcHelperCapability, 10>>{}));
};

// Root-only GC accepts identities, never a caller endpoint, claim certificate,
// receipt, eligibility flag or allocator position. Success is committed G2.
struct EcGcAdminReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    RETURN_ON_ERROR(identity.validate());
    if (claimId.is_nil() || object.incarnation.is_nil() || object.inode.isTreeRoot() ||
        object.inode > InodeId::normalMax() || identity.object != object.incarnation || identity.shard >= 12)
      return INVALID("invalid exact GC identity");
    return VALID;
  }
};
struct CollectEcFragmentV2Req : EcGcAdminReq {};
struct QueryEcFragmentGcV2Req : EcGcAdminReq {};
// Permanent proof remains in ECGD; the response does not export G bearer data.
struct EcGcAdminRsp : RspBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(claimId, Uuid::zero());
  SERDE_STRUCT_FIELD(claimDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(ledgerSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(terminalRevision, uint64_t{});
};

// An explicit administrative metadata operation. The same client namespace
// and request UUID bind one exact historical revision permanently.
struct EcRevisionRetirementReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (client.uuid.is_nil() || object.incarnation.is_nil() || object.inode.isTreeRoot() ||
        object.inode > InodeId::normalMax() || !revision)
      return INVALID("invalid fixed EC revision retirement identity");
    return VALID;
  }
};
struct RetireEcRevisionV2Req : EcRevisionRetirementReq {};
struct QueryEcRevisionRetirementV2Req : EcRevisionRetirementReq {};
struct EcRevisionRetirementRsp : RspBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(clientNamespace, Uuid::zero());
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(referencesReleased, false);
};

// Root-authenticated administrative intent. The authority is selected by Meta.
// Query actively confirms an existing intent, never creates or prepares one.
struct EcTargetRetirementReq : ReqBase {
  SERDE_STRUCT_FIELD(endpoint, EcV2PhysicalEndpoint{});
  SERDE_STRUCT_FIELD(retirementId, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (retirementId.is_nil() || endpoint.engineUuid.is_nil() || endpoint.targetIncarnation.is_nil() ||
        endpoint.placement.node == flat::NodeId{} || endpoint.placement.chain == storage::ChainId{} ||
        endpoint.placement.target == storage::TargetId{})
      return INVALID("fixed exact target retirement identity is required");
    return VALID;
  }
};
struct PrepareEcTargetRetirementReq : EcTargetRetirementReq {};
struct QueryEcTargetRetirementReq : EcTargetRetirementReq {};
struct EcTargetRetirementRsp : RspBase {
  SERDE_STRUCT_FIELD(intent, EcTargetRetirementIntent{});
  SERDE_STRUCT_FIELD(stage, EcTargetRetirementStage::Prepared);
  // All-zero while Prepared; immutable first completion digest when Completed.
  SERDE_STRUCT_FIELD(completionDigest, storage::EcSha256{});
};

// File metadata/range RPCs deliberately have their own disabled-by-default gate.
struct DescribeEcFileV2Req : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(access, AccessType::READ);

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (client.uuid.is_nil() || object.incarnation.is_nil() || object.inode.isTreeRoot() ||
        object.inode > InodeId::normalMax() || (access != AccessType::READ && access != AccessType::WRITE))
      return INVALID("invalid EC file description request");
    return VALID;
  }
};
struct DescribeEcFileV2Rsp : RspBase {
  SERDE_STRUCT_FIELD(file, EcFileState{});
};
struct EcRangeReq : ReqBase {
  SERDE_STRUCT_FIELD(rangeId, Uuid::zero());
  SERDE_STRUCT_FIELD(selection, EcRangeSelection{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (client.uuid.is_nil() || rangeId.is_nil()) return INVALID("fixed EC range identity is required");
    return selection.valid();
  }
};
struct AcquireEcRangeV2Req : EcRangeReq {};
struct QueryEcRangeV2Req : EcRangeReq {};
struct EcRangeRsp : RspBase {
  SERDE_STRUCT_FIELD(snapshot, EcRangeSnapshot{});
};

// Owner-bound recovery observation. No grant or current inode attributes.
struct QueryEcOwnedMutationV2Req : EcOperationReq {
 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcOperationReq::valid());
    if (client.uuid.is_nil()) return INVALID("fixed mutation owner namespace is required");
    return VALID;
  }
};
struct EcOwnedMutationRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(clientNamespace, Uuid::zero());
  SERDE_STRUCT_FIELD(record, EcOperationRecord{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(drain, (std::optional<EcV2DrainProgress>{}));
  SERDE_STRUCT_FIELD(publishedContentConfirmed, false);
};

// testRpc
// Meta 46-49/51: requests retain caller-assigned IDs. Existing objects open by
// exact incarnation/birth; creation alone resolves the supplied pathname.
struct AdvanceEcTreeReclaimReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  // nil is a bounded read-only queue inspection; otherwise one exact node.
  SERDE_STRUCT_FIELD(node, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax())
      return INVALID("exact tree object required");
    return VALID;
  }
};
struct AdvanceEcTreeReclaimRsp : RspBase {
  SERDE_STRUCT_FIELD(progress, EcTreeReclaimProgress{});
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(clientNamespace, Uuid::zero());
};
struct OpenEcFileSessionReq : CreateEcFileReq {
  SERDE_STRUCT_FIELD(createNew, false);
  // Existing exact incarnation only; never resolves a pathname or upgrades mode 2/3.
  SERDE_STRUCT_FIELD(resolveBirth, false);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(rights, uint8_t{kEcSessionRead});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (session.is_nil() || !rights || (rights & ~(kEcSessionRead | kEcSessionWrite)))
      return INVALID("invalid file session identity or rights");
    if (createNew) {
      RETURN_ON_ERROR(CreateEcFileReq::valid());
      if (resolveBirth || !object.incarnation.is_nil() || !birth.is_nil())
        return INVALID("new file cannot select an old birth");
    } else {
      if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
          (resolveBirth ? !birth.is_nil() : birth.is_nil()) || path.path.has_value())
        return INVALID("existing file open requires exact object/birth");
    }
    return VALID;
  }
};
struct OpenEcFileSessionRsp : RspBase {
  SERDE_STRUCT_FIELD(inode, Inode{});
  SERDE_STRUCT_FIELD(object, EcObjectRecord{});
  SERDE_STRUCT_FIELD(root, EcTreeRoot{});
  SERDE_STRUCT_FIELD(session, EcFileSessionRecord{});
};
struct EcFilePwriteReq : EcOperationReq {
  SERDE_STRUCT_FIELD(session, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcOperationReq::valid());
    if (session.is_nil()) return INVALID("file session required");
    return VALID;
  }
};
struct BeginEcFilePwriteReq : EcFilePwriteReq {
  SERDE_STRUCT_FIELD(offset, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(inputSha256, storage::EcSha256{});
};
struct QueryEcFilePwriteReq : EcFilePwriteReq {
  SERDE_STRUCT_FIELD(child, Uuid::zero());
};
struct AdvanceEcFilePwriteReq : EcFilePwriteReq {
  SERDE_STRUCT_FIELD(action, EcFileAdvanceAction::Plan);
  SERDE_STRUCT_FIELD(intent, EcFileChildIntent{});
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFilePwriteReq::valid());
    if (action == EcFileAdvanceAction::Plan) {
      if (intent.object != object || intent.parent != operation || intent.child != child || child.is_nil())
        return INVALID("planned child differs from parent request");
    } else if (action == EcFileAdvanceAction::Publish) {
      if (child.is_nil()) return INVALID("publication child required");
    } else if (action == EcFileAdvanceAction::CleanupChild) {
      if (child.is_nil() || outputRevocation.is_nil() || sourceRevocation.is_nil())
        return INVALID("cleanup must preserve explicit child and revocation IDs");
    } else if (action != EcFileAdvanceAction::SealPrefix)
      return INVALID("invalid file advance action");
    return VALID;
  }
};
struct EcFilePwriteRsp : RspBase {
  SERDE_STRUCT_FIELD(progress, EcFilePwriteProgress{});
};
struct CloseEcFileSessionReq : ReqBase {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        session.is_nil())
      return INVALID("invalid close identity");
    return VALID;
  }
};
struct CloseEcFileSessionRsp : RspBase {
  SERDE_STRUCT_FIELD(session, EcFileSessionRecord{});
};

// Insert in fbs/meta/Service.h after AcquireEcReadV2Rsp is defined, with
// fbs/meta/EcFileTreeRead.h included at the top of that file.
struct EcTreeReadReq : ReqBase {
  SERDE_STRUCT_FIELD(intent, EcTreeReadIntent{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    RETURN_ON_ERROR(intent.selection.valid());
    if (intent.version != kEcFileTreeVersion || intent.session.is_nil() || intent.request.is_nil() ||
        intent.range.is_nil())
      return INVALID("invalid tree read identity");
    return VALID;
  }
};
struct AcquireEcTreeReadReq : EcTreeReadReq {
  SERDE_STRUCT_FIELD(stripeIndex, (std::optional<uint8_t>{}));

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcTreeReadReq::valid());
    if (stripeIndex && *stripeIndex >= kEcFileRangeMaxStripes) return INVALID("tree read stripe index exceeds bound");
    return VALID;
  }
};
struct QueryEcTreeReadReq : EcTreeReadReq {};
struct ReleaseEcTreeReadReq : EcTreeReadReq {
  SERDE_STRUCT_FIELD(revocations, (std::array<Uuid, 8>{}));
};
struct EcTreeReadRsp : RspBase {
  SERDE_STRUCT_FIELD(record, EcTreeReadRecord{});
  SERDE_STRUCT_FIELD(read, (std::optional<AcquireEcReadV2Rsp>{}));
};

// Include fbs/meta/EcFileTruncateRpc.h in Service.h. Numbers 56..59 are reserved
// for this layer; do not replace W1/W2/tree-read/W4 method registrations.
struct EcFileTruncateReq : ReqBase {
  SERDE_STRUCT_FIELD(intent, EcFileTruncateIntent{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    return validateEcFileTruncateIntent(intent);
  }
};
struct BeginEcFileTruncateReq : EcFileTruncateReq {};
struct QueryEcFileTruncateReq : EcFileTruncateReq {};
struct AdvanceEcFileTruncateReq : EcFileTruncateReq {};
struct CloseEcFileTruncateDebtReq : EcFileTruncateReq {
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileTruncateReq::valid());
    if (outputRevocation.is_nil() || sourceRevocation.is_nil() || outputRevocation == sourceRevocation)
      return INVALID("fixed independent truncate revocations are required");
    return VALID;
  }
};
struct EcFileTruncateRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(progress, EcFileTruncateProgress{});
};

struct EcFileAppendReq : ReqBase {
  SERDE_STRUCT_FIELD(intent, EcFileAppendIntent{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    return validateEcAppend(intent);
  }
};
struct BeginEcFileAppendReq : EcFileAppendReq {
 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileAppendReq::valid());
    if (uuid != intent.request) return INVALID("append acceptance request differs from permanent intent");
    return VALID;
  }
};
struct QueryEcFileAppendReq : EcFileAppendReq {};
struct EcFileAppendRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(record, (std::optional<EcFileAppendRecord>{}));
};
struct SyncEcFileSessionReq : ReqBase {
  SERDE_STRUCT_FIELD(intent, EcFileSyncIntent{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    RETURN_ON_ERROR(validateEcSync(intent));
    if (uuid != intent.request) return INVALID("fsync request differs from permanent barrier identity");
    return VALID;
  }
};
struct SyncEcFileSessionRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(record, EcFileSyncRecord{});
};

struct EcFileRepairReq : ReqBase {
  SERDE_STRUCT_FIELD(intent, EcFileRepairIntent{});

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(checkUuid());
    return validateEcFileRepairIntent(intent);
  }
};
struct BeginEcFileRepairReq : EcFileRepairReq {
 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileRepairReq::valid());
    if (uuid != intent.request) return INVALID("repair acceptance UUID changed");
    return VALID;
  }
};
struct QueryEcFileRepairReq : EcFileRepairReq {};
struct AdvanceEcFileRepairReq : EcFileRepairReq {
  SERDE_STRUCT_FIELD(action, EcFileRepairAdvance::Prepare);

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileRepairReq::valid());
    if (action != EcFileRepairAdvance::Prepare && action != EcFileRepairAdvance::Publish)
      return INVALID("unknown repair action");
    if (action == EcFileRepairAdvance::Prepare && intent.mode == EcFileRepairMode::HelperChainDirect)
      return INVALID("direct repair requires prepareEcFileRepairDirect");
    return VALID;
  }
};
struct PrepareEcFileRepairDirectReq : EcFileRepairReq {
 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileRepairReq::valid());
    if (intent.mode != EcFileRepairMode::HelperChainDirect) return INVALID("direct repair mode required");
    return VALID;
  }
};
struct CloseEcFileRepairDebtReq : EcFileRepairReq {
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());

 public:
  Result<Void> valid() const {
    RETURN_ON_ERROR(EcFileRepairReq::valid());
    if (outputRevocation.is_nil() || sourceRevocation.is_nil() || outputRevocation == sourceRevocation)
      return INVALID("fixed distinct debt revocations required");
    return VALID;
  }
};
struct EcFileRepairRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(progress, EcFileRepairProgress{});
  // Present only after a committed issuance for an accepted READ|WRITE session.
  SERDE_STRUCT_FIELD(access, (std::optional<EcFileRepairAccess>{}));
};

struct EcFileRepairDirectRsp : RspBase {
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(progress, EcFileRepairProgress{});
  SERDE_STRUCT_FIELD(access, (std::optional<EcFileRepairDirectAccess>{}));
};

struct TestRpcReq : ReqBase {
  SERDE_STRUCT_FIELD(path, PathAt());
  SERDE_STRUCT_FIELD(flags, uint32_t(0));

 public:
  Result<Void> valid() const { return VALID; }
};
struct TestRpcRsp : RspBase {
  SERDE_STRUCT_FIELD(stat, Inode());
};

/* MetaSerde service */
SERDE_SERVICE(MetaSerde, 4) {
 private:
  // Meta has more methods than the generic field reflection's Rank<64>.
  // Keep its accumulator independent, then export one complete tuple to Helper.
  static std::tuple<> CollectMetaMethod(::hf3fs::refl::Rank<0>);

#define META_SERVICE_METHOD(NAME, CODE, REQ, RSP)                                                                \
  SERDE_SERVICE_METHOD_SENDER(NAME, CODE, REQ, RSP)                                                              \
 private:                                                                                                        \
  struct MetaMethodId##CODE : std::type_identity<decltype(CollectMetaMethod(::hf3fs::refl::Rank<128>{}))> {};    \
  static_assert(std::tuple_size_v<typename MetaMethodId##CODE::type> < 128,                                      \
                "Meta method reflection capacity exceeded");                                                     \
  static auto CollectMetaMethod(::hf3fs::refl::Rank<std::tuple_size_v<typename MetaMethodId##CODE::type> + 1>) { \
    if constexpr (std::is_void_v<T>) {                                                                           \
      return ::hf3fs::refl::Append_t<typename MetaMethodId##CODE::type,                                          \
                                     ::hf3fs::serde::MethodInfo<#NAME, T, REQ, RSP, CODE, nullptr>>{};           \
    } else {                                                                                                     \
      return ::hf3fs::refl::Append_t<typename MetaMethodId##CODE::type,                                          \
                                     ::hf3fs::serde::MethodInfo<#NAME, T, REQ, RSP, CODE, &T::NAME>>{};          \
    }                                                                                                            \
  }                                                                                                              \
                                                                                                                 \
 public:                                                                                                         \
  static constexpr std::string_view getRpcName(const REQ &) { return #NAME; }                                    \
  static_assert(serde::SerializableToBytes<REQ> && serde::SerializableToJson<REQ>);                              \
  static_assert(serde::SerializableToBytes<RSP> && serde::SerializableToJson<RSP>)

  META_SERVICE_METHOD(statFs, 1, StatFsReq, StatFsRsp);
  META_SERVICE_METHOD(stat, 2, StatReq, StatRsp);
  META_SERVICE_METHOD(create, 3, CreateReq, CreateRsp);
  META_SERVICE_METHOD(mkdirs, 4, MkdirsReq, MkdirsRsp);
  META_SERVICE_METHOD(symlink, 5, SymlinkReq, SymlinkRsp);
  META_SERVICE_METHOD(hardLink, 6, HardLinkReq, HardLinkRsp);
  META_SERVICE_METHOD(remove, 7, RemoveReq, RemoveRsp);
  META_SERVICE_METHOD(open, 8, OpenReq, OpenRsp);
  META_SERVICE_METHOD(sync, 9, SyncReq, SyncRsp);
  META_SERVICE_METHOD(close, 10, CloseReq, CloseRsp);
  META_SERVICE_METHOD(rename, 11, RenameReq, RenameRsp);
  META_SERVICE_METHOD(list, 12, ListReq, ListRsp);
  // deperated:
  META_SERVICE_METHOD(truncate, 13, TruncateReq, TruncateRsp);
  META_SERVICE_METHOD(getRealPath, 14, GetRealPathReq, GetRealPathRsp);
  META_SERVICE_METHOD(setAttr, 15, SetAttrReq, SetAttrRsp);
  META_SERVICE_METHOD(pruneSession, 16, PruneSessionReq, PruneSessionRsp);
  META_SERVICE_METHOD(dropUserCache, 17, DropUserCacheReq, DropUserCacheRsp);
  META_SERVICE_METHOD(authenticate, 18, AuthReq, AuthRsp);
  META_SERVICE_METHOD(lockDirectory, 19, LockDirectoryReq, LockDirectoryRsp);
  META_SERVICE_METHOD(batchStat, 20, BatchStatReq, BatchStatRsp);
  META_SERVICE_METHOD(batchStatByPath, 21, BatchStatByPathReq, BatchStatByPathRsp);
  META_SERVICE_METHOD(createEcFile, 22, CreateEcFileReq, CreateEcFileRsp);
  META_SERVICE_METHOD(beginEcMutation, 23, BeginEcMutationReq, EcOperationRsp);
  META_SERVICE_METHOD(publishEcMutation, 24, PublishEcMutationReq, EcOperationRsp);
  META_SERVICE_METHOD(getEcOperation, 25, GetEcOperationReq, EcOperationRsp);
  META_SERVICE_METHOD(cancelEcMutation, 26, CancelEcMutationReq, EcOperationRsp);
  META_SERVICE_METHOD(acquireEcRead, 27, AcquireEcReadReq, AcquireEcReadRsp);
  META_SERVICE_METHOD(releaseEcRead, 28, ReleaseEcReadReq, ReleaseEcReadRsp);
  META_SERVICE_METHOD(createEcFileV2, 29, CreateEcFileV2Req, CreateEcFileRsp);
  META_SERVICE_METHOD(beginEcMutationV2, 30, BeginEcMutationV2Req, EcV2MutationRsp);
  META_SERVICE_METHOD(bindEcMutationV2, 31, BindEcMutationV2Req, EcV2MutationRsp);
  META_SERVICE_METHOD(publishEcMutationV2, 32, PublishEcMutationV2Req, EcV2MutationRsp);
  META_SERVICE_METHOD(getEcOperationV2, 33, GetEcOperationV2Req, EcV2MutationRsp);
  META_SERVICE_METHOD(cancelEcMutationV2, 34, CancelEcMutationV2Req, EcV2MutationRsp);
  META_SERVICE_METHOD(acquireEcReadV2, 35, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  META_SERVICE_METHOD(releaseEcReadV2, 36, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  META_SERVICE_METHOD(prepareEcRepairV2, 37, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  META_SERVICE_METHOD(collectEcFragmentV2, 38, CollectEcFragmentV2Req, EcGcAdminRsp);
  META_SERVICE_METHOD(queryEcFragmentGcV2, 39, QueryEcFragmentGcV2Req, EcGcAdminRsp);

  META_SERVICE_METHOD(retireEcRevisionV2, 40, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  META_SERVICE_METHOD(queryEcRevisionRetirementV2, 41, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);

  META_SERVICE_METHOD(describeEcFileV2, 42, DescribeEcFileV2Req, DescribeEcFileV2Rsp);
  META_SERVICE_METHOD(acquireEcRangeV2, 43, AcquireEcRangeV2Req, EcRangeRsp);
  META_SERVICE_METHOD(queryEcRangeV2, 44, QueryEcRangeV2Req, EcRangeRsp);

  META_SERVICE_METHOD(queryEcOwnedMutationV2, 45, QueryEcOwnedMutationV2Req, EcOwnedMutationRsp);
  META_SERVICE_METHOD(openEcFileSession, 46, OpenEcFileSessionReq, OpenEcFileSessionRsp);
  META_SERVICE_METHOD(beginEcFilePwrite, 47, BeginEcFilePwriteReq, EcFilePwriteRsp);
  META_SERVICE_METHOD(queryEcFilePwrite, 48, QueryEcFilePwriteReq, EcFilePwriteRsp);
  META_SERVICE_METHOD(advanceEcFilePwrite, 49, AdvanceEcFilePwriteReq, EcFilePwriteRsp);
  META_SERVICE_METHOD(closeEcFileSession, 51, CloseEcFileSessionReq, CloseEcFileSessionRsp);
  META_SERVICE_METHOD(acquireEcTreeRead, 53, AcquireEcTreeReadReq, EcTreeReadRsp);
  META_SERVICE_METHOD(queryEcTreeRead, 54, QueryEcTreeReadReq, EcTreeReadRsp);
  META_SERVICE_METHOD(releaseEcTreeRead, 55, ReleaseEcTreeReadReq, EcTreeReadRsp);
  META_SERVICE_METHOD(advanceEcTreeReclaim, 60, AdvanceEcTreeReclaimReq, AdvanceEcTreeReclaimRsp);
  META_SERVICE_METHOD(beginEcFileTruncate, 56, BeginEcFileTruncateReq, EcFileTruncateRsp);
  META_SERVICE_METHOD(queryEcFileTruncate, 57, QueryEcFileTruncateReq, EcFileTruncateRsp);
  META_SERVICE_METHOD(advanceEcFileTruncate, 58, AdvanceEcFileTruncateReq, EcFileTruncateRsp);
  META_SERVICE_METHOD(closeEcFileTruncateDebt, 59, CloseEcFileTruncateDebtReq, EcFileTruncateRsp);
  META_SERVICE_METHOD(beginEcFileAppend, 61, BeginEcFileAppendReq, EcFileAppendRsp);
  META_SERVICE_METHOD(queryEcFileAppend, 62, QueryEcFileAppendReq, EcFileAppendRsp);
  META_SERVICE_METHOD(syncEcFileSession, 63, SyncEcFileSessionReq, SyncEcFileSessionRsp);
  META_SERVICE_METHOD(beginEcFileRepair, 64, BeginEcFileRepairReq, EcFileRepairRsp);
  META_SERVICE_METHOD(queryEcFileRepair, 65, QueryEcFileRepairReq, EcFileRepairRsp);
  META_SERVICE_METHOD(advanceEcFileRepair, 66, AdvanceEcFileRepairReq, EcFileRepairRsp);
  META_SERVICE_METHOD(closeEcFileRepairDebt, 67, CloseEcFileRepairDebtReq, EcFileRepairRsp);
  META_SERVICE_METHOD(prepareEcTargetRetirement, 68, PrepareEcTargetRetirementReq, EcTargetRetirementRsp);
  META_SERVICE_METHOD(queryEcTargetRetirement, 69, QueryEcTargetRetirementReq, EcTargetRetirementRsp);
  META_SERVICE_METHOD(prepareEcFileRepairDirect, 70, PrepareEcFileRepairDirectReq, EcFileRepairDirectRsp);

  META_SERVICE_METHOD(testRpc, 50, TestRpcReq, TestRpcRsp);
  META_SERVICE_METHOD(bindEcRmwOutput, 52, BindEcRmwOutputReq, BindEcRmwOutputRsp);

#undef META_SERVICE_METHOD

 private:
  using MetaMethodList = decltype(CollectMetaMethod(::hf3fs::refl::Rank<128>{}));
  static auto CollectField(::hf3fs::refl::Rank<>)->MetaMethodList;
  friend struct ::hf3fs::refl::Helper;
};

}  // namespace hf3fs::meta
