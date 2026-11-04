#pragma once

#include "common/kv/ITransaction.h"
#include "fbs/meta/Service.h"

namespace hf3fs::meta::server {
struct EcCreateRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(inputPath, PathAt{});
  SERDE_STRUCT_FIELD(gid, flat::Gid{});
  SERDE_STRUCT_FIELD(perm, Permission{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(resolvedParent, InodeId{});
  SERDE_STRUCT_FIELD(name, std::string{});
  SERDE_STRUCT_FIELD(result, CreateEcFileRsp{});
};

// Permanent create identity, separate from the expiring generic Idempotent
// table and from mutable directory entries/permissions. No storage I/O.
class EcCreateCatalog {
 public:
  static CoTryTask<std::optional<EcCreateRecord>> load(kv::IReadWriteTransaction &, const CreateEcFileReq &);
  static CoTryTask<void> store(kv::IReadWriteTransaction &,
                               const CreateEcFileReq &,
                               InodeId parent,
                               std::string name,
                               const CreateEcFileRsp &);
};
}  // namespace hf3fs::meta::server
