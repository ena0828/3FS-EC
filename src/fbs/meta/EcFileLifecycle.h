#pragma once

#include "fbs/meta/Common.h"
#include "fbs/meta/EcFileMutation.h"
#include "fbs/meta/Schema.h"

namespace hf3fs::meta {
enum class EcFileLifeState : uint8_t { Linked = 1, Unlinked = 2, Retired = 3 };
// This record never authorizes physical deletion. Retired means the live root
// edge was detached, while node/manifest/source/execution holds remain exact.
struct EcFileLifeRecord {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(state, EcFileLifeState::Linked);
  SERDE_STRUCT_FIELD(links, uint16_t{});
  SERDE_STRUCT_FIELD(lastUnlink, Uuid::zero());
  SERDE_STRUCT_FIELD(retiredRoot, (std::optional<EcTreeRoot>{}));
};
enum class EcFileNamespaceAction : uint8_t { Link = 1, Unlink = 2 };
// Tokens and transient transport metadata are intentionally not persisted.
// Authenticated UID/client plus all semantic pathname arguments bind retries.
struct EcFileNamespaceIntent {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(action, EcFileNamespaceAction::Link);
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(oldPath, PathAt{});
  SERDE_STRUCT_FIELD(newPath, PathAt{});
  SERDE_STRUCT_FIELD(flags, AtFlags{});
  SERDE_STRUCT_FIELD(recursive, false);
  SERDE_STRUCT_FIELD(checkType, false);
  SERDE_STRUCT_FIELD(expectedInode, (std::optional<InodeId>{}));
};
struct EcFileNamespaceRecord {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(intent, EcFileNamespaceIntent{});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(parent, InodeId{});
  SERDE_STRUCT_FIELD(name, String{});
  SERDE_STRUCT_FIELD(result, Inode{});
};
}  // namespace hf3fs::meta
