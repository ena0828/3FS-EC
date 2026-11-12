#pragma once

#include "fbs/meta/EcFileRange.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/Inode.h"

namespace hf3fs::meta::server {
struct LoadedEcFile {
  Inode inode;
  EcObjectRecord object;
};

// Shared ordinary-request validation. Preserves the existing single-stripe
// semantics, including mode 2. Cleanup queries must not call this liveness/ACL
// path. File-range callers separately require mode-3 birth enrollment.
CoTryTask<LoadedEcFile> loadV2File(kv::IReadWriteTransaction &,
                                   const UserInfo &,
                                   const EcObjectRef &,
                                   std::optional<AccessType>);
CoTryTask<Void> requireTrackedEcFile(kv::IReadWriteTransaction &, const EcObjectRef &);
EcFileState ecFileState(const LoadedEcFile &);
}  // namespace hf3fs::meta::server
