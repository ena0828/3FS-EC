#pragma once

#include "common/kv/ITransaction.h"
#include "fbs/meta/EcFileTree.h"

namespace hf3fs::meta::server {
class EcFileTreeCatalog;
class EcFileTreeGcGuard {
 public:
  // Extra safety condition only. This does not authenticate, authorize GC, or
  // make mode-4 objects acceptable to the legacy mode-3 claim implementation.
  // The absent/zero read conflicts with addHold's write. addHold independently
  // reads permanent claim state, conflicting with a concurrent claim write.
  static CoTryTask<Void> requireUnheld(kv::IReadWriteTransaction &,
                                       const EcObjectRef &,
                                       const storage::EcFragmentIdentity &);

 private:
  friend class EcFileTreeCatalog;
  static CoTryTask<Void> adjust(kv::IReadWriteTransaction &,
                                const EcObjectRef &,
                                const storage::EcFragmentIdentity &,
                                bool increment);
};
}  // namespace hf3fs::meta::server
