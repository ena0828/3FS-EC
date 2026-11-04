#pragma once

#include "meta/store/Inode.h"

namespace hf3fs::meta::server {

// Temporary namespace boundary until EC unlink/hardlink/GC are integrated.
// All mutations must share the namespace operation's transaction. Discard that
// transaction on any error, including errors after a helper has returned success.
class EcNamespaceGuard {
 public:
  static CoTryTask<void> registerFile(IReadWriteTransaction &txn, const Inode &file, InodeId parent);
  static CoTryTask<uint64_t> subtreeCount(IReadWriteTransaction &txn, InodeId directory);
  static CoTryTask<void> checkRemove(IReadWriteTransaction &txn, InodeId directory);
  static CoTryTask<void> moveDirectory(IReadWriteTransaction &txn, const Inode &directory, InodeId newParent);
};

}  // namespace hf3fs::meta::server
