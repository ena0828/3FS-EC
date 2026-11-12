#include "EcRmwResources.h"

#include <folly/ScopeGuard.h>

namespace hf3fs::storage {
EcRmwJobLease::~EcRmwJobLease() { resources_->budget_.signal(); }
Result<std::shared_ptr<EcRmwJobLease>> EcRmwResources::acquire() {
  auto session = sessions_->acquire();
  if (!session) return makeError(std::move(session.error()));
  if (!budget_.try_wait()) return makeError(StorageClientCode::kResourceBusy, "RMW job reservation is full");
  auto restore = folly::makeGuard([this] { budget_.signal(); });
  auto lease = std::unique_ptr<EcRmwJobLease>(new EcRmwJobLease(shared_from_this(), std::move(*session)));
  // After construction the lease owns the permit, including a later shared
  // control-block allocation failure. Do not also signal from this guard.
  restore.dismiss();
  return std::shared_ptr<EcRmwJobLease>(std::move(lease));
}
}  // namespace hf3fs::storage
