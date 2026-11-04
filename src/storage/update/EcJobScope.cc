#include <algorithm>

#include "storage/store/StorageTarget.h"
#include "storage/update/EcJob.h"

namespace hf3fs::storage {
Result<Void> checkEcJobTarget(const StorageTarget &target,
                              const EcScopeTicket &ticket,
                              uint32_t chain,
                              uint64_t targetId,
                              const Uuid &object) {
  const auto &binding = ticket.binding();
  if (chain != binding.target.chain || targetId != binding.target.target ||
      !std::equal(binding.object.begin(), binding.object.end(), object.data)) {
    return makeError(StatusCode::kTokenMismatch, "EC ticket does not identify this request");
  }
  return target.checkEcScopeTarget(binding.target);
}
}  // namespace hf3fs::storage
