#include "IBDeviceList.h"

#include <cerrno>
#include <folly/logging/xlog.h>

namespace hf3fs::net::detail {

Result<IBDeviceList> loadIBDeviceList(bool allowNoDevices, IBDeviceList::Get get, IBDeviceList::Free free) {
  int count = 0;
  auto raw = get(&count);
  const int error = errno;
  IBDeviceList result{{raw, free}, count};
  if (raw == nullptr) {
    // ENOSYS means that the kernel has no RDMA support. Permission, memory,
    // provider, and unexpected failures must still fail even in TCP-only labs.
    if (allowNoDevices && error == ENOSYS) {
      XLOGF(WARN, "Kernel has no RDMA support; allow_no_usable_devices is enabled.");
      result.count = 0;
      return std::move(result);
    }
    XLOGF(ERR, "Failed to load verbs device list, errno {}", error);
    return makeError(RPCCode::kIBInitFailed, "Failed to load verbs devices.");
  }
  if (count < 0) {
    return makeError(RPCCode::kIBInitFailed, "Invalid verbs device count.");
  }
  if (count == 0) {
    XLOGF(WARN, "No RDMA devices found.");
    if (!allowNoDevices) {
      return makeError(RPCCode::kIBInitFailed, "No usable RDMA devices.");
    }
  }
  return std::move(result);
}

}  // namespace hf3fs::net::detail
