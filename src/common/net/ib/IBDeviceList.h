#pragma once

#include <infiniband/verbs.h>
#include <memory>

#include "common/utils/Result.h"

namespace hf3fs::net::detail {

// Keep the verbs list alive until all selected devices have been opened.
struct IBDeviceList {
  using Get = ibv_device **(*)(int *);
  using Free = void (*)(ibv_device **);
  std::unique_ptr<ibv_device *, Free> devices;
  int count;
};

// Per-call dependencies allow deterministic enumeration tests without changing
// process-wide verbs symbols or exposing a runtime fault-injection setting.
Result<IBDeviceList> loadIBDeviceList(bool allowNoDevices,
                                      IBDeviceList::Get get = ibv_get_device_list,
                                      IBDeviceList::Free free = ibv_free_device_list);

}  // namespace hf3fs::net::detail
