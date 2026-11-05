#pragma once

#include "fbs/storage/EcGcControl.h"

namespace hf3fs::storage {
// RPC28 carries the existing fixed request/ACK. Collect and Query are distinct
// signed actions in one envelope; no wire bool can enable GC or skip auth.
struct EcGcRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcGcAck>{makeError(StorageClientCode::kNotInitialized)}));
};
}  // namespace hf3fs::storage
