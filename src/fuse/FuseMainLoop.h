#pragma once

#include "common/utils/String.h"

namespace hf3fs::fuse {
// Application boundary only: no ordinary/global/session teardown follows an
// unconfirmed local join. Persistent EC request identities remain on disk.
struct FuseClients;
void checkedFuseShutdownOrExit(FuseClients &) noexcept;
void checkedFuseShutdownOrExit() noexcept;
int fuseMainLoop(const String &programName,
                 bool allowOther,
                 const String &mountpoint,
                 size_t maxbufsize,
                 const String &clusterId);
}  // namespace hf3fs::fuse
