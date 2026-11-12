#pragma once

#include "fbs/meta/Service.h"
#include "meta/store/MetaStore.h"

namespace hf3fs::meta::server {
MetaStore::OpPtr<OpenEcFileSessionRsp> makeOpenEcFileSessionOp(MetaStore &, const OpenEcFileSessionReq &);
}  // namespace hf3fs::meta::server
