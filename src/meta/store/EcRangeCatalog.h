#pragma once

#include "fbs/meta/Service.h"
#include "meta/store/EcFileAccess.h"

namespace hf3fs::meta::server {
// All operations use the caller's one transaction. No commit, retry, Storage
// access, grant issuance or generic expiring RPC cache occurs in this catalog.
// The service authenticates effective UserInfo before calling it. On any error
// the caller discards the entire transaction, including partially created pins.
class EcRangeCatalog {
 public:
  static CoTryTask<EcRangeRsp> acquire(kv::IReadWriteTransaction &, const EcRangeReq &);
  static CoTryTask<EcRangeRsp> query(kv::IReadWriteTransaction &, const EcRangeReq &);
};
}  // namespace hf3fs::meta::server
