#pragma once

#include "fbs/meta/Service.h"
#include "meta/store/EcCatalog.h"

namespace hf3fs::meta::server {
// Authenticated-owner recovery observation. Every operation below is a read in
// the supplied transaction; no commit, grant issuance, Storage RPC or repair.
class EcOwnedMutationCatalog {
 public:
  static CoTryTask<EcOwnedMutationRsp> query(kv::IReadWriteTransaction &,
                                             const QueryEcOwnedMutationV2Req &,
                                             const storage::EcScopeControlKey &historicalControlKey);
};
}  // namespace hf3fs::meta::server
