#pragma once

#include "fbs/meta/Service.h"
#include "meta/store/EcV2BindingCatalog.h"

namespace hf3fs::meta::server {

// Transaction core only: the caller authenticates and authorizes the effective
// user, commits on success, and discards on any failure. No physical deletion.
class EcRevisionRetirementCatalog {
 public:
  static CoTryTask<EcRevisionRetirementRsp> retire(kv::IReadWriteTransaction &, const EcRevisionRetirementReq &);
  // Absence is only "no completion observed", never a GC authorization.
  static CoTryTask<EcRevisionRetirementRsp> query(kv::IReadWriteTransaction &, const EcRevisionRetirementReq &);
};

}  // namespace hf3fs::meta::server
