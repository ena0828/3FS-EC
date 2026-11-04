#pragma once

#include "meta/store/EcV2RepairPlanCatalog.h"
#include "storage/ec_repair/EcHelperAuthorization.h"

namespace hf3fs::meta::server {
class EcV2RepairIssuer {
 public:
  // Internal coordinator method. The supplied record must come from a
  // successfully committed prepare transaction with current permission and
  // issuance-open checks. The record itself is not proof of those checks.
  // A late response from an issuance committed before Closing remains bound
  // to that scope and all its persisted instances; durable denial covers it.
  static Result<std::array<storage::EcHelperCapability, 10>> sign(const EcV2RepairPlanRecord &,
                                                                  const storage::EcHelperKey &,
                                                                  uint64_t nowSeconds,
                                                                  uint64_t ttlSeconds);
};
}  // namespace hf3fs::meta::server
