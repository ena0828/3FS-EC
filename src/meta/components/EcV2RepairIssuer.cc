#include "meta/components/EcV2RepairIssuer.h"

namespace hf3fs::meta::server {
Result<std::array<storage::EcHelperCapability, 10>> EcV2RepairIssuer::sign(const EcV2RepairPlanRecord &record,
                                                                           const storage::EcHelperKey &key,
                                                                           uint64_t nowSeconds,
                                                                           uint64_t ttlSeconds) {
  CHECK_RESULT(plan, EcV2RepairPlanCatalog::validate(record));
  const auto blocks = plan->blockCount();
  if (!blocks || blocks > 16) return makeError(StatusCode::kInvalidArg, "unsupported helper block count");
  const auto mask = static_cast<uint16_t>((uint32_t{1} << blocks) - 1);
  std::array<storage::EcHelperCapability, 10> result;
  for (uint8_t hop = 0; hop != result.size(); ++hop) {
    CHECK_RESULT(claims, storage::makeEcHelperClaims(*plan, hop, mask, nowSeconds, ttlSeconds));
    CHECK_RESULT(grant, storage::signEcHelperGrant(key, claims, nowSeconds));
    result[hop] = std::move(grant);
  }
  return result;
}
}  // namespace hf3fs::meta::server
