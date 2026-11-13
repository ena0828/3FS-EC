#pragma once

#include "fbs/storage/EcHelperDirect.h"
#include "storage/ec_repair/EcHelperAuthorization.h"

namespace hf3fs::storage {

Result<EcHelperDirectDelegation> issueEcHelperDirectDelegation(
    const EcHelperKey &,
    const EcRepairPlan &,
    std::array<EcCapabilityV2, 2> appendGrants,
    std::array<EcCapabilityV2, 2> queryGrants,
    uint16_t blockMask,
    uint64_t nowSeconds,
    uint64_t ttlSeconds);

// No-key checks compare public structure/commitments only, never authenticate
// the bearer. Target services must still verify the actual data-capability MAC.
Result<Void> validateEcHelperDirectDelegation(const EcRepairPlan &,
                                              const EcHelperDirectDelegation &,
                                              uint32_t blockIndex);
Result<Void> verifyEcHelperDirectDelegation(const EcHelperKey &,
                                            const EcRepairPlan &,
                                            const EcHelperDirectDelegation &,
                                            uint32_t blockIndex,
                                            uint64_t nowSeconds);
Result<EcSha256> digestEcHelperDirectContext(const EcRepairPlan &, const EcHelperDirectHopReq &);
Result<Void> validateEcHelperDirectRequest(const EcRepairPlan &, const EcHelperDirectHopReq &);
Result<Void> verifyEcHelperDirectPredecessor(const EcHelperKey &,
                                             const EcRepairPlan &,
                                             const EcHelperDirectHopReq &,
                                             uint64_t nowSeconds);
Result<Void> validateEcHelperDirectResult(const EcRepairPlan &,
                                         const EcHelperDirectHopReq &,
                                         const EcHelperDirectHopResult &);
Result<Void> verifyEcHelperDirectResult(const EcHelperKey &,
                                       const EcRepairPlan &,
                                       const EcHelperDirectHopReq &,
                                       const EcHelperDirectHopResult &,
                                       uint64_t nowSeconds);

// Trusted key-holder operations after real source computation / target Append.
// They do not certify local/remote drain, publication or physical GC.
namespace ec_helper_direct_detail {
Result<EcHelperDirectStamp> stamp(const EcHelperKey &,
                                  const EcRepairPlan &,
                                  const EcHelperDirectHopReq &,
                                  const EcHelperPacket &computedPacket,
                                  uint64_t nowSeconds);
Result<EcHelperDirectHopResult> finish(const EcHelperKey &,
                                      const EcRepairPlan &,
                                      const EcHelperDirectHopReq &,
                                      const EcHelperPacket &completePacket,
                                      std::array<EcStageStateV2, 2> appendedStates,
                                      uint64_t nowSeconds);
}  // namespace ec_helper_direct_detail
}  // namespace hf3fs::storage
