#pragma once

#include "fbs/storage/EcHelper.h"
#include "storage/ec_repair/EcRepairPlan.h"

namespace hf3fs::storage {

class EcHelperKey final {
 public:
  static Result<std::unique_ptr<EcHelperKey>> loadFile(const std::filesystem::path &path);
  EcHelperKey(const EcHelperKey &) = delete;
  EcHelperKey &operator=(const EcHelperKey &) = delete;

 private:
  friend struct ec_helper_detail::Access;
  explicit EcHelperKey(std::unique_ptr<EcCapabilityKey> key)
      : key_(std::move(key)) {}
  std::unique_ptr<EcCapabilityKey> key_;
};

Result<EcHelperCapability> signEcHelperGrant(const EcHelperKey &, const EcHelperClaims &, uint64_t nowSeconds);
Result<Void> verifyEcHelperGrant(const EcHelperKey &,
                                 const EcHelperCapability &,
                                 const EcRepairPlan &,
                                 const EcScopeEndpoint &actualRecipient,
                                 uint8_t helperPosition,
                                 uint32_t blockIndex,
                                 uint64_t nowSeconds);
// Scope, owner, complete endpoint set and all allocation/integrity commitments
// are included through planDigest. No authority is derived from a client UID.
Result<EcHelperClaims> makeEcHelperClaims(const EcRepairPlan &,
                                          uint8_t helperPosition,
                                          uint16_t blockMask,
                                          uint64_t nowSeconds,
                                          uint64_t ttlSeconds);

EcHelperPacket helperPacket(EcRepairBlock block);
EcRepairBlock repairBlock(EcHelperPacket packet);
Result<Void> verifyEcHelperPredecessor(const EcHelperKey &,
                                       const EcRepairPlan &,
                                       const EcHelperPacket &,
                                       const EcHelperStamp &,
                                       uint8_t recipientPosition,
                                       uint64_t nowSeconds);
Result<Void> verifyEcHelperFinal(const EcHelperKey &,
                                 const EcRepairPlan &,
                                 const EcHelperHopResult &,
                                 uint64_t nowSeconds);

// Internal key-holder API, called after actual source-byte verification and
// contribution computation. It is not a generic public proof-of-execution API.
// Every key holder remains inside the trusted Storage/Meta security boundary.
namespace ec_helper_detail {
Result<EcHelperStamp> stamp(const EcHelperKey &,
                            const EcRepairPlan &,
                            const EcHelperPacket &,
                            uint64_t nowSeconds,
                            uint64_t expiresAtSeconds);
}

}  // namespace hf3fs::storage
