#pragma once

#include "client/storage/EcRmwTransport.h"
#include "fbs/storage/EcRmwRpc.h"
#include "storage/ec_rmw/EcRmwRuntime.h"

namespace hf3fs::storage::ec_rmw_detail {
// Test-only access: no production loader or metadata publication is bypassed
// by service code. Private memory IO below tests arithmetic/ownership, not ACL.
struct AuthorizationTestAccess {
  static std::shared_ptr<const EcRmwKey> key() {
    std::array<uint8_t, 32> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = uint8_t(i + 73);
    return std::shared_ptr<const EcRmwKey>(
        new EcRmwKey(std::make_unique<EcCapabilityKey>(std::span<const uint8_t, 32>(bytes))));
  }
  static Result<EcRmwComputedCommitment> computed(const EcRmwKey &key,
                                                  const EcRmwPlan &plan,
                                                  const EcRmwOutputCommitment &out) {
    return EcRmwComputationAuthorization::sign(key, plan, out);
  }
  static Result<EcRmwGrant> grant(const EcRmwKey &key,
                                  const EcRmwPlan &plan,
                                  uint16_t rights = kEcRmwAllRights,
                                  uint64_t now = 1000) {
    EcRmwGrantClaims c;
    c.rights = rights;
    c.authority = Uuid::from(91, 92);
    c.planDigest = plan.digest();
    c.worker = plan.worker();
    c.grantId = Uuid::from(93, 94);
    c.issuedAtSeconds = now;
    c.expiresAtSeconds = now + 100;
    return EcRmwAuthorization::sign(key, c, now);
  }
};
struct RuntimeTestAccess {
  static Result<Void> install(EcRmwRuntime &runtime,
                              std::shared_ptr<const EcRmwPlan> plan,
                              const EcRmwGrant &grant,
                              std::shared_ptr<EcRmwIo> io) {
    return runtime.installInternal(std::move(plan), grant, std::move(io));
  }
};
inline EcRmwPlanInput zeroPlan(std::string_view patch, uint32_t shardBytes = 65536) {
  EcRmwPlanInput p;
  p.inode = 10;
  p.object = Uuid::from(1, 2);
  p.birth = Uuid::from(3, 4);
  p.planId = Uuid::from(5, 6);
  p.sessionId = Uuid::from(7, 8);
  p.parentId = Uuid::from(9, 10);
  p.operationId = Uuid::from(11, 12);
  p.ownerUid = flat::Uid(123);
  p.clientNamespace = Uuid::from(13, 14);
  p.fenceEpoch = 1;
  p.sourceSequence = 1;
  p.shardBytes = shardBytes;
  p.patchOffset = 3;
  p.patchLength = patch.size();
  p.patchSha256 = *sha256(patch);
  p.targetLogicalLength = p.patchOffset + p.patchLength;
  p.targetGeneration = 1;
  p.targetRevision = 1;
  for (size_t i = 0; i < 12; ++i) {
    auto &t = p.targets[i];
    t.identity.object = p.object;
    t.identity.generation = 1;
    t.identity.shard = i;
    t.identity.allocation = Uuid::from(100 + i, 1);
    t.endpoint = {NodeId(1), ChainId(100 + i), TargetId(200 + i), Uuid::from(300 + i, 1), Uuid::from(400 + i, 1)};
  }
  return p;
}
}  // namespace hf3fs::storage::ec_rmw_detail
