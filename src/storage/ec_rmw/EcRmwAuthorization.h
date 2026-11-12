#pragma once

#include "EcRmwPlan.h"

namespace hf3fs::meta::server {
class EcRmwPlanIssuer;
}
namespace hf3fs::storage {
namespace ec_rmw_detail {
struct AuthorizationTestAccess;
}
enum class EcRmwRight : uint16_t { Install = 1, Upload = 2, Execute = 4, Observe = 8 };
inline constexpr uint16_t kEcRmwAllRights = 15;
class EcRmwKey final {
 public:
  // The bootstrap caller supplies the identities of ALL other enabled roles,
  // obtained from the same fd as their secrets. Missing role evidence is an
  // init failure at that caller. No data/helper/control/G-key fallback exists.
  static Result<std::unique_ptr<EcRmwKey>> loadFile(const std::filesystem::path &,
                                                    std::span<const EcKeyFileIdentity> otherLoadedRoles);
  EcRmwKey(const EcRmwKey &) = delete;
  EcRmwKey &operator=(const EcRmwKey &) = delete;
  const std::optional<EcKeyFileIdentity> &fileIdentity() const noexcept { return key_->fileIdentity(); }

 private:
  friend class EcRmwAuthorization;
  friend class EcRmwComputationAuthorization;
  friend struct ec_rmw_detail::AuthorizationTestAccess;
  explicit EcRmwKey(std::unique_ptr<EcCapabilityKey> key)
      : key_(std::move(key)) {}
  std::unique_ptr<EcCapabilityKey> key_;
};
struct EcRmwGrantClaims {
  uint16_t version = 1;
  uint16_t rights = 0;
  Uuid authority = Uuid::zero();
  EcSha256 planDigest{};
  EcScopeEndpoint worker;
  Uuid grantId = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};
// Binary Serde is the fixed bounded EcRmwWire codec; readable output is redacted,
// never a permissive reflection of this bearer.
struct EcRmwGrant {
  EcRmwGrantClaims claims;

 private:
  friend class EcRmwWireCodec;
  friend class EcRmwAuthorization;
  friend struct ec_rmw_detail::AuthorizationTestAccess;
  EcSha256 signature_{};
};
class VerifiedEcRmwPlan final {
 public:
  const std::shared_ptr<const EcRmwPlan> &plan() const noexcept { return plan_; }
  EcRmwRight right() const noexcept { return right_; }

 private:
  friend class EcRmwAuthorization;
  VerifiedEcRmwPlan(std::shared_ptr<const EcRmwPlan> plan, EcRmwRight right)
      : plan_(std::move(plan)),
        right_(right) {}
  std::shared_ptr<const EcRmwPlan> plan_;
  EcRmwRight right_;
};
class EcRmwAuthorization final {
 public:
  // Instantaneous authorization only. Execution also requires actual target,
  // route, deadline and irreversible scope-deny/ticket checks after queueing.
  static Result<VerifiedEcRmwPlan> verify(const EcRmwKey &,
                                          const EcRmwGrant &,
                                          std::shared_ptr<const EcRmwPlan>,
                                          const EcScopeEndpoint &actualWorker,
                                          const Uuid &configuredAuthority,
                                          EcRmwRight,
                                          uint64_t nowSeconds);

 private:
  friend class hf3fs::meta::server::EcRmwPlanIssuer;
  friend struct ec_rmw_detail::AuthorizationTestAccess;
  // The sole production friend is the committed-plan Meta issuer, not a
  // generic client or Storage helper. Its fresh transaction must commit first.
  static Result<EcRmwGrant> sign(const EcRmwKey &, EcRmwGrantClaims, uint64_t nowSeconds);
};
}  // namespace hf3fs::storage
