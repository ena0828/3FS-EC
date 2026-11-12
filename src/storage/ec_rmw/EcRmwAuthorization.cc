#include "EcRmwAuthorization.h"

#include <algorithm>

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
Result<Void> valid(const EcRmwGrantClaims &c, uint64_t now) {
  if (c.version != 1 || !c.rights || (c.rights & ~kEcRmwAllRights) || c.authority.is_nil() ||
      c.planDigest == EcSha256{} || c.grantId.is_nil() || c.worker.nodeId == NodeId{} ||
      c.worker.chainId == ChainId{} || c.worker.targetId == TargetId{} || c.worker.engineUuid.is_nil() ||
      c.worker.targetIncarnation.is_nil() || c.issuedAtSeconds > now || c.expiresAtSeconds <= now ||
      c.expiresAtSeconds <= c.issuedAtSeconds || c.expiresAtSeconds - c.issuedAtSeconds > 300)
    return makeError(StatusCode::kAuthenticationFail, "invalid RMW capability");
  return Void{};
}
std::string canonical(const EcRmwGrantClaims &c) {
  std::string out("3FS-RMW-GRANT-v1");
  const auto number = [&](uint64_t v, unsigned width) {
    for (unsigned i = width; i; --i) out.push_back(static_cast<char>(v >> ((i - 1) * 8)));
  };
  number(c.version, 2);
  number(c.rights, 2);
  out.append(c.authority.asStringView());
  out.append(reinterpret_cast<const char *>(c.planDigest.data()), c.planDigest.size());
  number(c.worker.nodeId.toUnderType(), 4);
  number(c.worker.chainId.toUnderType(), 4);
  number(c.worker.targetId.toUnderType(), 8);
  out.append(c.worker.engineUuid.asStringView());
  out.append(c.worker.targetIncarnation.asStringView());
  out.append(c.grantId.asStringView());
  number(c.issuedAtSeconds, 8);
  number(c.expiresAtSeconds, 8);
  return out;
}
}  // namespace
Result<std::unique_ptr<EcRmwKey>> EcRmwKey::loadFile(const std::filesystem::path &path,
                                                     std::span<const EcKeyFileIdentity> others) {
  CHECK_RESULT(key, EcCapabilityKey::loadFile(path));
  if (!key->fileIdentity() || std::find(others.begin(), others.end(), *key->fileIdentity()) != others.end())
    return makeError(StatusCode::kInvalidConfig, "RMW requires a distinct explicitly loaded role key");
  return std::unique_ptr<EcRmwKey>(new EcRmwKey(std::move(key)));
}
Result<EcRmwGrant> EcRmwAuthorization::sign(const EcRmwKey &key, EcRmwGrantClaims claims, uint64_t now) {
  RETURN_ON_ERROR(valid(claims, now));
  const auto bytes = canonical(claims);
  CHECK_RESULT(
      mac,
      ec_authorization_detail::Access::authenticate(*key.key_,
                                                    {reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
  EcRmwGrant grant;
  grant.claims = std::move(claims);
  grant.signature_ = mac;
  return grant;
}
Result<VerifiedEcRmwPlan> EcRmwAuthorization::verify(const EcRmwKey &key,
                                                     const EcRmwGrant &grant,
                                                     std::shared_ptr<const EcRmwPlan> plan,
                                                     const EcScopeEndpoint &actualWorker,
                                                     const Uuid &authority,
                                                     EcRmwRight right,
                                                     uint64_t now) {
  RETURN_ON_ERROR(valid(grant.claims, now));
  const auto required = static_cast<uint16_t>(right);
  if (!plan || (required != 1 && required != 2 && required != 4 && required != 8) ||
      !(grant.claims.rights & required) || authority.is_nil() || grant.claims.authority != authority ||
      grant.claims.planDigest != plan->digest() || !ec_rmw_detail::sameEndpoint(grant.claims.worker, actualWorker) ||
      !ec_rmw_detail::sameEndpoint(plan->worker(), actualWorker))
    return makeError(StatusCode::kAuthenticationFail, "RMW capability does not authorize the exact plan/worker");
  const auto bytes = canonical(grant.claims);
  CHECK_RESULT(
      mac,
      ec_authorization_detail::Access::authenticate(*key.key_,
                                                    {reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
  if (!ec_authorization_detail::Access::constantTimeEqual(mac, grant.signature_))
    return makeError(StatusCode::kAuthenticationFail, "RMW capability MAC differs");
  return VerifiedEcRmwPlan(std::move(plan), right);
}
}  // namespace hf3fs::storage
