#include <folly/experimental/coro/WithCancellation.h>

#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
Result<Void> StorageOperator::initEcGc() {
  if (!config_.enable_ec_gc()) return Void{};
  if (!config_.enable_ec_fragments() || !components_.config.targets().ec_staging_v2() ||
      !components_.config.targets().ec_exact_gc() || !components_.getEcCapabilityKey())
    return makeError(StatusCode::kInvalidConfig, "GC requires explicit format3 EC storage and a loaded data key");
  CHECK_RESULT(authority, Uuid::fromHexString(config_.ec_gc_authority()));
  CHECK_RESULT(keyId, Uuid::fromHexString(config_.ec_gc_key_id()));
  if (authority.is_nil() || keyId.is_nil() || config_.ec_gc_key_file().empty())
    return makeError(StatusCode::kInvalidConfig, "GC requires an explicit G file, key ID and authority");
  std::vector<EcGcRoleFileIdentity> otherRoles;
  const auto add = [&](const std::optional<EcKeyFileIdentity> &identity) -> Result<Void> {
    if (!identity) return makeError(StatusCode::kInvalidConfig, "enabled EC role has no loaded-fd file identity");
    otherRoles.push_back({identity->device, identity->inode});
    return Void{};
  };
  RETURN_ON_ERROR(add(components_.getEcCapabilityKey()->fileIdentity()));
  if (config_.enable_ec_scope_control()) RETURN_ON_ERROR(add(ecControlKeyFileIdentity_));
  if (config_.enable_ec_helpers()) RETURN_ON_ERROR(add(ecHelperKeyFileIdentity_));
  CHECK_RESULT(key, EcGcKey::loadFile(std::filesystem::path(config_.ec_gc_key_file().string()), keyId, otherRoles));
  auto shared = std::shared_ptr<const EcGcKey>(std::move(key));
  CHECK_RESULT(executor,
               EcGcExecutor::create(shared, authority, components_.appInfo.nodeId, ecAuthorizationNow_, [this] {
                 return config_.read_only();
               }));
  ecGc_ = std::move(executor);
  return Void{};
}

CoTryTask<EcGcRsp> StorageOperator::exchangeEcGc(const EcGcRequest &request) {
  EcGcRsp response;
  if (!ecGc_) {
    response.result = makeError(StatusCode::kAuthenticationFail, "GC RPC requires explicit G authority and format3");
    co_return response;
  }
  if (request.claims.action == EcGcAction::Collect && config_.read_only()) {
    response.result = makeError(StatusCode::kReadOnlyMode);
    co_return response;
  }
  const auto &endpoint = request.claims.certificate.endpoint;
  auto found = components_.targetMap.getByTargetId(endpoint.targetId);
  if (!found || !(*found)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid, "exact claimed GC target is not loaded");
    co_return response;
  }
  // Lookup never registers an identity or replaces the signed instance. The
  // dedicated executor checks the actual loaded target and MAC before enqueue
  // and again immediately before the same-handle Rust GC operation.
  auto actual = (*found)->storageTarget;
  response.result =
      co_await folly::coro::co_withCancellation({}, ecGc_->execute(request.claims.action, request, actual));
  if (response.result) {
    auto current = components_.targetMap.getByTargetId(endpoint.targetId);
    if (!current || (*current)->storageTarget != actual)
      response.result =
          makeError(StorageCode::kEcSealOutcomeUnknown, "GC confirmed on owned instance but loaded target map changed");
  }
  co_return response;
}
}  // namespace hf3fs::storage
