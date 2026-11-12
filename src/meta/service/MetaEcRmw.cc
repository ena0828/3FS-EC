#include <chrono>
#include <folly/ScopeGuard.h>

#include "meta/service/MetaOperator.h"

namespace hf3fs::meta::server {
Result<Void> MetaOperator::initEcRmw() {
  if (!config_.enable_ec_rmw()) return Void{};
  if (!config_.enable_ec_catalog() || !config_.enable_ec_v2() || !config_.authenticate() || !ecRmwStorage_ ||
      config_.ec_rmw_key_file().empty() || config_.ec_rmw_grant_ttl_seconds() == 0 ||
      config_.ec_rmw_grant_ttl_seconds() > 300)
    return makeError(StatusCode::kInvalidConfig, "RMW requires authenticated native V2 and an independent key");
  RETURN_ON_ERROR(ecV2Coordinator_->checkEnabled());
  auto authority = Uuid::fromHexString(config_.ec_rmw_authority());
  if (!authority || authority->is_nil() || *authority != ecV2Coordinator_->authority())
    return makeError(StatusCode::kInvalidConfig, "RMW and scope-control authority must match explicitly");
  auto identities = ecV2Coordinator_->loadedKeyFileIdentities();
  RETURN_ON_ERROR(identities);
  auto v1 = ecCoordinator_->loadedDataKeyFileIdentity();
  RETURN_ON_ERROR(v1);
  identities->push_back(*v1);
  if (config_.enable_ec_exact_gc()) {
    auto g = ecGcAdmin_->loadedKeyFileIdentity();
    RETURN_ON_ERROR(g);
    identities->push_back(*g);
  }
  auto key = storage::EcRmwKey::loadFile(config_.ec_rmw_key_file().string(), *identities);
  RETURN_ON_ERROR(key);
  auto sharedKey = std::shared_ptr<const storage::EcRmwKey>(std::move(*key));
  const auto now = [] {
    return uint64_t(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  };
  auto issuer = EcRmwPlanIssuer::create({*authority, config_.ec_rmw_grant_ttl_seconds(), now},
                                        kvEngine_,
                                        sharedKey,
                                        ecV2Coordinator_->sharedDataKey());
  RETURN_ON_ERROR(issuer);
  auto verifier = EcRmwPublicationVerifier::create(
      {*authority, now, [this](const EcV2PhysicalEndpoint &endpoint) { return ecV2Coordinator_->route(endpoint); }},
      kvEngine_,
      *issuer,
      ecRmwStorage_,
      ecV2Coordinator_->sharedControlKey());
  RETURN_ON_ERROR(verifier);
  auto transport = std::make_shared<storage::client::EcRmwTransport>(config_.ec_rmw_transport());
  RETURN_ON_ERROR(transport->start());
  // All following moves are nonthrowing. afterStop follows ServiceGroup join;
  // initialization has no outstanding calls and never signs on its own.
  ecRmwTransport_ = std::move(transport);
  ecRmwIssuer_ = std::move(*issuer);
  ecRmwVerifier_ = std::move(*verifier);
  return Void{};
}

CoTryTask<BindEcRmwOutputRsp> MetaOperator::bindEcRmwOutput(BindEcRmwOutputReq req) {
  if (!config_.enable_ec_rmw() || !ecRmwIssuer_ || !config_.authenticate())
    co_return makeError(StatusCode::kAuthenticationFail);
  if (stop_) co_return makeError(StorageClientCode::kRequestCanceled);
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  // No user-supplied endpoint or descriptor is trusted here. Both RMW MACs
  // are checked against the committed mode4 plan, then its exact binding and
  // issuance counter commit before any new data credentials leave this call.
  auto issued =
      co_await ecRmwIssuer_->bind(req.object, req.owner, req.child, std::move(req.execution), std::move(req.computed));
  if (!issued) co_return makeError(std::move(issued.error()));
  if (!issued->writes) co_return makeError(StatusCode::kDataCorruption);
  BindEcRmwOutputRsp result;
  result.planDigest = issued->observed.plan->digest();
  result.writes = std::move(*issued->writes);
  co_return result;
}
}  // namespace hf3fs::meta::server
