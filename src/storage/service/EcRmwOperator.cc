#include <algorithm>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/WithCancellation.h>

#include "storage/ec_rmw/NativeEcRmwOutputBinder.h"
#include "storage/ec_scope/EcScopeLoadBudget.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"
#include "storage/update/EcAdmissionJob.h"

namespace hf3fs::storage {
namespace {
uint64_t rmwMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}
Uuid rmwUuid(const std::array<uint8_t, 16> &b) {
  Uuid u = Uuid::zero();
  std::copy(b.begin(), b.end(), std::begin(u.data));
  return u;
}
std::array<uint8_t, 16> rmwBytes(const Uuid &u) {
  std::array<uint8_t, 16> b{};
  std::copy(std::begin(u.data), std::end(u.data), b.begin());
  return b;
}
Result<VersionedChainId> rmwRoute(hf3fs::client::ICommonMgmtdClient &mgmtd, const EcScopeEndpoint &endpoint) {
  auto routing = mgmtd.getRoutingInfo();
  if (!routing || !routing->raw()) return makeError(StorageClientCode::kRoutingError);
  const auto *chain = routing->raw()->getChain(endpoint.chainId);
  const auto *target = routing->raw()->getTarget(endpoint.targetId);
  const auto *node = routing->raw()->getNode(endpoint.nodeId);
  if (!chain || !target || !node || chain->targets.size() != 1 ||
      chain->targets.front().targetId != endpoint.targetId ||
      chain->targets.front().publicState != flat::PublicTargetState::SERVING ||
      target->publicState != flat::PublicTargetState::SERVING || target->chainId != endpoint.chainId ||
      !target->nodeId || *target->nodeId != endpoint.nodeId || node->type != flat::NodeType::STORAGE ||
      node->status != flat::NodeStatus::HEARTBEAT_CONNECTED)
    return makeError(StorageClientCode::kRoutingError);
  return VersionedChainId{endpoint.chainId, chain->chainVersion};
}
Result<net::Address> rmwMeta(hf3fs::client::ICommonMgmtdClient &mgmtd) {
  auto routing = mgmtd.getRoutingInfo();
  if (!routing) return makeError(StorageClientCode::kRoutingError);
  for (const auto &node : routing->getNodeBy([](const auto &n) {
         return n.type == flat::NodeType::META && n.status == flat::NodeStatus::HEARTBEAT_CONNECTED;
       }))
    for (const auto &group : node.app.serviceGroups)
      if (group.services.contains("MetaSerde"))
        for (const auto &address : group.endpoints)
          if (address.type == net::Address::TCP) return address;
  return makeError(StorageClientCode::kRoutingError);
}
Result<EcRmwStatus> rmwStatus(Result<EcRmwObservation> observed) {
  if (!observed) return makeError(std::move(observed.error()));
  EcRmwStatus out;
  out.planId = observed->planId;
  out.planDigest = observed->planDigest;
  out.state = static_cast<uint8_t>(observed->state);
  out.receivedBlocks = observed->received.count();
  out.executionError = observed->error;
  return out;
}
}  // namespace
Result<Void> StorageOperator::initEcRmw() {
  if (!config_.enable_ec_rmw()) return Void{};
  if (!config_.enable_ec_fragments() || !config_.enable_ec_scope_control() ||
      !components_.config.targets().ec_staging_v2() || !components_.config.targets().ec_exact_gc() ||
      !components_.getEcCapabilityKey() || config_.ec_rmw_key_file().empty())
    return makeError(StatusCode::kInvalidConfig, "RMW requires explicit format3, scope control and data authorization");
  auto authority = Uuid::fromHexString(config_.ec_rmw_authority());
  auto controlAuthority = Uuid::fromHexString(config_.ec_scope_control_authority());
  if (!authority || authority->is_nil() || !controlAuthority || *controlAuthority != *authority)
    return makeError(StatusCode::kInvalidConfig, "RMW and scope authority differ");
  std::vector<EcKeyFileIdentity> roles;
  const auto add = [&](const std::optional<EcKeyFileIdentity> &id) -> Result<Void> {
    if (!id) return makeError(StatusCode::kInvalidConfig, "enabled role lacks loaded-fd identity");
    roles.push_back(*id);
    return Void{};
  };
  RETURN_ON_ERROR(add(components_.getEcCapabilityKey()->fileIdentity()));
  RETURN_ON_ERROR(add(ecControlKeyFileIdentity_));
  if (config_.enable_ec_helpers()) RETURN_ON_ERROR(add(ecHelperKeyFileIdentity_));
  if (config_.enable_ec_gc()) RETURN_ON_ERROR(add(ecGcKeyFileIdentity_));
  auto key = EcRmwKey::loadFile(config_.ec_rmw_key_file().string(), roles);
  RETURN_ON_ERROR(key);
  auto sharedKey = std::shared_ptr<const EcRmwKey>(std::move(*key));
  auto mgmtd = components_.mgmtdClient.load();
  if (!mgmtd) return makeError(StatusCode::kInvalidConfig);
  auto storage = client::StorageClient::create(ClientId::random(), config_.ec_rmw_client(), *mgmtd);
  RETURN_ON_ERROR(storage->start());
  auto closeStorage = folly::makeGuard([&] { storage->stop(); });
  auto transport = std::make_shared<client::EcRmwTransport>(config_.ec_rmw_transport());
  RETURN_ON_ERROR(transport->start());
  auto closeTransport = folly::makeGuard([&] { transport->stopAndJoin(); });
  auto resources = EcRmwResources::create();
  auto runtime =
      EcRmwRuntime::create(sharedKey, *authority, components_.appInfo.nodeId, [this] { return ecAuthorizationNow_(); });
  RETURN_ON_ERROR(runtime);
  // No throwing operation follows the thread's transfer into application ownership.
  closeTransport.dismiss();
  closeStorage.dismiss();
  ecRmwKey_ = std::move(sharedKey);
  ecRmwAuthority_ = *authority;
  ecRmwMgmtd_ = std::move(mgmtd);
  ecRmwStorage_ = std::move(storage);
  ecRmwTransport_ = std::move(transport);
  ecRmwResources_ = std::move(resources);
  ecRmw_ = std::move(*runtime);
  return Void{};
}
CoTryTask<EcRmwStatusRsp> StorageOperator::installEcRmw(const EcRmwInstallReq &wire) {
  EcRmwStatusRsp out;
  if (!ecRmw_) {
    out.result = makeError(StatusCode::kAuthenticationFail);
    co_return out;
  }
  try {
    out.result = co_await folly::coro::co_withCancellation({}, installEcRmwOwned(wire));
  } catch (const std::bad_alloc &) {
    out.result = makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    out.result = makeError(StatusCode::kIOError);
  }
  co_return out;
}
CoTryTask<EcRmwStatus> StorageOperator::installEcRmwOwned(EcRmwInstallReq req) {
  const auto received = std::chrono::steady_clock::now();
  const auto wall = rmwMillis();
  if (req.deadlineUnixMillis <= wall || req.deadlineUnixMillis - wall > 300000)
    co_return makeError(StorageClientCode::kTimeout);
  if (config_.read_only()) co_return makeError(StatusCode::kReadOnlyMode);
  auto planResult = EcRmwPlan::create(req.plan.input);
  CO_RETURN_ON_ERROR(planResult);
  auto plan = std::move(*planResult);
  if ((plan->input().sourceKind == EcRmwSourceKind::Data) != req.reads.has_value())
    co_return makeError(StatusCode::kAuthenticationFail);
  auto prepare = ecRmw_->prepareInstall(plan, req.grant);
  CO_RETURN_ON_ERROR(prepare);
  if (!*prepare) co_return rmwStatus(ecRmw_->query(plan->input().planId, req.grant));
  auto lease = ecRmwResources_->acquire();
  CO_RETURN_ON_ERROR(lease);
  auto version = rmwRoute(*ecRmwMgmtd_, plan->worker());
  CO_RETURN_ON_ERROR(version);
  auto selected = ecTarget(*version, plan->worker().targetId, false);
  CO_RETURN_ON_ERROR(selected);
  auto target = *selected;
  if (!target->storageTarget->usesEcStagingEngine()) co_return makeError(StorageCode::kTargetStateInvalid);
  auto scope = target->storageTarget->ecScopeState();
  CO_RETURN_ON_ERROR(scope);
  const auto identity = scope->second;
  const EcScopeEndpoint actual{components_.appInfo.nodeId,
                               target->vChainId.chainId,
                               target->targetId,
                               rmwUuid(identity.engine),
                               rmwUuid(identity.incarnation)};
  client::EcRequestControl control;
  control.transport = client::EcRequestControl::TransportPolicy::TcpOnly;
  control.deadline = received + std::chrono::milliseconds(req.deadlineUnixMillis - wall);
  const auto validate = [this, target, identity, actual, plan, grant = req.grant, control]() -> Result<Void> {
    if (config_.read_only()) return makeError(StatusCode::kReadOnlyMode);
    if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
    RETURN_ON_ERROR(validateEcTarget(target, false));
    RETURN_ON_ERROR(target->storageTarget->checkEcScopeTarget(identity));
    RETURN_ON_ERROR(EcRmwAuthorization::verify(*ecRmwKey_,
                                               grant,
                                               plan,
                                               actual,
                                               ecRmwAuthority_,
                                               EcRmwRight::Install,
                                               ecAuthorizationNow_()));
    return Void{};
  };
  CO_RETURN_ON_ERROR(validate());
  EcScopeBinding binding{};
  binding.target = identity;
  binding.object = rmwBytes(plan->input().object);
  binding.kind = 2;
  binding.scope = rmwBytes(plan->input().operationId);
  binding.owner_uid = plan->input().ownerUid.toUnderType();
  binding.client_namespace = rmwBytes(plan->input().clientNamespace);
  auto session = updateWorker_.acquireEcSession();
  CO_RETURN_ON_ERROR(session);
  const EcScopeLoadBudget budget{config_.ec_scope_load_wait_ms(), received, control.deadline};
  const auto expires = req.grant.claims.expiresAtSeconds;
  EcAdmissionJob admission(binding, scope->first, *session, target->storageTarget, validate, [this, budget, expires] {
    return budget.remaining(EcScopeLoadBudget::Clock::now(), expires, ecAuthorizationNow_());
  });
  co_await folly::coro::co_withCancellation({}, updateWorker_.enqueue(&admission));
  co_await folly::coro::co_withCancellation({}, admission.complete());
  auto ticket = admission.takeTicket();
  CO_RETURN_ON_ERROR(ticket);
  CO_RETURN_ON_ERROR(validate());
  auto mgmtd = ecRmwMgmtd_;
  auto binder = std::make_shared<NativeEcRmwOutputBinder>(
      ecRmwTransport_,
      [mgmtd] { return rmwMeta(*mgmtd); },
      req.grant);
  auto io = NativeEcRmwIo::create(
      plan,
      req.grant,
      ecRmwKey_,
      components_.sharedEcCapabilityKey(),
      ecRmwAuthority_,
      actual,
      target->storageTarget,
      std::move(*ticket),
      std::move(*lease),
      ecRmwStorage_,
      req.reads.value_or(std::array<EcCapabilityV2, 12>{}),
      std::move(binder),
      [mgmtd](const EcScopeEndpoint &endpoint) { return rmwRoute(*mgmtd, endpoint); },
      [this] { return ecAuthorizationNow_(); },
      validate,
      control);
  CO_RETURN_ON_ERROR(io);
  CO_RETURN_ON_ERROR(ecRmw_->install(plan, req.grant, std::move(*io)));
  co_return rmwStatus(ecRmw_->query(plan->input().planId, req.grant));
}
CoTryTask<EcRmwStatusRsp> StorageOperator::putEcRmw(const EcRmwPutReq &req) {
  EcRmwStatusRsp out;
  if (!ecRmw_) {
    out.result = makeError(StatusCode::kAuthenticationFail);
    co_return out;
  }
  if (config_.read_only()) {
    out.result = makeError(StatusCode::kReadOnlyMode);
    co_return out;
  }
  auto put = ecRmw_->put(req.planId, req.grant, req.blockIndex, req.payload.data);
  out.result =
      put ? rmwStatus(ecRmw_->query(req.planId, req.grant)) : Result<EcRmwStatus>(makeError(std::move(put.error())));
  co_return out;
}
CoTryTask<EcRmwStatusRsp> StorageOperator::actionEcRmw(const EcRmwActionReq &req) {
  EcRmwStatusRsp out;
  if (!ecRmw_) {
    out.result = makeError(StatusCode::kAuthenticationFail);
    co_return out;
  }
  if (req.action == EcRmwActionRequest::Query)
    out.result = rmwStatus(ecRmw_->query(req.planId, req.grant));
  else if (req.action == EcRmwActionRequest::Submit) {
    if (config_.read_only())
      out.result = makeError(StatusCode::kReadOnlyMode);
    else
      out.result = rmwStatus(ecRmw_->submit(req.planId, req.grant));
  } else
    out.result = makeError(StatusCode::kInvalidArg);
  co_return out;  // Submission never waits for nested network/compute work.
}
}  // namespace hf3fs::storage
