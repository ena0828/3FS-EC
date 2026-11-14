#include <algorithm>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/Sleep.h>

#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_repair/EcHelperDirectAuthorization.h"
#include "storage/ec_scope/EcScopeLoadBudget.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
namespace {
uint64_t directWallMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}
Uuid directUuid(const std::array<uint8_t, 16> &value) {
  auto out = Uuid::zero();
  std::copy(value.begin(), value.end(), std::begin(out.data));
  return out;
}
std::array<uint8_t, 16> directBytes(const Uuid &value) {
  std::array<uint8_t, 16> out{};
  std::copy(std::begin(value.data), std::end(value.data), out.begin());
  return out;
}
Result<net::Address> directAddress(const hf3fs::client::RoutingInfo &routing,
                                   const EcScopeEndpoint &endpoint,
                                   ChainVer version,
                                   net::Address::Type transportType) {
  const auto node = routing.getNode(endpoint.nodeId);
  const auto target = routing.getTarget(endpoint.targetId);
  const auto chain = routing.getChain(endpoint.chainId);
  if (!node || node->type != flat::NodeType::STORAGE || node->status != flat::NodeStatus::HEARTBEAT_CONNECTED ||
      !target || target->nodeId != endpoint.nodeId || target->chainId != endpoint.chainId ||
      target->publicState != flat::PublicTargetState::SERVING || !chain || chain->chainVersion != version ||
      std::none_of(chain->targets.begin(), chain->targets.end(), [&](const auto &member) {
        return member.targetId == endpoint.targetId && member.publicState == flat::PublicTargetState::SERVING;
      }))
    return makeError(StorageClientCode::kRoutingVersionMismatch);
  for (const auto &group : node->app.serviceGroups)
    if (group.services.contains("StorageSerde"))
      for (const auto &address : group.endpoints)
        if (address.type == transportType) return address;
  return makeError(StorageClientCode::kRoutingError);
}
EcFragmentAccessV2 directAccess(const EcRepairFragment &fragment, ChainVer version) {
  EcFragmentAccessV2 access;
  access.identity = fragment.identity;
  access.operationId = fragment.operationId;
  access.vChainId = {fragment.endpoint.chainId, version};
  access.targetId = fragment.endpoint.targetId;
  access.integrity = fragment.integrity;
  return access;
}
auto directUnknown() {
  return makeError(StorageCode::kEcSealOutcomeUnknown);
}
}  // namespace

CoTryTask<EcHelperDirectHopRsp> StorageOperator::executeEcHelperDirect(const EcHelperDirectHopReq &request,
                                                                     net::Address::Type transportType) {
  const auto receivedAt = std::chrono::steady_clock::now();
  EcHelperDirectHopRsp response;
  if (transportType != net::Address::TCP && transportType != net::Address::RDMA) {
    response.result = makeError(StatusCode::kInvalidArg, "direct helper requires explicit TCP or RDMA ingress");
    co_return response;
  }
  if (!ecHelpers_) {
    response.result = makeError(StatusCode::kAuthenticationFail);
    co_return response;
  }
  if (request.packet.nextHelper >= 10 || request.packet.blockIndex >= 16 ||
      request.packet.outputs[0].data.size() > kEcIntegrityBlockBytes ||
      request.packet.outputs[1].data.size() > kEcIntegrityBlockBytes) {
    response.result = makeError(StatusCode::kInvalidArg);
    co_return response;
  }
  auto session = ecHelpers_->sessions->acquire();
  if (!session) {
    response.result = makeError(session.error());
    co_return response;
  }
  if (!ecHelpers_->budget.try_wait()) {
    response.result = makeError(StorageClientCode::kResourceBusy);
    co_return response;
  }
  auto release = folly::makeGuard([this] { ecHelpers_->budget.signal(); });
  try {
    // Copy only after bounded admission. A network waiter disappearing cannot
    // cancel these owned frames or destroy their tickets while a child runs.
    response.result = co_await folly::coro::co_withCancellation(
        CancellationToken{}, executeEcHelperDirectOwned(request, receivedAt, transportType).scheduleOn(&ecHelpers_->executor));
  } catch (...) {
    // Includes construction/await/response failures outside the owned body.
    // Conservatively retain uncertainty even if this particular copy failed early.
    response.result = directUnknown();
  }
  co_return response;
}

CoTryTask<EcHelperDirectHopResult> StorageOperator::executeEcHelperDirectOwned(
    EcHelperDirectHopReq request,
    std::chrono::steady_clock::time_point receivedAt,
    net::Address::Type transportType) {
  bool dispatchedMutation = false;
  // The stored closure and all referenced locals outlive this immediately joined
  // task. No callback, borrowed request, or observer is handed to background work.
  auto run = [&]() -> CoTryTask<EcHelperDirectHopResult> {
    auto made = EcRepairPlan::create(request.plan);
    CO_RETURN_ON_ERROR(made);
    auto plan = std::move(*made);
    CO_RETURN_ON_ERROR(validateEcHelperDirectRequest(*plan, request));
    const auto position = request.packet.nextHelper;
    const auto block = request.packet.blockIndex;
    const auto wall = directWallMillis();
    if (request.deadlineUnixMillis <= wall || request.deadlineUnixMillis - wall > 60000)
      co_return makeError(StorageClientCode::kTimeout);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(request.deadlineUnixMillis - wall);
    const auto &source = plan->input().sources[position];
    EcReadBlockV2Req read;
    read.request = directAccess(source, request.sourceRouteVersions[position]);
    read.blockIndex = block;
    read.grant = request.reads[position];
    const auto &claims = read.grant.claims;
    if (claims.scopeKind != EcGrantScope::WriteOperation || claims.scopeId != plan->input().operationId ||
        claims.scopeObject != source.identity.object || claims.ownerUid != plan->input().ownerUid ||
        claims.clientNamespace != plan->input().clientNamespace)
      co_return makeError(StatusCode::kAuthenticationFail);
    auto selected = ecTarget(read.request.vChainId, source.endpoint.targetId, false);
    CO_RETURN_ON_ERROR(selected);
    auto target = *selected;
    if (!target->storageTarget->usesEcStagingEngine()) co_return makeError(StorageCode::kTargetStateInvalid);
    auto scope = target->storageTarget->ecScopeState();
    CO_RETURN_ON_ERROR(scope);
    const auto identity = scope->second;
    const EcScopeEndpoint actual{components_.appInfo.nodeId, target->vChainId.chainId, target->targetId,
                                 directUuid(identity.engine), directUuid(identity.incarnation)};
    const auto validate = [&]() -> Result<Void> {
      if (std::chrono::steady_clock::now() >= deadline || directWallMillis() >= request.deadlineUnixMillis)
        return makeError(StorageClientCode::kTimeout);
      RETURN_ON_ERROR(validateEcTarget(target, false));
      RETURN_ON_ERROR(target->storageTarget->checkEcScopeTarget(identity));
      RETURN_ON_ERROR(verifyEcHelperGrant(*ecHelpers_->key, request.helpers[position], *plan, actual, position,
                                         block, ecAuthorizationNow_()));
      RETURN_ON_ERROR(verifyEcHelperDirectPredecessor(*ecHelpers_->key, *plan, request, ecAuthorizationNow_()));
      const auto *key = components_.getEcCapabilityKey();
      if (!key) return makeError(StatusCode::kAuthenticationFail);
      RETURN_ON_ERROR(verifyEcRequestV2(*key, read,
                                       {actual.engineUuid, actual.targetIncarnation, target->vChainId, actual.targetId,
                                        actual.nodeId}, ecAuthorizationNow_()));
      return Void{};
    };
    CO_RETURN_ON_ERROR(validate());
    std::string windowKey(reinterpret_cast<const char *>(plan->digest().data()), plan->digest().size());
    windowKey.push_back(static_cast<char>(position));
    const auto bit = uint16_t(uint16_t{1} << block);
    CO_RETURN_ON_ERROR(ecHelpers_->enterBlock(windowKey, bit, plan->input().maxBlocksInFlight));
    auto releaseWindow = folly::makeGuard([&] { ecHelpers_->leaveBlock(windowKey, bit); });
    EcScopeBinding binding{};
    binding.target = identity;
    binding.object = directBytes(source.identity.object);
    binding.kind = 2;
    binding.scope = directBytes(plan->input().operationId);
    binding.owner_uid = plan->input().ownerUid.toUnderType();
    binding.client_namespace = directBytes(plan->input().clientNamespace);
    auto expires = std::min({request.helpers[position].claims.expiresAtSeconds, claims.expiresAtSeconds,
                             request.delegation.directGrant.claims.expiresAtSeconds});
    if (position) expires = std::min(expires, request.predecessor.expiresAtSeconds);
    const EcScopeLoadBudget loadBudget{config_.ec_scope_load_wait_ms(), receivedAt, deadline};
    auto wait = loadBudget.remaining(EcScopeLoadBudget::Clock::now(), expires, ecAuthorizationNow_());
    CO_RETURN_ON_ERROR(wait);
    CO_RETURN_ON_ERROR(scope->first->prepareWait(binding, *wait));
    CO_RETURN_ON_ERROR(validate());
    auto ticket = scope->first->tryAdmit(binding);
    CO_RETURN_ON_ERROR(ticket);
    const auto check = [&]() -> Result<Void> {
      RETURN_ON_ERROR(validate());
      return ticket->checkExecution();
    };
    const auto address = [&](const EcScopeEndpoint &endpoint, ChainVer version) -> Result<net::Address> {
      auto mgmtd = components_.mgmtdClient.load();
      if (!mgmtd) return makeError(StorageClientCode::kRoutingError);
      auto routing = mgmtd->getRoutingInfo();
      if (!routing) return makeError(StorageClientCode::kRoutingError);
      return directAddress(*routing, endpoint, version, transportType);
    };
    const auto options = [&]() -> Result<net::UserRequestOptions> {
      RETURN_ON_ERROR(check());
      const auto remaining = deadline - std::chrono::steady_clock::now();
      if (remaining <= std::chrono::steady_clock::duration::zero()) return makeError(StorageClientCode::kTimeout);
      net::UserRequestOptions out;
      out.timeout = Duration(remaining);
      out.sendRetryTimes = 0;
      out.requireRdma = transportType == net::Address::RDMA;
      return out;
    };
    CO_RETURN_ON_ERROR(check());
    auto local = co_await readEcBlockV2(read);
    CO_RETURN_ON_ERROR(local);
    CO_RETURN_ON_ERROR(local->result);
    CO_RETURN_ON_ERROR(validateEcReadBlockV2(*local->result, read));
    CO_RETURN_ON_ERROR(check());
    // Preserve the original authenticated packet for later result validation.
    // The extra bounded accumulator copy is included in the per-call footprint.
    auto computed = EcRepairBlockCore::advance(*plan, position, repairBlock(request.packet),
                                                local->result->payload.data);
    CO_RETURN_ON_ERROR(computed);
    local->result->payload.data.clear();
    auto packet = helperPacket(std::move(*computed));
    EcHelperDirectHopResult result;
    if (position != 9) {
      auto stamp = ec_helper_direct_detail::stamp(*ecHelpers_->key, *plan, request, packet, ecAuthorizationNow_());
      CO_RETURN_ON_ERROR(stamp);
      auto nextAddress = address(plan->input().sources[position + 1].endpoint,
                                  request.sourceRouteVersions[position + 1]);
      CO_RETURN_ON_ERROR(nextAddress);
      auto opts = options();
      CO_RETURN_ON_ERROR(opts);
      auto forwarded = request;
      forwarded.packet = std::move(packet);
      forwarded.predecessor = std::move(*stamp);
      dispatchedMutation = true;
      auto response = co_await ecHelpers_->messenger.executeEcHelperDirect(*nextAddress, forwarded, &*opts);
      CO_RETURN_ON_ERROR(response);
      CO_RETURN_ON_ERROR(response->result);
      result = std::move(*response->result);
    } else {
      CO_RETURN_ON_ERROR(EcRepairBlockCore::validateComplete(*plan, repairBlock(packet)));
      const auto start = uint64_t(block) * kEcIntegrityBlockBytes;
      bool ready = false;
      // Query is only a hint for ordering. Every selected target still receives
      // the actual original Append, including when its prefix is already ahead.
      // At most 64 rounds; sleep yields the helper executor, never a disk worker
      // or window mutex. Missing lower blocks fail instead of creating new IDs.
      for (uint32_t round = 0; round != 64; ++round) {
        bool allReady = true;
        for (uint8_t i = 0; i != plan->input().targetCount; ++i) {
          if (!(request.activeTargetMask & (uint8_t{1} << i))) continue;
          const auto &fragment = plan->input().targets[i];
          EcQueryStageV2Req query;
          query.request = directAccess(fragment, request.targetRouteVersions[i]);
          query.grant = request.delegation.queryGrants[i];
          auto endpoint = address(fragment.endpoint, request.targetRouteVersions[i]);
          CO_RETURN_ON_ERROR(endpoint);
          auto opts = options();
          CO_RETURN_ON_ERROR(opts);
          auto observed = co_await ecHelpers_->messenger.queryEcStageV2(*endpoint, query, &*opts);
          CO_RETURN_ON_ERROR(observed);
          CO_RETURN_ON_ERROR(observed->result);
          if (!serde::equals(observed->tag, query.request.tag)) co_return directUnknown();
          CO_RETURN_ON_ERROR(validateEcStageStateV2(*observed->result, query.request, query.grant.claims));
          CO_RETURN_ON_ERROR(check());
          CO_RETURN_ON_ERROR(address(fragment.endpoint, request.targetRouteVersions[i]));
          if (observed->result->state != 1 || observed->result->needsReconcile) co_return directUnknown();
          // A pending prefix block is replayable; a higher block must wait.
          if (observed->result->prefixBytes < start) allReady = false;
        }
        if (allReady) {
          ready = true;
          break;
        }
        CO_RETURN_ON_ERROR(check());
        if (round == 63) break;
        co_await folly::coro::sleep(std::min(std::chrono::milliseconds(50),
                                            std::chrono::milliseconds(5 * (round + 1))));
        CO_RETURN_ON_ERROR(check());
      }
      if (!ready) co_return makeError(StorageClientCode::kTimeout, "direct helper prefix wait exhausted");
      std::array<EcStageStateV2, 2> appended{};
      for (uint8_t i = 0; i != plan->input().targetCount; ++i) {
        if (!(request.activeTargetMask & (uint8_t{1} << i))) continue;
        const auto &fragment = plan->input().targets[i];
        EcAppendStageV2Req append;
        append.request = directAccess(fragment, request.targetRouteVersions[i]);
        append.grant = request.delegation.appendGrants[i];
        append.blockIndex = block;
        append.payload.data = std::move(packet.outputs[i].data);
        auto endpoint = address(fragment.endpoint, request.targetRouteVersions[i]);
        CO_RETURN_ON_ERROR(endpoint);
        auto opts = options();
        CO_RETURN_ON_ERROR(opts);
        dispatchedMutation = true;
        auto response = co_await ecHelpers_->messenger.appendEcStageV2(*endpoint, append, &*opts);
        CO_RETURN_ON_ERROR(response);
        CO_RETURN_ON_ERROR(response->result);
        if (!serde::equals(response->tag, append.request.tag)) co_return directUnknown();
        CO_RETURN_ON_ERROR(validateEcStageStateV2(*response->result, append.request, append.grant.claims));
        CO_RETURN_ON_ERROR(check());
        CO_RETURN_ON_ERROR(address(fragment.endpoint, request.targetRouteVersions[i]));
        appended[i] = std::move(*response->result);
        // Keep the authenticated complete packet for finish's hash validation.
        packet.outputs[i].data = std::move(append.payload.data);
      }
      auto finished = ec_helper_direct_detail::finish(*ecHelpers_->key, *plan, request, packet,
                                                       std::move(appended), ecAuthorizationNow_());
      CO_RETURN_ON_ERROR(finished);
      result = std::move(*finished);
    }
    CO_RETURN_ON_ERROR(verifyEcHelperDirectResult(*ecHelpers_->key, *plan, request, result, ecAuthorizationNow_()));
    CO_RETURN_ON_ERROR(check());
    co_return result;
  };
  try {
    auto result = co_await run();
    if (!result && dispatchedMutation) co_return directUnknown();
    co_return result;
  } catch (const std::bad_alloc &) {
    if (dispatchedMutation) co_return directUnknown();
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    if (dispatchedMutation) co_return directUnknown();
    co_return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::storage
