#include <algorithm>
#include <chrono>
#include <folly/ScopeGuard.h>

#include "storage/ec_scope/EcScopeLoadBudget.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
namespace {
uint64_t unixMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}
Uuid uuid(const std::array<uint8_t, 16> &bytes) {
  Uuid result = Uuid::zero();
  std::copy(bytes.begin(), bytes.end(), std::begin(result.data));
  return result;
}
std::array<uint8_t, 16> bytes(const Uuid &value) {
  std::array<uint8_t, 16> result{};
  std::copy(std::begin(value.data), std::end(value.data), result.begin());
  return result;
}
Result<net::Address> helperAddress(const hf3fs::client::RoutingInfo &routing,
                                   const EcScopeEndpoint &endpoint,
                                   net::Address::Type transportType) {
  auto node = routing.getNode(endpoint.nodeId);
  auto target = routing.getTarget(endpoint.targetId);
  if (!node || node->type != flat::NodeType::STORAGE || node->status != flat::NodeStatus::HEARTBEAT_CONNECTED ||
      !target || target->nodeId != endpoint.nodeId || target->chainId != endpoint.chainId ||
      target->publicState != flat::PublicTargetState::SERVING) {
    return makeError(StorageClientCode::kRoutingError, "fixed helper node or target is not serving");
  }
  for (const auto &group : node->app.serviceGroups) {
    if (!group.services.contains("StorageSerde")) continue;
    for (const auto &address : group.endpoints)
      if (address.type == transportType) return address;
  }
  return makeError(StorageClientCode::kRoutingError, "fixed helper has no matching transport StorageSerde endpoint");
}
}  // namespace

Result<Void> StorageOperator::initEcHelpers() {
  if (!config_.enable_ec_helpers()) return Void{};
  if (!config_.enable_ec_fragments() || !components_.config.targets().ec_staging_v2() ||
      !components_.getEcCapabilityKey()) {
    return makeError(StatusCode::kInvalidConfig, "helpers require restored V2 storage and a data capability key");
  }
  const std::filesystem::path helperPath(config_.ec_helper_key_file().string());
  for (const auto &other : {config_.ec_capability_key_file(), config_.ec_scope_control_key_file()}) {
    if (other.empty()) continue;
    std::error_code error;
    const auto same = std::filesystem::equivalent(helperPath, std::filesystem::path(other.string()), error);
    if (error || same) return makeError(StatusCode::kInvalidConfig, "helper key must be a distinct explicit file");
  }
  CHECK_RESULT(key, EcHelperKey::loadFile(helperPath));
  const auto loadedIdentity = key->fileIdentity();
  CHECK_RESULT(runtime, EcHelperRuntime::create(components_.config.forward_client(), std::move(key)));
  ecHelperKeyFileIdentity_ = loadedIdentity;
  ecHelpers_ = std::move(runtime);
  return Void{};
}

CoTryTask<EcHelperHopRsp> StorageOperator::executeEcHelper(const EcHelperHopReq &request,
                                                         net::Address::Type transportType) {
  const auto receivedAt = std::chrono::steady_clock::now();
  EcHelperHopRsp response;
  if (transportType != net::Address::TCP && transportType != net::Address::RDMA) {
    response.result = makeError(StatusCode::kInvalidArg, "helper requires explicit TCP or RDMA ingress");
    co_return response;
  }
  if (!ecHelpers_) {
    response.result = makeError(StatusCode::kAuthenticationFail, "native EC helpers are disabled");
    co_return response;
  }
  // Non-waiting limits prevent an exhausted recursive chain from deadlocking
  // itself. All 64 occupied slots still leave control25/26 independent.
  auto session = ecHelpers_->sessions->acquire();
  if (!session) {
    response.result = makeError(session.error());
    co_return response;
  }
  if (!ecHelpers_->budget.try_wait()) {
    response.result = makeError(StorageClientCode::kResourceBusy, "helper admission budget is full");
    co_return response;
  }
  auto release = folly::makeGuard([this] { ecHelpers_->budget.signal(); });
  // Input is copied only after admission; it remains owning until every actual
  // child completes. Session and budget outlive the owned response/postchecks.
  response.result = co_await folly::coro::co_withCancellation(
      CancellationToken{},
      executeEcHelperOwned(request, receivedAt, transportType).scheduleOn(&ecHelpers_->executor));
  co_return response;
}

CoTryTask<EcHelperHopResult> StorageOperator::executeEcHelperOwned(EcHelperHopReq request,
                                                                   std::chrono::steady_clock::time_point receivedAt,
                                                                   net::Address::Type transportType) {
  try {
    auto planResult = EcRepairPlan::create(request.plan);
    CO_RETURN_ON_ERROR(planResult);
    auto plan = std::move(*planResult);
    const uint8_t position = request.packet.nextHelper;
    const uint32_t block = request.packet.blockIndex;
    if (position >= 10) co_return makeError(StatusCode::kInvalidArg, "helper position is out of range");
    const auto wallNow = unixMillis();
    if (request.deadlineUnixMillis <= wallNow || request.deadlineUnixMillis - wallNow > 60000) {
      co_return makeError(StorageClientCode::kTimeout, "helper requires a finite absolute deadline within 60 seconds");
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(request.deadlineUnixMillis - wallNow);
    const auto &source = plan->input().sources[position];
    EcReadBlockV2Req read;
    read.request.identity = source.identity;
    read.request.operationId = source.operationId;
    read.request.vChainId = {source.endpoint.chainId, request.routeVersions[position]};
    read.request.targetId = source.endpoint.targetId;
    read.request.integrity = source.integrity;
    read.blockIndex = block;
    read.grant = request.reads[position];
    const auto helper = request.helpers[position];
    const auto &readClaims = read.grant.claims;
    if (readClaims.scopeKind != EcGrantScope::WriteOperation || readClaims.scopeId != plan->input().operationId ||
        readClaims.scopeObject != source.identity.object || readClaims.ownerUid != plan->input().ownerUid ||
        readClaims.clientNamespace != plan->input().clientNamespace) {
      co_return makeError(StatusCode::kAuthenticationFail,
                          "helper ReadBlock credential has another operation owner/scope");
    }
    auto selected = ecTarget(read.request.vChainId, source.endpoint.targetId, false);
    CO_RETURN_ON_ERROR(selected);
    auto target = *selected;
    if (!target->storageTarget->usesEcStagingEngine()) co_return makeError(StorageCode::kTargetStateInvalid);
    auto scope = target->storageTarget->ecScopeState();
    CO_RETURN_ON_ERROR(scope);
    const auto identity = scope->second;
    const EcScopeEndpoint actual{components_.appInfo.nodeId,
                                 target->vChainId.chainId,
                                 target->targetId,
                                 uuid(identity.engine),
                                 uuid(identity.incarnation)};
    const auto validate = [&]() -> Result<Void> {
      if (std::chrono::steady_clock::now() >= deadline || unixMillis() >= request.deadlineUnixMillis) {
        return makeError(StorageClientCode::kTimeout);
      }
      RETURN_ON_ERROR(validateEcTarget(target, false));
      RETURN_ON_ERROR(target->storageTarget->checkEcScopeTarget(identity));
      RETURN_ON_ERROR(
          verifyEcHelperGrant(*ecHelpers_->key, helper, *plan, actual, position, block, ecAuthorizationNow_()));
      const auto *key = components_.getEcCapabilityKey();
      if (!key) return makeError(StatusCode::kAuthenticationFail);
      EcLocalTargetV2 local{actual.engineUuid,
                            actual.targetIncarnation,
                            target->vChainId,
                            actual.targetId,
                            actual.nodeId};
      RETURN_ON_ERROR(verifyEcRequestV2(*key, read, local, ecAuthorizationNow_()));
      return Void{};
    };
    CO_RETURN_ON_ERROR(validate());
    CO_RETURN_ON_ERROR(verifyEcHelperPredecessor(*ecHelpers_->key,
                                                 *plan,
                                                 request.packet,
                                                 request.predecessor,
                                                 position,
                                                 ecAuthorizationNow_()));
    std::string windowKey(reinterpret_cast<const char *>(plan->digest().data()), plan->digest().size());
    windowKey.push_back(static_cast<char>(position));
    const uint16_t blockBit = uint16_t{1} << block;
    CO_RETURN_ON_ERROR(ecHelpers_->enterBlock(windowKey, blockBit, plan->input().maxBlocksInFlight));
    auto releaseWindow = folly::makeGuard([&] { ecHelpers_->leaveBlock(windowKey, blockBit); });
    EcScopeBinding binding{};
    binding.target = identity;
    binding.object = bytes(source.identity.object);
    binding.kind = 2;
    binding.scope = bytes(plan->input().operationId);
    binding.owner_uid = plan->input().ownerUid.toUnderType();
    binding.client_namespace = bytes(plan->input().clientNamespace);
    // RocksDB cold fence loading runs on the separate helper executor. Do not
    // register a target here or keep any DB transaction across a remote await.
    const EcScopeLoadBudget loadBudget{config_.ec_scope_load_wait_ms(), receivedAt, deadline};
    auto grantExpires = std::min(helper.claims.expiresAtSeconds, read.grant.claims.expiresAtSeconds);
    if (position != 0) grantExpires = std::min(grantExpires, request.predecessor.expiresAtSeconds);
    auto wait = loadBudget.remaining(EcScopeLoadBudget::Clock::now(), grantExpires, ecAuthorizationNow_());
    CO_RETURN_ON_ERROR(wait);
    CO_RETURN_ON_ERROR(scope->first->prepareWait(binding, *wait));
    CO_RETURN_ON_ERROR(validate());
    CO_RETURN_ON_ERROR(target->storageTarget->checkEcScopeTarget(identity));
    auto ticket = scope->first->tryAdmit(binding);
    CO_RETURN_ON_ERROR(ticket);
    CO_RETURN_ON_ERROR(validate());
    CO_RETURN_ON_ERROR(ticket->checkExecution());
    auto readResponse = co_await readEcBlockV2(read);  // Real V2 authorization, queued Rust Engine block read.
    CO_RETURN_ON_ERROR(readResponse);
    CO_RETURN_ON_ERROR(readResponse->result);
    CO_RETURN_ON_ERROR(validate());
    CO_RETURN_ON_ERROR(ticket->checkExecution());
    if (readResponse->result->blockIndex != block) co_return makeError(StatusCode::kDataCorruption);
    auto computed = EcRepairBlockCore::advance(*plan,
                                               position,
                                               repairBlock(std::move(request.packet)),
                                               readResponse->result->payload.data);
    CO_RETURN_ON_ERROR(computed);
    readResponse->result->payload.data.clear();
    const auto now = ecAuthorizationNow_();
    auto expires = std::min(helper.claims.expiresAtSeconds, read.grant.claims.expiresAtSeconds);
    if (position != 0) expires = std::min(expires, request.predecessor.expiresAtSeconds);
    auto packet = helperPacket(std::move(*computed));
    auto stamp = ec_helper_detail::stamp(*ecHelpers_->key, *plan, packet, now, expires);
    CO_RETURN_ON_ERROR(stamp);
    EcHelperHopResult result;
    if (position == 9) {
      result.packet = std::move(packet);
      result.finalStamp = std::move(*stamp);
    } else {
      auto mgmtd = components_.mgmtdClient.load();
      if (!mgmtd) co_return makeError(StorageClientCode::kRoutingError);
      auto routing = mgmtd->getRoutingInfo();
      if (!routing) co_return makeError(StorageClientCode::kRoutingError);
      auto address = helperAddress(*routing, plan->input().sources[position + 1].endpoint, transportType);
      CO_RETURN_ON_ERROR(address);
      CO_RETURN_ON_ERROR(validate());
      CO_RETURN_ON_ERROR(ticket->checkExecution());
      request.packet = std::move(packet);
      request.predecessor = std::move(*stamp);
      net::UserRequestOptions options;
      const auto remaining = deadline - std::chrono::steady_clock::now();
      if (remaining <= std::chrono::steady_clock::duration::zero()) co_return makeError(StorageClientCode::kTimeout);
      options.timeout = Duration(remaining);
      options.sendRetryTimes = 0;
      options.requireRdma = transportType == net::Address::RDMA;
      // Request and ticket stay on this coroutine frame until the selected transport Waiter
      // returns. Timeout can leave a downstream server running; Meta drains it.
      auto response = co_await ecHelpers_->messenger.executeEcHelper(*address, request, &options);
      CO_RETURN_ON_ERROR(response);
      CO_RETURN_ON_ERROR(response->result);
      result = std::move(*response->result);
      if (result.packet.blockIndex != block) co_return makeError(StatusCode::kDataCorruption);
      CO_RETURN_ON_ERROR(verifyEcHelperFinal(*ecHelpers_->key, *plan, result, ecAuthorizationNow_()));
    }
    CO_RETURN_ON_ERROR(validate());
    CO_RETURN_ON_ERROR(ticket->checkExecution());
    // Owned response construction and the last route/expiry checks happen
    // before ticket destruction. No response is a drain or publication proof.
    co_return result;
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    co_return makeError(StatusCode::kIOError, "helper failed; operation remains pinned for durable reconciliation");
  } catch (...) {
    co_return makeError(StatusCode::kIOError, "helper failed with an unknown exception");
  }
}

}  // namespace hf3fs::storage
