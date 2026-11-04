#include "meta/components/EcV2Coordinator.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <folly/ScopeGuard.h>
#include <set>

#include "fbs/meta/EcRequestDigest.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::meta::server {
namespace {
uint64_t wallSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
storage::EcFragmentAccessV2 accessFor(const EcV2AllocationBinding &allocation, storage::VersionedChainId route) {
  storage::EcFragmentAccessV2 request;
  request.identity = allocation.fragment.identity;
  request.operationId = allocation.fragment.operation;
  request.vChainId = route;
  request.targetId = allocation.fragment.placement.target;
  request.integrity = allocation.fragment.integrity;
  return request;
}
}  // namespace
EcV2Coordinator::EcV2Coordinator(const Config &config,
                                 std::shared_ptr<client::ICommonMgmtdClient> mgmtd,
                                 std::shared_ptr<storage::client::StorageClient> storage)
    : config_(config),
      mgmtd_(std::move(mgmtd)),
      storage_(std::move(storage)),
      verifying_(config.ec_max_verifying_stripes()) {
  if (!config.enable_ec_v2()) return;
  auto data = storage::EcCapabilityKey::loadFile(config.ec_capability_key_file().string());
  if (!data) {
    initializationError_ = data.error();
    return;
  }
  dataKey_ = std::shared_ptr<const storage::EcCapabilityKey>(std::move(*data));
  auto control = storage::EcScopeControlKey::loadFile(config.ec_v2_control_key_file().string());
  if (!control) {
    initializationError_ = control.error();
    return;
  }
  controlKey_ = std::shared_ptr<const storage::EcScopeControlKey>(std::move(*control));
  auto authority = Uuid::fromHexString(config.ec_v2_control_authority());
  if (!authority) {
    initializationError_ = authority.error();
    return;
  }
  authority_ = *authority;
  {
    std::error_code error;
    const bool same = std::filesystem::equivalent(std::filesystem::path(config.ec_capability_key_file().string()),
                                                  std::filesystem::path(config.ec_v2_control_key_file().string()),
                                                  error);
    if (error || same) {
      initializationError_ = Status(StatusCode::kInvalidConfig, "V2 data/control keys must be distinct actual files");
      return;
    }
  }
  if (!config.ec_v2_helper_key_file().empty()) {
    const std::filesystem::path helperPath(config.ec_v2_helper_key_file().string());
    for (const auto &other : {config.ec_capability_key_file(), config.ec_v2_control_key_file()}) {
      std::error_code error;
      const bool same = std::filesystem::equivalent(helperPath, std::filesystem::path(other.string()), error);
      if (error || same) {
        initializationError_ = Status(StatusCode::kInvalidConfig, "V2 helper key must be a distinct explicit file");
        return;
      }
    }
    auto helper = storage::EcHelperKey::loadFile(config.ec_v2_helper_key_file().string());
    if (!helper) {
      initializationError_ = helper.error();
      return;
    }
    helperKey_ = std::shared_ptr<const storage::EcHelperKey>(std::move(*helper));
  }
}
Result<Void> EcV2Coordinator::checkEnabled() const {
  if (!config_.enable_ec_v2() || !config_.enable_ec_catalog())
    return makeError(StatusCode::kNotImplemented, "native V2 EC is disabled");
  if (!config_.authenticate()) return makeError(StatusCode::kAuthenticationFail, "V2 EC requires Meta authentication");
  if (initializationError_) return makeError(*initializationError_);
  if (!dataKey_ || !controlKey_ || authority_.is_nil() || !mgmtd_ || !storage_ ||
      config_.ec_capability_key_file() == config_.ec_v2_control_key_file())
    return makeError(StatusCode::kInvalidConfig, "V2 requires separate data/control key files and an authority");
  if (!config_.ec_grant_ttl_seconds() || config_.ec_grant_ttl_seconds() > storage::kEcGrantMaxTtlSeconds ||
      config_.ec_verify_timeout() <= 0_s || config_.ec_v2_drain_timeout() <= 0_s ||
      config_.ec_v2_drain_poll_interval() <= 0_s)
    return makeError(StatusCode::kInvalidConfig, "invalid V2 capability or verification/drain lifetime");
  if (helperKey_ && (config_.ec_v2_helper_key_file() == config_.ec_capability_key_file() ||
                     config_.ec_v2_helper_key_file() == config_.ec_v2_control_key_file() ||
                     !config_.ec_v2_helper_grant_ttl_seconds() ||
                     config_.ec_v2_helper_grant_ttl_seconds() > storage::kEcHelperMaxTtlSeconds))
    return makeError(StatusCode::kInvalidConfig, "V2 helper authority requires a separate key and lifetime 1..300");
  RETURN_ON_ERROR(configuredPool());
  return Void{};
}
Result<EcV2ReservationCatalog::PhysicalPool> EcV2Coordinator::configuredPool() const {
  if (config_.ec_targets_length() != 12)
    return makeError(StatusCode::kInvalidConfig, "V2 requires twelve explicit physical target instances");
  EcV2ReservationCatalog::PhysicalPool result;
  std::set<flat::NodeId> nodes;
  std::set<storage::ChainId> chains;
  std::set<storage::TargetId> targets;
  for (size_t i = 0; i != 12; ++i) {
    const auto &entry = config_.ec_targets(i);
    const auto placement = entry.placement();
    auto engine = Uuid::fromHexString(entry.engine_uuid());
    auto target = Uuid::fromHexString(entry.target_incarnation());
    if (!engine || !target || engine->is_nil() || target->is_nil() || placement.node == flat::NodeId{} ||
        placement.chain == storage::ChainId{} || placement.target == storage::TargetId{} ||
        !chains.insert(placement.chain).second || !targets.insert(placement.target).second)
      return makeError(StatusCode::kInvalidConfig, "V2 target pool contains a missing or duplicate identity");
    nodes.insert(placement.node);
    result[i] = {placement, *engine, *target};
  }
  if (!config_.ec_allow_colocated_test_targets() && nodes.size() != 12)
    return makeError(StatusCode::kInvalidConfig, "V2 requires twelve distinct Storage nodes");
  return result;
}
Result<storage::VersionedChainId> EcV2Coordinator::route(const EcV2PhysicalEndpoint &endpoint) const {
  const auto &p = endpoint.placement;
  if (endpoint.engineUuid.is_nil() || endpoint.targetIncarnation.is_nil())
    return makeError(StatusCode::kInvalidArg, "V2 allocation has no persistent instance");
  auto routing = mgmtd_->getRoutingInfo();
  if (!routing || !routing->raw()) return makeError(MgmtdClientCode::kRoutingInfoNotReady);
  const auto *chain = routing->raw()->getChain(p.chain);
  const auto *target = routing->raw()->getTarget(p.target);
  const auto *node = routing->raw()->getNode(p.node);
  if (!chain || !target || !node || chain->targets.size() != 1 || chain->targets.front().targetId != p.target ||
      chain->targets.front().publicState != flat::PublicTargetState::SERVING ||
      target->publicState != flat::PublicTargetState::SERVING || target->chainId != p.chain || !target->nodeId ||
      *target->nodeId != p.node || node->type != flat::NodeType::STORAGE ||
      node->status != flat::NodeStatus::HEARTBEAT_CONNECTED)
    return makeError(StorageClientCode::kRoutingError, "V2 allocation is not at its fixed serving endpoint");
  // The pool may change for future Begin calls. It cannot replace an already
  // reserved historical instance; Storage checks that instance in the MAC.
  return storage::VersionedChainId{p.chain, chain->chainVersion};
}
Result<EcV2ReservationCatalog::PhysicalPool> EcV2Coordinator::pool(uint16_t replacementMask) const {
  CHECK_RESULT(result, configuredPool());
  for (size_t i = 0; i != result.size(); ++i)
    if (replacementMask & (1u << i)) RETURN_ON_ERROR(route(result[i]));
  return result;
}
Result<storage::EcCapabilityV2> EcV2Coordinator::issueGrant(const EcV2AllocationBinding &allocation,
                                                            const EcOwner &owner,
                                                            storage::EcGrantScope kind,
                                                            const Uuid &scope,
                                                            uint16_t rights) const {
  RETURN_ON_ERROR(checkEnabled());
  // Availability is checked per actual Storage request. A missing/offline
  // historical target must not prevent issuing the other eleven read grants.
  const auto &fragment = allocation.fragment;
  CHECK_RESULT(digest, storage::digestEcIntegrityV2(fragment.identity, fragment.integrity));
  storage::EcGrantClaimsV2 claims;
  claims.engineUuid = allocation.engineUuid;
  claims.targetIncarnation = allocation.targetIncarnation;
  claims.identity = fragment.identity;
  claims.fragmentOperationId = fragment.operation;
  claims.chainId = fragment.placement.chain;
  claims.targetId = fragment.placement.target;
  claims.nodeId = fragment.placement.node;
  claims.expectedLength = fragment.integrity.wholeLength;
  claims.expectedCrc32c = fragment.integrity.wholeCrc32c;
  claims.integrityDigest = digest;
  claims.ownerUid = owner.uid;
  claims.clientNamespace = owner.client;
  claims.scopeObject = fragment.identity.object;
  claims.scopeKind = kind;
  claims.scopeId = scope;
  claims.rights = rights;
  claims.grantId = Uuid::random();
  claims.issuedAtSeconds = wallSeconds();
  claims.expiresAtSeconds = claims.issuedAtSeconds + config_.ec_grant_ttl_seconds();
  return storage::signEcGrantV2(*dataKey_, claims, claims.issuedAtSeconds, storage::kEcGrantMaxTtlSeconds);
}
Result<Void> EcV2Coordinator::addMutationGrants(EcV2MutationRsp &rsp) const {
  if (rsp.record.state != EcOperationState::Preparing || rsp.drain || !rsp.allocations)
    return makeError(StatusCode::kTokenStale, "V2 mutation cannot issue grants before binding or after Closing");
  for (size_t i = 0; i != 12; ++i) {
    const bool replacement = rsp.record.intent.replacementMask & (1u << i);
    CHECK_RESULT(grant,
                 issueGrant((*rsp.allocations)[i],
                            rsp.record.owner,
                            storage::EcGrantScope::WriteOperation,
                            rsp.record.intent.operation,
                            replacement ? storage::kEcGrantAllRightsV2
                                        : static_cast<uint16_t>(storage::EcGrantRightV2::ReadBlock)));
    rsp.grants[i] = std::move(grant);
  }
  return Void{};
}
Result<Void> EcV2Coordinator::addReadGrants(AcquireEcReadV2Rsp &rsp) const {
  for (size_t i = 0; i != 12; ++i) {
    EcV2AllocationBinding allocation;
    allocation.object = rsp.snapshot.object;
    allocation.fragment = rsp.manifest.fragments[i];
    allocation.engineUuid = rsp.snapshot.endpoints[i].endpoint.engineUuid;
    allocation.targetIncarnation = rsp.snapshot.endpoints[i].endpoint.targetIncarnation;
    CHECK_RESULT(grant,
                 issueGrant(allocation,
                            rsp.snapshot.owner,
                            storage::EcGrantScope::ReadPin,
                            rsp.snapshot.pin,
                            static_cast<uint16_t>(storage::EcGrantRightV2::ReadBlock)));
    rsp.readGrants[i] = std::move(grant);
  }
  return Void{};
}
Result<std::optional<std::array<storage::EcHelperCapability, 10>>> EcV2Coordinator::issueRepairHelpers(
    const EcV2RepairPlanRecord &record) const {
  RETURN_ON_ERROR(checkEnabled());
  if (!helperKey_) return std::nullopt;
  // The caller has committed prepare's current ACL/epoch/ECVI checks. This
  // signer accepts only the reconstructed persistent plan, never wire fields.
  CHECK_RESULT(
      grants,
      EcV2RepairIssuer::sign(record,
                             *helperKey_,
                             wallSeconds(),
                             std::min(config_.ec_grant_ttl_seconds(), config_.ec_v2_helper_grant_ttl_seconds())));
  return std::optional<std::array<storage::EcHelperCapability, 10>>(std::move(grants));
}
CoTryTask<std::shared_ptr<const EcV2PublishEvidence>> EcV2Coordinator::verifyForPublish(
    const EcV2MutationRsp &snapshot) {
  CO_RETURN_ON_ERROR(checkEnabled());
  if (!snapshot.reservation || !snapshot.allocations || snapshot.drain ||
      snapshot.record.state != EcOperationState::Preparing)
    co_return makeError(StatusCode::kTokenStale, "V2 verification requires an open, bound operation");
  if (!verifying_.try_wait()) co_return makeError(MetaCode::kBusy, "V2 verification admission is full");
  auto admitted = folly::makeGuard([&] { verifying_.signal(); });
  const auto deadline = SteadyClock::now() + config_.ec_verify_timeout();
  storage::client::EcRequestControl control;
  control.deadline = deadline;
  control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
  std::array<storage::EcCapabilityV2, 12> grants;
  // All grants belong to this committed issuance snapshot. Never refresh an
  // individual block's grant while a concurrent T0 may have closed the scope.
  for (size_t i = 0; i != 12; ++i) {
    auto grant = issueGrant((*snapshot.allocations)[i],
                            snapshot.record.owner,
                            storage::EcGrantScope::WriteOperation,
                            snapshot.record.intent.operation,
                            static_cast<uint16_t>(storage::EcGrantRightV2::ReadBlock) |
                                static_cast<uint16_t>(storage::EcGrantRightV2::Seal));
    CO_RETURN_ON_ERROR(grant);
    grants[i] = std::move(*grant);
  }
  EcManifest manifest = snapshot.record.candidate;
  std::array<std::string, 12> bytes;
  std::array<storage::EcCodecShardView, 12> views;
  std::array<std::string_view, 10> logical;
  for (size_t i = 0; i != 12; ++i) {
    const auto &allocation = (*snapshot.allocations)[i];
    manifest.fragments[i] = allocation.fragment;
    const auto &fragment = allocation.fragment;
    CO_RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
    if (fragment.integrity.wholeLength != snapshot.object.shardBytes ||
        fragment.integrity.wholeCrc32c != snapshot.record.intent.fragmentCrc32c[i])
      co_return makeError(StatusCode::kTokenMismatch, "V2 persisted descriptor differs from Begin");
    bytes[i].reserve(fragment.integrity.wholeLength);
    for (uint32_t block = 0; block != fragment.integrity.blockCount; ++block) {
      if (SteadyClock::now() >= deadline) co_return makeError(MetaCode::kOperationTimeout);
      auto current = route(allocation.endpoint());
      CO_RETURN_ON_ERROR(current);
      storage::EcReadBlockV2Req req;
      req.request = accessFor(allocation, *current);
      req.blockIndex = block;
      req.grant = grants[i];
      auto response = co_await storage_->readEcBlockV2Controlled(req, control);
      CO_RETURN_ON_ERROR(response);
      CO_RETURN_ON_ERROR(storage::validateEcReadBlockV2(*response, req));
      bytes[i].append(response->payload.data);
    }
    auto actual = storage::computeEcIntegrity(fragment.identity, bytes[i]);
    CO_RETURN_ON_ERROR(actual);
    if (*actual != fragment.integrity)
      co_return makeError(StatusCode::kDataCorruption, "V2 stored bytes differ from fixed descriptor");
    views[i] = {static_cast<uint16_t>(i), bytes[i]};
    if (i < 10) logical[i] = bytes[i];
  }
  const auto &format = manifest.fragments[0].integrity;
  CO_RETURN_ON_ERROR(storage::EcCodec::verify(
      views,
      manifest.logicalLength,
      snapshot.object.shardBytes,
      {format.codecId, format.matrixVersion, format.dataShards, format.parityShards, format.fieldPolynomial}));
  auto content = computeEcLogicalSha256(logical, manifest.logicalLength);
  CO_RETURN_ON_ERROR(content);
  auto requestDigest = computeEcRequestDigest(snapshot.record.intent, snapshot.object.shardBytes, *content);
  CO_RETURN_ON_ERROR(requestDigest);
  if (*content != snapshot.reservation->contentSha256 || *requestDigest != snapshot.record.intent.requestDigest)
    co_return makeError(StatusCode::kTokenMismatch, "V2 logical contents differ from permanent Begin commitment");
  for (size_t i = 0; i != 12; ++i) {
    if (SteadyClock::now() >= deadline) co_return makeError(MetaCode::kOperationTimeout);
    const auto &allocation = (*snapshot.allocations)[i];
    auto current = route(allocation.endpoint());
    CO_RETURN_ON_ERROR(current);
    storage::EcSealStageV2Req req;
    req.request = accessFor(allocation, *current);
    req.grant = grants[i];
    auto seal = co_await storage_->sealEcStageV2Controlled(req, control);
    CO_RETURN_ON_ERROR(seal);
    CO_RETURN_ON_ERROR(storage::validateEcReceiptV2(*seal, req.request, req.grant.claims));
  }
  for (const auto &allocation : *snapshot.allocations) CO_RETURN_ON_ERROR(route(allocation.endpoint()));
  if (SteadyClock::now() >= deadline) co_return makeError(MetaCode::kOperationTimeout);
  co_return std::shared_ptr<const EcV2PublishEvidence>(
      new EcV2PublishEvidence(snapshot.record, std::move(manifest), *content));
}
CoTryTask<std::optional<EcVerifiedDrainAck>> EcV2Coordinator::observeDrain(const EcV2DrainRecord &record,
                                                                           size_t index,
                                                                           storage::EcScopeControlAction action) {
  CO_RETURN_ON_ERROR(checkEnabled());
  auto request = EcV2DrainCatalog::makeRequest(record, index, action, *controlKey_, wallSeconds());
  CO_RETURN_ON_ERROR(request);
  auto ack = action == storage::EcScopeControlAction::Revoke ? co_await storage_->revokeEcScope(*request)
                                                             : co_await storage_->queryEcScopeDrain(*request);
  CO_RETURN_ON_ERROR(ack);
  // Pending is not evidence, but still must authenticate the complete reply.
  CO_RETURN_ON_ERROR(storage::verifyEcScopeControlAck(*controlKey_, *ack, *request));
  if (ack->claims.state != storage::EcScopeControlState::Drained) co_return std::nullopt;
  auto evidence = EcVerifiedDrainAck::verify(*controlKey_, record, index, *request, *ack);
  CO_RETURN_ON_ERROR(evidence);
  co_return std::move(*evidence);
}
}  // namespace hf3fs::meta::server
