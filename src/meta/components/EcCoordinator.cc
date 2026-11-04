#include "meta/components/EcCoordinator.h"

#include <algorithm>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <set>

#include "fbs/meta/EcRequestDigest.h"
#include "fbs/storage/EcAuthorized.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::meta::server {

EcCoordinator::EcCoordinator(const Config &config,
                             std::shared_ptr<client::ICommonMgmtdClient> mgmtd,
                             std::shared_ptr<storage::client::StorageClient> storage)
    : config_(config),
      mgmtd_(std::move(mgmtd)),
      storage_(std::move(storage)),
      verifying_(config.ec_max_verifying_stripes()) {
  if (!config.ec_capability_key_file().empty()) {
    auto loaded = storage::EcCapabilityKey::loadFile(config.ec_capability_key_file().string());
    if (loaded)
      key_ = std::shared_ptr<const storage::EcCapabilityKey>(std::move(*loaded));
    else
      keyError_ = loaded.error();
  }
}

Result<Void> EcCoordinator::checkEnabled() const {
  if (!config_.enable_ec_catalog()) return makeError(StatusCode::kNotImplemented, "native EC catalog is disabled");
  if (!config_.authenticate())
    return makeError(StatusCode::kAuthenticationFail, "native EC requires Meta authentication");
  if (keyError_) return makeError(*keyError_);
  if (!key_ && !config_.ec_allow_unauthorized_storage_for_tests()) {
    return makeError(StatusCode::kNotImplemented, "native EC requires an explicit storage capability key");
  }
  if (!config_.ec_grant_ttl_seconds() || config_.ec_grant_ttl_seconds() > storage::kEcGrantMaxTtlSeconds) {
    return makeError(StatusCode::kInvalidArg, "invalid EC capability lifetime");
  }
  return Void{};
}

Result<storage::VersionedChainId> EcCoordinator::route(const EcPlacement &p) const {
  bool allowed = false;
  for (size_t i = 0; i != config_.ec_targets_length(); ++i) {
    allowed |= serde::equals(config_.ec_targets(i).placement(), p);
  }
  if (!allowed) {
    return makeError(MetaCode::kNoPermission, "EC placement is outside the configured target pool");
  }
  auto routing = mgmtd_->getRoutingInfo();
  if (!routing || !routing->raw()) return makeError(MgmtdClientCode::kRoutingInfoNotReady);
  const auto *chain = routing->raw()->getChain(p.chain);
  const auto *target = routing->raw()->getTarget(p.target);
  const auto *node = routing->raw()->getNode(p.node);
  if (!chain || !target || !node || chain->targets.size() != 1 || chain->targets.front().targetId != p.target ||
      chain->targets.front().publicState != flat::PublicTargetState::SERVING ||
      target->publicState != flat::PublicTargetState::SERVING || target->chainId != p.chain || !target->nodeId ||
      *target->nodeId != p.node || node->type != flat::NodeType::STORAGE ||
      node->status != flat::NodeStatus::HEARTBEAT_CONNECTED) {
    return makeError(StorageClientCode::kRoutingError, "EC placement is not the exact current serving target");
  }
  return storage::VersionedChainId{p.chain, chain->chainVersion};
}

Result<std::array<EcPlacement, 12>> EcCoordinator::placements() const {
  if (config_.ec_targets_length() != 12) {
    return makeError(StatusCode::kInvalidArg, "native EC requires exactly twelve configured targets");
  }
  std::array<EcPlacement, 12> result;
  std::set<flat::NodeId> nodes;
  std::set<storage::ChainId> chains;
  std::set<storage::TargetId> targets;
  for (size_t i = 0; i != 12; ++i) {
    const auto p = config_.ec_targets(i).placement();
    if (p.chain == storage::ChainId{} || p.target == storage::TargetId{} || p.node == flat::NodeId{} ||
        !chains.insert(p.chain).second || !targets.insert(p.target).second) {
      return makeError(StatusCode::kInvalidArg, "native EC requires distinct nonzero chains and targets");
    }
    nodes.insert(p.node);
    RETURN_ON_ERROR(route(p));
    result[i] = p;
  }
  if (!config_.ec_allow_colocated_test_targets() && nodes.size() != 12) {
    return makeError(StatusCode::kInvalidArg, "native EC requires twelve distinct storage nodes");
  }
  return result;
}

Result<Void> EcCoordinator::validatePlacements(const EcOperationRecord &record) const {
  for (const auto &fragment : record.candidate.fragments) RETURN_ON_ERROR(route(fragment.placement));
  return Void{};
}

CoTryTask<std::shared_ptr<const EcPublishEvidence>> EcCoordinator::verifyForPublish(const PublishEcMutationReq &req,
                                                                                    const EcOperationRsp &snapshot) {
  CO_RETURN_ON_ERROR(checkEnabled());
  if (!storage_ || snapshot.record.state != EcOperationState::Preparing ||
      !serde::equals(req.object, snapshot.record.intent.object) || req.operation != snapshot.record.intent.operation) {
    co_return makeError(StatusCode::kTokenMismatch, "EC verification requires its persisted preparing operation");
  }
  if (!verifying_.try_wait()) co_return makeError(MetaCode::kBusy, "EC verification admission budget is exhausted");
  auto admitted = folly::makeGuard([&] { verifying_.signal(); });
  const auto deadline = SteadyClock::now() + config_.ec_verify_timeout();
  auto timedOut = [&] { return SteadyClock::now() >= deadline; };
  EcManifest manifest = snapshot.record.candidate;
  std::array<storage::EcReadResult, 12> reads;
  std::array<storage::EcFragmentReceipt, 12> seals;
  std::array<storage::EcCodecShardView, 12> views;
  std::array<std::string_view, 10> logical;
  for (size_t i = 0; i != 12; ++i) {
    if (timedOut()) co_return makeError(MetaCode::kOperationTimeout, "EC verification deadline exceeded");
    auto &fragment = manifest.fragments[i];
    fragment.integrity = req.descriptors[i];
    if (fragment.integrity.wholeLength != snapshot.object.shardBytes) {
      co_return makeError(StatusCode::kInvalidArg, "EC descriptor length differs from its object capacity");
    }
    if (fragment.integrity.wholeCrc32c != snapshot.record.intent.fragmentCrc32c[i]) {
      co_return makeError(StatusCode::kTokenMismatch, "EC descriptor CRC differs from the Begin commitment");
    }
    CO_RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
    if (snapshot.record.intent.kind == EcMutationKind::Repair &&
        !serde::equals(fragment.integrity, snapshot.record.candidate.fragments[i].integrity)) {
      co_return makeError(StatusCode::kTokenMismatch, "repair must retain published content integrity");
    }
    auto chain = route(fragment.placement);
    CO_RETURN_ON_ERROR(chain);
    storage::EcReadReq read;
    read.identity = fragment.identity;
    read.operationId = fragment.operation;
    read.vChainId = *chain;
    read.targetId = fragment.placement.target;
    read.expectedLength = fragment.integrity.wholeLength;
    read.checksum.type = storage::ChecksumType::CRC32C;
    read.checksum.value = ~fragment.integrity.wholeCrc32c;
    Result<storage::EcReadResult> response = makeError(StatusCode::kNotImplemented);
    if (key_) {
      auto grant = issueGrant(fragment,
                              snapshot.record.owner,
                              storage::EcGrantScope::WriteOperation,
                              req.operation,
                              static_cast<uint8_t>(storage::EcGrantRight::Read),
                              fragment.integrity.wholeLength,
                              fragment.integrity.wholeCrc32c);
      CO_RETURN_ON_ERROR(grant);
      storage::EcAuthorizedReadReq authorized;
      authorized.request = read;
      authorized.grant = std::move(*grant);
      response = co_await storage_->authorizedReadEcFragment(authorized);
    } else {
      // Explicit unsafe local test mode; req.user is not storage authorization.
      response = co_await storage_->readEcFragment(read);
    }
    CO_RETURN_ON_ERROR(response);
    reads[i] = std::move(*response);
    auto actual = storage::computeEcIntegrity(fragment.identity, reads[i].payload.data);
    CO_RETURN_ON_ERROR(actual);
    if (!serde::equals(*actual, fragment.integrity)) {
      co_return makeError(StatusCode::kDataCorruption, "EC stored bytes differ from their descriptor");
    }
    views[i] = {static_cast<uint16_t>(i), reads[i].payload.data};
    if (i < 10) logical[i] = reads[i].payload.data;
  }
  const auto &format = manifest.fragments[0].integrity;
  CO_RETURN_ON_ERROR(storage::EcCodec::verify(
      views,
      manifest.logicalLength,
      snapshot.object.shardBytes,
      {format.codecId, format.matrixVersion, format.dataShards, format.parityShards, format.fieldPolynomial}));
  auto content = computeEcLogicalSha256(logical, manifest.logicalLength);
  CO_RETURN_ON_ERROR(content);
  auto digest = computeEcRequestDigest(snapshot.record.intent, snapshot.object.shardBytes, *content);
  CO_RETURN_ON_ERROR(digest);
  if (*digest != snapshot.record.intent.requestDigest) {
    co_return makeError(StatusCode::kTokenMismatch, "EC bytes do not match the logical request committed by Begin");
  }
  for (size_t i = 0; i != 12; ++i) {
    if (timedOut()) co_return makeError(MetaCode::kOperationTimeout, "EC reconciliation deadline exceeded");
    const auto &fragment = manifest.fragments[i];
    auto chain = route(fragment.placement);
    CO_RETURN_ON_ERROR(chain);
    storage::EcReconcileReq reconcile;
    reconcile.identity = fragment.identity;
    reconcile.operationId = fragment.operation;
    reconcile.vChainId = *chain;
    reconcile.targetId = fragment.placement.target;
    reconcile.expectedLength = fragment.integrity.wholeLength;
    reconcile.checksum.type = storage::ChecksumType::CRC32C;
    reconcile.checksum.value = ~fragment.integrity.wholeCrc32c;
    Result<storage::EcFragmentReceipt> seal = makeError(StatusCode::kNotImplemented);
    if (key_) {
      auto grant = issueGrant(fragment,
                              snapshot.record.owner,
                              storage::EcGrantScope::WriteOperation,
                              req.operation,
                              static_cast<uint8_t>(storage::EcGrantRight::Reconcile),
                              fragment.integrity.wholeLength,
                              fragment.integrity.wholeCrc32c);
      CO_RETURN_ON_ERROR(grant);
      storage::EcAuthorizedReconcileReq authorized;
      authorized.request = reconcile;
      authorized.grant = std::move(*grant);
      seal = co_await storage_->authorizedReconcileEcFragment(authorized);
    } else {
      seal = co_await storage_->reconcileEcFragment(reconcile);
    }
    CO_RETURN_ON_ERROR(seal);
    seals[i] = std::move(*seal);
  }
  CO_RETURN_ON_ERROR(validatePlacements(snapshot.record));
  if (timedOut()) co_return makeError(MetaCode::kOperationTimeout, "EC verification deadline exceeded");
  auto verified = EcVerifiedManifest::fromStorageResponses(std::move(manifest), reads, seals);
  CO_RETURN_ON_ERROR(verified);
  co_return std::shared_ptr<const EcPublishEvidence>(new EcPublishEvidence(snapshot.record, std::move(*verified)));
}

Result<storage::EcCapability> EcCoordinator::issueGrant(const EcFragment &fragment,
                                                        const EcOwner &owner,
                                                        storage::EcGrantScope scope,
                                                        const Uuid &scopeId,
                                                        uint8_t rights,
                                                        uint32_t length,
                                                        uint32_t crc) const {
  if (!key_) return makeError(StatusCode::kNotImplemented, "EC capability key is not configured");
  RETURN_ON_ERROR(route(fragment.placement));
  const auto now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  storage::EcGrantClaims claims;
  claims.identity = fragment.identity;
  claims.fragmentOperationId = fragment.operation;
  claims.chainId = fragment.placement.chain;
  claims.targetId = fragment.placement.target;
  claims.nodeId = fragment.placement.node;
  claims.expectedLength = length;
  claims.expectedCrc32c = crc;
  claims.ownerUid = owner.uid;
  claims.clientUuid = owner.client;
  claims.scopeObject = fragment.identity.object;
  claims.scopeKind = scope;
  claims.scopeId = scopeId;
  claims.rights = rights;
  claims.grantId = Uuid::random();
  claims.issuedAtSeconds = now;
  claims.expiresAtSeconds = now + config_.ec_grant_ttl_seconds();
  return storage::signEcGrant(*key_, claims, now, config_.ec_grant_ttl_seconds());
}

Result<storage::EcCapability> EcCoordinator::issueCreateGrant(const EcFragment &fragment,
                                                              const EcOwner &owner,
                                                              const Uuid &operation,
                                                              uint32_t length,
                                                              uint32_t crc) const {
  return issueGrant(
      fragment,
      owner,
      storage::EcGrantScope::WriteOperation,
      operation,
      static_cast<uint8_t>(storage::EcGrantRight::Create) | static_cast<uint8_t>(storage::EcGrantRight::Reconcile),
      length,
      crc);
}
Result<storage::EcCapability> EcCoordinator::issueReadGrant(const EcFragment &fragment,
                                                            const EcOwner &owner,
                                                            const Uuid &pin) const {
  return issueGrant(fragment,
                    owner,
                    storage::EcGrantScope::ReadPin,
                    pin,
                    static_cast<uint8_t>(storage::EcGrantRight::Read),
                    fragment.integrity.wholeLength,
                    fragment.integrity.wholeCrc32c);
}
Result<Void> EcCoordinator::addCreateGrants(EcOperationRsp &rsp) const {
  if (!key_ || rsp.record.state != EcOperationState::Preparing) return Void{};
  for (size_t i = 0; i != 12; ++i) {
    if (!(rsp.record.intent.replacementMask & (1u << i))) continue;
    CHECK_RESULT(grant,
                 issueCreateGrant(rsp.record.candidate.fragments[i],
                                  rsp.record.owner,
                                  rsp.record.intent.operation,
                                  rsp.object.shardBytes,
                                  rsp.record.intent.fragmentCrc32c[i]));
    rsp.createGrants[i] = std::move(grant);
  }
  return Void{};
}
Result<Void> EcCoordinator::addReadGrants(AcquireEcReadRsp &rsp, const EcOwner &owner) const {
  if (!key_) return Void{};
  for (size_t i = 0; i != 12; ++i) {
    CHECK_RESULT(grant, issueReadGrant(rsp.manifest.fragments[i], owner, rsp.pin));
    rsp.readGrants[i] = std::move(grant);
  }
  return Void{};
}
Result<Void> EcCoordinator::confirmReadDrained(const EcPinRecord &pin) const {
  if (pin.released) return Void{};
  return makeError(StatusCode::kNotImplemented, "cannot release a live EC pin without storage read-drain evidence");
}
}  // namespace hf3fs::meta::server
