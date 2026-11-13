#include "detail/EcStripeClientCore.h"

#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::client::ec::detail {
Result<Void> EcStripeClientCore::validControl(const EcStripeControl &control) const {
  const auto now = std::chrono::steady_clock::now();
  if (control.deadline <= now || control.deadline - now > limits.maxOperationTime) {
    return makeError(StatusCode::kInvalidArg, "stripe deadline must be finite, future and within the manager limit");
  }
  return active(control);
}
Result<Void> EcStripeClientCore::active(const EcStripeControl &control) const {
  if (stop.isCancellationRequested() || control.cancellation.isCancellationRequested())
    return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
Result<Void> EcStripeClientCore::validOwner(const meta::EcOwner &value) const {
  if (value.uid != owner.uid || value.client != owner.client)
    return makeError(StatusCode::kInvalidArg, "EC response owner differs from authenticated UID and fixed namespace");
  return Void{};
}
Result<Void> EcStripeClientCore::validPin(const EcStripePinIds &value) const {
  if (value.object.incarnation.is_nil() || value.object.inode.isTreeRoot() || value.pin.is_nil() ||
      value.acquireRequest.is_nil() || value.releaseRequest.is_nil())
    return makeError(StatusCode::kInvalidArg, "pin and request identities must be persisted before starting");
  return Void{};
}
Result<Void> EcStripeClientCore::validIds(const EcStripeMutationIds &value) const {
  if (value.operation.is_nil() || value.beginRequest.is_nil() || value.bindRequest.is_nil() ||
      value.publishRequest.is_nil() || value.getRequest.is_nil())
    return makeError(StatusCode::kInvalidArg, "operation and request identities must be persisted before starting");
  return Void{};
}
void EcStripeClientCore::request(meta::ReqBase &value, const Uuid &id) const {
  value.user = credentials;
  value.client = ClientId{owner.client};
  value.uuid = id;
}
Result<storage::VersionedChainId> EcStripeClientCore::route(const storage::EcScopeEndpoint &endpoint) const {
  const auto routing = mgmtd->getRoutingInfo();
  if (!routing) return makeError(StorageClientCode::kNotInitialized, "routing information unavailable");
  const auto chain = routing->getChain(endpoint.chainId);
  const auto target = routing->getTarget(endpoint.targetId);
  const auto node = routing->getNode(endpoint.nodeId);
  if (!chain || !target || !node || chain->targets.size() != 1 || chain->targets[0].targetId != endpoint.targetId ||
      chain->targets[0].publicState != flat::PublicTargetState::SERVING ||
      target->publicState != flat::PublicTargetState::SERVING || target->chainId != endpoint.chainId ||
      target->nodeId != endpoint.nodeId || node->type != flat::NodeType::STORAGE ||
      node->status != flat::NodeStatus::HEARTBEAT_CONNECTED) {
    return makeError(StorageClientCode::kNotInitialized,
                     "fixed EC endpoint is absent or not serving in current routing");
  }
  return storage::VersionedChainId{endpoint.chainId, chain->chainVersion};
}
CoTask<void> EcStripeClientCore::close(std::shared_ptr<EcStripeClientCore> core) {
  bool first = false;
  {
    std::lock_guard lock(core->mutex);
    first = !core->closing;
    core->closing = true;
  }
  if (first) {
    core->stop.requestCancellation();
    co_await folly::coro::co_withCancellation(CancellationToken{}, core->tasks.joinAsync());
    core->closed.post();
  } else {
    co_await core->closed;
  }
}
CoTryTask<meta::CreateEcFileRsp> EcStripeClientCore::createOwned(meta::CreateEcFileV2Req value,
                                                                 EcStripeControl control) {
  CO_RETURN_ON_ERROR(validControl(control));
  if (value.uuid.is_nil()) co_return makeError(StatusCode::kInvalidArg, "create request UUID must be persisted");
  request(value, value.uuid);
  // MetaClient's existing RPC/retry timeout governs an already issued call.
  // An expired outer deadline stops new stages but never destroys that frame.
  auto result = co_await meta->createEcFileV2(std::move(value));
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(validOwner(result->object.creator));
  co_return std::move(*result);
}
CoTryTask<meta::ReleaseEcReadV2Rsp> EcStripeClientCore::releaseOwned(EcStripePinIds value, EcStripeControl control) {
  CO_RETURN_ON_ERROR(validPin(value));
  CO_RETURN_ON_ERROR(validControl(control));
  meta::ReleaseEcReadV2Req req;
  request(req, value.releaseRequest);
  req.object = value.object;
  req.stripe = value.stripe;
  req.pin = value.pin;
  auto result = co_await meta->releaseEcReadV2(std::move(req));
  CO_RETURN_ON_ERROR(result);
  if (result->pin != value.pin || result->drain.expectedEndpoints == 0 ||
      result->drain.terminalEndpoints() > result->drain.expectedEndpoints ||
      (result->drain.state == meta::EcV2DrainState::ReadReleased &&
       result->drain.terminalEndpoints() != result->drain.expectedEndpoints)) {
    co_return makeError(StatusCode::kDataCorruption, "inconsistent remote pin drain result");
  }
  // Closing is a real pending result, never reported as released or GC-safe.
  co_return std::move(*result);
}
Result<Void> EcStripeClientCore::validateObservation(const meta::EcV2MutationRsp &response,
                                                     const meta::BeginEcMutationV2Req &expected) const {
  const auto &intent = response.record.intent;
  RETURN_ON_ERROR(validOwner(response.record.owner));
  if (intent.object != expected.object || intent.operation != expected.operation || intent.stripe != expected.stripe ||
      intent.expectedEpoch != expected.expectedEpoch || intent.expectedRevision != expected.expectedRevision ||
      intent.logicalLength != expected.logicalLength || intent.kind != expected.kind ||
      intent.replacementMask != expected.replacementMask || intent.fragmentCrc32c != expected.fragmentCrc32c ||
      response.object.object != expected.object || !response.reservation ||
      response.reservation->contentSha256 != expected.contentSha256) {
    return makeError(StatusCode::kTokenMismatch, "persisted EC operation differs from the original request");
  }
  CHECK_RESULT(digest, meta::computeEcRequestDigest(intent, response.object.shardBytes, expected.contentSha256));
  if (digest != intent.requestDigest || !serde::equals(response.reservation->original.intent, intent) ||
      response.record.candidate.object != expected.object || response.record.candidate.stripe != expected.stripe ||
      response.record.candidate.logicalLength != expected.logicalLength) {
    return makeError(StatusCode::kDataCorruption, "persisted request digest or reservation differs");
  }
  return Void{};
}
CoTryTask<meta::EcV2MutationRsp> EcStripeClientCore::getOperation(const meta::EcObjectRef &object,
                                                                  const EcStripeMutationIds &ids,
                                                                  EcStripeControl control) {
  CO_RETURN_ON_ERROR(active(control));
  meta::GetEcOperationV2Req req;
  request(req, ids.getRequest);
  req.object = object;
  req.operation = ids.operation;
  co_return co_await meta->getEcOperationV2(std::move(req));
}
CoTryTask<meta::EcV2MutationRsp> EcStripeClientCore::begin(meta::BeginEcMutationV2Req req,
                                                           const EcStripeMutationIds &ids,
                                                           EcStripeControl control) {
  request(req, ids.beginRequest);
  std::optional<Status> last;
  for (unsigned attempt = 0; attempt != limits.recoveryAttempts; ++attempt) {
    CO_RETURN_ON_ERROR(active(control));
    auto result = co_await meta->beginEcMutationV2(req);
    if (result) {
      CO_RETURN_ON_ERROR(validateObservation(*result, req));
      co_return std::move(*result);
    }
    last = result.error();
    auto observed = co_await getOperation(req.object, ids, control);
    if (observed) {
      CO_RETURN_ON_ERROR(validateObservation(*observed, req));
      co_return std::move(*observed);
    }
    // An unsuccessful Get proves nothing about existence. Repeat only the
    // exact same Begin; it is the server's durable intent CAS that arbitrates.
  }
  co_return makeError(*last);
}
CoTryTask<meta::EcV2MutationRsp> EcStripeClientCore::bind(
    const meta::BeginEcMutationV2Req &beginReq,
    const EcStripeMutationIds &ids,
    const std::array<storage::EcIntegrityDescriptor, 12> &descriptors,
    EcStripeControl control) {
  meta::BindEcMutationV2Req req;
  request(req, ids.bindRequest);
  req.object = beginReq.object;
  req.operation = ids.operation;
  req.descriptors = descriptors;
  std::optional<Status> last;
  for (unsigned attempt = 0; attempt != limits.recoveryAttempts; ++attempt) {
    CO_RETURN_ON_ERROR(active(control));
    auto result = co_await meta->bindEcMutationV2(req);
    if (result) {
      CO_RETURN_ON_ERROR(validateObservation(*result, beginReq));
      if (result->record.state != meta::EcOperationState::Preparing || result->drain) co_return std::move(*result);
      if (!result->allocations) co_return makeError(StatusCode::kDataCorruption, "Bind omitted fixed allocations");
      for (size_t i = 0; i != 12; ++i) {
        const auto &allocation = (*result->allocations)[i];
        const auto &reserved = result->reservation->candidates[i];
        if (!result->grants[i] || allocation.object != beginReq.object ||
            allocation.fragment.integrity != descriptors[i] ||
            !serde::equals(allocation.fragment.identity, reserved.identity) ||
            allocation.fragment.operation != reserved.operation || allocation.endpoint() != reserved.endpoint ||
            allocation.writer.uid != reserved.writer.uid || allocation.writer.client != reserved.writer.client) {
          co_return makeError(StatusCode::kDataCorruption, "Bind differs from its immutable reservation");
        }
      }
      co_return std::move(*result);
    }
    last = result.error();
    auto observed = co_await getOperation(req.object, ids, control);
    if (observed) {
      CO_RETURN_ON_ERROR(validateObservation(*observed, beginReq));
      if (observed->record.state != meta::EcOperationState::Preparing || observed->drain)
        co_return std::move(*observed);
    }
  }
  co_return makeError(*last);
}
CoTryTask<meta::EcV2MutationRsp> EcStripeClientCore::publish(const meta::EcObjectRef &object,
                                                             const EcStripeMutationIds &ids,
                                                             EcStripeControl control) {
  std::optional<Status> last;
  for (unsigned attempt = 0; attempt != limits.recoveryAttempts; ++attempt) {
    CO_RETURN_ON_ERROR(active(control));
    meta::PublishEcMutationV2Req req;
    request(req, ids.publishRequest);
    req.object = object;
    req.operation = ids.operation;
    auto result = co_await meta->publishEcMutationV2(std::move(req));
    if (result) co_return std::move(*result);
    last = result.error();
    auto observed = co_await getOperation(object, ids, control);
    if (observed && observed->record.state != meta::EcOperationState::Preparing) co_return std::move(*observed);
  }
  auto observed = co_await getOperation(object, ids, control);
  if (observed) co_return std::move(*observed);
  co_return makeError(*last);
}
}  // namespace hf3fs::client::ec::detail
