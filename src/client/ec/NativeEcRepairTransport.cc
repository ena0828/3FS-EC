#include "NativeEcRepairTransport.h"

#include <algorithm>

#include "client/ec/EcBlockRead.h"
#include "client/ec/NativeEcBlockTransport.h"
#include "client/storage/EcRequestControl.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_repair/EcHelperAuthorization.h"
#include "storage/ec_repair/EcHelperDirectAuthorization.h"

namespace hf3fs::client::ec {
namespace {
using namespace hf3fs::storage;

Result<Void> binding(const EcRepairPlan &plan,
                     const EcRepairFragment &fragment,
                     const EcFragmentAccessV2 &request,
                     const EcCapabilityV2 &grant,
                     uint16_t rights) {
  CHECK_RESULT(integrityDigest, digestEcIntegrityV2(fragment.identity, fragment.integrity));
  const auto &claims = grant.claims;
  if (request.version != kEcGrantVersionV2 || !serde::equals(request.identity, fragment.identity) ||
      request.operationId != fragment.operationId || request.vChainId.chainId != fragment.endpoint.chainId ||
      request.targetId != fragment.endpoint.targetId || request.integrity != fragment.integrity ||
      claims.version != kEcGrantVersionV2 || (claims.rights & rights) != rights ||
      !serde::equals(claims.identity, fragment.identity) || claims.fragmentOperationId != fragment.operationId ||
      claims.chainId != fragment.endpoint.chainId || claims.targetId != fragment.endpoint.targetId ||
      claims.nodeId != fragment.endpoint.nodeId || claims.engineUuid != fragment.endpoint.engineUuid ||
      claims.targetIncarnation != fragment.endpoint.targetIncarnation ||
      claims.expectedLength != fragment.integrity.wholeLength ||
      claims.expectedCrc32c != fragment.integrity.wholeCrc32c || claims.integrityDigest != integrityDigest ||
      claims.scopeKind != EcGrantScope::WriteOperation || claims.scopeId != plan.input().operationId ||
      claims.scopeObject != fragment.identity.object || claims.ownerUid != plan.input().ownerUid ||
      claims.clientNamespace != plan.input().clientNamespace) {
    return makeError(StatusCode::kInvalidArg, "native repair grant/request differs from fixed operation plan");
  }
  // These comparisons do not authenticate the bearer. Storage independently
  // verifies its MAC, current route, actual instance and fresh expiry three times.
  return Void{};
}

Result<Void> receipt(const EcRepairFragment &expected, const EcFragmentReceiptV2 &value) {
  if (value.version != kEcGrantVersionV2 || !serde::equals(value.identity, expected.identity) ||
      value.operationId != expected.operationId || value.engineUuid != expected.endpoint.engineUuid ||
      value.targetIncarnation != expected.endpoint.targetIncarnation ||
      value.vChainId.chainId != expected.endpoint.chainId || value.targetId != expected.endpoint.targetId ||
      value.length != expected.integrity.wholeLength || value.crc32c != expected.integrity.wholeCrc32c ||
      value.integrityRoot != expected.integrity.root) {
    return makeError(StatusCode::kDataCorruption, "native repair receipt differs from fixed allocation");
  }
  return Void{};
}

Result<Void> stage(const EcRepairFragment &expected,
                   const EcStageStateV2 &state,
                   uint32_t minimumPrefix,
                   bool allowPending = false) {
  RETURN_ON_ERROR(receipt(expected, state.receipt));
  if (state.state == 3) return makeError(StatusCode::kInvalidArg, "fixed repair stage is durably aborted");
  if ((state.state != 1 && state.state != 2) || (state.pendingBlock && !allowPending) || state.needsReconcile ||
      state.prefixBytes < minimumPrefix || state.prefixBytes > expected.integrity.wholeLength) {
    return makeError(StorageCode::kEcSealOutcomeUnknown, "repair stage requires explicit reconciliation");
  }
  return Void{};
}
storage::client::EcRequestControl options(EcRepairControl control, EcRepairObservation *observation) {
  return {control.deadline, control.cancellation, storage::client::EcRequestControl::TransportPolicy::TcpOnly,
          observation ? &observation->selectedRepairRpc() : nullptr};
}
}  // namespace

Result<std::shared_ptr<NativeEcRepairTransport>> NativeEcRepairTransport::create(
    Plan plan,
    std::shared_ptr<storage::client::StorageClient> client,
    EcRepairNativeBindings bindings,
    std::optional<std::array<storage::EcHelperCapability, 10>> helpers,
    EcRepairObservation *observation,
    std::optional<EcHelperDirectDelegation> direct) {
  if (!plan || !client) return makeError(StatusCode::kInvalidArg, "native repair requires plan and StorageClient");
  for (size_t i = 0; i != 10; ++i) {
    RETURN_ON_ERROR(binding(*plan,
                            plan->input().sources[i],
                            bindings.sources[i].request,
                            bindings.sources[i].grant,
                            uint16_t(EcGrantRightV2::ReadBlock)));
    const auto &source = plan->input().sources[i];
    RETURN_ON_ERROR(makeEcReadBlockRequest({source.identity, source.operationId, source.endpoint, source.integrity},
                                           bindings.sources[i].grant,
                                           bindings.sources[i].request.vChainId,
                                           0));
  }
  for (size_t i = 0; i != plan->input().targetCount; ++i) {
    RETURN_ON_ERROR(binding(*plan,
                            plan->input().targets[i],
                            bindings.targets[i].request,
                            bindings.targets[i].grant,
                            uint16_t(EcGrantRightV2::Begin) | uint16_t(EcGrantRightV2::Append) |
                                uint16_t(EcGrantRightV2::Query) | uint16_t(EcGrantRightV2::Reconcile) |
                                uint16_t(EcGrantRightV2::Seal)));
  }
  if (direct) {
    if (!helpers) return makeError(StatusCode::kInvalidArg, "direct delivery requires native helper capabilities");
    RETURN_ON_ERROR(validateEcHelperDirectDelegation(*plan, *direct, 0));
  }
  return std::shared_ptr<NativeEcRepairTransport>(
      new NativeEcRepairTransport(
          std::move(plan), std::move(client), std::move(bindings), std::move(helpers), observation, std::move(direct)));
}

Result<Void> NativeEcRepairTransport::check(const Plan &plan, const EcRepairControl &control) const {
  if (!plan || plan->digest() != plan_->digest())
    return makeError(StatusCode::kInvalidArg, "native repair plan changed");
  if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}

Status NativeEcRepairTransport::preserveOutcome(uint8_t target, Status error) {
  if (error.code() == StorageCode::kEcSealOutcomeUnknown) unconfirmed_[target].store(true);
  if (unconfirmed_[target].load() && error.code() != StorageCode::kEcSealOutcomeUnknown)
    return error.convert(StorageCode::kEcSealOutcomeUnknown);
  return error;
}

CoTryTask<void> NativeEcRepairTransport::begin(Plan plan, uint8_t target, EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeBegin);
  if (target >= plan_->input().targetCount) co_return makeError(StatusCode::kInvalidArg);
  const auto failure = [&](Status error) { return makeError(preserveOutcome(target, std::move(error))); };
  if (auto active = check(plan, control); !active) co_return failure(active.error());
  const auto request = bindings_.targets[target];
  // A resumed direct chain can have appended without returning its small ACK.
  // Re-establish the original allocation's durable state even when a fresh
  // adapter has no in-memory uncertainty from that prior process.
  if (direct_) unconfirmed_[target].store(true);
  metric.noteInvocation();
  auto result = co_await client_->beginEcStageV2Controlled(request, options(control, observation_));
  uint32_t observedPrefix = 0;
  if (!result) {
    auto error = preserveOutcome(target, result.error());
    if (error.code() != StorageCode::kEcSealOutcomeUnknown) co_return makeError(error);
  } else {
    auto valid = validateEcStageStateV2(*result, request.request, request.grant.claims);
    if (!valid) {
      unconfirmed_[target].store(true);
      co_return failure(valid.error());
    }
    observedPrefix = result->prefixBytes;
    if (result->needsReconcile || result->pendingBlock) unconfirmed_[target].store(true);
  }
  if (unconfirmed_[target].load()) {
    if (auto active = check(plan, control); !active) co_return failure(active.error());
    EcQueryStageV2Req query{request.request, request.grant};
    metric.noteInvocation();
    auto observed = co_await client_->queryEcStageV2Controlled(std::move(query), options(control, observation_));
    if (observed) {
      auto valid = validateEcStageStateV2(*observed, request.request, request.grant.claims);
      if (!valid) co_return failure(valid.error());
      observedPrefix = std::max(observedPrefix, observed->prefixBytes);
    }
    // Query is not a barrier. Even a missing/unconfirmed observation may be a
    // lost reservation ACK: Reconcile can reassert that same held allocation.
    // It can never allocate another identity, instance or position here.
    if (auto active = check(plan, control); !active) co_return failure(active.error());
    EcReconcileStageV2Req reconcile{request.request, request.grant};
    metric.noteInvocation();
    result = co_await client_->reconcileEcStageV2Controlled(std::move(reconcile), options(control, observation_));
    if (!result) co_return failure(result.error());
    auto valid = validateEcStageStateV2(*result, request.request, request.grant.claims);
    if (!valid) co_return failure(valid.error());
    if (result->needsReconcile || result->prefixBytes < observedPrefix)
      co_return failure(Status(StorageCode::kEcSealOutcomeUnknown, "repair reconciliation is not confirmed"));
    if (auto active = check(plan, control); !active) co_return failure(active.error());
    unconfirmed_[target].store(false);
  }
  if (auto active = check(plan, control); !active) {
    unconfirmed_[target].store(true);
    co_return failure(active.error());
  }
  // A reconciled pending intent is deliberately not promoted by Rust. Replay
  // its original bound block after the confirmed prefix; exact duplicates of
  // earlier blocks remain checked by Engine::append.
  auto valid = stage(plan_->input().targets[target], *result, observedPrefix, true);
  if (!valid) co_return failure(valid.error());
  alreadySealed_[target].store(result->state == 2);
  metric.success();
  co_return Void{};
}

CoTryTask<std::string> NativeEcRepairTransport::read(Plan plan,
                                                     uint8_t source,
                                                     uint32_t block,
                                                     EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeRead);
  CO_RETURN_ON_ERROR(check(plan, control));
  if (source >= 10) co_return makeError(StatusCode::kInvalidArg);
  CO_RETURN_ON_ERROR(plan->blockLength(block));
  const auto &expected = plan_->input().sources[source];
  auto request =
      makeEcReadBlockRequest({expected.identity, expected.operationId, expected.endpoint, expected.integrity},
                             bindings_.sources[source].grant,
                             bindings_.sources[source].request.vChainId,
                             block);
  CO_RETURN_ON_ERROR(request);
  NativeEcBlockTransport transport(client_, observation_ ? &observation_->selectedRepairRpc() : nullptr);
  metric.noteInvocation();
  auto result = co_await transport.read(std::move(*request), {control.deadline, control.cancellation});
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(check(plan, control));
  CO_RETURN_ON_ERROR(receipt(expected, result->receipt));
  if (result->blockIndex != block) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(verifyEcIntegrityBlock(expected.identity, expected.integrity, block, result->payload.data));
  metric.validated(result->payload.data.size());
  metric.success();
  co_return std::move(result->payload.data);
}

CoTryTask<void> NativeEcRepairTransport::append(Plan plan,
                                                uint8_t target,
                                                uint32_t block,
                                                std::string data,
                                                EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeAppend);
  if (target >= plan_->input().targetCount) co_return makeError(StatusCode::kInvalidArg);
  const auto failure = [&](Status error) { return makeError(preserveOutcome(target, std::move(error))); };
  if (auto active = check(plan, control); !active) co_return failure(active.error());
  const auto &expected = plan_->input().targets[target];
  auto validBlock = verifyEcIntegrityBlock(expected.identity, expected.integrity, block, data);
  if (!validBlock) co_return failure(validBlock.error());
  // Begin may recover the durable result of an earlier Seal whose ACK was
  // lost. A sealed allocation cannot accept append; retain its immutable bytes
  // and require another real Seal barrier below instead of rewriting them.
  if (alreadySealed_[target].load()) {
    metric.success();
    co_return Void{};
  }
  EcAppendStageV2Req request;
  request.request = bindings_.targets[target].request;
  request.grant = bindings_.targets[target].grant;
  request.blockIndex = block;
  request.payload.data = std::move(data);
  metric.noteInvocation(request.payload.data.size());
  auto result = co_await client_->appendEcStageV2Controlled(std::move(request), options(control, observation_));
  if (!result) co_return failure(result.error());
  if (!check(plan, control))
    co_return failure(
        Status(StorageCode::kEcSealOutcomeUnknown, "repair Append completed after local deadline/cancellation"));
  auto shape =
      validateEcStageStateV2(*result, bindings_.targets[target].request, bindings_.targets[target].grant.claims);
  if (!shape) {
    unconfirmed_[target].store(true);
    co_return failure(shape.error());
  }
  auto valid = stage(expected, *result, block * kEcIntegrityBlockBytes + expected.integrity.blocks[block].validLength);
  if (!valid) co_return failure(valid.error());
  metric.success();
  co_return Void{};
}

CoTryTask<storage::EcFragmentReceiptV2> NativeEcRepairTransport::seal(Plan plan,
                                                                      uint8_t target,
                                                                      EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeSeal);
  if (target >= plan_->input().targetCount) co_return makeError(StatusCode::kInvalidArg);
  const auto failure = [&](Status error) { return makeError(preserveOutcome(target, std::move(error))); };
  if (auto active = check(plan, control); !active) co_return failure(active.error());
  EcSealStageV2Req request;
  request.request = bindings_.targets[target].request;
  request.grant = bindings_.targets[target].grant;
  metric.noteInvocation();
  auto result = co_await client_->sealEcStageV2Controlled(std::move(request), options(control, observation_));
  if (!result) co_return failure(result.error());
  if (!check(plan, control))
    co_return failure(
        Status(StorageCode::kEcSealOutcomeUnknown, "repair Seal completed after local deadline/cancellation"));
  auto valid = receipt(plan_->input().targets[target], *result);
  if (!valid) {
    unconfirmed_[target].store(true);
    co_return failure(valid.error());
  }
  unconfirmed_[target].store(false);
  metric.success();
  co_return std::move(*result);
}

CoTryTask<storage::EcRepairBlock> NativeEcRepairTransport::helperBlock(Plan plan,
                                                                       uint32_t block,
                                                                       EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeHelper);
  CO_RETURN_ON_ERROR(check(plan, control));
  if (!helpers_) co_return makeError(StatusCode::kNotImplemented, "native helper capabilities were not supplied");
  auto seed = EcRepairBlockCore::begin(*plan_, block);
  CO_RETURN_ON_ERROR(seed);
  EcHelperHopReq request;
  request.plan = plan_->input();
  request.helpers = *helpers_;
  for (size_t i = 0; i != 10; ++i) {
    request.reads[i] = bindings_.sources[i].grant;
    request.routeVersions[i] = bindings_.sources[i].request.vChainId.chainVer;
  }
  request.packet = helperPacket(std::move(*seed));
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(control.deadline - std::chrono::steady_clock::now());
  if (remaining.count() <= 0) co_return makeError(StorageClientCode::kTimeout);
  const auto wall =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count();
  request.deadlineUnixMillis = wall + std::min<int64_t>(60000, remaining.count());
  storage::client::EcRequestControl options{control.deadline,
                                            control.cancellation,
                                            storage::client::EcRequestControl::TransportPolicy::TcpOnly,
                                            observation_ ? &observation_->selectedRepairRpc() : nullptr};
  metric.noteInvocation();
  auto response = co_await client_->executeEcHelper(std::move(request), options);
  CO_RETURN_ON_ERROR(response);
  CO_RETURN_ON_ERROR(check(plan, control));
  if (response->packet.blockIndex != block) co_return makeError(StatusCode::kDataCorruption);
  auto result = repairBlock(std::move(response->packet));
  CO_RETURN_ON_ERROR(EcRepairBlockCore::validateComplete(*plan_, result));
  // Clients do not possess the helper MAC key. Actual target block hashes are
  // checked here; upstream Storage verifies finalStamp in every forwarding hop.
  for (size_t target = 0; target != result.targetCount; ++target) metric.validated(result.outputs[target].size());
  metric.success();
  co_return result;
}

CoTryTask<void> NativeEcRepairTransport::helperDirectBlock(Plan plan,
                                                            uint32_t block,
                                                            EcRepairControl control) {
  EcRepairObservation::Scope metric(observation_, EcRepairPoint::NativeHelper);
  uint8_t activeMask = 0;
  for (uint8_t target = 0; target != plan_->input().targetCount; ++target) {
    if (!alreadySealed_[target].load()) activeMask |= uint8_t{1} << target;
  }
  bool dispatched = false;
  const auto failure = [&](Status error) {
    bool unknown = dispatched;
    for (uint8_t target = 0; target != plan_->input().targetCount; ++target) {
      if (activeMask & (uint8_t{1} << target)) {
        if (dispatched || error.code() == StorageCode::kEcSealOutcomeUnknown) unconfirmed_[target].store(true);
        unknown = unknown || unconfirmed_[target].load();
      }
    }
    return unknown ? error.convert(StorageCode::kEcSealOutcomeUnknown) : error;
  };
  const auto exception = [&]() noexcept {
    // Pipeline also guards task creation. Retain uncertainty in this adapter
    // before returning, so another block cannot clear an unconfirmed mutation.
    if (dispatched) {
      for (uint8_t target = 0; target != plan_->input().targetCount; ++target) {
        if (activeMask & (uint8_t{1} << target)) unconfirmed_[target].store(true);
      }
    }
    return makeError(StorageCode::kEcSealOutcomeUnknown);
  };
  try {
    if (auto ready = check(plan, control); !ready) co_return makeError(failure(ready.error()));
    if (!supportsHelperDirect())
      co_return makeError(failure(Status(StatusCode::kNotImplemented, "native helper direct delegation was not supplied")));
    auto seed = EcRepairBlockCore::begin(*plan_, block);
    if (!seed) co_return makeError(failure(seed.error()));
    if (!activeMask) {
      // Every target was already sealed by a previous attempt. The enclosing
      // pipeline still performs a real Seal for each original allocation.
      metric.success();
      co_return Void{};
    }
    EcHelperDirectHopReq request;
    request.plan = plan_->input();
    request.helpers = *helpers_;
    request.delegation = *direct_;
    request.activeTargetMask = activeMask;
    for (size_t source = 0; source != 10; ++source) {
      request.reads[source] = bindings_.sources[source].grant;
      request.sourceRouteVersions[source] = bindings_.sources[source].request.vChainId.chainVer;
    }
    for (uint8_t target = 0; target != plan_->input().targetCount; ++target) {
      request.targetRouteVersions[target] = bindings_.targets[target].request.vChainId.chainVer;
    }
    request.packet = helperPacket(std::move(*seed));
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(control.deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) co_return makeError(failure(Status(StorageClientCode::kTimeout)));
    const auto wall =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    request.deadlineUnixMillis = wall + std::min<int64_t>(60000, remaining.count());
    if (auto valid = validateEcHelperDirectRequest(*plan_, request); !valid)
      co_return makeError(failure(valid.error()));
    if (auto ready = check(plan, control); !ready) co_return makeError(failure(ready.error()));
    dispatched = true;
    metric.noteInvocation();
    // Keep the bounded original request to validate the complete context. The
    // SDK owns its copy until the actual local RPC task completes.
    auto response = co_await client_->executeEcHelperDirect(request, options(control, observation_));
    if (!response) co_return makeError(failure(response.error()));
    if (auto ready = check(plan, control); !ready) co_return makeError(failure(ready.error()));
    if (auto valid = validateEcHelperDirectResult(*plan_, request, *response); !valid)
      co_return makeError(failure(valid.error()));
    // This client has no helper MAC key and receives no reconstructed payload.
    // Do not count bytes as client-hash-validated or clear prior uncertainty.
    // True Seal and Meta's full readback/publication barriers remain required.
    metric.success();
    co_return Void{};
  } catch (...) {
    co_return exception();
  }
}

}  // namespace hf3fs::client::ec
