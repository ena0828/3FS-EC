#include <algorithm>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/WithCancellation.h>

#include "fbs/storage/EcStageResultV2.h"
#include "storage/ec_scope/EcScopeLoadBudget.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"
#include "storage/update/EcAdmissionJob.h"
#include "storage/update/EcStageJob.h"

namespace hf3fs::storage {
namespace {
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
EcScopeBinding scopeBinding(const VerifiedEcGrantV2 &verified, const EcScopeTargetIdentity &target) {
  const auto &claims = verified.claims();
  EcScopeBinding result{};
  result.target = target;
  result.object = bytes(claims.scopeObject);
  result.kind = claims.scopeKind == EcGrantScope::ReadPin ? 1 : 2;
  result.scope = bytes(claims.scopeId);
  result.owner_uid = claims.ownerUid;
  result.client_namespace = bytes(claims.clientNamespace);
  return result;
}
EcFragmentReceiptV2 receipt(const EcFragmentAccessV2 &request, const EcScopeTargetIdentity &target) {
  EcFragmentReceiptV2 result;
  result.identity = request.identity;
  result.operationId = request.operationId;
  result.engineUuid = uuid(target.engine);
  result.targetIncarnation = uuid(target.incarnation);
  result.vChainId = request.vChainId;
  result.targetId = request.targetId;
  result.length = request.integrity.wholeLength;
  result.crc32c = request.integrity.wholeCrc32c;
  result.integrityRoot = request.integrity.root;
  return result;
}
}  // namespace

template <typename Request>
CoTryTask<StorageOperator::EcStageExecution> StorageOperator::executeEcStageV2(const Request &wire,
                                                                               EcStageOperation operation) {
  const EcScopeLoadBudget loadBudget{config_.ec_scope_load_wait_ms(), EcScopeLoadBudget::Clock::now(), std::nullopt};
  const auto &request = wire.request;
  const bool changesContent = operation == EcStageOperation::Begin || operation == EcStageOperation::Append ||
                              operation == EcStageOperation::Seal;
  const bool allocates = operation == EcStageOperation::Begin;
  if (changesContent && config_.read_only()) co_return makeError(StatusCode::kReadOnlyMode);
  auto selected = ecTarget(request.vChainId, request.targetId, allocates);
  CO_RETURN_ON_ERROR(selected);
  auto target = *selected;
  if (!target->storageTarget->usesEcStagingEngine()) {
    co_return makeError(StorageCode::kTargetStateInvalid, "V2 data methods require a fully restored staging target");
  }
  const auto *key = components_.getEcCapabilityKey();
  if (!key) co_return makeError(StatusCode::kAuthenticationFail, "V2 data capability key is not configured");
  auto scope = target->storageTarget->ecScopeState();
  CO_RETURN_ON_ERROR(scope);
  const auto identity = scope->second;
  const auto validate = [&, target, identity]() -> Result<VerifiedEcGrantV2> {
    if (changesContent && config_.read_only()) return makeError(StatusCode::kReadOnlyMode);
    RETURN_ON_ERROR(validateEcTarget(target, allocates));
    if (!target->storageTarget->usesEcStagingEngine()) {
      return makeError(StorageCode::kTargetStateInvalid, "V2 target changed during data operation");
    }
    RETURN_ON_ERROR(target->storageTarget->checkEcScopeTarget(identity));
    EcLocalTargetV2 local;
    local.engineUuid = uuid(identity.engine);
    local.targetIncarnation = uuid(identity.incarnation);
    local.vChainId = target->vChainId;
    local.targetId = target->targetId;
    local.nodeId = components_.appInfo.nodeId;
    return verifyEcRequestV2(*key, wire, local, ecAuthorizationNow_());
  };
  auto verified = validate();
  CO_RETURN_ON_ERROR(verified);
  // Reject instead of waiting with additional owned payloads. The generic
  // receiver and the disk queue retain independent bounded-resource limits.
  if (!ecFragmentSemaphore_.try_wait()) co_return makeError(StorageClientCode::kResourceBusy);
  auto releaseBudget = folly::makeGuard([this] { ecFragmentSemaphore_.signal(); });
  auto session = updateWorker_.acquireEcSession();
  CO_RETURN_ON_ERROR(session);
  const auto validateAccess = [&]() -> Result<Void> {
    auto current = validate();
    if (!current) return makeError(current.error());
    return Void{};
  };
  try {
    EcAdmissionJob admission(scopeBinding(*verified, identity),
                             scope->first,
                             *session,
                             target->storageTarget,
                             validateAccess,
                             [&]() {
                               return loadBudget.remaining(EcScopeLoadBudget::Clock::now(),
                                                           verified->claims().expiresAtSeconds,
                                                           ecAuthorizationNow_());
                             });
    // Submitted work is drained under an explicit empty token; queue-full work
    // is completed as ResourceBusy before any disk worker takes ownership.
    // Network timeout never ends ownership of a submitted borrowed job.
    co_await folly::coro::co_withCancellation(folly::CancellationToken{}, updateWorker_.enqueue(&admission));
    co_await folly::coro::co_withCancellation(folly::CancellationToken{}, admission.complete());
    auto ticket = admission.takeTicket();
    CO_RETURN_ON_ERROR(ticket);
    CO_RETURN_ON_ERROR(validateAccess());
    EcStageRequest input;
    input.operation = operation;
    input.identity = request.identity;
    input.vChainId = request.vChainId;
    input.targetId = request.targetId;
    input.operationId = request.operationId;
    input.integrity = request.integrity;
    if constexpr (std::is_same_v<Request, EcBeginStageV2Req>) {
      auto derived = deriveEcStageSpecV2(*verified);
      CO_RETURN_ON_ERROR(derived);
      input.writerNamespace = verified->claims().clientNamespace;
    }
    if constexpr (std::is_same_v<Request, EcReadBlockV2Req> || std::is_same_v<Request, EcAppendStageV2Req>) {
      // verifyEcRequestV2 rejected blockIndex >= the fixed sixteen-slot bound.
      input.blockIndex = static_cast<uint8_t>(wire.blockIndex);
    }
    if constexpr (std::is_same_v<Request, EcAppendStageV2Req>) input.payload = wire.payload.data;
    EcStageJob job(std::move(*ticket), *session, std::move(input), target->storageTarget, validateAccess);
    co_await folly::coro::co_withCancellation(folly::CancellationToken{}, updateWorker_.enqueue(&job));
    co_await folly::coro::co_withCancellation(folly::CancellationToken{}, job.complete());
    auto result = job.takeResult();
    CO_RETURN_ON_ERROR(result);
    co_return EcStageExecution{std::move(*result), identity};
  } catch (...) {
    // Borrowed jobs retain their owning frame, ticket and payload until the
    // actual worker completes, even if creating complete() itself throws.
    const bool durable = operation != EcStageOperation::ReadBlock && operation != EcStageOperation::Query;
    co_return makeError(durable ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  }
}

CoTryTask<EcReadBlockV2Rsp> StorageOperator::readEcBlockV2(const EcReadBlockV2Req &request) {
  EcReadBlockV2Rsp response;
  response.tag = request.request.tag;
  auto executed = co_await executeEcStageV2(request, EcStageOperation::ReadBlock);
  if (!executed) {
    response.result = makeError(executed.error());
    co_return response;
  }
  EcReadBlockResultV2 result;
  result.receipt = receipt(request.request, executed->second);
  result.blockIndex = request.blockIndex;
  result.payload.data = std::move(executed->first.data);
  response.result = std::move(result);
  co_return response;
}

template <typename Request>
CoTryTask<EcStageV2Rsp> StorageOperator::stageStateV2(const Request &request, EcStageOperation operation) {
  EcStageV2Rsp response;
  response.tag = request.request.tag;
  auto executed = co_await executeEcStageV2(request, operation);
  if (!executed) {
    response.result = makeError(executed.error());
    co_return response;
  }
  if (!executed->first.state || executed->first.sealed || !executed->first.data.empty()) {
    response.result =
        makeError(StorageCode::kEcSealOutcomeUnknown, "stage worker returned an unexpected response kind");
    co_return response;
  }
  const auto &state = *executed->first.state;
  EcStageStateV2 result;
  result.receipt = receipt(request.request, executed->second);
  result.state = state.state;
  result.prefixBytes = state.prefix_bytes;
  result.pendingBlock = state.pending_block;
  result.revision = state.revision;
  result.needsReconcile = state.needs_reconcile;
  response.result = std::move(result);
  co_return response;
}
CoTryTask<EcStageV2Rsp> StorageOperator::beginEcStageV2(const EcBeginStageV2Req &request) {
  return stageStateV2(request, EcStageOperation::Begin);
}
CoTryTask<EcStageV2Rsp> StorageOperator::appendEcStageV2(const EcAppendStageV2Req &request) {
  return stageStateV2(request, EcStageOperation::Append);
}
CoTryTask<EcStageV2Rsp> StorageOperator::queryEcStageV2(const EcQueryStageV2Req &request) {
  return stageStateV2(request, EcStageOperation::Query);
}
CoTryTask<EcStageV2Rsp> StorageOperator::reconcileEcStageV2(const EcReconcileStageV2Req &request) {
  return stageStateV2(request, EcStageOperation::Reconcile);
}
CoTryTask<EcSealStageV2Rsp> StorageOperator::sealEcStageV2(const EcSealStageV2Req &request) {
  EcSealStageV2Rsp response;
  response.tag = request.request.tag;
  auto executed = co_await executeEcStageV2(request, EcStageOperation::Seal);
  if (!executed) {
    response.result = makeError(executed.error());
    co_return response;
  }
  if (!executed->first.sealed || executed->first.state || !executed->first.data.empty()) {
    response.result = makeError(StorageCode::kEcSealOutcomeUnknown, "seal worker returned no confirmed receipt");
    co_return response;
  }
  response.result = receipt(request.request, executed->second);
  co_return response;
}
}  // namespace hf3fs::storage
