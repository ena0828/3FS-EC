#include <chrono>
#include <folly/ScopeGuard.h>

#include "common/monitor/Recorder.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
namespace {
monitor::OperationRecorder ecCreateRecorder{"storage.ec_create_fragment"};
monitor::OperationRecorder ecReadRecorder{"storage.ec_read_fragment"};
monitor::OperationRecorder ecReconcileRecorder{"storage.ec_reconcile_fragment"};

template <typename Request>
EcGrantBinding grantBinding(const Request &request, const EcCapability &grant, NodeId localNode) {
  EcGrantBinding expected;
  expected.identity = request.identity;
  expected.fragmentOperationId = request.operationId;
  expected.chainId = request.vChainId.chainId;
  expected.targetId = request.targetId;
  expected.nodeId = localNode;
  if constexpr (std::is_same_v<Request, EcCreateReq>) {
    expected.expectedLength = static_cast<uint32_t>(request.payload.data.size());
  } else {
    expected.expectedLength = request.expectedLength;
  }
  expected.expectedCrc32c = ~request.checksum.value;
  // These are signed bearer-scope claims, not authenticated request.userInfo.
  expected.ownerUid = grant.claims.ownerUid;
  expected.clientUuid = grant.claims.clientUuid;
  expected.scopeObject = request.identity.object;
  expected.scopeKind = grant.claims.scopeKind;
  expected.scopeId = grant.claims.scopeId;
  return expected;
}
}  // namespace

Result<Void> StorageOperator::validateUnsafeEcAccess() const {
  if (!config_.allow_unsafe_ec_fragment_rpc_for_testing()) {
    return makeError(StatusCode::kAuthenticationFail, "uncredentialed EC fragment RPC is disabled");
  }
  return Void{};
}

StorageOperator::EcValidation StorageOperator::ecAuthorization(const EcCapability &grant,
                                                               EcGrantBinding expected,
                                                               EcGrantRight right) const {
  return [this, &grant, expected = std::move(expected), right]() -> Result<Void> {
    const auto *key = components_.getEcCapabilityKey();
    if (!key) return makeError(StatusCode::kAuthenticationFail, "EC capability verification key is not configured");
    if (right != EcGrantRight::Read && expected.scopeKind != EcGrantScope::WriteOperation) {
      return makeError(StatusCode::kAuthenticationFail, "EC durable operations require a write-operation grant");
    }
    return verifyEcGrant(*key, grant, expected, right, ecAuthorizationNow_(), kEcGrantMaxTtlSeconds);
  };
}

CoTryTask<EcCreateRsp> StorageOperator::createEcFragment(const EcCreateReq &req) {
  return createEcFragmentImpl(req, [this] { return validateUnsafeEcAccess(); });
}

CoTryTask<EcReadRsp> StorageOperator::readEcFragment(const EcReadReq &req) {
  return readEcFragmentImpl(req, [this] { return validateUnsafeEcAccess(); });
}

CoTryTask<EcReconcileRsp> StorageOperator::reconcileEcFragment(const EcReconcileReq &req) {
  return reconcileEcFragmentImpl(req, [this] { return validateUnsafeEcAccess(); });
}

CoTryTask<EcCreateRsp> StorageOperator::authorizedCreateEcFragment(const EcAuthorizedCreateReq &req) {
  return createEcFragmentImpl(req.request,
                              ecAuthorization(req.grant,
                                              grantBinding(req.request, req.grant, components_.appInfo.nodeId),
                                              EcGrantRight::Create));
}

CoTryTask<EcReadRsp> StorageOperator::authorizedReadEcFragment(const EcAuthorizedReadReq &req) {
  return readEcFragmentImpl(
      req.request,
      ecAuthorization(req.grant, grantBinding(req.request, req.grant, components_.appInfo.nodeId), EcGrantRight::Read));
}

CoTryTask<EcReconcileRsp> StorageOperator::authorizedReconcileEcFragment(const EcAuthorizedReconcileReq &req) {
  return reconcileEcFragmentImpl(req.request,
                                 ecAuthorization(req.grant,
                                                 grantBinding(req.request, req.grant, components_.appInfo.nodeId),
                                                 EcGrantRight::Reconcile));
}

Result<TargetPtr> StorageOperator::ecTarget(VersionedChainId chain, TargetId targetId, bool writing) const {
  if (!config_.enable_ec_fragments()) {
    return makeError(StatusCode::kNotImplemented, "immutable EC fragment service is disabled");
  }
  if (writing && config_.read_only()) {
    return makeError(StatusCode::kReadOnlyMode, "immutable EC fragment service is readonly");
  }
  CHECK_RESULT(target, components_.targetMap.getByChainId(chain));
  if (target->targetId != targetId || !target->ecOnly || target->chainMemberCount != 1 || !target->storageTarget ||
      !target->storageTarget->ecOnly() || !target->useChunkEngine || !target->isHead || !target->isTail ||
      target->successor || !target->upToDate() || target->publicState != flat::PublicTargetState::SERVING) {
    return makeError(StorageCode::kTargetStateInvalid,
                     "EC fragments require the exact serving single-member EC target");
  }
  if (writing && target->rejectCreateChunk) {
    return makeError(StorageClientCode::kNoSpace, "EC target is rejecting new fragments");
  }
  return target;
}

Result<Void> StorageOperator::validateEcTarget(const TargetPtr &expected, bool writing) const {
  CHECK_RESULT(current, ecTarget(expected->vChainId, expected->targetId, writing));
  if (current->storageTarget != expected->storageTarget ||
      current->storageTarget->generationId() != expected->storageTarget->generationId()) {
    return makeError(StorageCode::kTargetStateInvalid, "EC target instance changed during the operation");
  }
  return Void{};
}

CoTryTask<EcCreateTargetRsp> StorageOperator::createEcTarget(const EcCreateTargetReq &req) {
  if (!config_.enable_ec_fragments()) {
    co_return makeError(StatusCode::kNotImplemented, "immutable EC fragment service is disabled");
  }
  if (config_.read_only()) {
    co_return makeError(StatusCode::kReadOnlyMode, "immutable EC fragment service is readonly");
  }
  if (req.version != kEcFragmentProtocolVersion || !req.settings.onlyChunkEngine || req.settings.addChunkSize ||
      req.settings.chainId == ChainId{} || req.settings.targetId == TargetId{}) {
    co_return makeError(StatusCode::kInvalidArg, "EC target requires version 1 and an explicit immutable engine chain");
  }
  auto created = components_.storageTargets.create(req.settings, true);
  if (!created) co_return makeError(created.error());
  EcCreateTargetRsp rsp;
  rsp.targetId = req.settings.targetId;
  co_return rsp;
}

CoTryTask<EcCreateRsp> StorageOperator::createEcFragmentImpl(const EcCreateReq &req, EcValidation authorization) {
  auto record = ecCreateRecorder.record();
  EcCreateRsp rsp;
  rsp.tag = req.tag;
  auto authorized = authorization();
  if (!authorized) {
    rsp.result = makeError(authorized.error());
    co_return rsp;
  }
  auto valid = req.validate();
  if (!valid) {
    rsp.result = makeError(valid.error());
    co_return rsp;
  }
  const auto checksum = ChecksumInfo::create(ChecksumType::CRC32C,
                                             reinterpret_cast<const uint8_t *>(req.payload.data.data()),
                                             req.payload.data.size());
  if (checksum != req.checksum) {
    rsp.result = makeError(StorageCode::kChecksumMismatch, "EC creation payload differs from its checksum");
    co_return rsp;
  }
  auto targetResult = ecTarget(req.vChainId, req.targetId, true);
  if (!targetResult) {
    rsp.result = makeError(targetResult.error());
    co_return rsp;
  }
  // Reject excess work instead of accumulating payload-owning semaphore waiters.
  // The generic RPC receive queue has its own, separate memory budget.
  if (!ecFragmentSemaphore_.try_wait()) {
    rsp.result = makeError(StorageClientCode::kResourceBusy, "EC fragment admission limit reached");
    co_return rsp;
  }
  auto admission = folly::makeGuard([this] { ecFragmentSemaphore_.signal(); });
  auto target = std::move(*targetResult);
  auto key = req.identity.chunkId();
  if (!key) {
    rsp.result = makeError(key.error());
    co_return rsp;
  }
  folly::coro::Baton baton;
  auto lock = target->storageTarget->lockChunk(baton, *key, fmt::to_string(req.tag));
  if (!lock.locked()) co_await lock.lock();

  auto validateRoute = [this, target, &authorization]() -> Result<Void> {
    RETURN_ON_ERROR(authorization());
    return validateEcTarget(target, true);
  };
  auto route = validateRoute();
  if (!route) {
    rsp.result = makeError(route.error());
    co_return rsp;
  }
  EcCreateJob job(EcLegacyV1Admission{}, req, target->storageTarget, validateRoute);
  co_await updateWorker_.enqueue(&job);
  // The disk worker borrows both job and request. Always drain it, even if the
  // RPC peer timed out; timeout is not evidence that no fragment was committed.
  co_await job.complete();
  rsp.result = std::move(job.result());
  if (rsp.result) {
    route = validateRoute();
    if (!route) {
      rsp.result = makeError(
          StorageCode::kEcSealOutcomeUnknown,
          fmt::format("fragment committed but final access validation failed: {}; retain allocation", route.error()));
    }
  }
  record.report(rsp.result.hasValue());
  co_return rsp;
}

CoTryTask<EcReadRsp> StorageOperator::readEcFragmentImpl(const EcReadReq &req, EcValidation authorization) {
  auto record = ecReadRecorder.record();
  EcReadRsp rsp;
  rsp.tag = req.tag;
  auto authorized = authorization();
  if (!authorized) {
    rsp.result = makeError(authorized.error());
    co_return rsp;
  }
  auto valid = req.validate();
  if (!valid) {
    rsp.result = makeError(valid.error());
    co_return rsp;
  }
  auto targetResult = ecTarget(req.vChainId, req.targetId, false);
  if (!targetResult) {
    rsp.result = makeError(targetResult.error());
    co_return rsp;
  }
  if (!ecFragmentSemaphore_.try_wait()) {
    rsp.result = makeError(StorageClientCode::kResourceBusy, "EC fragment admission limit reached");
    co_return rsp;
  }
  auto admission = folly::makeGuard([this] { ecFragmentSemaphore_.signal(); });
  auto target = std::move(*targetResult);
  auto validateRoute = [this, target, &authorization]() -> Result<Void> {
    RETURN_ON_ERROR(authorization());
    return validateEcTarget(target, false);
  };
  EcReadJob job(EcLegacyV1Admission{}, req, target->storageTarget, validateRoute);
  co_await updateWorker_.enqueue(&job);
  co_await job.complete();
  rsp.result = std::move(job.result());
  if (rsp.result) {
    auto route = validateRoute();
    if (!route) rsp.result = makeError(route.error());
  }
  record.report(rsp.result.hasValue());
  co_return rsp;
}

CoTryTask<EcReconcileRsp> StorageOperator::reconcileEcFragmentImpl(const EcReconcileReq &req,
                                                                   EcValidation authorization) {
  auto record = ecReconcileRecorder.record();
  EcReconcileRsp rsp;
  rsp.tag = req.tag;
  auto authorized = authorization();
  if (!authorized) {
    rsp.result = makeError(authorized.error());
    co_return rsp;
  }
  auto valid = req.validate();
  if (!valid) {
    rsp.result = makeError(valid.error());
    co_return rsp;
  }
  // Reconciliation never changes contents, and remains available in readonly
  // mode. It still requires a serving, exactly identified immutable target.
  auto targetResult = ecTarget(req.vChainId, req.targetId, false);
  if (!targetResult) {
    rsp.result = makeError(targetResult.error());
    co_return rsp;
  }
  if (!ecFragmentSemaphore_.try_wait()) {
    rsp.result = makeError(StorageClientCode::kResourceBusy, "EC fragment admission limit reached");
    co_return rsp;
  }
  auto admission = folly::makeGuard([this] { ecFragmentSemaphore_.signal(); });
  auto target = std::move(*targetResult);
  auto key = req.identity.chunkId();
  if (!key) {
    rsp.result = makeError(key.error());
    co_return rsp;
  }
  folly::coro::Baton baton;
  auto lock = target->storageTarget->lockChunk(baton, *key, fmt::to_string(req.tag));
  if (!lock.locked()) co_await lock.lock();
  auto validateRoute = [this, target, &authorization]() -> Result<Void> {
    RETURN_ON_ERROR(authorization());
    return validateEcTarget(target, false);
  };
  auto route = validateRoute();
  if (!route) {
    rsp.result = makeError(route.error());
    co_return rsp;
  }
  EcReconcileJob job(EcLegacyV1Admission{}, req, target->storageTarget, validateRoute);
  co_await updateWorker_.enqueue(&job);
  co_await job.complete();
  rsp.result = std::move(job.result());
  if (rsp.result) {
    route = validateRoute();
    if (!route) {
      rsp.result = makeError(
          StorageCode::kEcSealOutcomeUnknown,
          fmt::format("fragment reconciled but final access validation failed: {}; retain allocation", route.error()));
    }
  }
  record.report(rsp.result.hasValue());
  co_return rsp;
}

}  // namespace hf3fs::storage
