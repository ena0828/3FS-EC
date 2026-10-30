#include <folly/ScopeGuard.h>

#include "common/monitor/Recorder.h"
#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
namespace {
monitor::OperationRecorder ecCreateRecorder{"storage.ec_create_fragment"};
monitor::OperationRecorder ecReadRecorder{"storage.ec_read_fragment"};
monitor::OperationRecorder ecReconcileRecorder{"storage.ec_reconcile_fragment"};
}  // namespace

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

CoTryTask<EcCreateRsp> StorageOperator::createEcFragment(const EcCreateReq &req) {
  auto record = ecCreateRecorder.record();
  EcCreateRsp rsp;
  rsp.tag = req.tag;
  auto valid = req.validate();
  if (!valid) {
    rsp.result = makeError(valid.error());
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

  auto validateRoute = [this, target] { return validateEcTarget(target, true); };
  auto route = validateRoute();
  if (!route) {
    rsp.result = makeError(route.error());
    co_return rsp;
  }
  EcCreateJob job(req, target->storageTarget, validateRoute);
  co_await updateWorker_.enqueue(&job);
  // The disk worker borrows both job and request. Always drain it, even if the
  // RPC peer timed out; timeout is not evidence that no fragment was committed.
  co_await job.complete();
  rsp.result = std::move(job.result());
  if (rsp.result) {
    route = validateRoute();
    if (!route) {
      rsp.result =
          makeError(StorageCode::kEcSealOutcomeUnknown,
                    fmt::format("fragment committed but routing changed: {}; retain allocation", route.error()));
    }
  }
  record.report(rsp.result.hasValue());
  co_return rsp;
}

CoTryTask<EcReadRsp> StorageOperator::readEcFragment(const EcReadReq &req) {
  auto record = ecReadRecorder.record();
  EcReadRsp rsp;
  rsp.tag = req.tag;
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
  auto validateRoute = [this, target] { return validateEcTarget(target, false); };
  EcReadJob job(req, target->storageTarget, validateRoute);
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

CoTryTask<EcReconcileRsp> StorageOperator::reconcileEcFragment(const EcReconcileReq &req) {
  auto record = ecReconcileRecorder.record();
  EcReconcileRsp rsp;
  rsp.tag = req.tag;
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
  auto validateRoute = [this, target] { return validateEcTarget(target, false); };
  auto route = validateRoute();
  if (!route) {
    rsp.result = makeError(route.error());
    co_return rsp;
  }
  EcReconcileJob job(req, target->storageTarget, validateRoute);
  co_await updateWorker_.enqueue(&job);
  co_await job.complete();
  rsp.result = std::move(job.result());
  if (rsp.result) {
    route = validateRoute();
    if (!route) {
      rsp.result =
          makeError(StorageCode::kEcSealOutcomeUnknown,
                    fmt::format("fragment reconciled but routing changed: {}; retain allocation", route.error()));
    }
  }
  record.report(rsp.result.hasValue());
  co_return rsp;
}

}  // namespace hf3fs::storage
