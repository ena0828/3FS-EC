#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
CoTryTask<EcGcDiscoveryRsp> StorageOperator::getEcGcCapability(const EcGcDiscoveryRequest &request) {
  EcGcDiscoveryRsp response;
  if (!ecGc_) {
    response.result =
        makeError(StatusCode::kAuthenticationFail, "GC capability discovery requires initialized G authority");
    co_return response;
  }
  auto valid = ecGc_->validateDiscoveryRequest(request);
  if (!valid) {
    response.result = makeError(std::move(valid.error()));
    co_return response;
  }
  auto found = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!found || !(*found)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid);
    co_return response;
  }
  auto actual = (*found)->storageTarget;
  // The synchronous callback runs within the same GC session. No DB lookup,
  // identity creation or synthetic capability flag enters this read path.
  response.result = ecGc_->observeCapabilities(request, actual, [&]() -> Result<Void> {
    auto current = components_.targetMap.getByTargetId(request.claims.targetId);
    if (!current || (*current)->storageTarget != actual)
      return makeError(StorageCode::kTargetStateInvalid, "loaded GC target changed during capability observation");
    return Void{};
  });
  co_return response;
}
CoTryTask<EcGcAbsentDiscoveryRsp> StorageOperator::getEcGcAbsentCapability(const EcGcAbsentDiscoveryRequest &request) {
  EcGcAbsentDiscoveryRsp response;
  if (!ecGcAbsent_) {
    response.result =
        makeError(StatusCode::kAuthenticationFail, "GC capability discovery requires initialized G authority");
    co_return response;
  }
  auto valid = ecGcAbsent_->validateDiscoveryRequest(request);
  if (!valid) {
    response.result = makeError(std::move(valid.error()));
    co_return response;
  }
  auto found = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!found || !(*found)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid);
    co_return response;
  }
  auto actual = (*found)->storageTarget;
  // The synchronous callback runs within the same GC session. No DB lookup,
  // identity creation or synthetic capability flag enters this read path.
  response.result = ecGcAbsent_->observeCapabilities(request, actual, [&]() -> Result<Void> {
    auto current = components_.targetMap.getByTargetId(request.claims.targetId);
    if (!current || (*current)->storageTarget != actual)
      return makeError(StorageCode::kTargetStateInvalid, "loaded GC target changed during capability observation");
    return Void{};
  });
  co_return response;
}
}  // namespace hf3fs::storage
