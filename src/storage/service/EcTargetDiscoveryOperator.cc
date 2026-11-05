#include <folly/experimental/coro/WithCancellation.h>

#include "storage/service/Components.h"
#include "storage/service/StorageOperator.h"

namespace hf3fs::storage {
CoTryTask<EcTargetDiscoveryRsp> StorageOperator::getEcTargetIdentity(const EcTargetDiscoveryRequest &request) {
  EcTargetDiscoveryRsp response;
  if (!ecDiscovery_) {
    response.result =
        makeError(StatusCode::kAuthenticationFail, "EC instance discovery requires explicit control authority");
    co_return response;
  }
  auto valid = ecDiscovery_->validateRequest(request);
  if (!valid) {
    response.result = makeError(valid.error());
    co_return response;
  }
  auto target = components_.targetMap.getByTargetId(request.claims.targetId);
  if (!target || !(*target)->storageTarget) {
    response.result = makeError(StorageCode::kTargetStateInvalid, "EC discovery target is not loaded");
    co_return response;
  }
  // Non-SERVING targets may still be observed. No route decides their identity
  // and no request creates a missing physical target or an incarnation.
  auto actual = (*target)->storageTarget;
  response.result = co_await folly::coro::co_withCancellation({}, ecDiscovery_->execute(request, actual));
  if (response.result) {
    auto current = components_.targetMap.getByTargetId(request.claims.targetId);
    if (!current || (*current)->storageTarget != actual)
      response.result = makeError(StorageCode::kTargetStateInvalid, "loaded EC target changed during discovery");
  }
  co_return response;
}
}  // namespace hf3fs::storage
