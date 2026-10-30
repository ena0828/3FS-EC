#pragma once

#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <memory>

#include "fbs/storage/Ec.h"

namespace hf3fs::storage {

class StorageTarget;

// The caller must keep the request and job alive until complete(), including
// during cancellation. Disk completion cannot safely abandon a borrowed job.
template <typename Request, typename Response>
class EcJob {
 public:
  EcJob(const Request &request, std::shared_ptr<StorageTarget> target, std::function<Result<Void>()> validateRoute)
      : request_(request),
        target_(std::move(target)),
        validateRoute_(std::move(validateRoute)) {}

  const auto &request() const { return request_; }
  const auto &target() const { return target_; }
  auto &result() { return result_; }
  Result<Void> validateRoute() const {
    if (!validateRoute_) return makeError(StatusCode::kInvalidArg, "EC job requires routing validation");
    return validateRoute_();
  }
  CoTask<void> complete() const { co_await baton_; }
  void setResult(Result<Response> result) {
    result_ = std::move(result);
    baton_.post();
  }

 private:
  const Request &request_;
  std::shared_ptr<StorageTarget> target_;
  std::function<Result<Void>()> validateRoute_;
  Result<Response> result_{makeError(StorageClientCode::kNotInitialized)};
  folly::coro::Baton baton_;
};

using EcCreateJob = EcJob<EcCreateReq, EcFragmentReceipt>;
using EcReadJob = EcJob<EcReadReq, EcReadResult>;
using EcReconcileJob = EcJob<EcReconcileReq, EcFragmentReceipt>;

}  // namespace hf3fs::storage
