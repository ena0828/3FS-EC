#include "EcAdmissionJob.h"

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
void EcAdmissionJob::execute() {
  try {
    result_ = [&]() -> Result<EcScopeTicket> {
      if (!scope_ || !target_ || !session_ || !validate_) {
        return makeError(StatusCode::kInvalidArg, "incomplete EC admission job");
      }
      RETURN_ON_ERROR(validate_());
      RETURN_ON_ERROR(target_->checkEcScopeTarget(binding_.target));
      if (waitBudget_) {
        CHECK_RESULT(millis, waitBudget_());
        RETURN_ON_ERROR(scope_->prepareWait(binding_, millis));
      } else {
        RETURN_ON_ERROR(scope_->prepare(binding_));
      }
      RETURN_ON_ERROR(validate_());
      RETURN_ON_ERROR(target_->checkEcScopeTarget(binding_.target));
      return scope_->tryAdmit(binding_);
    }();
  } catch (const std::exception &) {
    result_ = makeError(StorageCode::kChunkMetadataGetError);
  } catch (...) {
    result_ = makeError(StorageCode::kChunkMetadataGetError);
  }
  completion_.finish();
}
void EcAdmissionJob::reject(Status status) {
  result_ = makeError(std::move(status));
  completion_.finish();
}
Result<EcScopeTicket> EcAdmissionJob::takeTicket() {
  if (!completion_.observed() || consumed_) {
    return makeError(StorageClientCode::kResourceBusy, "EC admission is incomplete or already consumed");
  }
  consumed_ = true;
  session_.reset();
  if (completion_.waitFailed()) return makeError(StatusCode::kNotEnoughMemory);
  return std::move(result_);
}
}  // namespace hf3fs::storage
