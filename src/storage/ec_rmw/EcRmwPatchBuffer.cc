#include "EcRmwPatchBuffer.h"

#include <cstring>

namespace hf3fs::storage {
Result<std::unique_ptr<EcRmwPatchBuffer>> EcRmwPatchBuffer::create(std::shared_ptr<const EcRmwPlan> plan) {
  if (!plan) return makeError(StatusCode::kInvalidArg);
  auto out = std::unique_ptr<EcRmwPatchBuffer>(new EcRmwPatchBuffer(std::move(plan)));
  out->bytes_.resize(out->plan_->input().patchLength, '\0');
  return out;
}
Result<Void> EcRmwPatchBuffer::put(uint32_t block, std::string_view bytes) {
  if (consumed_) return makeError(StatusCode::kTokenStale, "RMW patch was already consumed");
  CHECK_RESULT(length, plan_->patchBlockLength(block));
  if (bytes.size() != length) return makeError(StatusCode::kInvalidArg, "RMW patch block length differs");
  const size_t offset = size_t(block) * kEcRmwPatchBlockBytes;
  if (received_[block]) {
    if (std::string_view(bytes_).substr(offset, length) != bytes)
      return makeError(StatusCode::kTokenMismatch, "RMW retry changed patch bytes");
    return Void{};
  }
  std::memcpy(bytes_.data() + offset, bytes.data(), length);
  received_.set(block);
  return Void{};
}
Result<std::string> EcRmwPatchBuffer::finish() {
  if (consumed_) return makeError(StatusCode::kTokenStale, "RMW patch was already consumed");
  if (received_.count() != plan_->patchBlocks())
    return makeError(StorageClientCode::kResourceBusy, "RMW patch is incomplete");
  CHECK_RESULT(hash, ec_rmw_detail::sha256(bytes_));
  if (hash != plan_->input().patchSha256)
    return makeError(StatusCode::kDataCorruption, "RMW complete patch SHA differs");
  consumed_ = true;
  return std::move(bytes_);
}
}  // namespace hf3fs::storage
