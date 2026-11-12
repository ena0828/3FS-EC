#include "EcFilePlanning.h"

#include <algorithm>
#include <limits>

namespace hf3fs::client::ec {
Result<EcFileExtentPlan> planEcFileRead(uint32_t shardBytes, uint64_t offset, uint64_t length) {
  if (!shardBytes || shardBytes > (1u << 20) || length > kEcFileMaxPayloadBytes ||
      offset > std::numeric_limits<uint64_t>::max() - length)
    return makeError(StatusCode::kInvalidArg, "invalid bounded file extent or uint64 overflow");
  EcFileExtentPlan plan;
  plan.offset = offset;
  plan.length = length;
  plan.shardBytes = shardBytes;
  plan.stripeBytes = shardBytes * 10;
  if (!length) return plan;
  const uint64_t first = offset / plan.stripeBytes;
  const uint64_t count = (offset + length - 1) / plan.stripeBytes - first + 1;
  if (count > kEcFileMaxStripes)
    return makeError(StatusCode::kInvalidArg, "file extent exceeds eight stripes including alignment");
  plan.count = static_cast<uint16_t>(count);
  uint64_t cursor = offset, remaining = length;
  for (size_t i = 0; i != plan.count; ++i) {
    auto &slice = plan.slices[i];
    slice.stripe = cursor / plan.stripeBytes;
    slice.fileOffset = cursor;
    slice.offsetInStripe = static_cast<uint32_t>(cursor % plan.stripeBytes);
    slice.length = static_cast<uint32_t>(std::min<uint64_t>(remaining, plan.stripeBytes - slice.offsetInStripe));
    cursor += slice.length;
    remaining -= slice.length;
  }
  return plan;
}
Result<EcFileExtentPlan> clipEcFileRead(const EcFileExtentPlan &original, uint64_t capturedEOF) {
  CHECK_RESULT(rebuilt, planEcFileRead(original.shardBytes, original.offset, original.length));
  if (rebuilt != original) return makeError(StatusCode::kInvalidArg, "malformed original file extent");
  const uint64_t readable =
      original.offset >= capturedEOF ? 0 : std::min(original.length, capturedEOF - original.offset);
  return planEcFileRead(original.shardBytes, original.offset, readable);
}
Result<EcFileExtentPlan> planEcFileAppend(uint32_t shardBytes, uint64_t expectedEOF, uint64_t length) {
  CHECK_RESULT(plan, planEcFileRead(shardBytes, expectedEOF, length));
  if (!length || expectedEOF % plan.stripeBytes || length % plan.stripeBytes)
    return makeError(StatusCode::kInvalidArg, "append requires nonempty complete stripes at aligned expected EOF");
  return plan;
}
}  // namespace hf3fs::client::ec
