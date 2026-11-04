#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

#include "common/utils/Result.h"

namespace hf3fs::storage {
// Budget for extra waiting behind an existing cold-scope loader. Expiration
// reduces the wait to zero; it does not add a deadline to warm admission or to
// the original synchronous loader. Data40--45 transmit no client deadline.
// Helper46 supplies its actual deadline separately. Neither expiry nor this
// budget permits dropping submitted jobs or releasing pins.
struct EcScopeLoadBudget {
  using Clock = std::chrono::steady_clock;
  uint32_t milliseconds = 250;
  Clock::time_point receivedAt = Clock::now();
  std::optional<Clock::time_point> requestDeadline;

  Result<uint32_t> remaining(Clock::time_point now, uint64_t grantExpires, uint64_t authNow) const {
    if (milliseconds > 1000) return makeError(StatusCode::kInvalidConfig, "scope load wait exceeds 1000 ms");
    if (authNow >= grantExpires) return makeError(StatusCode::kAuthenticationFail, "scope grant has expired");
    if (requestDeadline && now >= *requestDeadline) return makeError(StorageClientCode::kTimeout);
    // Explicit zero retains the original nonwaiting prepare operation.
    if (milliseconds == 0) return uint32_t{0};
    auto deadline = receivedAt + std::chrono::milliseconds(milliseconds);
    if (requestDeadline) deadline = std::min(deadline, *requestDeadline);
    if (now >= deadline) return uint32_t{0};
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    if (left <= 0) return uint32_t{0};
    // The authorization clock has second resolution; fresh validation after
    // waiting remains mandatory at the actual admission/execution boundary.
    const auto grantMillis = std::min<uint64_t>(grantExpires - authNow, 1) * 1000;
    return static_cast<uint32_t>(std::min<uint64_t>(left, grantMillis));
  }
};
}  // namespace hf3fs::storage
