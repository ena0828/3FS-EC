#pragma once

#include <array>
#include <cstdint>

#include "common/utils/Result.h"

namespace hf3fs::client::ec {
// Client-local bounds; the Meta range adapter will check them against the
// frozen F1/F2 protocol constants. These types are not RPC/Serde structures.
inline constexpr size_t kEcFileMaxStripes = 8;
inline constexpr uint64_t kEcFileMaxPayloadBytes = 32ull << 20;

struct EcFileSlice {
  uint64_t stripe = 0;
  uint64_t fileOffset = 0;
  uint32_t offsetInStripe = 0;
  uint32_t length = 0;
  bool operator==(const EcFileSlice &) const = default;
};
struct EcFileExtentPlan {
  uint64_t offset = 0;
  uint64_t length = 0;
  uint32_t shardBytes = 0;
  uint32_t stripeBytes = 0;
  uint16_t count = 0;
  std::array<EcFileSlice, kEcFileMaxStripes> slices{};
  bool operator==(const EcFileExtentPlan &) const = default;
};

// Read identity covers the original requested extent before EOF clipping.
Result<EcFileExtentPlan> planEcFileRead(uint32_t shardBytes, uint64_t offset, uint64_t length);
// A clipped plan selects data slices only; it cannot replace the original
// persisted pin selection in Acquire or Query.
Result<EcFileExtentPlan> clipEcFileRead(const EcFileExtentPlan &, uint64_t capturedEOF);
// Complete stripes at an explicitly supplied EOF only. No automatic EOF
// selection, partial tail extension or whole-batch atomicity is implied.
Result<EcFileExtentPlan> planEcFileAppend(uint32_t shardBytes, uint64_t expectedEOF, uint64_t length);
}  // namespace hf3fs::client::ec
