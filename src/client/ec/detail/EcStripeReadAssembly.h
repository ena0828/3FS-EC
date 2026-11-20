#pragma once

#include <optional>

#include "client/ec/EcStripeRead.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::client::ec::detail {

EcStripeReadOptions foregroundEcReadOptions(const std::array<std::optional<Status>, 12> &routeFailures,
                                            std::chrono::steady_clock::time_point deadline,
                                            bool quorumFirst = true);

enum class EcReadBlockAssembly { Systematic, Recovered };

// Sources already passed pinned receipt and block integrity checks. Offset and
// length refer to the same block in each shard. The caller verifies the final
// logical SHA before publishing any assembled bytes.
Result<EcReadBlockAssembly> assembleEcReadBlock(std::array<storage::EcCodecShardView, 10> sources,
                                                uint32_t shardBytes,
                                                uint32_t offset,
                                                uint32_t length,
                                                std::span<char> logical);

}  // namespace hf3fs::client::ec::detail
