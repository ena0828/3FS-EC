#pragma once

#include "fbs/meta/Ec.h"

namespace hf3fs::meta {

// Version 1 uses a fixed domain, big-endian fixed-width integers and raw UUID
// bytes. Generation and allocation are outputs of Begin and are not inputs.
Result<storage::EcSha256> computeEcRequestDigest(const EcMutationIntent &intent,
                                                 uint32_t shardBytes,
                                                 const storage::EcSha256 &logicalContentSha256);
Result<storage::EcSha256> computeEcLogicalSha256(const std::array<std::string_view, 10> &data, uint64_t logicalLength);

}  // namespace hf3fs::meta
