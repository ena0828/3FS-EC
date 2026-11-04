#pragma once

#include <cstdint>
#include <string_view>

#include "common/serde/Serde.h"
#include "common/serde/SerdeComparisons.h"
#include "common/utils/Uuid.h"

namespace hf3fs::meta {

// A distinct variant name makes pre-EC readers reject the layout instead of
// silently interpreting its parameters as a replicated chain layout.
struct EcManifestLayoutV1 {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{1u << 20});
  SERDE_STRUCT_FIELD(dataShards, uint16_t{10});
  SERDE_STRUCT_FIELD(parityShards, uint16_t{2});
  SERDE_STRUCT_FIELD(codecId, uint16_t{1});
  SERDE_STRUCT_FIELD(matrixVersion, uint16_t{1});

 public:
  static constexpr std::string_view kTypeNameForSerde = "EcManifestLayoutV1";

  // The incarnation is a file-specific object identity, not a directory
  // inheritance policy. The inode identifier belongs to the metadata catalog.
  Result<Void> valid() const {
    if (version != 1 || incarnation.is_nil() || dataShards != 10 || parityShards != 2 || codecId != 1 ||
        matrixVersion != 1 || shardBytes == 0 || shardBytes > (1u << 20)) {
      return makeError(StatusCode::kInvalidArg, "invalid EC manifest layout");
    }
    return Void{};
  }

  bool operator==(const EcManifestLayoutV1 &other) const { return serde::equals(*this, other); }
};

}  // namespace hf3fs::meta
