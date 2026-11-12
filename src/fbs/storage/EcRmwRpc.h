#pragma once

#include "fbs/storage/EcAuthorizedV2.h"
#include "storage/ec_rmw/EcRmwWire.h"

// Exactly twelve valid source credentials, present only for a Data plan. A
// Zero install omits the optional array instead of encoding twelve nil grants.
template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::storage::EcCapabilityV2, 12>> {
  using Values = std::array<storage::EcCapabilityV2, 12>;
  static void serialize(const Values &v, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = v.rbegin(); it != v.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &x : v) serde::serialize(x, out);
    }
    out.arrayEnd(12);
  }
  static Result<Void> deserialize(Values &v, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; })
      return makeError(StatusCode::kInvalidFormat);
    else {
      Varint64 n = 0;
      RETURN_ON_ERROR(serde::deserialize(n, in));
      if (n != 12) return makeError(StatusCode::kInvalidFormat);
      for (auto &x : v) RETURN_ON_ERROR(serde::deserialize(x, in));
      return Void{};
    }
  }
};
namespace hf3fs::storage {
struct EcRmwInstallReq {
  SERDE_STRUCT_FIELD(plan, EcRmwPlanWire{});
  SERDE_STRUCT_FIELD(grant, EcRmwGrant{});
  SERDE_STRUCT_FIELD(reads, (std::optional<std::array<EcCapabilityV2, 12>>{}));
  // Server derives a finite local deadline and fresh grant expiry checks.
  SERDE_STRUCT_FIELD(deadlineUnixMillis, uint64_t{});
};
struct EcRmwPutReq {
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(grant, EcRmwGrant{});
  SERDE_STRUCT_FIELD(blockIndex, uint32_t{});
  SERDE_STRUCT_FIELD(payload, EcSlicePayloadV2{});
};
enum class EcRmwActionRequest : uint8_t { Submit = 1, Query = 2 };
struct EcRmwActionReq {
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(grant, EcRmwGrant{});
  SERDE_STRUCT_FIELD(action, EcRmwActionRequest::Query);
};
struct EcRmwStatus {
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(planDigest, EcSha256{});
  // 1 Receiving, 2 Queued, 3 Running, 4 Complete. This is local volatile state,
  // never a Published/T2/physical-delete result. Missing is also inconclusive.
  SERDE_STRUCT_FIELD(state, uint8_t{});
  SERDE_STRUCT_FIELD(receivedBlocks, uint16_t{});
  SERDE_STRUCT_FIELD(executionError, uint16_t{});
};
struct EcRmwStatusRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcRmwStatus>{makeError(StorageClientCode::kNotInitialized)}));
};
static_assert(sizeof(EcRmwInstallReq) < 32u << 10);
static_assert(serde::Serializable<EcRmwInstallReq>);
static_assert(serde::Serializable<EcRmwPutReq>);
static_assert(serde::Serializable<EcRmwActionReq>);
}  // namespace hf3fs::storage
