#pragma once

#include "fbs/meta/EcV2Lifecycle.h"
#include "fbs/storage/EcAuthorizationV2.h"

// Fixed response cardinality; no attacker-controlled temporary vector.
template <>
struct hf3fs::serde::SerdeMethod<std::array<std::optional<hf3fs::storage::EcCapabilityV2>, 12>> {
  using Values = std::array<std::optional<storage::EcCapabilityV2>, 12>;
  static void serialize(const Values &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(12);
  }
  static Result<Void> deserialize(Values &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 12) return makeError(StatusCode::kInvalidFormat, "V2 grants require twelve slots");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 12) return makeError(StatusCode::kInvalidFormat, "V2 grants require twelve slots");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
using EcV2Grants = std::array<std::optional<storage::EcCapabilityV2>, 12>;
struct EcV2DrainProgress {
  SERDE_STRUCT_FIELD(state, EcV2DrainState::Closing);
  SERDE_STRUCT_FIELD(revocation, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(acknowledgedEndpoints, uint16_t{});
};
}  // namespace hf3fs::meta
