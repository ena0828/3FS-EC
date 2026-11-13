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
struct EcV2DrainProgressV1 {
  SERDE_STRUCT_FIELD(state, EcV2DrainState::Closing);
  SERDE_STRUCT_FIELD(revocation, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(acknowledgedEndpoints, uint16_t{});
};
struct EcV2DrainProgressV2 {
  SERDE_STRUCT_FIELD(state, EcV2DrainState::Closing);
  SERDE_STRUCT_FIELD(revocation, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(acknowledgedEndpoints, uint16_t{});
  SERDE_STRUCT_FIELD(retiredEndpoints, uint16_t{});
};
struct EcV2DrainProgress : EcV2DrainProgressV2 {
  uint32_t terminalEndpoints() const { return uint32_t(acknowledgedEndpoints) + retiredEndpoints; }
};
}  // namespace hf3fs::meta

// Preserve old ACK-only wire/journal representation exactly, including JSON.
template <>
struct hf3fs::serde::SerdeMethod<hf3fs::meta::EcV2DrainProgress> {
  static void serialize(const hf3fs::meta::EcV2DrainProgress &value, auto &out) {
    if (value.retiredEndpoints == 0) {
      hf3fs::meta::EcV2DrainProgressV1 old;
      old.state = value.state;
      old.revocation = value.revocation;
      old.expectedEndpoints = value.expectedEndpoints;
      old.acknowledgedEndpoints = value.acknowledgedEndpoints;
      serde::serialize(old, out);
    } else {
      serde::serialize(static_cast<const hf3fs::meta::EcV2DrainProgressV2 &>(value), out);
    }
  }
  static Result<Void> deserialize(hf3fs::meta::EcV2DrainProgress &value, auto &in) {
    hf3fs::meta::EcV2DrainProgressV2 next;
    RETURN_ON_ERROR(serde::deserialize(next, in));
    static_cast<hf3fs::meta::EcV2DrainProgressV2 &>(value) = std::move(next);
    return Void{};
  }
};
