#pragma once

#include "fbs/meta/EcFileMutation.h"
#include "fbs/meta/EcFileRange.h"

namespace hf3fs::meta {
enum class EcTreeReadState : uint8_t { Active = 1, Closing = 2, Released = 3 };

struct EcTreeReadIntent {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(range, Uuid::zero());
  SERDE_STRUCT_FIELD(selection, EcRangeSelection{});
};

struct EcTreeReadStripe {
  SERDE_STRUCT_FIELD(slot, EcTreeSlot{});
  // Zero slots have no storage scope or fabricated physical endpoints.
  SERDE_STRUCT_FIELD(snapshot, (std::optional<EcV2PinSnapshot>{}));
};
}  // namespace hf3fs::meta

template <typename T>
requires(std::is_same_v<T, hf3fs::meta::EcTreeReadStripe> ||
         std::is_same_v<T, hf3fs::Uuid>) struct hf3fs::serde::SerdeMethod<std::array<T, 8>> {
  using Array = std::array<T, 8>;
  static void serialize(const Array &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(values.size());
  }
  static Result<Void> deserialize(Array &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 8) return makeError(StatusCode::kInvalidFormat, "tree read requires eight fixed slots");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 8) return makeError(StatusCode::kInvalidFormat, "tree read requires eight fixed slots");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
struct EcTreeReadRecord {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(intent, EcTreeReadIntent{});
  SERDE_STRUCT_FIELD(root, EcTreeRoot{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(readableLength, uint64_t{});
  SERDE_STRUCT_FIELD(stripeCount, uint16_t{});
  SERDE_STRUCT_FIELD(stripes, (std::array<EcTreeReadStripe, 8>{}));
  SERDE_STRUCT_FIELD(state, EcTreeReadState::Active);
  SERDE_STRUCT_FIELD(closeAuthority, Uuid::zero());
  SERDE_STRUCT_FIELD(revocations, (std::array<Uuid, 8>{}));
};
}  // namespace hf3fs::meta
