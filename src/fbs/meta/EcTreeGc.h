#pragma once
#include "fbs/meta/EcFileTree.h"
namespace hf3fs::meta {
struct EcTreeReclaimIdentities {
  SERDE_STRUCT_FIELD(fragments, (std::array<storage::EcFragmentIdentity, 12>{}));
};
}  // namespace hf3fs::meta
// No allocation from a wire count: one exact leaf fanout before any element decode.
template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::meta::EcTreeReclaimIdentities, 16>> {
  using Values = std::array<hf3fs::meta::EcTreeReclaimIdentities, 16>;
  static void serialize(const Values &v, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = v.rbegin(); it != v.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &item : v) serde::serialize(item, out);
    }
    out.arrayEnd(16);
  }
  static Result<Void> deserialize(Values &v, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 16) return makeError(StatusCode::kInvalidFormat, "invalid reclaim identity fanout");
      for (auto &item : v) RETURN_ON_ERROR(serde::deserialize(item, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 16) return makeError(StatusCode::kInvalidFormat, "invalid reclaim identity fanout");
      auto it = std::move(container.second);
      for (auto &item : v) RETURN_ON_ERROR(serde::deserialize(item, in.fetchAndNext(it)));
    }
    return Void{};
  }
};
namespace hf3fs::meta {
// Internal tree metadata reclaim is independent of Storage deletion. All IDs
// remain permanent as ECNR tombstones; reclaim removes only a terminal ECNT
// body. Manifest history and the original RPC60 result remain permanent.
struct EcTreeReclaimProgress {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(node, Uuid::zero());
  SERDE_STRUCT_FIELD(reclaimed, false);
  SERDE_STRUCT_FIELD(refs, (std::optional<EcTreeNodeRefs>{}));
  SERDE_STRUCT_FIELD(next, Uuid::zero());
  // At most one leaf's 16 historical revisions; each still needs explicit
  // RPC40 retirement, then exact RPC38 claim/Collect. These are not proofs.
  SERDE_STRUCT_FIELD(revisions, (std::array<EcTreeSlot, 16>{}));
  // Public identifiers only, not grants or proof. Fixed to each revision above
  // so an administrator can invoke exact 38/39 without reading user contents.
  SERDE_STRUCT_FIELD(identities, (std::array<EcTreeReclaimIdentities, 16>{}));
};
}  // namespace hf3fs::meta
