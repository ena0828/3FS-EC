#pragma once

#include "fbs/meta/EcV2.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcFileTreeVersion = 1;
inline constexpr uint16_t kEcFileTreeMode = 4;
inline constexpr size_t kEcFileTreeFanout = 16;
inline constexpr size_t kEcFileTreeDepth = 16;

// This is a new-object semantic marker, independent of disk/data/GC protocols.
// It is never accepted by legacy requireV2Mode or mode-3 GC enrollment.
struct EcTreeBirth {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(creator, EcOwner{});
  SERDE_STRUCT_FIELD(createRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(allowColocated, false);
};
struct EcTreeRoot {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(root, Uuid::zero());
  SERDE_STRUCT_FIELD(visibleLength, uint64_t{});
  SERDE_STRUCT_FIELD(sequence, uint64_t{1});
  SERDE_STRUCT_FIELD(epoch, uint64_t{1});
};
enum class EcTreeSlotKind : uint8_t { Zero = 0, Data = 1 };
struct EcTreeSlot {
  SERDE_STRUCT_FIELD(kind, EcTreeSlotKind::Zero);
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
};
}  // namespace hf3fs::meta

// Reject oversized arrays before element decode/copy. Defaults never authorize
// omitted Data fields: semantic validation is mandatory after deserialization.
template <typename T, size_t N>
requires((N == 16 && (std::is_same_v<T, hf3fs::Uuid> || std::is_same_v<T, hf3fs::meta::EcTreeSlot>)) ||
         (N == 12 &&
          std::is_same_v<T, hf3fs::storage::EcFragmentIdentity>)) struct hf3fs::serde::SerdeMethod<std::array<T, N>> {
  static void serialize(const std::array<T, N> &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(N);
  }
  static Result<Void> deserialize(std::array<T, N> &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != N) return makeError(StatusCode::kInvalidFormat, "invalid EC tree fixed extent");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != N) return makeError(StatusCode::kInvalidFormat, "invalid EC tree fixed extent");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
struct EcTreeNode {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(id, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(level, uint8_t{});
  SERDE_STRUCT_FIELD(prefix, uint64_t{});
  SERDE_STRUCT_FIELD(children, (std::array<Uuid, 16>{}));
  SERDE_STRUCT_FIELD(slots, (std::optional<std::array<EcTreeSlot, 16>>{}));
};
enum class EcTreeRefState : uint8_t { Live = 1, Reclaimable = 2, Reclaimed = 3 };
struct EcTreeNodeRefs {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(node, Uuid::zero());
  // Immutable path set with the body at node creation. Ref updates never alter it.
  SERDE_STRUCT_FIELD(level, uint8_t{});
  SERDE_STRUCT_FIELD(prefix, uint64_t{});
  SERDE_STRUCT_FIELD(references, uint64_t{});
  SERDE_STRUCT_FIELD(state, EcTreeRefState::Live);
};
struct EcTreeReclaimWork {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(node, Uuid::zero());
};
// Immutable request body. The UUID array is fixed before transaction retry and
// is part of the permanent replay comparison, including a MaybeCommitted retry.
struct EcTreeEdit {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedRoot, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedSequence, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(visibleLength, uint64_t{});
  SERDE_STRUCT_FIELD(nodeIds, (std::array<Uuid, 16>{}));
  SERDE_STRUCT_FIELD(replacement, EcTreeSlot{});
};
struct EcTreeEditResult {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(intent, EcTreeEdit{});
  SERDE_STRUCT_FIELD(root, EcTreeRoot{});
};
// Compact reference accounting, not a publication proof or capability. W0
// exposes no production installer. The private test seam writes and validates
// real same-mode ECMF/ECVA/ECRF records before creating this commitment.
// Future retirement must conflict-read treeHolds==0 before releasing ECMF refs.
struct EcTreeManifestHolds {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(slot, EcTreeSlot{});
  SERDE_STRUCT_FIELD(identities, (std::array<storage::EcFragmentIdentity, 12>{}));
  SERDE_STRUCT_FIELD(manifestDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(bindingsDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(treeHolds, uint64_t{});
  SERDE_STRUCT_FIELD(retired, false);
};
// Cross-object physical identity stays in the key and body. A claimed
// allocation can never gain a hold, even if an old root/node is replayed.
struct EcTreeAllocationHolds {
  SERDE_STRUCT_FIELD(version, kEcFileTreeVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(holds, uint64_t{});
};
}  // namespace hf3fs::meta
