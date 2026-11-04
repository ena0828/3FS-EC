#pragma once

#include "fbs/meta/Common.h"
#include "fbs/storage/EcIntegrity.h"

namespace hf3fs::meta {

inline constexpr uint16_t kEcCatalogVersion = 1;
inline constexpr uint16_t kEcAllShards = (1u << 12) - 1;

struct EcObjectRef {
  SERDE_STRUCT_FIELD(inode, InodeId{});
  SERDE_STRUCT_FIELD(incarnation, Uuid::zero());
};

struct EcPlacement {
  SERDE_STRUCT_FIELD(chain, storage::ChainId{});
  SERDE_STRUCT_FIELD(target, storage::TargetId{});
  SERDE_STRUCT_FIELD(node, flat::NodeId{});
};

struct EcFragment {
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(placement, EcPlacement{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(integrity, storage::EcIntegrityDescriptor{});
};

}  // namespace hf3fs::meta

// Only the two fixed twelve-shard catalog collections use this specialization.
// Reject wire counts before constructing or decoding any element.
template <typename T>
requires(std::is_same_v<T, hf3fs::meta::EcPlacement> ||
         std::is_same_v<T, hf3fs::meta::EcFragment>) struct hf3fs::serde::SerdeMethod<std::array<T, 12>> {
  static void serialize(const std::array<T, 12> &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(values.size());
  }
  static Result<Void> deserialize(std::array<T, 12> &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 12) return makeError(StatusCode::kInvalidFormat, "EC catalog requires twelve shards");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 12) return makeError(StatusCode::kInvalidFormat, "EC catalog requires twelve shards");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {

struct EcManifest {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(fragments, (std::array<EcFragment, 12>{}));
};

enum class EcMutationKind : uint8_t { Write = 1, Repair = 2 };
enum class EcOperationState : uint8_t { Preparing = 1, Published = 2, Aborted = 3 };

struct EcMutationIntent {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  // The trusted coordinator must compute this nonzero SHA-256 before Begin
  // from a versioned, canonical encoding of the logical request content and
  // range. It must not depend on generation or allocation assigned by Begin.
  // This binds retries to their request; it is not a storage seal proof.
  SERDE_STRUCT_FIELD(requestDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(expectedRevision, uint64_t{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(kind, EcMutationKind::Write);
  SERDE_STRUCT_FIELD(replacementMask, kEcAllShards);
  SERDE_STRUCT_FIELD(placements, (std::array<EcPlacement, 12>{}));
};

struct EcObjectRecord {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(allowColocated, false);
  SERDE_STRUCT_FIELD(epoch, uint64_t{1});
  SERDE_STRUCT_FIELD(nextGeneration, uint64_t{1});
  SERDE_STRUCT_FIELD(nextRevision, uint64_t{1});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(deleting, false);
};

struct EcHead {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
};

struct EcManifestRecord {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(manifest, EcManifest{});
  SERDE_STRUCT_FIELD(pins, uint64_t{});
  SERDE_STRUCT_FIELD(retired, false);
  SERDE_STRUCT_FIELD(referencesReleased, false);
};

struct EcOperationRecord {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(intent, EcMutationIntent{});
  SERDE_STRUCT_FIELD(state, EcOperationState::Preparing);
  SERDE_STRUCT_FIELD(candidate, EcManifest{});
};

struct EcPinRecord {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(id, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(released, false);
};

struct EcFragmentRefRecord {
  SERDE_STRUCT_FIELD(version, kEcCatalogVersion);
  SERDE_STRUCT_FIELD(fragment, EcFragment{});
  SERDE_STRUCT_FIELD(owner, Uuid::zero());
  SERDE_STRUCT_FIELD(references, uint64_t{});
  // Eligibility for future fenced GC, never physical deletion permission.
  SERDE_STRUCT_FIELD(gcCandidate, false);
};

}  // namespace hf3fs::meta
