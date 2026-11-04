#pragma once

#include "fbs/meta/Ec.h"
#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::meta {
// Side-table version only; existing EcCatalog v2 records and RPCs do not change.
inline constexpr uint16_t kEcBindingCatalogVersion = 1;

struct EcV2PhysicalEndpoint {
  SERDE_STRUCT_FIELD(placement, EcPlacement{});
  SERDE_STRUCT_FIELD(engineUuid, Uuid::zero());
  SERDE_STRUCT_FIELD(targetIncarnation, Uuid::zero());

 public:
  bool operator==(const EcV2PhysicalEndpoint &) const = default;
  storage::EcScopeEndpoint controlEndpoint() const {
    return {placement.node, placement.chain, placement.target, engineUuid, targetIncarnation};
  }
};

struct EcV2AllocationBinding {
  SERDE_STRUCT_FIELD(version, kEcBindingCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(fragment, EcFragment{});
  SERDE_STRUCT_FIELD(engineUuid, Uuid::zero());
  SERDE_STRUCT_FIELD(targetIncarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(writer, EcOwner{});

 public:
  bool operator==(const EcV2AllocationBinding &other) const {
    return version == other.version && object == other.object && fragment == other.fragment &&
           engineUuid == other.engineUuid && targetIncarnation == other.targetIncarnation &&
           writer.uid == other.writer.uid && writer.client == other.writer.client;
  }
  EcV2PhysicalEndpoint endpoint() const { return {fragment.placement, engineUuid, targetIncarnation}; }
};

struct EcV2ReadEndpoint {
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(endpoint, EcV2PhysicalEndpoint{});

 public:
  bool operator==(const EcV2ReadEndpoint &other) const {
    return serde::equals(identity, other.identity) && operation == other.operation && endpoint == other.endpoint;
  }
};
}  // namespace hf3fs::meta

template <typename T, size_t N>
requires((std::is_same_v<T, hf3fs::meta::EcV2AllocationBinding> && N == 12) ||
         (std::is_same_v<T, hf3fs::meta::EcV2ReadEndpoint> && N == 12) ||
         (std::is_same_v<T, hf3fs::meta::EcV2PhysicalEndpoint> &&
          N == 24)) struct hf3fs::serde::SerdeMethod<std::array<T, N>> {
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
      if (count != N) return makeError(StatusCode::kInvalidFormat, "invalid fixed V2 binding array extent");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != N) return makeError(StatusCode::kInvalidFormat, "invalid fixed V2 binding array extent");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
using EcV2AllocationBindings = std::array<EcV2AllocationBinding, 12>;

struct EcV2ObjectMode {
  SERDE_STRUCT_FIELD(version, kEcBindingCatalogVersion);
  SERDE_STRUCT_FIELD(mode, uint16_t{2});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(creator, EcOwner{});
  SERDE_STRUCT_FIELD(createRequest, Uuid::zero());
};

struct EcV2OperationEndpoints {
  SERDE_STRUCT_FIELD(count, uint16_t{});
  SERDE_STRUCT_FIELD(endpoints, (std::array<EcV2PhysicalEndpoint, 24>{}));
  SERDE_STRUCT_FIELD(digest, storage::EcSha256{});
};

struct EcV2OperationBinding {
  SERDE_STRUCT_FIELD(version, kEcBindingCatalogVersion);
  SERDE_STRUCT_FIELD(intent, EcMutationIntent{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(allocations, EcV2AllocationBindings{});
  // Repair includes its entire base and candidate instances, not just the
  // twelve final shards. Ordinary whole-stripe Write currently reads no base.
  SERDE_STRUCT_FIELD(operationEndpoints, EcV2OperationEndpoints{});
};

struct EcV2PinSnapshot {
  SERDE_STRUCT_FIELD(version, kEcBindingCatalogVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(pin, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  // One mapping per allocation; do not replace these with current routing.
  SERDE_STRUCT_FIELD(endpoints, (std::array<EcV2ReadEndpoint, 12>{}));
  SERDE_STRUCT_FIELD(endpointSetDigest, storage::EcSha256{});
};

struct EcV2PinnedRead {
  EcManifest manifest;
  EcV2PinSnapshot snapshot;
};
}  // namespace hf3fs::meta
