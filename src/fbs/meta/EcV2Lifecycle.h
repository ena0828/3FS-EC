#pragma once

#include "fbs/meta/EcV2.h"

namespace hf3fs::meta {
inline constexpr uint16_t kEcV2LifecycleVersion = 1;

// Physical identity is reserved before descriptors or data grants exist.
struct EcV2ReservedAllocation {
  SERDE_STRUCT_FIELD(identity, storage::EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(endpoint, EcV2PhysicalEndpoint{});
  SERDE_STRUCT_FIELD(writer, EcOwner{});
};

struct EcV2DrainObservation {
  SERDE_STRUCT_FIELD(request, storage::EcScopeControlRequest{});
  SERDE_STRUCT_FIELD(ack, storage::EcScopeControlAck{});
};
}  // namespace hf3fs::meta

template <typename T, size_t N>
requires((std::is_same_v<T, hf3fs::meta::EcV2ReservedAllocation> && N == 12) ||
         (std::is_same_v<T, std::optional<hf3fs::meta::EcV2DrainObservation>> &&
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
      if (count != N) return makeError(StatusCode::kInvalidFormat, "invalid fixed V2 lifecycle array extent");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != N) return makeError(StatusCode::kInvalidFormat, "invalid fixed V2 lifecycle array extent");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
struct EcV2Reservation {
  SERDE_STRUCT_FIELD(version, kEcV2LifecycleVersion);
  SERDE_STRUCT_FIELD(original, EcOperationRecord{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(candidates, (std::array<EcV2ReservedAllocation, 12>{}));
  SERDE_STRUCT_FIELD(operationEndpoints, EcV2OperationEndpoints{});
};

enum class EcV2DrainState : uint8_t { Closing = 1, ReadReleased = 2, Published = 3, Aborted = 4 };

struct EcV2DrainIdentity {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(kind, storage::EcGrantScope::ReadPin);
  SERDE_STRUCT_FIELD(scopeId, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(objectEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(generation, uint64_t{});
  SERDE_STRUCT_FIELD(revision, uint64_t{});
  SERDE_STRUCT_FIELD(clusterAuthority, Uuid::zero());
  SERDE_STRUCT_FIELD(revocationId, Uuid::zero());
  SERDE_STRUCT_FIELD(endpoints, EcV2OperationEndpoints{});
};

struct EcV2DrainRecord {
  SERDE_STRUCT_FIELD(version, kEcV2LifecycleVersion);
  SERDE_STRUCT_FIELD(identity, EcV2DrainIdentity{});
  SERDE_STRUCT_FIELD(state, EcV2DrainState::Closing);
  // Only durable, fully drained and authenticated observations occupy slots.
  // Store exact signed requests so ACKs remain independently verifiable after
  // coordinator restart; a bitmap alone is not evidence.
  SERDE_STRUCT_FIELD(observations, (std::array<std::optional<EcV2DrainObservation>, 24>{}));
  // Set only by startPublish's private coordinator evidence, atomically with
  // Closing. Never populated from a user-supplied serialized manifest.
  SERDE_STRUCT_FIELD(verifiedManifest, (std::optional<EcManifest>{}));
  SERDE_STRUCT_FIELD(verifiedContentSha256, storage::EcSha256{});
};
}  // namespace hf3fs::meta
