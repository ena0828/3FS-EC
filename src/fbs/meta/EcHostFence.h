#pragma once

#include "fbs/meta/EcV2.h"

namespace hf3fs::meta {
struct EcTargetRetirementIntent;
inline constexpr size_t kEcHostFenceClaimsBytes = 248;
inline constexpr size_t kEcHostFenceCertificateBytes = 312;
using EcHostFencePublicKey = std::array<uint8_t, 32>;

// The independent provider owns the execution domain before its first launch.
// This binding is fixed by Meta before the provider may fence the domain.
struct EcHostFenceBinding {
  SERDE_STRUCT_FIELD(providerId, Uuid::zero());
  SERDE_STRUCT_FIELD(enrollmentId, Uuid::zero());
  SERDE_STRUCT_FIELD(resourceGeneration, Uuid::zero());
  SERDE_STRUCT_FIELD(bindingDigest, storage::EcSha256{});
 public:
  bool operator==(const EcHostFenceBinding &) const = default;
  bool valid() const;
};
struct EcHostFenceSummary {
  SERDE_STRUCT_FIELD(providerId, Uuid::zero());
  SERDE_STRUCT_FIELD(enrollmentId, Uuid::zero());
  SERDE_STRUCT_FIELD(resourceGeneration, Uuid::zero());
  SERDE_STRUCT_FIELD(bindingDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(denyDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(proofDigest, storage::EcSha256{});
  SERDE_STRUCT_FIELD(sequence, uint64_t(0));
 public:
  bool operator==(const EcHostFenceSummary &) const = default;
  bool valid() const;
};

// Ed25519 domain 3FSEHF01, version=1, policy=1. Big-endian integers,
// raw UUID bytes: C authority; node/chain/target; engine/incarnation;
// provider/enrollment/resourceGeneration; retirement; owner namespace/uid;
// request UUID; binding/deny digests; sequence. Claims(248) || signature(64).
// No clock expiry, caller-supplied success bool, C/G key or Storage ACK.
class EcHostFence {
 public:
  static Result<EcHostFencePublicKey> loadPublicKey(std::string_view path);
  static Result<std::array<uint8_t, kEcHostFenceClaimsBytes>> claims(
      const EcTargetRetirementIntent &, const EcHostFenceBinding &,
      const storage::EcSha256 &denyDigest, uint64_t sequence);
  static Result<EcHostFenceSummary> verify(std::string_view certificate,
      const EcTargetRetirementIntent &, const EcHostFenceBinding &, const EcHostFencePublicKey &);
};
}  // namespace hf3fs::meta
