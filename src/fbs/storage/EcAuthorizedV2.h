#pragma once

#include "fbs/storage/EcAuthorizationV2.h"

namespace hf3fs::storage {

// Reserved candidate IDs only; this header does not register service methods.
// Existing V1 methods 22--24 and their binary layouts remain unchanged.
enum class EcDataMethodV2 : uint16_t { ReadBlock = 40, Begin = 41, Append = 42, Query = 43, Reconcile = 44, Seal = 45 };

struct EcSlicePayloadV2 {
  std::string data;
  std::string serdeToReadable() const { return fmt::format("EcSlicePayloadV2({} bytes)", data.size()); }
};

}  // namespace hf3fs::storage

template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcSlicePayloadV2> {
  static std::string_view serdeTo(const storage::EcSlicePayloadV2 &payload) { return payload.data; }
  static Result<storage::EcSlicePayloadV2> serdeFrom(std::string_view bytes) {
    // The view decoder checks extent before any owned allocation is requested.
    if (bytes.size() > storage::kEcIntegrityBlockBytes) {
      return makeError(StatusCode::kInvalidArg, "V2 EC slice exceeds 64 KiB");
    }
    return storage::EcSlicePayloadV2{std::string(bytes)};
  }
};

namespace hf3fs::storage {

struct EcFragmentAccessV2 {
  SERDE_STRUCT_FIELD(version, kEcGrantVersionV2);
  SERDE_STRUCT_FIELD(identity, EcFragmentIdentity{});
  SERDE_STRUCT_FIELD(operationId, Uuid::zero());
  SERDE_STRUCT_FIELD(vChainId, VersionedChainId{});
  SERDE_STRUCT_FIELD(targetId, TargetId{});
  SERDE_STRUCT_FIELD(integrity, EcIntegrityDescriptor{});
  SERDE_STRUCT_FIELD(tag, MessageTag{});
  SERDE_STRUCT_FIELD(userInfo, flat::UserInfo{});
};

struct EcReadBlockV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(blockIndex, uint32_t{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};
struct EcBeginStageV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};
struct EcAppendStageV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(blockIndex, uint32_t{});
  SERDE_STRUCT_FIELD(payload, EcSlicePayloadV2{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};
struct EcQueryStageV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};
struct EcReconcileStageV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};
struct EcSealStageV2Req {
  SERDE_STRUCT_FIELD(request, EcFragmentAccessV2{});
  SERDE_STRUCT_FIELD(grant, EcCapabilityV2{});
};

// Trusted local snapshot, deliberately not Serde. Obtain persistent instance
// UUIDs from the actual StorageTarget and current route from the routing map;
// never populate these from a request or from the grant being checked.
struct EcLocalTargetV2 {
  Uuid engineUuid = Uuid::zero();
  Uuid targetIncarnation = Uuid::zero();
  VersionedChainId vChainId;
  TargetId targetId{};
  NodeId nodeId{};
};

// Every overload binds the actual request fields, verified descriptor digest,
// local instance and exact method right. Read/Append address one complete
// integrity block (the final block can be short), never an arbitrary byte range.
// userInfo and transport MessageTag are diagnostics, not authority. The signed
// owner/client namespace are bearer scope fields; the issuer must authenticate
// the Meta operation. Fresh route/expiry checks are required at all three
// service boundaries: before admission, before execution, after completion.
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcReadBlockV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcBeginStageV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcAppendStageV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcQueryStageV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcReconcileStageV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);
Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &,
                                            const EcSealStageV2Req &,
                                            const EcLocalTargetV2 &,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds = kEcGrantMaxTtlSeconds);

// Stable protocol-derived staging context, not a caller-selectable wire spec.
// chainVersion is always zero only in immutable fragment metadata. The actual
// request/routing version above must still match at every service boundary.
struct EcStableStageSpecV2 {
  Uuid stageId = Uuid::zero();
  uint32_t length = 0;
  uint32_t crc32c = 0;
  uint32_t chainVersion = 0;
  uint64_t lastRequestId = 0;
  uint64_t lastClientLow = 0;
  uint64_t lastClientHigh = 0;
  std::array<uint8_t, 16> etag{};
  bool operator==(const EcStableStageSpecV2 &) const = default;
};
Result<EcStableStageSpecV2> deriveEcStageSpecV2(const VerifiedEcGrantV2 &begin);

static_assert(serde::Serializable<EcReadBlockV2Req>);
static_assert(serde::Serializable<EcBeginStageV2Req>);
static_assert(serde::Serializable<EcAppendStageV2Req>);
static_assert(serde::Serializable<EcQueryStageV2Req>);
static_assert(serde::Serializable<EcReconcileStageV2Req>);
static_assert(serde::Serializable<EcSealStageV2Req>);
}  // namespace hf3fs::storage
