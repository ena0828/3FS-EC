#pragma once

#include <optional>

#include "fbs/storage/EcHelper.h"
#include "fbs/storage/EcStageResultV2.h"

namespace hf3fs::storage {

inline constexpr uint16_t kEcHelperDirectVersion = 1;
inline constexpr size_t kEcHelperDirectResultMaxBytes = 8192;
namespace ec_helper_direct_detail {
struct Access;
}

// Separate authority to participate in a fixed direct-delivery plan. This is
// still bearer authority inside the existing trusted Storage/Meta key domain;
// it does not authenticate the TCP peer as the last helper.
struct EcHelperDirectClaims {
  uint16_t version = kEcHelperDirectVersion;
  EcSha256 planDigest{};
  EcSha256 delegationDigest{};
  EcScopeEndpoint lastHelper{};
  uint8_t targetCount = 0;
  uint8_t maxBlocksInFlight = 0;
  uint16_t blockMask = 0;
  Uuid grantId = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};
struct EcHelperDirectGrant {
  EcHelperDirectClaims claims;

 private:
  friend struct ec_helper_direct_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcHelperDirectGrant>;
  EcSha256 signature_{};
};
struct EcHelperDirectDelegation {
  std::array<EcCapabilityV2, 2> appendGrants{};
  std::array<EcCapabilityV2, 2> queryGrants{};
  EcHelperDirectGrant directGrant{};
};
struct EcHelperDirectStamp {
  uint16_t version = kEcHelperDirectVersion;
  EcSha256 contextDigest{};
  EcSha256 valueDigest{};
  uint8_t senderPosition = 0;
  uint8_t recipientPosition = 0;
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;

 private:
  friend struct ec_helper_direct_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcHelperDirectStamp>;
  EcSha256 signature_{};
};
struct EcHelperDirectHopReq {
  uint16_t version = kEcHelperDirectVersion;
  EcRepairPlanInput plan{};
  std::array<EcHelperCapability, 10> helpers{};
  std::array<EcCapabilityV2, 10> reads{};
  std::array<ChainVer, 10> sourceRouteVersions{};
  std::array<ChainVer, 2> targetRouteVersions{};
  EcHelperDirectDelegation delegation{};
  uint8_t activeTargetMask = 0;
  EcHelperPacket packet{};
  EcHelperDirectStamp predecessor{};
  uint64_t deadlineUnixMillis = 0;
};
// No block payload is returned. These stage observations are not Seal, drain,
// publication or physical-reclamation certificates.
struct EcHelperDirectHopResult {
  uint16_t version = kEcHelperDirectVersion;
  EcSha256 planDigest{};
  EcSha256 contextDigest{};
  uint32_t blockIndex = 0;
  uint8_t targetCount = 0;
  uint8_t activeTargetMask = 0;
  uint8_t appendedTargetMask = 0;
  std::array<EcStageStateV2, 2> states{};
  EcHelperDirectStamp finalStamp{};
};
struct EcHelperDirectHopRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcHelperDirectHopResult>{makeError(StorageClientCode::kNotInitialized)}));
};

}  // namespace hf3fs::storage

#define EC_HELPER_DIRECT_FIELDS(Type, ...)                                                                      \
  template <>                                                                                                 \
  struct hf3fs::serde::SerdeMethod<Type> {                                                                      \
    static auto fields(auto &value) { return std::tie(__VA_ARGS__); }                                            \
    static void serialize(const Type &value, auto &out) {                                                       \
      if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {                        \
        auto tuple = fields(value);                                                                           \
        storage::ec_helper_detail::writeTuple(                                                                 \
            tuple, out, std::make_index_sequence<std::tuple_size_v<decltype(tuple)>>{});                        \
      } else                                                                                                  \
        serde::serialize(std::string_view("EC helper direct wire (redacted)"), out);                            \
    }                                                                                                         \
    static Result<Void> deserialize(Type &value, auto &in) {                                                    \
      if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {                          \
        auto tuple = fields(value);                                                                           \
        Varint64 count = 0;                                                                                    \
        RETURN_ON_ERROR(serde::deserialize(count, in));                                                         \
        if (count != std::tuple_size_v<decltype(tuple)>)                                                        \
          return makeError(StatusCode::kInvalidFormat, "direct record has a wrong fixed extent");               \
        return storage::ec_helper_detail::readTuple(tuple, in);                                                \
      } else                                                                                                  \
        return makeError(StatusCode::kInvalidFormat, "direct wire requires binary Serde");                     \
    }                                                                                                         \
  };

EC_HELPER_DIRECT_FIELDS(hf3fs::storage::EcHelperDirectClaims,
                        value.version,
                        value.planDigest,
                        value.delegationDigest,
                        value.lastHelper,
                        value.targetCount,
                        value.maxBlocksInFlight,
                        value.blockMask,
                        value.grantId,
                        value.issuedAtSeconds,
                        value.expiresAtSeconds)
EC_HELPER_DIRECT_FIELDS(hf3fs::storage::EcHelperDirectGrant, value.claims, value.signature_)
EC_HELPER_DIRECT_FIELDS(hf3fs::storage::EcHelperDirectStamp,
                        value.version,
                        value.contextDigest,
                        value.valueDigest,
                        value.senderPosition,
                        value.recipientPosition,
                        value.issuedAtSeconds,
                        value.expiresAtSeconds,
                        value.signature_)

// A default V2 capability deliberately cannot decode as an authorized token.
// Only this new container encodes an unused slot as an explicit absent value;
// the underlying V2 capability and every old array representation are unchanged.
template <>
struct hf3fs::serde::SerdeMethod<hf3fs::storage::EcHelperDirectDelegation> {
  using Type = storage::EcHelperDirectDelegation;
  static void writeSlots(const std::array<storage::EcCapabilityV2, 2> &slots, auto &out) {
    out.arrayBegin();
    for (auto it = slots.rbegin(); it != slots.rend(); ++it) {
      std::optional<storage::EcCapabilityV2> slot;
      if (serde::serialize(*it) != serde::serialize(storage::EcCapabilityV2{})) slot = *it;
      serde::serialize(slot, out);
    }
    out.arrayEnd(2);
  }
  static Result<Void> readSlots(std::array<storage::EcCapabilityV2, 2> &slots, auto &in) {
    Varint64 count = 0;
    RETURN_ON_ERROR(serde::deserialize(count, in));
    if (count != 2) return makeError(StatusCode::kInvalidFormat, "direct grants require two fixed slots");
    for (auto &value : slots) {
      std::optional<storage::EcCapabilityV2> slot;
      RETURN_ON_ERROR(serde::deserialize(slot, in));
      value = slot ? std::move(*slot) : storage::EcCapabilityV2{};
    }
    return Void{};
  }
  static void serialize(const Type &value, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      out.arrayBegin();
      serde::serialize(value.directGrant, out);
      writeSlots(value.queryGrants, out);
      writeSlots(value.appendGrants, out);
      out.arrayEnd(3);
    } else {
      serde::serialize(std::string_view("EC helper direct delegation (redacted)"), out);
    }
  }
  static Result<Void> deserialize(Type &value, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 3) return makeError(StatusCode::kInvalidFormat, "direct delegation has a wrong fixed extent");
      RETURN_ON_ERROR(readSlots(value.appendGrants, in));
      RETURN_ON_ERROR(readSlots(value.queryGrants, in));
      return serde::deserialize(value.directGrant, in);
    } else {
      return makeError(StatusCode::kInvalidFormat, "direct delegation requires binary Serde");
    }
  }
};

template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::storage::ChainVer, 2>>
    : hf3fs::storage::ec_helper_detail::FixedArraySerde<hf3fs::storage::ChainVer, 2> {};
template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::storage::EcStageStateV2, 2>>
    : hf3fs::storage::ec_helper_detail::FixedArraySerde<hf3fs::storage::EcStageStateV2, 2> {};

EC_HELPER_DIRECT_FIELDS(hf3fs::storage::EcHelperDirectHopReq,
                        value.version,
                        value.plan,
                        value.helpers,
                        value.reads,
                        value.sourceRouteVersions,
                        value.targetRouteVersions,
                        value.delegation,
                        value.activeTargetMask,
                        value.packet,
                        value.predecessor,
                        value.deadlineUnixMillis)
EC_HELPER_DIRECT_FIELDS(hf3fs::storage::EcHelperDirectHopResult,
                        value.version,
                        value.planDigest,
                        value.contextDigest,
                        value.blockIndex,
                        value.targetCount,
                        value.activeTargetMask,
                        value.appendedTargetMask,
                        value.states,
                        value.finalStamp)
#undef EC_HELPER_DIRECT_FIELDS

static_assert(hf3fs::serde::Serializable<hf3fs::storage::EcHelperDirectHopReq>);
static_assert(hf3fs::serde::Serializable<hf3fs::storage::EcHelperDirectHopRsp>);
static_assert(sizeof(hf3fs::storage::EcHelperDirectHopReq) <= 64u << 10);
