#pragma once

#include <tuple>

#include "fbs/storage/EcAuthorizedV2.h"
#include "fbs/storage/EcRepairSpec.h"

namespace hf3fs::storage {

// Independent helper authority. These are not EcGrantRightV2 bits.
enum class EcHelperRight : uint16_t { Compute = 1, Forward = 2 };
inline constexpr uint16_t kEcHelperVersion = 1;
inline constexpr uint16_t kEcHelperAllRights = 3;
inline constexpr uint64_t kEcHelperMaxTtlSeconds = 300;

struct EcHelperClaims {
  uint16_t version = kEcHelperVersion;
  uint16_t rights = 0;
  EcSha256 planDigest{};
  EcScopeEndpoint recipient;
  uint8_t helperPosition = 0;
  uint16_t blockMask = 0;
  Uuid grantId = Uuid::zero();
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;
};

// Signatures remain opaque to callers; no readable bearer representation.
namespace ec_helper_detail {
struct Access;
}
struct EcHelperCapability {
  EcHelperClaims claims;

 private:
  friend struct ec_helper_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcHelperCapability>;
  EcSha256 signature_{};
};

struct EcHelperPacket {
  EcSha256 planDigest{};
  uint32_t blockIndex = 0;
  uint16_t contributorMask = 0;
  uint8_t nextHelper = 0;
  uint8_t targetCount = 0;
  std::array<EcSlicePayloadV2, 2> outputs;
};

// A predecessor stamp proves only a key-holding Storage produced this packet.
// It is neither a seal receipt nor a durable drain/publication certificate.
struct EcHelperStamp {
  uint16_t version = kEcHelperVersion;
  EcSha256 packetDigest{};
  uint8_t senderPosition = 0;
  uint8_t recipientPosition = 0;  // 255 denotes the final return path.
  uint64_t issuedAtSeconds = 0;
  uint64_t expiresAtSeconds = 0;

 private:
  friend struct ec_helper_detail::Access;
  friend struct ::hf3fs::serde::SerdeMethod<EcHelperStamp>;
  EcSha256 signature_{};
};

struct EcHelperHopReq {
  EcRepairPlanInput plan;
  std::array<EcHelperCapability, 10> helpers;
  std::array<EcCapabilityV2, 10> reads;
  std::array<ChainVer, 10> routeVersions;
  EcHelperPacket packet;
  // First hop requires the all-zero empty stamp; subsequent hops require MAC.
  EcHelperStamp predecessor;
  uint64_t deadlineUnixMillis = 0;
};
struct EcHelperHopResult {
  EcHelperPacket packet;
  EcHelperStamp finalStamp;
};
struct EcHelperHopRsp {
  SERDE_STRUCT_FIELD(result, (Result<EcHelperHopResult>{makeError(StorageClientCode::kNotInitialized)}));
};

}  // namespace hf3fs::storage

namespace hf3fs::storage::ec_helper_detail {
template <size_t I = 0, typename Tuple, typename In>
Result<Void> readTuple(Tuple &tuple, In &in) {
  if constexpr (I != std::tuple_size_v<Tuple>) {
    RETURN_ON_ERROR(serde::deserialize(std::get<I>(tuple), in));
    return readTuple<I + 1>(tuple, in);
  }
  return Void{};
}
template <typename Tuple, typename Out, size_t... I>
void writeTuple(Tuple tuple, Out &out, std::index_sequence<I...>) {
  out.arrayBegin();
  (serde::serialize(std::get<sizeof...(I) - 1 - I>(tuple), out), ...);
  out.arrayEnd(sizeof...(I));
}
template <typename T, size_t N>
struct FixedArraySerde {
  static void serialize(const std::array<T, N> &array, auto &out) {
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      out.arrayBegin();
      for (auto it = array.rbegin(); it != array.rend(); ++it) serde::serialize(*it, out);
      out.arrayEnd(N);
    } else {
      serde::serialize(std::string_view("bounded helper fields (redacted)"), out);
    }
  }
  static Result<Void> deserialize(std::array<T, N> &array, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != N) return makeError(StatusCode::kInvalidFormat, "helper array has a wrong fixed extent");
      for (auto &item : array) RETURN_ON_ERROR(serde::deserialize(item, in));
      return Void{};
    } else
      return makeError(StatusCode::kInvalidFormat, "helper wire requires binary Serde");
  }
};
}  // namespace hf3fs::storage::ec_helper_detail

#define EC_HELPER_FIELDS(Type, ...)                                                                            \
  template <>                                                                                                  \
  struct hf3fs::serde::SerdeMethod<Type> {                                                                     \
    static auto fields(auto &value) { return std::tie(__VA_ARGS__); }                                          \
    static void serialize(const Type &value, auto &out) {                                                      \
      if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {                       \
        auto tuple = fields(value);                                                                            \
        storage::ec_helper_detail::writeTuple(tuple,                                                           \
                                              out,                                                             \
                                              std::make_index_sequence<std::tuple_size_v<decltype(tuple)>>{}); \
      } else                                                                                                   \
        serde::serialize(std::string_view("EC helper wire (redacted)"), out);                                  \
    }                                                                                                          \
    static Result<Void> deserialize(Type &value, auto &in) {                                                   \
      if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {                         \
        auto tuple = fields(value);                                                                            \
        Varint64 count = 0;                                                                                    \
        RETURN_ON_ERROR(serde::deserialize(count, in));                                                        \
        if (count != std::tuple_size_v<decltype(tuple)>)                                                       \
          return makeError(StatusCode::kInvalidFormat, "helper record has a wrong fixed extent");              \
        return storage::ec_helper_detail::readTuple(tuple, in);                                                \
      } else                                                                                                   \
        return makeError(StatusCode::kInvalidFormat, "helper wire requires binary Serde");                     \
    }                                                                                                          \
  };

EC_HELPER_FIELDS(hf3fs::storage::EcScopeEndpoint,
                 value.nodeId,
                 value.chainId,
                 value.targetId,
                 value.engineUuid,
                 value.targetIncarnation)
EC_HELPER_FIELDS(hf3fs::storage::EcRepairFragment,
                 value.identity,
                 value.operationId,
                 value.writerNamespace,
                 value.endpoint,
                 value.integrity)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperClaims,
                 value.version,
                 value.rights,
                 value.planDigest,
                 value.recipient,
                 value.helperPosition,
                 value.blockMask,
                 value.grantId,
                 value.issuedAtSeconds,
                 value.expiresAtSeconds)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperCapability, value.claims, value.signature_)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperStamp,
                 value.version,
                 value.packetDigest,
                 value.senderPosition,
                 value.recipientPosition,
                 value.issuedAtSeconds,
                 value.expiresAtSeconds,
                 value.signature_)

#define EC_HELPER_ARRAY(Type, Count)                        \
  template <>                                               \
  struct hf3fs::serde::SerdeMethod<std::array<Type, Count>> \
      : hf3fs::storage::ec_helper_detail::FixedArraySerde<Type, Count> {};
EC_HELPER_ARRAY(hf3fs::storage::EcRepairFragment, 10)
EC_HELPER_ARRAY(hf3fs::storage::EcRepairFragment, 2)
EC_HELPER_ARRAY(hf3fs::storage::EcScopeEndpoint, 24)
EC_HELPER_ARRAY(hf3fs::storage::EcHelperCapability, 10)
EC_HELPER_ARRAY(hf3fs::storage::EcCapabilityV2, 10)
EC_HELPER_ARRAY(hf3fs::storage::ChainVer, 10)
EC_HELPER_ARRAY(hf3fs::storage::EcSlicePayloadV2, 2)
#undef EC_HELPER_ARRAY

EC_HELPER_FIELDS(hf3fs::storage::EcRepairPlanInput,
                 value.planId,
                 value.operationId,
                 value.ownerUid,
                 value.clientNamespace,
                 value.baseEpoch,
                 value.baseRevision,
                 value.logicalLength,
                 value.logicalSha256,
                 value.sources,
                 value.targets,
                 value.targetCount,
                 value.operationEndpoints,
                 value.operationEndpointCount,
                 value.maxBlocksInFlight)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperPacket,
                 value.planDigest,
                 value.blockIndex,
                 value.contributorMask,
                 value.nextHelper,
                 value.targetCount,
                 value.outputs)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperHopReq,
                 value.plan,
                 value.helpers,
                 value.reads,
                 value.routeVersions,
                 value.packet,
                 value.predecessor,
                 value.deadlineUnixMillis)
EC_HELPER_FIELDS(hf3fs::storage::EcHelperHopResult, value.packet, value.finalStamp)
#undef EC_HELPER_FIELDS

static_assert(hf3fs::serde::Serializable<hf3fs::storage::EcHelperHopReq>);
static_assert(hf3fs::serde::Serializable<hf3fs::storage::EcHelperHopRsp>);
static_assert(sizeof(hf3fs::storage::EcHelperHopReq) <= 32u << 10);
