#pragma once

#include <limits>

#include "fbs/meta/EcLayout.h"
#include "fbs/meta/EcV2.h"

namespace hf3fs::meta {
inline constexpr size_t kEcFileRangeMaxStripes = 8;
inline constexpr uint64_t kEcFileRangeMaxBytes = 32ull << 20;
inline constexpr size_t kEcFileRangeMaxRecordBytes = 64u << 10;

struct EcFileState {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(layout, EcManifestLayoutV1{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
};

struct EcRangePin {
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(pin, Uuid::zero());

 public:
  bool operator==(const EcRangePin &other) const { return serde::equals(*this, other); }
};

enum class EcRangePinState : uint8_t { Unused = 0, Active = 1, Closing = 2, Released = 3 };

struct EcRangeStripe {
  SERDE_STRUCT_FIELD(snapshot, EcV2PinSnapshot{});
  SERDE_STRUCT_FIELD(logicalLength, uint64_t{});
  SERDE_STRUCT_FIELD(contentSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(state, EcRangePinState::Unused);

 public:
  bool operator==(const EcRangeStripe &other) const { return serde::equals(*this, other); }
};
}  // namespace hf3fs::meta

// Wire counts are checked before any element is deserialized or allocated.
template <typename T>
requires(std::is_same_v<T, hf3fs::meta::EcRangePin> ||
         std::is_same_v<T, hf3fs::meta::EcRangeStripe>) struct hf3fs::serde::SerdeMethod<std::array<T, 8>> {
  static void serialize(const std::array<T, 8> &values, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = values.rbegin(); it != values.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &value : values) serde::serialize(value, out);
    }
    out.arrayEnd(values.size());
  }
  static Result<Void> deserialize(std::array<T, 8> &values, auto &in) {
    if constexpr (requires { typename std::decay_t<decltype(in)>::is_binary_in; }) {
      Varint64 count = 0;
      RETURN_ON_ERROR(serde::deserialize(count, in));
      if (count != 8) return makeError(StatusCode::kInvalidFormat, "EC range requires eight fixed slots");
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in));
    } else {
      CHECK_RESULT(container, in.parseContainer());
      if (container.first != 8) return makeError(StatusCode::kInvalidFormat, "EC range requires eight fixed slots");
      auto it = std::move(container.second);
      for (auto &value : values) RETURN_ON_ERROR(serde::deserialize(value, in.fetchAndNext(it)));
    }
    return Void{};
  }
};

namespace hf3fs::meta {
struct EcRangeSelection {
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(offset, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(pinCount, uint16_t{});
  SERDE_STRUCT_FIELD(pins, (std::array<EcRangePin, 8>{}));

 public:
  Result<Void> valid() const {
    if (object.incarnation.is_nil() || object.inode.isTreeRoot() || object.inode > InodeId::normalMax() ||
        length > kEcFileRangeMaxBytes || offset > std::numeric_limits<uint64_t>::max() - length ||
        pinCount > kEcFileRangeMaxStripes || ((length == 0) != (pinCount == 0)))
      return makeError(StatusCode::kInvalidArg, "invalid bounded EC range");
    for (size_t i = 0; i != pins.size(); ++i) {
      if (i >= pinCount) {
        if (!serde::equals(pins[i], EcRangePin{}))
          return makeError(StatusCode::kInvalidArg, "unused range pin slots must be zero");
        continue;
      }
      if (pins[i].pin.is_nil()) return makeError(StatusCode::kInvalidArg, "range pins must be nonzero");
      for (size_t j = 0; j != i; ++j)
        if (pins[i].pin == pins[j].pin) return makeError(StatusCode::kInvalidArg, "duplicate range pin");
    }
    return Void{};
  }

  Result<Void> matchesLayout(const EcManifestLayoutV1 &layout) const {
    RETURN_ON_ERROR(valid());
    RETURN_ON_ERROR(layout.valid());
    if (layout.incarnation != object.incarnation)
      return makeError(StatusCode::kTokenMismatch, "range layout incarnation differs");
    const uint64_t stripeBytes = uint64_t{layout.shardBytes} * 10;
    const uint64_t first = offset / stripeBytes;
    const uint64_t count = length ? ((offset + length - 1) / stripeBytes - first + 1) : 0;
    if (count != pinCount)
      return makeError(StatusCode::kInvalidArg, "range pins must cover requested extent before EOF clipping");
    for (size_t i = 0; i != pinCount; ++i) {
      if (first > std::numeric_limits<uint64_t>::max() - i || pins[i].stripe != first + i)
        return makeError(StatusCode::kInvalidArg, "range pin stripe mapping differs from layout");
    }
    return Void{};
  }
};

// Contains no capability, token, or authorization. Entries are fixed snapshots;
// Query changes only their observed pin state, within its one read transaction.
struct EcRangeSnapshot {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(requestId, Uuid::zero());
  SERDE_STRUCT_FIELD(rangeId, Uuid::zero());
  SERDE_STRUCT_FIELD(selection, EcRangeSelection{});
  SERDE_STRUCT_FIELD(file, EcFileState{});
  SERDE_STRUCT_FIELD(readableLength, uint64_t{});
  SERDE_STRUCT_FIELD(stripeCount, uint16_t{});
  SERDE_STRUCT_FIELD(stripes, (std::array<EcRangeStripe, 8>{}));
};
}  // namespace hf3fs::meta
