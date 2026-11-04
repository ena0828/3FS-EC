#pragma once

#include "fbs/meta/EcV2Lifecycle.h"
#include "fbs/storage/EcHelper.h"

// A request may select shard indices, never physical instances or descriptors.
// Reject an oversized source list before decoding its first element.
template <>
struct hf3fs::serde::SerdeMethod<std::array<uint8_t, 10>>
    : hf3fs::storage::ec_helper_detail::FixedArraySerde<uint8_t, 10> {};

namespace hf3fs::meta {
struct EcV2RepairSelection {
  SERDE_STRUCT_FIELD(planId, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceOrder, (std::array<uint8_t, 10>{}));
  SERDE_STRUCT_FIELD(maxBlocksInFlight, uint8_t{1});
};

// One permanent plan per repair operation. Renewals change bearer lifetimes,
// never this record, its source order, its window, or any physical binding.
struct EcV2RepairPlanRecord {
  SERDE_STRUCT_FIELD(version, kEcV2LifecycleVersion);
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(selection, EcV2RepairSelection{});
  SERDE_STRUCT_FIELD(plan, storage::EcRepairPlanInput{});
  SERDE_STRUCT_FIELD(digest, storage::EcSha256{});
};
}  // namespace hf3fs::meta
