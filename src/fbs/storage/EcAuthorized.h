#pragma once

#include "fbs/storage/EcAuthorization.h"

namespace hf3fs::storage {

// Separate method IDs preserve the original experimental request wire formats.
// The capability is a bearer credential; userInfo is not authentication.
struct EcAuthorizedCreateReq {
  SERDE_STRUCT_FIELD(request, EcCreateReq{});
  SERDE_STRUCT_FIELD(grant, EcCapability{});
};

struct EcAuthorizedReadReq {
  SERDE_STRUCT_FIELD(request, EcReadReq{});
  SERDE_STRUCT_FIELD(grant, EcCapability{});
};

struct EcAuthorizedReconcileReq {
  SERDE_STRUCT_FIELD(request, EcReconcileReq{});
  SERDE_STRUCT_FIELD(grant, EcCapability{});
};

static_assert(serde::Serializable<EcAuthorizedCreateReq>);
static_assert(serde::Serializable<EcAuthorizedReadReq>);
static_assert(serde::Serializable<EcAuthorizedReconcileReq>);

}  // namespace hf3fs::storage
