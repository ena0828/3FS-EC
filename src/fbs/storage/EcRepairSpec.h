#pragma once

#include <array>

#include "fbs/storage/EcAuthorizationV2.h"
#include "fbs/storage/EcScopeControl.h"

namespace hf3fs::storage {

struct EcRepairFragment {
  EcFragmentIdentity identity;
  Uuid operationId = Uuid::zero();
  Uuid writerNamespace = Uuid::zero();
  EcScopeEndpoint endpoint;
  EcIntegrityDescriptor integrity;
};

// Local, owning plan description. Construction validates structure, not the
// issuer's authority. Only a separately authenticated Meta plan may enter a
// helper service. Bounded wire Serde is defined in EcHelper.h; no conversion
// from an ordinary ReadBlock grant can confer helper authority.
struct EcRepairPlanInput {
  Uuid planId = Uuid::zero();
  Uuid operationId = Uuid::zero();
  flat::Uid ownerUid{};
  Uuid clientNamespace = Uuid::zero();
  uint64_t baseEpoch = 0;
  uint64_t baseRevision = 0;
  uint64_t logicalLength = 0;
  EcSha256 logicalSha256{};
  std::array<EcRepairFragment, 10> sources;
  std::array<EcRepairFragment, 2> targets;
  uint8_t targetCount = 0;
  // Full operation set, including unselected base and candidate allocations.
  // The selected ten sources plus replacements are not a sufficient GC set.
  std::array<EcScopeEndpoint, 24> operationEndpoints;
  uint8_t operationEndpointCount = 0;
  uint8_t maxBlocksInFlight = 1;
};

}  // namespace hf3fs::storage
