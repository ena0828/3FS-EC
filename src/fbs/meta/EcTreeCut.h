#pragma once

#include "fbs/meta/EcFileTree.h"

namespace hf3fs::meta {
// Internal tree primitive, not a public RPC or Data publication certificate.
struct EcTreeCut {
  EcObjectRef object;
  Uuid operation = Uuid::zero();
  EcTreeRoot expected;
  uint64_t length = 0;
  std::array<Uuid, 16> nodeIds{};
  // Present only for a genuinely shortened Data tail, already installed by
  // the trusted publication verifier in this same transaction.
  std::optional<EcTreeSlot> tail;
};
}  // namespace hf3fs::meta
