#include "EcFileRepair.h"

#include <bit>
#include <set>

namespace hf3fs::meta {
Result<Void> validateEcFileRepairIntent(const EcFileRepairIntent &i) {
  if (i.version != 1 || i.object.incarnation.is_nil() || i.object.inode.isTreeRoot() ||
      i.object.inode > InodeId::normalMax() || i.owner.client.is_nil() || i.session.is_nil() ||
      i.expectedRoot.is_nil() || !i.expectedEpoch || !i.expectedSequence || (i.replacementMask & ~uint16_t{4095}) ||
      !i.replacementMask || std::popcount(i.replacementMask) > 2 ||
      (i.mode != EcFileRepairMode::CentralSerial && i.mode != EcFileRepairMode::ClientPipeline &&
       i.mode != EcFileRepairMode::HelperChain && i.mode != EcFileRepairMode::HelperChainDirect) ||
      !i.selection.maxBlocksInFlight || i.selection.maxBlocksInFlight > 4)
    return makeError(StatusCode::kInvalidArg, "invalid mode4 repair identity/selection");
  std::set<Uuid> ids;
  for (const auto &u : {i.request, i.operation, i.child, i.sourcePin, i.selection.planId})
    if (u.is_nil() || !ids.insert(u).second)
      return makeError(StatusCode::kInvalidArg, "repair identities must be fixed and distinct");
  for (const auto &u : i.nodeIds)
    if (u.is_nil() || !ids.insert(u).second) return makeError(StatusCode::kInvalidArg);
  uint16_t seen = 0;
  for (auto n : i.selection.sourceOrder) {
    if (n >= 12 || (i.replacementMask & (uint16_t{1} << n)) || (seen & (uint16_t{1} << n)))
      return makeError(StatusCode::kInvalidArg);
    seen |= uint16_t{1} << n;
  }
  return Void{};
}
}  // namespace hf3fs::meta
