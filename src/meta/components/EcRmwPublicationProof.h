#pragma once

#include "fbs/meta/EcV2Lifecycle.h"
#include "storage/ec_rmw/EcRmwPlan.h"

namespace hf3fs::meta::server {
class EcRmwPublicationVerifier;
// This type has no public constructor, Serde, caller boolean or test friend.
// A Storage sealed-result/MAC alone cannot construct it. The future trusted
// verifier must fresh-read the committed W2 child/output binding, verify all
// twelve actual bytes/codeword/padding/logical SHA and Seal barriers, close the
// candidate WriteOperation and verify all twelve persisted authenticated T2
// ACKs. Source-pin cleanup is separate and may remain owed.
//
// Only the actual EcRmwPublicationVerifier factory can construct this type.
// W2 still conflict-reads child/epoch/root CAS in the installation txn. A
// Drained execution retains drain.state=Closing until that metadata commit;
// complete ACKs alone do not claim that the new tree is already visible.
class EcRmwPublicationProof final {
 public:
  const storage::EcRmwPlan &plan() const noexcept { return *plan_; }
  const EcManifest &manifest() const noexcept { return manifest_; }
  const EcV2AllocationBindings &allocations() const noexcept { return allocations_; }
  const EcV2DrainRecord &drain() const noexcept { return drain_; }

 private:
  friend class EcRmwPublicationVerifier;
  EcRmwPublicationProof(std::shared_ptr<const storage::EcRmwPlan> plan,
                        EcManifest manifest,
                        EcV2AllocationBindings allocations,
                        EcV2DrainRecord drain)
      : plan_(std::move(plan)),
        manifest_(std::move(manifest)),
        allocations_(std::move(allocations)),
        drain_(std::move(drain)) {}
  std::shared_ptr<const storage::EcRmwPlan> plan_;
  EcManifest manifest_;
  EcV2AllocationBindings allocations_;
  EcV2DrainRecord drain_;
};
}  // namespace hf3fs::meta::server
