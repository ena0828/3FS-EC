#pragma once

#include <memory>
#include <string>

#include "fbs/storage/EcRepairSpec.h"

namespace hf3fs::storage {
inline constexpr uint16_t kEcRmwPlanVersion = 1;
inline constexpr uint32_t kEcRmwPatchBlockBytes = 64u << 10;
inline constexpr uint32_t kEcRmwMaxPatchBlocks = 160;
enum class EcRmwAction : uint8_t { Pwrite = 1, TruncateTail = 2, Repair = 3 };
enum class EcRmwSourceKind : uint8_t { Zero = 0, Data = 1 };
struct EcRmwTarget {
  EcFragmentIdentity identity;
  EcScopeEndpoint endpoint;
};
// Local owning description only. It is not wire Serde or authorization, and
// cannot install a mode-4 leaf. Only a committed Meta plan may be signed.
struct EcRmwPlanInput {
  uint16_t version = kEcRmwPlanVersion;
  EcRmwAction action = EcRmwAction::Pwrite;
  uint64_t inode = 0;
  Uuid object = Uuid::zero();
  Uuid birth = Uuid::zero();
  Uuid planId = Uuid::zero();
  Uuid sessionId = Uuid::zero();
  Uuid parentId = Uuid::zero();
  Uuid operationId = Uuid::zero();  // Fixed child / output WriteOperation.
  flat::Uid ownerUid{};
  Uuid clientNamespace = Uuid::zero();
  uint64_t fenceEpoch = 0;
  Uuid sourceRoot = Uuid::zero();
  uint64_t sourceSequence = 0;
  uint64_t lengthAtPlan = 0;  // Exact visible EOF captured with this source root.
  uint64_t stripe = 0;
  uint32_t shardBytes = 0;
  EcRmwSourceKind sourceKind = EcRmwSourceKind::Zero;
  Uuid sourcePin = Uuid::zero();
  uint64_t sourceRevision = 0;
  uint64_t sourceGeneration = 0;
  uint32_t sourceLogicalLength = 0;
  EcSha256 sourceLogicalSha256{};
  std::array<EcRepairFragment, 12> sources;
  uint64_t targetRevision = 0;
  uint64_t targetGeneration = 0;
  std::array<EcRmwTarget, 12> targets;
  uint8_t workerIndex = 0;  // The executor is one of the twelve target instances.
  uint32_t patchOffset = 0;
  uint32_t patchLength = 0;
  EcSha256 patchSha256{};
  uint32_t targetLogicalLength = 0;
};
class EcRmwPlan final {
 public:
  static Result<std::shared_ptr<const EcRmwPlan>> create(EcRmwPlanInput);
  const EcRmwPlanInput &input() const noexcept { return input_; }
  const EcSha256 &digest() const noexcept { return digest_; }
  const EcScopeEndpoint &worker() const noexcept { return input_.targets[input_.workerIndex].endpoint; }
  uint32_t patchBlocks() const noexcept {
    return (input_.patchLength + kEcRmwPatchBlockBytes - 1) / kEcRmwPatchBlockBytes;
  }
  Result<uint32_t> patchBlockLength(uint32_t) const;

 private:
  explicit EcRmwPlan(EcRmwPlanInput input)
      : input_(std::move(input)) {}
  EcRmwPlanInput input_;
  EcSha256 digest_{};
};
namespace ec_rmw_detail {
Result<EcSha256> sha256(std::string_view);
bool sameEndpoint(const EcScopeEndpoint &, const EcScopeEndpoint &) noexcept;
}  // namespace ec_rmw_detail
}  // namespace hf3fs::storage
