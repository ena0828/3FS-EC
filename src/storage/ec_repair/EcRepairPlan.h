#pragma once

#include <array>
#include <memory>
#include <span>
#include <string>

#include "fbs/storage/EcRepairSpec.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::storage {

class EcRepairPlan {
 public:
  static Result<std::shared_ptr<const EcRepairPlan>> create(EcRepairPlanInput input);
  const EcRepairPlanInput &input() const { return input_; }
  const EcSha256 &digest() const { return digest_; }
  const EcSha256 &endpointSetDigest() const { return endpointDigest_; }
  const std::array<uint16_t, 10> &healthy() const { return healthy_; }
  std::span<const uint16_t> targets() const { return {targets_.data(), input_.targetCount}; }
  uint32_t shardBytes() const { return input_.sources[0].integrity.wholeLength; }
  uint16_t blockCount() const { return input_.sources[0].integrity.blockCount; }
  Result<uint32_t> blockLength(uint32_t blockIndex) const;

 private:
  explicit EcRepairPlan(EcRepairPlanInput input)
      : input_(std::move(input)) {}
  EcRepairPlanInput input_;
  EcSha256 digest_{};
  EcSha256 endpointDigest_{};
  std::array<uint16_t, 10> healthy_{};
  std::array<uint16_t, 2> targets_{};
};

// Arithmetic packet only, never an authenticated network message. A helper
// envelope must MAC the complete packet and bind the exact predecessor and
// recipient. Retry recomputes from the predecessor packet, never from a saved
// post-XOR accumulator, so the same helper is not added twice.
struct EcRepairBlock {
  EcSha256 planDigest{};
  uint32_t blockIndex = 0;
  uint16_t contributorMask = 0;  // Positions in healthy(), not shard numbers.
  uint8_t nextHelper = 0;
  uint8_t targetCount = 0;
  std::array<std::string, 2> outputs;
};

class EcRepairBlockCore {
 public:
  static Result<EcRepairBlock> begin(const EcRepairPlan &plan, uint32_t blockIndex);
  static Result<EcRepairBlock> advance(const EcRepairPlan &plan,
                                       uint8_t helperPosition,
                                       EcRepairBlock incoming,
                                       std::string_view verifiedLocalBlock);
  static Result<Void> validate(const EcRepairPlan &plan, const EcRepairBlock &block, uint8_t expectedNextHelper);
  static Result<Void> validateComplete(const EcRepairPlan &plan, const EcRepairBlock &block);
  // Digest for a future authenticated hop envelope; a digest alone is not a MAC.
  static Result<EcSha256> digestPacket(const EcRepairPlan &plan, const EcRepairBlock &block);
};

}  // namespace hf3fs::storage
