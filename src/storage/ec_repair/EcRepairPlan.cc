#include "EcRepairPlan.h"

#include <algorithm>
#include <new>
#include <openssl/evp.h>

namespace hf3fs::storage {
namespace {

void integer(std::string &out, uint64_t value, size_t width) {
  for (size_t i = width; i != 0; --i) out.push_back(static_cast<char>(value >> ((i - 1) * 8)));
}
void uuid(std::string &out, const Uuid &value) { out.append(value.asStringView()); }
void hash(std::string &out, const EcSha256 &value) {
  out.append(reinterpret_cast<const char *>(value.data()), value.size());
}
Result<EcSha256> sha256(std::string_view bytes) {
  EcSha256 result{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), result.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != result.size()) {
    return makeError(StatusCode::kIOError, "repair plan SHA-256 failed");
  }
  return result;
}
bool sameEndpoint(const EcScopeEndpoint &a, const EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}
void endpoint(std::string &out, const EcScopeEndpoint &value) {
  integer(out, value.nodeId.toUnderType(), 4);
  integer(out, value.chainId.toUnderType(), 4);
  integer(out, value.targetId.toUnderType(), 8);
  uuid(out, value.engineUuid);
  uuid(out, value.targetIncarnation);
}
Result<Void> fragment(std::string &out,
                      const EcRepairFragment &value,
                      const EcRepairPlanInput &input,
                      std::span<const EcScopeEndpoint> endpoints) {
  RETURN_ON_ERROR(value.identity.validate());
  RETURN_ON_ERROR(validateEcIntegrity(value.identity, value.integrity));
  if (value.operationId.is_nil() || value.writerNamespace.is_nil() || value.identity.shard >= 12 ||
      value.integrity.wholeLength == 0 || value.integrity.wholeLength > EcCodec::kMaxShardBytes ||
      std::none_of(endpoints.begin(), endpoints.end(), [&](const auto &item) {
        return sameEndpoint(item, value.endpoint);
      })) {
    return makeError(StatusCode::kInvalidArg, "repair fragment has invalid ownership, length or endpoint");
  }
  const auto &first = input.sources[0];
  if (value.identity.object != first.identity.object || value.identity.stripe != first.identity.stripe ||
      value.identity.generation != first.identity.generation ||
      value.integrity.wholeLength != first.integrity.wholeLength) {
    return makeError(StatusCode::kInvalidArg, "repair plan mixes stripe content identities or lengths");
  }
  CHECK_RESULT(descriptorDigest, digestEcIntegrityV2(value.identity, value.integrity));
  integer(out, value.identity.version, 2);
  uuid(out, value.identity.object);
  integer(out, value.identity.stripe, 8);
  integer(out, value.identity.generation, 8);
  integer(out, value.identity.shard, 2);
  uuid(out, value.identity.allocation);
  uuid(out, value.operationId);
  uuid(out, value.writerNamespace);
  endpoint(out, value.endpoint);
  hash(out, descriptorDigest);
  return Void{};
}

}  // namespace

Result<std::shared_ptr<const EcRepairPlan>> EcRepairPlan::create(EcRepairPlanInput input) {
  try {
    if (input.planId.is_nil() || input.operationId.is_nil() || input.clientNamespace.is_nil() || input.baseEpoch == 0 ||
        input.baseRevision == 0 || input.targetCount == 0 || input.targetCount > 2 || input.maxBlocksInFlight == 0 ||
        input.maxBlocksInFlight > 4 || input.operationEndpointCount == 0 || input.operationEndpointCount > 24 ||
        input.logicalLength > uint64_t(input.sources[0].integrity.wholeLength) * 10) {
      return makeError(StatusCode::kInvalidArg, "invalid fixed repair plan bounds or identity");
    }
    auto plan = std::shared_ptr<EcRepairPlan>(new EcRepairPlan(std::move(input)));
    const auto &spec = plan->input_;
    auto endpoints = std::span(spec.operationEndpoints.data(), spec.operationEndpointCount);
    CHECK_RESULT(endpointDigest, computeEcScopeEndpointDigest(endpoints));
    plan->endpointDigest_ = endpointDigest;
    std::string canonical("3FSERPL1", 8);
    integer(canonical, 1, 2);
    uuid(canonical, spec.planId);
    uuid(canonical, spec.operationId);
    integer(canonical, spec.ownerUid.toUnderType(), 4);
    uuid(canonical, spec.clientNamespace);
    integer(canonical, spec.baseEpoch, 8);
    integer(canonical, spec.baseRevision, 8);
    integer(canonical, spec.logicalLength, 8);
    hash(canonical, spec.logicalSha256);
    integer(canonical, spec.maxBlocksInFlight, 1);
    hash(canonical, endpointDigest);
    integer(canonical, spec.targetCount, 1);
    std::array<bool, 12> seen{};
    std::array<Uuid, 12> allocations{};
    size_t count = 0;
    const auto append = [&](const EcRepairFragment &value) -> Result<Void> {
      RETURN_ON_ERROR(fragment(canonical, value, spec, endpoints));
      if (seen[value.identity.shard] ||
          std::find(allocations.begin(), allocations.begin() + count, value.identity.allocation) !=
              allocations.begin() + count) {
        return makeError(StatusCode::kInvalidArg, "duplicate repair shard or allocation");
      }
      seen[value.identity.shard] = true;
      allocations[count++] = value.identity.allocation;
      return Void{};
    };
    for (size_t i = 0; i != spec.sources.size(); ++i) {
      RETURN_ON_ERROR(append(spec.sources[i]));
      plan->healthy_[i] = spec.sources[i].identity.shard;
    }
    for (size_t i = 0; i != spec.targetCount; ++i) {
      if (spec.targets[i].operationId != spec.operationId || spec.targets[i].writerNamespace != spec.clientNamespace) {
        return makeError(StatusCode::kInvalidArg, "repair replacement must belong to the fixed write operation");
      }
      RETURN_ON_ERROR(append(spec.targets[i]));
      plan->targets_[i] = spec.targets[i].identity.shard;
    }
    CHECK_RESULT(digest, sha256(canonical));
    plan->digest_ = digest;
    return std::shared_ptr<const EcRepairPlan>(std::move(plan));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<uint32_t> EcRepairPlan::blockLength(uint32_t index) const {
  if (index >= blockCount()) return makeError(StatusCode::kInvalidArg, "repair block index is out of range");
  return input_.sources[0].integrity.blocks[index].validLength;
}

Result<EcRepairBlock> EcRepairBlockCore::begin(const EcRepairPlan &plan, uint32_t blockIndex) {
  try {
    CHECK_RESULT(length, plan.blockLength(blockIndex));
    EcRepairBlock result;
    result.planDigest = plan.digest();
    result.blockIndex = blockIndex;
    result.targetCount = plan.input().targetCount;
    for (size_t i = 0; i != result.targetCount; ++i) result.outputs[i].assign(length, '\0');
    return result;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<Void> EcRepairBlockCore::validate(const EcRepairPlan &plan,
                                         const EcRepairBlock &block,
                                         uint8_t expectedNextHelper) {
  CHECK_RESULT(length, plan.blockLength(block.blockIndex));
  if (expectedNextHelper > 10 || block.nextHelper != expectedNextHelper || block.planDigest != plan.digest() ||
      block.targetCount != plan.input().targetCount ||
      block.contributorMask != uint16_t((uint16_t{1} << expectedNextHelper) - 1)) {
    return makeError(StatusCode::kInvalidArg, "repair block violates plan, hop or contribution prefix");
  }
  for (size_t i = 0; i != block.outputs.size(); ++i) {
    if (block.outputs[i].size() != (i < block.targetCount ? length : 0)) {
      return makeError(StatusCode::kInvalidArg, "repair accumulator has wrong output extent");
    }
    if (expectedNextHelper == 0 &&
        std::any_of(block.outputs[i].begin(), block.outputs[i].end(), [](char value) { return value != 0; })) {
      return makeError(StatusCode::kInvalidArg, "first repair accumulator must be zero");
    }
  }
  return Void{};
}

Result<EcRepairBlock> EcRepairBlockCore::advance(const EcRepairPlan &plan,
                                                 uint8_t position,
                                                 EcRepairBlock incoming,
                                                 std::string_view localBlock) {
  try {
    if (position >= 10) return makeError(StatusCode::kInvalidArg, "repair helper position is out of range");
    RETURN_ON_ERROR(validate(plan, incoming, position));
    const auto &source = plan.input().sources[position];
    RETURN_ON_ERROR(verifyEcIntegrityBlock(source.identity, source.integrity, incoming.blockIndex, localBlock));
    const auto &format = source.integrity;
    CHECK_RESULT(
        contributions,
        EcCodec::contribute(
            plan.healthy(),
            plan.targets(),
            source.identity.shard,
            localBlock,
            {format.codecId, format.matrixVersion, format.dataShards, format.parityShards, format.fieldPolynomial}));
    if (contributions.size() != incoming.targetCount) return makeError(StatusCode::kFoundBug);
    for (size_t target = 0; target != incoming.targetCount; ++target) {
      if (contributions[target].size() != incoming.outputs[target].size()) return makeError(StatusCode::kFoundBug);
      for (size_t byte = 0; byte != incoming.outputs[target].size(); ++byte) {
        incoming.outputs[target][byte] ^= contributions[target][byte];
      }
    }
    incoming.nextHelper = position + 1;
    incoming.contributorMask |= uint16_t{1} << position;
    if (incoming.nextHelper == 10) RETURN_ON_ERROR(validateComplete(plan, incoming));
    return incoming;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

Result<Void> EcRepairBlockCore::validateComplete(const EcRepairPlan &plan, const EcRepairBlock &block) {
  RETURN_ON_ERROR(validate(plan, block, 10));
  for (size_t i = 0; i != block.targetCount; ++i) {
    const auto &target = plan.input().targets[i];
    RETURN_ON_ERROR(verifyEcIntegrityBlock(target.identity, target.integrity, block.blockIndex, block.outputs[i]));
  }
  return Void{};
}

Result<EcSha256> EcRepairBlockCore::digestPacket(const EcRepairPlan &plan, const EcRepairBlock &block) {
  try {
    RETURN_ON_ERROR(validate(plan, block, block.nextHelper));
    std::string canonical("3FSERPK1", 8);
    hash(canonical, block.planDigest);
    integer(canonical, block.blockIndex, 4);
    integer(canonical, block.contributorMask, 2);
    integer(canonical, block.nextHelper, 1);
    integer(canonical, block.targetCount, 1);
    for (size_t i = 0; i != block.targetCount; ++i) {
      integer(canonical, block.outputs[i].size(), 4);
      canonical.append(block.outputs[i]);
    }
    return sha256(canonical);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}

}  // namespace hf3fs::storage
