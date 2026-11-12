#include "EcRmwPlan.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <set>

namespace hf3fs::storage {
namespace {
void number(std::string &out, uint64_t value, unsigned bytes) {
  for (unsigned i = bytes; i; --i) out.push_back(static_cast<char>(value >> ((i - 1) * 8)));
}
void uuid(std::string &out, const Uuid &value) { out.append(value.asStringView()); }
void appendDigest(std::string &out, const EcSha256 &value) {
  out.append(reinterpret_cast<const char *>(value.data()), value.size());
}
void identity(std::string &out, const EcFragmentIdentity &id) {
  number(out, id.version, 2);
  uuid(out, id.object);
  number(out, id.stripe, 8);
  number(out, id.generation, 8);
  number(out, id.shard, 2);
  uuid(out, id.allocation);
}
void endpoint(std::string &out, const EcScopeEndpoint &ep) {
  number(out, ep.nodeId.toUnderType(), 4);
  number(out, ep.chainId.toUnderType(), 4);
  number(out, ep.targetId.toUnderType(), 8);
  uuid(out, ep.engineUuid);
  uuid(out, ep.targetIncarnation);
}
bool validEndpoint(const EcScopeEndpoint &ep) {
  return ep.nodeId != NodeId{} && ep.chainId != ChainId{} && ep.targetId != TargetId{} && !ep.engineUuid.is_nil() &&
         !ep.targetIncarnation.is_nil();
}
bool emptySource(const EcRepairFragment &source) {
  const auto &id = source.identity;
  return id.version == kEcFragmentProtocolVersion && id.object.is_nil() && !id.stripe && !id.generation && !id.shard &&
         id.allocation.is_nil() && source.operationId.is_nil() && source.writerNamespace.is_nil() &&
         ec_rmw_detail::sameEndpoint(source.endpoint, EcScopeEndpoint{}) && source.integrity == EcIntegrityDescriptor{};
}
}  // namespace
namespace ec_rmw_detail {
bool sameEndpoint(const EcScopeEndpoint &a, const EcScopeEndpoint &b) noexcept {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}
Result<EcSha256> sha256(std::string_view bytes) {
  using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
  Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  EcSha256 out{};
  unsigned size = 0;
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), bytes.data(), bytes.size()) != 1 ||
      EVP_DigestFinal_ex(context.get(), out.data(), &size) != 1 || size != out.size())
    return makeError(StatusCode::kIOError, "RMW SHA computation failed");
  return out;
}
}  // namespace ec_rmw_detail
Result<std::shared_ptr<const EcRmwPlan>> EcRmwPlan::create(EcRmwPlanInput input) {
  const auto &p = input;
  const uint64_t capacity = uint64_t(p.shardBytes) * 10;
  if (p.version != kEcRmwPlanVersion || p.inode <= 1 || p.object.is_nil() || p.birth.is_nil() || p.planId.is_nil() ||
      p.sessionId.is_nil() || p.parentId.is_nil() || p.operationId.is_nil() || p.clientNamespace.is_nil() ||
      !p.fenceEpoch || !p.sourceSequence || !p.shardBytes || p.shardBytes > kEcFragmentRpcMaxBytes ||
      p.workerIndex >= 12 || p.patchOffset >= capacity || p.patchLength > capacity - p.patchOffset ||
      p.patchSha256 == EcSha256{} || !p.targetRevision || !p.targetGeneration || p.sourceLogicalLength > capacity ||
      p.stripe > std::numeric_limits<uint64_t>::max() / capacity)
    return makeError(StatusCode::kInvalidArg, "invalid fixed RMW plan extent or identity");
  const uint64_t start = p.stripe * capacity;
  const uint64_t visible = p.lengthAtPlan > start ? std::min(capacity, p.lengthAtPlan - start) : 0;
  if (p.sourceLogicalLength > visible) return makeError(StatusCode::kInvalidArg);
  if (p.action == EcRmwAction::Pwrite) {
    if (!p.patchLength || p.targetLogicalLength != std::max<uint64_t>(visible, uint64_t(p.patchOffset) + p.patchLength))
      return makeError(StatusCode::kInvalidArg, "RMW output would lose the captured visible zero tail");
  } else if (p.action == EcRmwAction::TruncateTail) {
    CHECK_RESULT(emptyHash, ec_rmw_detail::sha256({}));
    if (p.patchOffset || p.patchLength || p.patchSha256 != emptyHash || !p.targetLogicalLength ||
        p.targetLogicalLength >= visible)
      return makeError(StatusCode::kInvalidArg, "RMW truncate requires an explicit strict tail and no patch");
  } else if (p.action == EcRmwAction::Repair) {
    CHECK_RESULT(emptyHash, ec_rmw_detail::sha256({}));
    if (p.sourceKind != EcRmwSourceKind::Data || p.patchOffset || p.patchLength || p.patchSha256 != emptyHash ||
        !p.sourceLogicalLength || p.targetLogicalLength != p.sourceLogicalLength ||
        p.targetGeneration != p.sourceGeneration)
      return makeError(StatusCode::kInvalidArg, "repair preserves exact Data content generation and logical extent");
  } else
    return makeError(StatusCode::kInvalidArg, "unknown RMW action");
  if (p.targetLogicalLength > std::numeric_limits<uint64_t>::max() - start)
    return makeError(StatusCode::kInvalidArg, "RMW logical end overflow");
  if (p.sourceKind != EcRmwSourceKind::Zero && p.sourceKind != EcRmwSourceKind::Data)
    return makeError(StatusCode::kInvalidArg, "invalid RMW source kind");
  std::set<Uuid> allocations;
  std::string canonical("3FS-RMW-PLAN-v1", 15);
  canonical.reserve(4096);
  number(canonical, p.version, 2);
  number(canonical, uint8_t(p.action), 1);
  number(canonical, p.inode, 8);
  uuid(canonical, p.object);
  uuid(canonical, p.birth);
  uuid(canonical, p.planId);
  uuid(canonical, p.sessionId);
  uuid(canonical, p.parentId);
  uuid(canonical, p.operationId);
  number(canonical, p.ownerUid.toUnderType(), 4);
  uuid(canonical, p.clientNamespace);
  number(canonical, p.fenceEpoch, 8);
  uuid(canonical, p.sourceRoot);
  number(canonical, p.sourceSequence, 8);
  number(canonical, p.lengthAtPlan, 8);
  number(canonical, p.stripe, 8);
  number(canonical, p.shardBytes, 4);
  number(canonical, static_cast<uint8_t>(p.sourceKind), 1);
  uuid(canonical, p.sourcePin);
  number(canonical, p.sourceRevision, 8);
  number(canonical, p.sourceGeneration, 8);
  number(canonical, p.sourceLogicalLength, 4);
  appendDigest(canonical, p.sourceLogicalSha256);
  if (p.sourceKind == EcRmwSourceKind::Zero) {
    if (!p.sourcePin.is_nil() || p.sourceRevision || p.sourceGeneration || p.sourceLogicalLength ||
        p.sourceLogicalSha256 != EcSha256{})
      return makeError(StatusCode::kInvalidArg, "Zero RMW source contains data authority");
    for (const auto &source : p.sources)
      if (!emptySource(source)) return makeError(StatusCode::kInvalidArg, "Zero RMW source has nonempty source slots");
  } else {
    if (p.sourceRoot.is_nil() || p.sourcePin.is_nil() || !p.sourceRevision || !p.sourceGeneration ||
        !p.sourceLogicalLength || p.sourceLogicalSha256 == EcSha256{} || p.targetRevision <= p.sourceRevision ||
        (p.action == EcRmwAction::Repair ? p.targetGeneration != p.sourceGeneration
                                         : p.targetGeneration <= p.sourceGeneration))
      return makeError(StatusCode::kInvalidArg, "Data RMW source lost its fixed pin/content revision");
    for (size_t i = 0; i < p.sources.size(); ++i) {
      const auto &source = p.sources[i];
      const auto &id = source.identity;
      RETURN_ON_ERROR(validateEcIntegrity(id, source.integrity));
      if (id.object != p.object || id.stripe != p.stripe || id.shard != i || id.generation != p.sourceGeneration ||
          source.operationId.is_nil() || source.operationId == p.operationId || source.writerNamespace.is_nil() ||
          !validEndpoint(source.endpoint) || source.integrity.wholeLength != p.shardBytes ||
          !allocations.insert(id.allocation).second)
        return makeError(StatusCode::kInvalidArg, "RMW source binding differs");
      identity(canonical, id);
      uuid(canonical, source.operationId);
      uuid(canonical, source.writerNamespace);
      endpoint(canonical, source.endpoint);
      CHECK_RESULT(hash, digestEcIntegrityV2(id, source.integrity));
      appendDigest(canonical, hash);
    }
  }
  number(canonical, p.targetRevision, 8);
  number(canonical, p.targetGeneration, 8);
  for (size_t i = 0; i < p.targets.size(); ++i) {
    const auto &target = p.targets[i];
    const auto &id = target.identity;
    RETURN_ON_ERROR(id.validate());
    if (id.object != p.object || id.stripe != p.stripe || id.shard != i || id.generation != p.targetGeneration ||
        !validEndpoint(target.endpoint) || !allocations.insert(id.allocation).second)
      return makeError(StatusCode::kInvalidArg, "RMW output must use twelve fresh exact allocations");
    identity(canonical, id);
    endpoint(canonical, target.endpoint);
  }
  number(canonical, p.workerIndex, 1);
  number(canonical, p.patchOffset, 4);
  number(canonical, p.patchLength, 4);
  appendDigest(canonical, p.patchSha256);
  number(canonical, p.targetLogicalLength, 4);
  CHECK_RESULT(hash, ec_rmw_detail::sha256(canonical));
  auto out = std::shared_ptr<EcRmwPlan>(new EcRmwPlan(std::move(input)));
  out->digest_ = hash;
  return std::shared_ptr<const EcRmwPlan>(std::move(out));
}
Result<uint32_t> EcRmwPlan::patchBlockLength(uint32_t block) const {
  if (block >= patchBlocks()) return makeError(StatusCode::kInvalidArg, "RMW patch block out of range");
  return std::min<uint32_t>(kEcRmwPatchBlockBytes, input_.patchLength - block * kEcRmwPatchBlockBytes);
}
}  // namespace hf3fs::storage
