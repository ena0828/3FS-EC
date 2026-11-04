#include "fbs/storage/EcAuthorizedV2.h"

#include <algorithm>

namespace hf3fs::storage {
namespace {
Result<VerifiedEcGrantV2> verify(const EcCapabilityKey &key,
                                 const EcFragmentAccessV2 &request,
                                 const EcCapabilityV2 &grant,
                                 const EcLocalTargetV2 &local,
                                 EcGrantRightV2 right,
                                 uint64_t nowSeconds,
                                 uint64_t maxTtlSeconds) {
  RETURN_ON_ERROR(request.identity.validate());
  if (request.version != kEcGrantVersionV2 || request.operationId.is_nil() || local.engineUuid.is_nil() ||
      local.targetIncarnation.is_nil() || local.nodeId == NodeId{} || local.targetId == TargetId{} ||
      local.vChainId.chainId == ChainId{} || local.vChainId.chainVer == ChainVer{}) {
    return makeError(StatusCode::kInvalidArg, "V2 EC request requires an actual local instance and current route");
  }
  if (request.vChainId != local.vChainId || request.targetId != local.targetId) {
    return makeError(StorageClientCode::kRoutingVersionMismatch, "V2 EC request differs from current local placement");
  }
  CHECK_RESULT(digest, digestEcIntegrityV2(request.identity, request.integrity));
  EcGrantBindingV2 expected;
  expected.engineUuid = local.engineUuid;
  expected.targetIncarnation = local.targetIncarnation;
  expected.identity = request.identity;
  expected.fragmentOperationId = request.operationId;
  expected.chainId = local.vChainId.chainId;
  expected.targetId = local.targetId;
  expected.nodeId = local.nodeId;
  expected.expectedLength = request.integrity.wholeLength;
  expected.expectedCrc32c = request.integrity.wholeCrc32c;
  expected.integrityDigest = digest;
  // These are bearer scope claims; verifyEcGrantV2 validates their MAC along
  // with every request-derived value. No userInfo UID is treated as trusted.
  expected.ownerUid = grant.claims.ownerUid;
  expected.clientNamespace = grant.claims.clientNamespace;
  expected.scopeObject = request.identity.object;
  expected.scopeKind = grant.claims.scopeKind;
  expected.scopeId = grant.claims.scopeId;
  return verifyEcGrantV2(key, grant, expected, right, nowSeconds, maxTtlSeconds);
}
}  // namespace

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcReadBlockV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  CHECK_RESULT(verified,
               verify(key, req.request, req.grant, local, EcGrantRightV2::ReadBlock, nowSeconds, maxTtlSeconds));
  if (req.blockIndex >= req.request.integrity.blockCount) {
    return makeError(StatusCode::kInvalidArg, "V2 EC read must select one complete integrity block");
  }
  return verified;
}

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcBeginStageV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  return verify(key, req.request, req.grant, local, EcGrantRightV2::Begin, nowSeconds, maxTtlSeconds);
}

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcAppendStageV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  CHECK_RESULT(verified, verify(key, req.request, req.grant, local, EcGrantRightV2::Append, nowSeconds, maxTtlSeconds));
  RETURN_ON_ERROR(
      verifyEcIntegrityBlock(req.request.identity, req.request.integrity, req.blockIndex, req.payload.data));
  return verified;
}

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcQueryStageV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  return verify(key, req.request, req.grant, local, EcGrantRightV2::Query, nowSeconds, maxTtlSeconds);
}

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcReconcileStageV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  return verify(key, req.request, req.grant, local, EcGrantRightV2::Reconcile, nowSeconds, maxTtlSeconds);
}

Result<VerifiedEcGrantV2> verifyEcRequestV2(const EcCapabilityKey &key,
                                            const EcSealStageV2Req &req,
                                            const EcLocalTargetV2 &local,
                                            uint64_t nowSeconds,
                                            uint64_t maxTtlSeconds) {
  return verify(key, req.request, req.grant, local, EcGrantRightV2::Seal, nowSeconds, maxTtlSeconds);
}

Result<EcStableStageSpecV2> deriveEcStageSpecV2(const VerifiedEcGrantV2 &begin) {
  if (begin.right() != EcGrantRightV2::Begin || begin.claims().scopeKind != EcGrantScope::WriteOperation) {
    return makeError(StatusCode::kInvalidArg, "staging context requires a verified V2 Begin grant");
  }
  const auto &claims = begin.claims();
  const auto word = [](const uint8_t *bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i != 8; ++i) value = (value << 8) | bytes[i];
    return value;
  };
  EcStableStageSpecV2 spec;
  spec.stageId = claims.fragmentOperationId;
  spec.length = claims.expectedLength;
  spec.crc32c = claims.expectedCrc32c;
  spec.chainVersion = 0;
  spec.lastRequestId = word(claims.fragmentOperationId.data);
  spec.lastClientLow = word(claims.clientNamespace.data);
  spec.lastClientHigh = word(claims.clientNamespace.data + 8);
  std::copy(std::begin(claims.fragmentOperationId.data), std::end(claims.fragmentOperationId.data), spec.etag.begin());
  return spec;
}
}  // namespace hf3fs::storage
