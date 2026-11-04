#include "EcStageValidationV2.h"

namespace hf3fs::storage {
Result<Void> validateEcReceiptV2(const EcFragmentReceiptV2 &result,
                                 const EcFragmentAccessV2 &request,
                                 const EcGrantClaimsV2 &claims) {
  if (result.version != kEcGrantVersionV2 || !serde::equals(result.identity, request.identity) ||
      result.operationId != request.operationId || result.vChainId != request.vChainId ||
      result.targetId != request.targetId || result.engineUuid != claims.engineUuid ||
      result.targetIncarnation != claims.targetIncarnation || result.length != request.integrity.wholeLength ||
      result.crc32c != request.integrity.wholeCrc32c || result.integrityRoot != request.integrity.root) {
    return makeError(StorageClientCode::kProtocolMismatch, "V2 response does not identify the requested allocation");
  }
  return Void{};
}
Result<Void> validateEcStageStateV2(const EcStageStateV2 &result,
                                    const EcFragmentAccessV2 &request,
                                    const EcGrantClaimsV2 &claims) {
  RETURN_ON_ERROR(validateEcReceiptV2(result.receipt, request, claims));
  const auto length = request.integrity.wholeLength;
  if (result.state < 1 || result.state > 3 || result.revision == 0 || result.prefixBytes > length ||
      (result.prefixBytes != length && result.prefixBytes % kEcIntegrityBlockBytes != 0) ||
      (result.state == 2 && (result.prefixBytes != length || result.pendingBlock)) ||
      (result.pendingBlock && (result.prefixBytes == length || result.state != 1))) {
    return makeError(StorageClientCode::kProtocolMismatch, "V2 response contains an inconsistent stage state");
  }
  return Void{};
}
Result<Void> validateEcReadBlockV2(const EcReadBlockResultV2 &result, const EcReadBlockV2Req &request) {
  RETURN_ON_ERROR(validateEcReceiptV2(result.receipt, request.request, request.grant.claims));
  if (result.blockIndex != request.blockIndex || result.payload.data.size() > kEcIntegrityBlockBytes) {
    return makeError(StorageClientCode::kProtocolMismatch, "V2 response contains the wrong block");
  }
  return verifyEcIntegrityBlock(request.request.identity,
                                request.request.integrity,
                                result.blockIndex,
                                result.payload.data);
}
}  // namespace hf3fs::storage
