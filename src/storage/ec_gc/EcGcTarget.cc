#include <algorithm>

#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
Result<EcGcLocalTarget> StorageTarget::gcLocalTarget(NodeId actualLocalNode) const {
  if (released_ || !usesEcStagingEngine() || actualLocalNode == NodeId{}) {
    return makeError(StorageCode::kTargetStateInvalid, "GC requires a loaded isolated staging target");
  }
  CHECK_RESULT(state, ecScopeState());
  RETURN_ON_ERROR(checkEcScopeTarget(state.second));
  CHECK_RESULT(format, staging_->actualDiskFormat());
  if (format != 3) return makeError(StorageCode::kTargetStateInvalid, "GC requires actual engine disk format 3");
  EcGcLocalTarget local;
  local.endpoint.nodeId = actualLocalNode;
  local.endpoint.chainId = chainId();
  local.endpoint.targetId = targetId();
  std::copy(state.second.engine.begin(), state.second.engine.end(), std::begin(local.endpoint.engineUuid.data));
  std::copy(state.second.incarnation.begin(),
            state.second.incarnation.end(),
            std::begin(local.endpoint.targetIncarnation.data));
  local.dataProtocol = 2;
  local.diskFormat = format;
  local.gcProtocol = kEcGcSupportedProtocol;
  // This private adapter is reached only through the configured executor.
  // It does not publish a Discovery capability or a deployment mode flag.
  local.enabled = true;
  return local;
}

Result<EcGcLedgerReceipt> StorageTarget::executeGc(const VerifiedEcGcRequest &verified, NodeId node) const {
  CHECK_RESULT(actual, gcLocalTarget(node));
  const auto &expected = verified.certificate().endpoint;
  const auto &observed = actual.endpoint;
  if (observed.nodeId != expected.nodeId || observed.chainId != expected.chainId ||
      observed.targetId != expected.targetId || observed.engineUuid != expected.engineUuid ||
      observed.targetIncarnation != expected.targetIncarnation) {
    return makeError(StorageCode::kTargetStateInvalid, "GC verified target changed before dispatch");
  }
  EcScopeTargetIdentity identity{};
  std::copy(std::begin(expected.engineUuid.data), std::end(expected.engineUuid.data), identity.engine.begin());
  std::copy(std::begin(expected.targetIncarnation.data),
            std::end(expected.targetIncarnation.data),
            identity.incarnation.begin());
  identity.chain = expected.chainId.toUnderType();
  identity.target = expected.targetId.toUnderType();
  RETURN_ON_ERROR(checkEcScopeTarget(identity));
  return staging_->executeGc(verified, chainId());
}
Result<EcGcAbsentLedgerReceipt> StorageTarget::executeGcAbsent(const VerifiedEcGcAbsentRequest &verified, NodeId node) const {
  CHECK_RESULT(actual, gcLocalTarget(node));
  const auto &expected = verified.certificate().endpoint;
  const auto &observed = actual.endpoint;
  if (observed.nodeId != expected.nodeId || observed.chainId != expected.chainId ||
      observed.targetId != expected.targetId || observed.engineUuid != expected.engineUuid ||
      observed.targetIncarnation != expected.targetIncarnation) {
    return makeError(StorageCode::kTargetStateInvalid, "GC verified target changed before dispatch");
  }
  EcScopeTargetIdentity identity{};
  std::copy(std::begin(expected.engineUuid.data), std::end(expected.engineUuid.data), identity.engine.begin());
  std::copy(std::begin(expected.targetIncarnation.data),
            std::end(expected.targetIncarnation.data),
            identity.incarnation.begin());
  identity.chain = expected.chainId.toUnderType();
  identity.target = expected.targetId.toUnderType();
  RETURN_ON_ERROR(checkEcScopeTarget(identity));
  return staging_->executeGcAbsent(verified, chainId());
}
}  // namespace hf3fs::storage
