#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
Result<Void> StorageTarget::initializeEcScope(EcScopeOpenMode mode) {
  std::lock_guard lock(ecScopeMutex_);
  if ((!engine_ && !staging_) || !initialized_ || !useChunkEngine() || !ecOnly()) {
    return makeError(StorageCode::kTargetStateInvalid, "scope startup requires an initialized immutable target");
  }
  if (ecScope_) return Void{};
  CHECK_RESULT(scope, staging_ ? staging_->scope() : EcScope::open(*engine_));
  auto identity = mode == EcScopeOpenMode::RegisterNew ? scope->registerTarget(chainId(), targetId())
                                                       : scope->loadTarget(chainId(), targetId());
  if (!identity) return makeError(identity.error());
  ecScopeIdentity_ = *identity;
  ecScope_ = std::move(scope);
  return Void{};
}
Result<Void> StorageTarget::checkEcScopeTarget(const EcScopeTargetIdentity &identity) const {
  std::lock_guard lock(ecScopeMutex_);
  if (!ecScope_ || !ecOnly() || identity != ecScopeIdentity_ || identity.chain != chainId() ||
      identity.target != targetId()) {
    return makeError(StatusCode::kTokenMismatch, "EC scope does not identify the initialized target instance");
  }
  return Void{};
}
Result<std::pair<std::shared_ptr<EcScope>, EcScopeTargetIdentity>> StorageTarget::ecScopeState() const {
  std::lock_guard lock(ecScopeMutex_);
  if (!ecScope_) return makeError(StorageClientCode::kNotInitialized, "target scope was not initialized");
  return std::make_pair(ecScope_, ecScopeIdentity_);
}
}  // namespace hf3fs::storage
