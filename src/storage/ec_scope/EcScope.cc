#include "EcScope.h"

namespace hf3fs::storage {
namespace {
Result<Void> check(const chunk_engine::RawEcScopeStatus &status) {
  if (status.error_code != 0) {
    return makeError(status.error_code, std::string(status.error.data(), status.error.size()));
  }
  if (!status.error.empty()) return makeError(StatusCode::kFoundBug, "scope bridge success contains an error");
  return Void{};
}
Result<EcScopeDrainStatus> drain(const chunk_engine::RawEcDrainResult &result) {
  RETURN_ON_ERROR(check(result.status));
  if (result.drained && (!result.durable || result.inflight != 0)) {
    return makeError(StatusCode::kFoundBug, "scope bridge returned contradictory drain state");
  }
  return EcScopeDrainStatus{result.durable, result.inflight, result.drained};
}
}  // namespace

EcScopeTicket::EcScopeTicket(EcScopeTicket &&other) noexcept
    : handle_(std::move(other.handle_)),
      binding_(other.binding_) {
  other.handle_.reset();
}
EcScopeTicket &EcScopeTicket::operator=(EcScopeTicket &&other) noexcept {
  if (this != &other) {
    handle_ = std::move(other.handle_);
    binding_ = other.binding_;
    other.handle_.reset();
  }
  return *this;
}
Result<Void> EcScopeTicket::checkExecution() const {
  if (!handle_) return makeError(StatusCode::kInvalidArg, "scope ticket was moved or completed");
  return check(chunk_engine::ec_scope_ticket_check(**handle_));
}
Result<std::shared_ptr<EcScope>> EcScope::open(const chunk_engine::Engine &engine) {
  return fromResult(chunk_engine::ec_scope_open(engine));
}
Result<std::shared_ptr<EcScope>> EcScope::fromResult(chunk_engine::RawEcScopeOpenResult result) {
  RETURN_ON_ERROR(check(result.status));
  return std::shared_ptr<EcScope>(new EcScope(std::move(result.handle)));
}
Result<EcScopeTargetIdentity> EcScope::registerTarget(uint32_t chain, uint64_t target) const {
  auto result = chunk_engine::ec_scope_register_target(*handle_, chain, target);
  RETURN_ON_ERROR(check(result.status));
  return result.target;
}
Result<EcScopeTargetIdentity> EcScope::loadTarget(uint32_t chain, uint64_t target) const {
  auto result = chunk_engine::ec_scope_load_target(*handle_, chain, target);
  RETURN_ON_ERROR(check(result.status));
  return result.target;
}
Result<Void> EcScope::prepare(const EcScopeBinding &binding) const {
  return check(chunk_engine::ec_scope_prepare(*handle_, binding));
}
Result<EcScopeTicket> EcScope::tryAdmit(const EcScopeBinding &binding) const {
  auto result = chunk_engine::ec_scope_try_admit(*handle_, binding);
  RETURN_ON_ERROR(check(result.status));
  return EcScopeTicket(std::move(result.ticket), binding);
}
Result<EcScopeDrainStatus> EcScope::revoke(const EcScopeRevocation &request) const {
  return drain(chunk_engine::ec_scope_revoke(*handle_, request));
}
Result<EcScopeDrainStatus> EcScope::drainStatus(const EcScopeRevocation &request) const {
  return drain(chunk_engine::ec_scope_drain_status(*handle_, request));
}
}  // namespace hf3fs::storage
