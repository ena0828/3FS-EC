#include "meta/store/EcTerminalEvidence.h"

#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
CoTryTask<Void> verifyEcStoredRetirementReferences(kv::IReadWriteTransaction &txn,
                                                  const EcV2DrainRecord &record) {
  CO_RETURN_ON_ERROR(ec_v2_lifecycle::drainValid(record));
  for (size_t i = 0; i < record.identity.endpoints.count; ++i) {
    if (!record.retirements[i]) continue;
    CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::verifyStoredReference(txn,
        record.identity.endpoints.endpoints[i], record.identity.clusterAuthority, *record.retirements[i]));
  }
  co_return Void{};
}
CoTryTask<Void> verifyEcRetirementReferences(kv::IReadWriteTransaction &txn,
                                            const EcV2DrainRecord &record,
                                            const storage::EcScopeControlKey &key) {
  CO_RETURN_ON_ERROR(ec_v2_lifecycle::drainValid(record));
  for (size_t i = 0; i < record.identity.endpoints.count; ++i) {
    if (!record.retirements[i]) continue;
    CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::verifyReference(txn,
        record.identity.endpoints.endpoints[i], record.identity.clusterAuthority, *record.retirements[i], key));
  }
  co_return Void{};
}
CoTryTask<Void> verifyEcTerminalEvidence(kv::IReadWriteTransaction &txn,
                                       const EcV2DrainRecord &record,
                                       const storage::EcScopeControlKey &key,
                                       EcTerminalPurpose purpose) {
  CO_RETURN_ON_ERROR(ec_v2_lifecycle::drainValid(record));
  if (purpose == EcTerminalPurpose::Publication &&
      (record.version != kEcV2LifecycleVersion || record.terminalUse != EcV2DrainUse::AckOnly ||
       record.identity.kind != storage::EcGrantScope::WriteOperation))
    co_return makeError(StatusCode::kTokenStale, "retirement evidence cannot authorize publication");
  if ((purpose == EcTerminalPurpose::ReadRelease && record.identity.kind != storage::EcGrantScope::ReadPin) ||
      (purpose == EcTerminalPurpose::FencedAbort && record.identity.kind != storage::EcGrantScope::WriteOperation))
    co_return makeError(StatusCode::kDataCorruption, "terminal evidence purpose differs from scope");
  for (size_t i = 0; i < record.identity.endpoints.count; ++i) {
    if (record.observations[i]) {
      const auto &ack = *record.observations[i];
      CO_RETURN_ON_ERROR(EcVerifiedDrainAck::verify(key, record, i, ack.request, ack.ack));
    } else if (record.retirements[i]) {
      CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::verifyReference(txn,
          record.identity.endpoints.endpoints[i], record.identity.clusterAuthority, *record.retirements[i], key));
    } else {
      co_return makeError(StatusCode::kTokenStale, "not every fixed endpoint has terminal evidence");
    }
  }
  co_return Void{};
}
CoTryTask<bool> attachEcCompletedRetirement(kv::IReadWriteTransaction &txn,
                                          EcV2DrainRecord &record,
                                          size_t index,
                                          EcV2DrainUse use,
                                          const storage::EcScopeControlKey &key) {
  CO_RETURN_ON_ERROR(ec_v2_lifecycle::drainValid(record));
  if (index >= record.identity.endpoints.count || use == EcV2DrainUse::AckOnly ||
      (record.identity.kind == storage::EcGrantScope::ReadPin ? use != EcV2DrainUse::ReadRelease
                                                            : use != EcV2DrainUse::AbortOnly))
    co_return makeError(StatusCode::kInvalidArg, "invalid retirement terminal purpose or index");
  if (record.retirements[index]) {
    CO_RETURN_ON_ERROR(co_await EcTargetRetirementCatalog::verifyReference(txn,
        record.identity.endpoints.endpoints[index], record.identity.clusterAuthority, *record.retirements[index], key));
    co_return true;
  }
  if (record.observations[index]) co_return true;
  if (record.state != EcV2DrainState::Closing)
    co_return makeError(StatusCode::kTokenStale, "terminal record cannot acquire new evidence");
  auto completed = co_await EcTargetRetirementCatalog::findCompleted(txn,
      record.identity.endpoints.endpoints[index], record.identity.clusterAuthority, key);
  CO_RETURN_ON_ERROR(completed);
  if (!*completed) co_return false;
  record.version = kEcV2RetirementDrainVersion;
  record.terminalUse = use;
  record.retirements[index] = **completed;
  CO_RETURN_ON_ERROR(ec_v2_lifecycle::drainValid(record));
  co_return true;
}
}  // namespace hf3fs::meta::server
