#include "detail/EcReadDispatcherCore.h"
#include "detail/EcReadSpoolScan.h"

namespace hf3fs::client::ec::detail {
CoTryTask<Void> EcReadDispatcherCore::confirmTerminal(const EcReadSpool::Run &run,
                                                      const flat::UserInfo &user,
                                                      EcStripeControl c) {
  const auto &r = run.journal->record();
  const auto &p = run.journal->latest();
  if (!p || !p->allPinsReleased() || !p->localComplete || p->errorCode || run.journal->poisoned())
    co_return makeError(StatusCode::kTokenStale, "retirement requires an already completed all-pin T2 journal");
  auto check = active(c);
  CO_RETURN_ON_ERROR(check);
  meta::EcRangeSnapshot original;
  check = serde::deserialize(original, p->snapshotBytes);
  CO_RETURN_ON_ERROR(check);
  check = validateFileSnapshot(r, original);
  CO_RETURN_ON_ERROR(check);
  meta::QueryEcRangeV2Req query;
  request(query, user, r.rangeRequest);
  query.rangeId = r.rangeId;
  query.selection = fileSelection(r);
  auto current = co_await meta->queryEcRangeV2(std::move(query));
  CO_RETURN_ON_ERROR(current);
  check = validateFileSnapshot(r, current->snapshot);
  CO_RETURN_ON_ERROR(check);
  check = validateSameFileSnapshot(original, current->snapshot);
  CO_RETURN_ON_ERROR(check);
  if (current->snapshot.stripeCount != p->actualPins) co_return makeError(StatusCode::kDataCorruption);
  for (size_t i = 0; i != current->snapshot.stripeCount; ++i) {
    if (current->snapshot.stripes[i].state != meta::EcRangePinState::Released)
      co_return makeError(StatusCode::kTokenStale, "active/closing pin cannot retire local recovery evidence");
    check = active(c);
    CO_RETURN_ON_ERROR(check);
    const auto &slot = r.slots[i];
    meta::ReleaseEcReadV2Req req;
    request(req, user, slot.releaseRequest);
    req.object = r.object;
    req.stripe = slot.stripe;
    req.pin = slot.pin;
    // Terminal replay only after Query44 reported Released. Meta returns the
    // persisted T2 proof; it cannot issue another pin or substitute new IDs.
    auto released = co_await meta->releaseEcReadV2(std::move(req));
    CO_RETURN_ON_ERROR(released);
    const auto &drain = released->drain;
    if (released->pin != slot.pin || drain.revocation.is_nil() || drain.state != meta::EcV2DrainState::ReadReleased ||
        drain.expectedEndpoints != 12 || drain.terminalEndpoints() != 12)
      co_return makeError(StatusCode::kDataCorruption, "retirement did not observe the complete original T2 tuple");
  }
  check = active(c);
  CO_RETURN_ON_ERROR(check);
  co_return Void{};
}
CoTryTask<EcReadRetirementOutcome> EcReadDispatcherCore::retireOwned(EcReadReceipt receipt,
                                                                     flat::UserInfo user,
                                                                     std::filesystem::path archive,
                                                                     EcStripeControl c) {
  if (spool->poisoned())
    co_return makeError(StatusCode::kIOError, "reopen after uncertain spool persistence before any retirement");
  if (heldOutputs()) co_return makeError(StorageClientCode::kResourceBusy, "output lease still owns this spool/budget");
  auto authenticated = co_await authenticate(std::move(user), c);
  CO_RETURN_ON_ERROR(authenticated);
  if (authenticated->uid.toUnderType() != receipt.ownerUid) co_return makeError(StatusCode::kTokenMismatch);
  auto check = spool->validReceipt(receipt);
  CO_RETURN_ON_ERROR(check);
  auto snapshot = spool->inspect();
  CO_RETURN_ON_ERROR(snapshot);
  const EcReadDebt *debt = nullptr;
  for (const auto &item : snapshot->records)
    if (item.receipt.sequence == receipt.sequence) {
      debt = &item;
      break;
    }
  if (!debt)
    co_return makeError(StatusCode::kKVStoreNotFound, "NoRetainedEvidence: old receipt will not be reacquired");
  if (!sameReadReceipt(debt->receipt, receipt)) co_return makeError(StatusCode::kTokenMismatch);
  Result<storage::EcSha256> digest = makeError(StatusCode::kInvalidArg);
  if (debt->retirementPending) {
    // The durable marker was only published after the original full journal
    // and fresh terminal responses were verified. Recovery is local-only;
    // authentication still applies and archive/path/digest must match exactly.
    digest = spool->finishRetirement(receipt, archive);
  } else {
    auto run = spool->resume(receipt);
    CO_RETURN_ON_ERROR(run);
    activeReceipt = receipt;
    auto confirmed = co_await confirmTerminal(*run, *authenticated, c);
    CO_RETURN_ON_ERROR(confirmed);
    digest = spool->retire(*run, archive);
  }
  CO_RETURN_ON_ERROR(digest);
  EcReadRetirementOutcome out;
  out.receipt = receipt;
  out.archive = std::move(archive);
  out.archiveSha256 = *digest;
  out.localFilesRemoved = true;
  co_return out;
}
}  // namespace hf3fs::client::ec::detail
