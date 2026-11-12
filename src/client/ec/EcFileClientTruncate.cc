#include "detail/EcFileClientCore.h"

namespace hf3fs::client::ec::detail {
namespace {
Result<Void> beginTruncateAttempt(EcTruncateJournal &j) {
  auto s = j.latest().value_or(EcTruncateJournalState{});
  if (j.latest()) {
    if (s.attempt == UINT64_MAX) return makeError(StatusCode::kInvalidArg);
    ++s.attempt;
  }
  s.localComplete = false;
  s.errorCode = 0;
  return j.append(std::move(s));
}
Result<Void> finish(EcTruncateJournal &j, const std::optional<Status> &error) {
  auto s = j.latest().value_or(EcTruncateJournalState{});
  s.localComplete = true;
  s.errorCode = error ? error->code() : 0;
  return j.append(std::move(s));
}
Result<meta::EcFileTruncateProgress> remember(EcTruncateJournal &j, meta::EcFileTruncateRsp rsp, const Uuid &request) {
  if (rsp.requestId != request) return makeError(StatusCode::kTokenMismatch, "truncate response request differs");
  RETURN_ON_ERROR(validateEcTruncateProgress(j.record(), rsp.progress));
  auto state = j.latest().value_or(EcTruncateJournalState{});
  if (state.progress) RETURN_ON_ERROR(compareEcTruncateProgress(*state.progress, rsp.progress));
  state.progress = rsp.progress;
  RETURN_ON_ERROR(j.append(std::move(state)));
  return std::move(rsp.progress);
}
}  // namespace
CoTryTask<meta::EcFileTruncateProgress> EcFileClientCore::truncateOwned(std::shared_ptr<EcTruncateJournal> j,
                                                                        EcStripeControl control,
                                                                        EcTruncateClientAction action) {
  CO_RETURN_ON_ERROR(j->record().validate());
  CO_RETURN_ON_ERROR(active(control));
  if (j->poisoned()) co_return makeError(StatusCode::kIOError, "truncate journal requires explicit resume");
  if (serde::serialize(j->record().intent.owner) != serde::serialize(owner))
    co_return makeError(MetaCode::kNoPermission);
  CO_RETURN_ON_ERROR(beginTruncateAttempt(*j));
  const auto &run = j->record();
  auto operation = [&]() -> CoTryTask<meta::EcFileTruncateProgress> {
    // Always query before another mutation, including the first call. Missing
    // may retry only the exact original Begin CAS; no new expected root/IDs.
    meta::QueryEcFileTruncateReq query;
    request(query, run.queryRequest);
    query.intent = run.intent;
    auto queried = co_await meta->queryEcFileTruncate(std::move(query));
    CO_RETURN_ON_ERROR(queried);
    auto progress = remember(*j, std::move(*queried), run.queryRequest);
    CO_RETURN_ON_ERROR(progress);
    if (action == EcTruncateClientAction::Query) co_return progress;
    if (!progress->observed) {
      if (action == EcTruncateClientAction::CloseDebt)
        co_return makeError(MetaCode::kNotFound, "missing is not released debt");
      CO_RETURN_ON_ERROR(active(control));
      auto state = *j->latest();
      state.beginIssued = true;
      CO_RETURN_ON_ERROR(j->append(std::move(state)));
      meta::BeginEcFileTruncateReq begin;
      request(begin, run.beginRequest);
      begin.intent = run.intent;
      auto begun = co_await meta->beginEcFileTruncate(std::move(begin));
      CO_RETURN_ON_ERROR(begun);
      progress = remember(*j, std::move(*begun), run.beginRequest);
      CO_RETURN_ON_ERROR(progress);
      if (!progress->observed) co_return makeError(StatusCode::kDataCorruption, "Begin omitted accepted truncate");
    }
    if (action == EcTruncateClientAction::CloseDebt) {
      if (progress->observed->state != meta::EcFileTruncateState::Planned && progress->observed->outputDrained &&
          progress->observed->sourceReleased)
        co_return progress;
      CO_RETURN_ON_ERROR(active(control));
      auto state = *j->latest();
      state.closeIssued = true;
      CO_RETURN_ON_ERROR(j->append(std::move(state)));
      meta::CloseEcFileTruncateDebtReq close;
      request(close, run.closeRequest);
      close.intent = run.intent;
      close.outputRevocation = run.outputRevocation;
      close.sourceRevocation = run.sourceRevocation;
      auto closed = co_await meta->closeEcFileTruncateDebt(std::move(close));
      CO_RETURN_ON_ERROR(closed);
      progress = remember(*j, std::move(*closed), run.closeRequest);
      CO_RETURN_ON_ERROR(progress);
      if (!progress->observed || progress->observed->state == meta::EcFileTruncateState::Planned ||
          !progress->observed->outputDrained || !progress->observed->sourceReleased)
        co_return makeError(StatusCode::kTokenStale, "truncate debt is not fully closed");
      co_return progress;
    }
    if (progress->observed->state == meta::EcFileTruncateState::Published) co_return progress;
    if (progress->observed->state == meta::EcFileTruncateState::Aborted)
      co_return makeError(StatusCode::kTokenStale, "truncate was fenced");
    CO_RETURN_ON_ERROR(active(control));
    auto state = *j->latest();
    state.advanceIssued = true;
    CO_RETURN_ON_ERROR(j->append(std::move(state)));
    meta::AdvanceEcFileTruncateReq next;
    request(next, run.advanceRequest);
    next.intent = run.intent;
    auto advanced = co_await meta->advanceEcFileTruncate(std::move(next));
    CO_RETURN_ON_ERROR(advanced);
    // Planned means one bounded worker step is pending. A caller may invoke
    // truncate again with this same journal; no implicit unbounded poll loop.
    co_return remember(*j, std::move(*advanced), run.advanceRequest);
  };
  auto result = co_await operation();
  std::optional<Status> error;
  if (!result) error = result.error();
  auto saved = finish(*j, error);
  if (!saved && result) co_return makeError(std::move(saved.error()));
  co_return result;
}
}  // namespace hf3fs::client::ec::detail
