#include "EcFileClient.h"

#include "detail/EcFileClientCore.h"
namespace hf3fs::client::ec {
using Core = detail::EcFileClientCore;
EcFileClient::EcFileClient(std::shared_ptr<Core> core)
    : core_(std::move(core)) {}
EcFileClient::~EcFileClient() = default;
CoTryTask<std::shared_ptr<EcFileClient>> EcFileClient::connect(std::shared_ptr<meta::client::MetaClient> metadata,
                                                               std::shared_ptr<storage::client::StorageClient> storage,
                                                               std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd,
                                                               flat::UserInfo credentials,
                                                               Uuid expectedNamespace,
                                                               folly::CPUThreadPoolExecutor &executor,
                                                               std::chrono::seconds maximumTime) {
  if (maximumTime <= std::chrono::seconds::zero() || maximumTime > std::chrono::hours(1))
    co_return makeError(StatusCode::kInvalidArg);
  EcStripeClient::Limits limits;
  limits.maxOperations = 1;
  limits.maxApplicationBytes = 64u << 20;
  limits.maxOperationTime = maximumTime;
  auto stripe = co_await EcStripeClient::connect(metadata,
                                                 std::move(storage),
                                                 std::move(mgmtd),
                                                 credentials,
                                                 expectedNamespace,
                                                 executor,
                                                 limits);
  if (!stripe) co_return makeError(std::move(stripe.error()));
  auto budget = EcFilePayloadBudget::create();
  if (!budget) co_return makeError(std::move(budget.error()));
  credentials.uid = (*stripe)->owner().uid;
  try {
    auto core = std::make_shared<Core>(std::move(metadata),
                                       std::move(*stripe),
                                       std::move(*budget),
                                       std::move(credentials),
                                       maximumTime,
                                       executor);
    co_return std::shared_ptr<EcFileClient>(new EcFileClient(std::move(core)));
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  }
}
const meta::EcOwner &EcFileClient::owner() const { return core_->owner; }
Result<EcFilePayload> EcFileClient::allocatePayload(size_t bytes) { return core_->budget->allocate(bytes); }
size_t EcFileClient::payloadBytes() const { return core_->budget->usedBytes(); }
bool EcFileClient::localJoinUnconfirmed() const noexcept { return core_->localJoinUnconfirmed.load(); }
CoTryTask<meta::EcFileState> EcFileClient::describe(meta::EcObjectRef object,
                                                    Uuid id,
                                                    meta::AccessType access,
                                                    EcStripeControl control) {
  return core_->launch<Result<meta::EcFileState>>(
      [core = core_, object, id, access, control] { return core->describeOwned(object, id, access, control); },
      [](Status error) -> Result<meta::EcFileState> { return makeError(std::move(error)); });
}
CoTryTask<EcFileReadOutput> EcFileClient::read(std::shared_ptr<EcFileRunJournal> journal, EcStripeControl control) {
  if (!journal) return Core::immediate(Result<EcFileReadOutput>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<EcFileReadOutput>>(
      [core = core_, journal = std::move(journal), control] { return core->readOwned(journal, control); },
      [](Status error) -> Result<EcFileReadOutput> { return makeError(std::move(error)); });
}
CoTask<EcFileAppendOutcome> EcFileClient::appendAt(std::shared_ptr<EcFileRunJournal> journal,
                                                   EcFilePayload input,
                                                   EcStripeControl control) {
  if (!journal || !core_->budget->owns(input)) {
    EcFileAppendOutcome out;
    out.failure.emplace(StatusCode::kInvalidArg);
    return Core::immediate(std::move(out));
  }
  return core_->launch<EcFileAppendOutcome>(
      [core = core_, journal, input = std::move(input), control]() mutable {
        return core->appendOwned(journal, std::move(input), control);
      },
      [journal](Status error) { return detail::fileAppendOutcome(*journal, std::move(error)); });
}
CoTask<EcFileReleaseOutcome> EcFileClient::releaseRead(std::shared_ptr<EcFileRunJournal> journal,
                                                       EcStripeControl control) {
  if (!journal) {
    EcFileReleaseOutcome out;
    out.failure.emplace(StatusCode::kInvalidArg);
    return Core::immediate(std::move(out));
  }
  return core_->launch<EcFileReleaseOutcome>(
      [core = core_, journal = std::move(journal), control] { return core->releaseOwned(journal, control); },
      [](Status error) {
        EcFileReleaseOutcome out;
        out.failure = std::move(error);
        return out;
      });
}
CoTryTask<EcFileTreeReadOutput> EcFileClient::readTree(std::shared_ptr<EcTreeReadJournal> journal,
                                                       EcStripeControl control) {
  if (!journal) return Core::immediate(Result<EcFileTreeReadOutput>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<EcFileTreeReadOutput>>(
      [core = core_, journal = std::move(journal), control] { return core->readTreeOwned(journal, control); },
      [](Status error) -> Result<EcFileTreeReadOutput> { return makeError(std::move(error)); });
}
CoTryTask<meta::EcTreeReadRecord> EcFileClient::releaseTree(std::shared_ptr<EcTreeReadJournal> journal,
                                                            EcStripeControl control) {
  if (!journal) return Core::immediate(Result<meta::EcTreeReadRecord>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<meta::EcTreeReadRecord>>(
      [core = core_, journal = std::move(journal), control] { return core->releaseTreeOwned(journal, control); },
      [](Status error) -> Result<meta::EcTreeReadRecord> { return makeError(std::move(error)); });
}
CoTryTask<meta::EcFileTruncateProgress> EcFileClient::truncate(std::shared_ptr<EcTruncateJournal> journal,
                                                               EcStripeControl control) {
  if (!journal) return Core::immediate(Result<meta::EcFileTruncateProgress>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<meta::EcFileTruncateProgress>>(
      [core = core_, journal = std::move(journal), control] {
        return core->truncateOwned(journal, control, detail::EcTruncateClientAction::Advance);
      },
      [](Status error) -> Result<meta::EcFileTruncateProgress> { return makeError(std::move(error)); });
}
CoTryTask<meta::EcFileTruncateProgress> EcFileClient::queryTruncate(std::shared_ptr<EcTruncateJournal> journal,
                                                                    EcStripeControl control) {
  if (!journal) return Core::immediate(Result<meta::EcFileTruncateProgress>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<meta::EcFileTruncateProgress>>(
      [core = core_, journal = std::move(journal), control] {
        return core->truncateOwned(journal, control, detail::EcTruncateClientAction::Query);
      },
      [](Status error) -> Result<meta::EcFileTruncateProgress> { return makeError(std::move(error)); });
}
CoTryTask<meta::EcFileTruncateProgress> EcFileClient::closeTruncateDebt(std::shared_ptr<EcTruncateJournal> journal,
                                                                        EcStripeControl control) {
  if (!journal) return Core::immediate(Result<meta::EcFileTruncateProgress>(makeError(StatusCode::kInvalidArg)));
  return core_->launch<Result<meta::EcFileTruncateProgress>>(
      [core = core_, journal = std::move(journal), control] {
        return core->truncateOwned(journal, control, detail::EcTruncateClientAction::CloseDebt);
      },
      [](Status error) -> Result<meta::EcFileTruncateProgress> { return makeError(std::move(error)); });
}
CoTask<void> EcFileClient::close() {
  {
    std::lock_guard lock(core_->mutex);
    core_->closing = true;
    if (!core_->closeComplete) {
      core_->unconfirmedJoinLease = core_;
      core_->localJoinUnconfirmed.store(true);
    }
  }
  core_->stop.requestCancellation();
  return Core::close(core_);
}
}  // namespace hf3fs::client::ec
