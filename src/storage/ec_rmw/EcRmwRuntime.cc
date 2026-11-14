#include "EcRmwRuntime.h"

#include <folly/experimental/coro/BlockingWait.h>

namespace hf3fs::storage {
Result<std::unique_ptr<EcRmwRuntime>> EcRmwRuntime::create(std::shared_ptr<const EcRmwKey> key,
                                                           Uuid authority,
                                                           flat::NodeId node,
                                                           Clock clock) {
  if (!key || authority.is_nil() || node == flat::NodeId{} || !clock) return makeError(StatusCode::kInvalidArg);
  auto runtime = std::unique_ptr<EcRmwRuntime>(new EcRmwRuntime(std::move(key), authority, node, std::move(clock)));
  try {
    runtime->worker_ = std::thread([raw = runtime.get()] { raw->work(); });
  } catch (...) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
  return std::move(runtime);
}
EcRmwRuntime::~EcRmwRuntime() {
  // Never destroy resources behind an unfinished task. The application owns
  // the checked shutdown order; an omitted/failed join is a contract violation.
  if (worker_.joinable()) std::terminate();
}
Result<VerifiedEcRmwPlan> EcRmwRuntime::verify(const Entry &entry, const EcRmwGrant &grant, EcRmwRight right) const {
  if (entry.plan->worker().nodeId != node_) return makeError(StatusCode::kAuthenticationFail);
  return EcRmwAuthorization::verify(*key_, grant, entry.plan, entry.plan->worker(), authority_, right, clock_());
}
Result<bool> EcRmwRuntime::prepareInstall(std::shared_ptr<const EcRmwPlan> plan,
                                          const EcRmwGrant &grant,
                                          TransportPolicy transport) {
  if (!client::isExplicitEcTransportPolicy(transport)) return makeError(StatusCode::kInvalidArg);
  if (!plan || plan->worker().nodeId != node_) return makeError(StatusCode::kAuthenticationFail);
  auto verified =
      EcRmwAuthorization::verify(*key_, grant, plan, plan->worker(), authority_, EcRmwRight::Install, clock_());
  RETURN_ON_ERROR(verified);
  std::lock_guard lock(mutex_);
  if (closing_) return makeError(StorageClientCode::kResourceBusy);
  if (installBinding_ && installBinding_->planId == plan->input().planId &&
      (installBinding_->digest != plan->digest() || installBinding_->transport != transport))
    return makeError(StatusCode::kTokenMismatch);
  if (!entry_) {
    installBinding_ = InstallBinding{plan->input().planId, plan->digest(), transport};
    return true;
  }
  const bool same = entry_->plan->input().planId == plan->input().planId;
  if (same && (entry_->plan->digest() != plan->digest() || entry_->transport != transport))
    return makeError(StatusCode::kTokenMismatch);
  if (entry_->observation.state == EcRmwLocalState::Running || entry_->observation.state == EcRmwLocalState::Queued) {
    if (same) return false;
    return makeError(StorageClientCode::kResourceBusy);
  }
  if (same && entry_->observation.state == EcRmwLocalState::Complete && entry_->observation.error == StatusCode::kOK)
    return false;
  if (!same && entry_->observation.state != EcRmwLocalState::Complete)
    return makeError(StorageClientCode::kResourceBusy);
  installBinding_ = InstallBinding{plan->input().planId, plan->digest(), transport};
  entry_.reset();  // No running job; releases its old ticket and reservation.
  return true;
}
Result<Void> EcRmwRuntime::install(std::shared_ptr<const EcRmwPlan> plan,
                                   const EcRmwGrant &grant,
                                   std::shared_ptr<NativeEcRmwIo> io) {
  if (!plan || !io || io->planDigest() != plan->digest()) return makeError(StatusCode::kTokenMismatch);
  const auto transport = io->transportPolicy();
  return installInternal(std::move(plan), grant, std::move(io), transport);
}
Result<Void> EcRmwRuntime::installInternal(std::shared_ptr<const EcRmwPlan> plan,
                                           const EcRmwGrant &grant,
                                           std::shared_ptr<EcRmwIo> io,
                                           TransportPolicy transport) {
  if (!plan || !io || !client::isExplicitEcTransportPolicy(transport))
    return makeError(StatusCode::kInvalidArg);
  if (plan->worker().nodeId != node_) return makeError(StatusCode::kAuthenticationFail);
  auto verified =
      EcRmwAuthorization::verify(*key_, grant, plan, plan->worker(), authority_, EcRmwRight::Install, clock_());
  RETURN_ON_ERROR(verified);
  RETURN_ON_ERROR(io->check());
  std::lock_guard lock(mutex_);
  if (closing_) return makeError(StorageClientCode::kResourceBusy);
  if (installBinding_ && (installBinding_->planId != plan->input().planId ||
                          installBinding_->digest != plan->digest() || installBinding_->transport != transport))
    return makeError(StatusCode::kTokenMismatch);
  if (entry_ && entry_->plan->input().planId == plan->input().planId) {
    if (entry_->plan->digest() != plan->digest() || entry_->transport != transport)
      return makeError(StatusCode::kTokenMismatch);
    if (entry_->observation.state != EcRmwLocalState::Complete || entry_->observation.error == StatusCode::kOK)
      return Void{};  // Running/successful replay cannot restart; failed same-plan retry may reupload.
  }
  if (entry_ && entry_->observation.state != EcRmwLocalState::Complete)
    return makeError(StorageClientCode::kResourceBusy);
  auto patch = EcRmwPatchBuffer::create(plan);
  RETURN_ON_ERROR(patch);
  auto entry = std::make_unique<Entry>();
  entry->plan = std::move(plan);
  entry->patch = std::move(*patch);
  entry->io = std::move(io);
  entry->installed = grant;
  entry->transport = transport;
  entry->observation.planId = entry->plan->input().planId;
  entry->observation.planDigest = entry->plan->digest();
  installBinding_ = InstallBinding{entry->plan->input().planId, entry->plan->digest(), transport};
  entry_ = std::move(entry);
  wake_.notify_one();
  return Void{};
}
Result<Void> EcRmwRuntime::put(const Uuid &id, const EcRmwGrant &grant, uint32_t block,
                              std::string_view bytes, TransportPolicy transport) {
  if (!client::isExplicitEcTransportPolicy(transport)) return makeError(StatusCode::kInvalidArg);
  std::lock_guard lock(mutex_);
  if (closing_) return makeError(StorageClientCode::kResourceBusy);
  if (!entry_ || entry_->plan->input().planId != id) return makeError(StatusCode::kKVStoreNotFound);
  RETURN_ON_ERROR(verify(*entry_, grant, EcRmwRight::Upload));
  if (entry_->transport != transport) return makeError(StatusCode::kTokenMismatch);
  if (entry_->observation.state != EcRmwLocalState::Receiving) return makeError(StatusCode::kTokenStale);
  RETURN_ON_ERROR(entry_->io->check());
  RETURN_ON_ERROR(entry_->patch->put(block, bytes));
  entry_->observation.received = entry_->patch->received();
  return Void{};
}
Result<EcRmwObservation> EcRmwRuntime::submit(const Uuid &id, const EcRmwGrant &grant, TransportPolicy transport) {
  if (!client::isExplicitEcTransportPolicy(transport)) return makeError(StatusCode::kInvalidArg);
  std::lock_guard lock(mutex_);
  if (closing_) return makeError(StorageClientCode::kResourceBusy);
  if (!entry_ || entry_->plan->input().planId != id) return makeError(StatusCode::kKVStoreNotFound);
  auto verified = verify(*entry_, grant, EcRmwRight::Execute);
  RETURN_ON_ERROR(verified);
  if (entry_->transport != transport) return makeError(StatusCode::kTokenMismatch);
  if (entry_->observation.state != EcRmwLocalState::Receiving) return entry_->observation;
  RETURN_ON_ERROR(entry_->io->check());
  auto patch = entry_->patch->finish();
  RETURN_ON_ERROR(patch);
  entry_->ownedPatch = std::move(*patch);
  entry_->patch.reset();
  entry_->execute.emplace(std::move(*verified));
  entry_->observation.state = EcRmwLocalState::Queued;
  wake_.notify_one();
  return entry_->observation;
}
Result<EcRmwObservation> EcRmwRuntime::query(const Uuid &id, const EcRmwGrant &grant) const {
  std::lock_guard lock(mutex_);
  if (!entry_ || entry_->plan->input().planId != id) return makeError(StatusCode::kKVStoreNotFound);
  RETURN_ON_ERROR(verify(*entry_, grant, EcRmwRight::Observe));
  return entry_->observation;  // No wait, no source bytes, no credentials.
}
void EcRmwRuntime::work() noexcept {
  static_assert(std::is_nothrow_move_assignable_v<decltype(EcRmwObservation::sealed)>);
  for (;;) {
    Entry *job = nullptr;
    bool skip = false;
    {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [&] {
        return closing_ || (entry_ && (entry_->observation.state == EcRmwLocalState::Queued ||
                                       entry_->observation.state == EcRmwLocalState::Receiving));
      });
      if (closing_ && (!entry_ || entry_->observation.state != EcRmwLocalState::Queued)) return;
      if (entry_->observation.state == EcRmwLocalState::Receiving) {
        status_code_t invalid = StatusCode::kOK;
        try {
          auto live = verify(*entry_, entry_->installed, EcRmwRight::Install);
          if (!live)
            invalid = live.error().code();
          else {
            auto checked = entry_->io->check();
            if (!checked) invalid = checked.error().code();
          }
        } catch (...) {
          invalid = StatusCode::kNotEnoughMemory;
        }
        if (invalid != StatusCode::kOK) {
          // No task was dispatched. A revoked/expired idle upload must not
          // retain a ticket forever and prevent actual durable scope drain.
          entry_->patch.reset();
          entry_->io.reset();
          entry_->observation.error = invalid;
          entry_->observation.state = EcRmwLocalState::Complete;
        } else {
          wake_.wait_for(lock, std::chrono::milliseconds(50), [&] {
            return closing_ || !entry_ || entry_->observation.state != EcRmwLocalState::Receiving;
          });
        }
        continue;
      }
      job = entry_.get();
      skip = closing_;
      job->observation.state = EcRmwLocalState::Running;
    }
    status_code_t error = StatusCode::kOK;
    std::optional<EcRmwSealedCandidate> output;
    bool taskConstructed = false;
    try {
      // Task frame construction itself cannot dispatch. After this boundary,
      // any unexpected wait/delivery exception conservatively retains unknown.
      if (skip) {
        error = StorageClientCode::kRequestCanceled;
      } else {
        auto task = EcRmwExecution::run(*job->execute, std::move(job->ownedPatch), job->io);
        taskConstructed = true;
        auto result = folly::coro::blockingWait(std::move(task));
        if (result)
          output.emplace(std::move(*result));
        else
          error = result.error().code();
      }
    } catch (const std::bad_alloc &) {
      error = taskConstructed ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory;
    } catch (...) {
      error = taskConstructed ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError;
    }
    // blockingWait has completed. Release target ticket/session/reservation
    // only now, before publishing a terminal *local* observation. No drain or
    // durable Meta publication is inferred from this terminal state.
    job->io.reset();
    job->execute.reset();
    job->patch.reset();
    std::string{}.swap(job->ownedPatch);
    {
      std::lock_guard lock(mutex_);
      job->observation.error = error;
      job->observation.sealed = std::move(output);
      job->observation.state = EcRmwLocalState::Complete;
    }
  }
}
Result<Void> EcRmwRuntime::stopAndJoin() {
  std::lock_guard serial(stopMutex_);
  if (worker_.get_id() == std::this_thread::get_id()) return makeError(StatusCode::kInvalidArg);
  {
    std::lock_guard lock(mutex_);
    if (joined_) return Void{};
    closing_ = true;
    // No task was dispatched for Receiving. Its volatile upload can be dropped
    // while retaining any already persisted Meta intent for same-ID recovery.
    if (entry_ && entry_->observation.state == EcRmwLocalState::Receiving) entry_.reset();
    wake_.notify_one();
  }
  try {
    if (worker_.joinable()) worker_.join();
  } catch (...) {
    return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  std::lock_guard lock(mutex_);
  joined_ = true;
  return Void{};
}
}  // namespace hf3fs::storage
