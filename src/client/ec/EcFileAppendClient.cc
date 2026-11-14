#include "EcFileAppendClient.h"

#include <folly/experimental/coro/BlockingWait.h>

#include "detail/EcFileValidation.h"

namespace hf3fs::client::ec {
namespace {
using folly::coro::blockingWait;
bool same(const auto &a, const auto &b) { return serde::serialize(a) == serde::serialize(b); }
}  // namespace
Result<std::unique_ptr<EcFileAppendClient>> EcFileAppendClient::connect(std::shared_ptr<meta::client::MetaClient> meta,
                                                                        EcFilePwriteClient &writer,
                                                                        flat::UserInfo user,
                                                                        Uuid expected) {
  if (!meta || expected.is_nil() || meta->clientId().uuid != expected || writer.owner().client != expected)
    return makeError(StatusCode::kInvalidArg);
  try {
    auto authenticated = blockingWait(meta->authenticate(user));
    if (!authenticated) return makeError(std::move(authenticated.error()));
    auto token = std::move(user.token);
    user = std::move(*authenticated);
    user.token = std::move(token);
    if (user.uid != writer.owner().uid) return makeError(MetaCode::kNoPermission);
    return std::unique_ptr<EcFileAppendClient>(new EcFileAppendClient(std::move(meta), writer, std::move(user)));
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}
Result<Void> EcFileAppendClient::check(const EcAppendJournal &j, EcStripeControl c) const {
  RETURN_ON_ERROR(validateEcStorageTransport(c.transport));
  RETURN_ON_ERROR(j.record().validate());
  if (j.poisoned() || !same(j.record().session.intent.owner, writer_.owner()))
    return makeError(StatusCode::kTokenMismatch);
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  const auto now = std::chrono::steady_clock::now();
  if (c.deadline <= now) return makeError(StorageClientCode::kTimeout);
  if (c.deadline - now > std::chrono::hours(1)) return makeError(StatusCode::kInvalidArg);
  return Void{};
}
void EcFileAppendClient::request(meta::ReqBase &r, Uuid id) const {
  r.user = user_;
  r.client = ClientId(writer_.owner().client);
  r.uuid = id;
}
Result<EcAppendOutcome> EcFileAppendClient::execute(EcAppendJournal &j,
                                                    EcFilePayload *input,
                                                    EcStripeControl c,
                                                    bool seal) {
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) return makeError(StorageClientCode::kResourceBusy);
  bool invoked = false;
  try {
    RETURN_ON_ERROR(check(j, c));
    const auto &r = j.record();
    if (r.kind != EcAppendRunKind::Append) return makeError(StatusCode::kInvalidArg);
    if (input) {
      CHECK_RESULT(hash, detail::fileContentSha(input->bytes()));
      if (input->size() != r.appendIntent.length || hash != r.appendIntent.inputSha256)
        return makeError(StatusCode::kTokenMismatch);
    }
    meta::QueryEcFileAppendReq query;
    request(query, r.queryRequest);
    query.intent = r.appendIntent;
    auto observed = blockingWait(meta_->queryEcFileAppend(std::move(query)));
    if (!observed) return makeError(std::move(observed.error()));
    if (observed->requestId != r.queryRequest) return makeError(StatusCode::kTokenMismatch);
    auto state = j.latest().value_or(EcAppendJournalState{});
    if (!observed->record) {
      if (state.accepted) return makeError(StatusCode::kDataCorruption, "permanent append acceptance disappeared");
      if (!input || seal) return makeError(StatusCode::kKVStoreNotFound, "not accepted; no successful bytes observed");
      state.issued = true;
      RETURN_ON_ERROR(j.append(state));
      RETURN_ON_ERROR(check(j, c));
      meta::BeginEcFileAppendReq req;
      request(req, r.appendIntent.request);
      req.intent = r.appendIntent;
      invoked = true;
      observed = blockingWait(meta_->beginEcFileAppend(std::move(req)));
      if (!observed) return makeError(std::move(observed.error()));
      if (observed->requestId != r.appendIntent.request || !observed->record)
        return makeError(StatusCode::kTokenMismatch);
    }
    state.issued = true;
    state.accepted = *observed->record;
    RETURN_ON_ERROR(j.append(state));
    const auto &parent = state.accepted->parent;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(r.childDirectory, error);
    if (error && error != std::errc::no_such_file_or_directory) return makeError(StatusCode::kIOError);
    std::unique_ptr<EcFilePwriteJournal> child;
    if (status.type() == std::filesystem::file_type::not_found) {
      if (parent.confirmedPrefix || !parent.activeChild.is_nil() || !parent.fencedChild.is_nil())
        return makeError(StatusCode::kDataCorruption, "accepted append progressed but fixed child journal is missing");
      if (!input || seal) {
        // Before any child was planned, a fixed parent can be logically closed
        // without inventing child credentials or a fictitious cleanup ACK.
        if (seal && parent.confirmedPrefix == 0 && parent.activeChild.is_nil()) {
          meta::AdvanceEcFilePwriteReq req;
          request(req, r.sealRequest);
          req.object = r.appendIntent.object;
          req.operation = r.appendIntent.operation;
          req.session = r.appendIntent.session;
          req.action = meta::EcFileAdvanceAction::SealPrefix;
          invoked = true;
          auto closed = blockingWait(meta_->advanceEcFilePwrite(std::move(req)));
          if (!closed) return makeError(std::move(closed.error()));
          if (!closed->progress.parent) return makeError(StatusCode::kDataCorruption);
          state.accepted->parent = *closed->progress.parent;
          if (auto saved = j.append(state); !saved)
            return makeError(TransactionCode::kMaybeCommitted,
                             "logical prefix close observed but local persistence failed");
        }
        EcAppendOutcome out;
        out.accepted = *state.accepted;
        out.acceptedOffset = parent.intent.offset;
        out.write.observed = true;
        out.write.confirmedPrefix = state.accepted->parent.confirmedPrefix;
        out.write.revalidatedPrefix = out.write.confirmedPrefix;
        out.write.logicalClosed = state.accepted->parent.state == meta::EcFileMutationState::ClosedLogical;
        out.write.logicalComplete = out.write.logicalClosed && out.write.confirmedPrefix == r.appendIntent.length;
        out.write.allCleanupComplete =
            out.write.logicalClosed && out.write.confirmedPrefix == 0 && state.accepted->parent.fencedChild.is_nil();
        if (!out.write.allCleanupComplete && seal)
          out.write.failure = Status(StatusCode::kDataCorruption, "missing child recovery journal");
        return out;
      }
      CHECK_RESULT(
          run,
          prepareEcPwriteFromAcceptedParent(r.session, r.shardBytes, r.cluster, parent, r.inputPath, input->bytes()));
      CHECK_RESULT(created, EcFilePwriteJournal::create(r.childDirectory, std::move(run)));
      child = std::move(created);
    } else {
      CHECK_RESULT(resumed, EcFilePwriteJournal::resume(r.childDirectory));
      child = std::move(resumed);
    }
    const auto &fixed = child->record();
    if (fixed.kind != EcPwriteRunKind::AcceptedAppend || fixed.object != r.appendIntent.object ||
        fixed.operation != r.appendIntent.operation || fixed.session != r.appendIntent.session ||
        !same(fixed.owner, r.appendIntent.owner) || fixed.birth != r.session.intent.birth ||
        fixed.cluster != r.cluster || fixed.shardBytes != r.shardBytes || fixed.offset != parent.intent.offset ||
        fixed.length != r.appendIntent.length || fixed.inputSha256 != r.appendIntent.inputSha256 ||
        fixed.inputPath != r.inputPath)
      return makeError(StatusCode::kTokenMismatch, "append child journal does not match fixed Meta acceptance");
    RETURN_ON_ERROR(check(j, c));
    EcAppendOutcome out;
    out.accepted = *state.accepted;
    out.acceptedOffset = parent.intent.offset;
    invoked = invoked || input || seal;
    out.write = seal    ? writer_.sealAndCleanup(*child, c)
                : input ? writer_.pwrite(*child, std::move(*input), c)
                        : writer_.query(*child, c);
    if (child->latest() && child->latest()->parent) {
      state.accepted->parent = *child->latest()->parent;
      if (auto saved = j.append(state); !saved)
        return makeError(TransactionCode::kMaybeCommitted, "append progress observed but local persistence failed");
      out.accepted = *state.accepted;
    }
    return out;
  } catch (const std::bad_alloc &) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
Result<EcAppendOutcome> EcFileAppendClient::append(EcAppendJournal &j, EcFilePayload input, EcStripeControl c) {
  return execute(j, &input, c, false);
}
Result<EcAppendOutcome> EcFileAppendClient::query(EcAppendJournal &j, EcStripeControl c) {
  return execute(j, nullptr, c, false);
}
Result<EcAppendOutcome> EcFileAppendClient::sealAndCleanup(EcAppendJournal &j, EcStripeControl c) {
  return execute(j, nullptr, c, true);
}
Result<meta::EcFileSyncRecord> EcFileAppendClient::fsync(EcAppendJournal &j, EcStripeControl c) {
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) return makeError(StorageClientCode::kResourceBusy);
  bool invoked = false;
  try {
    RETURN_ON_ERROR(check(j, c));
    const auto &r = j.record();
    if (r.kind != EcAppendRunKind::Sync) return makeError(StatusCode::kInvalidArg);
    auto state = j.latest().value_or(EcAppendJournalState{});
    state.issued = true;
    RETURN_ON_ERROR(j.append(state));
    meta::SyncEcFileSessionReq req;
    request(req, r.syncIntent.request);
    req.intent = r.syncIntent;
    invoked = true;
    auto result = blockingWait(meta_->syncEcFileSession(std::move(req)));
    if (!result) return makeError(std::move(result.error()));
    if (result->requestId != r.syncIntent.request) return makeError(StatusCode::kTokenMismatch);
    state.synced = result->record;
    if (auto saved = j.append(state); !saved)
      return makeError(TransactionCode::kMaybeCommitted, "durability barrier observed but local persistence failed");
    return result->record;
  } catch (const std::bad_alloc &) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
}  // namespace hf3fs::client::ec
