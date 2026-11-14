#include "EcFileMount.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/logging/xlog.h>

#include "EcFuseRead.h"
#include "client/ec/EcFileRunFactory.h"

namespace hf3fs::fuse {
using namespace client::ec;
using folly::coro::blockingWait;
namespace {
template <class T>
std::string encode(const T &v) {
  auto b = serde::serialize(v);
  return std::string(b.data(), b.size());
}
template <class T>
Result<T> decode(std::string_view bytes) {
  T v;
  RETURN_ON_ERROR(serde::deserialize(v, bytes));
  if (encode(v) != bytes) return makeError(StatusCode::kInvalidFormat);
  return v;
}
Result<Void> active(EcStripeControl c) {
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
uint8_t rights(int flags) {
  return (flags & O_ACCMODE) == O_RDONLY   ? meta::kEcSessionRead
         : (flags & O_ACCMODE) == O_WRONLY ? meta::kEcSessionWrite
                                           : meta::kEcSessionRead | meta::kEcSessionWrite;
}
Result<Void> owner(const EcMountOpenRecord &r, Uuid ns) {
  if (r.version != 1 || !r.request.user.token.empty() || r.request.client.uuid != ns)
    return makeError(StatusCode::kInvalidFormat);
  RETURN_ON_ERROR(validateEcMountOpenFlags(r.flags, r.request.createNew));
  if (r.request.rights != rights(r.flags)) return makeError(StatusCode::kTokenMismatch);
  return r.request.valid();
}
// Local evidence is an audit observation, not a bearer or a substitute for
// server revalidation. Original journals and payloads remain in place forever.
struct TerminalEvidence {
  SERDE_STRUCT_FIELD(version, uint16_t{2});
  SERDE_STRUCT_FIELD(kind, std::string{});
  SERDE_STRUCT_FIELD(original, std::string{});
  SERDE_STRUCT_FIELD(observation, std::string{});
};
template <class R, class O>
std::string evidence(std::string kind, const R &original, const O &observed) {
  TerminalEvidence value;
  value.kind = std::move(kind);
  value.original = encode(original);
  value.observation = encode(observed);
  return encode(value);
}
struct WriteTerminal {
  SERDE_STRUCT_FIELD(parent, meta::EcFileMutationRecord{});
  SERDE_STRUCT_FIELD(cleanedMask, uint64_t{});
};
struct SessionTerminal {
  SERDE_STRUCT_FIELD(accepted, EcPwriteRunRecord{});
  SERDE_STRUCT_FIELD(closed, meta::EcFileSessionRecord{});
};
Result<std::string> writeEvidence(const EcFilePwriteJournal &j, const EcPwriteOutcome &outcome) {
  if (!outcome.observed || !outcome.logicalClosed || !outcome.allCleanupComplete ||
      outcome.confirmedPrefix != outcome.revalidatedPrefix || !j.latest() || !j.latest()->parent ||
      j.latest()->parent->state != meta::EcFileMutationState::ClosedLogical)
    return makeError(StorageClientCode::kResourceBusy);
  WriteTerminal terminal;
  terminal.parent = *j.latest()->parent;
  terminal.cleanedMask = j.latest()->cleanedMask;
  return evidence("write", j.record(), terminal);
}

}  // namespace
EcStripeControl EcFileMount::control() const {
  return {shutdownDeadline_.value_or(std::chrono::steady_clock::now() + time_), {}, transport_};
}
EcFileMount::~EcFileMount() {
  if (!stopped_) std::terminate();
}
Result<std::shared_ptr<EcFileMount>> EcFileMount::start(std::shared_ptr<EcFileMountState> s,
                                                        Dependencies d,
                                                        flat::Token token,
                                                        std::chrono::seconds time,
                                                        storage::client::EcRequestControl::TransportPolicy transport) {
  if (!s || !d.meta || !d.storage || !d.mgmtd || !d.rmw || d.meta->clientId().uuid != s->clientNamespace() ||
      time < std::chrono::seconds(1) || time > std::chrono::hours(1) ||
      !storage::client::isExplicitEcTransportPolicy(transport))
    return makeError(StatusCode::kInvalidArg);
  auto self = std::shared_ptr<EcFileMount>(new EcFileMount(std::move(s), std::move(d), time, transport));
  self->token_ = std::move(token);
  self->thread_ = std::thread([self] { self->loop(); });
  self->stopped_ = false;
  return self;
}
Result<std::shared_ptr<EcFileMount::Admission>> EcFileMount::admit() {
  if (closing_ || state_->poisoned()) return makeError(StorageClientCode::kResourceBusy);
  bool expected = false;
  if (!active_.compare_exchange_strong(expected, true)) return makeError(StorageClientCode::kResourceBusy);
  try {
    return std::make_shared<Admission>(shared_from_this());
  } catch (...) {
    active_ = false;
    throw;
  }
}
void EcFileMount::loop() noexcept {
  for (;;) {
    std::shared_ptr<JobBase> job;
    {
      std::unique_lock l(mutex_);
      changed_.wait(l, [&] { return closing_ || queued_; });
      if (!queued_) break;
      job = std::move(queued_);
    }
    job->run();
  }
  // All accepted jobs have actually returned. Try original remote cleanup on
  // the same ordinary worker, without equating a timeout to released scopes.
  shutdownDeadline_ = std::chrono::steady_clock::now() + time_;
  try {
    if (!reapCompleted()) remoteDebt_ = true;
  } catch (...) {
    remoteDebt_ = true;
  }
  for (auto &entry : sessions_) {
    auto &s = entry.second;
    if (!active(control())) {
      remoteDebt_ = true;
      break;
    }
    if (s.archived) continue;
    if (s.pendingRead && !s.pendingRead->output.expired()) {
      remoteDebt_ = true;
      continue;
    }
    if (retainedReader_) {
      remoteDebt_ = true;
      break;
    }
    try {
      auto user = s.original.request.user;
      user.token = token_;
      if (!s.accepted) {
        auto observed = reopen(s, user);
        if (!observed) {
          remoteDebt_ = true;
          continue;
        }
      }
      if (!closeSession(s, user)) remoteDebt_ = true;
    } catch (...) {
      remoteDebt_ = true;
    }
  }
  pruneArchived();
}
Result<std::unique_ptr<EcFilePwriteClient>> EcFileMount::writer(const flat::UserInfo &u) {
  return EcFilePwriteClient::connect(deps_.meta, deps_.rmw, deps_.mgmtd, u, state_->clientNamespace());
}
Result<std::shared_ptr<EcFileClient>> EcFileMount::reader(const flat::UserInfo &u) {
  if (retainedReader_) return makeError(StorageClientCode::kResourceBusy);
  auto c = blockingWait(
      EcFileClient::connect(deps_.meta, deps_.storage, deps_.mgmtd, u, state_->clientNamespace(), *executor_, time_));
  if (!c) return makeError(std::move(c.error()));
  retainedReader_ = *c;
  return *c;
}
Result<Void> EcFileMount::closeReader(std::shared_ptr<EcFileClient> &c) {
  try {
    blockingWait(c->close());
    retainedReader_.reset();
    c.reset();
    return Void{};
  } catch (...) {
    closing_ = true;
    changed_.notify_one();
    return makeError(StatusCode::kIOError, "local EC join unconfirmed");
  }
}
Result<EcFileMount::Session *> EcFileMount::find(const EcMountHandle &h, const flat::UserInfo &u) {
  auto it = sessions_.find(h.session);
  if (it == sessions_.end() || it->second.archived || !it->second.accepted || u.uid != h.owner.uid ||
      h.owner.client != state_->clientNamespace())
    return makeError(MetaCode::kNoPermission);
  auto &s = it->second;
  const auto &r = s.accepted->record();
  if (r.object != h.object || r.owner.uid != h.owner.uid || r.session != h.session || r.rights != h.rights ||
      r.shardBytes != h.shardBytes)
    return makeError(StatusCode::kTokenMismatch);
  return &s;
}
Result<meta::OpenEcFileSessionRsp> EcFileMount::reopen(Session &s, flat::UserInfo u) {
  RETURN_ON_ERROR(active(control()));
  RETURN_ON_ERROR(owner(s.original, state_->clientNamespace()));
  if (u.uid != s.original.request.user.uid || u.gid != s.original.request.user.gid)
    return makeError(MetaCode::kNoPermission);
  auto request = s.original.request;
  request.user = std::move(u);
  auto rsp = blockingWait(deps_.meta->openEcFileSession(std::move(request)));
  if (!rsp) return makeError(std::move(rsp.error()));
  const auto &i = rsp->session.intent;
  const auto &r = s.original.request;
  if (i.session != r.session || i.openRequest != r.uuid || i.owner.uid != r.user.uid ||
      i.owner.client != state_->clientNamespace() || i.rights != r.rights || (!r.createNew && i.object != r.object) ||
      (!r.resolveBirth && !r.createNew && i.birth != r.birth) || i.birth.is_nil() || rsp->object.object != i.object ||
      rsp->root.object != i.object || rsp->root.birth != i.birth || !rsp->root.sequence || !rsp->root.epoch ||
      rsp->inode.id != i.object.inode || !rsp->inode.isFile() || !rsp->inode.asFile().layout.ecLayout() ||
      rsp->inode.asFile().layout.ecLayout()->incarnation != i.object.incarnation)
    return makeError(StatusCode::kTokenMismatch);
  if (!s.accepted) {
    // This resolved bridge is ONLY consumed by preparePwrite/close, never used
    // to replay Open46. The immutable original above remains the replay source.
    auto existing = EcFilePwriteJournal::resume(s.directory / "accepted");
    if (existing)
      s.accepted = std::shared_ptr<EcFilePwriteJournal>(std::move(*existing));
    else if (std::filesystem::exists(s.directory / "accepted"))
      return makeError(std::move(existing.error()));
    else {
      EcPwriteRunRecord record;
      record.cluster = state_->cluster();
      record.owner = i.owner;
      record.object = i.object;
      record.birth = i.birth;
      record.shardBytes = rsp->object.shardBytes;
      record.session = i.session;
      record.openRequest = i.openRequest;
      record.closeRequest = Uuid::random();
      record.rights = i.rights;
      auto j = EcFilePwriteJournal::create(s.directory / "accepted", record);
      if (!j) return makeError(std::move(j.error()));
      s.accepted = std::shared_ptr<EcFilePwriteJournal>(std::move(*j));
    }
  }

  const auto &accepted = s.accepted->record();
  if (accepted.object != i.object || accepted.birth != i.birth || accepted.owner.uid != i.owner.uid ||
      accepted.owner.client != i.owner.client || accepted.session != i.session ||
      accepted.openRequest != i.openRequest || accepted.rights != i.rights ||
      accepted.shardBytes != rsp->object.shardBytes)
    return makeError(StatusCode::kTokenMismatch);
  // A session journal records acceptance and closure, not every changing root.
  // Truncate uses this RPC's returned root directly. Avoid a lifetime 4096-state
  // limit on an otherwise healthy long-lived session.
  if (!s.accepted->latest() || !s.accepted->latest()->session ||
      s.accepted->latest()->session->state != rsp->session.state) {
    auto progress = s.accepted->latest().value_or(EcPwriteRunProgress{});
    progress.issued = true;
    progress.session = rsp->session;
    progress.root = rsp->root;
    progress.shardBytes = rsp->object.shardBytes;
    RETURN_ON_ERROR(s.accepted->append(std::move(progress)));
  }
  return std::move(*rsp);
}
Result<std::filesystem::path> EcFileMount::next(Session &s, std::string_view kind, uint64_t input) {
  if (s.debt || s.pendingRead || s.archived)
    return makeError(StorageClientCode::kResourceBusy, "unresolved mount operation");
  CHECK_RESULT(path, state_->reserveOperation(s.directory, kind, input));
  s.debt = true;
  return path;
}
Result<Void> EcFileMount::reapCompleted() {
  if (retainedReader_) return makeError(StorageClientCode::kResourceBusy);
  for (auto &[id, s] : sessions_) {
    (void)id;
    if (s.pendingRead && s.pendingRead->output.expired()) {
      RETURN_ON_ERROR(state_->archiveOperation(s.directory, s.pendingRead->name, s.pendingRead->evidence));
      s.pendingRead.reset();
      s.debt = false;
    }
  }
  return Void{};
}
void EcFileMount::pruneArchived() {
  for (auto it = sessions_.begin(); it != sessions_.end();)
    if (it->second.archived)
      it = sessions_.erase(it);
    else
      ++it;
}

Result<EcMountOpenResult> EcFileMount::openOwned(EcMountOpenRecord original, flat::UserInfo user) {
  if ((original.request.rights & meta::kEcSessionWrite) && readonly(user)) return makeError(StatusCode::kReadOnlyMode);
  CHECK_RESULT(dir, state_->reserve("session"));
  RETURN_ON_ERROR(state_->write(dir, "open.bin", encode(original)));
  Session s;
  s.original = std::move(original);
  s.directory = std::move(dir);
  auto [it, inserted] = sessions_.emplace(s.original.request.session, std::move(s));
  if (!inserted) return makeError(StatusCode::kTokenDuplicated);
  CHECK_RESULT(rsp, reopen(it->second, user));
  if (rsp.session.state != meta::EcFileSessionState::Open) return makeError(StatusCode::kTokenStale);
  if (it->second.original.flags & O_TRUNC) {
    auto trunc = truncateOwned(it->second, user, 0);
    if (!trunc) return makeError(std::move(trunc.error()));
  }
  EcMountOpenResult out;
  out.handle = {rsp.session.intent.session,
                rsp.session.intent.object,
                rsp.session.intent.owner,
                rsp.object.shardBytes,
                rsp.session.intent.rights};
  out.inode = std::move(rsp.inode);
  return out;
}
CoTryTask<EcMountOpenResult> EcFileMount::open(meta::Inode inode, flat::UserInfo u, int flags) {
  auto valid = validateEcMountOpenFlags(flags, false);
  if (!valid) return failed<EcMountOpenResult>(std::move(valid.error()));
  auto object = ecReadObject(inode);
  if (!object) return failed<EcMountOpenResult>(std::move(object.error()));
  auto held = admit();
  if (!held) return failed<EcMountOpenResult>(std::move(held.error()));
  EcMountOpenRecord r;
  r.flags = flags;
  r.request.user = u;
  r.request.user.token.clear();
  r.request.client = ClientId(state_->clientNamespace());
  r.request.uuid = Uuid::random();
  r.request.session = Uuid::random();
  r.request.object = *object;
  r.request.resolveBirth = true;
  r.request.rights = rights(flags);
  auto self = shared_from_this();
  return post<EcMountOpenResult>(*held, [self, r = std::move(r), u = std::move(u)](auto) mutable {
    return self->openOwned(std::move(r), std::move(u));
  });
}
CoTryTask<EcMountOpenResult> EcFileMount::create(meta::PathAt path,
                                                 flat::UserInfo u,
                                                 int flags,
                                                 uint32_t perm,
                                                 uint32_t shard) {
  auto valid = validateEcMountOpenFlags(flags, true);
  if (!valid) return failed<EcMountOpenResult>(std::move(valid.error()));
  auto held = admit();
  if (!held) return failed<EcMountOpenResult>(std::move(held.error()));
  EcMountOpenRecord r;
  r.flags = flags;
  r.request.user = u;
  r.request.user.token.clear();
  r.request.client = ClientId(state_->clientNamespace());
  r.request.uuid = Uuid::random();
  r.request.session = Uuid::random();
  r.request.createNew = true;
  r.request.path = std::move(path);
  r.request.shardBytes = shard;
  r.request.perm = meta::Permission(perm);
  r.request.rights = rights(flags);
  auto self = shared_from_this();
  return post<EcMountOpenResult>(*held, [self, r = std::move(r), u = std::move(u)](auto) mutable {
    return self->openOwned(std::move(r), std::move(u));
  });
}
CoTryTask<EcMountReadResult> EcFileMount::read(EcMountHandle h,
                                               flat::UserInfo u,
                                               uint64_t off,
                                               uint64_t len,
                                               bool shortWindow) {
  auto held = admit();
  if (!held) return failed<EcMountReadResult>(std::move(held.error()));
  auto self = shared_from_this();
  return post<EcMountReadResult>(
      *held,
      [self, h, u = std::move(u), off, len, shortWindow](auto lease) mutable -> Result<EcMountReadResult> {
        CHECK_RESULT(s, self->find(h, u));
        if (!(h.rights & meta::kEcSessionRead)) return makeError(MetaCode::kNoPermission);
        if (s->debt) return makeError(StorageClientCode::kResourceBusy);
        meta::EcManifestLayoutV1 layout;
        layout.incarnation = h.object.incarnation;
        layout.shardBytes = h.shardBytes;
        CHECK_RESULT(size, ecReadWindowLength(layout, off, len, shortWindow));
        CHECK_RESULT(path, self->next(*s, "read"));
        CHECK_RESULT(
            record,
            prepareEcTreeRead(*s->accepted->latest()->session, self->state_->cluster(), h.shardBytes, off, size));
        CHECK_RESULT(created, EcTreeReadJournal::create(path, std::move(record)));
        auto journal = std::shared_ptr<EcTreeReadJournal>(std::move(created));
        s->debt = true;
        CHECK_RESULT(client, self->reader(u));
        auto read = blockingWait(client->readTree(journal, self->control()));
        std::optional<meta::EcTreeReadRecord> terminal;
        if (!client->localJoinUnconfirmed()) {
          auto cleanup = blockingWait(client->releaseTree(journal, self->control()));
          if (cleanup && cleanup->state == meta::EcTreeReadState::Released) terminal = std::move(*cleanup);
        }
        RETURN_ON_ERROR(self->closeReader(client));
        const bool released = terminal.has_value();
        if (terminal) {
          auto proof = evidence("read", journal->record(), *terminal);
          if (read)
            s->pendingRead = Session::PendingRead{path.filename().string(), std::move(proof), lease};
          else {
            RETURN_ON_ERROR(self->state_->archiveOperation(s->directory, path.filename().string(), proof));
            s->debt = false;
          }
        }
        if (!read) return makeError(std::move(read.error()));
        EcMountReadResult out;
        out.admission = std::move(lease);
        out.data = std::move(read->data);
        out.length = read->snapshot.root.visibleLength;
        out.allReleased = released;
        return out;
      });
}
CoTryTask<uint64_t> EcFileMount::write(EcMountHandle h,
                                       flat::UserInfo u,
                                       uint64_t off,
                                       std::span<const uint8_t> input) {
  if (input.size() > meta::kEcPwriteMaxBytes || off > UINT64_MAX - input.size())
    return failed<uint64_t>(Status(StatusCode::kInvalidArg));
  auto held = admit();
  if (!held) return failed<uint64_t>(std::move(held.error()));
  // One admission covers this staging copy. It is dropped before writer's
  // budget-owned input is loaded, so the two 32 MiB buffers never overlap.
  const auto size = input.size();
  std::shared_ptr<uint8_t[]> bytes(size ? new uint8_t[size] : nullptr);
  if (size) std::memcpy(bytes.get(), input.data(), size);
  auto self = shared_from_this();
  return post<uint64_t>(
      *held,
      [self, h, u = std::move(u), off, size, bytes = std::move(bytes)](auto) mutable -> Result<uint64_t> {
        CHECK_RESULT(s, self->find(h, u));
        if (!(h.rights & meta::kEcSessionWrite)) return makeError(MetaCode::kNoPermission);
        if (s->debt) return makeError(StorageClientCode::kResourceBusy);
        if (self->readonly(u)) return makeError(StatusCode::kReadOnlyMode);
        if (!size) return uint64_t{0};
        CHECK_RESULT(path, self->next(*s, "write", size));
        auto inputPath = path;
        inputPath += ".input";
        RETURN_ON_ERROR(saveEcFileReadOutput(inputPath, {bytes.get(), size}));
        bytes.reset();
        CHECK_RESULT(writer, self->writer(u));
        CHECK_RESULT(payload, writer->readInput(inputPath));
        CHECK_RESULT(record, prepareEcPwrite(*s->accepted, off, inputPath.string(), payload.bytes()));
        CHECK_RESULT(j, EcFilePwriteJournal::create(path, std::move(record)));
        s->debt = true;
        auto result = writer->pwrite(*j, std::move(payload), self->control());
        if (!result.logicalClosed) {
          result = writer->sealAndCleanup(*j, self->control());
        }
        if (!result.logicalClosed || !result.observed || result.confirmedPrefix != result.revalidatedPrefix)
          return makeError(result.failure ? std::move(*result.failure) : Status(StorageCode::kEcSealOutcomeUnknown));
        if (result.allCleanupComplete) {
          CHECK_RESULT(proof, writeEvidence(*j, result));
          RETURN_ON_ERROR(self->state_->archiveOperation(s->directory, path.filename().string(), proof));
          s->debt = false;
        }
        // A short result is allowed only after the SAME parent is fenced. Its tail
        // can never publish after the application retries the unacknowledged suffix.
        if (!result.confirmedPrefix)
          return makeError(result.failure ? std::move(*result.failure) : Status(StatusCode::kIOError));
        return result.confirmedPrefix;
      });
}
Result<uint64_t> EcFileMount::truncateOwned(Session &s, flat::UserInfo u, uint64_t length) {
  const char *stage = "guard";
  auto observeFailure = [&](status_code_t code, bool exception) noexcept {
    // This worker owns both the session and retained reader. Fixed scalar
    // observations cannot authorize cleanup, a retry or a changed reply.
    try {
      XLOGF(ERR,
            "EC_FILE_MOUNT_FAILURE operation=truncate stage={} code={} debt={} retained_reader={} "
            "local_join_unconfirmed={} exception={}",
            stage,
            code,
            s.debt ? 1 : 0,
            retainedReader_ ? 1 : 0,
            retainedReader_ && retainedReader_->localJoinUnconfirmed() ? 1 : 0,
            exception ? 1 : 0);
    } catch (...) {
    }
  };
  auto run = [&]() -> Result<uint64_t> {
    if (readonly(u)) return makeError(StatusCode::kReadOnlyMode);
    if (s.debt) return makeError(StorageClientCode::kResourceBusy);
    stage = "reopen";
    CHECK_RESULT(current, reopen(s, u));
    stage = "reserve";
    CHECK_RESULT(path, next(s, "truncate"));
    stage = "prepare";
    CHECK_RESULT(record, prepareEcFileTruncate(current.session, current.root, state_->cluster(), length));
    stage = "journal";
    CHECK_RESULT(j, EcTruncateJournal::create(path, std::move(record)));
    auto journal = std::shared_ptr<EcTruncateJournal>(std::move(j));
    s.debt = true;
    stage = "reader";
    CHECK_RESULT(client, reader(u));
    const auto deadline = control();
    Result<meta::EcFileTruncateProgress> progress = makeError(StatusCode::kIOError);
    // One client call appends at most seven states. Leave room for one later
    // Query (three) and one CloseDebt attempt (five), not a promise of remote T2.
    constexpr uint64_t kCallStates = 7, kRecoveryStates = 8;
    constexpr uint32_t kMaximumConflicts = 8;
    uint32_t conflicts = 0;
    do {
      stage = "deadline";
      auto permitted = active(deadline);
      if (!permitted) {
        progress = makeError(std::move(permitted.error()));
        break;
      }
      stage = "journal_budget";
      if (journal->remainingStates() < kCallStates + kRecoveryStates) {
        // Retain a definite conflict if that was the last actual result.
        if (progress || progress.error().code() != TransactionCode::kConflict)
          progress = makeError(StorageClientCode::kResourceBusy, "truncate journal recovery capacity reserved");
        break;
      }
      stage = "advance";
      progress = blockingWait(client->truncate(journal, deadline));
      if (client->localJoinUnconfirmed() || journal->poisoned()) break;
      if (!progress) {
        if (progress.error().code() != TransactionCode::kConflict || ++conflicts >= kMaximumConflicts) break;
        // The next SAME-journal call queries before any mutation. Neither an
        // unknown result nor a new identity/deadline is admitted here.
      } else if (progress->observed && progress->observed->state != meta::EcFileTruncateState::Planned) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (true);
    if (progress && progress->observed && progress->observed->state == meta::EcFileTruncateState::Published &&
        !client->localJoinUnconfirmed()) {
      stage = "close_debt";
      auto cleanup = blockingWait(client->closeTruncateDebt(journal, deadline));
      if (cleanup) progress = std::move(cleanup);
      else observeFailure(cleanup.error().code(), false);
    }
    // Preserve the pre-close status even if closing subsequently fails.
    if (!progress) observeFailure(progress.error().code(), false);
    stage = "close_reader";
    RETURN_ON_ERROR(closeReader(client));
    if (progress && progress->observed && progress->observed->state != meta::EcFileTruncateState::Planned &&
        progress->observed->outputDrained && progress->observed->sourceReleased) {
      stage = "archive";
      RETURN_ON_ERROR(state_->archiveOperation(s.directory,
                                               path.filename().string(),
                                               evidence("truncate", journal->record(), *progress->observed)));
      s.debt = false;
    }
    stage = "result";
    if (!progress) return makeError(std::move(progress.error()));
    if (!progress->observed || progress->observed->state != meta::EcFileTruncateState::Published)
      return makeError(StorageCode::kEcSealOutcomeUnknown);
    return length;
  };
  try {
    auto result = run();
    if (!result) observeFailure(result.error().code(), false);
    return result;
  } catch (...) {
    observeFailure(StatusCode::kIOError, true);
    throw;
  }
}
CoTryTask<uint64_t> EcFileMount::truncate(EcMountHandle h, flat::UserInfo u, uint64_t n) {
  auto held = admit();
  if (!held) return failed<uint64_t>(std::move(held.error()));
  auto self = shared_from_this();
  return post<uint64_t>(*held, [self, h, u = std::move(u), n](auto) mutable -> Result<uint64_t> {
    CHECK_RESULT(s, self->find(h, u));
    if (!(h.rights & meta::kEcSessionWrite)) return makeError(MetaCode::kNoPermission);
    return self->truncateOwned(*s, std::move(u), n);
  });
}
Result<Void> EcFileMount::closeSession(Session &s, flat::UserInfo u) {
  RETURN_ON_ERROR(recoverSession(s, u));
  CHECK_RESULT(writer, this->writer(u));
  CHECK_RESULT(closed, writer->closeSession(*s.accepted, control()));
  if (closed.state != meta::EcFileSessionState::Closed) return makeError(StorageClientCode::kResourceBusy);
  auto old = state_->read(s.directory, "closed");
  RETURN_ON_ERROR(old);
  if (!*old)
    RETURN_ON_ERROR(state_->write(s.directory, "closed", encode(closed)));
  else if (**old != encode(closed))
    return makeError(StatusCode::kTokenMismatch);
  SessionTerminal terminal;
  terminal.accepted = s.accepted->record();
  terminal.closed = closed;
  RETURN_ON_ERROR(state_->archiveSession(s.directory, evidence("session", s.original, terminal)));
  s.archived = true;
  return Void{};
}
CoTryTask<Void> EcFileMount::release(EcMountHandle h, flat::UserInfo u) {
  auto held = admit();
  if (!held) return failed<Void>(std::move(held.error()));
  auto self = shared_from_this();
  return post<Void>(*held, [self, h, u = std::move(u)](auto) mutable -> Result<Void> {
    CHECK_RESULT(s, self->find(h, u));
    return self->closeSession(*s, std::move(u));
  });
}
CoTryTask<Void> EcFileMount::flush(EcMountHandle h, flat::UserInfo u) {
  auto held = admit();
  if (!held) return failed<Void>(std::move(held.error()));
  auto self = shared_from_this();
  return post<Void>(*held, [self, h, u = std::move(u)](auto) mutable -> Result<Void> {
    CHECK_RESULT(s, self->find(h, u));
    return self->recoverSession(*s, std::move(u));
  });
}
CoTryTask<meta::EcFileSyncRecord> EcFileMount::fsync(EcMountHandle h, flat::UserInfo u) {
  auto held = admit();
  if (!held) return failed<meta::EcFileSyncRecord>(std::move(held.error()));
  auto self = shared_from_this();
  return post<meta::EcFileSyncRecord>(
      *held,
      [self, h, u = std::move(u)](auto) mutable -> Result<meta::EcFileSyncRecord> {
        CHECK_RESULT(s, self->find(h, u));
        // Admission proves every earlier local operation returned. It does not
        // prove an uncertain one committed: reject debt before creating a barrier.
        if (s->debt) return makeError(StorageClientCode::kResourceBusy, "resolve original mount journal before fsync");
        CHECK_RESULT(path, self->next(*s, "sync"));
        CHECK_RESULT(record, prepareEcSync(*s->accepted->latest()->session, self->state_->cluster()));
        CHECK_RESULT(j, EcAppendJournal::create(path, std::move(record)));
        s->debt = true;
        CHECK_RESULT(writer, self->writer(u));
        CHECK_RESULT(client,
                     EcFileAppendClient::connect(self->deps_.meta, *writer, u, self->state_->clientNamespace()));
        auto result = client->fsync(*j, self->control());
        if (!result) return makeError(std::move(result.error()));
        RETURN_ON_ERROR(self->state_->archiveOperation(s->directory,
                                                       path.filename().string(),
                                                       evidence("sync", j->record(), *result)));
        s->debt = false;
        return std::move(*result);
      });
}
Result<Void> EcFileMount::recoverSession(Session &s, flat::UserInfo u) {
  // Only ACTIVE indices are enumerated, never the unbounded audit history.
  // Missing or incomplete identity journals remain charged and fail closed.
  if (s.pendingRead)
    return makeError(StorageClientCode::kResourceBusy, "output lease or unarchived completion retained");
  CHECK_RESULT(writer, this->writer(u));
  s.debt = true;
  CHECK_RESULT(ops, state_->operations(s.directory));
  for (const auto &op : ops) {
    const auto &name = op.name;
    const auto path = s.directory / name;
    if (name.starts_with("write-")) {
      CHECK_RESULT(j, EcFilePwriteJournal::resume(path));
      if (j->record().session != s.original.request.session || j->record().length != op.inputBytes)
        return makeError(StatusCode::kTokenMismatch);
      auto observed = writer->query(*j, control());
      // Missing is only an observation. The pwrite library validates the saved
      // input and may replay this SAME original Begin, never a replacement ID.
      // Disappearance of an already observed parent is DataCorruption there.
      if (observed.failure && observed.failure->code() != StatusCode::kKVStoreNotFound)
        return makeError(std::move(*observed.failure));
      if (!observed.logicalClosed) {
        if (readonly(u)) return makeError(StatusCode::kReadOnlyMode);
        CHECK_RESULT(payload, writer->readInput(j->record().inputPath));
        observed = writer->pwrite(*j, std::move(payload), control());
      }
      if (!observed.logicalClosed)
        observed = writer->sealAndCleanup(*j, control());
      else if (!observed.allCleanupComplete)
        observed = writer->sealAndCleanup(*j, control());
      CHECK_RESULT(proof, writeEvidence(*j, observed));
      RETURN_ON_ERROR(state_->archiveOperation(s.directory, name, proof));
    } else if (name.starts_with("sync-")) {
      CHECK_RESULT(j, EcAppendJournal::resume(path));
      if (j->record().session.intent.session != s.original.request.session || j->record().kind != EcAppendRunKind::Sync)
        return makeError(StatusCode::kTokenMismatch);
      CHECK_RESULT(client, EcFileAppendClient::connect(deps_.meta, *writer, u, state_->clientNamespace()));
      CHECK_RESULT(synced, client->fsync(*j, control()));
      RETURN_ON_ERROR(state_->archiveOperation(s.directory, name, evidence("sync", j->record(), synced)));
    } else if (name.starts_with("read-")) {
      CHECK_RESULT(j, EcTreeReadJournal::resume(path));
      if (j->record().session.session != s.original.request.session) return makeError(StatusCode::kTokenMismatch);
      auto journal = std::shared_ptr<EcTreeReadJournal>(std::move(j));
      CHECK_RESULT(client, reader(u));
      auto released = blockingWait(client->releaseTree(journal, control()));
      RETURN_ON_ERROR(closeReader(client));
      if (!released) return makeError(std::move(released.error()));
      if (released->state != meta::EcTreeReadState::Released) return makeError(StorageClientCode::kResourceBusy);
      RETURN_ON_ERROR(state_->archiveOperation(s.directory, name, evidence("read", journal->record(), *released)));
    } else if (name.starts_with("truncate-")) {
      CHECK_RESULT(j, EcTruncateJournal::resume(path));
      if (j->record().session.session != s.original.request.session) return makeError(StatusCode::kTokenMismatch);
      auto journal = std::shared_ptr<EcTruncateJournal>(std::move(j));
      CHECK_RESULT(client, reader(u));
      auto observed = blockingWait(client->queryTruncate(journal, control()));
      if (observed && (!observed->observed || observed->observed->state == meta::EcFileTruncateState::Planned) &&
          !client->localJoinUnconfirmed()) {
        if (readonly(u))
          observed = makeError(StatusCode::kReadOnlyMode);
        else
          observed = blockingWait(client->truncate(journal, control()));
      }
      if (observed && observed->observed && observed->observed->state != meta::EcFileTruncateState::Planned &&
          !client->localJoinUnconfirmed())
        observed = blockingWait(client->closeTruncateDebt(journal, control()));
      RETURN_ON_ERROR(closeReader(client));
      if (!observed) return makeError(std::move(observed.error()));
      if (!observed->observed || observed->observed->state == meta::EcFileTruncateState::Planned ||
          !observed->observed->outputDrained || !observed->observed->sourceReleased)
        return makeError(StorageClientCode::kResourceBusy);
      RETURN_ON_ERROR(
          state_->archiveOperation(s.directory, name, evidence("truncate", journal->record(), *observed->observed)));
    } else
      return makeError(StatusCode::kInvalidFormat);
  }
  s.debt = false;
  return Void{};
}
CoTryTask<Void> EcFileMount::recoverState() {
  auto held = admit();
  if (!held) return failed<Void>(std::move(held.error()));
  auto self = shared_from_this();
  return post<Void>(*held, [self](auto) { return self->recover(self->token_); });
}
Result<Void> EcFileMount::recover(flat::Token token) {
  CHECK_RESULT(dirs, state_->sessions());
  for (const auto &dir : dirs) {
    CHECK_RESULT(raw, state_->read(dir, "open.bin"));
    if (!raw) return makeError(StatusCode::kInvalidFormat);
    CHECK_RESULT(record, decode<EcMountOpenRecord>(*raw));
    RETURN_ON_ERROR(owner(record, state_->clientNamespace()));
    Session s;
    s.original = std::move(record);
    s.directory = dir;
    auto user = s.original.request.user;
    user.token = token;
    auto [it, inserted] = sessions_.emplace(s.original.request.session, std::move(s));
    if (!inserted) return makeError(StatusCode::kTokenDuplicated);
    RETURN_ON_ERROR(reopen(it->second, user));
    RETURN_ON_ERROR(closeSession(it->second, user));
    sessions_.erase(it);
  }
  return Void{};
}
Result<Void> EcFileMount::stop() noexcept {
  try {
    std::lock_guard shutdown(stopMutex_);
    if (stopped_) return Void{};
    closing_ = true;
    changed_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (retainedReader_) {
      auto held = retainedReader_;
      RETURN_ON_ERROR(closeReader(held));
    }
    // Remote debts stay on disk for the next checked recovery. They do not
    // justify retaining live borrowed request pointers or claiming released T2.
    executor_.reset();
    deps_ = {};
    stopped_ = true;
    return Void{};
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::fuse
