#include "EcFilePwriteClient.h"

#include <folly/experimental/coro/BlockingWait.h>
#include <thread>

#include "detail/EcFileValidation.h"

namespace hf3fs::client::ec {
namespace {
using folly::coro::blockingWait;
Result<Void> active(const EcStripeControl &c) {
  RETURN_ON_ERROR(validateEcStorageTransport(c.transport));
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
uint64_t end(const EcPwriteRunRecord &r, size_t n) {
  return n + 1 < r.count ? r.children[n + 1].intent.expectedPrefix : r.length;
}
EcPwriteOutcome outcome(const EcFilePwriteJournal &j, std::optional<Status> error = {}) {
  EcPwriteOutcome out;
  out.failure = std::move(error);
  if (j.latest() && j.latest()->parent) {
    const auto &p = *j.latest()->parent;
    out.observed = true;
    out.confirmedPrefix = p.confirmedPrefix;
    out.logicalClosed = p.state == meta::EcFileMutationState::ClosedLogical;
    out.logicalComplete = out.logicalClosed && p.confirmedPrefix == j.record().length;
    uint64_t expected = 0;
    for (size_t n = 0; n < j.record().count; ++n)
      if (end(j.record(), n) <= p.confirmedPrefix || j.record().children[n].intent.child == p.fencedChild)
        expected |= uint64_t{1} << n;
    out.allCleanupComplete = out.logicalClosed && (j.latest()->cleanedMask & expected) == expected;
  }
  return out;
}
Result<net::Address> address(hf3fs::client::ICommonMgmtdClient &mgmtd,
                             const meta::EcV2PhysicalEndpoint &worker, EcStorageTransportPolicy policy) {
  RETURN_ON_ERROR(validateEcStorageTransport(policy));
  const auto type = policy == EcStorageTransportPolicy::RdmaOnly ? net::Address::RDMA : net::Address::TCP;
  auto route = mgmtd.getRoutingInfo();
  if (!route || !route->raw()) return makeError(StorageClientCode::kRoutingError);
  const auto &e = worker.placement;
  auto target = route->getTarget(e.target);
  auto chain = route->getChain(e.chain);
  auto node = route->raw()->getNode(e.node);
  if (!target || !chain || !node || target->nodeId != e.node || target->chainId != e.chain ||
      target->publicState != flat::PublicTargetState::SERVING || chain->targets.size() != 1 ||
      chain->targets[0].targetId != e.target || chain->targets[0].publicState != flat::PublicTargetState::SERVING ||
      node->type != flat::NodeType::STORAGE || node->status != flat::NodeStatus::HEARTBEAT_CONNECTED)
    return makeError(StorageClientCode::kRoutingError);
  for (const auto &g : node->app.serviceGroups)
    if (g.services.contains("StorageSerde"))
      for (const auto &a : g.endpoints)
        if (a.type == type) return a;
  return makeError(StorageClientCode::kRoutingError);
}
}  // namespace
Result<std::unique_ptr<EcFilePwriteClient>> EcFilePwriteClient::connect(
    std::shared_ptr<meta::client::MetaClient> meta,
    std::shared_ptr<storage::client::EcRmwTransport> transport,
    std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd,
    flat::UserInfo credentials,
    Uuid expected) {
  if (!meta || !transport || !mgmtd || expected.is_nil() || meta->clientId().uuid != expected)
    return makeError(StatusCode::kInvalidArg);
  try {
    auto auth = blockingWait(meta->authenticate(credentials));
    if (!auth) return makeError(std::move(auth.error()));
    auto token = std::move(credentials.token);
    credentials = std::move(*auth);
    credentials.token = std::move(token);
    CHECK_RESULT(budget, EcFilePayloadBudget::create());
    return std::unique_ptr<EcFilePwriteClient>(new EcFilePwriteClient(std::move(meta),
                                                                      std::move(transport),
                                                                      std::move(mgmtd),
                                                                      std::move(credentials),
                                                                      std::move(budget)));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}
Result<Void> EcFilePwriteClient::check(const EcFilePwriteJournal &j, EcStripeControl c) const {
  RETURN_ON_ERROR(j.record().validate());
  if (j.poisoned() || j.record().owner.uid != owner_.uid || j.record().owner.client != owner_.client)
    return makeError(StatusCode::kTokenMismatch, "run owner differs or persistence is unconfirmed");
  const auto now = std::chrono::steady_clock::now();
  if (c.deadline - now > std::chrono::hours(1)) return makeError(StatusCode::kInvalidArg);
  return active(c);
}
void EcFilePwriteClient::request(meta::ReqBase &r, Uuid id) const {
  r.user = credentials_;
  r.client = ClientId(owner_.client);
  r.uuid = id;
}
Result<meta::EcFileSessionRecord> EcFilePwriteClient::open(EcFilePwriteJournal &j, EcStripeControl control) {
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) return makeError(StorageClientCode::kResourceBusy);
  bool invoked = false;
  try {
    RETURN_ON_ERROR(check(j, control));
    const auto &r = j.record();
    if (r.kind != EcPwriteRunKind::Session) return makeError(StatusCode::kInvalidArg);
    auto state = j.latest().value_or(EcPwriteRunProgress{});
    state.issued = true;
    RETURN_ON_ERROR(j.append(state));
    meta::OpenEcFileSessionReq req;
    request(req, r.openRequest);
    req.createNew = r.createNew;
    req.object = r.object;
    req.birth = r.birth;
    req.session = r.session;
    req.rights = r.rights;
    req.shardBytes = r.shardBytes;
    req.perm = meta::Permission(r.permission);
    if (r.createNew) req.path = meta::PathAt(meta::InodeId::root(), Path(r.path));
    RETURN_ON_ERROR(req.valid());
    invoked = true;
    auto rsp = blockingWait(meta_->openEcFileSession(std::move(req)));
    if (!rsp) return makeError(std::move(rsp.error()));
    if (rsp->object.object != rsp->session.intent.object || rsp->root.object != rsp->object.object ||
        rsp->root.birth != rsp->session.intent.birth || rsp->root.birth.is_nil() || !rsp->root.epoch ||
        !rsp->root.sequence || (r.createNew && rsp->object.shardBytes != r.shardBytes))
      return makeError(StatusCode::kTokenMismatch);
    state.session = rsp->session;
    state.root = rsp->root;
    state.shardBytes = rsp->object.shardBytes;
    state.errorCode = 0;
    RETURN_ON_ERROR(j.append(state));
    return rsp->session;
  } catch (const std::bad_alloc &) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
Result<meta::EcFileSessionRecord> EcFilePwriteClient::closeSession(EcFilePwriteJournal &j, EcStripeControl control) {
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) return makeError(StorageClientCode::kResourceBusy);
  bool invoked = false;
  try {
    RETURN_ON_ERROR(check(j, control));
    const auto &r = j.record();
    if (r.kind != EcPwriteRunKind::Session || !j.latest() || !j.latest()->session)
      return makeError(StatusCode::kInvalidArg);
    auto state = *j.latest();
    RETURN_ON_ERROR(j.append(state));
    meta::CloseEcFileSessionReq req;
    request(req, r.closeRequest);
    req.object = state.session->intent.object;
    req.session = r.session;
    invoked = true;
    auto rsp = blockingWait(meta_->closeEcFileSession(std::move(req)));
    if (!rsp) return makeError(std::move(rsp.error()));
    state.session = rsp->session;
    state.errorCode = 0;
    RETURN_ON_ERROR(j.append(state));
    return rsp->session;
  } catch (const std::bad_alloc &) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    return makeError(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
Result<Void> EcFilePwriteClient::remember(EcFilePwriteJournal &j,
                                          const meta::EcFilePwriteProgress &p,
                                          std::optional<size_t> index) {
  auto state = j.latest().value_or(EcPwriteRunProgress{});
  if (!p.parent) {
    if (p.child || p.worker || p.outputDrained || p.sourceReleased || state.parent)
      return makeError(StatusCode::kDataCorruption);
    return Void{};
  }
  state.parent = p.parent;
  if (p.child) {
    if (!index) return makeError(StatusCode::kTokenMismatch);
    const auto &r = j.record();
    const auto &id = r.children[*index].intent;
    const auto &c = *p.child;
    const auto width = uint64_t(r.shardBytes) * 10;
    const auto offset = r.offset + id.expectedPrefix;
    if (c.child != id.child || c.plan != id.plan || c.stripe != offset / width || c.patchOffset != offset % width ||
        c.patchLength != end(r, *index) - id.expectedPrefix || c.targetLogicalLength < c.patchOffset + c.patchLength ||
        c.targetLogicalLength > width ||
        (c.state != meta::EcFileChildState::Planned && c.state != meta::EcFileChildState::Published &&
         c.state != meta::EcFileChildState::Fenced))
      return makeError(StatusCode::kTokenMismatch);
    if (c.state == meta::EcFileChildState::Published && p.parent->confirmedPrefix < end(r, *index))
      return makeError(StatusCode::kDataCorruption);
    if (c.state != meta::EcFileChildState::Planned && p.outputDrained && p.sourceReleased)
      state.cleanedMask |= uint64_t{1} << *index;
    else if (state.cleanedMask & (uint64_t{1} << *index))
      return makeError(StatusCode::kDataCorruption);
  } else if (p.worker || p.outputDrained || p.sourceReleased)
    return makeError(StatusCode::kDataCorruption);
  state.errorCode = 0;
  RETURN_ON_ERROR(j.append(std::move(state)));
  observed_ = true;
  revalidatedPrefix_ = p.parent->confirmedPrefix;
  return Void{};
}
Result<meta::EcFilePwriteRsp> EcFilePwriteClient::observe(EcFilePwriteJournal &j,
                                                          std::optional<size_t> n,
                                                          EcStripeControl control) {
  RETURN_ON_ERROR(check(j, control));
  const auto &r = j.record();
  meta::QueryEcFilePwriteReq req;
  request(req, n ? r.children[*n].query : r.queryRequest);
  req.object = r.object;
  req.operation = r.operation;
  req.session = r.session;
  if (n) req.child = r.children[*n].intent.child;
  auto result = blockingWait(meta_->queryEcFilePwrite(std::move(req)));
  if (!result) return makeError(std::move(result.error()));
  RETURN_ON_ERROR(remember(j, result->progress, n));
  return result;
}
Result<meta::EcFilePwriteRsp> EcFilePwriteClient::advance(EcFilePwriteJournal &j,
                                                          meta::EcFileAdvanceAction action,
                                                          std::optional<size_t> n,
                                                          EcStripeControl control) {
  RETURN_ON_ERROR(check(j, control));
  const auto &r = j.record();
  meta::AdvanceEcFilePwriteReq req;
  Uuid id = r.sealRequest;
  req.action = action;
  req.object = r.object;
  req.operation = r.operation;
  req.session = r.session;
  if (n) {
    const auto &c = r.children[*n];
    req.child = c.intent.child;
    if (action == meta::EcFileAdvanceAction::Plan) {
      id = c.planRequest;
      req.intent = c.intent;
    } else if (action == meta::EcFileAdvanceAction::Publish)
      id = c.publish;
    else {
      id = c.cleanup;
      req.outputRevocation = c.outputRevocation;
      req.sourceRevocation = c.sourceRevocation;
    }
  }
  request(req, id);
  auto state = j.latest().value_or(EcPwriteRunProgress{});
  state.issued = true;
  RETURN_ON_ERROR(j.append(state));
  mutationInvoked_ = true;
  auto result = blockingWait(meta_->advanceEcFilePwrite(std::move(req)));
  if (!result) return makeError(std::move(result.error()));
  RETURN_ON_ERROR(remember(j, result->progress, n));
  return result;
}
Result<Void> EcFilePwriteClient::upload(EcFilePwriteJournal &j,
                                        size_t n,
                                        const meta::EcFileWorkerAccess &worker,
                                        std::span<const uint8_t> input,
                                        EcStripeControl control) {
  const auto &c = j.record().children[n];
  const auto &claims = worker.grant.claims;
  if (worker.planDigest == storage::EcSha256{} || claims.planDigest != worker.planDigest ||
      !storage::ec_rmw_detail::sameEndpoint(claims.worker, worker.worker.controlEndpoint()) || claims.rights != 14 ||
      claims.authority.is_nil() || claims.grantId.is_nil())
    return makeError(StatusCode::kTokenMismatch);
  CHECK_RESULT(destination, address(*mgmtd_, worker.worker, control.transport));
  auto rpcControl = [&] {
    storage::client::EcRequestControl c;
    c.transport = control.transport;
    c.cancellation = control.cancellation;
    c.deadline = std::min(control.deadline, std::chrono::steady_clock::now() + std::chrono::seconds(300));
    return c;
  };
  RETURN_ON_ERROR(active(control));
  storage::EcRmwActionReq req;
  req.planId = c.intent.plan;
  req.grant = worker.grant;
  req.action = storage::EcRmwActionRequest::Query;
  auto status = blockingWait(transport_->action(destination, req, rpcControl()));
  if (!status) return makeError(std::move(status.error()));
  if (status->state == 1) {
    // Plan replay may reset Receiving; therefore upload the COMPLETE original
    // child patch on every explicit resume, never trust volatile receivedBlocks.
    for (size_t offset = 0; offset < input.size(); offset += 64u * 1024) {
      RETURN_ON_ERROR(active(control));
      storage::EcRmwPutReq req;
      req.planId = c.intent.plan;
      req.grant = worker.grant;
      req.blockIndex = uint32_t(offset / (64u * 1024));
      const auto bytes = input.subspan(offset, std::min<size_t>(64u * 1024, input.size() - offset));
      req.payload.data.assign(bytes.begin(), bytes.end());
      auto sent = blockingWait(transport_->put(destination, std::move(req), rpcControl()));
      if (!sent) return makeError(std::move(sent.error()));
    }
    RETURN_ON_ERROR(active(control));
    req.action = storage::EcRmwActionRequest::Submit;
    mutationInvoked_ = true;
    status = blockingWait(transport_->action(destination, req, rpcControl()));
    if (!status) return makeError(std::move(status.error()));
  }
  while (status->state != 4) {
    if (status->state < 1 || status->state > 4) return makeError(StatusCode::kDataCorruption);
    auto remaining = active(control);
    if (!remaining) return makeError(remaining.error().convert(StorageCode::kEcSealOutcomeUnknown));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    remaining = active(control);
    if (!remaining) return makeError(remaining.error().convert(StorageCode::kEcSealOutcomeUnknown));
    req.action = storage::EcRmwActionRequest::Query;
    status = blockingWait(transport_->action(destination, req, rpcControl()));
    if (!status) return makeError(status.error().convert(StorageCode::kEcSealOutcomeUnknown));
  }
  if (status->executionError) return makeError(Status(status->executionError));
  return Void{};  // Complete is worker execution only; Publish still verifies actual twelve outputs.
}
Result<Void> EcFilePwriteClient::executeOwned(EcFilePwriteJournal &j,
                                              EcFilePayload *input,
                                              EcStripeControl control,
                                              bool seal) {
  RETURN_ON_ERROR(check(j, control));
  const auto &r = j.record();
  if (r.kind != EcPwriteRunKind::Write && r.kind != EcPwriteRunKind::AcceptedAppend)
    return makeError(StatusCode::kInvalidArg);
  if (input) {
    if (!budget_->owns(*input) || input->size() != r.length) return makeError(StatusCode::kTokenMismatch);
    CHECK_RESULT(sha, detail::fileContentSha(input->bytes()));
    if (sha != r.inputSha256) return makeError(StatusCode::kTokenMismatch);
    for (size_t n = 0; n < r.count; ++n) {
      const auto &i = r.children[n].intent;
      CHECK_RESULT(part,
                   detail::fileContentSha(input->bytes().subspan(i.expectedPrefix, end(r, n) - i.expectedPrefix)));
      if (part != i.patchSha256) return makeError(StatusCode::kTokenMismatch);
    }
  }
  // Query first on every invocation. A missing snapshot does not clear issued
  // identity; only explicit pwrite may replay the SAME original Begin request.
  CHECK_RESULT(initial, observe(j, std::nullopt, control));
  if (!initial.progress.parent) {
    if (r.kind == EcPwriteRunKind::AcceptedAppend)
      return makeError(StatusCode::kDataCorruption, "accepted append parent missing; never recreate with Begin47");
    if (!input || seal) return makeError(StatusCode::kKVStoreNotFound, "no completion observed; retain original IDs");
    meta::BeginEcFilePwriteReq req;
    request(req, r.beginRequest);
    req.object = r.object;
    req.session = r.session;
    req.operation = r.operation;
    req.offset = r.offset;
    req.length = r.length;
    req.inputSha256 = r.inputSha256;
    auto state = j.latest().value_or(EcPwriteRunProgress{});
    state.issued = true;
    RETURN_ON_ERROR(j.append(state));
    RETURN_ON_ERROR(active(control));
    mutationInvoked_ = true;
    auto begun = blockingWait(meta_->beginEcFilePwrite(std::move(req)));
    if (!begun) return makeError(std::move(begun.error()));
    RETURN_ON_ERROR(remember(j, begun->progress, std::nullopt));
    if (!begun->progress.parent) return makeError(StatusCode::kDataCorruption);
  }
  if (seal) {
    auto closed = advance(j, meta::EcFileAdvanceAction::SealPrefix, std::nullopt, control);
    if (!closed) return makeError(std::move(closed.error()));
  }
  for (size_t n = 0; n < r.count; ++n) {
    CHECK_RESULT(observed, observe(j, n, control));
    const auto start = r.children[n].intent.expectedPrefix;
    if (!observed.progress.parent) return makeError(StatusCode::kDataCorruption);
    auto p = *observed.progress.parent;
    if (p.confirmedPrefix > start && p.confirmedPrefix < end(r, n)) return makeError(StatusCode::kDataCorruption);
    if (p.confirmedPrefix >= end(r, n) &&
        (!observed.progress.child || observed.progress.child->state != meta::EcFileChildState::Published))
      return makeError(StatusCode::kDataCorruption);
    if (p.confirmedPrefix == start && p.state == meta::EcFileMutationState::Open && input && !seal) {
      if (!p.activeChild.is_nil() && p.activeChild != r.children[n].intent.child)
        return makeError(StatusCode::kTokenMismatch);
      // T0 may already have committed before a lost Publish response. It
      // permanently rejects new issuance; resume that exact Publish instead
      // of trying to reopen the write scope or replacing the child ID.
      if (!observed.progress.outputDrained) {
        auto planned = advance(j, meta::EcFileAdvanceAction::Plan, n, control);
        if (!planned && planned.error().code() != StatusCode::kTokenStale) return makeError(std::move(planned.error()));
        if (planned) {
          if (!planned->progress.child || planned->progress.child->state != meta::EcFileChildState::Planned ||
              !planned->progress.worker)
            return makeError(StatusCode::kDataCorruption);
          RETURN_ON_ERROR(
              upload(j, n, *planned->progress.worker, input->bytes().subspan(start, end(r, n) - start), control));
        }
      }
      CHECK_RESULT(published, advance(j, meta::EcFileAdvanceAction::Publish, n, control));
      if (!published.progress.child || published.progress.child->state != meta::EcFileChildState::Published ||
          !published.progress.parent || published.progress.parent->confirmedPrefix < end(r, n))
        return makeError(StatusCode::kDataCorruption);
      observed = std::move(published);
    }
    if ((input || seal) && observed.progress.child &&
        (observed.progress.child->state != meta::EcFileChildState::Planned || seal) &&
        !(observed.progress.outputDrained && observed.progress.sourceReleased)) {
      CHECK_RESULT(cleaned, advance(j, meta::EcFileAdvanceAction::CleanupChild, n, control));
      if (!cleaned.progress.outputDrained || !cleaned.progress.sourceReleased)
        return makeError(StorageClientCode::kResourceBusy, "same child cleanup is pending");
    }
  }
  return Void{};
}
EcPwriteOutcome EcFilePwriteClient::execute(EcFilePwriteJournal &j,
                                            EcFilePayload *input,
                                            EcStripeControl control,
                                            bool seal) {
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) return outcome(j, Status(StorageClientCode::kResourceBusy));
  mutationInvoked_ = false;
  observed_ = false;
  revalidatedPrefix_ = 0;
  std::optional<Status> failure;
  try {
    auto result = executeOwned(j, input, control, seal);
    if (!result) failure = std::move(result.error());
  } catch (const std::bad_alloc &) {
    failure = Status(mutationInvoked_ ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (...) {
    failure = Status(mutationInvoked_ ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
  if (failure && !j.poisoned()) {
    try {
      auto state = j.latest().value_or(EcPwriteRunProgress{});
      state.errorCode = failure->code();
      auto saved = j.append(state);
      if (!saved && failure->code() != StorageCode::kEcSealOutcomeUnknown &&
          failure->code() != TransactionCode::kMaybeCommitted)
        failure = std::move(saved.error());
    } catch (...) {
      failure = Status(StorageCode::kEcSealOutcomeUnknown);
    }
  }
  auto out = outcome(j, std::move(failure));
  out.observed = observed_;
  out.revalidatedPrefix = revalidatedPrefix_;
  out.logicalComplete = out.logicalComplete && observed_;
  out.logicalClosed = out.logicalClosed && observed_;
  out.allCleanupComplete = out.allCleanupComplete && observed_;
  return out;
}
EcPwriteOutcome EcFilePwriteClient::query(EcFilePwriteJournal &j, EcStripeControl c) {
  return execute(j, nullptr, c, false);
}
EcPwriteOutcome EcFilePwriteClient::pwrite(EcFilePwriteJournal &j, EcFilePayload data, EcStripeControl c) {
  return execute(j, &data, c, false);
}
EcPwriteOutcome EcFilePwriteClient::sealAndCleanup(EcFilePwriteJournal &j, EcStripeControl c) {
  return execute(j, nullptr, c, true);
}
}  // namespace hf3fs::client::ec
