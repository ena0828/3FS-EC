#include "EcFileRepairClient.h"

#include <bit>
#include <folly/experimental/coro/BlockingWait.h>
#include <set>

#include "EcBlockRead.h"
#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_repair/EcHelperDirectAuthorization.h"

namespace hf3fs::client::ec {
namespace {
using folly::coro::blockingWait;
using namespace storage;
// End the observation before returning the original Result.
template <typename F>
auto observeResult(EcRepairObservation *observation, EcRepairPoint point, F &&call, bool rpc = false) {
  EcRepairObservation::Scope metric(observation, point);
  if (rpc) metric.noteInvocation();
  auto result = call();
  if (result) metric.success();
  return result;
}
bool same(const auto &a, const auto &b) { return serde::serialize(a) == serde::serialize(b); }
Result<Void> active(EcStripeControl c) {
  RETURN_ON_ERROR(validateEcStorageTransport(c.transport));
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
storage::client::EcRequestControl options(EcStripeControl c, EcRepairObservation *observation) {
  // This helper belongs only to copyOne, including its recovery primitives.
  return {c.deadline, c.cancellation, c.transport,
          observation ? &observation->healthyCopyRpc() : nullptr};
}
Result<VersionedChainId> route(hf3fs::client::ICommonMgmtdClient &mgmtd, const meta::EcV2PhysicalEndpoint &e) {
  const auto &p = e.placement;
  auto r = mgmtd.getRoutingInfo();
  if (!r || !r->raw()) return makeError(MgmtdClientCode::kRoutingInfoNotReady);
  auto chain = r->raw()->getChain(p.chain);
  auto target = r->raw()->getTarget(p.target);
  auto node = r->raw()->getNode(p.node);
  if (!chain || !target || !node || chain->targets.size() != 1 || chain->targets.front().targetId != p.target ||
      chain->targets.front().publicState != flat::PublicTargetState::SERVING ||
      target->publicState != flat::PublicTargetState::SERVING || target->chainId != p.chain || !target->nodeId ||
      *target->nodeId != p.node || node->type != flat::NodeType::STORAGE ||
      node->status != flat::NodeStatus::HEARTBEAT_CONNECTED)
    return makeError(StorageClientCode::kRoutingError);
  return VersionedChainId{p.chain, chain->chainVersion};
}
EcRepairFragment fragment(const meta::EcV2AllocationBinding &a) {
  EcRepairFragment f;
  f.identity = a.fragment.identity;
  f.operationId = a.fragment.operation;
  f.writerNamespace = a.writer.client;
  f.endpoint = a.endpoint().controlEndpoint();
  f.integrity = a.fragment.integrity;
  return f;
}
EcFragmentAccessV2 access(const meta::EcV2AllocationBinding &a, VersionedChainId route) {
  EcFragmentAccessV2 f;
  f.identity = a.fragment.identity;
  f.operationId = a.fragment.operation;
  f.vChainId = route;
  f.targetId = a.fragment.placement.target;
  f.integrity = a.fragment.integrity;
  return f;
}
Result<Void> grant(const EcCapabilityV2 &g,
                   const meta::EcV2AllocationBinding &a,
                   const meta::EcOwner &owner,
                   EcGrantScope kind,
                   Uuid scope,
                   uint16_t rights) {
  const auto &c = g.claims;
  const auto &f = a.fragment;
  CHECK_RESULT(hash, digestEcIntegrityV2(f.identity, f.integrity));
  if (c.version != kEcGrantVersionV2 || !same(c.identity, f.identity) || c.fragmentOperationId != f.operation ||
      c.engineUuid != a.engineUuid || c.targetIncarnation != a.targetIncarnation || c.nodeId != f.placement.node ||
      c.chainId != f.placement.chain || c.targetId != f.placement.target || c.integrityDigest != hash ||
      c.expectedLength != f.integrity.wholeLength || c.expectedCrc32c != f.integrity.wholeCrc32c ||
      c.ownerUid != owner.uid || c.clientNamespace != owner.client || c.scopeObject != a.object.incarnation ||
      c.scopeKind != kind || c.scopeId != scope || (c.rights & rights) != rights || c.grantId.is_nil())
    return makeError(StatusCode::kTokenMismatch);
  // Shape binding only; each real Storage instance authenticates MAC/expiry.
  return Void{};
}
Result<std::shared_ptr<const EcRepairPlan>> validate(const meta::EcFileRepairAccess &a,
                                                     const EcTreeRepairRun &r,
                                                     const meta::EcFileRepairRecord &record) {
  CHECK_RESULT(plan, EcRepairPlan::create(a.plan));
  const auto &p = plan->input();
  const auto &i = r.intent;
  const auto &old = record.child.source;
  if (p.planId != i.selection.planId || p.operationId != i.child || p.ownerUid != i.owner.uid ||
      p.clientNamespace != i.owner.client || p.baseEpoch != i.expectedEpoch || p.baseRevision != old.revision ||
      p.logicalLength != old.logicalLength || p.logicalSha256 != old.contentSha256 ||
      p.maxBlocksInFlight != i.selection.maxBlocksInFlight || p.targetCount != std::popcount(i.replacementMask))
    return makeError(StatusCode::kTokenMismatch);
  std::set<Uuid> ids;
  for (size_t n = 0; n < 12; ++n) {
    const auto &s = a.sources[n];
    const auto &t = a.targets[n];
    const auto &si = s.fragment.identity;
    const auto &ti = t.fragment.identity;
    if (s.object != i.object || t.object != i.object || si.object != i.object.incarnation || ti.object != si.object ||
        si.stripe != i.stripe || ti.stripe != i.stripe || si.shard != n || ti.shard != n ||
        si.generation != old.generation || ti.generation != si.generation || t.fragment.operation != i.child ||
        !same(t.writer, i.owner) || t.fragment.integrity != s.fragment.integrity || !ids.insert(si.allocation).second)
      return makeError(StatusCode::kTokenMismatch);
    RETURN_ON_ERROR(validateEcIntegrity(si, s.fragment.integrity));
    RETURN_ON_ERROR(validateEcIntegrity(ti, t.fragment.integrity));
    RETURN_ON_ERROR(
        grant(a.reads[n], s, i.owner, EcGrantScope::ReadPin, i.sourcePin, uint16_t(EcGrantRightV2::ReadBlock)));
    RETURN_ON_ERROR(grant(a.writes[n], t, i.owner, EcGrantScope::WriteOperation, i.child, kEcGrantAllRightsV2));
  }
  for (const auto &t : a.targets)
    if (!ids.insert(t.fragment.identity.allocation).second) return makeError(StatusCode::kTokenMismatch);
  for (size_t n = 0; n < 10; ++n) {
    const auto &s = a.sources[i.selection.sourceOrder[n]];
    if (!same(p.sources[n], fragment(s))) return makeError(StatusCode::kTokenMismatch);
    RETURN_ON_ERROR(grant(a.pipelineReads[n],
                          s,
                          i.owner,
                          EcGrantScope::WriteOperation,
                          i.child,
                          uint16_t(EcGrantRightV2::ReadBlock)));
  }
  size_t target = 0;
  for (size_t n = 0; n < 12; ++n)
    if (i.replacementMask & (uint16_t{1} << n))
      if (!same(p.targets[target++], fragment(a.targets[n]))) return makeError(StatusCode::kTokenMismatch);
  const bool helper = i.mode == meta::EcFileRepairMode::HelperChain ||
                      i.mode == meta::EcFileRepairMode::HelperChainDirect;
  if (helper != a.helpers.has_value())
    return makeError(StatusCode::kTokenMismatch);
  return plan;
}
}  // namespace
Result<std::unique_ptr<EcFileRepairClient>> EcFileRepairClient::connect(
    std::shared_ptr<meta::client::MetaClient> m,
    std::shared_ptr<storage::client::StorageClient> s,
    std::shared_ptr<hf3fs::client::ICommonMgmtdClient> g,
    flat::UserInfo u,
    Uuid ns) {
  if (!m || !s || !g || ns.is_nil() || m->clientId().uuid != ns) return makeError(StatusCode::kInvalidArg);
  try {
    auto auth = blockingWait(m->authenticate(u));
    if (!auth) return makeError(std::move(auth.error()));
    auto token = std::move(u.token);
    u = std::move(*auth);
    u.token = std::move(token);
    return std::unique_ptr<EcFileRepairClient>(
        new EcFileRepairClient(std::move(m), std::move(s), std::move(g), std::move(u)));
  } catch (...) {
    return makeError(StatusCode::kIOError);
  }
}
Result<Void> EcFileRepairClient::check(const EcTreeRepairJournal &j, EcStripeControl c) const {
  RETURN_ON_ERROR(j.record().validate());
  const auto &o = j.record().intent.owner;
  if (j.poisoned() || o.client != meta_->clientId().uuid || o.uid != user_.uid)
    return makeError(StatusCode::kTokenMismatch);
  RETURN_ON_ERROR(active(c));
  if (c.deadline - std::chrono::steady_clock::now() > std::chrono::hours(1)) return makeError(StatusCode::kInvalidArg);
  return Void{};
}
void EcFileRepairClient::request(meta::EcFileRepairReq &q, const EcTreeRepairRun &r, Uuid id) const {
  q.user = user_;
  q.client = meta_->clientId();
  q.uuid = id;
  q.intent = r.intent;
}
CoTryTask<Void> EcFileRepairClient::copyOne(const meta::EcV2AllocationBinding &s,
                                            const meta::EcV2AllocationBinding &t,
                                            EcCapabilityV2 read,
                                            EcCapabilityV2 write,
                                            EcStripeControl c, EcRepairObservation *observation) {
  CO_RETURN_ON_ERROR(active(c));
  auto sr = route(*mgmtd_, s.endpoint());
  CO_RETURN_ON_ERROR(sr);
  auto tr = route(*mgmtd_, t.endpoint());
  CO_RETURN_ON_ERROR(tr);
  // One bounded fragment at a time; no twelve-fragment resident copy array.
  std::string data;
  data.reserve(s.fragment.integrity.wholeLength);
  for (uint32_t b = 0; b < s.fragment.integrity.blockCount; ++b) {
    CO_RETURN_ON_ERROR(active(c));
    auto q = makeEcReadBlockRequest(
        {s.fragment.identity, s.fragment.operation, s.endpoint().controlEndpoint(), s.fragment.integrity},
        read,
        *sr,
        b);
    CO_RETURN_ON_ERROR(q);
    EcRepairObservation::Scope readMetric(observation, EcRepairPoint::CopyRead);
    readMetric.noteInvocation();
    auto value = co_await storage_->readEcBlockV2Controlled(*q, options(c, observation));
    CO_RETURN_ON_ERROR(value);
    CO_RETURN_ON_ERROR(validateEcReadBlockV2(*value, *q));
    readMetric.validated(value->payload.data.size());
    readMetric.success();
    readMetric.finish();
    data.append(value->payload.data);
  }
  auto descriptor = computeEcIntegrity(t.fragment.identity, data);
  CO_RETURN_ON_ERROR(descriptor);
  if (*descriptor != t.fragment.integrity) co_return makeError(StatusCode::kDataCorruption);
  EcBeginStageV2Req begin;
  begin.request = access(t, *tr);
  begin.grant = write;
  bool invoked = false;
  try {
    CO_RETURN_ON_ERROR(active(c));
    invoked = true;
    EcRepairObservation::Scope beginMetric(observation, EcRepairPoint::CopyBegin);
    beginMetric.noteInvocation();
    auto state = co_await storage_->beginEcStageV2Controlled(begin, options(c, observation));
    uint32_t prefix = 0;
    if (state) {
      CO_RETURN_ON_ERROR(validateEcStageStateV2(*state, begin.request, write.claims));
      prefix = state->prefixBytes;
      beginMetric.success();
    } else if (state.error().code() != StorageCode::kEcSealOutcomeUnknown)
      co_return makeError(std::move(state.error()));
    beginMetric.finish();
    // Always reconcile the same allocation after restart, never infer durability
    // from a stale Query or create a replacement operation on uncertain I/O.
    CO_RETURN_ON_ERROR(active(c));
    EcRepairObservation::Scope reconcileMetric(observation, EcRepairPoint::CopyReconcile);
    reconcileMetric.noteInvocation();
    state = co_await storage_->reconcileEcStageV2Controlled({begin.request, write}, options(c, observation));
    CO_RETURN_ON_ERROR(state);
    CO_RETURN_ON_ERROR(validateEcStageStateV2(*state, begin.request, write.claims));
    if (state->needsReconcile || state->prefixBytes < prefix)
      co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    if (state->state == 3) co_return makeError(StatusCode::kTokenStale);
    reconcileMetric.success();
    reconcileMetric.finish();
    // Reconcile confirms the existing allocation but deliberately retains a
    // pending block intent. Replay from its confirmed prefix using the same
    // verified source bytes; Storage checks the original bound block proof.
    // Rejecting pendingBlock here would make an interrupted healthy copy
    // impossible to resume, even after every durability barrier succeeded.
    if (state->state == 1)
      for (uint32_t b = state->prefixBytes / kEcIntegrityBlockBytes; b < descriptor->blockCount; ++b) {
        CO_RETURN_ON_ERROR(active(c));
        EcAppendStageV2Req q;
        q.request = begin.request;
        q.grant = write;
        q.blockIndex = b;
        q.payload.data = data.substr(size_t(b) * kEcIntegrityBlockBytes, descriptor->blocks[b].validLength);
        EcRepairObservation::Scope appendMetric(observation, EcRepairPoint::CopyAppend);
        appendMetric.noteInvocation(q.payload.data.size());
        auto added = co_await storage_->appendEcStageV2Controlled(std::move(q), options(c, observation));
        CO_RETURN_ON_ERROR(added);
        CO_RETURN_ON_ERROR(validateEcStageStateV2(*added, begin.request, write.claims));
        if (added->needsReconcile || added->pendingBlock || added->state != 1 ||
            added->prefixBytes < (b * kEcIntegrityBlockBytes + descriptor->blocks[b].validLength))
          co_return makeError(StorageCode::kEcSealOutcomeUnknown);
        appendMetric.success();
      }
    CO_RETURN_ON_ERROR(active(c));
    EcRepairObservation::Scope sealMetric(observation, EcRepairPoint::CopySeal);
    sealMetric.noteInvocation();
    auto sealed = co_await storage_->sealEcStageV2Controlled({begin.request, write}, options(c, observation));
    CO_RETURN_ON_ERROR(sealed);
    CO_RETURN_ON_ERROR(validateEcReceiptV2(*sealed, begin.request, write.claims));
    CO_RETURN_ON_ERROR(active(c));
    sealMetric.success();
    co_return Void{};
  } catch (...) {
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
CoTryTask<Void> EcFileRepairClient::transfer(meta::EcFileRepairAccess a, const EcTreeRepairRun &r, EcStripeControl c,
                                           EcRepairObservation *observation,
                                           std::optional<EcHelperDirectDelegation> direct) {
  if ((r.intent.mode == meta::EcFileRepairMode::HelperChainDirect) != direct.has_value())
    co_return makeError(StatusCode::kTokenMismatch);
  // validate() was completed against the fixed accepted record before entry.
  auto plan = EcRepairPlan::create(a.plan);
  CO_RETURN_ON_ERROR(plan);
  EcRepairNativeBindings bindings;
  for (size_t n = 0; n < 10; ++n) {
    const auto &s = a.sources[r.intent.selection.sourceOrder[n]];
    auto v = route(*mgmtd_, s.endpoint());
    CO_RETURN_ON_ERROR(v);
    auto q = makeEcReadBlockRequest(
        {s.fragment.identity, s.fragment.operation, s.endpoint().controlEndpoint(), s.fragment.integrity},
        a.pipelineReads[n],
        *v,
        0);
    CO_RETURN_ON_ERROR(q);
    bindings.sources[n] = std::move(*q);
  }
  size_t index = 0;
  for (size_t n = 0; n < 12; ++n)
    if (r.intent.replacementMask & (uint16_t{1} << n)) {
      auto v = route(*mgmtd_, a.targets[n].endpoint());
      CO_RETURN_ON_ERROR(v);
      bindings.targets[index++] = {access(a.targets[n], *v), a.writes[n]};
    }
  auto transport = NativeEcRepairTransport::create(
      *plan, storage_, std::move(bindings), a.helpers, observation, std::move(direct), c.transport);
  CO_RETURN_ON_ERROR(transport);
  auto mode = r.intent.mode == meta::EcFileRepairMode::CentralSerial    ? EcRepairMode::CentralSerial
              : r.intent.mode == meta::EcFileRepairMode::ClientPipeline ? EcRepairMode::ClientPipeline
                                                                        : EcRepairMode::HelperChain;
  {
    EcRepairObservation::Scope selected(observation, EcRepairPoint::SelectedRepair);
    auto done = co_await EcRepairPipeline::run(
        *plan, *transport, mode, {c.deadline, c.cancellation}, executor_, observation,
        r.intent.mode == meta::EcFileRepairMode::HelperChainDirect ? EcRepairDelivery::HelperDirect
                                                                : EcRepairDelivery::ClientAppend);
    CO_RETURN_ON_ERROR(done);
    selected.success();
  }
  // The selected erasures use the requested real strategy; surviving fragments
  // are separately copied into fresh allocations. This is deliberately visible.
  for (size_t n = 0; n < 12; ++n)
    if (!(r.intent.replacementMask & (uint16_t{1} << n))) {
      EcRepairObservation::Scope copied(observation, EcRepairPoint::HealthyCopy);
      CO_RETURN_ON_ERROR(co_await copyOne(a.sources[n], a.targets[n], a.reads[n], a.writes[n], c, observation));
      copied.success();
    }
  co_return Void{};
}
EcTreeRepairOutcome EcFileRepairClient::execute(EcTreeRepairJournal &j,
                                               EcStripeControl c,
                                               uint8_t action,
                                               bool collectMetrics) {
  EcTreeRepairOutcome out;
  std::optional<EcRepairObservation> observation;
  if (collectMetrics) observation.emplace();
  auto *metrics = observation ? &*observation : nullptr;
  bool journalStateObserved = false, hadState = false;
  uint64_t priorSequence = 0;
  // Snapshot BEFORE moving the return value, including Busy/check/query/close.
  // Every instrumented scope has ended before these return sites.
  auto finish = [&] {
    if (metrics) {
      out.metrics = metrics->snapshot();
      out.metrics.action = action;
      out.metrics.journalStateObserved = journalStateObserved;
      out.metrics.hadJournalState = hadState;
      out.metrics.priorJournalSequence = priorSequence;
      out.metrics.configuredWindow = j.record().intent.selection.maxBlocksInFlight;
      out.metrics.blockActorsApplicable = j.record().intent.mode != meta::EcFileRepairMode::CentralSerial;
      out.metrics.cancellationRequested = c.cancellation.isCancellationRequested();
      out.metrics.deadlineExpired = std::chrono::steady_clock::now() >= c.deadline;
    }
    return std::move(out);
  };
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock) {
    out.failure = Status(StorageClientCode::kResourceBusy);
    return finish();
  }
  journalStateObserved = true;
  hadState = j.latest().has_value();
  priorSequence = hadState ? j.latest()->sequence : 0;
  if (hadState) out.progress = j.latest()->progress;
  bool invoked = false;
  auto fail = [&](Status s) {
    out.failure = std::move(s);
    return finish();
  };
  try {
    auto ok = check(j, c);
    if (!ok) return fail(std::move(ok.error()));
    const auto &r = j.record();
    auto state = j.latest().value_or(EcTreeRepairState{});
    auto remember = [&](const auto &rsp, Uuid id) -> Result<Void> {
      if (rsp.requestId != id) return makeError(StatusCode::kTokenMismatch);
      state.issued = state.issued || rsp.progress.record.has_value();
      state.progress = rsp.progress;
      RETURN_ON_ERROR(state.validate(r, nullptr));
      out.progress = rsp.progress;
      out.revalidated = true;
      auto saved = observeResult(metrics, EcRepairPoint::Journal, [&] { return j.append(state); });
      if (!saved) return makeError(TransactionCode::kMaybeCommitted, "repair observation not durably journaled");
      return Void{};
    };
    meta::QueryEcFileRepairReq q;
    request(q, r, r.queryRequest);
    auto observed = observeResult(
        metrics, EcRepairPoint::Query, [&] { return blockingWait(meta_->queryEcFileRepair(std::move(q))); }, true);
    if (!observed) return fail(std::move(observed.error()));
    ok = remember(*observed, r.queryRequest);
    if (!ok) return fail(std::move(ok.error()));
    if (action == 0) return finish();
    if (action == 2) {
      if (!state.progress.record) return fail(Status(MetaCode::kNotFound, "missing repair is not cleanup completion"));
      meta::CloseEcFileRepairDebtReq close;
      request(close, r, r.closeRequest);
      close.outputRevocation = r.outputRevocation;
      close.sourceRevocation = r.sourceRevocation;
      invoked = true;
      auto closed = observeResult(
          metrics, EcRepairPoint::CloseDebt, [&] { return blockingWait(meta_->closeEcFileRepairDebt(std::move(close))); }, true);
      if (!closed) return fail(std::move(closed.error()));
      ok = remember(*closed, r.closeRequest);
      if (!ok) return fail(std::move(ok.error()));
      return finish();
    }
    if (!state.progress.record) {
      state.issued = true;
      ok = observeResult(metrics, EcRepairPoint::Journal, [&] { return j.append(state); });
      if (!ok) return fail(std::move(ok.error()));
      meta::BeginEcFileRepairReq begin;
      request(begin, r, r.intent.request);
      invoked = true;
      auto accepted = observeResult(
          metrics, EcRepairPoint::Begin, [&] { return blockingWait(meta_->beginEcFileRepair(std::move(begin))); }, true);
      if (!accepted) return fail(std::move(accepted.error()));
      ok = remember(*accepted, r.intent.request);
      if (!ok) return fail(std::move(ok.error()));
    }
    if (!state.progress.record) return fail(Status(StatusCode::kDataCorruption));
    if (state.progress.record->state == meta::EcFileRepairState::Published) return finish();
    if (state.progress.record->state != meta::EcFileRepairState::Planned) return fail(Status(StatusCode::kTokenStale));
    if (!state.dataComplete && !state.progress.outputClosing) {
      std::optional<meta::EcFileRepairAccess> access;
      std::optional<EcHelperDirectDelegation> direct;
      invoked = true;
      if (r.intent.mode == meta::EcFileRepairMode::HelperChainDirect) {
        meta::PrepareEcFileRepairDirectReq prepare;
        request(prepare, r, r.prepareRequest);
        auto response = observeResult(metrics, EcRepairPoint::Prepare,
            [&] { return blockingWait(meta_->prepareEcFileRepairDirect(std::move(prepare))); }, true);
        if (!response) return fail(std::move(response.error()));
        ok = remember(*response, r.prepareRequest);
        if (!ok) return fail(std::move(ok.error()));
        if (state.progress.record && state.progress.record->state == meta::EcFileRepairState::Published) return finish();
        if (response->access) {
          access = std::move(response->access->base);
          direct = std::move(response->access->delegation);
        }
      } else {
        meta::AdvanceEcFileRepairReq prepare;
        request(prepare, r, r.prepareRequest);
        prepare.action = meta::EcFileRepairAdvance::Prepare;
        auto response = observeResult(metrics, EcRepairPoint::Prepare,
            [&] { return blockingWait(meta_->advanceEcFileRepair(std::move(prepare))); }, true);
        if (!response) return fail(std::move(response.error()));
        ok = remember(*response, r.prepareRequest);
        if (!ok) return fail(std::move(ok.error()));
        if (state.progress.record && state.progress.record->state == meta::EcFileRepairState::Published) return finish();
        access = std::move(response->access);
      }
      if (!access || !state.progress.record) return fail(Status(StatusCode::kDataCorruption));
      auto plan = validate(*access, r, *state.progress.record);
      if (!plan) return fail(std::move(plan.error()));
      if (direct) {
        const auto mask = static_cast<uint16_t>((uint32_t{1} << (*plan)->blockCount()) - 1);
        if (direct->directGrant.claims.blockMask != mask) return fail(Status(StatusCode::kTokenMismatch));
        // Public shape/exact-role binding only. Storage authenticates every MAC.
        ok = validateEcHelperDirectDelegation(**plan, *direct, 0);
        if (!ok) return fail(std::move(ok.error()));
      }
      auto moved = blockingWait(transfer(std::move(*access), r, c, metrics, std::move(direct)));
      if (!moved) return fail(std::move(moved.error()));
      state.dataComplete = true;
      ok = observeResult(metrics, EcRepairPoint::Journal, [&] { return j.append(state); });
      if (!ok) return fail(Status(TransactionCode::kMaybeCommitted, "fixed targets require reconciliation"));
    }
    ok = check(j, c);
    if (!ok) return fail(std::move(ok.error()));
    meta::AdvanceEcFileRepairReq publish;
    request(publish, r, r.publishRequest);
    publish.action = meta::EcFileRepairAdvance::Publish;
    invoked = true;
    auto result = observeResult(
        metrics, EcRepairPoint::Publish, [&] { return blockingWait(meta_->advanceEcFileRepair(std::move(publish))); }, true);
    if (!result) return fail(std::move(result.error()));
    ok = remember(*result, r.publishRequest);
    if (!ok) return fail(std::move(ok.error()));
    return finish();
  } catch (...) {
    return fail(Status(invoked ? TransactionCode::kMaybeCommitted : StatusCode::kIOError));
  }
}
EcTreeRepairOutcome EcFileRepairClient::repair(EcTreeRepairJournal &j, EcStripeControl c, bool collectMetrics) {
  return execute(j, c, 1, collectMetrics);
}
EcTreeRepairOutcome EcFileRepairClient::query(EcTreeRepairJournal &j, EcStripeControl c, bool collectMetrics) {
  return execute(j, c, 0, collectMetrics);
}
EcTreeRepairOutcome EcFileRepairClient::closeDebt(EcTreeRepairJournal &j, EcStripeControl c, bool collectMetrics) {
  return execute(j, c, 2, collectMetrics);
}
}  // namespace hf3fs::client::ec
