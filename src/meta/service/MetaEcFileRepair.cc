#include "meta/store/EcTerminalEvidence.h"
#include <chrono>

#include "MetaOperator.h"
#include "client/storage/EcRmwTransport.h"
#include "meta/components/EcRmwPlanIssuer.h"
#include "meta/components/EcRmwPublicationVerifier.h"
#include "meta/store/EcFileExecutionCatalog.h"
#include "meta/store/EcFileRepairCatalog.h"
#include "meta/store/detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcFileTreeTxnBudget;
using Control = storage::client::EcRequestControl;
using namespace ec_file_mutation_detail;
EcOwner ownerOf(const ReqBase &r) { return {r.user.uid, r.client.uuid}; }
uint64_t wallSeconds() {
  return uint64_t(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
Control controlFor(const Config &c) {
  Control r;
  r.transport = Control::TransportPolicy::TcpOnly;
  r.deadline = std::chrono::steady_clock::now() + c.ec_verify_timeout().asMs();
  return r;
}
Result<Void> ready(const Control &c) {
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
template <class R, class Fn>
CoTryTask<R> transaction(kv::IKVEngine &db, Fn fn) {
  bool committing = false;
  try {
    auto raw = db.createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    Tx tx(*raw, Tx::Profile::Repair);
    auto result = co_await fn(tx);
    CO_RETURN_ON_ERROR(result);
    committing = true;
    CO_RETURN_ON_ERROR(co_await tx.commit());
    co_return std::move(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(committing ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
EcTreeSourcePinIntent sourceIntent(const EcFileChildRecord &c) {
  EcTreeSourcePinIntent p;
  p.object = c.intent.object;
  p.owner = c.owner;
  p.session = c.session;
  p.parent = c.intent.parent;
  p.child = c.intent.child;
  p.pin = c.intent.sourcePin;
  p.root = c.sourceRoot;
  p.sequence = c.sourceSequence;
  p.epoch = c.epoch;
  p.lengthAtPlan = c.lengthAtPlan;
  p.slot = c.source;
  return p;
}
CoTryTask<std::optional<EcFileRepairRecord>> retained(Tx &tx, const EcFileRepairReq &req) {
  auto r = co_await EcFileRepairCatalog::query(tx, ownerOf(req), req.intent.object, req.intent.operation);
  CO_RETURN_ON_ERROR(r);
  if (*r && !same((**r).intent, req.intent)) co_return makeError(StatusCode::kTokenMismatch);
  co_return r;
}
CoTryTask<EcFileRepairRsp> observe(Tx &tx, const EcFileRepairReq &req) {
  auto r = co_await retained(tx, req);
  CO_RETURN_ON_ERROR(r);
  EcFileRepairRsp out;
  out.requestId = req.uuid;
  out.progress.record = *r;
  if (!*r) co_return out;
  const auto &i = req.intent;
  auto raw = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, i.object, i.child));
  CO_RETURN_ON_ERROR(raw);
  if (*raw) {
    auto e = co_await EcFileExecutionCatalog::get(tx, ownerOf(req), i.object, i.child);
    CO_RETURN_ON_ERROR(e);
    if (e->record.ownerKind != EcFileExecutionOwner::Repair) co_return makeError(StatusCode::kDataCorruption);
    out.progress.outputClosing =
        e->record.state == EcFileExecutionState::Closing || e->record.state == EcFileExecutionState::Drained;
    out.progress.outputDrained = e->record.state == EcFileExecutionState::Drained ||
                                 e->record.state == EcFileExecutionState::Published ||
                                 e->record.state == EcFileExecutionState::Aborted;
    if (((**r).state == EcFileRepairState::Published) != (e->record.state == EcFileExecutionState::Published))
      co_return makeError(StatusCode::kDataCorruption);
  } else {
    if ((**r).state == EcFileRepairState::Published) co_return makeError(StatusCode::kDataCorruption);
    out.progress.outputDrained = (**r).state == EcFileRepairState::Aborted;
  }
  auto source = co_await EcTreeSourcePinCatalog::query(tx, sourceIntent((**r).child));
  CO_RETURN_ON_ERROR(source);
  out.progress.sourceReleased = source->state == EcTreeSourcePinState::Released;
  if (out.progress.sourceReleased && !out.progress.outputDrained) co_return makeError(StatusCode::kDataCorruption);
  co_return out;
}
CoTryTask<EcFileRepairDirectRsp> observeDirect(Tx &tx, const EcFileRepairReq &req) {
  auto observed = co_await observe(tx, req);
  CO_RETURN_ON_ERROR(observed);
  EcFileRepairDirectRsp out;
  out.requestId = observed->requestId;
  out.progress = std::move(observed->progress);
  co_return out;
}
CoTryTask<Void> closeDebt(kv::IKVEngine &db,
                          storage::client::StorageClient &storage,
                          const EcV2Coordinator &coordinator,
                          const CloseEcFileRepairDebtReq &req,
                          const Control &control) {
  const auto owner = ownerOf(req);
  const auto &i = req.intent;
  // Logical fencing and missing-execution observation share the transaction.
  // On an existing candidate, startCancelClosing fences via the repair typed resolver.
  auto child = co_await transaction<EcFileRepairRecord>(db, [&](Tx &tx) -> CoTryTask<EcFileRepairRecord> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r) co_return makeError(MetaCode::kNotFound, "missing repair is not debt completion");
    if ((**r).state == EcFileRepairState::Planned) {
      auto aborted = co_await EcFileRepairCatalog::abort(tx, owner, i.object, i.operation);
      CO_RETURN_ON_ERROR(aborted);
      co_return std::move(*aborted);
    }
    co_return std::move(**r);
  });
  CO_RETURN_ON_ERROR(child);
  auto candidate = co_await transaction<std::optional<EcV2DrainRecord>>(
      db,
      [&](Tx &tx) -> CoTryTask<std::optional<EcV2DrainRecord>> {
        auto r = co_await retained(tx, req);
        CO_RETURN_ON_ERROR(r);
        if (!*r || (**r).state == EcFileRepairState::Planned) co_return makeError(StatusCode::kTokenStale);
        auto raw = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, i.object, i.child));
        CO_RETURN_ON_ERROR(raw);
        if (!*raw) {
          if ((**r).state != EcFileRepairState::Aborted) co_return makeError(StatusCode::kDataCorruption);
          co_return std::nullopt;
        }
        auto e = co_await EcFileExecutionCatalog::get(tx, owner, i.object, i.child);
        CO_RETURN_ON_ERROR(e);
        if (e->record.ownerKind != EcFileExecutionOwner::Repair) co_return makeError(StatusCode::kDataCorruption);
        if (e->record.state == EcFileExecutionState::Published || e->record.state == EcFileExecutionState::Aborted) {
          if (!e->record.drain) co_return makeError(StatusCode::kDataCorruption);
          co_return e->record.drain;
        }
        const auto revoke = e->record.drain ? e->record.drain->identity.revocationId : req.outputRevocation;
        auto closing = co_await EcFileExecutionCatalog::startCancelClosing(tx,
                                                                           owner,
                                                                           i.object,
                                                                           i.child,
                                                                           coordinator.authority(),
                                                                           revoke);
        CO_RETURN_ON_ERROR(closing);
        co_return std::optional<EcV2DrainRecord>{std::move(*closing)};
      });
  CO_RETURN_ON_ERROR(candidate);
  if (*candidate) {
    const auto frozen = **candidate;
    for (size_t n = 0; n < frozen.identity.endpoints.count; ++n) {
      if (ecTerminalAt(frozen, n)) continue;
      auto retired = co_await transaction<EcV2DrainRecord>(db, [&](Tx &tx) {
        return EcFileExecutionCatalog::recordRetirement(tx, owner, i.object, i.child, n, coordinator.controlKey());
      });
      CO_RETURN_ON_ERROR(retired);
      if (ecTerminalAt(*retired, n)) continue;
      CO_RETURN_ON_ERROR(ready(control));
      auto request = EcV2DrainCatalog::makeRequest(frozen,
                                                   n,
                                                   storage::EcScopeControlAction::Revoke,
                                                   coordinator.controlKey(),
                                                   wallSeconds());
      CO_RETURN_ON_ERROR(request);
      auto ack = co_await storage.revokeEcScope(*request);
      CO_RETURN_ON_ERROR(ack);
      CO_RETURN_ON_ERROR(storage::verifyEcScopeControlAck(coordinator.controlKey(), *ack, *request));
      if (ack->claims.state != storage::EcScopeControlState::Drained)
        co_return makeError(StorageClientCode::kResourceBusy);
      CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &tx) -> CoTryTask<Void> {
        auto stored = co_await EcFileExecutionCatalog::recordAck(tx,
                                                                 owner,
                                                                 i.object,
                                                                 i.child,
                                                                 n,
                                                                 coordinator.controlKey(),
                                                                 *request,
                                                                 *ack);
        CO_RETURN_ON_ERROR(stored);
        co_return Void{};
      }));
    }
    CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &tx) -> CoTryTask<Void> {
      auto done = co_await EcFileExecutionCatalog::finishDrain(tx, owner, i.object, i.child, coordinator.controlKey());
      CO_RETURN_ON_ERROR(done);
      if (done->record.state != EcFileExecutionState::Aborted && done->record.state != EcFileExecutionState::Published)
        co_return makeError(StatusCode::kTokenStale);
      co_return Void{};
    }));
  }
  // Only after candidate/worker T2 (or a fenced never-issued candidate) may the
  // independently retained old-source scope stop accepting its own requests.
  const auto pin = sourceIntent(child->child);
  auto source = co_await transaction<EcV2DrainRecord>(db, [&](Tx &tx) {
    return EcTreeSourcePinCatalog::startClosing(tx, pin, coordinator.authority(), req.sourceRevocation);
  });
  CO_RETURN_ON_ERROR(source);
  for (size_t n = 0; n < source->identity.endpoints.count; ++n) {
    if (ecTerminalAt(*source, n)) continue;
    auto retired = co_await transaction<EcV2DrainRecord>(db, [&](Tx &tx) {
      return EcTreeSourcePinCatalog::recordRetirement(tx, pin, n, coordinator.controlKey());
    });
    CO_RETURN_ON_ERROR(retired);
    if (ecTerminalAt(*retired, n)) continue;
    CO_RETURN_ON_ERROR(ready(control));
    auto request = EcV2DrainCatalog::makeRequest(*source,
                                                 n,
                                                 storage::EcScopeControlAction::Revoke,
                                                 coordinator.controlKey(),
                                                 wallSeconds());
    CO_RETURN_ON_ERROR(request);
    auto ack = co_await storage.revokeEcScope(*request);
    CO_RETURN_ON_ERROR(ack);
    CO_RETURN_ON_ERROR(storage::verifyEcScopeControlAck(coordinator.controlKey(), *ack, *request));
    if (ack->claims.state != storage::EcScopeControlState::Drained)
      co_return makeError(StorageClientCode::kResourceBusy);
    CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &tx) -> CoTryTask<Void> {
      auto stored = co_await EcTreeSourcePinCatalog::recordAck(tx, pin, n, coordinator.controlKey(), *request, *ack);
      CO_RETURN_ON_ERROR(stored);
      co_return Void{};
    }));
  }
  CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &tx) -> CoTryTask<Void> {
    auto released = co_await EcTreeSourcePinCatalog::finishRelease(tx, pin, coordinator.controlKey());
    CO_RETURN_ON_ERROR(released);
    co_return Void{};
  }));
  co_return Void{};
}
}  // namespace
CoTryTask<EcFileRepairRsp> MetaOperator::beginEcFileRepair(BeginEcFileRepairReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await transaction<EcFileRepairRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileRepairRsp> {
    auto r = co_await EcFileRepairCatalog::begin(tx, req.intent);
    CO_RETURN_ON_ERROR(r);
    co_return co_await observe(tx, req);
  });
}
CoTryTask<EcFileRepairRsp> MetaOperator::queryEcFileRepair(QueryEcFileRepairReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await transaction<EcFileRepairRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
}
CoTryTask<EcFileRepairRsp> MetaOperator::advanceEcFileRepair(AdvanceEcFileRepairReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  const auto &i = req.intent;
  const auto owner = ownerOf(req);
  if (req.action == EcFileRepairAdvance::Prepare) {
    auto prepared = co_await prepareEcFileRepair(req);
    CO_RETURN_ON_ERROR(prepared);
    EcFileRepairRsp out;
    out.requestId = prepared->requestId;
    out.progress = std::move(prepared->progress);
    if (prepared->access) out.access = std::move(prepared->access->base);
    co_return out;
  }
  auto before = co_await transaction<EcFileRepairRecord>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileRepairRecord> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r) co_return makeError(MetaCode::kNotFound);
    co_return std::move(**r);
  });
  CO_RETURN_ON_ERROR(before);
  if (before->state == EcFileRepairState::Aborted) co_return makeError(StatusCode::kTokenStale);
  if (before->state == EcFileRepairState::Published)
    co_return co_await transaction<EcFileRepairRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
  if (req.action == EcFileRepairAdvance::Publish) {
    auto proof = co_await ecRmwVerifier_->verify(i.object, owner, i.child, controlFor(config_));
    CO_RETURN_ON_ERROR(proof);
    CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &tx) -> CoTryTask<Void> {
      auto done = co_await EcFileRepairCatalog::publish(tx, owner, i.object, i.operation, **proof);
      CO_RETURN_ON_ERROR(done);
      co_return Void{};
    }));
    co_return co_await transaction<EcFileRepairRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
  }
  co_return makeError(StatusCode::kInvalidArg);
}
CoTryTask<EcFileRepairDirectRsp> MetaOperator::prepareEcFileRepairDirect(PrepareEcFileRepairDirectReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await prepareEcFileRepair(req);
}
CoTryTask<EcFileRepairDirectRsp> MetaOperator::prepareEcFileRepair(const EcFileRepairReq &req) {
  // The public entry already authenticated the session, normalized owner and
  // validated mode/action. Both Prepare protocols share one issuance sequence.
  const auto &i = req.intent;
  const auto owner = ownerOf(req);
  auto before = co_await transaction<EcFileRepairRecord>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileRepairRecord> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r) co_return makeError(MetaCode::kNotFound);
    co_return std::move(**r);
  });
  CO_RETURN_ON_ERROR(before);
  if (before->state == EcFileRepairState::Aborted) co_return makeError(StatusCode::kTokenStale);
  if (before->state == EcFileRepairState::Published)
    co_return co_await transaction<EcFileRepairDirectRsp>(*kvEngine_, [&](Tx &tx) { return observeDirect(tx, req); });
  CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &tx) -> CoTryTask<Void> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r || (**r).state != EcFileRepairState::Planned) co_return makeError(StatusCode::kTokenStale);
    auto old = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, i.object, i.child));
    CO_RETURN_ON_ERROR(old);
    if (!*old) {
      auto pool = ecV2Coordinator_->pool();
      CO_RETURN_ON_ERROR(pool);
      auto reserved = co_await EcFileExecutionCatalog::reserveExecution(tx,
                                                                        owner,
                                                                        i.object,
                                                                        i.child,
                                                                        *pool,
                                                                        0,
                                                                        EcFileExecutionOwner::Repair);
      CO_RETURN_ON_ERROR(reserved);
    }
    auto bound = co_await EcFileExecutionCatalog::bindRepairOutput(tx, owner, i.object, i.child);
    CO_RETURN_ON_ERROR(bound);
    co_return Void{};
  }));
  // This issuer commits ECFE and ECSP issuance before any signature. Neither
  // its internal RMW Execute MAC nor install MAC is returned to this client.
  auto issued = co_await ecRmwIssuer_->issue(i.object, owner, i.child);
  CO_RETURN_ON_ERROR(issued);
  if (issued->observed.record.ownerKind != EcFileExecutionOwner::Repair || !issued->reads || !issued->repairReads ||
      !issued->writes || !issued->observed.record.allocations)
    co_return makeError(StatusCode::kDataCorruption);
  auto output = co_await transaction<EcFileRepairDirectRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileRepairDirectRsp> {
    auto out = co_await observeDirect(tx, req);
    CO_RETURN_ON_ERROR(out);
    if (!out->progress.record || out->progress.record->state != EcFileRepairState::Planned)
      co_return makeError(StatusCode::kTokenStale);
    auto plan = co_await EcFileRepairCatalog::repairPlan(tx, owner, i.object, i.child);
    CO_RETURN_ON_ERROR(plan);
    auto source = co_await EcTreeSourcePinCatalog::query(tx, sourceIntent(out->progress.record->child));
    CO_RETURN_ON_ERROR(source);
    EcFileRepairAccess access;
    access.plan = (*plan)->input();
    access.sources = source->allocations;
    access.targets = *issued->observed.record.allocations;
    access.reads = *issued->reads;
    access.pipelineReads = *issued->repairReads;
    access.writes = *issued->writes;
    out->access.emplace();
    out->access->base = std::move(access);
    co_return std::move(*out);
  });
  CO_RETURN_ON_ERROR(output);
  if (i.mode == EcFileRepairMode::HelperChain || i.mode == EcFileRepairMode::HelperChainDirect) {
    EcV2RepairPlanRecord helper;
    helper.object = i.object;
    helper.operation = i.child;
    helper.owner = owner;
    helper.selection = i.selection;
    helper.plan = output->access->base.plan;
    auto compiled = storage::EcRepairPlan::create(helper.plan);
    CO_RETURN_ON_ERROR(compiled);
    helper.digest = (*compiled)->digest();
    auto grants = ecV2Coordinator_->issueRepairHelpers(helper);
    CO_RETURN_ON_ERROR(grants);
    if (!*grants)
      co_return makeError(StatusCode::kNotImplemented, "native helper key is unavailable; no centralized fallback");
    output->access->base.helpers = std::move(*grants);
    if (i.mode == EcFileRepairMode::HelperChainDirect) {
      if (!issued->repairAppends || !issued->repairQueries) co_return makeError(StatusCode::kDataCorruption);
      auto direct = ecV2Coordinator_->issueRepairDirect(helper, *issued->repairAppends, *issued->repairQueries);
      CO_RETURN_ON_ERROR(direct);
      output->access->delegation = std::move(*direct);
    }
  }
  co_return std::move(*output);
}
CoTryTask<EcFileRepairRsp> MetaOperator::closeEcFileRepairDebt(CloseEcFileRepairDebtReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await closeDebt(*kvEngine_, *ecRmwStorage_, *ecV2Coordinator_, req, controlFor(config_)));
  co_return co_await transaction<EcFileRepairRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
}
}  // namespace hf3fs::meta::server
