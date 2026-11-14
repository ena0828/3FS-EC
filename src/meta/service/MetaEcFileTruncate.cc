#include "meta/store/EcTerminalEvidence.h"
#include <chrono>

#include "MetaOperator.h"
#include "client/storage/EcRmwTransport.h"
#include "meta/components/EcRmwPlanIssuer.h"
#include "meta/components/EcRmwPublicationVerifier.h"
#include "meta/store/EcFileTruncateCatalog.h"
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
  r.transport = c.ec_storage_transport() == "rdma" ? Control::TransportPolicy::RdmaOnly
                                                               : Control::TransportPolicy::TcpOnly;
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
    Tx tx(*raw, Tx::Profile::Rmw);
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
CoTryTask<std::optional<EcFileTruncateRecord>> retained(Tx &tx, const EcFileTruncateReq &req) {
  auto session = co_await EcFileSessionCatalog::get(tx, req.intent.object, req.intent.session, ownerOf(req));
  CO_RETURN_ON_ERROR(session);
  if (!(session->intent.rights & kEcSessionWrite)) co_return makeError(MetaCode::kNoPermission);
  auto r = co_await EcFileTruncateCatalog::query(tx, ownerOf(req), req.intent.object, req.intent.operation);
  CO_RETURN_ON_ERROR(r);
  if (*r && (!same((**r).intent, req.intent) || (**r).birth != session->intent.birth))
    co_return makeError(StatusCode::kTokenMismatch, "truncate replay changed permanent intent/session");
  co_return r;
}
CoTryTask<EcFileTruncateRsp> observe(Tx &tx, const EcFileTruncateReq &req) {
  auto r = co_await retained(tx, req);
  CO_RETURN_ON_ERROR(r);
  EcFileTruncateRsp out;
  out.requestId = req.uuid;
  out.progress.intent = req.intent;
  if (!*r) co_return out;
  const auto &record = **r;
  EcFileTruncateObservation o;
  o.birth = record.birth;
  o.state = record.state;
  o.fencedRoot = record.fencedRoot;
  o.tailRequired = record.tail.has_value();
  o.publishedRoot = record.publishedRoot;
  o.outputDrained = !record.tail;
  o.sourceReleased = !record.tail;
  if (record.tail) {
    auto raw = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, req.intent.object, req.intent.child));
    CO_RETURN_ON_ERROR(raw);
    if (*raw) {
      auto e = co_await EcFileExecutionCatalog::get(tx, ownerOf(req), req.intent.object, req.intent.child);
      CO_RETURN_ON_ERROR(e);
      if (e->record.ownerKind != EcFileExecutionOwner::TruncateTail) co_return makeError(StatusCode::kDataCorruption);
      o.outputDrained = e->record.state == EcFileExecutionState::Drained ||
                        e->record.state == EcFileExecutionState::Published ||
                        e->record.state == EcFileExecutionState::Aborted;
      if ((record.state == EcFileTruncateState::Published) != (e->record.state == EcFileExecutionState::Published))
        co_return makeError(StatusCode::kDataCorruption, "truncate publication/execution differs");
    } else {
      if (record.state == EcFileTruncateState::Published) co_return makeError(StatusCode::kDataCorruption);
      // Aborted child plus this normal missing-ECFE conflict read excludes any
      // issuer. It is not a fabricated remote ACK for an existing execution.
      o.outputDrained = record.state == EcFileTruncateState::Aborted;
    }
    auto pin = co_await EcTreeSourcePinCatalog::query(tx, sourceIntent(*record.tail));
    CO_RETURN_ON_ERROR(pin);
    o.sourceReleased = pin->state == EcTreeSourcePinState::Released;
    if (o.sourceReleased && !o.outputDrained) co_return makeError(StatusCode::kDataCorruption);
  }
  out.progress.observed = std::move(o);
  co_return out;
}
Result<net::Address> workerAddress(const EcV2Coordinator &coordinator,
                                   client::ICommonMgmtdClient &mgmtd,
                                   const EcV2PhysicalEndpoint &worker,
                                   Control::TransportPolicy transport) {
  if (!storage::client::isExplicitEcTransportPolicy(transport))
    return makeError(StatusCode::kInvalidArg);
  const auto required = transport == Control::TransportPolicy::RdmaOnly ? net::Address::RDMA
                                                                         : net::Address::TCP;
  RETURN_ON_ERROR(coordinator.route(worker));
  const auto routes = mgmtd.getRoutingInfo();
  if (!routes || !routes->raw()) return makeError(MgmtdClientCode::kRoutingInfoNotReady);
  const auto *node = routes->raw()->getNode(worker.placement.node);
  if (!node || node->type != flat::NodeType::STORAGE) return makeError(StorageClientCode::kRoutingError);
  for (const auto &group : node->app.serviceGroups)
    if (group.services.contains("StorageSerde"))
      for (const auto &address : group.endpoints)
        if (address.type == required) return address;
  return makeError(StorageClientCode::kRoutingError, "truncate worker has no StorageSerde endpoint for the selected transport");
}
CoTryTask<Void> closeDebt(kv::IKVEngine &db,
                          storage::client::StorageClient &storage,
                          const EcV2Coordinator &coordinator,
                          const CloseEcFileTruncateDebtReq &req,
                          const Control &control) {
  const auto owner = ownerOf(req);
  const auto &i = req.intent;
  // Logical fencing and missing-execution observation share the transaction.
  // On an existing candidate, startCancelClosing fences via W3's typed resolver.
  auto child = co_await transaction<EcFileTruncateRecord>(db, [&](Tx &tx) -> CoTryTask<EcFileTruncateRecord> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r) co_return makeError(MetaCode::kNotFound, "missing truncate is not debt completion");
    if ((**r).state == EcFileTruncateState::Planned) {
      auto aborted = co_await EcFileTruncateCatalog::abort(tx, owner, i.object, i.operation);
      CO_RETURN_ON_ERROR(aborted);
      co_return std::move(*aborted);
    }
    co_return std::move(**r);
  });
  CO_RETURN_ON_ERROR(child);
  if (!child->tail) co_return Void{};
  auto candidate = co_await transaction<std::optional<EcV2DrainRecord>>(
      db,
      [&](Tx &tx) -> CoTryTask<std::optional<EcV2DrainRecord>> {
        auto r = co_await retained(tx, req);
        CO_RETURN_ON_ERROR(r);
        if (!*r || (**r).state == EcFileTruncateState::Planned) co_return makeError(StatusCode::kTokenStale);
        auto raw = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, i.object, i.child));
        CO_RETURN_ON_ERROR(raw);
        if (!*raw) {
          if ((**r).state != EcFileTruncateState::Aborted) co_return makeError(StatusCode::kDataCorruption);
          co_return std::nullopt;
        }
        auto e = co_await EcFileExecutionCatalog::get(tx, owner, i.object, i.child);
        CO_RETURN_ON_ERROR(e);
        if (e->record.ownerKind != EcFileExecutionOwner::TruncateTail) co_return makeError(StatusCode::kDataCorruption);
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
  const auto pin = sourceIntent(*child->tail);
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

CoTryTask<EcFileTruncateRsp> MetaOperator::beginEcFileTruncate(BeginEcFileTruncateReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await transaction<EcFileTruncateRsp>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileTruncateRsp> {
    auto accepted = co_await EcFileTruncateCatalog::begin(tx, req.intent);
    CO_RETURN_ON_ERROR(accepted);
    co_return co_await observe(tx, req);
  });
}
CoTryTask<EcFileTruncateRsp> MetaOperator::queryEcFileTruncate(QueryEcFileTruncateReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await transaction<EcFileTruncateRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
}
CoTryTask<EcFileTruncateRsp> MetaOperator::advanceEcFileTruncate(AdvanceEcFileTruncateReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  const auto owner = ownerOf(req);
  const auto &i = req.intent;
  const auto control = controlFor(config_);
  auto before = co_await transaction<EcFileTruncateRecord>(*kvEngine_, [&](Tx &tx) -> CoTryTask<EcFileTruncateRecord> {
    auto r = co_await retained(tx, req);
    CO_RETURN_ON_ERROR(r);
    if (!*r) co_return makeError(MetaCode::kNotFound);
    co_return std::move(**r);
  });
  CO_RETURN_ON_ERROR(before);
  if (before->state == EcFileTruncateState::Aborted)
    co_return makeError(StatusCode::kTokenStale, "truncate was fenced");
  if (before->state == EcFileTruncateState::Planned && !before->tail) {
    CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &tx) -> CoTryTask<Void> {
      auto result = co_await EcFileTruncateCatalog::publishWithoutTail(tx, owner, i.object, i.operation);
      CO_RETURN_ON_ERROR(result);
      co_return Void{};
    }));
  } else if (before->state == EcFileTruncateState::Planned) {
    auto execution = co_await transaction<EcFileExecutionObservation>(
        *kvEngine_,
        [&](Tx &tx) -> CoTryTask<EcFileExecutionObservation> {
          auto raw = co_await tx.get(idKey(kv::KeyPrefix::EcFileExecution, i.object, i.child));
          CO_RETURN_ON_ERROR(raw);
          if (*raw) co_return co_await EcFileExecutionCatalog::get(tx, owner, i.object, i.child);
          auto pool = ecV2Coordinator_->pool();
          CO_RETURN_ON_ERROR(pool);
          co_return co_await EcFileExecutionCatalog::reserveExecution(tx,
                                                                      owner,
                                                                      i.object,
                                                                      i.child,
                                                                      *pool,
                                                                      0,
                                                                      EcFileExecutionOwner::TruncateTail);
        });
    CO_RETURN_ON_ERROR(execution);
    if (execution->record.ownerKind != EcFileExecutionOwner::TruncateTail)
      co_return makeError(StatusCode::kTokenMismatch);
    bool completed = true;
    if (execution->record.state == EcFileExecutionState::Reserved ||
        execution->record.state == EcFileExecutionState::Bound) {
      auto issued = co_await ecRmwIssuer_->issue(i.object, owner, i.child);
      CO_RETURN_ON_ERROR(issued);
      const auto &plan = issued->observed.plan->input();
      if (plan.action != storage::EcRmwAction::TruncateTail || plan.parentId != i.operation ||
          plan.operationId != i.child || plan.patchLength || plan.patchOffset)
        co_return makeError(StatusCode::kDataCorruption);
      auto address =
          workerAddress(*ecV2Coordinator_, *mgmtd_,
                        issued->observed.record.candidates[plan.workerIndex].endpoint, control.transport);
      CO_RETURN_ON_ERROR(address);
      CO_RETURN_ON_ERROR(ready(control));
      storage::EcRmwInstallReq install;
      install.plan.input = plan;
      install.grant = issued->install;
      install.reads = issued->reads;
      install.deadlineUnixMillis = issued->install.claims.expiresAtSeconds * 1000;
      auto installed = co_await ecRmwTransport_->install(*address, std::move(install), control);
      CO_RETURN_ON_ERROR(installed);
      if (installed->planId != i.plan || installed->planDigest != issued->observed.plan->digest())
        co_return makeError(StorageCode::kEcSealOutcomeUnknown);
      CO_RETURN_ON_ERROR(ready(control));
      storage::EcRmwActionReq submit;
      submit.planId = i.plan;
      submit.grant = issued->client;
      submit.action = storage::EcRmwActionRequest::Submit;
      auto status = co_await ecRmwTransport_->action(*address, std::move(submit), control);
      CO_RETURN_ON_ERROR(status);
      if (status->planId != i.plan || status->planDigest != issued->observed.plan->digest() || status->state < 1 ||
          status->state > 4)
        co_return makeError(StorageCode::kEcSealOutcomeUnknown);
      if (status->executionError) co_return makeError(Status(status->executionError));
      completed = status->state == 4;
    }
    if (completed) {
      auto proof = co_await ecRmwVerifier_->verify(i.object, owner, i.child, control);
      CO_RETURN_ON_ERROR(proof);
      CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &tx) -> CoTryTask<Void> {
        auto published = co_await EcFileTruncateCatalog::publishDataTail(tx, owner, i.object, i.operation, **proof);
        CO_RETURN_ON_ERROR(published);
        co_return Void{};
      }));
    }
  }
  co_return co_await transaction<EcFileTruncateRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
}
CoTryTask<EcFileTruncateRsp> MetaOperator::closeEcFileTruncateDebt(CloseEcFileTruncateDebtReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  req.intent.owner = ownerOf(req);
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await closeDebt(*kvEngine_, *ecRmwStorage_, *ecV2Coordinator_, req, controlFor(config_)));
  co_return co_await transaction<EcFileTruncateRsp>(*kvEngine_, [&](Tx &tx) { return observe(tx, req); });
}
}  // namespace hf3fs::meta::server
