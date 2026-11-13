#include "meta/store/EcTerminalEvidence.h"
#include <chrono>

#include "MetaOperator.h"
#include "client/storage/EcRmwTransport.h"
#include "meta/components/EcRmwPlanIssuer.h"
#include "meta/components/EcRmwPublicationVerifier.h"
#include "meta/store/EcFileDataInstaller.h"
#include "meta/store/Operation.h"
#include "meta/store/detail/EcFileMutationKeys.h"
#include "meta/store/ops/EcFileOperations.h"

namespace hf3fs::meta::server {
namespace {
using Tx = EcFileTreeTxnBudget;
using Control = storage::client::EcRequestControl;
using namespace ec_file_mutation_detail;
EcOwner ownerOf(const ReqBase &req) { return {req.user.uid, req.client.uuid}; }
uint64_t wallSeconds() {
  return uint64_t(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
Control controlFor(const Config &config) {
  Control out;
  out.transport = Control::TransportPolicy::TcpOnly;
  out.deadline = std::chrono::steady_clock::now() + config.ec_verify_timeout().asMs();
  return out;
}
Result<Void> ready(const Control &control) {
  if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
// One owning request frame keeps Fn alive across its coroutine. No storage
// RPC is awaited in a transaction, and no new ID follows a commit-unknown.
// Complete RMW stages share one ledger from their first read. Standalone
// session close explicitly retains W0; the profile is never request-supplied.
template <typename R, typename Fn>
CoTryTask<R> transaction(kv::IKVEngine &db, Fn fn, Tx::Profile profile = Tx::Profile::Rmw) {
  bool commitStarted = false;
  try {
    auto raw = db.createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    Tx txn(*raw, profile);
    auto result = co_await fn(txn);
    CO_RETURN_ON_ERROR(result);
    commitStarted = true;
    CO_RETURN_ON_ERROR(co_await txn.commit());
    co_return std::move(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
EcTreeSourcePinIntent sourceIntent(const EcFileChildRecord &c) {
  EcTreeSourcePinIntent pin;
  pin.object = c.intent.object;
  pin.owner = c.owner;
  pin.session = c.session;
  pin.parent = c.intent.parent;
  pin.child = c.intent.child;
  pin.pin = c.intent.sourcePin;
  pin.root = c.sourceRoot;
  pin.sequence = c.sourceSequence;
  pin.epoch = c.epoch;
  pin.lengthAtPlan = c.lengthAtPlan;
  pin.slot = c.source;
  return pin;
}
EcFileChildProgress publicChild(const EcFileChildRecord &c) {
  EcFileChildProgress out;
  out.child = c.intent.child;
  out.plan = c.intent.plan;
  out.state = c.state;
  out.stripe = c.stripe;
  out.patchOffset = c.patchOffset;
  out.patchLength = c.patchLength;
  out.targetLogicalLength = c.targetLogicalLength;
  return out;
}
CoTryTask<EcFilePwriteRsp> observe(Tx &txn, const EcFilePwriteReq &req, const Uuid &child) {
  const auto owner = ownerOf(req);
  auto session = co_await EcFileSessionCatalog::get(txn, req.object, req.session, owner);
  CO_RETURN_ON_ERROR(session);
  auto parent = co_await EcFileMutationCatalog::query(txn, req.object, req.operation, owner);
  CO_RETURN_ON_ERROR(parent);
  if (*parent && (**parent).intent.session != req.session) co_return makeError(StatusCode::kTokenMismatch);
  EcFilePwriteRsp rsp;
  rsp.progress.parent = std::move(*parent);
  if (!child.is_nil()) {
    auto current = co_await EcFileMutationCatalog::queryChild(txn, req.object, child, owner);
    CO_RETURN_ON_ERROR(current);
    if (*current) {
      const auto &c = **current;
      if (c.intent.parent != req.operation || c.session != req.session || !rsp.progress.parent)
        co_return makeError(StatusCode::kTokenMismatch);
      rsp.progress.child = publicChild(c);
      auto raw = co_await txn.get(idKey(kv::KeyPrefix::EcFileExecution, req.object, child));
      CO_RETURN_ON_ERROR(raw);
      if (*raw) {
        auto execution = co_await EcFileExecutionCatalog::get(txn, owner, req.object, child);
        CO_RETURN_ON_ERROR(execution);
        rsp.progress.outputDrained = execution->record.state == EcFileExecutionState::Published ||
                                     execution->record.state == EcFileExecutionState::Drained ||
                                     execution->record.state == EcFileExecutionState::Aborted;
      } else if (c.state == EcFileChildState::Published) {
        co_return makeError(StatusCode::kDataCorruption, "published child has no permanent execution");
      } else if (c.state == EcFileChildState::Fenced &&
                 rsp.progress.parent->state == EcFileMutationState::ClosedLogical &&
                 rsp.progress.parent->fencedChild == child) {
        // This normal missing-ECFE conflict read plus the permanent parent/child
        // fence excludes issuance. No candidate ever needs a fabricated ACK.
        // Source completion below still requires its actual persisted T2.
        rsp.progress.outputDrained = true;
      }
      rsp.progress.sourceReleased = c.source.kind == EcTreeSlotKind::Zero;
      if (c.source.kind == EcTreeSlotKind::Data) {
        auto pin = co_await EcTreeSourcePinCatalog::query(txn, sourceIntent(c));
        CO_RETURN_ON_ERROR(pin);
        rsp.progress.sourceReleased = pin->state == EcTreeSourcePinState::Released;
      }
    }
  }
  co_return rsp;
}
Result<net::Address> workerAddress(const EcV2Coordinator &coordinator,
                                   client::ICommonMgmtdClient &mgmtd,
                                   const EcV2PhysicalEndpoint &worker) {
  RETURN_ON_ERROR(coordinator.route(worker));
  auto routing = mgmtd.getRoutingInfo();
  if (!routing || !routing->raw()) return makeError(MgmtdClientCode::kRoutingInfoNotReady);
  const auto *node = routing->raw()->getNode(worker.placement.node);
  if (!node || node->type != flat::NodeType::STORAGE) return makeError(StorageClientCode::kRoutingError);
  for (const auto &group : node->app.serviceGroups) {
    if (!group.services.contains("StorageSerde")) continue;
    for (const auto &address : group.endpoints)
      if (address.type == net::Address::TCP) return address;
  }
  return makeError(StorageClientCode::kRoutingError, "fixed RMW worker has no TCP StorageSerde endpoint");
}
// Cleanup keeps candidate and source scope evidence separate. The source
// cannot drain until the entire candidate/worker scope has stopped executing.
CoTryTask<Void> cleanup(kv::IKVEngine &db,
                        storage::client::StorageClient &storage,
                        const EcV2Coordinator &coordinator,
                        const AdvanceEcFilePwriteReq &req,
                        const Control &control) {
  const auto owner = ownerOf(req);
  auto c = co_await transaction<EcFileChildRecord>(db, [&](Tx &txn) -> CoTryTask<EcFileChildRecord> {
    auto progress = co_await observe(txn, req, req.child);
    CO_RETURN_ON_ERROR(progress);
    if (!progress->progress.child) co_return makeError(MetaCode::kNotFound);
    auto value = co_await EcFileMutationCatalog::queryChild(txn, req.object, req.child, owner);
    CO_RETURN_ON_ERROR(value);
    co_return std::move(**value);
  });
  CO_RETURN_ON_ERROR(c);
  auto candidate = co_await transaction<std::optional<EcV2DrainRecord>>(
      db,
      [&](Tx &txn) -> CoTryTask<std::optional<EcV2DrainRecord>> {
        auto raw = co_await txn.get(idKey(kv::KeyPrefix::EcFileExecution, req.object, req.child));
        CO_RETURN_ON_ERROR(raw);
        if (!*raw) {
          // No issuer can cross this normal conflict read without an ECFE write.
          // Fence the still-logical parent before closing an unused source pin.
          auto current = co_await EcFileMutationCatalog::queryChild(txn, req.object, req.child, owner);
          CO_RETURN_ON_ERROR(current);
          if (!*current) co_return makeError(StatusCode::kDataCorruption);
          if ((**current).state == EcFileChildState::Planned)
            CO_RETURN_ON_ERROR(co_await EcFileMutationCatalog::sealPrefix(txn, req.object, req.operation, owner));
          co_return std::nullopt;
        }
        auto execution = co_await EcFileExecutionCatalog::get(txn, owner, req.object, req.child);
        CO_RETURN_ON_ERROR(execution);
        if (execution->record.state == EcFileExecutionState::Published ||
            execution->record.state == EcFileExecutionState::Aborted)
          co_return execution->record.drain;
        // A prior Publish may already have committed T0 with its own fixed
        // revocation. Continue that exact denial; the caller cannot replace it.
        const auto revocation =
            execution->record.drain ? execution->record.drain->identity.revocationId : req.outputRevocation;
        auto record = co_await EcFileExecutionCatalog::startCancelClosing(txn,
                                                                          owner,
                                                                          req.object,
                                                                          req.child,
                                                                          coordinator.authority(),
                                                                          revocation);
        CO_RETURN_ON_ERROR(record);
        co_return std::optional<EcV2DrainRecord>{std::move(*record)};
      });
  CO_RETURN_ON_ERROR(candidate);
  if (*candidate && (**candidate).state == EcV2DrainState::Closing) {
    const auto frozen = **candidate;
    for (size_t i = 0; i < frozen.identity.endpoints.count; ++i) {
      if (ecTerminalAt(frozen, i)) continue;
      auto retired = co_await transaction<EcV2DrainRecord>(db, [&](Tx &txn) {
        return EcFileExecutionCatalog::recordRetirement(txn, owner, req.object, req.child, i, coordinator.controlKey());
      });
      CO_RETURN_ON_ERROR(retired);
      if (ecTerminalAt(*retired, i)) continue;
      CO_RETURN_ON_ERROR(ready(control));
      auto request = EcV2DrainCatalog::makeRequest(frozen,
                                                   i,
                                                   storage::EcScopeControlAction::Revoke,
                                                   coordinator.controlKey(),
                                                   wallSeconds());
      CO_RETURN_ON_ERROR(request);
      auto ack = co_await storage.revokeEcScope(*request);
      CO_RETURN_ON_ERROR(ack);
      CO_RETURN_ON_ERROR(storage::verifyEcScopeControlAck(coordinator.controlKey(), *ack, *request));
      if (ack->claims.state != storage::EcScopeControlState::Drained)
        co_return makeError(StorageClientCode::kResourceBusy,
                            "candidate drain is pending; retry the same child and revocations");
      CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &txn) -> CoTryTask<Void> {
        auto stored = co_await EcFileExecutionCatalog::recordAck(txn,
                                                                 owner,
                                                                 req.object,
                                                                 req.child,
                                                                 i,
                                                                 coordinator.controlKey(),
                                                                 *request,
                                                                 *ack);
        CO_RETURN_ON_ERROR(stored);
        co_return Void{};
      }));
    }
    CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &txn) -> CoTryTask<Void> {
      auto done =
          co_await EcFileExecutionCatalog::finishDrain(txn, owner, req.object, req.child, coordinator.controlKey());
      CO_RETURN_ON_ERROR(done);
      if (done->record.state != EcFileExecutionState::Aborted && done->record.state != EcFileExecutionState::Published)
        co_return makeError(StatusCode::kTokenStale, "candidate still needs publication, not source release");
      co_return Void{};
    }));
  }
  if (c->source.kind == EcTreeSlotKind::Data) {
    const auto pin = sourceIntent(*c);
    auto closing = co_await transaction<EcV2DrainRecord>(db, [&](Tx &txn) {
      return EcTreeSourcePinCatalog::startClosing(txn, pin, coordinator.authority(), req.sourceRevocation);
    });
    CO_RETURN_ON_ERROR(closing);
    for (size_t i = 0; i < closing->identity.endpoints.count; ++i) {
      if (ecTerminalAt(*closing, i)) continue;
      auto retired = co_await transaction<EcV2DrainRecord>(db, [&](Tx &txn) {
        return EcTreeSourcePinCatalog::recordRetirement(txn, pin, i, coordinator.controlKey());
      });
      CO_RETURN_ON_ERROR(retired);
      if (ecTerminalAt(*retired, i)) continue;
      CO_RETURN_ON_ERROR(ready(control));
      auto request = EcV2DrainCatalog::makeRequest(*closing,
                                                   i,
                                                   storage::EcScopeControlAction::Revoke,
                                                   coordinator.controlKey(),
                                                   wallSeconds());
      CO_RETURN_ON_ERROR(request);
      auto ack = co_await storage.revokeEcScope(*request);
      CO_RETURN_ON_ERROR(ack);
      CO_RETURN_ON_ERROR(storage::verifyEcScopeControlAck(coordinator.controlKey(), *ack, *request));
      if (ack->claims.state != storage::EcScopeControlState::Drained)
        co_return makeError(StorageClientCode::kResourceBusy,
                            "source drain is pending; retry the same child and revocations");
      CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &txn) -> CoTryTask<Void> {
        auto stored = co_await EcTreeSourcePinCatalog::recordAck(txn, pin, i, coordinator.controlKey(), *request, *ack);
        CO_RETURN_ON_ERROR(stored);
        co_return Void{};
      }));
    }
    CO_RETURN_ON_ERROR(co_await transaction<Void>(db, [&](Tx &txn) -> CoTryTask<Void> {
      auto released = co_await EcTreeSourcePinCatalog::finishRelease(txn, pin, coordinator.controlKey());
      CO_RETURN_ON_ERROR(released);
      co_return Void{};
    }));
  }
  co_return Void{};
}
}  // namespace

CoTryTask<void> MetaOperator::authenticateEcFileSession(ReqBase &req) {
  if (stop_.load() || !config_.enable_ec_rmw() || !ecRmwIssuer_ || !ecRmwVerifier_ || !ecRmwTransport_ ||
      !ecRmwStorage_)
    co_return makeError(StatusCode::kNotImplemented, "mode-4 RMW service is disabled or stopping");
  if (!config_.authenticate()) co_return makeError(StatusCode::kAuthenticationFail);
  CO_RETURN_ON_ERROR(req.checkUuid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  if (req.client.uuid.is_nil()) co_return makeError(StatusCode::kInvalidArg, "persistent client namespace required");
  co_return Void{};
}
CoTryTask<OpenEcFileSessionRsp> MetaOperator::openEcFileSession(OpenEcFileSessionReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly() && (req.createNew || (req.rights & kEcSessionWrite)))
    co_return makeError(StatusCode::kReadOnlyMode);
  if (req.createNew) CO_RETURN_ON_ERROR(ecV2Coordinator_->configuredPool());
  auto operation = makeOpenEcFileSessionOp(*metaStore_, req);
  auto raw = kvEngine_->createReadWriteTransaction();
  if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
  // The open operation owns its fixed generated incarnation/inode across
  // OperationDriver retries. Its permanent create/open identities are checked.
  auto driver =
      OperationDriver(*operation, req, std::optional<SteadyTime>{SteadyClock::now() + config_.ec_verify_timeout()});
  co_return co_await driver.run(std::move(raw), createRetryConfig(), false, config_.grv_cache());
}
CoTryTask<EcFilePwriteRsp> MetaOperator::beginEcFilePwrite(BeginEcFilePwriteReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  CO_RETURN_ON_ERROR(req.valid());
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  co_return co_await transaction<EcFilePwriteRsp>(*kvEngine_, [&](Tx &txn) -> CoTryTask<EcFilePwriteRsp> {
    EcFilePwriteIntent intent;
    intent.object = req.object;
    intent.owner = ownerOf(req);
    intent.session = req.session;
    intent.request = req.operation;
    intent.offset = req.offset;
    intent.length = req.length;
    intent.inputSha256 = req.inputSha256;
    auto accepted = co_await EcFileMutationCatalog::begin(txn, intent);
    CO_RETURN_ON_ERROR(accepted);
    co_return co_await observe(txn, req, accepted->activeChild);
  });
}
CoTryTask<EcFilePwriteRsp> MetaOperator::queryEcFilePwrite(QueryEcFilePwriteReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await transaction<EcFilePwriteRsp>(*kvEngine_, [&](Tx &txn) { return observe(txn, req, req.child); });
}
CoTryTask<EcFilePwriteRsp> MetaOperator::advanceEcFilePwrite(AdvanceEcFilePwriteReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  CO_RETURN_ON_ERROR(req.valid());
  const auto owner = ownerOf(req);
  const auto control = controlFor(config_);
  if (config_.readonly() && (req.action == EcFileAdvanceAction::Plan || req.action == EcFileAdvanceAction::Publish))
    co_return makeError(StatusCode::kReadOnlyMode);
  // Validate authenticated owner/session/parent even for a trusted verifier
  // dispatch; the verifier then independently rechecks the accepted child.
  auto before =
      co_await transaction<EcFilePwriteRsp>(*kvEngine_, [&](Tx &txn) { return observe(txn, req, req.child); });
  CO_RETURN_ON_ERROR(before);
  if (!before->progress.parent) co_return makeError(MetaCode::kNotFound);
  if (req.action == EcFileAdvanceAction::Plan) {
    auto pool = ecV2Coordinator_->pool();
    CO_RETURN_ON_ERROR(pool);
    // Accept the fixed child and its exact source pin atomically. A failed or
    // unknown commit returns immediately; the same IDs recover this phase.
    auto accepted = co_await transaction<Void>(*kvEngine_, [&](Tx &txn) -> CoTryTask<Void> {
      auto child = co_await EcFileMutationCatalog::planChild(txn, owner, req.intent);
      CO_RETURN_ON_ERROR(child);
      if (child->session != req.session) co_return makeError(StatusCode::kTokenMismatch);
      co_return Void{};
    });
    CO_RETURN_ON_ERROR(accepted);
    // This fresh transaction owns a complete budget and rechecks executable
    // parent/session/source state before creating any candidate reservation.
    // A fenced child with no ECFE remains recoverable by the existing cleanup
    // path. The issuer is reached only after this reservation commit succeeds.
    auto reserved = co_await transaction<Void>(*kvEngine_, [&](Tx &txn) -> CoTryTask<Void> {
      auto execution = co_await EcFileExecutionCatalog::reserveExecution(txn, owner, req.object, req.child, *pool, 0);
      CO_RETURN_ON_ERROR(execution);
      co_return Void{};
    });
    CO_RETURN_ON_ERROR(reserved);
    auto issued = co_await ecRmwIssuer_->issue(req.object, owner, req.child);
    CO_RETURN_ON_ERROR(issued);
    const auto &p = issued->observed.plan->input();
    const auto &worker = issued->observed.record.candidates[p.workerIndex].endpoint;
    auto address = workerAddress(*ecV2Coordinator_, *mgmtd_, worker);
    CO_RETURN_ON_ERROR(address);
    storage::EcRmwInstallReq install;
    install.plan.input = p;
    install.grant = issued->install;
    install.reads = issued->reads;
    install.deadlineUnixMillis = issued->install.claims.expiresAtSeconds * 1000;
    auto installed = co_await ecRmwTransport_->install(*address, std::move(install), control);
    CO_RETURN_ON_ERROR(installed);
    if (installed->planId != p.planId || installed->planDigest != issued->observed.plan->digest())
      co_return makeError(StorageCode::kEcSealOutcomeUnknown, "RMW install response changed its fixed plan");
    auto result =
        co_await transaction<EcFilePwriteRsp>(*kvEngine_, [&](Tx &txn) { return observe(txn, req, req.child); });
    CO_RETURN_ON_ERROR(result);
    EcFileWorkerAccess access;
    access.worker = worker;
    access.planDigest = issued->observed.plan->digest();
    access.grant = issued->client;
    result->progress.worker = std::move(access);
    co_return result;
  }
  if (req.action == EcFileAdvanceAction::Publish) {
    if (!before->progress.child) co_return makeError(MetaCode::kNotFound);
    auto proof = co_await ecRmwVerifier_->verify(req.object, owner, req.child, control);
    CO_RETURN_ON_ERROR(proof);
    CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &txn) -> CoTryTask<Void> {
      auto published = co_await EcFileDataInstaller::publishPwrite(txn, owner, **proof);
      CO_RETURN_ON_ERROR(published);
      co_return Void{};
    }));
  } else if (req.action == EcFileAdvanceAction::SealPrefix) {
    CO_RETURN_ON_ERROR(co_await transaction<Void>(*kvEngine_, [&](Tx &txn) -> CoTryTask<Void> {
      auto sealed = co_await EcFileMutationCatalog::sealPrefix(txn, req.object, req.operation, owner);
      CO_RETURN_ON_ERROR(sealed);
      co_return Void{};
    }));
  } else {
    CO_RETURN_ON_ERROR(co_await cleanup(*kvEngine_, *ecRmwStorage_, *ecV2Coordinator_, req, control));
  }
  co_return co_await transaction<EcFilePwriteRsp>(*kvEngine_, [&](Tx &txn) { return observe(txn, req, req.child); });
}
CoTryTask<CloseEcFileSessionRsp> MetaOperator::closeEcFileSession(CloseEcFileSessionReq req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcFileSession(req));
  CO_RETURN_ON_ERROR(req.valid());
  co_return co_await transaction<CloseEcFileSessionRsp>(
      *kvEngine_,
      [&](Tx &txn) -> CoTryTask<CloseEcFileSessionRsp> {
        auto closed = co_await EcFileSessionCatalog::close(txn, req.object, req.session, ownerOf(req));
        CO_RETURN_ON_ERROR(closed);
        CloseEcFileSessionRsp out;
        out.session = std::move(*closed);
        co_return out;
      },
      Tx::Profile::W0);
}
}  // namespace hf3fs::meta::server
