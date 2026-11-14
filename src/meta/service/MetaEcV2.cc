#include "meta/store/EcTerminalEvidence.h"
#include <algorithm>
#include <folly/experimental/coro/Sleep.h>

#include "meta/service/MetaOperator.h"
#include "meta/store/Operation.h"
#include "meta/store/ops/EcV2Operations.h"

namespace hf3fs::meta::server {
namespace {
enum class V2WritePolicy { FilesystemMutation, ReferenceMaintenance };
template <typename Rsp, typename Req>
CoTryTask<Rsp> driveV2(MetaStore::OpPtr<Rsp> operation,
                       const Req &req,
                       kv::IKVEngine &engine,
                       const Config &config,
                       kv::FDBRetryStrategy::Config retry,
                       V2WritePolicy policy = V2WritePolicy::FilesystemMutation) {
  CO_RETURN_ON_ERROR(req.valid());
  auto deadline = config.operation_timeout() == 0_s
                      ? std::optional<SteadyTime>{}
                      : std::optional<SteadyTime>{SteadyClock::now() + config.operation_timeout()};
  auto transaction = engine.createReadWriteTransaction();
  if (!transaction) co_return makeError(StatusCode::kKVStoreNotFound, "V2 transaction could not be created");
  auto driver = OperationDriver(*operation, req, deadline);
  // Read pins, durable drain observations and cancellation change reference
  // metadata only. They still commit actual transactions in filesystem readonly
  // mode; never disguise these writes as an isReadOnly operation.
  const bool enforceReadonly = policy == V2WritePolicy::FilesystemMutation && config.readonly();
  co_return co_await driver.run(std::move(transaction), std::move(retry), enforceReadonly, config.grv_cache());
}
EcV2PhaseRequest phaseRequest(const EcOperationReq &req, EcV2Phase phase, const EcV2Coordinator *coordinator) {
  EcV2PhaseRequest out;
  static_cast<EcOperationReq &>(out) = req;
  out.phase = phase;
  out.coordinator = coordinator;
  return out;
}
EcV2PhaseRequest readRequest(const AcquireEcReadReq &req, EcV2Phase phase, const EcV2Coordinator *coordinator) {
  EcV2PhaseRequest out;
  static_cast<ReqBase &>(out) = static_cast<const ReqBase &>(req);
  out.object = req.object;
  out.operation = req.pin;
  out.stripe = req.stripe;
  out.scopeKind = storage::EcGrantScope::ReadPin;
  out.phase = phase;
  out.coordinator = coordinator;
  return out;
}
EcV2DrainProgress drainProgress(const EcV2DrainRecord &record) {
  EcV2DrainProgress out;
  out.state = record.state;
  out.revocation = record.identity.revocationId;
  out.expectedEndpoints = record.identity.endpoints.count;
  for (size_t i = 0; i != record.identity.endpoints.count; ++i) {
    out.acknowledgedEndpoints += record.observations[i].has_value();
    out.retiredEndpoints += record.retirements[i].has_value();
  }
  return out;
}
}  // namespace
CoTryTask<void> MetaOperator::authenticateEcV2(ReqBase &req) {
  CO_RETURN_ON_ERROR(ecV2Coordinator_->checkEnabled());
  CO_RETURN_ON_ERROR(req.checkUuid());
  CO_RETURN_ON_ERROR(co_await authenticate(req.user));
  co_return Void{};
}
CoTryTask<CreateEcFileRsp> MetaOperator::createEcFileV2(CreateEcFileV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  // Configured physical identity is mandatory even for an empty new file. The
  // first Begin freezes that pool; creation itself never emits data grants.
  CO_RETURN_ON_ERROR(ecV2Coordinator_->configuredPool());
  co_return co_await driveV2(makeCreateEcV2Op(*metaStore_, req), req, *kvEngine_, config_, createRetryConfig());
}
CoTryTask<EcV2MutationRsp> MetaOperator::beginEcMutationV2(BeginEcMutationV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  auto context = phaseRequest(req, EcV2Phase::Begin, ecV2Coordinator_.get());
  context.begin = req;
  auto result =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  co_return std::move(result->mutation);
}
CoTryTask<EcV2MutationRsp> MetaOperator::bindEcMutationV2(BindEcMutationV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  auto context = phaseRequest(req, EcV2Phase::Bind, ecV2Coordinator_.get());
  context.descriptors = req.descriptors;
  auto result =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(ecV2Coordinator_->addMutationGrants(result->mutation));
  co_return std::move(result->mutation);
}
CoTryTask<PrepareEcRepairV2Rsp> MetaOperator::prepareEcRepairV2(PrepareEcRepairV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  CO_RETURN_ON_ERROR(req.valid());
  auto context = phaseRequest(req, EcV2Phase::PrepareRepair, ecV2Coordinator_.get());
  context.repairSelection.planId = req.planId;
  context.repairSelection.sourceOrder = req.sourceOrder;
  context.repairSelection.maxBlocksInFlight = req.maxBlocksInFlight;
  auto result =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  if (!result->repair) co_return makeError(StatusCode::kDataCorruption);
  PrepareEcRepairV2Rsp response;
  // History has already passed the same WRITE and permanent-delivery checks,
  // but neither increments ECVI nor renews any data/helper authority.
  if (result->mutation.record.state == EcOperationState::Preparing && !result->mutation.drain) {
    CO_RETURN_ON_ERROR(ecV2Coordinator_->addMutationGrants(result->mutation));
    auto helpers = ecV2Coordinator_->issueRepairHelpers(*result->repair);
    CO_RETURN_ON_ERROR(helpers);
    response.helpers = std::move(*helpers);
  }
  response.mutation = std::move(result->mutation);
  response.plan = std::move(result->repair->plan);
  co_return response;
}
CoTryTask<PrepareEcRepairDirectV2Rsp> MetaOperator::prepareEcRepairDirectV2(PrepareEcRepairDirectV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  CO_RETURN_ON_ERROR(req.valid());
  auto context = phaseRequest(req, EcV2Phase::PrepareRepairDirect, ecV2Coordinator_.get());
  context.repairSelection.planId = req.planId;
  context.repairSelection.sourceOrder = req.sourceOrder;
  context.repairSelection.maxBlocksInFlight = req.maxBlocksInFlight;
  auto result = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  if (!result->repair) co_return makeError(StatusCode::kDataCorruption);
  PrepareEcRepairDirectV2Rsp response;
  if (result->mutation.record.state == EcOperationState::Preparing && !result->mutation.drain) {
    // Actual ECVI/ECRP commit above precedes every signature below.
    auto delegation = ecV2Coordinator_->issueFlatRepairDirect(*result->repair, result->mutation);
    CO_RETURN_ON_ERROR(delegation);
    response.delegation = std::move(*delegation);
    CO_RETURN_ON_ERROR(ecV2Coordinator_->addMutationGrants(result->mutation));
    auto helpers = ecV2Coordinator_->issueRepairHelpers(*result->repair);
    CO_RETURN_ON_ERROR(helpers);
    response.base.helpers = std::move(*helpers);
  }
  response.base.mutation = std::move(result->mutation);
  response.base.plan = std::move(result->repair->plan);
  co_return response;
}
CoTryTask<EcV2MutationRsp> MetaOperator::getEcOperationV2(GetEcOperationV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  auto context = phaseRequest(req, EcV2Phase::Get, ecV2Coordinator_.get());
  auto result =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  co_return std::move(result->mutation);
}
CoTryTask<EcV2DrainRecord> MetaOperator::advanceEcV2Drain(const EcOperationReq &request, EcV2DrainRecord record) {
  if (record.state != EcV2DrainState::Closing) co_return record;
  const auto deadline = SteadyClock::now() + config_.ec_v2_drain_timeout();
  std::array<bool, 24> revokeSent{};
  auto req = request;
  while (true) {
    bool complete = true;
    for (size_t i = 0; i != record.identity.endpoints.count; ++i) {
      if (ecTerminalAt(record, i)) continue;
      complete = false;
      if (SteadyClock::now() >= deadline)
        co_return makeError(MetaCode::kOperationTimeout, "V2 drain remains Closing; no pin was released");
      CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
      auto observed = co_await ecV2Coordinator_->observeDrain(
          record,
          i,
          revokeSent[i] ? storage::EcScopeControlAction::Query : storage::EcScopeControlAction::Revoke);
      CO_RETURN_ON_ERROR(observed);
      revokeSent[i] = true;
      if (!*observed) continue;
      CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
      auto context = phaseRequest(req, EcV2Phase::RecordAck, ecV2Coordinator_.get());
      context.scopeKind = record.identity.kind;
      context.observation = std::make_shared<const EcVerifiedDrainAck>(std::move(**observed));
      auto saved = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                    context,
                                    *kvEngine_,
                                    config_,
                                    createRetryConfig(),
                                    V2WritePolicy::ReferenceMaintenance);
      CO_RETURN_ON_ERROR(saved);
      if (!saved->drain) co_return makeError(StatusCode::kDataCorruption);
      record = std::move(*saved->drain);
    }
    if (complete || std::all_of(record.observations.begin(),
                                record.observations.begin() + record.identity.endpoints.count,
                                [](const auto &ack) { return ack.has_value(); }))
      co_return record;
    // Local timeout bounds further admission. An already dispatched TCP request
    // retains its finite Waiter until completion; timeout is never remote drain.
    if (SteadyClock::now() >= deadline)
      co_return makeError(MetaCode::kOperationTimeout, "V2 drain remains Closing; retry the same scope");
    co_await folly::coro::sleep(config_.ec_v2_drain_poll_interval());
  }
}
CoTryTask<EcV2MutationRsp> MetaOperator::publishEcMutationV2(PublishEcMutationV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  if (config_.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
  auto context = phaseRequest(req, EcV2Phase::PreparePublish, ecV2Coordinator_.get());
  auto prepared =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(prepared);
  if (!prepared->drain) {
    auto evidence = co_await ecV2Coordinator_->verifyForPublish(prepared->mutation);
    CO_RETURN_ON_ERROR(evidence);
    CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
    static_cast<EcOperationReq &>(context) = req;
    context.phase = EcV2Phase::StartPublish;
    context.publication = std::move(*evidence);
    prepared =
        co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
    CO_RETURN_ON_ERROR(prepared);
  }
  if (!prepared->drain) co_return makeError(StatusCode::kDataCorruption);
  // Persisted T0 proof is sufficient on restart; never re-read an already
  // revoked data scope to reconstruct evidence.
  auto drained = co_await advanceEcV2Drain(req, std::move(*prepared->drain));
  CO_RETURN_ON_ERROR(drained);
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  context = phaseRequest(req, EcV2Phase::FinishPublish, ecV2Coordinator_.get());
  auto result =
      co_await driveV2(makeEcV2PhaseOp(*metaStore_, context), context, *kvEngine_, config_, createRetryConfig());
  CO_RETURN_ON_ERROR(result);
  co_return std::move(result->mutation);
}
CoTryTask<EcV2MutationRsp> MetaOperator::cancelEcMutationV2(CancelEcMutationV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  auto context = phaseRequest(req, EcV2Phase::StartCancel, ecV2Coordinator_.get());
  auto started = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                  context,
                                  *kvEngine_,
                                  config_,
                                  createRetryConfig(),
                                  V2WritePolicy::ReferenceMaintenance);
  CO_RETURN_ON_ERROR(started);
  if (!started->drain) co_return makeError(StatusCode::kDataCorruption);
  if (started->drain->state == EcV2DrainState::Closing) {
    for (size_t i = 0; i < started->drain->identity.endpoints.count; ++i) {
      if (ecTerminalAt(*started->drain, i)) continue;
      auto retired = context;
      retired.phase = EcV2Phase::RecordRetirement;
      retired.retirementIndex = i;
      auto saved = co_await driveV2(makeEcV2PhaseOp(*metaStore_, retired), retired, *kvEngine_, config_,
                                   createRetryConfig(), V2WritePolicy::ReferenceMaintenance);
      CO_RETURN_ON_ERROR(saved);
      if (!saved->drain) co_return makeError(StatusCode::kDataCorruption);
      started->drain = std::move(saved->drain);
    }
  }
  auto drained = co_await advanceEcV2Drain(req, std::move(*started->drain));
  CO_RETURN_ON_ERROR(drained);
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  context = phaseRequest(req, EcV2Phase::FinishCancel, ecV2Coordinator_.get());
  auto result = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                 context,
                                 *kvEngine_,
                                 config_,
                                 createRetryConfig(),
                                 V2WritePolicy::ReferenceMaintenance);
  CO_RETURN_ON_ERROR(result);
  co_return std::move(result->mutation);
}
CoTryTask<AcquireEcReadV2Rsp> MetaOperator::acquireEcReadV2(AcquireEcReadV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  CO_RETURN_ON_ERROR(req.valid());
  auto context = readRequest(req, EcV2Phase::AcquireRead, ecV2Coordinator_.get());
  auto result = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                 context,
                                 *kvEngine_,
                                 config_,
                                 createRetryConfig(),
                                 V2WritePolicy::ReferenceMaintenance);
  CO_RETURN_ON_ERROR(result);
  if (!result->read) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(ecV2Coordinator_->addReadGrants(*result->read));
  co_return std::move(*result->read);
}
CoTryTask<ReleaseEcReadV2Rsp> MetaOperator::releaseEcReadV2(ReleaseEcReadV2Req req) {
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  CO_RETURN_ON_ERROR(req.valid());
  auto context = readRequest(req, EcV2Phase::StartRelease, ecV2Coordinator_.get());
  auto started = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                  context,
                                  *kvEngine_,
                                  config_,
                                  createRetryConfig(),
                                  V2WritePolicy::ReferenceMaintenance);
  CO_RETURN_ON_ERROR(started);
  if (!started->drain) co_return makeError(StatusCode::kDataCorruption);
  if (started->drain->state == EcV2DrainState::Closing) {
    for (size_t i = 0; i < started->drain->identity.endpoints.count; ++i) {
      if (ecTerminalAt(*started->drain, i)) continue;
      auto retired = context;
      retired.phase = EcV2Phase::RecordRetirement;
      retired.retirementIndex = i;
      auto saved = co_await driveV2(makeEcV2PhaseOp(*metaStore_, retired), retired, *kvEngine_, config_,
                                   createRetryConfig(), V2WritePolicy::ReferenceMaintenance);
      CO_RETURN_ON_ERROR(saved);
      if (!saved->drain) co_return makeError(StatusCode::kDataCorruption);
      started->drain = std::move(saved->drain);
    }
  }
  auto drained = co_await advanceEcV2Drain(context, std::move(*started->drain));
  CO_RETURN_ON_ERROR(drained);
  CO_RETURN_ON_ERROR(co_await authenticateEcV2(req));
  context = readRequest(req, EcV2Phase::FinishRelease, ecV2Coordinator_.get());
  auto result = co_await driveV2(makeEcV2PhaseOp(*metaStore_, context),
                                 context,
                                 *kvEngine_,
                                 config_,
                                 createRetryConfig(),
                                 V2WritePolicy::ReferenceMaintenance);
  CO_RETURN_ON_ERROR(result);
  if (!result->drain) co_return makeError(StatusCode::kDataCorruption);
  ReleaseEcReadV2Rsp rsp;
  rsp.pin = req.pin;
  rsp.drain = drainProgress(*result->drain);
  co_return rsp;
}
}  // namespace hf3fs::meta::server
