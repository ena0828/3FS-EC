#include "meta/components/EcTargetRetirementCoordinator.h"

#include <atomic>
#include <chrono>
#include <new>
#include <folly/ScopeGuard.h>
#include <limits>

#include "meta/store/EcFileTreeTxnBudget.h"
#include "meta/store/EcTargetRetirementCatalog.h"

namespace hf3fs::meta::server {
namespace {
uint64_t wallSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
EcTargetRetirementRsp response(const EcTargetRetirementRecord &record) {
  EcTargetRetirementRsp out;
  out.intent = record.intent;
  if (record.completion) {
    out.stage = EcTargetRetirementStage::Completed;
    out.completionDigest = record.completion->digest;
  }
  return out;
}
}  // namespace
struct EcTargetRetirementCoordinator::State {
  explicit State(const Config &c) : config(c) {}
  const Config &config;
  std::shared_ptr<kv::IKVEngine> engine;
  std::shared_ptr<storage::client::StorageClient> client;
  std::shared_ptr<const storage::EcScopeControlKey> key;
  Uuid authority;
  std::atomic<bool> closing{false};
  std::atomic<uint32_t> active{0};
  bool enter() {
    auto count = active.load(std::memory_order_relaxed);
    while (count < 8) {
      if (active.compare_exchange_weak(count, count + 1, std::memory_order_acquire)) return true;
    }
    return false;
  }
  Result<Void> ready(SteadyTime deadline) const {
    if (closing.load(std::memory_order_acquire)) return makeError(StorageClientCode::kRequestCanceled);
    if (!config.authenticate()) return makeError(StatusCode::kAuthenticationFail);
    if (SteadyClock::now() >= deadline) return makeError(StorageClientCode::kTimeout);
    return Void{};
  }
};
EcTargetRetirementCoordinator::EcTargetRetirementCoordinator(
    const Config &config,
    std::shared_ptr<kv::IKVEngine> engine,
    std::shared_ptr<storage::client::StorageClient> client,
    const EcV2Coordinator &v2)
    : config_(config) {
  if (!config.enable_ec_target_retirement()) return;
  auto initialize = [&]() -> Result<Void> {
    RETURN_ON_ERROR(v2.checkEnabled());
    if (!config.enable_ec_catalog() || !config.enable_ec_v2() || !config.authenticate() || !engine || !client ||
        config.ec_v2_drain_timeout() <= 0_s || config.ec_v2_drain_timeout() > 60_s)
      return makeError(StatusCode::kInvalidConfig, "target retirement requires authenticated V2 and finite control timeout");
    auto state = std::make_shared<State>(config);
    state->engine = std::move(engine);
    state->client = std::move(client);
    state->key = v2.sharedControlKey();
    state->authority = v2.authority();
    if (!state->key || state->authority.is_nil()) return makeError(StatusCode::kInvalidConfig);
    state_ = std::move(state);
    return Void{};
  };
  auto result = initialize();
  if (!result) initializationError_ = std::move(result.error());
}
Result<Void> EcTargetRetirementCoordinator::checkEnabled() const {
  if (!config_.enable_ec_target_retirement()) return makeError(StatusCode::kNotImplemented);
  if (initializationError_) return makeError(*initializationError_);
  if (!state_) return makeError(StatusCode::kInvalidConfig);
  if (!config_.authenticate()) return makeError(StatusCode::kAuthenticationFail);
  if (state_->closing.load(std::memory_order_acquire)) return makeError(StorageClientCode::kRequestCanceled);
  return Void{};
}
void EcTargetRetirementCoordinator::close() {
  if (state_) state_->closing.store(true, std::memory_order_release);
}
CoTryTask<EcTargetRetirementRsp> EcTargetRetirementCoordinator::prepare(EcTargetRetirementReq req) const {
  return executeOwned(state_, std::move(req), storage::EcTargetRetirementAction::Prepare);
}
CoTryTask<EcTargetRetirementRsp> EcTargetRetirementCoordinator::query(EcTargetRetirementReq req) const {
  return executeOwned(state_, std::move(req), storage::EcTargetRetirementAction::Query);
}
CoTryTask<EcTargetRetirementRsp> EcTargetRetirementCoordinator::executeOwned(
    std::shared_ptr<State> state,
    EcTargetRetirementReq req,
    storage::EcTargetRetirementAction action) {
  if (!state) co_return makeError(StatusCode::kNotImplemented);
  CO_RETURN_ON_ERROR(req.valid());
  if (!req.user.isRoot()) co_return makeError(MetaCode::kNoPermission);
  const auto deadline = SteadyClock::now() + state->config.ec_v2_drain_timeout();
  CO_RETURN_ON_ERROR(state->ready(deadline));
  if (!state->enter()) co_return makeError(StorageClientCode::kResourceBusy);
  SCOPE_EXIT { state->active.fetch_sub(1, std::memory_order_release); };
  bool commitStarted = false;
  bool storageInvoked = false;
  try {
    EcTargetRetirementIntent intent;
    intent.endpoint = req.endpoint;
    intent.retirementId = req.retirementId;
    intent.authority = state->authority;
    intent.owner = {req.user.uid, req.client.uuid};
    intent.requestId = req.uuid;
    EcTargetRetirementRecord accepted;
    {
      auto raw = state->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget txn(*raw);
      auto record = action == storage::EcTargetRetirementAction::Prepare
                        ? co_await EcTargetRetirementCatalog::prepare(txn, intent)
                        : co_await EcTargetRetirementCatalog::get(txn, intent);
      CO_RETURN_ON_ERROR(record);
      if (record->completion) {
        auto ref = co_await EcTargetRetirementCatalog::findCompleted(txn, intent.endpoint, intent.authority, *state->key);
        CO_RETURN_ON_ERROR(ref);
        if (!*ref) co_return makeError(StatusCode::kDataCorruption);
        co_return response(*record);
      }
      CO_RETURN_ON_ERROR(state->ready(deadline));
      if (state->config.readonly()) co_return makeError(StatusCode::kReadOnlyMode);
      // The accepted intent and request index become durable before any Storage
      // operation. Query commits only reads; it cannot install a missing intent.
      commitStarted = true;
      auto committed = co_await txn.commit();
      if (!committed) co_return makeError(std::move(committed.error()));
      accepted = std::move(*record);
    }
    CO_RETURN_ON_ERROR(state->ready(deadline));
    const auto now = wallSeconds();
    if (now > std::numeric_limits<uint64_t>::max() - 60)
      co_return makeError(StatusCode::kInvalidArg);
    storage::EcTargetRetirementClaims claims;
    claims.action = action;
    claims.clusterAuthority = intent.authority;
    claims.nodeId = intent.endpoint.placement.node;
    claims.chainId = intent.endpoint.placement.chain;
    claims.targetId = intent.endpoint.placement.target;
    claims.engineUuid = intent.endpoint.engineUuid;
    claims.targetIncarnation = intent.endpoint.targetIncarnation;
    claims.retirementId = intent.retirementId;
    // Fresh signed transport request, fixed durable retirement identity.
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = now;
    claims.expiresAtSeconds = now + 60;
    auto request = storage::signEcTargetRetirement(*state->key, claims, now);
    CO_RETURN_ON_ERROR(request);
    storage::client::EcRequestControl control;
    control.deadline = deadline;
    control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
    storageInvoked = true;
    auto observed = action == storage::EcTargetRetirementAction::Prepare
                        ? co_await folly::coro::co_withCancellation(
                              {}, state->client->prepareEcTargetRetirement(*request, state->key, control))
                        : co_await folly::coro::co_withCancellation(
                              {}, state->client->queryEcTargetRetirement(*request, state->key, control));
    if (!observed) co_return makeError(std::move(observed.error()));
    CO_RETURN_ON_ERROR(storage::verifyEcTargetRetirementObservation(*state->key, *observed, *request));
    if (!observed->claims.durable || observed->claims.inflight ||
        observed->claims.state != storage::EcTargetRetirementState::LocalDataDrained)
      co_return response(accepted);
    // Even after readonly/stop changes, finish recording an already obtained
    // valid completion. This is evidence persistence, not another disk action.
    auto raw = state->engine->createReadWriteTransaction();
    if (!raw) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    EcFileTreeTxnBudget txn(*raw);
    auto completed = co_await EcTargetRetirementCatalog::recordCompletion(txn, intent, *request, *observed, *state->key);
    CO_RETURN_ON_ERROR(completed);
    commitStarted = true;
    auto committed = co_await txn.commit();
    if (!committed) co_return makeError(std::move(committed.error()));
    co_return response(*completed);
  } catch (const std::bad_alloc &) {
    co_return makeError(storageInvoked ? StorageCode::kEcSealOutcomeUnknown
                                      : commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(storageInvoked ? StorageCode::kEcSealOutcomeUnknown
                                      : commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
}  // namespace hf3fs::meta::server
