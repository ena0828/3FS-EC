#include "meta/components/EcGcCoordinator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <folly/ScopeGuard.h>
#include <limits>
#include <new>

namespace hf3fs::meta::server {
namespace {
using Control = storage::client::EcRequestControl;

bool sameEndpoint(const storage::EcScopeEndpoint &a, const storage::EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}

Result<Void> ready(const Control &control) {
  if (control.transport != Control::TransportPolicy::TcpOnly ||
      control.deadline == std::chrono::steady_clock::time_point::max())
    return makeError(StatusCode::kInvalidArg, "GC requires a finite TCP-only transport deadline");
  if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}

Status unknown(Status error) noexcept {
  try {
    return error.convert(StorageCode::kEcSealOutcomeUnknown);
  } catch (...) {
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}
}  // namespace

struct EcGcCoordinator::State {
  Config config;
  std::shared_ptr<kv::IKVEngine> engine;
  std::shared_ptr<const storage::EcGcKey> key;
  std::shared_ptr<EcGcTransport> transport;
  std::atomic<uint32_t> active{0};

  bool enter() {
    auto current = active.load(std::memory_order_relaxed);
    while (current < config.maxConcurrent) {
      if (active.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel)) return true;
    }
    return false;
  }
};

Result<std::unique_ptr<EcGcCoordinator>> EcGcCoordinator::create(Config config,
                                                                 std::shared_ptr<kv::IKVEngine> engine,
                                                                 std::shared_ptr<const storage::EcGcKey> key,
                                                                 std::shared_ptr<EcGcTransport> transport) {
  if (!engine || !key || !transport || config.authority.is_nil() || !config.requestTtlSeconds ||
      config.requestTtlSeconds > storage::kEcGcMaxTtlSeconds || !config.maxConcurrent || config.maxConcurrent > 64 ||
      config.targets.empty() || config.targets.size() > 1024)
    return makeError(StatusCode::kInvalidConfig, "invalid internal GC coordinator configuration");
  for (size_t i = 0; i < config.targets.size(); ++i) {
    const auto &target = config.targets[i];
    const auto &e = target.endpoint;
    if (!target.enabled || target.dataProtocol != 2 || target.diskFormat != 3 || target.gcProtocol != 1 ||
        e.nodeId == flat::NodeId{} || e.chainId == storage::ChainId{} || e.targetId == storage::TargetId{} ||
        e.engineUuid.is_nil() || e.targetIncarnation.is_nil())
      return makeError(StatusCode::kInvalidConfig, "GC target requires an exact enabled instance and protocols");
    for (size_t j = 0; j < i; ++j)
      if (sameEndpoint(config.targets[j].endpoint, e))
        return makeError(StatusCode::kInvalidConfig, "duplicate GC target instance");
  }
  if (!config.nowSeconds)
    config.nowSeconds = [] {
      return static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
              .count());
    };
  auto state = std::make_shared<State>();
  state->config = std::move(config);
  state->engine = std::move(engine);
  state->key = std::move(key);
  state->transport = std::move(transport);
  return std::unique_ptr<EcGcCoordinator>(new EcGcCoordinator(std::move(state)));
}

CoTryTask<EcConfirmedGcClaim> EcGcCoordinator::loadCommitted(std::shared_ptr<State> state,
                                                             EcObjectRef object,
                                                             storage::EcFragmentIdentity identity,
                                                             Uuid claimId) {
  if (claimId.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  // An externally supplied transaction cannot leak its uncommitted RYW state
  // across this boundary. A fresh database read is mandatory even after retry.
  auto txn = state->engine->createReadWriteTransaction();
  auto claim = co_await EcV2GcCatalog::getClaim(*txn, object, identity);
  CO_RETURN_ON_ERROR(claim);
  if (!*claim) co_return makeError(StatusCode::kTokenStale, "GC claim is not durably present");
  if ((**claim).claimId != claimId) co_return makeError(StatusCode::kTokenMismatch);
  auto certificate = EcGcCompletionCatalog::project(**claim);
  CO_RETURN_ON_ERROR(certificate);
  auto committedRead = co_await txn->commit();
  CO_RETURN_ON_ERROR(committedRead);
  co_return EcConfirmedGcClaim(std::move(**claim), std::move(*certificate));
}

CoTryTask<std::optional<EcGcCompletion>> EcGcCoordinator::getOwned(std::shared_ptr<State> state,
                                                                   EcObjectRef object,
                                                                   storage::EcFragmentIdentity identity,
                                                                   Uuid claimId) {
  auto txn = state->engine->createReadWriteTransaction();
  co_return co_await EcGcCompletionCatalog::get(*txn, object, identity, claimId, *state->key, state->config.authority);
}

CoTryTask<EcGcCompletion> EcGcCoordinator::executeOwned(std::shared_ptr<State> state,
                                                        EcObjectRef object,
                                                        storage::EcFragmentIdentity identity,
                                                        Uuid claimId,
                                                        storage::EcGcAction action,
                                                        Control control) {
  CO_RETURN_ON_ERROR(ready(control));
  if (!state->enter()) co_return makeError(StorageClientCode::kResourceBusy);
  SCOPE_EXIT { state->active.fetch_sub(1, std::memory_order_release); };
  bool dispatched = false;
  try {
    auto confirmed = co_await loadCommitted(state, object, identity, claimId);
    CO_RETURN_ON_ERROR(confirmed);
    auto prior = co_await getOwned(state, object, identity, claimId);
    CO_RETURN_ON_ERROR(prior);
    if (*prior) co_return std::move(**prior);
    const auto &certificate = confirmed->certificate();
    const auto target =
        std::find_if(state->config.targets.begin(), state->config.targets.end(), [&](const auto &value) {
          return sameEndpoint(value.endpoint, certificate.endpoint);
        });
    if (target == state->config.targets.end())
      co_return makeError(StatusCode::kNotImplemented, "exact claimed instance is not configured for GC");
    CO_RETURN_ON_ERROR(ready(control));
    const auto now = state->config.nowSeconds();
    if (now > std::numeric_limits<uint64_t>::max() - state->config.requestTtlSeconds)
      co_return makeError(StatusCode::kInvalidArg, "GC request time overflows");
    storage::EcGcRequestClaims claims;
    claims.action = action;
    claims.keyId = state->key->keyId();
    claims.authority = state->config.authority;
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = now;
    claims.expiresAtSeconds = now + state->config.requestTtlSeconds;
    claims.certificate = certificate;
    // Only this friend may reach RequestSigner. Its input came from a new
    // committed DB read, not a caller-supplied certificate or receipt.
    auto request =
        storage::ec_gc_control_detail::RequestSigner::sign(*state->key, claims, now, storage::kEcGcMaxTtlSeconds);
    CO_RETURN_ON_ERROR(request);
    CO_RETURN_ON_ERROR(ready(control));
    dispatched = true;
    // Cancellation is explicit in control. An inherited coroutine token must
    // not destroy the owned transport frame before its real RPC settles.
    auto response = co_await folly::coro::co_withCancellation({}, state->transport->exchange(*request, control));
    if (!response) {
      if (action == storage::EcGcAction::Collect) co_return makeError(unknown(std::move(response.error())));
      co_return makeError(std::move(response.error()));
    }
    // Do not discard a valid historical irreversible receipt just because the
    // local caller cancels after delivery. G2 persists it while owning all data.
    auto txn = state->engine->createReadWriteTransaction();
    auto completed = co_await EcGcCompletionCatalog::record(*txn,
                                                            object,
                                                            identity,
                                                            claimId,
                                                            *request,
                                                            *response,
                                                            *state->key,
                                                            state->config.authority);
    if (!completed) co_return makeError(unknown(std::move(completed.error())));
    auto committed = co_await txn->commit();
    if (!committed) co_return makeError(unknown(std::move(committed.error())));
    co_return std::move(*completed);
  } catch (const std::bad_alloc &) {
    co_return makeError(dispatched ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    co_return makeError(dispatched ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  } catch (...) {
    co_return makeError(dispatched ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}

CoTryTask<EcGcCompletion> EcGcCoordinator::collect(EcObjectRef object,
                                                   storage::EcFragmentIdentity identity,
                                                   Uuid claimId,
                                                   Control control) const {
  return executeOwned(state_, object, identity, claimId, storage::EcGcAction::Collect, std::move(control));
}
CoTryTask<EcGcCompletion> EcGcCoordinator::query(EcObjectRef object,
                                                 storage::EcFragmentIdentity identity,
                                                 Uuid claimId,
                                                 Control control) const {
  return executeOwned(state_, object, identity, claimId, storage::EcGcAction::Query, std::move(control));
}
CoTryTask<std::optional<EcGcCompletion>> EcGcCoordinator::getCompletion(EcObjectRef object,
                                                                        storage::EcFragmentIdentity identity,
                                                                        Uuid claimId) const {
  return getOwned(state_, object, identity, claimId);
}
}  // namespace hf3fs::meta::server
