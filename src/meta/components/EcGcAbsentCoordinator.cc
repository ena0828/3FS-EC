#include "meta/components/EcGcAbsentCoordinator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <folly/ScopeGuard.h>
#include <limits>
#include <new>

#include "meta/store/EcGcCompletionCatalog.h"

namespace hf3fs::meta::server {
namespace {
using Control = storage::client::EcRequestControl;
bool sameEndpoint(const storage::EcScopeEndpoint &a, const storage::EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId &&
         a.engineUuid == b.engineUuid && a.targetIncarnation == b.targetIncarnation;
}
Result<Void> ready(const Control &c) {
  if (c.transport != Control::TransportPolicy::TcpOnly || c.deadline == std::chrono::steady_clock::time_point::max())
    return makeError(StatusCode::kInvalidArg);
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
Status unknown(Status s) noexcept {
  try { return s.convert(StorageCode::kEcSealOutcomeUnknown); }
  catch (...) { return Status(StorageCode::kEcSealOutcomeUnknown); }
}
}  // namespace
struct EcGcAbsentCoordinator::State {
  Config config;
  std::shared_ptr<kv::IKVEngine> engine;
  std::shared_ptr<const storage::EcScopeControlKey> control;
  std::shared_ptr<const storage::EcGcKey> key;
  std::shared_ptr<EcGcAbsentTransport> transport;
  std::atomic<uint32_t> active{0};
  bool enter() {
    auto n = active.load(std::memory_order_relaxed);
    while (n < config.maxConcurrent)
      if (active.compare_exchange_weak(n, n + 1, std::memory_order_acq_rel)) return true;
    return false;
  }
};
Result<std::unique_ptr<EcGcAbsentCoordinator>> EcGcAbsentCoordinator::create(Config config,
    std::shared_ptr<kv::IKVEngine> engine, std::shared_ptr<const storage::EcScopeControlKey> control,
    std::shared_ptr<const storage::EcGcKey> key, std::shared_ptr<EcGcAbsentTransport> transport) {
  if (!engine || !control || !key || !transport || config.authority.is_nil() || !config.requestTtlSeconds ||
      config.requestTtlSeconds > storage::kEcGcMaxTtlSeconds || !config.maxConcurrent || config.maxConcurrent > 64 ||
      config.targets.empty() || config.targets.size() > 1024)
    return makeError(StatusCode::kInvalidConfig);
  for (size_t n = 0; n < config.targets.size(); ++n) {
    const auto &t = config.targets[n];
    if (!t.enabled || t.dataProtocol != 2 || t.diskFormat != 3 || t.gcProtocol != 2 ||
        t.endpoint.nodeId == flat::NodeId{} || t.endpoint.chainId == storage::ChainId{} ||
        t.endpoint.targetId == storage::TargetId{} || t.endpoint.engineUuid.is_nil() || t.endpoint.targetIncarnation.is_nil())
      return makeError(StatusCode::kInvalidConfig);
    for (size_t p = 0; p < n; ++p)
      if (sameEndpoint(t.endpoint, config.targets[p].endpoint)) return makeError(StatusCode::kInvalidConfig);
  }
  if (!config.nowSeconds) config.nowSeconds = [] {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
  };
  auto state = std::make_shared<State>();
  state->config = std::move(config);
  state->engine = std::move(engine);
  state->control = std::move(control);
  state->key = std::move(key);
  state->transport = std::move(transport);
  return std::unique_ptr<EcGcAbsentCoordinator>(new EcGcAbsentCoordinator(std::move(state)));
}
CoTryTask<EcGcAbsentCompletion> EcGcAbsentCoordinator::executeOwned(std::shared_ptr<State> s,
    EcObjectRef object, storage::EcFragmentIdentity identity, Uuid claimId,
    storage::EcGcAbsentAction action, Control control) {
  CO_RETURN_ON_ERROR(ready(control));
  if (!s->enter()) co_return makeError(StorageClientCode::kResourceBusy);
  SCOPE_EXIT { s->active.fetch_sub(1, std::memory_order_release); };
  bool dispatched = false;
  try {
    EcGcBoundClosure bound;
    {
      auto raw = s->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
      auto read = co_await EcTreeGcCatalog::closureForClaim(tx, object, identity, claimId, *s->control);
      CO_RETURN_ON_ERROR(read);
      CO_RETURN_ON_ERROR(co_await tx.commit());
      bound = std::move(*read);
    }
    {
      auto raw = s->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
      auto prior = co_await EcGcAbsentCompletionCatalog::get(tx, object, identity, claimId,
                                                            *s->control, *s->key, s->config.authority);
      CO_RETURN_ON_ERROR(prior);
      if (*prior) co_return **prior;
    }
    auto certificate = EcGcCompletionCatalog::project(bound.claim);
    CO_RETURN_ON_ERROR(certificate);
    auto closure = EcGcAbsentCompletionCatalog::project(bound);
    CO_RETURN_ON_ERROR(closure);
    if (bound.drain.identity.clusterAuthority != s->config.authority ||
        std::none_of(s->config.targets.begin(), s->config.targets.end(), [&](const auto &t) {
          return sameEndpoint(t.endpoint, certificate->endpoint);
        })) co_return makeError(StatusCode::kTokenMismatch);
    CO_RETURN_ON_ERROR(ready(control));
    const auto now = s->config.nowSeconds();
    if (now > std::numeric_limits<uint64_t>::max() - s->config.requestTtlSeconds)
      co_return makeError(StatusCode::kInvalidArg);
    storage::EcGcAbsentRequestClaims claims;
    claims.action = action;
    claims.keyId = s->key->keyId();
    claims.authority = s->config.authority;
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = now;
    claims.expiresAtSeconds = now + s->config.requestTtlSeconds;
    claims.certificate = *certificate;
    claims.closure = std::move(*closure);
    auto request = storage::ec_gc_absent_detail::RequestSigner::sign(*s->key, claims, now);
    CO_RETURN_ON_ERROR(request);
    CO_RETURN_ON_ERROR(ready(control));
    dispatched = true;
    auto response = co_await folly::coro::co_withCancellation({}, s->transport->exchange(*request, control));
    if (!response) {
      if (action == storage::EcGcAbsentAction::ConfirmAbsent)
        co_return makeError(unknown(std::move(response.error())));
      co_return makeError(std::move(response.error()));
    }
    auto raw = s->engine->createReadWriteTransaction();
    if (!raw) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
    auto stored = co_await EcGcAbsentCompletionCatalog::record(tx, object, identity, claimId, *request, *response,
                                                             *s->control, *s->key, s->config.authority);
    if (!stored) co_return makeError(unknown(std::move(stored.error())));
    auto committed = co_await tx.commit();
    if (!committed) co_return makeError(unknown(std::move(committed.error())));
    co_return *stored;
  } catch (const std::bad_alloc &) {
    co_return makeError(dispatched ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(dispatched ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
CoTryTask<EcGcAbsentCompletion> EcGcAbsentCoordinator::confirm(EcObjectRef object,
    storage::EcFragmentIdentity identity, Uuid claimId, Control control) const {
  return executeOwned(state_, object, identity, claimId, storage::EcGcAbsentAction::ConfirmAbsent, std::move(control));
}
CoTryTask<EcGcAbsentCompletion> EcGcAbsentCoordinator::query(EcObjectRef object,
    storage::EcFragmentIdentity identity, Uuid claimId, Control control) const {
  return executeOwned(state_, object, identity, claimId, storage::EcGcAbsentAction::QueryAbsent, std::move(control));
}
}  // namespace hf3fs::meta::server
