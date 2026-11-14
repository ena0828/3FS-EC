#include "meta/components/EcGcAdminCoordinator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <folly/ScopeGuard.h>
#include <limits>
#include <new>

#include "fbs/storage/EcGcDiscovery.h"
#include "fbs/storage/EcGcAbsentDiscovery.h"
#include "meta/store/EcExactGcCatalog.h"

namespace hf3fs::meta::server {
namespace {
uint64_t wallSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
bool sameEndpoint(const storage::EcScopeEndpoint &a, const storage::EcScopeEndpoint &b) {
  return a.nodeId == b.nodeId && a.chainId == b.chainId && a.targetId == b.targetId && a.engineUuid == b.engineUuid &&
         a.targetIncarnation == b.targetIncarnation;
}
EcGcAdminRsp response(const EcGcCompletion &completed) {
  EcGcAdminRsp out;
  out.object = completed.object;
  out.identity = completed.identity;
  out.claimId = completed.claimId;
  out.claimDigest = completed.claimDigest;
  out.ledgerSha256 = completed.ack.claims.ledgerSha256;
  out.terminalRevision = completed.ack.claims.terminalRevision;
  return out;
}
}  // namespace

struct EcGcAdminCoordinator::State {
  explicit State(const Config &value)
      : config(value) {}
  const Config &config;
  std::shared_ptr<kv::IKVEngine> engine;
  std::shared_ptr<storage::client::StorageClient> client;
  std::shared_ptr<const storage::EcScopeControlKey> controlKey;
  std::shared_ptr<const storage::EcGcKey> key;
  std::shared_ptr<NativeEcGcTransport> transport;
  std::shared_ptr<NativeEcGcAbsentTransport> absentTransport;
  Uuid authority = Uuid::zero();
  std::atomic<bool> closing{false};
  std::atomic<uint32_t> active{0};

  bool enter() {
    auto value = active.load(std::memory_order_relaxed);
    while (value < config.ec_gc_max_concurrent()) {
      if (active.compare_exchange_weak(value, value + 1, std::memory_order_acq_rel)) return true;
    }
    return false;
  }
  Result<Void> ready(storage::EcGcAction action, std::chrono::steady_clock::time_point deadline) const {
    if (closing.load(std::memory_order_acquire)) return makeError(StorageClientCode::kRequestCanceled);
    if (!config.authenticate()) return makeError(StatusCode::kAuthenticationFail);
    if (action == storage::EcGcAction::Collect && config.readonly()) return makeError(StatusCode::kReadOnlyMode);
    if (std::chrono::steady_clock::now() >= deadline) return makeError(StorageClientCode::kTimeout);
    return Void{};
  }
};

EcGcAdminCoordinator::EcGcAdminCoordinator(const Config &config,
                                           std::shared_ptr<kv::IKVEngine> engine,
                                           std::shared_ptr<storage::client::StorageClient> client,
                                           const EcCoordinator &v1,
                                           const EcV2Coordinator &v2)
    : config_(config) {
  if (!config.enable_ec_exact_gc()) return;
  auto initialize = [&]() -> Result<Void> {
    RETURN_ON_ERROR(v1.checkEnabled());
    RETURN_ON_ERROR(v2.checkEnabled());
    if (!engine || !client || !config.authenticate() || config.ec_gc_key_file().empty() ||
        !config.ec_gc_request_ttl_seconds() || config.ec_gc_request_ttl_seconds() > storage::kEcGcMaxTtlSeconds ||
        config.ec_gc_timeout() <= 0_s || config.ec_gc_timeout() > 300_s || !config.ec_gc_max_concurrent() ||
        config.ec_gc_max_concurrent() > 64)
      return makeError(StatusCode::kInvalidConfig, "invalid explicit Meta GC configuration");
    auto authority = Uuid::fromHexString(config.ec_gc_authority());
    auto keyId = Uuid::fromHexString(config.ec_gc_key_id());
    if (!authority || !keyId || authority->is_nil() || keyId->is_nil())
      return makeError(StatusCode::kInvalidConfig, "GC requires explicit authority and key ID");
    auto identities = v2.loadedKeyFileIdentities();
    RETURN_ON_ERROR(identities);
    auto v1Identity = v1.loadedDataKeyFileIdentity();
    RETURN_ON_ERROR(v1Identity);
    identities->push_back(*v1Identity);
    std::vector<storage::EcGcRoleFileIdentity> roles;
    for (const auto &id : *identities) roles.push_back({id.device, id.inode});
    // Uses the same fd that supplied each live role's bytes; no new stat(path)
    // substitutes identity evidence, including the independently loaded V1 key.
    auto key = storage::EcGcKey::loadFile(config.ec_gc_key_file().string(), *keyId, roles);
    RETURN_ON_ERROR(key);
    auto state = std::make_shared<State>(config);
    state->engine = std::move(engine);
    state->client = std::move(client);
    state->controlKey = v2.sharedControlKey();
    if (!state->controlKey) return makeError(StatusCode::kInvalidConfig);
    state->key = std::shared_ptr<const storage::EcGcKey>(std::move(*key));
    state->authority = *authority;
    auto transport = NativeEcGcTransport::create(state->client, state->key);
    RETURN_ON_ERROR(transport);
    state->transport = std::move(*transport);
    auto absent = NativeEcGcAbsentTransport::create(state->client, state->key);
    RETURN_ON_ERROR(absent);
    state->absentTransport = std::move(*absent);
    state_ = std::move(state);
    return Void{};
  };
  auto initialized = initialize();
  if (!initialized) initializationError_ = std::move(initialized.error());
}

Result<Void> EcGcAdminCoordinator::checkEnabled() const {
  if (!config_.enable_ec_exact_gc()) return makeError(StatusCode::kNotImplemented, "explicit Meta GC is disabled");
  if (initializationError_) return makeError(*initializationError_);
  if (!state_) return makeError(StatusCode::kInvalidConfig);
  if (!config_.authenticate()) return makeError(StatusCode::kAuthenticationFail);
  if (state_->closing.load(std::memory_order_acquire)) return makeError(StorageClientCode::kRequestCanceled);
  return Void{};
}
Result<storage::EcKeyFileIdentity> EcGcAdminCoordinator::loadedKeyFileIdentity() const {
  RETURN_ON_ERROR(checkEnabled());
  const auto &id = state_->key->fileIdentity();
  return storage::EcKeyFileIdentity{id.device, id.inode};
}
void EcGcAdminCoordinator::close() {
  if (state_) state_->closing.store(true, std::memory_order_release);
}
CoTryTask<EcGcAdminRsp> EcGcAdminCoordinator::collect(EcGcAdminReq req) const {
  // Task owns its state/identities even after the public waiter is dropped.
  return executeOwned(state_, std::move(req), storage::EcGcAction::Collect);
}
CoTryTask<EcGcAdminRsp> EcGcAdminCoordinator::query(EcGcAdminReq req) const {
  return executeOwned(state_, std::move(req), storage::EcGcAction::Query);
}
CoTryTask<EcAbsentAdminRsp> EcGcAdminCoordinator::confirmAbsent(EcGcAdminReq req) const {
  return executeAbsentOwned(state_, std::move(req), storage::EcGcAbsentAction::ConfirmAbsent);
}
CoTryTask<EcAbsentAdminRsp> EcGcAdminCoordinator::queryAbsent(EcGcAdminReq req) const {
  return executeAbsentOwned(state_, std::move(req), storage::EcGcAbsentAction::QueryAbsent);
}

CoTryTask<EcAbsentAdminRsp> EcGcAdminCoordinator::executeAbsentOwned(std::shared_ptr<State> state,
    EcGcAdminReq req, storage::EcGcAbsentAction action) {
  if (!state) co_return makeError(StatusCode::kNotImplemented);
  CO_RETURN_ON_ERROR(req.valid());
  if (req.client.uuid.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  const auto oldAction = action == storage::EcGcAbsentAction::ConfirmAbsent ? storage::EcGcAction::Collect
                                                                          : storage::EcGcAction::Query;
  const auto deadline = SteadyClock::now() + state->config.ec_gc_timeout();
  CO_RETURN_ON_ERROR(state->ready(oldAction, deadline));
  if (!state->enter()) co_return makeError(StorageClientCode::kResourceBusy);
  SCOPE_EXIT { state->active.fetch_sub(1, std::memory_order_release); };
  bool coordinatorInvoked = false;
  bool committingClaim = false;
  const auto respond = [&](const EcGcAbsentCompletion &c) -> Result<EcAbsentAdminRsp> {
    EcAbsentAdminRsp out;
    out.object = c.object;
    out.identity = c.identity;
    out.claimId = c.claimId;
    out.clientNamespace = req.client.uuid;
    out.requestId = req.uuid;
    out.state = c.ack.claims.state;
    out.claimDigest = c.claimDigest;
    out.closureDigest = c.closureDigest;
    out.ledgerSha256 = c.ack.claims.ledgerSha256;
    out.recordRevision = c.ack.claims.recordRevision;
    out.candidateReservationReleaseEligible = true;
    RETURN_ON_ERROR(out.valid());
    return out;
  };
  try {
    if (action == storage::EcGcAbsentAction::ConfirmAbsent) {
      auto raw = state->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
      auto tree = co_await EcTreeGcCatalog::isTree(tx, req.object);
      CO_RETURN_ON_ERROR(tree);
      if (!*tree) co_return makeError(StatusCode::kNotImplemented, "absence requires an original mode4 G2 claim");
      auto claim = co_await EcTreeGcCatalog::claim(tx, req.object, req.identity, req.claimId, *state->controlKey);
      CO_RETURN_ON_ERROR(claim);
      CO_RETURN_ON_ERROR(state->ready(oldAction, deadline));
      committingClaim = true;
      CO_RETURN_ON_ERROR(co_await tx.commit());
      committingClaim = false;
    }
    EcGcBoundClosure bound;
    {
      // Both actions sign only from a fresh committed view. Query never creates
      // the claim or substitutes a new fence/witness when history is missing.
      auto raw = state->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
      auto original = co_await EcTreeGcCatalog::closureForClaim(tx, req.object, req.identity, req.claimId, *state->controlKey);
      CO_RETURN_ON_ERROR(original);
      CO_RETURN_ON_ERROR(co_await tx.commit());
      bound = std::move(*original);
    }
    {
      auto raw = state->engine->createReadWriteTransaction();
      if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Gc);
      auto prior = co_await EcGcAbsentCompletionCatalog::get(tx, req.object, req.identity, req.claimId,
          *state->controlKey, *state->key, state->authority);
      CO_RETURN_ON_ERROR(prior);
      if (*prior) co_return respond(**prior);
    }
    auto certificate = EcGcCompletionCatalog::project(bound.claim);
    CO_RETURN_ON_ERROR(certificate);
    if (bound.drain.identity.clusterAuthority != state->authority)
      co_return makeError(StatusCode::kTokenMismatch, "absence authority differs from original T2");
    CO_RETURN_ON_ERROR(state->ready(oldAction, deadline));
    const auto now = wallSeconds();
    if (now > std::numeric_limits<uint64_t>::max() - storage::kEcGcAbsentDiscoveryMaxTtlSeconds)
      co_return makeError(StatusCode::kInvalidArg);
    storage::EcGcAbsentDiscoveryClaims claims;
    claims.keyId = state->key->keyId();
    claims.authority = state->authority;
    claims.nodeId = certificate->endpoint.nodeId;
    claims.chainId = certificate->endpoint.chainId;
    claims.targetId = certificate->endpoint.targetId;
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = now;
    claims.expiresAtSeconds = now + storage::kEcGcAbsentDiscoveryMaxTtlSeconds;
    auto request = storage::signEcGcAbsentDiscovery(*state->key, claims, now);
    CO_RETURN_ON_ERROR(request);
    storage::client::EcRequestControl control;
    control.deadline = deadline;
    control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
    auto discoveryControl = control;
    discoveryControl.deadline = std::min(deadline, SteadyClock::now() + 60_s);
    auto observation = co_await folly::coro::co_withCancellation({}, state->client->getEcGcAbsentCapabilityControlled(
        *request, state->key, discoveryControl));
    CO_RETURN_ON_ERROR(observation);
    CO_RETURN_ON_ERROR(storage::verifyEcGcAbsentDiscoveryObservation(*state->key, *observation, *request, wallSeconds()));
    const auto &actual = observation->claims;
    const uint16_t required = action == storage::EcGcAbsentAction::ConfirmAbsent ? 1 : 2;
    if (!sameEndpoint(actual.endpoint, certificate->endpoint))
      co_return makeError(StatusCode::kTokenMismatch, "absence discovery cannot replace original target");
    if (actual.dataProtocol != 2 || actual.diskFormat != 3 || actual.gcProtocol != 2 ||
        (actual.capabilities & required) != required)
      co_return makeError(StatusCode::kNotImplemented, "target does not admit this explicit absence action");
    EcGcAbsentCoordinator::Config config;
    config.authority = state->authority;
    config.requestTtlSeconds = state->config.ec_gc_request_ttl_seconds();
    config.maxConcurrent = 1;
    config.targets.push_back({actual.endpoint, actual.dataProtocol, actual.diskFormat, actual.gcProtocol, true});
    auto coordinator = EcGcAbsentCoordinator::create(std::move(config), state->engine, state->controlKey,
                                                     state->key, state->absentTransport);
    CO_RETURN_ON_ERROR(coordinator);
    CO_RETURN_ON_ERROR(state->ready(oldAction, deadline));
    coordinatorInvoked = true;
    auto result = action == storage::EcGcAbsentAction::ConfirmAbsent
        ? co_await folly::coro::co_withCancellation({}, (*coordinator)->confirm(req.object, req.identity, req.claimId, control))
        : co_await folly::coro::co_withCancellation({}, (*coordinator)->query(req.object, req.identity, req.claimId, control));
    if (!result) co_return makeError(std::move(result.error()));
    co_return respond(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(coordinatorInvoked ? StorageCode::kEcSealOutcomeUnknown
        : committingClaim ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(coordinatorInvoked ? StorageCode::kEcSealOutcomeUnknown
        : committingClaim ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}

CoTryTask<EcGcAdminRsp> EcGcAdminCoordinator::executeOwned(std::shared_ptr<State> state,
                                                           EcGcAdminReq req,
                                                           storage::EcGcAction action) {
  if (!state) co_return makeError(StatusCode::kNotImplemented);
  CO_RETURN_ON_ERROR(req.valid());
  const auto deadline = SteadyClock::now() + state->config.ec_gc_timeout();
  CO_RETURN_ON_ERROR(state->ready(action, deadline));
  if (!state->enter()) co_return makeError(StorageClientCode::kResourceBusy);
  SCOPE_EXIT { state->active.fetch_sub(1, std::memory_order_release); };
  bool coordinatorInvoked = false;
  try {
    // G0 reads the full permanent ref/protection/drain history. It neither
    // retires a revision nor manufactures a claim for mode2/unbound records.
    if (action == storage::EcGcAction::Collect) {
      auto txn = state->engine->createReadWriteTransaction();
      if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
      auto claim = co_await EcExactGcCatalog::claim(*txn, req.object, req.identity, req.claimId, *state->controlKey);
      CO_RETURN_ON_ERROR(claim);
      CO_RETURN_ON_ERROR(state->ready(action, deadline));
      CO_RETURN_ON_ERROR(co_await txn->commit());
    }
    EcGcClaim claim;
    {
      // A separate transaction proves G0 is durable; Query never creates it.
      auto txn = state->engine->createReadWriteTransaction();
      if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
      auto loaded = co_await EcExactGcCatalog::getClaim(*txn, req.object, req.identity);
      CO_RETURN_ON_ERROR(loaded);
      if (!*loaded) co_return makeError(StatusCode::kTokenStale, "no committed exact GC claim");
      if ((**loaded).claimId != req.claimId) co_return makeError(StatusCode::kTokenMismatch);
      claim = std::move(**loaded);
      CO_RETURN_ON_ERROR(co_await txn->commit());
    }
    {
      // Immutable ECGD can be replayed while Storage is unavailable. It still
      // verifies the complete first exchange and the same permanent claim.
      auto txn = state->engine->createReadWriteTransaction();
      if (!txn) co_return makeError(StatusCode::kKVStoreNotFound);
      auto prior = co_await EcGcCompletionCatalog::get(*txn,
                                                       req.object,
                                                       req.identity,
                                                       req.claimId,
                                                       *state->key,
                                                       state->authority);
      CO_RETURN_ON_ERROR(prior);
      if (*prior) co_return response(**prior);
    }
    auto certificate = EcGcCompletionCatalog::project(claim);
    CO_RETURN_ON_ERROR(certificate);
    CO_RETURN_ON_ERROR(state->ready(action, deadline));
    const auto now = wallSeconds();
    if (now > std::numeric_limits<uint64_t>::max() - storage::kEcGcDiscoveryMaxTtlSeconds)
      co_return makeError(StatusCode::kInvalidArg);
    storage::EcGcDiscoveryClaims discoveryClaims;
    discoveryClaims.keyId = state->key->keyId();
    discoveryClaims.authority = state->authority;
    discoveryClaims.nodeId = certificate->endpoint.nodeId;
    discoveryClaims.chainId = certificate->endpoint.chainId;
    discoveryClaims.targetId = certificate->endpoint.targetId;
    discoveryClaims.nonce = Uuid::random();
    discoveryClaims.issuedAtSeconds = now;
    discoveryClaims.expiresAtSeconds = now + storage::kEcGcDiscoveryMaxTtlSeconds;
    auto request = storage::signEcGcDiscovery(*state->key, discoveryClaims, now);
    CO_RETURN_ON_ERROR(request);
    storage::client::EcRequestControl control;
    control.deadline = deadline;
    control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
    auto discoveryControl = control;
    discoveryControl.deadline = std::min(deadline, SteadyClock::now() + 60_s);
    auto observed = co_await folly::coro::co_withCancellation(
        {},
        state->client->getEcGcCapabilityControlled(*request, state->key, discoveryControl));
    CO_RETURN_ON_ERROR(observed);
    CO_RETURN_ON_ERROR(storage::verifyEcGcDiscoveryObservation(*state->key, *observed, *request, wallSeconds()));
    const auto &actual = observed->claims;
    const uint16_t required = action == storage::EcGcAction::Collect ? uint16_t{1} : uint16_t{2};
    if (!sameEndpoint(actual.endpoint, certificate->endpoint))
      co_return makeError(StatusCode::kTokenMismatch, "GC discovery cannot replace the claimed physical instance");
    if (actual.dataProtocol != 2 || actual.diskFormat != 3 ||
        !storage::ecGcProtocolSupports(actual.gcProtocol, certificate->gcProtocol) ||
        (actual.capabilities & required) != required)
      co_return makeError(StatusCode::kNotImplemented, "claimed instance does not admit the requested GC action");
    EcGcCoordinator::Config config;
    config.authority = state->authority;
    config.requestTtlSeconds = state->config.ec_gc_request_ttl_seconds();
    config.maxConcurrent = 1;
    // This is a point-in-time authenticated observation, never a lease. The
    // subsequent actual Storage handler rechecks instance, authority and policy.
    config.targets.push_back({actual.endpoint, actual.dataProtocol, actual.diskFormat, actual.gcProtocol, true});
    auto coordinator = EcGcCoordinator::create(std::move(config), state->engine, state->key, state->transport);
    CO_RETURN_ON_ERROR(coordinator);
    CO_RETURN_ON_ERROR(state->ready(action, deadline));
    coordinatorInvoked = true;
    auto result = action == storage::EcGcAction::Collect
                      ? co_await folly::coro::co_withCancellation(
                            {},
                            (*coordinator)->collect(req.object, req.identity, req.claimId, control))
                      : co_await folly::coro::co_withCancellation(
                            {},
                            (*coordinator)->query(req.object, req.identity, req.claimId, control));
    // Preserve code-only 4085 without a macro that may allocate an explanatory
    // message. Query can also carry an unconfirmed WAL/G2 outcome.
    if (!result) co_return makeError(std::move(result.error()));
    // After a valid historical ACK, G2 must finish even if readonly/closing
    // changes. A hot update cannot atomically revoke already-started disk I/O.
    co_return response(*result);
  } catch (const std::bad_alloc &) {
    co_return makeError(coordinatorInvoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(coordinatorInvoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
}  // namespace hf3fs::meta::server
