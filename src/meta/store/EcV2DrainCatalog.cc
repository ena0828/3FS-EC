#include "meta/store/EcV2DrainCatalog.h"

#include <limits>

#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
using Kind = storage::EcGrantScope;
Result<Void> issuedMatches(const EcV2DrainRecord &record, size_t index, const storage::EcScopeControlRequest &issued) {
  RETURN_ON_ERROR(drainValid(record));
  const auto &id = record.identity;
  if (index >= id.endpoints.count) return makeError(StatusCode::kInvalidArg, "invalid drain endpoint index");
  const auto &endpoint = id.endpoints.endpoints[index];
  const auto &claims = issued.claims;
  if (claims.clusterAuthority != id.clusterAuthority || claims.object != id.object.incarnation ||
      claims.scopeKind != id.kind || claims.scopeId != id.scopeId || claims.ownerUid != id.owner.uid ||
      claims.clientNamespace != id.owner.client || claims.revocationId != id.revocationId ||
      claims.endpointSetDigest != id.endpoints.digest || claims.engineUuid != endpoint.engineUuid ||
      claims.targetIncarnation != endpoint.targetIncarnation || claims.chainId != endpoint.placement.chain ||
      claims.targetId != endpoint.placement.target || claims.nodeId != endpoint.placement.node) {
    return makeError(StatusCode::kTokenMismatch, "control request differs from fixed drain scope or endpoint");
  }
  return Void{};
}
Result<Void> authorityMatches(const EcV2DrainRecord &record, const Uuid &authority) {
  if (authority.is_nil() || authority != record.identity.clusterAuthority) {
    return makeError(StatusCode::kTokenMismatch, "drain authority cannot change across retry");
  }
  return Void{};
}
Result<Void> completeEvidence(const EcV2DrainRecord &record, const storage::EcScopeControlKey &key) {
  RETURN_ON_ERROR(drainValid(record));
  for (size_t i = 0; i != record.identity.endpoints.count; ++i) {
    if (!record.observations[i]) return makeError(StatusCode::kTokenStale, "not every fixed instance has drained");
    const auto &observation = *record.observations[i];
    RETURN_ON_ERROR(EcVerifiedDrainAck::verify(key, record, i, observation.request, observation.ack));
  }
  return Void{};
}
CoTryTask<EcV2DrainRecord> required(Tx &txn,
                                    const EcObjectRef &object,
                                    Kind kind,
                                    const Uuid &scope,
                                    const EcOwner &owner) {
  auto record = co_await EcV2DrainCatalog::get(txn, object, kind, scope, owner);
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return makeError(StatusCode::kTokenStale, "scope has not started durable drain");
  co_return **record;
}
Result<Void> writeMatches(const EcV2DrainRecord &record, const EcV2Reservation &reservation) {
  const auto &op = reservation.original;
  const auto &id = record.identity;
  if (id.kind != Kind::WriteOperation || id.object != op.intent.object || id.scopeId != op.intent.operation ||
      !same(id.owner, op.owner) || id.objectEpoch != op.intent.expectedEpoch ||
      id.generation != op.candidate.generation || id.revision != op.candidate.revision ||
      !same(id.endpoints, reservation.operationEndpoints)) {
    return makeError(StatusCode::kDataCorruption, "drain lost its fixed operation reservation");
  }
  return Void{};
}
Result<Void> proofMatches(const EcManifest &manifest,
                          const storage::EcSha256 &content,
                          const EcV2Reservation &reservation,
                          const EcV2OperationBinding &binding) {
  const auto &candidate = reservation.original.candidate;
  if (content != reservation.contentSha256 || content == storage::EcSha256{} || manifest.version != kEcCatalogVersion ||
      manifest.object != candidate.object || manifest.stripe != candidate.stripe ||
      manifest.generation != candidate.generation || manifest.revision != candidate.revision ||
      manifest.logicalLength != candidate.logicalLength || !same(binding.intent, reservation.original.intent) ||
      !same(binding.owner, reservation.original.owner) ||
      !same(binding.operationEndpoints, reservation.operationEndpoints)) {
    return makeError(StatusCode::kTokenMismatch, "publication evidence differs from fixed Begin/binding");
  }
  for (size_t i = 0; i != 12; ++i) {
    if (manifest.fragments[i] != binding.allocations[i].fragment) {
      return makeError(StatusCode::kTokenMismatch,
                       "publication evidence does not identify the exact bound allocations");
    }
    RETURN_ON_ERROR(storage::validateEcIntegrity(manifest.fragments[i].identity, manifest.fragments[i].integrity));
  }
  return Void{};
}
EcV2DrainRecord writeRecord(const EcV2Reservation &reservation, const Uuid &authority, const Uuid &revocation) {
  EcV2DrainRecord record;
  const auto &op = reservation.original;
  auto &id = record.identity;
  id.object = op.intent.object;
  id.kind = Kind::WriteOperation;
  id.scopeId = op.intent.operation;
  id.owner = op.owner;
  id.objectEpoch = op.intent.expectedEpoch;
  id.generation = op.candidate.generation;
  id.revision = op.candidate.revision;
  id.clusterAuthority = authority;
  id.revocationId = revocation;
  id.endpoints = reservation.operationEndpoints;
  return record;
}
}  // namespace

Result<EcVerifiedDrainAck> EcVerifiedDrainAck::verify(const storage::EcScopeControlKey &key,
                                                      const EcV2DrainRecord &record,
                                                      size_t index,
                                                      const storage::EcScopeControlRequest &issued,
                                                      const storage::EcScopeControlAck &observed) {
  RETURN_ON_ERROR(issuedMatches(record, index, issued));
  // This verifies both the original request MAC and the ACK MAC, their exact
  // canonical binding and observation time. Durable deny evidence has no TTL.
  RETURN_ON_ERROR(storage::verifyEcScopeControlAck(key, observed, issued));
  if (observed.claims.state != storage::EcScopeControlState::Drained || !observed.claims.durable ||
      observed.claims.inflight != 0) {
    return makeError(StatusCode::kTokenStale, "scope is durably denied but admitted jobs have not drained");
  }
  return EcVerifiedDrainAck(record.identity, index, EcV2DrainObservation{issued, observed});
}

Result<storage::EcScopeControlRequest> EcV2DrainCatalog::makeRequest(const EcV2DrainRecord &record,
                                                                     size_t index,
                                                                     storage::EcScopeControlAction action,
                                                                     const storage::EcScopeControlKey &key,
                                                                     uint64_t now,
                                                                     uint64_t ttl) {
  using namespace ec_v2_lifecycle;
  RETURN_ON_ERROR(drainValid(record));
  if (index >= record.identity.endpoints.count || !ttl || ttl > storage::kEcScopeControlMaxTtlSeconds ||
      now > std::numeric_limits<uint64_t>::max() - ttl) {
    return makeError(StatusCode::kInvalidArg, "invalid drain request index or lifetime");
  }
  const auto &id = record.identity;
  const auto &endpoint = id.endpoints.endpoints[index];
  storage::EcScopeControlClaims claims;
  claims.action = action;
  claims.clusterAuthority = id.clusterAuthority;
  claims.nodeId = endpoint.placement.node;
  claims.chainId = endpoint.placement.chain;
  claims.targetId = endpoint.placement.target;
  claims.engineUuid = endpoint.engineUuid;
  claims.targetIncarnation = endpoint.targetIncarnation;
  claims.object = id.object.incarnation;
  claims.scopeKind = id.kind;
  claims.scopeId = id.scopeId;
  claims.ownerUid = id.owner.uid;
  claims.clientNamespace = id.owner.client;
  claims.endpointSetDigest = id.endpoints.digest;
  claims.revocationId = id.revocationId;
  claims.nonce = Uuid::random();
  claims.issuedAtSeconds = now;
  claims.expiresAtSeconds = now + ttl;
  return storage::signEcScopeControl(key, claims, now);
}

CoTryTask<std::optional<EcV2DrainRecord>> EcV2DrainCatalog::get(Transaction &txn,
                                                                const EcObjectRef &object,
                                                                Kind kind,
                                                                const Uuid &scope,
                                                                const EcOwner &owner) {
  using namespace ec_v2_lifecycle;
  CO_RETURN_ON_ERROR(scopeValid(kind, scope));
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  auto record = co_await load<EcV2DrainRecord>(txn, drainKey(object, kind, scope));
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return std::nullopt;
  CO_RETURN_ON_ERROR(drainValid(**record));
  const auto &id = (**record).identity;
  if (id.object != object || id.kind != kind || id.scopeId != scope)
    co_return makeError(StatusCode::kDataCorruption, "V2 drain key mismatch");
  CO_RETURN_ON_ERROR(ownerMatches(id.owner, owner));
  co_return **record;
}

CoTryTask<EcV2DrainRecord> EcV2DrainCatalog::startRead(Transaction &txn,
                                                       const EcObjectRef &object,
                                                       const Uuid &pin,
                                                       const EcOwner &owner,
                                                       const Uuid &authority,
                                                       const Uuid &revocation) {
  using namespace ec_v2_lifecycle;
  auto existing = co_await get(txn, object, Kind::ReadPin, pin, owner);
  CO_RETURN_ON_ERROR(existing);
  if (*existing) {
    CO_RETURN_ON_ERROR(authorityMatches(**existing, authority));
    co_return **existing;
  }
  auto snapshot = co_await EcV2BindingCatalog::getPinSnapshot(txn, object, pin, owner);
  CO_RETURN_ON_ERROR(snapshot);
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  EcV2DrainRecord record;
  auto &id = record.identity;
  id.object = object;
  id.scopeId = pin;
  id.owner = owner;
  id.objectEpoch = file->epoch;
  id.generation = snapshot->generation;
  id.revision = snapshot->revision;
  id.clusterAuthority = authority;
  id.revocationId = revocation;
  for (const auto &endpoint : snapshot->endpoints) CO_RETURN_ON_ERROR(addEndpoint(id.endpoints, endpoint.endpoint));
  auto digest = setDigest(id.endpoints);
  CO_RETURN_ON_ERROR(digest);
  id.endpoints.digest = *digest;
  if (*digest != snapshot->endpointSetDigest) co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(drainValid(record));
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::ReadPin, pin), record));
  co_return record;
}

CoTryTask<EcV2DrainRecord> EcV2DrainCatalog::startCancel(Transaction &txn,
                                                         const EcObjectRef &object,
                                                         const Uuid &operation,
                                                         const EcOwner &owner,
                                                         const Uuid &authority,
                                                         const Uuid &revocation) {
  using namespace ec_v2_lifecycle;
  auto existing = co_await get(txn, object, Kind::WriteOperation, operation, owner);
  CO_RETURN_ON_ERROR(existing);
  if (*existing) {
    CO_RETURN_ON_ERROR(authorityMatches(**existing, authority));
    co_return **existing;
  }
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  auto current = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(current);
  if (current->state != EcOperationState::Preparing)
    co_return makeError(StatusCode::kTokenStale, "operation terminated without V2 drain");
  auto record = writeRecord(*reservation, authority, revocation);
  CO_RETURN_ON_ERROR(drainValid(record));
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::WriteOperation, operation), record));
  co_return record;
}

CoTryTask<EcV2DrainRecord> EcV2DrainCatalog::startPublish(Transaction &txn,
                                                          const EcV2PublishEvidence &evidence,
                                                          const EcOwner &owner,
                                                          const Uuid &authority,
                                                          const Uuid &revocation) {
  using namespace ec_v2_lifecycle;
  const auto &expected = evidence.operation();
  const auto &object = expected.intent.object;
  const auto &operation = expected.intent.operation;
  auto existing = co_await get(txn, object, Kind::WriteOperation, operation, owner);
  CO_RETURN_ON_ERROR(existing);
  if (*existing) {
    CO_RETURN_ON_ERROR(authorityMatches(**existing, authority));
    if (!(**existing).verifiedManifest || (**existing).verifiedManifest != evidence.manifest() ||
        (**existing).verifiedContentSha256 != evidence.contentSha256()) {
      co_return makeError(StatusCode::kTokenStale, "closed scope cannot acquire or replace publication evidence");
    }
    co_return **existing;
  }
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  if (op->state != EcOperationState::Preparing || !same(*op, expected))
    co_return makeError(StatusCode::kTokenStale, "publication snapshot changed before Closing");
  auto file = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(file);
  if (file->deleting || file->epoch != op->intent.expectedEpoch) co_return makeError(StatusCode::kTokenStale);
  auto binding = co_await EcV2BindingCatalog::getOperationBinding(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(binding);
  CO_RETURN_ON_ERROR(proofMatches(evidence.manifest(), evidence.contentSha256(), *reservation, *binding));
  auto record = writeRecord(*reservation, authority, revocation);
  record.verifiedManifest = evidence.manifest();
  record.verifiedContentSha256 = evidence.contentSha256();
  CO_RETURN_ON_ERROR(drainValid(record));
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::WriteOperation, operation), record));
  co_return record;
}

CoTryTask<EcV2DrainRecord> EcV2DrainCatalog::recordAck(Transaction &txn, const EcVerifiedDrainAck &evidence) {
  using namespace ec_v2_lifecycle;
  const auto &id = evidence.identity_;
  auto record = co_await required(txn, id.object, id.kind, id.scopeId, id.owner);
  CO_RETURN_ON_ERROR(record);
  if (!same(record->identity, id) || evidence.index_ >= id.endpoints.count)
    co_return makeError(StatusCode::kTokenMismatch, "drain scope changed before storing observation");
  if (record->observations[evidence.index_]) co_return record;
  if (record->state != EcV2DrainState::Closing)
    co_return makeError(StatusCode::kDataCorruption, "terminal drain is missing an ACK");
  record->observations[evidence.index_] = evidence.observation_;
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(id.object, id.kind, id.scopeId), *record));
  co_return record;
}

CoTryTask<EcPinRecord> EcV2DrainCatalog::finishRead(Transaction &txn,
                                                    const EcObjectRef &object,
                                                    const Uuid &pin,
                                                    const EcOwner &owner,
                                                    const storage::EcScopeControlKey &key) {
  using namespace ec_v2_lifecycle;
  auto record = co_await required(txn, object, Kind::ReadPin, pin, owner);
  CO_RETURN_ON_ERROR(record);
  CO_RETURN_ON_ERROR(completeEvidence(*record, key));
  auto original = co_await EcCatalog::getPin(txn, object, pin);
  CO_RETURN_ON_ERROR(original);
  CO_RETURN_ON_ERROR(ownerMatches(original->owner, owner));
  if (original->revision != record->identity.revision ||
      original->released != (record->state == EcV2DrainState::ReadReleased)) {
    co_return makeError(StatusCode::kDataCorruption, "historical read pin changed outside V2 drain");
  }
  auto historical = co_await EcCatalog::getManifest(txn, object, original->stripe, original->revision);
  CO_RETURN_ON_ERROR(historical);
  if (historical->manifest.generation != record->identity.generation) co_return makeError(StatusCode::kDataCorruption);
  if (original->released) co_return original;
  auto snapshot = co_await EcV2BindingCatalog::getPinSnapshot(txn, object, pin, owner);
  CO_RETURN_ON_ERROR(snapshot);
  if (snapshot->endpointSetDigest != record->identity.endpoints.digest)
    co_return makeError(StatusCode::kDataCorruption);
  CO_RETURN_ON_ERROR(co_await EcCatalog::releaseRead(txn, object, pin));
  record->state = EcV2DrainState::ReadReleased;
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::ReadPin, pin), *record));
  co_return co_await EcCatalog::getPin(txn, object, pin);
}

CoTryTask<EcOperationRecord> EcV2DrainCatalog::finishCancel(Transaction &txn,
                                                            const EcObjectRef &object,
                                                            const Uuid &operation,
                                                            const EcOwner &owner,
                                                            const storage::EcScopeControlKey &key) {
  using namespace ec_v2_lifecycle;
  auto record = co_await required(txn, object, Kind::WriteOperation, operation, owner);
  CO_RETURN_ON_ERROR(record);
  CO_RETURN_ON_ERROR(completeEvidence(*record, key));
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  CO_RETURN_ON_ERROR(writeMatches(*record, *reservation));
  auto current = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(current);
  if (record->state != EcV2DrainState::Closing) {
    const auto expected =
        record->state == EcV2DrainState::Published ? EcOperationState::Published : EcOperationState::Aborted;
    if (current->state != expected) co_return makeError(StatusCode::kDataCorruption);
    co_return current;
  }
  if (current->state != EcOperationState::Preparing)
    co_return makeError(StatusCode::kDataCorruption, "operation terminated outside V2 drain");
  auto cancelled = co_await EcCatalog::cancel(txn, object, operation);
  CO_RETURN_ON_ERROR(cancelled);
  record->state = EcV2DrainState::Aborted;
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::WriteOperation, operation), *record));
  co_return cancelled;
}

CoTryTask<EcOperationRecord> EcV2DrainCatalog::finishPublish(Transaction &txn,
                                                             const EcObjectRef &object,
                                                             const Uuid &operation,
                                                             const EcOwner &owner,
                                                             const storage::EcScopeControlKey &key) {
  using namespace ec_v2_lifecycle;
  auto record = co_await required(txn, object, Kind::WriteOperation, operation, owner);
  CO_RETURN_ON_ERROR(record);
  CO_RETURN_ON_ERROR(completeEvidence(*record, key));
  if (!record->verifiedManifest || record->state == EcV2DrainState::Aborted) {
    co_return makeError(StatusCode::kTokenStale, "scope has no durable publication evidence or is aborted");
  }
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  CO_RETURN_ON_ERROR(writeMatches(*record, *reservation));
  auto binding = co_await EcV2BindingCatalog::getOperationBinding(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(binding);
  CO_RETURN_ON_ERROR(proofMatches(*record->verifiedManifest, record->verifiedContentSha256, *reservation, *binding));
  auto current = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(current);
  if (current->state !=
      (record->state == EcV2DrainState::Published ? EcOperationState::Published : EcOperationState::Preparing)) {
    co_return makeError(StatusCode::kDataCorruption, "operation terminated outside V2 drain");
  }
  // Narrow friend access restores only a proof persisted by private coordinator
  // evidence at T0; all bindings and every stored signed ACK were revalidated.
  EcVerifiedManifest restored(*record->verifiedManifest);
  auto published = co_await EcCatalog::publish(txn, object, operation, restored);
  CO_RETURN_ON_ERROR(published);
  record->state = EcV2DrainState::Published;
  CO_RETURN_ON_ERROR(co_await save(txn, drainKey(object, Kind::WriteOperation, operation), *record));
  co_return published;
}
}  // namespace hf3fs::meta::server
