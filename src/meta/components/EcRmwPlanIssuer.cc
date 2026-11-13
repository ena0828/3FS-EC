#include "EcRmwPlanIssuer.h"

#include <bit>
#include <limits>

#include "meta/store/EcFileRepairCatalog.h"

namespace hf3fs::meta::server {
using namespace storage;
Result<std::shared_ptr<EcRmwPlanIssuer>> EcRmwPlanIssuer::create(Config c,
                                                                 std::shared_ptr<kv::IKVEngine> db,
                                                                 std::shared_ptr<const EcRmwKey> rmw,
                                                                 std::shared_ptr<const EcCapabilityKey> data) {
  if (!db || !rmw || !data || !c.now || c.authority.is_nil() || !c.ttlSeconds || c.ttlSeconds > 300 ||
      !rmw->fileIdentity() || !data->fileIdentity() || *rmw->fileIdentity() == *data->fileIdentity())
    return makeError(StatusCode::kInvalidConfig, "RMW issuer requires distinct actually-loaded role keys");
  return std::shared_ptr<EcRmwPlanIssuer>(
      new EcRmwPlanIssuer(std::move(c), std::move(db), std::move(rmw), std::move(data)));
}
CoTryTask<EcRmwIssuedExecution> EcRmwPlanIssuer::issue(EcObjectRef object, EcOwner owner, Uuid child) const {
  auto raw = db_->createReadWriteTransaction();
  if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
  EcFileTreeTxnBudget txn(*raw, EcFileTreeTxnBudget::Profile::Rmw);
  auto observed = co_await EcFileExecutionCatalog::reserveIssuance(txn, owner, object, child);
  if (!observed) co_return makeError(std::move(observed.error()));
  std::optional<std::array<uint8_t, 10>> selected;
  uint16_t directMask = 0;
  if (observed->record.ownerKind == EcFileExecutionOwner::Repair) {
    auto repair = co_await EcFileRepairCatalog::byChild(txn, owner, object, child);
    CO_RETURN_ON_ERROR(repair);
    selected = repair->intent.selection.sourceOrder;
    if (repair->intent.mode == EcFileRepairMode::HelperChainDirect) directMask = repair->intent.replacementMask;
  }
  auto committed = co_await txn.commit();
  if (!committed) co_return makeError(std::move(committed.error()));
  auto result = sign(std::move(*observed), directMask);
  CO_RETURN_ON_ERROR(result);
  if (selected) {
    result->repairReads.emplace();
    const auto &plan = *result->observed.plan;
    const auto now = config_.now();
    if (now > UINT64_MAX - config_.ttlSeconds) co_return makeError(StatusCode::kInvalidArg);
    for (size_t n = 0; n < 10; ++n) {
      auto grant = dataGrant(plan.input().sources[(*selected)[n]],
                             plan,
                             EcGrantScope::WriteOperation,
                             child,
                             uint16_t(EcGrantRightV2::ReadBlock),
                             now);
      CO_RETURN_ON_ERROR(grant);
      (*result->repairReads)[n] = std::move(*grant);
    }
  }
  co_return std::move(*result);
}
CoTryTask<EcRmwIssuedExecution> EcRmwPlanIssuer::bind(EcObjectRef object,
                                                      EcOwner owner,
                                                      Uuid child,
                                                      EcRmwGrant execution,
                                                      EcRmwComputedCommitment computed) const {
  auto raw = db_->createReadWriteTransaction();
  if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
  EcFileTreeTxnBudget txn(*raw, EcFileTreeTxnBudget::Profile::Rmw);
  auto current = co_await EcFileExecutionCatalog::get(txn, owner, object, child);
  if (!current) co_return makeError(std::move(current.error()));
  auto allowed = EcRmwAuthorization::verify(*rmw_,
                                            execution,
                                            current->plan,
                                            current->plan->worker(),
                                            config_.authority,
                                            EcRmwRight::Execute,
                                            config_.now());
  if (!allowed) co_return makeError(std::move(allowed.error()));
  auto verified = EcRmwComputationAuthorization::verify(*rmw_, current->plan, computed);
  if (!verified) co_return makeError(std::move(verified.error()));
  auto bound = co_await EcFileExecutionCatalog::bindOutput(txn, owner, object, child, *verified);
  if (!bound) co_return makeError(std::move(bound.error()));
  // bindOutput already performs the one ECFE/ECSP issuance increment.
  auto committed = co_await txn.commit();
  if (!committed) co_return makeError(std::move(committed.error()));
  co_return sign(std::move(*bound));
}
Result<EcCapabilityV2> EcRmwPlanIssuer::dataGrant(const EcRepairFragment &f,
                                                  const EcRmwPlan &plan,
                                                  EcGrantScope kind,
                                                  const Uuid &scope,
                                                  uint16_t rights,
                                                  uint64_t now) const {
  EcGrantClaimsV2 c;
  const auto &p = plan.input();
  c.engineUuid = f.endpoint.engineUuid;
  c.targetIncarnation = f.endpoint.targetIncarnation;
  c.identity = f.identity;
  c.fragmentOperationId = f.operationId;
  c.chainId = f.endpoint.chainId;
  c.targetId = f.endpoint.targetId;
  c.nodeId = f.endpoint.nodeId;
  c.expectedLength = f.integrity.wholeLength;
  c.expectedCrc32c = f.integrity.wholeCrc32c;
  CHECK_RESULT(digest, digestEcIntegrityV2(f.identity, f.integrity));
  c.integrityDigest = digest;
  c.ownerUid = p.ownerUid;
  c.clientNamespace = p.clientNamespace;
  c.scopeObject = p.object;
  c.scopeKind = kind;
  c.scopeId = scope;
  c.rights = rights;
  c.grantId = Uuid::random();
  c.issuedAtSeconds = now;
  c.expiresAtSeconds = now + config_.ttlSeconds;
  return signEcGrantV2(*data_, c, now, config_.ttlSeconds);
}
Result<EcRmwIssuedExecution> EcRmwPlanIssuer::sign(EcFileExecutionObservation observation, uint16_t directMask) const {
  if (!observation.plan || observation.record.issuanceSequence == 0 ||
      (observation.record.state != EcFileExecutionState::Reserved &&
       observation.record.state != EcFileExecutionState::Bound))
    return makeError(StatusCode::kTokenStale);
  const auto now = config_.now();
  if (now > std::numeric_limits<uint64_t>::max() - config_.ttlSeconds) return makeError(StatusCode::kInvalidArg);
  const auto &plan = *observation.plan;
  const auto &p = plan.input();
  EcRmwIssuedExecution issued;
  EcRmwGrantClaims c;
  c.authority = config_.authority;
  c.planDigest = plan.digest();
  c.worker = plan.worker();
  c.grantId = Uuid::random();
  c.issuedAtSeconds = now;
  c.expiresAtSeconds = now + config_.ttlSeconds;
  c.rights = kEcRmwAllRights;
  CHECK_RESULT(internal, EcRmwAuthorization::sign(*rmw_, c, now));
  issued.install = std::move(internal);
  c.rights = uint16_t(EcRmwRight::Upload) | uint16_t(EcRmwRight::Execute) | uint16_t(EcRmwRight::Observe);
  c.grantId = Uuid::random();
  CHECK_RESULT(clientGrant, EcRmwAuthorization::sign(*rmw_, c, now));
  issued.client = std::move(clientGrant);
  if (p.sourceKind == EcRmwSourceKind::Data) {
    issued.reads.emplace();
    for (size_t i = 0; i < 12; ++i) {
      CHECK_RESULT(
          grant,
          dataGrant(p.sources[i], plan, EcGrantScope::ReadPin, p.sourcePin, uint16_t(EcGrantRightV2::ReadBlock), now));
      (*issued.reads)[i] = std::move(grant);
    }
  }
  if (directMask) {
    if ((directMask & ~uint16_t{4095}) || std::popcount(directMask) > 2 ||
        observation.record.ownerKind != EcFileExecutionOwner::Repair || !observation.record.allocations)
      return makeError(StatusCode::kDataCorruption);
    issued.repairAppends.emplace();
    issued.repairQueries.emplace();
  }
  if (observation.record.allocations) {
    issued.writes.emplace();
    size_t selectedTarget = 0;
    for (size_t i = 0; i < 12; ++i) {
      const auto &a = (*observation.record.allocations)[i];
      EcRepairFragment f;
      f.identity = a.fragment.identity;
      f.operationId = a.fragment.operation;
      f.writerNamespace = a.writer.client;
      f.endpoint = a.endpoint().controlEndpoint();
      f.integrity = a.fragment.integrity;
      CHECK_RESULT(grant, dataGrant(f, plan, EcGrantScope::WriteOperation, p.operationId, kEcGrantAllRightsV2, now));
      (*issued.writes)[i] = std::move(grant);
      if (directMask & (uint16_t{1} << i)) {
        // Each is a new MAC over exact rights, never a changed full-rights grant.
        CHECK_RESULT(append, dataGrant(f, plan, EcGrantScope::WriteOperation, p.operationId,
                                      uint16_t(EcGrantRightV2::Append), now));
        CHECK_RESULT(query, dataGrant(f, plan, EcGrantScope::WriteOperation, p.operationId,
                                     uint16_t(EcGrantRightV2::Query), now));
        (*issued.repairAppends)[selectedTarget] = std::move(append);
        (*issued.repairQueries)[selectedTarget++] = std::move(query);
      }
    }
  }
  issued.observed = std::move(observation);
  return issued;
}
}  // namespace hf3fs::meta::server
