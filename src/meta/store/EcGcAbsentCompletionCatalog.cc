#include "meta/store/EcGcAbsentCompletionCatalog.h"

#include "meta/store/EcGcCompletionCatalog.h"
#include "meta/store/detail/EcFileTreeKeys.h"
#include "meta/store/detail/EcGcTxnScope.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_tree_detail;
using Codec = storage::ec_gc_absent_detail::Codec;
using G2 = storage::ec_gc_control_detail::Codec;
CoTryTask<Void> noCollected(kv::IReadWriteTransaction &tx, const storage::EcFragmentIdentity &identity) {
  auto key = allocationKey(kv::KeyPrefix::EcGcCompletion, identity);
  CO_RETURN_ON_ERROR(key);
  auto old = co_await tx.get(*key);
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return makeError(StatusCode::kTokenStale, "Collected completion cannot become AbsentAfterClose");
  co_return Void{};
}
Result<Void> checkExchange(const EcGcBoundClosure &bound, const storage::EcGcAbsentRequest &request,
                           const storage::EcGcAbsentAck &ack, const storage::EcGcKey &key, const Uuid &authority) {
  if (authority.is_nil() || request.claims.authority != authority || request.claims.keyId != key.keyId() ||
      bound.drain.identity.clusterAuthority != authority)
    return makeError(StatusCode::kTokenMismatch, "absence authority differs from original closure");
  CHECK_RESULT(certificate, EcGcCompletionCatalog::project(bound.claim));
  CHECK_RESULT(closure, EcGcAbsentCompletionCatalog::project(bound));
  if (G2::encode(certificate) != G2::encode(request.claims.certificate) ||
      !same(closure, request.claims.closure))
    return makeError(StatusCode::kTokenMismatch, "absence request differs from permanent G2 and original closure");
  RETURN_ON_ERROR(Codec::verifyAck(key, ack, request));
  CHECK_RESULT(claimDigest, G2::claimDigest(certificate));
  CHECK_RESULT(closureDigest, Codec::closureDigest(closure));
  if (ack.claims.state != storage::EcGcAbsentState::AbsentAfterClose || ack.claims.recordRevision != 1 ||
      ack.claims.claimDigest != claimDigest || ack.claims.closureDigest != closureDigest)
    return makeError(StatusCode::kDataCorruption, "absence stable fact differs");
  return Void{};
}
CoTryTask<std::optional<EcGcAbsentCompletion>> getWithClosure(kv::IReadWriteTransaction &tx,
    const EcGcBoundClosure &bound, const storage::EcGcKey &key, const Uuid &authority) {
  const auto &claim = bound.claim;
  CO_RETURN_ON_ERROR(co_await noCollected(tx, claim.allocation.fragment.identity));
  auto k = allocationKey(kv::KeyPrefix::EcGcAbsentCompletion, claim.allocation.fragment.identity);
  CO_RETURN_ON_ERROR(k);
  auto old = co_await load<EcGcAbsentCompletion>(tx, *k);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    const auto &r = **old;
    if (r.version != 1 || r.object != claim.enrollment.object || r.claimId != claim.claimId ||
        !same(r.identity, claim.allocation.fragment.identity))
      co_return makeError(StatusCode::kDataCorruption, "absence completion identity differs");
    CO_RETURN_ON_ERROR(checkExchange(bound, r.request, r.ack, key, authority));
    if (r.claimDigest != r.ack.claims.claimDigest || r.closureDigest != r.ack.claims.closureDigest)
      co_return makeError(StatusCode::kDataCorruption, "absence completion commitment differs");
  }
  co_return old;
}
}  // namespace
Result<storage::EcGcLocalClosureWitness> EcGcAbsentCompletionCatalog::project(const EcGcBoundClosure &bound) {
  const auto &id = bound.drain.identity;
  const auto index = bound.endpointIndex;
  if (bound.claim.version != 2 || bound.claim.enrollment.version != 2 ||
      index >= id.endpoints.count || id.endpoints.endpoints[index] != bound.claim.allocation.endpoint() ||
      id.object != bound.claim.enrollment.object || id.scopeId != bound.claim.allocation.fragment.operation ||
      !same(id.owner, bound.claim.allocation.writer) || id.kind != storage::EcGrantScope::WriteOperation ||
      (bound.drain.state != EcV2DrainState::Published && bound.drain.state != EcV2DrainState::Aborted))
    return makeError(StatusCode::kDataCorruption, "invalid original closure projection");
  storage::EcGcLocalClosureWitness out;
  out.terminalUse = bound.drain.state == EcV2DrainState::Published ? storage::EcGcClosureUse::Publication
                                                                : storage::EcGcClosureUse::FencedAbort;
  out.scopeKind = id.kind;
  out.scopeId = id.scopeId;
  out.ownerUid = id.owner.uid;
  out.clientNamespace = id.owner.client;
  out.objectEpoch = id.objectEpoch;
  out.generation = id.generation;
  out.revision = id.revision;
  out.endpointSetDigest = id.endpoints.digest;
  out.revocationId = id.revocationId;
  out.originDrainEvidence = bound.claim.originDrainEvidence;
  if (bound.retirement) {
    if (!bound.drain.retirements[index] || bound.drain.observations[index])
      return makeError(StatusCode::kDataCorruption, "invalid retirement closure selection");
    out.kind = storage::EcGcClosureKind::TargetRetirement;
    out.retirementRequest = bound.retirement->request;
    out.retirementObservation = bound.retirement->observation;
  } else {
    if (!bound.drain.observations[index] || bound.drain.retirements[index])
      return makeError(StatusCode::kDataCorruption, "original scope exchange is missing");
    out.scopeRequest = bound.drain.observations[index]->request;
    out.scopeAck = bound.drain.observations[index]->ack;
  }
  RETURN_ON_ERROR(Codec::closureDigest(out));
  return out;
}
CoTryTask<std::optional<EcGcAbsentCompletion>> EcGcAbsentCompletionCatalog::get(Transaction &raw,
    const EcObjectRef &object, const storage::EcFragmentIdentity &identity, const Uuid &claimId,
    const storage::EcScopeControlKey &control, const storage::EcGcKey &key, const Uuid &authority) {
  EcGcTxnScope scope(raw);
  auto &tx = scope.transaction();
  auto bound = co_await EcTreeGcCatalog::closureForClaim(tx, object, identity, claimId, control);
  CO_RETURN_ON_ERROR(bound);
  co_return co_await getWithClosure(tx, *bound, key, authority);
}
CoTryTask<EcGcAbsentCompletion> EcGcAbsentCompletionCatalog::record(Transaction &raw,
    const EcObjectRef &object, const storage::EcFragmentIdentity &identity, const Uuid &claimId,
    const storage::EcGcAbsentRequest &request, const storage::EcGcAbsentAck &ack,
    const storage::EcScopeControlKey &control, const storage::EcGcKey &key, const Uuid &authority) {
  EcGcTxnScope scope(raw);
  auto &tx = scope.transaction();
  auto bound = co_await EcTreeGcCatalog::closureForClaim(tx, object, identity, claimId, control);
  CO_RETURN_ON_ERROR(bound);
  CO_RETURN_ON_ERROR(checkExchange(*bound, request, ack, key, authority));
  auto prior = co_await getWithClosure(tx, *bound, key, authority);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    const auto &first = (**prior).ack.claims;
    if (first.state != ack.claims.state || first.claimDigest != ack.claims.claimDigest ||
        first.closureDigest != ack.claims.closureDigest || first.ledgerSha256 != ack.claims.ledgerSha256 ||
        first.recordRevision != ack.claims.recordRevision)
      co_return makeError(StatusCode::kDataCorruption, "permanent absence ledger fact changed");
    co_return **prior;
  }
  EcGcAbsentCompletion out;
  out.object = object;
  out.identity = identity;
  out.claimId = claimId;
  out.claimDigest = ack.claims.claimDigest;
  out.closureDigest = ack.claims.closureDigest;
  out.request = request;
  out.ack = ack;
  auto k = allocationKey(kv::KeyPrefix::EcGcAbsentCompletion, identity);
  CO_RETURN_ON_ERROR(k);
  CO_RETURN_ON_ERROR(co_await store(tx, *k, out));
  co_return out;
}
}  // namespace hf3fs::meta::server
