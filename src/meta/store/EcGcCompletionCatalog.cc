#include "meta/store/EcGcCompletionCatalog.h"

#include "meta/store/EcExactGcCatalog.h"
#include "meta/store/EcTargetRetirementCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using Codec = storage::ec_gc_control_detail::Codec;
using namespace ec_v2_lifecycle;

Result<std::string> completionKey(const storage::EcFragmentIdentity &identity,
                                  kv::KeyPrefix prefix = kv::KeyPrefix::EcGcCompletion) {
  CHECK_RESULT(chunk, identity.chunkId());
  std::string key(kv::toStr(prefix));
  key.append(chunk.data());
  return key;
}

CoTryTask<EcGcClaim> exactClaim(kv::IReadWriteTransaction &txn,
                                const EcObjectRef &object,
                                const storage::EcFragmentIdentity &identity,
                                const Uuid &claimId) {
  if (claimId.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto claim = co_await EcExactGcCatalog::getClaim(txn, object, identity);
  CO_RETURN_ON_ERROR(claim);
  if (!*claim) co_return makeError(StatusCode::kTokenStale, "exact GC claim has not been committed");
  if ((**claim).claimId != claimId) co_return makeError(StatusCode::kTokenMismatch, "GC claim ID differs");
  co_return std::move(**claim);
}

Result<storage::EcSha256> checkExchange(const EcGcClaim &claim,
                                        const storage::EcGcRequest &request,
                                        const storage::EcGcAck &ack,
                                        const storage::EcGcKey &key,
                                        const Uuid &authority) {
  if (authority.is_nil() || request.claims.authority != authority || request.claims.keyId != key.keyId())
    return makeError(StatusCode::kTokenMismatch, "GC confirmation authority or key differs");
  CHECK_RESULT(certificate, EcGcCompletionCatalog::project(claim));
  if (Codec::encode(certificate) != Codec::encode(request.claims.certificate))
    return makeError(StatusCode::kTokenMismatch, "GC confirmation certificate differs from permanent claim");
  RETURN_ON_ERROR(Codec::verifyAck(key, ack, request));
  CHECK_RESULT(digest, Codec::claimDigest(certificate));
  if (ack.claims.claimDigest != digest)
    return makeError(StatusCode::kTokenMismatch, "GC confirmation claim digest differs");
  return digest;
}

Result<Void> checkRecord(const EcGcCompletion &value,
                         const EcGcClaim &claim,
                         const storage::EcGcKey &key,
                         const Uuid &authority) {
  if (value.version != 1 || value.object != claim.enrollment.object ||
      !serde::equals(value.identity, claim.allocation.fragment.identity) || value.claimId != claim.claimId)
    return makeError(StatusCode::kDataCorruption, "GC completion identity differs");
  CHECK_RESULT(digest, checkExchange(claim, value.request, value.ack, key, authority));
  if (value.claimDigest != digest) return makeError(StatusCode::kDataCorruption, "GC completion digest differs");
  return Void{};
}
CoTryTask<std::optional<EcGcCompletion>> getWithClaim(kv::IReadWriteTransaction &txn,
                                                      const EcGcClaim &claim,
                                                      const storage::EcGcKey &key,
                                                      const Uuid &authority) {
  if (claim.version == 2) {
    CO_RETURN_ON_ERROR(co_await EcGcCompletionCatalog::requireNoRetainedDisposition(txn, claim.allocation.fragment.identity));
    auto chunk = claim.allocation.fragment.identity.chunkId();
    CO_RETURN_ON_ERROR(chunk);
    std::string absentKey(kv::toStr(kv::KeyPrefix::EcGcAbsentCompletion));
    absentKey.append(chunk->data());
    auto absent = co_await txn.get(absentKey);
    CO_RETURN_ON_ERROR(absent);
    if (*absent) co_return makeError(StatusCode::kTokenStale, "AbsentAfterClose cannot become Collected");
  }
  auto ledgerKey = completionKey(claim.allocation.fragment.identity);
  CO_RETURN_ON_ERROR(ledgerKey);
  auto value = co_await load<EcGcCompletion>(txn, *ledgerKey);
  CO_RETURN_ON_ERROR(value);
  if (*value) CO_RETURN_ON_ERROR(checkRecord(**value, claim, key, authority));
  co_return value;
}
}  // namespace

CoTryTask<Void> EcGcCompletionCatalog::requireNoRetainedDisposition(Transaction &txn,
                                                                   const storage::EcFragmentIdentity &identity) {
  auto key = completionKey(identity, kv::KeyPrefix::EcGcRetainedDisposition);
  CO_RETURN_ON_ERROR(key);
  auto disposition = co_await txn.get(*key);
  CO_RETURN_ON_ERROR(disposition);
  if (*disposition) co_return makeError(StatusCode::kTokenStale, "allocation already classified as RetiredInaccessible");
  co_return Void{};
}

CoTryTask<std::optional<EcGcRetainedDisposition>> EcGcCompletionCatalog::retained(
    Transaction &raw, const EcObjectRef &object, const storage::EcFragmentIdentity &identity,
    const Uuid &claimId, const Uuid &controlAuthority, bool confirm) {
  if (controlAuthority.is_nil()) co_return makeError(StatusCode::kInvalidArg, "missing control authority");
  EcGcTxnScope scope(raw);
  auto &txn = scope.transaction();
  auto claim = co_await exactClaim(txn, object, identity, claimId);
  CO_RETURN_ON_ERROR(claim);
  if (claim->version != 2) co_return makeError(StatusCode::kNotImplemented, "retained disposition requires mode4");

  auto key = completionKey(identity, kv::KeyPrefix::EcGcRetainedDisposition);
  CO_RETURN_ON_ERROR(key);
  auto old = co_await load<EcGcRetainedDisposition>(txn, *key);
  CO_RETURN_ON_ERROR(old);
  if (!*old && !confirm) co_return std::nullopt;
  // Conflict reads in both directions serialize competing terminal writes,
  // including a late G2 ACK for a Collect issued before the fence.
  for (auto prefix : {kv::KeyPrefix::EcGcCompletion, kv::KeyPrefix::EcGcAbsentCompletion}) {
    auto otherKey = completionKey(identity, prefix);
    CO_RETURN_ON_ERROR(otherKey);
    auto other = co_await txn.get(*otherKey);
    CO_RETURN_ON_ERROR(other);
    if (*other) co_return makeError(*old ? StatusCode::kDataCorruption : StatusCode::kTokenStale,
                                    "allocation already has a Storage terminal proof");
  }
  auto endpoint = claim->allocation.endpoint();
  auto fence = co_await EcTargetRetirementCatalog::findHostFence(txn, endpoint, controlAuthority);
  CO_RETURN_ON_ERROR(fence);
  if (!*fence) {
    if (*old) co_return makeError(StatusCode::kDataCorruption, "retained disposition lost its verified host fence");
    co_return std::nullopt;
  }
  auto certificate = project(*claim);
  CO_RETURN_ON_ERROR(certificate);
  auto digest = Codec::claimDigest(*certificate);
  CO_RETURN_ON_ERROR(digest);
  EcGcRetainedDisposition value;
  value.object = object;
  value.identity = identity;
  value.claimId = claimId;
  value.claimDigest = *digest;
  value.endpoint = endpoint;
  value.retirementId = (**fence).retirementId;
  value.fenceCompletionDigest = (**fence).completionDigest;
  value.fenceProofDigest = (**fence).proofDigest;
  CO_RETURN_ON_ERROR(value.valid());
  if (*old) {
    if (!serde::equals(**old, value)) co_return makeError(StatusCode::kDataCorruption, "retained disposition changed");
  } else {
    CO_RETURN_ON_ERROR(co_await save(txn, *key, value));
  }
  co_return value;
}

Result<storage::EcGcCertificate> EcGcCompletionCatalog::project(const EcGcClaim &claim) {
  const bool flat = claim.version == 1 && claim.enrollment.version == 1;
  const bool tree = claim.version == 2 && claim.enrollment.version == 2;
  if ((!flat && !tree) || claim.allocation.version != kEcBindingCatalogVersion ||
      claim.enrollment.object != claim.allocation.object ||
      claim.allocation.fragment.identity.object != claim.enrollment.object.incarnation)
    return makeError(StatusCode::kDataCorruption, "GC claim projection identity or version differs");
  storage::EcGcCertificate out;
  if (tree) {
    out.version = 2;
    out.metaMode = 4;
    out.gcProtocol = 2;
  }
  out.catalogVersion = claim.version;
  out.enrollmentVersion = claim.enrollment.version;
  out.bindingVersion = claim.allocation.version;
  out.claimId = claim.claimId;
  out.objectInode = claim.enrollment.object.inode.u64();
  out.objectIncarnation = claim.enrollment.object.incarnation;
  out.creatorUid = claim.enrollment.creator.uid;
  out.creatorClient = claim.enrollment.creator.client;
  out.createRequest = claim.enrollment.createRequest;
  out.fragment = claim.allocation.fragment.identity;
  out.fragmentOperation = claim.allocation.fragment.operation;
  out.endpoint = claim.allocation.endpoint().controlEndpoint();
  out.writerUid = claim.allocation.writer.uid;
  out.writerClient = claim.allocation.writer.client;
  out.integrity = claim.allocation.fragment.integrity;
  out.registeredScopes = claim.registeredScopes;
  out.releasedScopes = claim.releasedScopes;
  out.releaseHistory = claim.releaseHistory;
  out.originDrainEvidence = claim.originDrainEvidence;
  out.eligibilityDigest = claim.eligibilityDigest;
  // claimDigest performs the canonical format's structural validation.
  RETURN_ON_ERROR(Codec::claimDigest(out));
  return out;
}

CoTryTask<std::optional<EcGcCompletion>> EcGcCompletionCatalog::get(Transaction &raw,
                                                                    const EcObjectRef &object,
                                                                    const storage::EcFragmentIdentity &identity,
                                                                    const Uuid &claimId,
                                                                    const storage::EcGcKey &key,
                                                                    const Uuid &authority) {
  EcGcTxnScope scope(raw);
  auto tree = co_await EcTreeGcCatalog::isTree(scope.transaction(), object);
  CO_RETURN_ON_ERROR(tree);
  // Flat catalogs retain their original transaction behavior. Only mode4
  // carries this common budget through dispatch, eligibility and ECGD.
  Transaction &txn = *tree ? scope.transaction() : raw;
  auto claim = co_await exactClaim(txn, object, identity, claimId);
  CO_RETURN_ON_ERROR(claim);
  co_return co_await getWithClaim(txn, *claim, key, authority);
}

CoTryTask<EcGcCompletion> EcGcCompletionCatalog::record(Transaction &raw,
                                                        const EcObjectRef &object,
                                                        const storage::EcFragmentIdentity &identity,
                                                        const Uuid &claimId,
                                                        const storage::EcGcRequest &request,
                                                        const storage::EcGcAck &ack,
                                                        const storage::EcGcKey &key,
                                                        const Uuid &authority) {
  EcGcTxnScope scope(raw);
  auto tree = co_await EcTreeGcCatalog::isTree(scope.transaction(), object);
  CO_RETURN_ON_ERROR(tree);
  // Flat catalogs retain their original transaction behavior. Only mode4
  // carries this common budget through dispatch, eligibility and ECGD.
  Transaction &txn = *tree ? scope.transaction() : raw;
  auto claim = co_await exactClaim(txn, object, identity, claimId);
  CO_RETURN_ON_ERROR(claim);
  auto digest = checkExchange(*claim, request, ack, key, authority);
  CO_RETURN_ON_ERROR(digest);
  auto prior = co_await getWithClaim(txn, *claim, key, authority);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    const auto &first = (**prior).ack.claims;
    if (first.ledgerSha256 != ack.claims.ledgerSha256 || first.terminalRevision != ack.claims.terminalRevision)
      co_return makeError(StatusCode::kDataCorruption, "GC stable ledger fact changed after completion");
    // Exchange nonce/time/bootNonce may legitimately change. The exact new
    // exchange was verified above; keep the first permanent proof unchanged.
    co_return std::move(**prior);
  }
  EcGcCompletion value;
  value.object = object;
  value.identity = identity;
  value.claimId = claimId;
  value.claimDigest = *digest;
  value.request = request;
  value.ack = ack;
  auto ledgerKey = completionKey(identity);
  CO_RETURN_ON_ERROR(ledgerKey);
  CO_RETURN_ON_ERROR(co_await save(txn, *ledgerKey, value));
  co_return value;
}
}  // namespace hf3fs::meta::server
