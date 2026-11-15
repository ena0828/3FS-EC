#include "meta/store/EcTargetRetirementCatalog.h"

#include <algorithm>
#include <openssl/evp.h>

#include "common/kv/KeyPrefix.h"
#include "common/utils/SerDeser.h"

namespace hf3fs::meta::server {
namespace {
using Tx = kv::IReadWriteTransaction;

Result<Void> endpointValid(const EcV2PhysicalEndpoint &ep) {
  if (ep.placement.node == flat::NodeId{} || ep.placement.chain == storage::ChainId{} ||
      ep.placement.target == storage::TargetId{} || ep.engineUuid.is_nil() || ep.targetIncarnation.is_nil())
    return makeError(StatusCode::kInvalidArg, "retirement requires an exact physical target");
  return Void{};
}
std::string targetKey(const EcV2PhysicalEndpoint &ep) {
  return Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirement,
                                ep.placement.node.toUnderType(),
                                ep.placement.chain.toUnderType(),
                                ep.placement.target.toUnderType(),
                                ep.engineUuid,
                                ep.targetIncarnation);
}
std::string requestKey(const EcTargetRetirementIntent &intent) {
  return Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirementRequest, intent.owner.client, intent.requestId);
}
bool sameIntent(const EcTargetRetirementIntent &a, const EcTargetRetirementIntent &b) {
  return serde::serialize(a) == serde::serialize(b);
}
template <class T>
CoTryTask<std::optional<T>> load(Tx &txn, std::string key) {
  auto bytes = co_await txn.get(key);
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  T value;
  if ((**bytes).size() > EcTargetRetirementCatalog::kMaximumRecordBytes ||
      !serde::deserialize(value, **bytes) || serde::serialize(value) != **bytes)
    co_return makeError(StatusCode::kDataCorruption, "invalid canonical target retirement record");
  co_return value;
}
template <class T>
CoTryTask<Void> save(Tx &txn, std::string key, const T &value) {
  const auto bytes = serde::serialize(value);
  if (bytes.size() > EcTargetRetirementCatalog::kMaximumRecordBytes)
    co_return makeError(StatusCode::kInvalidArg, "target retirement record exceeds fixed bound");
  CO_RETURN_ON_ERROR(co_await txn.set(key, bytes));
  co_return Void{};
}
CoTryTask<std::optional<EcTargetRetirementRecord>> loadTarget(Tx &txn, const EcV2PhysicalEndpoint &ep) {
  CO_RETURN_ON_ERROR(endpointValid(ep));
  auto raw = co_await txn.get(targetKey(ep));
  CO_RETURN_ON_ERROR(raw);
  if (!*raw) co_return std::nullopt;
  if ((**raw).size() > EcTargetRetirementCatalog::kMaximumRecordBytes)
    co_return makeError(StatusCode::kDataCorruption);
  EcTargetRetirementRecord record;
  if (serde::deserialize(record, **raw) && serde::serialize(record) == **raw && record.version == 1) {
    if (record.intent.version != 1) co_return makeError(StatusCode::kDataCorruption);
  } else {
    EcHostFenceRecord external;
    if (!serde::deserialize(external, **raw) || serde::serialize(external) != **raw ||
        external.version != 2 || external.intent.version != 2 || !external.binding.valid() ||
        std::all_of(external.publicKey.begin(), external.publicKey.end(), [](auto x) { return x == 0; }) ||
        (external.certificate.empty() != (external.digest == storage::EcSha256{})))
      co_return makeError(StatusCode::kDataCorruption, "invalid canonical external retirement record");
    record = {};
    record.version = 2;
    record.intent = external.intent;
    record.hostFence = std::move(external);
  }
  if (record.intent.endpoint != ep || !EcTargetRetirementCatalog::validIntent(record.intent))
    co_return makeError(StatusCode::kDataCorruption, "target retirement identity or version differs");
  co_return std::optional<EcTargetRetirementRecord>(std::move(record));
}
Result<storage::EcSha256> hostDigest(const EcHostFenceRecord &r) {
  RETURN_ON_ERROR(EcHostFence::verify(r.certificate, r.intent, r.binding, r.publicKey));
  std::string bytes("3FSEHC01");
  bytes += serde::serialize(r.intent);
  bytes += serde::serialize(r.binding);
  bytes += serde::serialize(r.publicKey);
  bytes += r.certificate;
  storage::EcSha256 out{};
  unsigned int size = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), out.data(), &size, EVP_sha256(), nullptr) != 1 || size != out.size())
    return makeError(StatusCode::kIOError);
  return out;
}
Result<Void> verifyHost(const EcTargetRetirementRecord &r) {
  if (r.version != 2 || !r.hostFence || r.completion || r.hostFence->certificate.empty())
    return makeError(StatusCode::kTokenStale, "external target retirement is not complete");
  CHECK_RESULT(digest, hostDigest(*r.hostFence));
  if (digest != r.hostFence->digest) return makeError(StatusCode::kDataCorruption);
  return Void{};
}
Result<storage::EcSha256> checkCompletion(const EcTargetRetirementIntent &intent,
                                         const storage::EcTargetRetirementRequest &request,
                                         const storage::EcTargetRetirementObservation &observation,
                                         const storage::EcScopeControlKey *key) {
  const auto &q = request.claims;
  const auto &ep = intent.endpoint;
  if (q.clusterAuthority != intent.authority || q.nodeId != ep.placement.node ||
      q.chainId != ep.placement.chain || q.targetId != ep.placement.target ||
      q.engineUuid != ep.engineUuid || q.targetIncarnation != ep.targetIncarnation ||
      q.retirementId != intent.retirementId)
    return makeError(StatusCode::kTokenMismatch, "retirement observation differs from fixed Meta intent");
  if (key) RETURN_ON_ERROR(storage::verifyEcTargetRetirementObservation(*key, observation, request));
  // Deserialization already checked both fixed canonical claim shapes. These
  // checks also cover the direct in-memory new-completion path.
  const auto requestBytes = storage::ec_target_retirement_detail::Codec::encode(q);
  const auto observationBytes = storage::ec_target_retirement_detail::Codec::encode(observation.claims);
  RETURN_ON_ERROR(storage::ec_target_retirement_detail::Codec::decodeRequest(
      {reinterpret_cast<const char *>(requestBytes.data()), requestBytes.size()}));
  RETURN_ON_ERROR(storage::ec_target_retirement_detail::Codec::decodeObservation(
      {reinterpret_cast<const char *>(observationBytes.data()), observationBytes.size()}));
  if (observation.claims.observedAtSeconds < q.issuedAtSeconds ||
      observation.claims.observedAtSeconds >= q.expiresAtSeconds)
    return makeError(StatusCode::kDataCorruption, "retirement observation is outside its signed request window");
  if (!observation.claims.durable || observation.claims.inflight != 0 ||
      observation.claims.state != storage::EcTargetRetirementState::LocalDataDrained)
    return makeError(StatusCode::kInvalidArg, "retirement completion requires durable local data drain");
  // Commit the complete first exchange, including both signatures and its
  // original request nonce/time. Never recompute this from a later observation.
  auto bytes = serde::serialize(intent);
  bytes.append(serde::serialize(request));
  bytes.append(serde::serialize(observation));
  bytes.insert(0, "3FSETRC1");
  storage::EcSha256 digest{};
  unsigned int size = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1 ||
      size != digest.size())
    return makeError(StatusCode::kIOError, "target retirement completion SHA256 failed");
  return digest;
}
Result<Void> verifyCompleted(const EcTargetRetirementRecord &record, const storage::EcScopeControlKey &key) {
  if (record.version == 2) return verifyHost(record);
  if (!record.completion) return makeError(StatusCode::kTokenStale, "target retirement is not complete");
  CHECK_RESULT(digest, checkCompletion(record.intent,
                                      record.completion->request,
                                      record.completion->observation,
                                      &key));
  if (digest != record.completion->digest)
    return makeError(StatusCode::kDataCorruption, "immutable target retirement completion digest differs");
  return Void{};
}
}  // namespace

Result<Void> EcTargetRetirementCatalog::validIntent(const EcTargetRetirementIntent &intent) {
  RETURN_ON_ERROR(endpointValid(intent.endpoint));
  if ((intent.version != 1 && intent.version != 2) || intent.authority.is_nil() ||
      intent.retirementId.is_nil() || intent.owner.client.is_nil() || intent.requestId.is_nil() ||
      intent.owner.uid != flat::Uid(0))
    return makeError(StatusCode::kInvalidArg, "invalid root-owned target retirement intent");
  return Void{};
}
CoTryTask<EcTargetRetirementRecord> EcTargetRetirementCatalog::prepare(Tx &txn,
                                                                     const EcTargetRetirementIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  if (intent.version != 1) co_return makeError(StatusCode::kInvalidArg);
  auto index = co_await load<EcTargetRetirementIntent>(txn, requestKey(intent));
  CO_RETURN_ON_ERROR(index);
  if (*index && !sameIntent(**index, intent))
    co_return makeError(StatusCode::kTokenMismatch, "retirement request UUID is permanently bound");
  auto old = co_await loadTarget(txn, intent.endpoint);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    if (!sameIntent((**old).intent, intent))
      co_return makeError(StatusCode::kTokenMismatch, "target retirement already has a different fixed intent");
    if (!*index) co_return makeError(StatusCode::kDataCorruption, "retirement request index is missing");
    co_return std::move(**old);
  }
  if (*index) co_return makeError(StatusCode::kDataCorruption, "retirement target record is missing");
  EcTargetRetirementRecord record;
  record.intent = intent;
  CO_RETURN_ON_ERROR(co_await save(txn, targetKey(intent.endpoint), record));
  CO_RETURN_ON_ERROR(co_await save(txn, requestKey(intent), intent));
  co_return record;
}
CoTryTask<EcTargetRetirementRecord> EcTargetRetirementCatalog::prepareHostFence(
    Tx &txn, const EcTargetRetirementIntent &intent, const EcHostFenceBinding &binding,
    const EcHostFencePublicKey &publicKey) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  if (intent.version != 2 || !binding.valid() ||
      std::all_of(publicKey.begin(), publicKey.end(), [](auto x) { return x == 0; }))
    co_return makeError(StatusCode::kInvalidArg);
  auto index = co_await load<EcTargetRetirementIntent>(txn, requestKey(intent));
  CO_RETURN_ON_ERROR(index);
  if (*index && !sameIntent(**index, intent)) co_return makeError(StatusCode::kTokenMismatch);
  auto old = co_await loadTarget(txn, intent.endpoint);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    const auto &r = **old;
    if (!sameIntent(r.intent, intent) || !r.hostFence ||
        serde::serialize(r.hostFence->binding) != serde::serialize(binding) || r.hostFence->publicKey != publicKey)
      co_return makeError(StatusCode::kTokenMismatch, "external target is bound to another fixed intent/provider");
    if (!*index) co_return makeError(StatusCode::kDataCorruption);
    co_return r;
  }
  if (*index) co_return makeError(StatusCode::kDataCorruption);
  EcHostFenceRecord external;
  external.intent = intent; external.binding = binding; external.publicKey = publicKey;
  CO_RETURN_ON_ERROR(co_await save(txn, targetKey(intent.endpoint), external));
  CO_RETURN_ON_ERROR(co_await save(txn, requestKey(intent), intent));
  EcTargetRetirementRecord result;
  result.version = 2; result.intent = intent; result.hostFence = std::move(external);
  co_return result;
}
CoTryTask<EcTargetRetirementRecord> EcTargetRetirementCatalog::recordHostFence(
    Tx &txn, const EcTargetRetirementIntent &intent, const EcHostFenceBinding &binding,
    std::string_view certificate) {
  auto record = co_await get(txn, intent);
  CO_RETURN_ON_ERROR(record);
  if (!record->hostFence || serde::serialize(record->hostFence->binding) != serde::serialize(binding))
    co_return makeError(StatusCode::kTokenMismatch);
  auto &r = *record->hostFence;
  CO_RETURN_ON_ERROR(EcHostFence::verify(certificate, intent, binding, r.publicKey));
  if (!r.certificate.empty()) {
    CO_RETURN_ON_ERROR(verifyHost(*record));
    if (r.certificate != certificate) co_return makeError(StatusCode::kTokenMismatch, "first fence evidence is immutable");
    co_return std::move(*record);
  }
  r.certificate = std::string(certificate);
  auto digest = hostDigest(r);
  CO_RETURN_ON_ERROR(digest);
  r.digest = *digest;
  CO_RETURN_ON_ERROR(co_await save(txn, targetKey(intent.endpoint), r));
  co_return std::move(*record);
}
Result<EcHostFenceSummary> EcTargetRetirementCatalog::hostFenceSummary(const EcTargetRetirementRecord &record) {
  RETURN_ON_ERROR(verifyHost(record));
  const auto &r = *record.hostFence;
  return EcHostFence::verify(r.certificate, r.intent, r.binding, r.publicKey);
}
CoTryTask<EcTargetRetirementRecord> EcTargetRetirementCatalog::get(Tx &txn,
                                                                 const EcTargetRetirementIntent &intent) {
  CO_RETURN_ON_ERROR(validIntent(intent));
  auto index = co_await load<EcTargetRetirementIntent>(txn, requestKey(intent));
  CO_RETURN_ON_ERROR(index);
  if (*index && !sameIntent(**index, intent))
    co_return makeError(StatusCode::kTokenMismatch, "retirement request UUID differs");
  auto record = co_await loadTarget(txn, intent.endpoint);
  CO_RETURN_ON_ERROR(record);
  if (!*record && !*index) co_return makeError(StatusCode::kTokenStale, "no accepted target retirement intent");
  if (*record && !sameIntent((**record).intent, intent))
    co_return makeError(StatusCode::kTokenMismatch, "target retirement intent differs");
  if (!*record || !*index) co_return makeError(StatusCode::kDataCorruption, "incomplete retirement intent/index");
  co_return std::move(**record);
}
CoTryTask<EcTargetRetirementRecord> EcTargetRetirementCatalog::recordCompletion(
    Tx &txn,
    const EcTargetRetirementIntent &intent,
    const storage::EcTargetRetirementRequest &request,
    const storage::EcTargetRetirementObservation &observation,
    const storage::EcScopeControlKey &key) {
  auto record = co_await get(txn, intent);
  CO_RETURN_ON_ERROR(record);
  if (record->version != 1 || record->hostFence) co_return makeError(StatusCode::kTokenMismatch);
  auto digest = checkCompletion(intent, request, observation, &key);
  CO_RETURN_ON_ERROR(digest);
  if (record->completion) {
    CO_RETURN_ON_ERROR(verifyCompleted(*record, key));
    co_return std::move(*record);
  }
  record->completion = EcTargetRetirementCompletion{request, observation, *digest};
  CO_RETURN_ON_ERROR(co_await save(txn, targetKey(intent.endpoint), *record));
  co_return std::move(*record);
}
CoTryTask<Void> EcTargetRetirementCatalog::requireAssignable(Tx &txn, const EcV2PhysicalEndpoint &endpoint) {
  auto record = co_await loadTarget(txn, endpoint);
  CO_RETURN_ON_ERROR(record);
  if (*record) co_return makeError(StatusCode::kTokenStale, "target retirement permanently prohibits new assignment");
  co_return Void{};
}
CoTryTask<std::optional<EcTargetRetirementRef>> EcTargetRetirementCatalog::findCompleted(
    Tx &txn,
    const EcV2PhysicalEndpoint &endpoint,
    const Uuid &authority,
    const storage::EcScopeControlKey &key) {
  if (authority.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto record = co_await loadTarget(txn, endpoint);
  CO_RETURN_ON_ERROR(record);
  if (!*record) co_return std::nullopt;
  if ((**record).intent.authority != authority)
    co_return makeError(StatusCode::kTokenMismatch, "target retirement authority differs");
  if (!(**record).completion && (!(**record).hostFence || (**record).hostFence->certificate.empty())) co_return std::nullopt;
  CO_RETURN_ON_ERROR(verifyCompleted(**record, key));
  co_return std::optional<EcTargetRetirementRef>{{(**record).intent.retirementId,
      (**record).hostFence ? (**record).hostFence->digest : (**record).completion->digest}};
}
CoTryTask<Void> EcTargetRetirementCatalog::verifyStoredReference(Tx &txn,
                                                               const EcV2PhysicalEndpoint &endpoint,
                                                               const Uuid &authority,
                                                               const EcTargetRetirementRef &reference) {
  if (authority.is_nil() || reference.retirementId.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto record = co_await loadTarget(txn, endpoint);
  CO_RETURN_ON_ERROR(record);
  if (!*record || (!(**record).completion && !(**record).hostFence))
    co_return makeError(StatusCode::kDataCorruption, "referenced target retirement completion is missing");
  const auto &value = **record;
  if (value.intent.authority != authority || value.intent.retirementId != reference.retirementId)
    co_return makeError(StatusCode::kTokenMismatch, "historical retirement identity differs");
  if (value.hostFence) {
    CO_RETURN_ON_ERROR(verifyHost(value));
    if (value.hostFence->digest != reference.completionDigest) co_return makeError(StatusCode::kTokenMismatch);
    co_return Void{};
  }
  auto digest = checkCompletion(value.intent, value.completion->request, value.completion->observation, nullptr);
  CO_RETURN_ON_ERROR(digest);
  if (*digest != value.completion->digest || *digest != reference.completionDigest)
    co_return makeError(StatusCode::kDataCorruption, "historical retirement exchange commitment differs");
  co_return Void{};
}
CoTryTask<Void> EcTargetRetirementCatalog::verifyReference(Tx &txn,
                                                         const EcV2PhysicalEndpoint &endpoint,
                                                         const Uuid &authority,
                                                         const EcTargetRetirementRef &reference,
                                                         const storage::EcScopeControlKey &key) {
  auto observed = co_await findCompleted(txn, endpoint, authority, key);
  CO_RETURN_ON_ERROR(observed);
  if (!*observed) co_return makeError(StatusCode::kDataCorruption, "referenced target retirement completion is missing");
  if (**observed != reference)
    co_return makeError(StatusCode::kTokenMismatch, "immutable retirement reference differs");
  co_return Void{};
}
CoTryTask<EcTargetRetirementCompletion> EcTargetRetirementCatalog::getVerifiedCompletion(
    Tx &txn, const EcV2PhysicalEndpoint &endpoint, const Uuid &authority,
    const EcTargetRetirementRef &reference, const storage::EcScopeControlKey &key) {
  auto record = co_await loadTarget(txn, endpoint);
  CO_RETURN_ON_ERROR(record);
  // A host fence is not a local disk retirement witness. Inaccessible old
  // allocations cannot use this API to manufacture Collected/Absent receipts.
  if (*record && (**record).hostFence) co_return makeError(StatusCode::kNotImplemented,
      "host-fenced inaccessible capacity is not a Storage absence witness");
  if (!*record || !(**record).completion)
    co_return makeError(StatusCode::kDataCorruption, "referenced target retirement completion is missing");
  const auto &r = **record;
  if (r.intent.authority != authority || r.intent.retirementId != reference.retirementId)
    co_return makeError(StatusCode::kTokenMismatch, "exact retirement witness identity differs");
  auto digest = checkCompletion(r.intent, r.completion->request, r.completion->observation, &key);
  CO_RETURN_ON_ERROR(digest);
  if (*digest != reference.completionDigest || *digest != r.completion->digest)
    co_return makeError(StatusCode::kDataCorruption, "exact retirement witness digest differs");
  co_return *r.completion;
}
}  // namespace hf3fs::meta::server
