#include "meta/store/EcFileOutputResolutionCatalog.h"

#include "meta/store/EcFileExecutionCatalog.h"
#include "meta/store/EcFileRepairCatalog.h"
#include "meta/store/EcFileTruncateCatalog.h"
#include "meta/store/EcTerminalEvidence.h"
#include "meta/store/detail/EcFileMutationKeys.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using Tx = EcFileTreeTxnBudget;
using kv::KeyPrefix;
std::string primaryKey(const EcFileOutputIdentity &identity) {
  return idKey(KeyPrefix::EcFileOutputResolution, identity.object, identity.child);
}
std::string requestKey(const Uuid &client, const Uuid &id) {
  std::string key(kv::toStr(KeyPrefix::EcFileOutputResolutionRequest));
  key.append(client.asStringView());
  key.append(id.asStringView());
  return key;
}
CoTryTask<EcFileChildRecord> typedChild(Tx &tx, const EcFileOutputIdentity &i) {
  if (i.ownerKind == EcFileOutputOwner::Repair)
    co_return co_await EcFileRepairCatalog::executionChild(tx, i.owner, i.object, i.child);
  if (i.ownerKind == EcFileOutputOwner::TruncateTail)
    co_return co_await EcFileTruncateCatalog::executionChild(tx, i.owner, i.object, i.child);
  auto child = co_await EcFileMutationCatalog::queryChild(tx, i.object, i.child, i.owner);
  CO_RETURN_ON_ERROR(child);
  if (!*child) co_return makeError(StatusCode::kDataCorruption, "resolution lost its typed child");
  co_return **child;
}
EcTreeSourcePinIntent sourceIntent(const EcFileChildRecord &c) {
  EcTreeSourcePinIntent p;
  p.object = c.intent.object;
  p.owner = c.owner;
  p.session = c.session;
  p.parent = c.intent.parent;
  p.child = c.intent.child;
  p.pin = c.intent.sourcePin;
  p.root = c.sourceRoot;
  p.sequence = c.sourceSequence;
  p.epoch = c.epoch;
  p.lengthAtPlan = c.lengthAtPlan;
  p.slot = c.source;
  return p;
}
Result<EcFileOutputDrain> closure(const EcV2DrainRecord &record) {
  EcFileOutputDrain out;
  out.version = record.version;
  out.identity = record.identity;
  out.state = record.state;
  out.terminalUse = record.terminalUse;
  out.retirements = record.retirements;
  for (size_t n = 0; n < record.identity.endpoints.count; ++n)
    if (record.observations[n]) out.ackMask |= uint32_t{1} << n;
  CHECK_RESULT(digest, ecFileOutputResolutionDigest("hf3fs.ec.file-output.closure.v1", serde::serialize(record)));
  out.recordDigest = digest;
  return out;
}
CoTryTask<EcFileOutputResolution> qualify(Tx &tx, const EcFileOutputIdentity &identity, const Uuid &id,
                                         const Uuid &client, const storage::EcScopeControlKey &control) {
  CO_RETURN_ON_ERROR(identity.valid());
  if (id.is_nil() || client.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto raw = co_await tx.get(idKey(KeyPrefix::EcFileExecution, identity.object, identity.child));
  CO_RETURN_ON_ERROR(raw);
  if (!*raw) co_return makeError(MetaCode::kNotFound, "no original output execution");
  auto execution = co_await EcFileExecutionCatalog::get(tx, identity.owner, identity.object, identity.child);
  CO_RETURN_ON_ERROR(execution);
  const auto &r = execution->record;
  if (r.child.intent.parent != identity.parent ||
      static_cast<uint8_t>(r.ownerKind) != static_cast<uint8_t>(identity.ownerKind))
    co_return makeError(StatusCode::kTokenMismatch, "resolution owner or parent changed");
  auto typed = co_await typedChild(tx, identity);
  CO_RETURN_ON_ERROR(typed);
  if (typed->state != EcFileChildState::Fenced || r.state != EcFileExecutionState::Aborted ||
      r.allocations || r.contentSha256 != storage::EcSha256{} || !r.drain || r.drain->verifiedManifest ||
      r.drain->state != EcV2DrainState::Aborted)
    co_return makeError(StatusCode::kTokenStale, "original unbound output is not fenced and fully closed");
  // get() checked each immutable ECFX identity and active=false. It deliberately
  // does not read ECVA when allocations is absent, so all twelve negative reads
  // below are mandatory conflict reads in this same transaction.
  for (const auto &candidate : r.candidates) {
    auto key = allocationKey(KeyPrefix::EcV2Allocation, candidate.identity);
    CO_RETURN_ON_ERROR(key);
    auto allocation = co_await tx.get(*key);
    CO_RETURN_ON_ERROR(allocation);
    if (*allocation) co_return makeError(StatusCode::kDataCorruption, "unbound candidate has permanent ECVA");
  }
  CO_RETURN_ON_ERROR(co_await verifyEcTerminalEvidence(tx, *r.drain, control, EcTerminalPurpose::FencedAbort));
  EcFileOutputResolution out;
  out.identity = identity;
  out.resolutionId = id;
  out.confirmingClientNamespace = client;
  out.birth = r.child.birth;
  out.childEpoch = r.child.epoch;
  out.issuanceSequence = r.issuanceSequence;
  out.kind = r.issuanceSequence ? EcFileOutputResolutionKind::NeverBoundAfterClose
                                : EcFileOutputResolutionKind::NoIssuanceAfterClose;
  out.candidates = r.candidates;
  auto candidateDigest = ecFileOutputCandidateDigest(r.candidates);
  CO_RETURN_ON_ERROR(candidateDigest);
  out.candidateDigest = *candidateDigest;
  auto executionDigest = ecFileOutputResolutionDigest("hf3fs.ec.file-output.execution.v1", **raw);
  CO_RETURN_ON_ERROR(executionDigest);
  out.executionDigest = *executionDigest;
  auto output = closure(*r.drain);
  CO_RETURN_ON_ERROR(output);
  out.outputClosure = std::move(*output);
  out.outputClosureDigest = out.outputClosure.recordDigest;
  out.sourceKind = r.child.source.kind;
  if (out.sourceKind == EcTreeSlotKind::Data) {
    auto source = co_await EcTreeSourcePinCatalog::query(tx, sourceIntent(r.child));
    CO_RETURN_ON_ERROR(source);
    if (source->state != EcTreeSourcePinState::Released || !source->drain ||
        source->drain->state != EcV2DrainState::ReadReleased)
      co_return makeError(StatusCode::kTokenStale, "original Data source is not released");
    CO_RETURN_ON_ERROR(co_await verifyEcTerminalEvidence(tx, *source->drain, control, EcTerminalPurpose::ReadRelease));
    auto sourceOutput = closure(*source->drain);
    CO_RETURN_ON_ERROR(sourceOutput);
    out.sourcePin = r.child.intent.sourcePin;
    out.sourceClosure = std::move(*sourceOutput);
    out.sourceClosureDigest = out.sourceClosure->recordDigest;
  } else if (out.sourceKind == EcTreeSlotKind::Zero) {
    // Explicit original typed Zero is not a failed lookup of a Data source.
    auto unexpected = co_await tx.get(idKey(KeyPrefix::EcTreeSourcePin, identity.object, r.child.intent.sourcePin));
    CO_RETURN_ON_ERROR(unexpected);
    if (*unexpected) co_return makeError(StatusCode::kDataCorruption, "Zero source has unexpected pin metadata");
    auto zero = ecFileOutputZeroSourceDigest(identity, out.birth, out.childEpoch);
    CO_RETURN_ON_ERROR(zero);
    out.sourceClosureDigest = *zero;
  } else co_return makeError(StatusCode::kDataCorruption, "unknown original source kind");
  out.candidateReservationsReleaseEligible = true;
  CO_RETURN_ON_ERROR(out.valid());
  co_return out;
}
CoTryTask<EcFileOutputResolution> revalidate(Tx &tx, const EcFileOutputResolution &prior,
                                            const EcFileOutputIdentity &identity, const Uuid &id,
                                            const storage::EcScopeControlKey &control) {
  CO_RETURN_ON_ERROR(prior.valid());
  if (!same(prior.identity, identity) || prior.resolutionId != id)
    co_return makeError(StatusCode::kTokenMismatch, "resolution identity is permanently bound");
  auto reverse = co_await require<EcFileOutputResolution>(tx, requestKey(prior.confirmingClientNamespace, id));
  CO_RETURN_ON_ERROR(reverse);
  if (!same(*reverse, prior)) co_return makeError(StatusCode::kDataCorruption, "resolution indexes disagree");
  auto current = co_await qualify(tx, identity, id, prior.confirmingClientNamespace, control);
  CO_RETURN_ON_ERROR(current);
  if (!same(*current, prior)) co_return makeError(StatusCode::kDataCorruption, "resolution original closure changed");
  co_return prior;
}
}  // namespace
CoTryTask<EcFileOutputResolution> EcFileOutputResolutionCatalog::confirm(
    Tx &tx, const EcFileOutputIdentity &identity, const Uuid &id, const Uuid &client,
    const storage::EcScopeControlKey &control) {
  CO_RETURN_ON_ERROR(identity.valid());
  if (id.is_nil() || client.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto prior = co_await load<EcFileOutputResolution>(tx, primaryKey(identity));
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    if ((**prior).confirmingClientNamespace != client)
      co_return makeError(StatusCode::kTokenMismatch, "confirmation namespace is permanently bound");
    co_return co_await revalidate(tx, **prior, identity, id, control);
  }
  auto reverse = co_await load<EcFileOutputResolution>(tx, requestKey(client, id));
  CO_RETURN_ON_ERROR(reverse);
  if (*reverse) {
    if (same((**reverse).identity, identity))
      co_return makeError(StatusCode::kDataCorruption, "resolution primary index missing");
    co_return makeError(StatusCode::kTokenMismatch, "resolution ID belongs to another child");
  }
  auto out = co_await qualify(tx, identity, id, client, control);
  CO_RETURN_ON_ERROR(out);
  CO_RETURN_ON_ERROR(co_await store(tx, primaryKey(identity), *out));
  CO_RETURN_ON_ERROR(co_await store(tx, requestKey(client, id), *out));
  co_return out;
}
CoTryTask<EcFileOutputResolution> EcFileOutputResolutionCatalog::query(
    Tx &tx, const EcFileOutputIdentity &identity, const Uuid &id, const storage::EcScopeControlKey &control) {
  CO_RETURN_ON_ERROR(identity.valid());
  if (id.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto prior = co_await load<EcFileOutputResolution>(tx, primaryKey(identity));
  CO_RETURN_ON_ERROR(prior);
  if (!*prior) co_return makeError(MetaCode::kNotFound, "output resolution has not been confirmed");
  co_return co_await revalidate(tx, **prior, identity, id, control);
}
}  // namespace hf3fs::meta::server
