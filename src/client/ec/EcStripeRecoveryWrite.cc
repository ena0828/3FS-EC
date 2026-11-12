#include "EcStripeRecoveryWrite.h"

#include <algorithm>
#include <array>

#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> active(const EcStripeControl &control) {
  if (control.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
Result<Void> publishedDrain(const meta::EcV2MutationRsp &rsp) {
  if (!rsp.drain || rsp.drain->state != meta::EcV2DrainState::Published || rsp.drain->revocation.is_nil() ||
      rsp.drain->expectedEndpoints < 12 || rsp.drain->expectedEndpoints > 24 ||
      rsp.drain->acknowledgedEndpoints != rsp.drain->expectedEndpoints || !rsp.reservation ||
      rsp.drain->expectedEndpoints != rsp.reservation->operationEndpoints.count)
    return makeError(StatusCode::kDataCorruption, "recovery requires complete historical publication, not Closing");
  return Void{};
}
EcStripeRunObservation expectedSource(const EcStripeRunRecord &run) {
  EcStripeRunObservation result;
  result.object = run.object;
  result.ownerUid = *run.expectedOwnerUid;
  result.revision = run.expectedRevision;
  result.mutationPublished = true;
  return result;
}
}  // namespace

Result<EcStripeRunRecord> prepareEcRecoveryWrite(EcStripeRunRecord fresh,
                                                 const EcStripeRunRecord &source,
                                                 const EcStripeRunObservation &published,
                                                 std::string sourceRun,
                                                 storage::EcSha256 recordDigest,
                                                 storage::EcSha256 observationDigest,
                                                 std::string inputPath,
                                                 std::string_view input) {
  RETURN_ON_ERROR(source.validate());
  if ((source.action != "write" && source.action != "repair" && source.action != "recovery-write") ||
      !published.mutationPublished || !published.object || !published.revision || published.errorCode ||
      (published.state != "Published" && !(source.action == "repair" && published.state == "ReadReleased")) ||
      source.cluster != fresh.cluster || published.object->shardBytes != source.shardBytes ||
      (source.expectedOwnerUid && *source.expectedOwnerUid != published.ownerUid) ||
      (source.object && source.object->object != published.object->object) || !input.size() ||
      input.size() != source.inputBytes)
    return makeError(StatusCode::kInvalidArg,
                     "recovery needs a confirmed same-cluster publication and exact full input");
  std::array<std::string_view, 10> parts{};
  parts[0] = input;
  CHECK_RESULT(digest, meta::computeEcLogicalSha256(parts, input.size()));
  if (digest != source.inputSha256)
    return makeError(StatusCode::kTokenMismatch, "recovery input differs from source logical SHA");
  const std::array freshIds{fresh.createRequest,
                            fresh.operation,
                            fresh.beginRequest,
                            fresh.bindRequest,
                            fresh.publishRequest,
                            fresh.getRequest,
                            fresh.prepareRepairRequest,
                            fresh.pin,
                            fresh.acquireRequest,
                            fresh.releaseRequest,
                            fresh.planId};
  const std::array sourceIds{source.createRequest,
                             source.operation,
                             source.beginRequest,
                             source.bindRequest,
                             source.publishRequest,
                             source.getRequest,
                             source.prepareRepairRequest,
                             source.pin,
                             source.acquireRequest,
                             source.releaseRequest,
                             source.planId};
  for (size_t i = 0; i != freshIds.size(); ++i) {
    if (freshIds[i].is_nil() || std::find(sourceIds.begin(), sourceIds.end(), freshIds[i]) != sourceIds.end() ||
        std::find(freshIds.begin(), freshIds.begin() + i, freshIds[i]) != freshIds.begin() + i)
      return makeError(StatusCode::kTokenMismatch,
                       "recovery requires independent nonzero request and operation identities");
  }
  fresh.version = 2;
  fresh.action = "recovery-write";
  fresh.clientNamespace = source.clientNamespace;
  fresh.expectedOwnerUid = published.ownerUid;
  fresh.object = published.object;
  fresh.expectedRevision = published.revision;
  fresh.inputPath = std::move(inputPath);
  fresh.inputBytes = input.size();
  fresh.inputSha256 = digest;
  fresh.remotePath.clear();
  fresh.shardBytes = source.shardBytes;
  EcStripeRecoverySource provenance;
  provenance.runPath = std::move(sourceRun);
  provenance.action = source.action;
  provenance.operation = source.operation;
  provenance.getRequest = source.getRequest;
  provenance.expectedEpoch = published.object->epoch;
  provenance.expectedRevision = source.expectedRevision;
  provenance.replacementMask = source.action == "repair" ? source.replacementMask : meta::kEcAllShards;
  provenance.recordSha256 = recordDigest;
  provenance.observationSha256 = observationDigest;
  fresh.recoverySource = std::move(provenance);
  RETURN_ON_ERROR(fresh.validate());
  return fresh;
}

CoTryTask<meta::EcV2MutationRsp> verifyEcRecoveryWriteSource(std::shared_ptr<meta::client::MetaClient> metadata,
                                                             const EcStripeRunRecord &run,
                                                             flat::UserInfo credentials,
                                                             EcStripeControl control) {
  CO_RETURN_ON_ERROR(run.validate());
  if (run.action != "recovery-write" || !metadata || metadata->clientId().uuid != run.clientNamespace)
    co_return makeError(StatusCode::kTokenMismatch, "recovery source requires its fixed actual client namespace");
  CO_RETURN_ON_ERROR(active(control));
  auto authenticated = co_await metadata->authenticate(credentials);
  CO_RETURN_ON_ERROR(authenticated);
  if (authenticated->uid.toUnderType() != *run.expectedOwnerUid)
    co_return makeError(StatusCode::kAuthenticationFail, "recovery owner differs from authenticated effective UID");
  auto token = std::move(credentials.token);
  credentials = std::move(*authenticated);
  credentials.token = std::move(token);
  const auto &source = *run.recoverySource;
  meta::GetEcOperationV2Req req;
  req.uuid = source.getRequest;
  req.user = std::move(credentials);
  req.object = run.object->object;
  req.operation = source.operation;
  CO_RETURN_ON_ERROR(active(control));
  auto result = co_await metadata->getEcOperationV2(std::move(req));
  CO_RETURN_ON_ERROR(result);
  CO_RETURN_ON_ERROR(active(control));
  // This projection carries the original intent fields, never new authority.
  auto original = run;
  original.action = source.action;
  original.operation = source.operation;
  original.getRequest = source.getRequest;
  original.expectedRevision = source.expectedRevision;
  original.replacementMask = source.replacementMask;
  CO_RETURN_ON_ERROR(validatePublishedEcStripeRun(original, expectedSource(run), *result));
  CO_RETURN_ON_ERROR(publishedDrain(*result));
  if (result->record.intent.expectedEpoch != source.expectedEpoch || result->object.epoch != run.object->epoch)
    co_return makeError(StatusCode::kTokenMismatch, "source epoch changed; do not rebase the fixed recovery CAS");
  co_return std::move(*result);
}

Result<Void> validateEcRecoveryWritePublication(const EcStripeRunRecord &run,
                                                const meta::EcV2MutationRsp &source,
                                                const meta::EcV2MutationRsp &replacement) {
  RETURN_ON_ERROR(run.validate());
  if (run.action != "recovery-write") return makeError(StatusCode::kInvalidArg);
  auto observed = expectedSource(run);
  observed.revision = replacement.record.candidate.revision;
  RETURN_ON_ERROR(validatePublishedEcStripeRun(run, observed, replacement));
  RETURN_ON_ERROR(publishedDrain(replacement));
  if (replacement.record.intent.expectedEpoch != run.object->epoch ||
      replacement.record.candidate.revision <= run.expectedRevision ||
      replacement.record.candidate.generation <= source.record.candidate.generation)
    return makeError(StatusCode::kDataCorruption, "recovery publication did not create a new version/generation");
  for (const auto &fragment : replacement.record.candidate.fragments)
    for (const auto &old : source.record.candidate.fragments)
      if (fragment.identity.allocation == old.identity.allocation)
        return makeError(StatusCode::kDataCorruption, "recovery reused an old allocation");
  return Void{};
}
}  // namespace hf3fs::client::ec
