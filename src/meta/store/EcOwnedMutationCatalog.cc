#include "meta/store/EcOwnedMutationCatalog.h"

#include <set>

#include "common/kv/KeyPrefix.h"
#include "meta/store/EcFileAccess.h"
#include "meta/store/EcV2PublishedCatalog.h"

namespace hf3fs::meta::server {
CoTryTask<EcOwnedMutationRsp> EcOwnedMutationCatalog::query(kv::IReadWriteTransaction &txn,
                                                            const QueryEcOwnedMutationV2Req &req,
                                                            const storage::EcScopeControlKey &key) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await requireTrackedEcFile(txn, req.object));
  auto op = co_await EcCatalog::getOperation(txn, req.object, req.operation);
  // Missing means only that this transaction did not observe Begin. It is not
  // cancellation, permission to choose a new operation, or deletion authority.
  CO_RETURN_ON_ERROR(op);
  const EcOwner owner{req.user.uid, req.client.uuid};
  if (!serde::equals(op->owner, owner))
    co_return makeError(MetaCode::kNoPermission, "mutation belongs to another effective owner or namespace");
  if (op->version != kEcCatalogVersion || op->intent.version != kEcCatalogVersion ||
      op->candidate.version != kEcCatalogVersion || op->intent.object != req.object ||
      op->intent.operation != req.operation || op->candidate.object != req.object ||
      op->candidate.stripe != op->intent.stripe || op->candidate.logicalLength != op->intent.logicalLength ||
      !op->candidate.generation || !op->candidate.revision || !op->intent.expectedEpoch ||
      op->intent.requestDigest == storage::EcSha256{})
    co_return makeError(StatusCode::kDataCorruption, "mutation observation identity differs");
  std::set<Uuid> allocations;
  for (size_t i = 0; i != op->candidate.fragments.size(); ++i) {
    const auto &fragment = op->candidate.fragments[i];
    CO_RETURN_ON_ERROR(fragment.identity.validate());
    if (fragment.identity.object != req.object.incarnation || fragment.identity.stripe != op->intent.stripe ||
        fragment.identity.generation != op->candidate.generation || fragment.identity.shard != i ||
        fragment.placement != op->intent.placements[i] || fragment.operation.is_nil() ||
        !allocations.insert(fragment.identity.allocation).second ||
        ((op->intent.replacementMask & (1u << i)) && fragment.operation != req.operation))
      co_return makeError(StatusCode::kDataCorruption, "mutation candidate has inconsistent indexed allocations");
  }
  auto object = co_await EcCatalog::getObject(txn, req.object);
  CO_RETURN_ON_ERROR(object);
  auto reservation = co_await EcV2ReservationCatalog::get(txn, req.object, req.operation, owner);
  if (!reservation && reservation.error().code() == StatusCode::kNotImplemented)
    co_return makeError(StatusCode::kDataCorruption, "mode-3 mutation lost its permanent reservation");
  CO_RETURN_ON_ERROR(reservation);
  // get revalidates the original intent, owner, all twelve identities and
  // original writers, plus the canonical Begin digest against this SHA.
  auto binding = co_await EcV2BindingCatalog::getOperationBinding(txn, req.object, req.operation, owner);
  if (!binding) {
    if (binding.error().code() != StatusCode::kNotImplemented) co_return makeError(binding.error());
    // The legacy getter uses NotImplemented both for absent ECVO and for an
    // existing ECVO whose referenced ECVA disappeared. Only the first case is
    // an ordinary not-yet-bound operation; inspect this exact key in this txn.
    std::string bindingKey(kv::toStr(kv::KeyPrefix::EcV2Operation));
    bindingKey += req.object.incarnation.asStringView();
    bindingKey += req.operation.asStringView();
    auto storedBinding = co_await txn.get(bindingKey);
    CO_RETURN_ON_ERROR(storedBinding);
    if (*storedBinding)
      co_return makeError(StatusCode::kDataCorruption, "existing operation binding lost a dependent allocation");
    if (op->state == EcOperationState::Published || op->candidate != reservation->original.candidate)
      co_return makeError(StatusCode::kDataCorruption, "mutation candidate changed without an immutable binding");
  } else {
    // Individually well-formed records are insufficient: ECVO and ECVR must
    // describe exactly the same original physical instances and writers.
    if (!serde::equals(binding->operationEndpoints, reservation->operationEndpoints))
      co_return makeError(StatusCode::kDataCorruption, "binding endpoint set differs from original reservation");
    for (size_t i = 0; i != binding->allocations.size(); ++i) {
      const auto &allocation = binding->allocations[i];
      const auto &reserved = reservation->candidates[i];
      if (!serde::equals(allocation.fragment.identity, reserved.identity) ||
          allocation.fragment.operation != reserved.operation || allocation.endpoint() != reserved.endpoint ||
          !serde::equals(allocation.writer, reserved.writer))
        co_return makeError(StatusCode::kDataCorruption, "binding allocation differs from original reservation");
    }
  }

  auto drain =
      co_await EcV2DrainCatalog::get(txn, req.object, storage::EcGrantScope::WriteOperation, req.operation, owner);
  CO_RETURN_ON_ERROR(drain);
  EcOwnedMutationRsp rsp;
  rsp.requestId = req.uuid;
  rsp.clientNamespace = req.client.uuid;
  rsp.record = *op;
  rsp.contentSha256 = reservation->contentSha256;
  rsp.shardBytes = object->shardBytes;
  if (*drain) {
    const auto &record = **drain;
    const auto &id = record.identity;
    if (id.object != req.object || id.kind != storage::EcGrantScope::WriteOperation || id.scopeId != req.operation ||
        !serde::equals(id.owner, owner) || id.objectEpoch != op->intent.expectedEpoch ||
        id.generation != op->candidate.generation || id.revision != op->candidate.revision ||
        !serde::equals(id.endpoints, reservation->operationEndpoints))
      co_return makeError(StatusCode::kDataCorruption, "mutation drain differs from its original reservation");
    const auto expected = op->state == EcOperationState::Preparing   ? EcV2DrainState::Closing
                          : op->state == EcOperationState::Published ? EcV2DrainState::Published
                                                                     : EcV2DrainState::Aborted;
    if (record.state != expected) co_return makeError(StatusCode::kDataCorruption, "mutation and drain state disagree");
    EcV2DrainProgress progress;
    progress.state = record.state;
    progress.revocation = id.revocationId;
    progress.expectedEndpoints = id.endpoints.count;
    for (size_t i = 0; i != id.endpoints.count; ++i) {
      if (!record.observations[i]) continue;
      const auto &observation = *record.observations[i];
      // Uses the recorded request and ACK, including historical instance and
      // authority. It does not contact a target or refresh a capability.
      CO_RETURN_ON_ERROR(EcVerifiedDrainAck::verify(key, record, i, observation.request, observation.ack));
      ++progress.acknowledgedEndpoints;
    }
    if (op->state != EcOperationState::Preparing && progress.acknowledgedEndpoints != progress.expectedEndpoints)
      co_return makeError(StatusCode::kDataCorruption, "terminal mutation has incomplete durable drain evidence");
    rsp.drain = progress;
  } else if (op->state != EcOperationState::Preparing) {
    co_return makeError(StatusCode::kDataCorruption, "terminal mutation has no durable drain record");
  }

  if (op->state == EcOperationState::Published) {
    auto content = co_await EcV2PublishedCatalog::get(txn, req.object, op->candidate.stripe, op->candidate.revision);
    if (!content && content.error().code() == StatusCode::kNotImplemented)
      co_return makeError(StatusCode::kDataCorruption, "Published mutation lost its historical content evidence");
    CO_RETURN_ON_ERROR(content);
    if (content->operation != req.operation || !serde::equals(content->owner, owner) ||
        content->contentSha256 != reservation->contentSha256 || content->generation != op->candidate.generation ||
        content->logicalLength != op->candidate.logicalLength)
      co_return makeError(StatusCode::kDataCorruption, "Published content does not bind this exact mutation");
    // ECVC::get also revalidates the persisted verified manifest against the
    // complete candidate. Historical revisions remain valid after replacement
    // or retirement; neither current head nor active GC counts are required.
    rsp.publishedContentConfirmed = true;
  }
  co_return rsp;
}
}  // namespace hf3fs::meta::server
