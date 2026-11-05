#include <bit>
#include <folly/CancellationToken.h>
#include <folly/hash/Checksum.h>

#include "client/storage/EcRequestControl.h"
#include "detail/EcStripeClientCore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::client::ec::detail {
namespace {
using namespace hf3fs::storage;
Status unconfirmedStageException(status_code_t cause, std::string_view message) noexcept {
  try {
    return Status(StorageCode::kEcSealOutcomeUnknown, message, Status(cause));
  } catch (...) {
    // Status with only a code does not allocate. A second allocation failure
    // while reporting the first must not erase the reconciliation requirement.
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}
storage::client::EcRequestControl transportControl(EcStripeControl control) {
  return {control.deadline, control.cancellation, storage::client::EcRequestControl::TransportPolicy::TcpOnly};
}
EcStripeMutationOutcome failure(EcStripeMutationOutcome value,
                                Status error,
                                std::chrono::steady_clock::time_point start) {
  value.failure = std::move(error);
  value.elapsed = std::chrono::steady_clock::now() - start;
  return value;
}
Result<Void> mutationShape(const meta::EcObjectRecord &object) {
  if (object.version != meta::kEcCatalogVersion || object.object.incarnation.is_nil() ||
      object.object.inode.isTreeRoot() || object.deleting || !object.epoch || !object.shardBytes ||
      object.shardBytes > EcCodec::kMaxShardBytes)
    return makeError(StatusCode::kInvalidArg, "invalid fixed EC object");
  return Void{};
}
EcFragmentAccessV2 access(const meta::EcV2AllocationBinding &allocation, VersionedChainId route) {
  EcFragmentAccessV2 result;
  result.identity = allocation.fragment.identity;
  result.operationId = allocation.fragment.operation;
  result.vChainId = route;
  result.targetId = allocation.fragment.placement.target;
  result.integrity = allocation.fragment.integrity;
  return result;
}
}  // namespace

std::optional<Status> EcStripeClientCore::collectStageResults(EcStripeMutationOutcome &out,
                                                              std::span<Result<storage::EcStageStateV2>> results) {
  XCHECK_EQ(results.size(), out.stages.size());
  std::optional<Status> error;
  for (size_t i = 0; i != results.size(); ++i) {
    if (results[i]) {
      out.stages[i] = std::move(*results[i]);
    } else if (!error || (error->code() != StorageCode::kEcSealOutcomeUnknown &&
                          results[i].error().code() == StorageCode::kEcSealOutcomeUnknown)) {
      error = results[i].error();
    }
  }
  return error;
}

Result<storage::EcBeginStageV2Req> EcStripeClientCore::stageRequest(const meta::EcV2AllocationBinding &allocation,
                                                                    const storage::EcCapabilityV2 &capability,
                                                                    const Uuid &operation) const {
  const auto endpoint = allocation.endpoint().controlEndpoint();
  CHECK_RESULT(currentRoute, route(endpoint));
  CHECK_RESULT(digest, digestEcIntegrityV2(allocation.fragment.identity, allocation.fragment.integrity));
  const auto &claims = capability.claims;
  constexpr uint16_t required = uint16_t(EcGrantRightV2::Begin) | uint16_t(EcGrantRightV2::Append) |
                                uint16_t(EcGrantRightV2::Query) | uint16_t(EcGrantRightV2::Reconcile) |
                                uint16_t(EcGrantRightV2::Seal);
  if (claims.version != kEcGrantVersionV2 || (claims.rights & required) != required ||
      !serde::equals(claims.identity, allocation.fragment.identity) ||
      claims.fragmentOperationId != allocation.fragment.operation || claims.engineUuid != endpoint.engineUuid ||
      claims.targetIncarnation != endpoint.targetIncarnation || claims.nodeId != endpoint.nodeId ||
      claims.chainId != endpoint.chainId || claims.targetId != endpoint.targetId ||
      claims.expectedLength != allocation.fragment.integrity.wholeLength ||
      claims.expectedCrc32c != allocation.fragment.integrity.wholeCrc32c || claims.integrityDigest != digest ||
      claims.scopeKind != EcGrantScope::WriteOperation || claims.scopeObject != allocation.object.incarnation ||
      claims.scopeId != operation || claims.ownerUid != owner.uid || claims.clientNamespace != owner.client ||
      allocation.writer.uid != owner.uid || allocation.writer.client != owner.client) {
    return makeError(StatusCode::kInvalidArg, "stage grant differs from fixed operation/allocation/writer");
  }
  EcBeginStageV2Req result;
  result.request = access(allocation, currentRoute);
  result.grant = capability;
  return result;
}

CoTryTask<storage::EcStageStateV2> EcStripeClientCore::writeFragment(const meta::EcV2AllocationBinding &allocation,
                                                                     const storage::EcCapabilityV2 &capability,
                                                                     std::string_view bytes,
                                                                     EcStripeControl control) {
  try {
    co_return co_await writeFragmentImpl(allocation, capability, bytes, control);
  } catch (const std::bad_alloc &) {
    // Allocation failure may occur while consuming a dispatched mutation's
    // response. Its exception cannot prove that the fixed stage was untouched.
    co_return makeError(
        unconfirmedStageException(StatusCode::kNotEnoughMemory,
                                  "stage task raised std::bad_alloc (NotEnoughMemory); preserve its fixed allocation"));
  } catch (...) {
    co_return makeError(
        unconfirmedStageException(StatusCode::kIOError, "stage task raised; preserve the fixed allocation"));
  }
}
CoTryTask<storage::EcStageStateV2> EcStripeClientCore::writeFragmentImpl(const meta::EcV2AllocationBinding &allocation,
                                                                         const storage::EcCapabilityV2 &capability,
                                                                         std::string_view bytes,
                                                                         EcStripeControl control) {
  CO_RETURN_ON_ERROR(active(control));
  auto fixed = stageRequest(allocation, capability, capability.claims.scopeId);
  CO_RETURN_ON_ERROR(fixed);
  if (bytes.size() != fixed->request.integrity.wholeLength) co_return makeError(StatusCode::kInvalidArg);
  std::optional<Status> last;
  std::optional<Status> unconfirmed;
  const auto remember = [&](Status error) {
    if (error.code() == StorageCode::kEcSealOutcomeUnknown && !unconfirmed) unconfirmed = error;
    last = std::move(error);
  };
  const auto failure = [&](Status error) {
    // Query, routing, cancellation and subsequent Begin replies cannot prove
    // away a previous unknown mutation. Only a validated explicit barrier can.
    return makeError(unconfirmed ? *unconfirmed : std::move(error));
  };
  const auto invalidDurableReply = [&](const Status &error) {
    // The RPC client already applies this rule. Keep the abstract StorageClient
    // boundary equally conservative: an invalid positive mutation reply does
    // not establish that the requested allocation was left unchanged.
    remember(Status(StorageCode::kEcSealOutcomeUnknown,
                    fmt::format("unconfirmed durable stage reply: {}", error.describe())));
    return failure(error);
  };
  for (unsigned retry = 0; retry != limits.recoveryAttempts; ++retry) {
    auto admitted = active(control);
    if (!admitted) co_return failure(admitted.error());
    // Refresh routing only. Signed physical instance, writer, stage identity
    // and operation remain exactly those returned by Bind.
    auto currentRoute = route(allocation.endpoint().controlEndpoint());
    if (!currentRoute) co_return failure(currentRoute.error());
    fixed->request.vChainId = *currentRoute;
    auto state = co_await storage->beginEcStageV2Controlled(*fixed, transportControl(control));
    bool reconciled = false;
    if (!state) remember(state.error());
    if (state && (state->needsReconcile || state->pendingBlock))
      remember(Status(StorageCode::kEcSealOutcomeUnknown, "existing stage requires reconciliation"));
    if (!state || unconfirmed) {
      EcQueryStageV2Req query;
      query.request = fixed->request;
      query.grant = capability;
      auto observed = co_await storage->queryEcStageV2Controlled(std::move(query), transportControl(control));
      if (!observed) {
        remember(observed.error());
      } else {
        auto valid = validateEcStageStateV2(*observed, fixed->request, capability.claims);
        if (!valid) co_return failure(valid.error());
      }
      // Even a query showing Sealed is not a durability re-confirmation.
      // A failed Query can also be an unconfirmed reservation still held by
      // Engine; Reconcile may reassert that same position, never a new key.
      admitted = active(control);
      if (!admitted) co_return failure(admitted.error());
      currentRoute = route(allocation.endpoint().controlEndpoint());
      if (!currentRoute) co_return failure(currentRoute.error());
      fixed->request.vChainId = *currentRoute;
      EcReconcileStageV2Req reconcile;
      reconcile.request = fixed->request;
      reconcile.grant = capability;
      state = co_await storage->reconcileEcStageV2Controlled(std::move(reconcile), transportControl(control));
      reconciled = bool(state);
    }
    if (!state) {
      remember(state.error());
      continue;
    }
    auto valid = validateEcStageStateV2(*state, fixed->request, capability.claims);
    if (!valid) co_return invalidDurableReply(valid.error());
    if (state->needsReconcile || (state->pendingBlock && !reconciled)) {
      remember(Status(StorageCode::kEcSealOutcomeUnknown, "stage reconciliation remains pending"));
      continue;
    }
    if (reconciled) {
      // Active+pendingBlock is a confirmed intent at prefixBytes, not confirmed
      // new progress. Rust requires its same bound bytes to be resent below.
      unconfirmed.reset();
      last.reset();
    }
    if (state->state == 3) co_return failure(Status(StatusCode::kInvalidArg, "fixed stage is durably aborted"));
    bool appendFailed = false;
    if (state->state == 1) {
      for (uint32_t block = 0; block != fixed->request.integrity.blockCount; ++block) {
        const uint32_t offset = block * kEcIntegrityBlockBytes;
        const auto length = fixed->request.integrity.blocks[block].validLength;
        if (offset + length <= state->prefixBytes) continue;
        if (offset != state->prefixBytes)
          co_return failure(Status(StatusCode::kDataCorruption, "non-block stage prefix"));
        admitted = active(control);
        if (!admitted) co_return failure(admitted.error());
        EcAppendStageV2Req append;
        append.request = fixed->request;
        append.grant = capability;
        append.blockIndex = block;
        append.payload.data.assign(bytes.substr(offset, length));
        state = co_await storage->appendEcStageV2Controlled(std::move(append), transportControl(control));
        if (!state) {
          remember(state.error());
          appendFailed = true;
          break;
        }
        valid = validateEcStageStateV2(*state, fixed->request, capability.claims);
        if (!valid) co_return invalidDurableReply(valid.error());
        if (state->needsReconcile || state->pendingBlock || state->prefixBytes < offset + length) {
          remember(Status(StorageCode::kEcSealOutcomeUnknown, "append progress requires reconciliation"));
          appendFailed = true;
          break;
        }
      }
    }
    if (appendFailed) continue;
    admitted = active(control);
    if (!admitted) co_return failure(admitted.error());
    EcSealStageV2Req seal;
    seal.request = fixed->request;
    seal.grant = capability;
    auto receipt = co_await storage->sealEcStageV2Controlled(std::move(seal), transportControl(control));
    if (!receipt) {
      remember(receipt.error());
      continue;
    }
    valid = validateEcReceiptV2(*receipt, fixed->request, capability.claims);
    if (!valid) co_return invalidDurableReply(valid.error());
    if (!active(control)) co_return makeError(StorageCode::kEcSealOutcomeUnknown, "Seal completed after local stop");
    state->receipt = std::move(*receipt);
    state->state = 2;
    state->prefixBytes = static_cast<uint32_t>(bytes.size());
    state->needsReconcile = false;
    state->pendingBlock = false;
    co_return std::move(*state);
  }
  co_return failure(last.value_or(Status(StorageCode::kEcSealOutcomeUnknown)));
}

CoTask<EcStripeMutationOutcome> EcStripeClientCore::writeOwned(EcStripeWrite input, EcStripeControl control) {
  CancellationSource combined;
  folly::CancellationCallback managerStop(stop.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback callerStop(control.cancellation, [&] { combined.requestCancellation(); });
  control.cancellation = combined.getToken();
  const auto start = std::chrono::steady_clock::now();
  EcStripeMutationOutcome out;
  out.object = input.object.object;
  out.operation = input.ids.operation;
  auto fail = [&](Status status) { return failure(std::move(out), std::move(status), start); };
  for (const auto &check : {validControl(control), validIds(input.ids), mutationShape(input.object)})
    if (!check) co_return fail(check.error());
  out.phase = EcStripePhase::Encode;
  auto encoded = EcCodec::encode(input.logicalData, input.object.shardBytes);
  if (!encoded) co_return fail(encoded.error());
  std::array<std::string_view, 10> data;
  for (size_t i = 0; i != 10; ++i) data[i] = (*encoded)[i];
  auto hash = meta::computeEcLogicalSha256(data, input.logicalData.size());
  if (!hash) co_return fail(hash.error());
  meta::BeginEcMutationV2Req beginReq;
  beginReq.object = input.object.object;
  beginReq.operation = input.ids.operation;
  beginReq.stripe = input.stripe;
  beginReq.expectedEpoch = input.object.epoch;
  beginReq.expectedRevision = input.expectedRevision;
  beginReq.logicalLength = input.logicalData.size();
  beginReq.kind = meta::EcMutationKind::Write;
  beginReq.replacementMask = meta::kEcAllShards;
  beginReq.contentSha256 = *hash;
  for (size_t i = 0; i != 12; ++i)
    beginReq.fragmentCrc32c[i] =
        ~folly::crc32c(reinterpret_cast<const uint8_t *>((*encoded)[i].data()), (*encoded)[i].size());
  out.phase = EcStripePhase::Begin;
  auto begun = co_await begin(beginReq, input.ids, control);
  if (!begun) co_return fail(begun.error());
  if (begun->object.shardBytes != input.object.shardBytes)
    co_return fail(Status(StatusCode::kTokenMismatch, "object shard capacity differs from admitted write"));
  out.observation = *begun;
  if (begun->record.state == meta::EcOperationState::Aborted)
    co_return fail(Status(StatusCode::kInvalidArg, "original EC operation is aborted"));
  if (begun->record.state == meta::EcOperationState::Preparing && !begun->drain) {
    std::array<EcIntegrityDescriptor, 12> descriptors;
    for (size_t i = 0; i != 12; ++i) {
      auto descriptor = computeEcIntegrity(begun->record.candidate.fragments[i].identity, (*encoded)[i]);
      if (!descriptor) co_return fail(descriptor.error());
      descriptors[i] = std::move(*descriptor);
    }
    out.phase = EcStripePhase::Bind;
    auto bound = co_await bind(beginReq, input.ids, descriptors, control);
    if (!bound) co_return fail(bound.error());
    out.observation = *bound;
    if (bound->record.state == meta::EcOperationState::Aborted)
      co_return fail(Status(StatusCode::kInvalidArg, "original EC operation is aborted"));
    if (bound->record.state == meta::EcOperationState::Preparing && !bound->drain) {
      out.phase = EcStripePhase::Stage;
      std::vector<CoTryTask<EcStageStateV2>> jobs;
      jobs.reserve(12);
      for (size_t i = 0; i != 12; ++i)
        jobs.push_back(writeFragment((*bound->allocations)[i], *bound->grants[i], (*encoded)[i], control));
      // All children finish before codeword or grant backing storage can die.
      const auto dataStarted = std::chrono::steady_clock::now();
      auto results = co_await folly::coro::collectAllWindowed(std::move(jobs), limits.writeFragments);
      out.dataPhaseElapsed = std::chrono::steady_clock::now() - dataStarted;
      auto error = collectStageResults(out, results);
      if (error) co_return fail(*error);
    }
  }
  if (out.observation->record.state != meta::EcOperationState::Published) {
    out.phase = EcStripePhase::Publish;
    auto published = co_await publish(input.object.object, input.ids, control);
    if (!published) co_return fail(published.error());
    auto matches = validateObservation(*published, beginReq);
    if (!matches) co_return fail(matches.error());
    out.observation = std::move(*published);
  }
  if (out.observation->record.state != meta::EcOperationState::Published)
    co_return fail(Status(StorageCode::kEcSealOutcomeUnknown, "publication is pending; retry the same operation"));
  out.phase = EcStripePhase::Published;
  out.elapsed = std::chrono::steady_clock::now() - start;
  co_return out;
}

CoTask<EcStripeMutationOutcome> EcStripeClientCore::repairOwned(EcStripeRepair input, EcStripeControl control) {
  CancellationSource combined;
  folly::CancellationCallback managerStop(stop.getToken(), [&] { combined.requestCancellation(); });
  folly::CancellationCallback callerStop(control.cancellation, [&] { combined.requestCancellation(); });
  control.cancellation = combined.getToken();
  const auto start = std::chrono::steady_clock::now();
  EcStripeMutationOutcome out;
  out.object = input.object.object;
  out.operation = input.ids.operation;
  auto fail = [&](Status status) { return failure(std::move(out), std::move(status), start); };
  for (const auto &check :
       {validControl(control), validIds(input.ids), mutationShape(input.object), validPin(input.baseRead)})
    if (!check) co_return fail(check.error());
  if (input.planId.is_nil() || input.ids.prepareRepairRequest.is_nil() ||
      input.baseRead.object != input.object.object || !input.replacementMask ||
      (input.replacementMask & ~meta::kEcAllShards) || std::popcount(input.replacementMask) > 2)
    co_return fail(Status(StatusCode::kInvalidArg, "repair requires fixed plan, pin and one/two replacement shards"));
  uint16_t seen = input.replacementMask;
  for (auto index : input.sources) {
    if (index >= 12 || (seen & (1u << index)))
      co_return fail(Status(StatusCode::kInvalidArg, "invalid fixed repair sources"));
    seen |= uint16_t(1u << index);
  }
  out.phase = EcStripePhase::Observe;
  // Resolve a prior Publish before re-acquiring the auxiliary base pin. That
  // pin may already have been explicitly released after a successful earlier
  // run; it must not hide a durable result of this exact operation.
  auto prior = co_await getOperation(input.object.object, input.ids, control);
  if (prior) {
    const auto &intent = prior->record.intent;
    if (intent.object != input.object.object || intent.operation != input.ids.operation ||
        intent.stripe != input.baseRead.stripe || intent.expectedEpoch != input.object.epoch ||
        intent.expectedRevision != input.expectedRevision || intent.kind != meta::EcMutationKind::Repair ||
        intent.replacementMask != input.replacementMask || !prior->reservation ||
        prior->object.shardBytes != input.object.shardBytes)
      co_return fail(Status(StatusCode::kTokenMismatch, "persisted repair differs from fixed request"));
    meta::BeginEcMutationV2Req original;
    original.object = intent.object;
    original.operation = intent.operation;
    original.stripe = intent.stripe;
    original.expectedEpoch = intent.expectedEpoch;
    original.expectedRevision = intent.expectedRevision;
    original.logicalLength = intent.logicalLength;
    original.kind = intent.kind;
    original.replacementMask = intent.replacementMask;
    original.fragmentCrc32c = intent.fragmentCrc32c;
    original.contentSha256 = prior->reservation->contentSha256;
    auto matching = validateObservation(*prior, original);
    if (!matching) co_return fail(matching.error());
    out.observation = *prior;
    if (prior->record.state == meta::EcOperationState::Aborted)
      co_return fail(Status(StatusCode::kTokenStale, "original repair is aborted"));
    if (prior->drain && prior->record.state == meta::EcOperationState::Preparing) {
      out.phase = EcStripePhase::Publish;
      auto resumed = co_await publish(input.object.object, input.ids, control);
      if (!resumed) co_return fail(resumed.error());
      matching = validateObservation(*resumed, original);
      if (!matching) co_return fail(matching.error());
      out.observation = std::move(*resumed);
    }
    if (out.observation->record.state == meta::EcOperationState::Published) {
      out.phase = EcStripePhase::Published;
      out.elapsed = std::chrono::steady_clock::now() - start;
      co_return out;
    }
    if (out.observation->drain)
      co_return fail(Status(StorageCode::kEcSealOutcomeUnknown, "repair drain remains pending"));
  }
  meta::AcquireEcReadV2Req acquire;
  request(acquire, input.baseRead.acquireRequest);
  acquire.object = input.baseRead.object;
  acquire.stripe = input.baseRead.stripe;
  acquire.pin = input.baseRead.pin;
  if (auto activeNow = active(control); !activeNow) co_return fail(activeNow.error());
  auto base = co_await meta->acquireEcReadV2(std::move(acquire));
  if (!base) co_return fail(base.error());
  auto ownerMatches = validOwner(base->snapshot.owner);
  if (!ownerMatches) co_return fail(ownerMatches.error());
  if (base->manifest.object != input.object.object || base->snapshot.pin != input.baseRead.pin ||
      base->manifest.stripe != input.baseRead.stripe || base->manifest.revision != input.expectedRevision)
    co_return fail(Status(StatusCode::kInvalidArg, "repair base pin differs from fixed expected revision"));
  meta::BeginEcMutationV2Req beginReq;
  beginReq.object = input.object.object;
  beginReq.operation = input.ids.operation;
  beginReq.stripe = input.baseRead.stripe;
  beginReq.expectedEpoch = input.object.epoch;
  beginReq.expectedRevision = input.expectedRevision;
  beginReq.logicalLength = base->manifest.logicalLength;
  beginReq.kind = meta::EcMutationKind::Repair;
  beginReq.replacementMask = input.replacementMask;
  beginReq.contentSha256 = base->contentSha256;
  std::array<EcIntegrityDescriptor, 12> descriptors;
  for (size_t i = 0; i != 12; ++i) {
    descriptors[i] = base->manifest.fragments[i].integrity;
    if (descriptors[i].wholeLength != input.object.shardBytes)
      co_return fail(Status(StatusCode::kTokenMismatch, "base shard size differs from admitted repair"));
    beginReq.fragmentCrc32c[i] = descriptors[i].wholeCrc32c;
  }
  out.phase = EcStripePhase::Begin;
  auto begun = co_await begin(beginReq, input.ids, control);
  if (!begun) co_return fail(begun.error());
  out.observation = *begun;
  if (begun->record.state == meta::EcOperationState::Aborted)
    co_return fail(Status(StatusCode::kInvalidArg, "original repair operation is aborted"));
  if (begun->record.state == meta::EcOperationState::Preparing && !begun->drain) {
    // Content descriptors omit allocation identity by definition. Repair keeps
    // generation/content fixed, so use the trusted base table without a full
    // preliminary stripe read. New grants separately bind new allocations.
    out.phase = EcStripePhase::Bind;
    auto bound = co_await bind(beginReq, input.ids, descriptors, control);
    if (!bound) co_return fail(bound.error());
    out.observation = *bound;
    if (bound->record.state == meta::EcOperationState::Preparing && !bound->drain) {
      meta::PrepareEcRepairV2Req prepare;
      request(prepare, input.ids.prepareRepairRequest);
      prepare.object = input.object.object;
      prepare.operation = input.ids.operation;
      prepare.planId = input.planId;
      prepare.maxBlocksInFlight = input.blockWindow;
      for (size_t i = 0; i != 10; ++i) prepare.sourceOrder[i] = static_cast<uint8_t>(input.sources[i]);
      if (auto activeNow = active(control); !activeNow) co_return fail(activeNow.error());
      auto issued = co_await meta->prepareEcRepairV2(std::move(prepare));
      if (!issued) co_return fail(issued.error());
      auto observation = validateObservation(issued->mutation, beginReq);
      if (!observation) co_return fail(observation.error());
      out.observation = issued->mutation;
      if (!issued->mutation.allocations || issued->mutation.drain ||
          issued->mutation.record.state != meta::EcOperationState::Preparing)
        co_return fail(Status(StatusCode::kTokenStale, "repair issuance is already closing"));
      if (input.mode == EcRepairMode::HelperChain && !issued->helpers)
        co_return fail(Status(StatusCode::kNotImplemented, "Meta helper signing is unavailable; no fallback selected"));
      auto plan = EcRepairPlan::create(issued->plan);
      if (!plan) co_return fail(plan.error());
      const auto &fixed = (*plan)->input();
      if (fixed.planId != input.planId || fixed.operationId != input.ids.operation || fixed.ownerUid != owner.uid ||
          fixed.clientNamespace != owner.client || fixed.baseEpoch != input.object.epoch ||
          fixed.baseRevision != input.expectedRevision || fixed.logicalLength != base->manifest.logicalLength ||
          fixed.logicalSha256 != base->contentSha256 || fixed.maxBlocksInFlight != input.blockWindow ||
          fixed.targetCount != std::popcount(input.replacementMask))
        co_return fail(Status(StatusCode::kTokenMismatch, "Meta repair plan differs from fixed caller intent"));
      const auto &boundAllocations = *issued->mutation.allocations;
      const auto &fullSet = issued->mutation.reservation->operationEndpoints;
      if (fixed.operationEndpointCount != fullSet.count || (*plan)->endpointSetDigest() != fullSet.digest)
        co_return fail(Status(StatusCode::kDataCorruption, "Meta plan omitted an operation endpoint"));
      auto sameFragment = [&](const EcRepairFragment &fragment, size_t index) {
        const auto &allocation = boundAllocations[index];
        const auto endpoint = allocation.endpoint().controlEndpoint();
        return serde::equals(fragment.identity, allocation.fragment.identity) &&
               fragment.operationId == allocation.fragment.operation &&
               fragment.writerNamespace == allocation.writer.client && fragment.endpoint.nodeId == endpoint.nodeId &&
               fragment.endpoint.chainId == endpoint.chainId && fragment.endpoint.targetId == endpoint.targetId &&
               fragment.endpoint.engineUuid == endpoint.engineUuid &&
               fragment.endpoint.targetIncarnation == endpoint.targetIncarnation &&
               fragment.integrity == descriptors[index];
      };
      EcRepairNativeBindings bindings;
      for (size_t i = 0; i != 10; ++i) {
        const auto index = input.sources[i];
        const auto &source = fixed.sources[i];
        if (source.identity.shard != index || !sameFragment(source, index) || !issued->mutation.grants[index])
          co_return fail(Status(StatusCode::kDataCorruption, "Meta repair source order/binding mismatch"));
        auto currentRoute = route(source.endpoint);
        if (!currentRoute) co_return fail(currentRoute.error());
        auto read = makeEcReadBlockRequest({source.identity, source.operationId, source.endpoint, source.integrity},
                                           *issued->mutation.grants[index],
                                           *currentRoute,
                                           0);
        if (!read) co_return fail(read.error());
        bindings.sources[i] = std::move(*read);
      }
      uint16_t actualTargets = 0;
      for (size_t i = 0; i != fixed.targetCount; ++i) {
        const auto index = fixed.targets[i].identity.shard;
        if (index >= 12 || !(input.replacementMask & (1u << index)) || !sameFragment(fixed.targets[i], index) ||
            !issued->mutation.grants[index])
          co_return fail(Status(StatusCode::kDataCorruption, "Meta repair target binding mismatch"));
        actualTargets |= uint16_t(1u << index);
        auto stage = stageRequest(boundAllocations[index], *issued->mutation.grants[index], input.ids.operation);
        if (!stage) co_return fail(stage.error());
        bindings.targets[i] = std::move(*stage);
      }
      if (actualTargets != input.replacementMask) co_return fail(Status(StatusCode::kDataCorruption));
      auto transport = NativeEcRepairTransport::create(*plan, storage, std::move(bindings), std::move(issued->helpers));
      if (!transport) co_return fail(transport.error());
      out.phase = EcStripePhase::Repair;
      const auto dataStarted = std::chrono::steady_clock::now();
      auto repaired = co_await EcRepairPipeline::run(*plan,
                                                     *transport,
                                                     input.mode,
                                                     {control.deadline, control.cancellation},
                                                     executor);
      out.dataPhaseElapsed = std::chrono::steady_clock::now() - dataStarted;
      if (!repaired) co_return fail(repaired.error());
    }
  }
  if (out.observation->record.state != meta::EcOperationState::Published) {
    out.phase = EcStripePhase::Publish;
    auto published = co_await publish(input.object.object, input.ids, control);
    if (!published) co_return fail(published.error());
    auto matches = validateObservation(*published, beginReq);
    if (!matches) co_return fail(matches.error());
    out.observation = std::move(*published);
  }
  if (out.observation->record.state != meta::EcOperationState::Published)
    co_return fail(
        Status(StorageCode::kEcSealOutcomeUnknown, "repair publication pending; retain original operation and pin"));
  out.phase = EcStripePhase::Published;
  out.elapsed = std::chrono::steady_clock::now() - start;
  co_return out;
}
}  // namespace hf3fs::client::ec::detail
