#include "NativeEcRmwIo.h"

#include <algorithm>

#include "fbs/storage/EcStageValidationV2.h"
#include "storage/store/StorageTarget.h"

namespace hf3fs::storage {
namespace {
std::array<uint8_t, 16> bytes(const Uuid &id) {
  std::array<uint8_t, 16> out{};
  std::copy(std::begin(id.data), std::end(id.data), out.begin());
  return out;
}
EcFragmentAccessV2 access(const EcRepairFragment &fragment, VersionedChainId route) {
  EcFragmentAccessV2 out;
  out.identity = fragment.identity;
  out.operationId = fragment.operationId;
  out.vChainId = route;
  out.targetId = fragment.endpoint.targetId;
  out.integrity = fragment.integrity;
  return out;
}
Status unknownException(status_code_t cause) noexcept {
  try {
    return Status(StorageCode::kEcSealOutcomeUnknown, "RMW target requires exact reconciliation", Status(cause));
  } catch (...) {
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}
}  // namespace
Result<std::shared_ptr<NativeEcRmwIo>> NativeEcRmwIo::create(std::shared_ptr<const EcRmwPlan> plan,
                                                             EcRmwGrant grant,
                                                             std::shared_ptr<const EcRmwKey> key,
                                                             std::shared_ptr<const EcCapabilityKey> dataKey,
                                                             Uuid authority,
                                                             EcScopeEndpoint actual,
                                                             std::shared_ptr<StorageTarget> target,
                                                             EcScopeTicket ticket,
                                                             std::shared_ptr<EcRmwJobLease> lease,
                                                             std::shared_ptr<client::StorageClient> client,
                                                             std::array<EcCapabilityV2, 12> reads,
                                                             std::shared_ptr<EcRmwOutputBinder> binder,
                                                             Route route,
                                                             Clock clock,
                                                             std::function<Result<Void>()> localFence,
                                                             client::EcRequestControl control) {
  if (!plan || !key || !dataKey || !target || !lease || !client || !binder || !route || !clock || !localFence ||
      control.transport != client::EcRequestControl::TransportPolicy::TcpOnly)
    return makeError(StatusCode::kInvalidArg);
  const auto &p = plan->input();
  const auto &b = ticket.binding();
  if (b.kind != 2 || b.object != bytes(p.object) || b.scope != bytes(p.operationId) ||
      b.owner_uid != p.ownerUid.toUnderType() || b.client_namespace != bytes(p.clientNamespace) ||
      b.target.engine != bytes(actual.engineUuid) || b.target.incarnation != bytes(actual.targetIncarnation) ||
      b.target.chain != actual.chainId.toUnderType() || b.target.target != actual.targetId.toUnderType())
    return makeError(StatusCode::kAuthenticationFail, "RMW worker ticket differs from fixed output scope");
  auto out = std::shared_ptr<NativeEcRmwIo>(new NativeEcRmwIo);
  out->lease_ = std::move(lease);
  out->plan_ = std::move(plan);
  out->grant_ = std::move(grant);
  out->key_ = std::move(key);
  out->dataKey_ = std::move(dataKey);
  out->authority_ = authority;
  out->actual_ = actual;
  out->target_ = std::move(target);
  out->ticket_.emplace(std::move(ticket));
  out->client_ = std::move(client);
  out->reads_ = std::move(reads);
  out->binder_ = std::move(binder);
  out->route_ = std::move(route);
  out->clock_ = std::move(clock);
  out->localFence_ = std::move(localFence);
  out->control_ = std::move(control);
  RETURN_ON_ERROR(out->check());
  if (p.sourceKind == EcRmwSourceKind::Data)
    for (size_t i = 0; i < 12; ++i)
      RETURN_ON_ERROR(verifyEcGrantV2(*out->dataKey_,
                                      out->reads_[i],
                                      out->expected(p.sources[i], EcGrantScope::ReadPin, p.sourcePin),
                                      EcGrantRightV2::ReadBlock,
                                      out->clock_()));
  return out;
}
Result<Void> NativeEcRmwIo::check() const {
  if (control_.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= control_.deadline) return makeError(StorageClientCode::kTimeout);
  RETURN_ON_ERROR(EcRmwAuthorization::verify(*key_, grant_, plan_, actual_, authority_, EcRmwRight::Execute, clock_()));
  RETURN_ON_ERROR(localFence_());
  if (!target_->usesEcStagingEngine()) return makeError(StorageCode::kTargetStateInvalid);
  RETURN_ON_ERROR(target_->checkEcScopeTarget(ticket_->binding().target));
  return ticket_->checkExecution();
}
EcGrantBindingV2 NativeEcRmwIo::expected(const EcRepairFragment &f, EcGrantScope kind, const Uuid &scope) const {
  EcGrantBindingV2 b;
  b.engineUuid = f.endpoint.engineUuid;
  b.targetIncarnation = f.endpoint.targetIncarnation;
  b.identity = f.identity;
  b.fragmentOperationId = f.operationId;
  b.chainId = f.endpoint.chainId;
  b.targetId = f.endpoint.targetId;
  b.nodeId = f.endpoint.nodeId;
  b.expectedLength = f.integrity.wholeLength;
  b.expectedCrc32c = f.integrity.wholeCrc32c;
  // All callers validate the descriptor first. A failed digest produces a zero
  // commitment, which can never validate an authentic nonzero V2 credential.
  auto hash = digestEcIntegrityV2(f.identity, f.integrity);
  if (hash) b.integrityDigest = *hash;
  b.ownerUid = plan_->input().ownerUid;
  b.clientNamespace = plan_->input().clientNamespace;
  b.scopeObject = plan_->input().object;
  b.scopeKind = kind;
  b.scopeId = scope;
  return b;
}
CoTryTask<std::string> NativeEcRmwIo::readSource(uint8_t index) {
  if (index >= 12 || plan_->input().sourceKind != EcRmwSourceKind::Data) co_return makeError(StatusCode::kInvalidArg);
  const auto &p = plan_->input();
  const auto &source = p.sources[index];
  CO_RETURN_ON_ERROR(check());
  CO_RETURN_ON_ERROR(verifyEcGrantV2(*dataKey_,
                                     reads_[index],
                                     expected(source, EcGrantScope::ReadPin, p.sourcePin),
                                     EcGrantRightV2::ReadBlock,
                                     clock_()));
  std::string output;
  output.reserve(p.shardBytes);
  for (uint32_t block = 0; block < source.integrity.blockCount; ++block) {
    CO_RETURN_ON_ERROR(check());
    auto route = route_(source.endpoint);
    CO_RETURN_ON_ERROR(route);
    EcReadBlockV2Req request;
    request.request = access(source, *route);
    request.blockIndex = block;
    request.grant = reads_[index];
    auto result = co_await client_->readEcBlockV2Controlled(request, control_);
    if (!result) co_return makeError(std::move(result.error()));
    CO_RETURN_ON_ERROR(validateEcReadBlockV2(*result, request));
    CO_RETURN_ON_ERROR(check());
    output.append(result->payload.data);
  }
  if (output.size() != p.shardBytes) co_return makeError(StatusCode::kDataCorruption);
  co_return output;
}
CoTryTask<Void> NativeEcRmwIo::bindOutput(const EcRmwOutputCommitment &commitment) {
  CO_RETURN_ON_ERROR(check());
  if (commitment.planDigest != plan_->digest() || commitment.logicalSha256 == EcSha256{} ||
      (bound_ && (bound_->planDigest != commitment.planDigest || bound_->logicalSha256 != commitment.logicalSha256 ||
                  bound_->descriptors != commitment.descriptors)))
    co_return makeError(StatusCode::kTokenMismatch, "RMW output commitment changed");
  for (size_t i = 0; i < 12; ++i) {
    CO_RETURN_ON_ERROR(validateEcIntegrity(plan_->input().targets[i].identity, commitment.descriptors[i]));
    if (commitment.descriptors[i].wholeLength != plan_->input().shardBytes)
      co_return makeError(StatusCode::kInvalidArg);
  }
  auto authenticated = EcRmwComputationAuthorization::sign(*key_, *plan_, commitment);
  if (!authenticated) co_return makeError(std::move(authenticated.error()));
  auto grants = co_await binder_->bind(*plan_, *authenticated, control_);
  if (!grants) co_return makeError(std::move(grants.error()));
  CO_RETURN_ON_ERROR(check());
  for (size_t i = 0; i < 12; ++i) {
    EcRepairFragment f;
    f.identity = plan_->input().targets[i].identity;
    f.endpoint = plan_->input().targets[i].endpoint;
    f.operationId = plan_->input().operationId;
    f.integrity = commitment.descriptors[i];
    const auto b = expected(f, EcGrantScope::WriteOperation, plan_->input().operationId);
    for (auto right : {EcGrantRightV2::Begin,
                       EcGrantRightV2::Append,
                       EcGrantRightV2::Query,
                       EcGrantRightV2::Reconcile,
                       EcGrantRightV2::Seal})
      CO_RETURN_ON_ERROR(verifyEcGrantV2(*dataKey_, (*grants)[i], b, right, clock_()));
  }
  writes_ = std::move(*grants);
  bound_ = commitment;
  co_return Void{};
}
Status NativeEcRmwIo::preserve(uint8_t i, Status error) {
  if (error.code() == StorageCode::kEcSealOutcomeUnknown) unknown_[i] = true;
  if (unknown_[i] && error.code() != StorageCode::kEcSealOutcomeUnknown)
    return error.convert(StorageCode::kEcSealOutcomeUnknown);
  return error;
}
CoTryTask<EcFragmentReceiptV2> NativeEcRmwIo::writeTarget(uint8_t index,
                                                          const EcIntegrityDescriptor &descriptor,
                                                          std::string data) {
  if (index >= 12) co_return makeError(StatusCode::kInvalidArg);
  bool entered = false;
  const auto fail = [&](Status error) { return makeError(preserve(index, std::move(error))); };
  try {
    if (auto valid = check(); !valid) co_return fail(std::move(valid.error()));
    if (!bound_ || bound_->descriptors[index] != descriptor) co_return fail(Status(StatusCode::kTokenMismatch));
    const auto &p = plan_->input();
    EcRepairFragment f;
    f.identity = p.targets[index].identity;
    f.endpoint = p.targets[index].endpoint;
    f.operationId = p.operationId;
    f.integrity = descriptor;
    auto hash = computeEcIntegrity(f.identity, data);
    if (!hash || *hash != descriptor) co_return fail(Status(StatusCode::kDataCorruption));
    auto route = route_(f.endpoint);
    if (!route) co_return fail(std::move(route.error()));
    EcBeginStageV2Req begin;
    begin.request = access(f, *route);
    begin.grant = writes_[index];
    entered = true;
    auto state = co_await client_->beginEcStageV2Controlled(begin, control_);
    uint32_t prefix = 0;
    if (!state) {
      auto error = preserve(index, std::move(state.error()));
      if (error.code() != StorageCode::kEcSealOutcomeUnknown) co_return makeError(std::move(error));
    } else {
      auto valid = validateEcStageStateV2(*state, begin.request, begin.grant.claims);
      if (!valid) {
        unknown_[index] = true;
        co_return fail(std::move(valid.error()));
      }
      prefix = state->prefixBytes;
    }
    // Always perform an explicit barrier, including after process restart when
    // the in-memory unknown bit was lost. Query alone can never confirm WAL.
    unknown_[index] = true;
    if (auto valid = check(); !valid) co_return fail(std::move(valid.error()));
    auto query = co_await client_->queryEcStageV2Controlled({begin.request, begin.grant}, control_);
    if (query) {
      auto valid = validateEcStageStateV2(*query, begin.request, begin.grant.claims);
      if (!valid) co_return fail(std::move(valid.error()));
      prefix = std::max(prefix, query->prefixBytes);
    }
    if (auto valid = check(); !valid) co_return fail(std::move(valid.error()));
    state = co_await client_->reconcileEcStageV2Controlled({begin.request, begin.grant}, control_);
    if (!state) co_return fail(std::move(state.error()));
    auto valid = validateEcStageStateV2(*state, begin.request, begin.grant.claims);
    if (!valid) co_return fail(std::move(valid.error()));
    if (state->needsReconcile || state->prefixBytes < prefix)
      co_return fail(Status(StorageCode::kEcSealOutcomeUnknown));
    if (auto active = check(); !active) co_return fail(std::move(active.error()));
    unknown_[index] = false;
    if (state->state == 3) co_return makeError(StatusCode::kTokenStale, "fixed RMW target was aborted");
    if (state->state == 1) {
      for (uint32_t block = state->prefixBytes / kEcIntegrityBlockBytes; block < descriptor.blockCount; ++block) {
        if (auto active = check(); !active) co_return fail(std::move(active.error()));
        EcAppendStageV2Req append;
        append.request = begin.request;
        append.grant = begin.grant;
        append.blockIndex = block;
        append.payload.data = data.substr(size_t(block) * kEcIntegrityBlockBytes, descriptor.blocks[block].validLength);
        auto appended = co_await client_->appendEcStageV2Controlled(std::move(append), control_);
        if (!appended) co_return fail(std::move(appended.error()));
        auto checked = validateEcStageStateV2(*appended, begin.request, begin.grant.claims);
        if (!checked) {
          unknown_[index] = true;
          co_return fail(std::move(checked.error()));
        }
        const uint32_t end = block * kEcIntegrityBlockBytes + descriptor.blocks[block].validLength;
        if (appended->needsReconcile || appended->pendingBlock || appended->state != 1 || appended->prefixBytes < end) {
          unknown_[index] = true;
          co_return fail(Status(StorageCode::kEcSealOutcomeUnknown));
        }
      }
    }
    if (auto active = check(); !active) co_return fail(std::move(active.error()));
    auto sealed = co_await client_->sealEcStageV2Controlled({begin.request, begin.grant}, control_);
    if (!sealed) co_return fail(std::move(sealed.error()));
    auto checked = validateEcReceiptV2(*sealed, begin.request, begin.grant.claims);
    if (!checked) {
      unknown_[index] = true;
      co_return fail(std::move(checked.error()));
    }
    if (auto active = check(); !active) {
      unknown_[index] = true;
      co_return fail(std::move(active.error()));
    }
    unknown_[index] = false;
    co_return std::move(*sealed);
  } catch (const std::bad_alloc &) {
    if (entered) unknown_[index] = true;
    co_return makeError(unknown_[index] ? unknownException(StatusCode::kNotEnoughMemory)
                                        : Status(StatusCode::kNotEnoughMemory));
  } catch (...) {
    if (entered) unknown_[index] = true;
    co_return makeError(unknown_[index] ? unknownException(StatusCode::kIOError) : Status(StatusCode::kIOError));
  }
}
}  // namespace hf3fs::storage
