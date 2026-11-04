#include "EcBlockRead.h"

#include "detail/EcQuorumRead.h"
#include "fbs/storage/EcStageValidationV2.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> validateBinding(const EcBlockBinding &binding,
                             const storage::EcCapabilityV2 &grant,
                             storage::VersionedChainId route,
                             uint32_t block) {
  RETURN_ON_ERROR(storage::validateEcIntegrity(binding.identity, binding.integrity));
  const auto &claims = grant.claims;
  const auto &endpoint = binding.endpoint;
  CHECK_RESULT(digest, storage::digestEcIntegrityV2(binding.identity, binding.integrity));
  constexpr auto read = uint16_t(storage::EcGrantRightV2::ReadBlock);
  if (binding.originalOperation.is_nil() || endpoint.engineUuid.is_nil() || endpoint.targetIncarnation.is_nil() ||
      endpoint.nodeId == flat::NodeId{} || endpoint.chainId == storage::ChainId{} ||
      endpoint.targetId == storage::TargetId{} || route.chainId != endpoint.chainId ||
      block >= binding.integrity.blockCount || claims.version != storage::kEcGrantVersionV2 ||
      claims.grantId.is_nil() || claims.clientNamespace.is_nil() || claims.scopeId.is_nil() ||
      (claims.rights & read) == 0 || (claims.rights & ~storage::kEcGrantAllRightsV2) != 0 ||
      (claims.scopeKind != storage::EcGrantScope::ReadPin &&
       claims.scopeKind != storage::EcGrantScope::WriteOperation) ||
      (claims.scopeKind == storage::EcGrantScope::ReadPin && claims.rights != read) ||
      claims.expiresAtSeconds <= claims.issuedAtSeconds ||
      claims.expiresAtSeconds - claims.issuedAtSeconds > storage::kEcGrantMaxTtlSeconds ||
      !serde::equals(claims.identity, binding.identity) || claims.fragmentOperationId != binding.originalOperation ||
      claims.engineUuid != endpoint.engineUuid || claims.targetIncarnation != endpoint.targetIncarnation ||
      claims.nodeId != endpoint.nodeId || claims.chainId != endpoint.chainId || claims.targetId != endpoint.targetId ||
      claims.expectedLength != binding.integrity.wholeLength ||
      claims.expectedCrc32c != binding.integrity.wholeCrc32c || claims.integrityDigest != digest ||
      claims.scopeObject != binding.identity.object) {
    return makeError(StatusCode::kInvalidArg, "V2 block grant differs from fixed allocation binding");
  }
  return Void{};
}

EcBlockBinding bindingAt(const meta::EcV2PinnedRead &input, size_t index) {
  const auto &fragment = input.manifest.fragments[index];
  return {fragment.identity,
          fragment.operation,
          input.snapshot.endpoints[index].endpoint.controlEndpoint(),
          fragment.integrity};
}

Result<Void> validateInput(const EcBlockReadInput &input) {
  const auto &manifest = input.pinned.manifest;
  const auto &snapshot = input.pinned.snapshot;
  const uint32_t length = manifest.fragments[0].integrity.wholeLength;
  if (manifest.version != meta::kEcCatalogVersion || manifest.object.incarnation.is_nil() || manifest.generation == 0 ||
      manifest.revision == 0 || length == 0 || length > storage::kEcFragmentRpcMaxBytes ||
      manifest.logicalLength > uint64_t(length) * 10 || snapshot.version != meta::kEcBindingCatalogVersion ||
      snapshot.object != manifest.object || snapshot.pin.is_nil() || snapshot.owner.client.is_nil() ||
      snapshot.stripe != manifest.stripe || snapshot.revision != manifest.revision ||
      snapshot.generation != manifest.generation) {
    return makeError(StatusCode::kInvalidArg, "V2 block read requires one fixed pinned manifest and instance snapshot");
  }
  std::array<storage::EcScopeEndpoint, 12> endpoints;
  for (size_t index = 0; index != 12; ++index) {
    const auto &fragment = manifest.fragments[index];
    const auto &mapping = snapshot.endpoints[index];
    const auto &wire = input.requests[index];
    const auto &request = wire.request;
    const auto &claims = wire.grant.claims;
    if (fragment.identity.object != manifest.object.incarnation || fragment.identity.stripe != manifest.stripe ||
        fragment.identity.generation != manifest.generation || fragment.identity.shard != index ||
        fragment.integrity.wholeLength != length || !serde::equals(mapping.identity, fragment.identity) ||
        mapping.operation != fragment.operation || mapping.endpoint.placement != fragment.placement ||
        request.version != storage::kEcGrantVersionV2 || !serde::equals(request.identity, fragment.identity) ||
        request.operationId != fragment.operation || request.targetId != fragment.placement.target ||
        request.integrity != fragment.integrity || wire.blockIndex != input.blockIndex ||
        claims.scopeKind != storage::EcGrantScope::ReadPin || claims.scopeId != snapshot.pin ||
        claims.ownerUid != snapshot.owner.uid || claims.clientNamespace != snapshot.owner.client) {
      return makeError(StatusCode::kInvalidArg, "V2 read candidate differs from pinned manifest or pin scope");
    }
    auto binding = bindingAt(input.pinned, index);
    RETURN_ON_ERROR(validateBinding(binding, wire.grant, request.vChainId, input.blockIndex));
    endpoints[index] = binding.endpoint;
  }
  CHECK_RESULT(digest, storage::computeEcScopeEndpointDigest(endpoints));
  if (digest != snapshot.endpointSetDigest) return makeError(StatusCode::kInvalidArg, "V2 pin endpoint set mismatch");
  return Void{};
}

struct BlockPolicy {
  using Input = EcBlockReadInput;
  using Response = storage::EcReadBlockResultV2;
  static constexpr bool splitOutputReservation = true;
  std::shared_ptr<EcBlockReadTransport> transport;
  bool available() const { return bool(transport); }
  Result<Void> validateInput(const Input &input) const { return ec::validateInput(input); }
  size_t payloadLength(const Input &input) const {
    return input.pinned.manifest.fragments[0].integrity.blocks[input.blockIndex].validLength;
  }
  CoTryTask<Response> read(const Input &input,
                           uint16_t index,
                           std::chrono::steady_clock::time_point deadline,
                           CancellationToken cancellation) const {
    return transport->read(input.requests[index], {deadline, cancellation});
  }
  Result<Void> validateResponse(const Input &input, uint16_t index, const Response &response) const {
    return storage::validateEcReadBlockV2(response, input.requests[index]);
  }
  void clearInput(Input &input) const { input.requests = {}; }
};
using Kernel = detail::EcQuorumRead<BlockPolicy>;
}  // namespace

Result<storage::EcReadBlockV2Req> makeEcReadBlockRequest(const EcBlockBinding &binding,
                                                         const storage::EcCapabilityV2 &grant,
                                                         storage::VersionedChainId route,
                                                         uint32_t block) {
  RETURN_ON_ERROR(validateBinding(binding, grant, route, block));
  storage::EcReadBlockV2Req request;
  request.request.identity = binding.identity;
  request.request.operationId = binding.originalOperation;
  request.request.vChainId = route;
  request.request.targetId = binding.endpoint.targetId;
  request.request.integrity = binding.integrity;
  request.blockIndex = block;
  request.grant = grant;
  return request;
}
Result<EcBlockReadInput> makeEcBlockReadInput(meta::EcV2PinnedRead pinned,
                                              const std::array<storage::EcCapabilityV2, 12> &grants,
                                              const std::array<storage::VersionedChainId, 12> &routes,
                                              uint32_t block) {
  EcBlockReadInput result;
  result.pinned = std::move(pinned);
  result.blockIndex = block;
  for (size_t index = 0; index != 12; ++index) {
    CHECK_RESULT(request, makeEcReadBlockRequest(bindingAt(result.pinned, index), grants[index], routes[index], block));
    result.requests[index] = std::move(request);
  }
  RETURN_ON_ERROR(validateInput(result));
  return result;
}

namespace detail {
struct EcBlockReadState {
  Kernel::Handle handle;
  meta::EcV2PinnedRead pinned;
  uint32_t blockIndex;
  EcBlockReadState(Kernel::Handle value, meta::EcV2PinnedRead fixed, uint32_t block)
      : handle(std::move(value)),
        pinned(std::move(fixed)),
        blockIndex(block) {}
  static CoTryTask<EcBlockSelection> take(std::shared_ptr<EcBlockReadState> state) {
    if (!state) co_return makeError(StatusCode::kInvalidArg, "empty V2 block read handle");
    auto selected = co_await state->handle.takeReady();
    if (!selected) co_return makeError(selected.error());
    EcBlockSelection output;
    output.pinned = state->pinned;
    output.blockIndex = state->blockIndex;
    for (size_t index = 0; index != 10; ++index) {
      output.shards[index] = {selected->shards[index].index, std::move(selected->shards[index].result)};
    }
    output.attempted = selected->attempted;
    output.rejected = selected->rejected;
    output.quorumElapsed = selected->quorumElapsed;
    output.payloadReservation = std::move(selected->reservation);
    co_return output;
  }
  static CoTask<void> cleanup(std::shared_ptr<EcBlockReadState> state) {
    if (state) co_await state->handle.waitLocalCleanup();
  }
};
}  // namespace detail

// Preserve accounting during replacement: destroy old payloads first, then
// exchange the lease. A default memberwise assignment would free the lease
// before assigning the following payload members.
EcBlockSelection &EcBlockSelection::operator=(EcBlockSelection &&other) noexcept {
  if (this != &other) {
    shards = std::move(other.shards);
    payloadReservation = std::move(other.payloadReservation);
    pinned = std::move(other.pinned);
    blockIndex = other.blockIndex;
    attempted = other.attempted;
    rejected = other.rejected;
    quorumElapsed = other.quorumElapsed;
  }
  return *this;
}
EcBlockReadHandle::EcBlockReadHandle(std::shared_ptr<detail::EcBlockReadState> state)
    : state_(std::move(state)) {}
EcBlockReadHandle::EcBlockReadHandle(EcBlockReadHandle &&) noexcept = default;
EcBlockReadHandle &EcBlockReadHandle::operator=(EcBlockReadHandle &&other) noexcept {
  if (this != &other) {
    cancel();
    state_ = std::move(other.state_);
  }
  return *this;
}
EcBlockReadHandle::~EcBlockReadHandle() { cancel(); }
CoTryTask<EcBlockSelection> EcBlockReadHandle::takeReady() { return detail::EcBlockReadState::take(state_); }
CoTask<void> EcBlockReadHandle::waitLocalCleanup() { return detail::EcBlockReadState::cleanup(state_); }
bool EcBlockReadHandle::ready() const { return state_ && state_->handle.ready(); }
bool EcBlockReadHandle::localCleanupComplete() const { return state_ && state_->handle.localCleanupComplete(); }
void EcBlockReadHandle::cancel() {
  if (state_) state_->handle.cancel();
}
struct EcBlockRead::Impl {
  Kernel kernel;
  Impl(std::shared_ptr<EcBlockReadTransport> transport, folly::CPUThreadPoolExecutor &executor, Limits limits)
      : kernel(std::make_shared<BlockPolicy>(BlockPolicy{std::move(transport)}),
               executor,
               {limits.maxOperations, limits.maxPayloadBytes, limits.maxOperationTime}) {}
};
EcBlockRead::EcBlockRead(std::shared_ptr<EcBlockReadTransport> transport,
                         folly::CPUThreadPoolExecutor &executor,
                         Limits limits)
    : impl_(std::make_unique<Impl>(std::move(transport), executor, limits)) {}
EcBlockRead::~EcBlockRead() = default;
Result<EcBlockReadHandle> EcBlockRead::start(EcBlockReadInput input, EcStripeReadOptions options) {
  auto pinned = input.pinned;
  auto block = input.blockIndex;
  auto started = impl_->kernel.start(std::move(input), {options.deadline, options.hedgeAfter, options.order});
  if (!started) return makeError(started.error());
  try {
    return EcBlockReadHandle(std::make_shared<detail::EcBlockReadState>(std::move(*started), std::move(pinned), block));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
CoTask<void> EcBlockRead::close() { return impl_->kernel.close(); }
EcBlockRead::Snapshot EcBlockRead::snapshot() const {
  const auto value = impl_->kernel.snapshot();
  return {value.activeOperations, value.activeRequests, value.reservedPayloadBytes};
}
}  // namespace hf3fs::client::ec
