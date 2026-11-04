#include "EcStripeRead.h"

#include "detail/EcQuorumRead.h"

namespace hf3fs::client::ec {
namespace {
Result<Void> validateInput(const EcStripeReadInput &input) {
  const auto &manifest = input.manifest;
  if (manifest.version != meta::kEcCatalogVersion || manifest.object.incarnation.is_nil() || manifest.generation == 0 ||
      manifest.revision == 0) {
    return makeError(StatusCode::kInvalidArg, "EC selector requires a fixed manifest");
  }
  const auto length = manifest.fragments[0].integrity.wholeLength;
  if (length == 0 || length > storage::kEcFragmentRpcMaxBytes || manifest.logicalLength > uint64_t(length) * 10) {
    return makeError(StatusCode::kInvalidArg, "invalid EC stripe extent");
  }
  for (size_t index = 0; index != 12; ++index) {
    const auto &fragment = manifest.fragments[index];
    const auto &request = input.requests[index].request;
    RETURN_ON_ERROR(request.validate());
    RETURN_ON_ERROR(storage::validateEcIntegrity(fragment.identity, fragment.integrity));
    if (fragment.identity.object != manifest.object.incarnation || fragment.identity.stripe != manifest.stripe ||
        fragment.identity.generation != manifest.generation || fragment.identity.shard != index ||
        fragment.integrity.wholeLength != length || !serde::equals(request.identity, fragment.identity) ||
        request.operationId != fragment.operation || request.vChainId.chainId != fragment.placement.chain ||
        request.targetId != fragment.placement.target || request.expectedLength != length ||
        ~request.checksum.value != fragment.integrity.wholeCrc32c) {
      return makeError(StatusCode::kInvalidArg, "EC read candidate differs from pinned manifest");
    }
  }
  return Void{};
}

Result<Void> validateResponse(const EcStripeReadInput &input, uint16_t index, const storage::EcReadResult &result) {
  const auto &request = input.requests[index].request;
  const auto &receipt = result.receipt;
  if (receipt.version != storage::kEcFragmentProtocolVersion || !serde::equals(receipt.identity, request.identity) ||
      receipt.operationId != request.operationId || receipt.vChainId != request.vChainId ||
      receipt.targetId != request.targetId || receipt.length != request.expectedLength ||
      receipt.checksum != request.checksum || result.payload.data.size() != request.expectedLength) {
    return makeError(StorageClientCode::kProtocolMismatch, "EC read response differs from pinned request");
  }
  auto actual = storage::computeEcIntegrity(request.identity, result.payload.data);
  RETURN_ON_ERROR(actual);
  if (*actual != input.manifest.fragments[index].integrity) {
    return makeError(StorageClientCode::kChecksumMismatch, "EC read differs from authoritative integrity descriptor");
  }
  return Void{};
}

struct LegacyPolicy {
  using Input = EcStripeReadInput;
  using Response = storage::EcReadResult;
  static constexpr bool splitOutputReservation = false;
  std::shared_ptr<EcReadTransport> transport;
  bool available() const { return bool(transport); }
  Result<Void> validateInput(const Input &input) const { return ec::validateInput(input); }
  size_t payloadLength(const Input &input) const { return input.manifest.fragments[0].integrity.wholeLength; }
  CoTryTask<Response> read(const Input &input,
                           uint16_t index,
                           std::chrono::steady_clock::time_point deadline,
                           CancellationToken cancellation) const {
    return transport->read(input.requests[index], {deadline, cancellation});
  }
  Result<Void> validateResponse(const Input &input, uint16_t index, const Response &response) const {
    return ec::validateResponse(input, index, response);
  }
  void clearInput(Input &input) const { input.requests = {}; }
};
using Kernel = detail::EcQuorumRead<LegacyPolicy>;
}  // namespace

namespace detail {
struct EcReadState {
  Kernel::Handle handle;
  meta::EcManifest manifest;
  EcReadState(Kernel::Handle value, meta::EcManifest pinned)
      : handle(std::move(value)),
        manifest(std::move(pinned)) {}
  static CoTryTask<EcStripeSelection> take(std::shared_ptr<EcReadState> state) {
    if (!state) co_return makeError(StatusCode::kInvalidArg, "empty EC read handle");
    auto selected = co_await state->handle.takeReady();
    if (!selected) co_return makeError(selected.error());
    EcStripeSelection output;
    output.manifest = state->manifest;
    for (size_t index = 0; index != 10; ++index) {
      output.shards[index] = {selected->shards[index].index, std::move(selected->shards[index].result)};
    }
    output.attempted = selected->attempted;
    output.rejected = selected->rejected;
    output.quorumElapsed = selected->quorumElapsed;
    output.payloadReservation = std::move(selected->reservation);
    co_return output;
  }
  static CoTask<void> cleanup(std::shared_ptr<EcReadState> state) {
    if (state) co_await state->handle.waitLocalCleanup();
  }
};
}  // namespace detail

struct EcStripeRead::Impl {
  Kernel kernel;
  Impl(std::shared_ptr<EcReadTransport> reader, folly::CPUThreadPoolExecutor &pool, Limits limits)
      : kernel(std::make_shared<LegacyPolicy>(LegacyPolicy{std::move(reader)}),
               pool,
               {limits.maxOperations, limits.maxPayloadBytes, limits.maxOperationTime}) {}
};

EcStripeReadHandle::EcStripeReadHandle(std::shared_ptr<detail::EcReadState> state)
    : state_(std::move(state)) {}
EcStripeReadHandle::EcStripeReadHandle(EcStripeReadHandle &&) noexcept = default;
EcStripeReadHandle &EcStripeReadHandle::operator=(EcStripeReadHandle &&other) noexcept {
  if (this != &other) {
    cancel();
    state_ = std::move(other.state_);
  }
  return *this;
}
EcStripeReadHandle::~EcStripeReadHandle() { cancel(); }
CoTryTask<EcStripeSelection> EcStripeReadHandle::takeReady() { return detail::EcReadState::take(state_); }
CoTask<void> EcStripeReadHandle::waitLocalCleanup() { return detail::EcReadState::cleanup(state_); }
bool EcStripeReadHandle::ready() const { return state_ && state_->handle.ready(); }
bool EcStripeReadHandle::localCleanupComplete() const { return state_ && state_->handle.localCleanupComplete(); }
void EcStripeReadHandle::cancel() {
  if (state_) state_->handle.cancel();
}

EcStripeRead::EcStripeRead(std::shared_ptr<EcReadTransport> transport,
                           folly::CPUThreadPoolExecutor &executor,
                           Limits limits)
    : impl_(std::make_unique<Impl>(std::move(transport), executor, limits)) {}
EcStripeRead::~EcStripeRead() = default;
Result<EcStripeReadHandle> EcStripeRead::start(EcStripeReadInput input, EcStripeReadOptions options) {
  auto manifest = input.manifest;
  auto started = impl_->kernel.start(std::move(input), {options.deadline, options.hedgeAfter, options.order});
  if (!started) return makeError(started.error());
  try {
    return EcStripeReadHandle(std::make_shared<detail::EcReadState>(std::move(*started), std::move(manifest)));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
CoTask<void> EcStripeRead::close() { return impl_->kernel.close(); }
EcStripeRead::Snapshot EcStripeRead::snapshot() const {
  const auto value = impl_->kernel.snapshot();
  return {value.activeOperations, value.activeRequests, value.reservedPayloadBytes};
}
}  // namespace hf3fs::client::ec
