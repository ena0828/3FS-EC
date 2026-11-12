#include "EcStripeClient.h"

#include "detail/EcStripeClientCore.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::client::ec {
namespace {
EcStripeMutationOutcome failed(const meta::EcObjectRef &object, const Uuid &operation, Status error) {
  EcStripeMutationOutcome result;
  result.object = object;
  result.operation = operation;
  result.failure = std::move(error);
  return result;
}
EcStripeMutationOutcome indeterminate(const meta::EcObjectRef &object, const Uuid &operation, Status error) {
  auto result = failed(object, operation, std::move(error));
  result.phase = EcStripePhase::Indeterminate;
  return result;
}
CoTask<void> cleanup(std::shared_ptr<detail::EcStripeClientReadState> state) {
  if (state) co_await state->cleaned;
}
CoTryTask<EcStripeReadOutput> takeRead(std::shared_ptr<detail::EcStripeClientReadState> state) {
  if (!state) co_return makeError(StatusCode::kInvalidArg, "empty stripe read session");
  co_await state->ready;
  std::lock_guard lock(state->mutex);
  if (state->taken) co_return makeError(StatusCode::kInvalidArg, "stripe read result already taken");
  state->taken = true;
  co_return std::move(*state->result);
}
CoTryTask<meta::ReleaseEcReadV2Rsp> releaseAfterCleanup(std::shared_ptr<detail::EcStripeClientCore> core,
                                                        std::shared_ptr<detail::EcStripeClientReadState> state,
                                                        EcStripeControl control) {
  if (!state) co_return makeError(StatusCode::kInvalidArg, "empty stripe read session");
  if (state->externalRange) co_return makeError(StatusCode::kInvalidArg, "tree range release requires Meta55");
  co_await state->cleaned;
  co_return co_await core->releaseOwned(state->pin, control);
}
}  // namespace

EcStripeReadOutput &EcStripeReadOutput::operator=(EcStripeReadOutput &&other) noexcept {
  if (this != &other) {
    logicalData = std::move(other.logicalData);
    reservation_ = std::move(other.reservation_);
    pinned = std::move(other.pinned);
    contentSha256 = other.contentSha256;
    readyElapsed = other.readyElapsed;
  }
  return *this;
}
EcStripeReadSession::EcStripeReadSession(std::shared_ptr<detail::EcStripeClientReadState> state)
    : state_(std::move(state)) {}
EcStripeReadSession::EcStripeReadSession(EcStripeReadSession &&) noexcept = default;
EcStripeReadSession &EcStripeReadSession::operator=(EcStripeReadSession &&other) noexcept {
  if (this != &other) {
    cancel();
    state_ = std::move(other.state_);
  }
  return *this;
}
EcStripeReadSession::~EcStripeReadSession() { cancel(); }
CoTryTask<EcStripeReadOutput> EcStripeReadSession::takeReady() { return takeRead(state_); }
CoTask<void> EcStripeReadSession::waitLocalCleanup() { return cleanup(state_); }
bool EcStripeReadSession::ready() const { return state_ && state_->ready.ready(); }
bool EcStripeReadSession::localCleanupComplete() const { return state_ && state_->cleaned.ready(); }
const EcStripePinIds &EcStripeReadSession::pin() const {
  XCHECK(state_);
  return state_->pin;
}
void EcStripeReadSession::cancel() {
  if (state_) state_->stop.requestCancellation();
}

EcStripeClient::EcStripeClient(std::shared_ptr<detail::EcStripeClientCore> core)
    : core_(std::move(core)) {}
EcStripeClient::~EcStripeClient() = default;
CoTryTask<std::shared_ptr<EcStripeClient>> EcStripeClient::connect(
    std::shared_ptr<meta::client::MetaClient> meta,
    std::shared_ptr<storage::client::StorageClient> storage,
    std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd,
    flat::UserInfo credentials,
    Uuid expectedClientNamespace,
    folly::CPUThreadPoolExecutor &executor,
    Limits limits) {
  if (!meta || !storage || !mgmtd || expectedClientNamespace.is_nil() ||
      meta->clientId().uuid != expectedClientNamespace || !limits.maxOperations || !limits.maxApplicationBytes ||
      !limits.writeFragments || limits.writeFragments > 4 || !limits.readBlocks || limits.readBlocks > 4 ||
      !limits.recoveryAttempts || limits.recoveryAttempts > 8 ||
      limits.maxOperationTime <= std::chrono::seconds::zero() || limits.maxOperationTime > std::chrono::hours(1)) {
    co_return makeError(StatusCode::kInvalidArg, "invalid stripe manager limits or persistent Meta client namespace");
  }
  // Authentication is performed by Meta; a caller-provided UID is not proof.
  auto authenticated = co_await meta->authenticate(credentials);
  CO_RETURN_ON_ERROR(authenticated);
  auto token = std::move(credentials.token);
  credentials = std::move(*authenticated);
  credentials.token = std::move(token);
  try {
    auto core = std::make_shared<detail::EcStripeClientCore>(std::move(meta),
                                                             std::move(storage),
                                                             std::move(mgmtd),
                                                             std::move(credentials),
                                                             expectedClientNamespace,
                                                             executor,
                                                             limits);
    co_return std::shared_ptr<EcStripeClient>(new EcStripeClient(std::move(core)));
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  }
}
CoTryTask<meta::CreateEcFileRsp> EcStripeClient::createFile(meta::CreateEcFileV2Req request, EcStripeControl control) {
  // The connected manager owns the namespace. Validate the caller's fixed
  // request UUID after installing it, as createOwned does before sending RPCs.
  request.client = ClientId{core_->owner.client};
  if (!request.path.path || request.path.path->native().size() > 4096 || !request.valid()) {
    return detail::EcStripeClientCore::immediate(Result<meta::CreateEcFileRsp>(
        makeError(StatusCode::kInvalidArg, "Create requires a persisted UUID and a valid path of at most 4096 bytes")));
  }
  const auto pathBytes = request.path.path->native().capacity();
  auto call = core_->launch<Result<meta::CreateEcFileRsp>>(
      pathBytes,
      [core = core_, request = std::move(request), control](const auto &) mutable {
        return core->createOwned(std::move(request), control);
      },
      [](Status error) -> Result<meta::CreateEcFileRsp> { return makeError(std::move(error)); });
  if (!call) return detail::EcStripeClientCore::immediate(Result<meta::CreateEcFileRsp>(makeError(call.error())));
  return detail::EcStripeClientCore::take(std::move(*call));
}
CoTask<EcStripeMutationOutcome> EcStripeClient::write(EcStripeWrite request, EcStripeControl control) {
  const auto object = request.object.object;
  const auto operation = request.ids.operation;
  const auto shard = request.object.shardBytes;
  if (!shard || shard > storage::EcCodec::kMaxShardBytes || request.logicalData.empty() ||
      request.logicalData.size() > size_t(shard) * 10) {
    return detail::EcStripeClientCore::immediate(failed(object, operation, Status(StatusCode::kInvalidArg)));
  }
  // Input and all twelve encoded shards coexist. The window charge covers
  // owned append buffers; transport/Serde allocations are separately bounded.
  // The CXX bridge temporarily holds both Rust and C++ codewords (24*S).
  const size_t bytes = request.logicalData.capacity() + size_t(shard) * 24 +
                       size_t(core_->limits.writeFragments) * 2 * storage::kEcIntegrityBlockBytes;
  auto call = core_->launch<EcStripeMutationOutcome>(
      bytes,
      [core = core_, request = std::move(request), control](const auto &) mutable {
        return core->writeOwned(std::move(request), control);
      },
      [object, operation](Status error) { return indeterminate(object, operation, std::move(error)); });
  if (!call) return detail::EcStripeClientCore::immediate(failed(object, operation, call.error()));
  return detail::EcStripeClientCore::take(std::move(*call));
}
CoTask<EcStripeMutationOutcome> EcStripeClient::repair(EcStripeRepair request, EcStripeControl control) {
  const auto object = request.object.object;
  const auto operation = request.ids.operation;
  const auto shard = request.object.shardBytes;
  if (!shard || shard > storage::EcCodec::kMaxShardBytes || !request.blockWindow || request.blockWindow > 4) {
    return detail::EcStripeClientCore::immediate(failed(object, operation, Status(StatusCode::kInvalidArg)));
  }
  // Central mode can retain ten complete sources and twelve recovered shards.
  // All modes reserve the same conservative upper bound for fair admission;
  // this is not an observed pipeline RSS measurement.
  const size_t bytes = size_t(shard) * 34 + size_t(request.blockWindow) * 24 * storage::kEcIntegrityBlockBytes;
  auto call = core_->launch<EcStripeMutationOutcome>(
      bytes,
      [core = core_, request = std::move(request), control](const auto &) mutable {
        return core->repairOwned(std::move(request), control);
      },
      [object, operation](Status error) { return indeterminate(object, operation, std::move(error)); });
  if (!call) return detail::EcStripeClientCore::immediate(failed(object, operation, call.error()));
  return detail::EcStripeClientCore::take(std::move(*call));
}
Result<EcStripeReadSession> EcStripeClient::startRead(EcStripePinIds request, EcStripeControl control) {
  return core_->startRead(std::move(request), control);
}
Result<EcStripeReadSession> EcStripeClient::startPinnedRead(EcStripePinIds request,
                                                            meta::AcquireEcReadV2Rsp read,
                                                            EcStripeControl control) {
  return core_->startRead(std::move(request), control, std::move(read));
}
CoTryTask<meta::ReleaseEcReadV2Rsp> EcStripeClient::release(EcStripeReadSession &session, EcStripeControl control) {
  auto state = session.state_;
  auto call = core_->launch<Result<meta::ReleaseEcReadV2Rsp>>(
      0,
      [core = core_, state = std::move(state), control](const auto &) {
        return releaseAfterCleanup(core, state, control);
      },
      [](Status error) -> Result<meta::ReleaseEcReadV2Rsp> { return makeError(std::move(error)); });
  if (!call) return detail::EcStripeClientCore::immediate(Result<meta::ReleaseEcReadV2Rsp>(makeError(call.error())));
  return detail::EcStripeClientCore::take(std::move(*call));
}
CoTryTask<meta::ReleaseEcReadV2Rsp> EcStripeClient::release(EcStripePinIds request, EcStripeControl control) {
  auto call = core_->launch<Result<meta::ReleaseEcReadV2Rsp>>(
      0,
      [core = core_, request = std::move(request), control](const auto &) mutable {
        return core->releaseOwned(std::move(request), control);
      },
      [](Status error) -> Result<meta::ReleaseEcReadV2Rsp> { return makeError(std::move(error)); });
  if (!call) return detail::EcStripeClientCore::immediate(Result<meta::ReleaseEcReadV2Rsp>(makeError(call.error())));
  return detail::EcStripeClientCore::take(std::move(*call));
}
const meta::EcOwner &EcStripeClient::owner() const { return core_->owner; }
EcStripeClient::Snapshot EcStripeClient::snapshot() const {
  std::lock_guard lock(core_->mutex);
  return {core_->activeOperations, core_->budget->bytes.load()};
}
CoTask<void> EcStripeClient::close() { return detail::EcStripeClientCore::close(core_); }
}  // namespace hf3fs::client::ec
