#include <algorithm>
#include <folly/CancellationToken.h>

#include "NativeEcBlockTransport.h"
#include "detail/EcStripeClientCore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::client::ec::detail {
namespace {
// A missing/offline route is a failure of this one candidate, not a change to
// its immutable physical identity and not a reason to reject the other eleven.
// Unavailable slots carry an unsent chain-version placeholder only to validate
// the complete fixed input. This adapter never dispatches those placeholders.
class RoutedReadTransport final : public EcBlockReadTransport {
 public:
  RoutedReadTransport(std::shared_ptr<storage::client::StorageClient> client,
                      std::array<std::optional<Status>, 12> failures)
      : native_(std::move(client)),
        failures_(std::move(failures)) {}
  CoTryTask<storage::EcReadBlockResultV2> read(storage::EcReadBlockV2Req request, EcReadControl control) override {
    const auto index = request.request.identity.shard;
    if (index >= failures_.size()) co_return makeError(StatusCode::kInvalidArg);
    if (failures_[index]) co_return makeError(*failures_[index]);
    co_return co_await native_.read(std::move(request), control);
  }

 private:
  NativeEcBlockTransport native_;
  std::array<std::optional<Status>, 12> failures_;
};

struct BlockWork {
  std::shared_ptr<EcStripeClientCore> core;
  std::shared_ptr<EcStripeClientReadState> session;
  EcBlockRead &reader;
  meta::EcV2PinnedRead pinned;
  std::array<storage::EcCapabilityV2, 12> grants;
  std::array<storage::VersionedChainId, 12> routes;
  std::string &logical;
  std::mutex mutex;
  std::optional<Status> error;
  BlockWork(std::shared_ptr<EcStripeClientCore> manager,
            std::shared_ptr<EcStripeClientReadState> state,
            EcBlockRead &blocks,
            meta::EcV2PinnedRead fixed,
            std::array<storage::EcCapabilityV2, 12> capabilities,
            std::array<storage::VersionedChainId, 12> versions,
            std::string &output)
      : core(std::move(manager)),
        session(std::move(state)),
        reader(blocks),
        pinned(std::move(fixed)),
        grants(std::move(capabilities)),
        routes(std::move(versions)),
        logical(output) {}
  bool failed() {
    std::lock_guard lock(mutex);
    return error.has_value();
  }
  void fail(Status value) {
    std::lock_guard lock(mutex);
    if (!error) error = std::move(value);
  }
};

CoTryTask<void> decodeBlock(std::shared_ptr<BlockWork> work, uint32_t block) {
  if (work->failed()) co_return Void{};
  CO_RETURN_ON_ERROR(work->core->active(work->session->control));
  if (work->session->stop.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
  auto input = makeEcBlockReadInput(work->pinned, work->grants, work->routes, block);
  CO_RETURN_ON_ERROR(input);
  EcStripeReadOptions options;
  options.deadline = work->session->control.deadline;
  auto handle = work->reader.start(std::move(*input), options);
  CO_RETURN_ON_ERROR(handle);
  folly::CancellationCallback cancelled(work->session->stop.getToken(), [&handle] { handle->cancel(); });
  auto selected = co_await handle->takeReady();
  CO_RETURN_ON_ERROR(selected);
  CO_RETURN_ON_ERROR(work->core->active(work->session->control));
  if (work->session->stop.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
  const uint64_t full = work->pinned.manifest.logicalLength;
  const uint32_t shardBytes = work->pinned.manifest.fragments[0].integrity.wholeLength;
  const uint32_t offset = block * storage::kEcIntegrityBlockBytes;
  const uint32_t length = work->pinned.manifest.fragments[0].integrity.blocks[block].validLength;
  uint64_t logicalBlockLength = 0;
  for (size_t index = 0; index != 10; ++index) {
    const uint64_t begin = index * uint64_t(shardBytes) + offset;
    if (begin < full) logicalBlockLength += std::min<uint64_t>(length, full - begin);
  }
  std::array<storage::EcCodecShardView, 10> views;
  for (size_t i = 0; i != 10; ++i) views[i] = {selected->shards[i].index, selected->shards[i].result.payload.data};
  auto recovered = storage::EcCodec::recover(views, logicalBlockLength, length);
  CO_RETURN_ON_ERROR(recovered);
  // Each actor writes disjoint ranges into a pre-sized logical buffer. No
  // resize, allocation or publication can occur while other actors write it.
  for (size_t index = 0; index != 10; ++index) {
    const uint64_t begin = index * uint64_t(shardBytes) + offset;
    if (begin < full) {
      const auto count = static_cast<size_t>(std::min<uint64_t>(length, full - begin));
      std::copy_n((*recovered)[index].data(), count, work->logical.data() + begin);
    }
  }
  // Local selector cleanup remains owned by EcBlockRead after this ready path.
  // Its 10+2 lease and this manager's outer lease both remain continuously held.
  co_return Void{};
}
CoTask<void> blockOwned(std::shared_ptr<BlockWork> work, uint32_t block) {
  try {
    auto result = co_await decodeBlock(work, block);
    if (!result) work->fail(result.error());
  } catch (const std::bad_alloc &) {
    work->fail(Status(StatusCode::kNotEnoughMemory));
  } catch (...) {
    work->fail(Status(StatusCode::kIOError));
  }
}

CoTryTask<EcStripeReadOutput> readReady(std::shared_ptr<EcStripeClientCore> core,
                                        std::shared_ptr<EcStripeClientReadState> state,
                                        std::unique_ptr<EcBlockRead> &reader) {
  const auto started = std::chrono::steady_clock::now();
  CO_RETURN_ON_ERROR(core->active(state->control));
  if (state->stop.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
  meta::AcquireEcReadV2Req request;
  core->request(request, state->pin.acquireRequest);
  request.object = state->pin.object;
  request.stripe = state->pin.stripe;
  request.pin = state->pin.pin;
  auto acquired = co_await core->meta->acquireEcReadV2(std::move(request));
  CO_RETURN_ON_ERROR(acquired);
  CO_RETURN_ON_ERROR(core->validOwner(acquired->snapshot.owner));
  if (acquired->manifest.object != state->pin.object || acquired->manifest.stripe != state->pin.stripe ||
      acquired->snapshot.pin != state->pin.pin || !acquired->manifest.logicalLength ||
      acquired->manifest.logicalLength > uint64_t(storage::EcCodec::kMaxShardBytes) * 10) {
    co_return makeError(StatusCode::kDataCorruption, "Acquire differs from fixed read pin or bounded stripe shape");
  }
  std::array<storage::EcCapabilityV2, 12> grants;
  std::array<storage::VersionedChainId, 12> routes;
  std::array<std::optional<Status>, 12> failures;
  for (size_t index = 0; index != 12; ++index) {
    if (!acquired->readGrants[index]) co_return makeError(StatusCode::kDataCorruption, "Acquire omitted a fixed grant");
    grants[index] = *acquired->readGrants[index];
    const auto endpoint = acquired->snapshot.endpoints[index].endpoint.controlEndpoint();
    auto current = core->route(endpoint);
    if (current)
      routes[index] = *current;
    else {
      failures[index] = current.error();
      routes[index] = {endpoint.chainId, storage::ChainVer{0}};
    }
  }
  meta::EcV2PinnedRead pinned{acquired->manifest, acquired->snapshot};
  // Validate the complete manifest and all grant bindings before allocating
  // logical output. Individual route failures are delivered only at attempts.
  CO_RETURN_ON_ERROR(makeEcBlockReadInput(pinned, grants, routes, 0));
  const auto blocks = pinned.manifest.fragments[0].integrity.blockCount;
  EcBlockRead::Limits bounds;
  bounds.maxOperations = storage::kEcIntegrityMaxBlocks;
  bounds.maxPayloadBytes =
      (2 * storage::kEcIntegrityMaxBlocks + 12 * core->limits.readBlocks) * storage::kEcIntegrityBlockBytes;
  bounds.maxOperationTime = core->limits.maxOperationTime;
  reader = std::make_unique<EcBlockRead>(std::make_shared<RoutedReadTransport>(core->storage, std::move(failures)),
                                         core->executor,
                                         bounds);
  EcStripeReadOutput output;
  output.pinned = pinned;
  output.contentSha256 = acquired->contentSha256;
  output.logicalData.resize(pinned.manifest.logicalLength);
  auto work = std::make_shared<BlockWork>(core, state, *reader, pinned, std::move(grants), routes, output.logicalData);
  std::vector<CoTask<void>> tasks;
  tasks.reserve(blocks);
  for (uint32_t block = 0; block != blocks; ++block) tasks.push_back(blockOwned(work, block));
  co_await folly::coro::collectAllWindowed(std::move(tasks), core->limits.readBlocks);
  if (work->error) co_return makeError(*work->error);
  CO_RETURN_ON_ERROR(core->active(state->control));
  if (state->stop.isCancellationRequested()) co_return makeError(StorageClientCode::kRequestCanceled);
  std::array<std::string_view, 10> data{};
  data[0] = output.logicalData;
  auto actual = meta::computeEcLogicalSha256(data, output.logicalData.size());
  CO_RETURN_ON_ERROR(actual);
  if (*actual != acquired->contentSha256)
    co_return makeError(StatusCode::kDataCorruption, "logical content SHA mismatch");
  output.readyElapsed = std::chrono::steady_clock::now() - started;
  co_return output;
}
}  // namespace

Result<EcStripeReadSession> EcStripeClientCore::startRead(EcStripePinIds pin, EcStripeControl control) {
  RETURN_ON_ERROR(validControl(control));
  RETURN_ON_ERROR(validPin(pin));
  // Peak per active block includes ten selected bytes plus Rust's twelve
  // reconstructed/twelve verification bytes (34), rounded to 36 to include
  // pending selector completions. Each earlier block can retain two late bytes.
  const size_t bytes = size_t(storage::EcCodec::kMaxShardBytes) * 10 +
                       (2 * storage::kEcIntegrityMaxBlocks + 36 * limits.readBlocks) * storage::kEcIntegrityBlockBytes;
  try {
    std::lock_guard lock(mutex);
    const auto used = budget->bytes.load();
    if (closing || activeOperations >= limits.maxOperations || bytes > limits.maxApplicationBytes ||
        used > limits.maxApplicationBytes - bytes)
      return makeError(StorageClientCode::kResourceBusy);
    auto state = std::make_shared<EcStripeClientReadState>();
    state->pin = std::move(pin);
    state->control = control;
    state->reservation = std::make_shared<EcReadReservation>(budget, bytes);
    ++activeOperations;
    try {
      tasks.add(readOwned(shared_from_this(), state).scheduleOn(executorLease));
    } catch (...) {
      --activeOperations;
      throw;
    }
    return EcStripeReadSession(std::move(state));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
CoTask<void> EcStripeClientCore::readOwned(std::shared_ptr<EcStripeClientCore> core,
                                           std::shared_ptr<EcStripeClientReadState> state) {
  std::unique_ptr<EcBlockRead> reader;
  folly::CancellationCallback managerStop(core->stop.getToken(), [state] { state->stop.requestCancellation(); });
  folly::CancellationCallback callerStop(state->control.cancellation, [state] { state->stop.requestCancellation(); });
  std::optional<Result<EcStripeReadOutput>> ready;
  try {
    ready.emplace(co_await folly::coro::co_withCancellation(CancellationToken{}, readReady(core, state, reader)));
    if (*ready) (*ready)->reservation_ = state->reservation->split((*ready)->logicalData.capacity());
  } catch (const std::bad_alloc &) {
    ready.emplace(makeError(StatusCode::kNotEnoughMemory));
  } catch (...) {
    ready.emplace(makeError(StatusCode::kIOError));
  }
  {
    std::lock_guard lock(state->mutex);
    state->result.emplace(std::move(*ready));
  }
  state->ready.post();
  if (reader) co_await folly::coro::co_withCancellation(CancellationToken{}, reader->close());
  reader.reset();
  // Decoders are joined and every late request has released its payload before
  // the remaining reservation is released. Ready output retains its own lease.
  state->reservation.reset();
  {
    std::lock_guard lock(core->mutex);
    --core->activeOperations;
  }
  state->cleaned.post();
}
}  // namespace hf3fs::client::ec::detail
