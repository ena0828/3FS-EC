#include "EcRepairPipeline.h"

#include <folly/experimental/coro/Baton.h>
#include <folly/experimental/coro/Collect.h>
#include <mutex>
#include <optional>

namespace hf3fs::client::ec {
namespace {
using namespace hf3fs::storage;
using Clock = std::chrono::steady_clock;

Result<Void> active(const EcRepairControl &control) {
  if (control.cancellation.isCancellationRequested()) {
    return makeError(StorageClientCode::kRequestCanceled, "EC repair cancellation requested");
  }
  if (Clock::now() >= control.deadline) return makeError(StorageClientCode::kTimeout, "EC repair deadline reached");
  return Void{};
}

Status unknownMutationException(const Status &cause) noexcept {
  try {
    return Status(StorageCode::kEcSealOutcomeUnknown,
                  fmt::format("repair mutation raised before its outcome was confirmed; retain the fixed allocation. "
                              "Cause: {}",
                              cause),
                  cause);
  } catch (...) {
    // Reporting an allocation failure must not allocate again or lose the
    // unknown-outcome classification. The ordinary path retains its cause.
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}
Status unknownMutationException(status_code_t code, std::string_view message) noexcept {
  try {
    return unknownMutationException(Status(code, message));
  } catch (...) {
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}

template <typename T, typename MakeTask>
CoTryTask<T> mutationCall(MakeTask makeTask) {
  try {
    // Invoke inside the try as well as awaiting: an implementation may throw
    // either when creating its task or after dispatching the actual mutation.
    co_return co_await makeTask();
  } catch (const StatusException &error) {
    co_return makeError(unknownMutationException(error.get()));
  } catch (const std::bad_alloc &) {
    co_return makeError(unknownMutationException(StatusCode::kNotEnoughMemory, "std::bad_alloc"));
  } catch (const OperationCancelled &) {
    co_return makeError(unknownMutationException(StorageClientCode::kRequestCanceled, "mutation coroutine cancelled"));
  } catch (const std::exception &error) {
    co_return makeError(unknownMutationException(StatusCode::kIOError, error.what()));
  } catch (...) {
    co_return makeError(unknownMutationException(StatusCode::kIOError, "non-standard mutation exception"));
  }
}

struct Window {
  std::shared_ptr<const EcRepairPlan> plan;
  std::shared_ptr<EcRepairTransport> transport;
  EcRepairMode mode;
  EcRepairDelivery delivery;
  EcRepairControl control;
  EcRepairObservation *observation = nullptr;
  std::mutex mutex;
  std::optional<Status> error;
  std::array<folly::coro::Baton, kEcIntegrityMaxBlocks + 1> writeTurn;

  bool stopped() {
    std::lock_guard lock(mutex);
    return error.has_value();
  }
  void fail(Status status) {
    {
      std::lock_guard lock(mutex);
      // A later completed write can have an unknown durable outcome even if
      // another block already failed. Preserve that reconciliation requirement.
      if (!error || (status.code() == StorageCode::kEcSealOutcomeUnknown &&
                     error->code() != StorageCode::kEcSealOutcomeUnknown)) {
        error = std::move(status);
      }
    }
    // Wake every potential waiter. They check failure before starting writes;
    // jobs already inside a transport operation are still awaited to completion.
    for (auto &turn : writeTurn) turn.post();
  }
};

CoTryTask<void> appendBlock(std::shared_ptr<Window> state, EcRepairBlock block) {
  CO_RETURN_ON_ERROR(EcRepairBlockCore::validateComplete(*state->plan, block));
  {
    EcRepairObservation::Scope waiting(state->observation, EcRepairPoint::OrderedAppendWait);
    co_await state->writeTurn[block.blockIndex];
    waiting.success();
  }
  if (state->stopped())
    co_return makeError(StorageClientCode::kRequestCanceled, "EC repair stopped before ordered append");
  CO_RETURN_ON_ERROR(active(state->control));
  for (uint8_t target = 0; target != block.targetCount; ++target) {
    CO_RETURN_ON_ERROR(active(state->control));
    auto appended = co_await mutationCall<void>([&] {
      return state->transport->append(state->plan,
                                      target,
                                      block.blockIndex,
                                      std::move(block.outputs[target]),
                                      state->control);
    });
    if (!appended) co_return makeError(std::move(appended.error()));
  }
  state->writeTurn[block.blockIndex + 1].post();
  co_return Void{};
}

CoTryTask<void> oneBlock(std::shared_ptr<Window> state, uint32_t blockIndex) {
  if (state->stopped()) co_return Void{};
  CO_RETURN_ON_ERROR(active(state->control));
  EcRepairObservation::Scope actor(state->observation, EcRepairPoint::BlockActor);
  if (state->delivery == EcRepairDelivery::HelperDirect) {
    // Target persistent prefixes and Engine::append arbitrate block order.
    // Holding the client writeTurn here would serialize the whole helper chain.
    auto completed = co_await mutationCall<void>([&] {
      return state->transport->helperDirectBlock(state->plan, blockIndex, state->control);
    });
    if (completed) actor.success();
    co_return completed;
  }
  auto block = EcRepairBlockCore::begin(*state->plan, blockIndex);
  CO_RETURN_ON_ERROR(block);
  if (state->mode == EcRepairMode::HelperChain) {
    block = co_await state->transport->helperBlock(state->plan, blockIndex, state->control);
    CO_RETURN_ON_ERROR(block);
    if (block->blockIndex != blockIndex)
      co_return makeError(StatusCode::kDataCorruption, "helper returned another block");
  } else {
    // One block actor retains only one source block and its target accumulator.
    // Different actors overlap read, contribution calculation and ordered write.
    for (uint8_t source = 0; source != 10; ++source) {
      if (state->stopped()) co_return Void{};
      CO_RETURN_ON_ERROR(active(state->control));
      auto bytes = co_await state->transport->read(state->plan, source, blockIndex, state->control);
      CO_RETURN_ON_ERROR(bytes);
      {
        // Includes integrity/plan validation and contribution accumulation;
        // this local wall span is not a pure GF arithmetic CPU measurement.
        EcRepairObservation::Scope compute(state->observation, EcRepairPoint::ClientBlockAdvance);
        block = EcRepairBlockCore::advance(*state->plan, source, std::move(*block), *bytes);
        if (block) compute.success();
      }
      CO_RETURN_ON_ERROR(block);
    }
  }
  CO_RETURN_ON_ERROR(active(state->control));
  auto appended = co_await appendBlock(state, std::move(*block));
  if (appended) actor.success();
  co_return appended;
}

CoTask<void> ownedBlock(std::shared_ptr<Window> state, uint32_t index) {
  try {
    auto result = co_await oneBlock(state, index);
    if (!result) state->fail(std::move(result.error()));
  } catch (const std::bad_alloc &) {
    state->fail(Status(StatusCode::kNotEnoughMemory));
  } catch (const std::exception &) {
    state->fail(Status(StatusCode::kIOError, "EC repair child raised an exception"));
  } catch (...) {
    state->fail(Status(StatusCode::kIOError, "EC repair child raised an unknown exception"));
  }
}

CoTryTask<void> central(std::shared_ptr<Window> state) {
  std::array<std::string, 10> data;
  std::array<EcCodecShardView, 10> views;
  for (uint8_t source = 0; source != 10; ++source) {
    data[source].reserve(state->plan->shardBytes());
    const auto &fragment = state->plan->input().sources[source];
    for (uint32_t block = 0; block != state->plan->blockCount(); ++block) {
      CO_RETURN_ON_ERROR(active(state->control));
      auto bytes = co_await state->transport->read(state->plan, source, block, state->control);
      CO_RETURN_ON_ERROR(bytes);
      CO_RETURN_ON_ERROR(verifyEcIntegrityBlock(fragment.identity, fragment.integrity, block, *bytes));
      data[source].append(*bytes);
    }
    views[source] = {fragment.identity.shard, data[source]};
  }
  CO_RETURN_ON_ERROR(active(state->control));
  auto recovered = [&] {
    EcRepairObservation::Scope compute(state->observation, EcRepairPoint::CentralCodecRecover);
    auto value = EcCodec::recover(views, state->plan->input().logicalLength, state->plan->shardBytes());
    if (value) compute.success();
    return value;
  }();
  CO_RETURN_ON_ERROR(recovered);
  for (uint32_t index = 0; index != state->plan->blockCount(); ++index) {
    CO_RETURN_ON_ERROR(active(state->control));
    auto block = EcRepairBlockCore::begin(*state->plan, index);
    CO_RETURN_ON_ERROR(block);
    block->nextHelper = 10;
    block->contributorMask = 1023;
    for (size_t target = 0; target != block->targetCount; ++target) {
      const auto shard = state->plan->targets()[target];
      const auto length = block->outputs[target].size();
      block->outputs[target].assign((*recovered)[shard], size_t(index) * kEcIntegrityBlockBytes, length);
    }
    auto appended = co_await appendBlock(state, std::move(*block));
    if (!appended) co_return makeError(std::move(appended.error()));
  }
  co_return Void{};
}

CoTryTask<EcRepairSealed> runOwned(std::shared_ptr<const EcRepairPlan> plan,
                                   std::shared_ptr<EcRepairTransport> transport,
                                   EcRepairMode mode,
                                   EcRepairControl control,
                                   EcRepairObservation *observation,
                                   EcRepairDelivery delivery) {
  try {
    if (!plan || !transport ||
        (mode != EcRepairMode::CentralSerial && mode != EcRepairMode::ClientPipeline &&
         mode != EcRepairMode::HelperChain) ||
        (delivery != EcRepairDelivery::ClientAppend && delivery != EcRepairDelivery::HelperDirect) ||
        (delivery == EcRepairDelivery::HelperDirect && mode != EcRepairMode::HelperChain)) {
      co_return makeError(StatusCode::kInvalidArg, "EC repair requires a plan, transport and explicit strategy");
    }
    CO_RETURN_ON_ERROR(active(control));
    if (mode == EcRepairMode::HelperChain && !transport->supportsHelperChain()) {
      co_return makeError(StatusCode::kNotImplemented, "transport has no authenticated native helper chain");
    }
    if (delivery == EcRepairDelivery::HelperDirect && !transport->supportsHelperDirect()) {
      co_return makeError(StatusCode::kNotImplemented, "transport has no authorized native helper direct delivery");
    }
    auto state = std::make_shared<Window>();
    state->plan = std::move(plan);
    state->transport = std::move(transport);
    state->mode = mode;
    state->delivery = delivery;
    state->control = control;
    state->observation = observation;
    state->writeTurn[0].post();
    for (uint8_t target = 0; target != state->plan->input().targetCount; ++target) {
      CO_RETURN_ON_ERROR(active(control));
      auto begun = co_await mutationCall<void>([&] { return state->transport->begin(state->plan, target, control); });
      if (!begun) co_return makeError(std::move(begun.error()));
    }
    if (mode == EcRepairMode::CentralSerial) {
      auto completed = co_await central(state);
      if (!completed) co_return makeError(std::move(completed.error()));
    } else {
      std::vector<CoTask<void>> tasks;
      tasks.reserve(state->plan->blockCount());
      for (uint32_t block = 0; block != state->plan->blockCount(); ++block) tasks.push_back(ownedBlock(state, block));
      // collectAllWindowed joins all started children; no task returns early on
      // another task's failure. Payload allocation happens only inside its slot.
      co_await folly::coro::collectAllWindowed(std::move(tasks), state->plan->input().maxBlocksInFlight);
      if (state->error) co_return makeError(std::move(*state->error));
    }
    EcRepairSealed result;
    result.mode = mode;
    result.delivery = delivery;
    result.planDigest = state->plan->digest();
    result.targetCount = state->plan->input().targetCount;
    result.blocks = state->plan->blockCount();
    for (uint8_t target = 0; target != result.targetCount; ++target) {
      CO_RETURN_ON_ERROR(active(control));
      auto receipt = co_await mutationCall<EcFragmentReceiptV2>(
          [&] { return state->transport->seal(state->plan, target, control); });
      if (!receipt) co_return makeError(std::move(receipt.error()));
      const auto &expected = state->plan->input().targets[target];
      if (receipt->version != kEcGrantVersionV2 || !serde::equals(receipt->identity, expected.identity) ||
          receipt->operationId != expected.operationId || receipt->engineUuid != expected.endpoint.engineUuid ||
          receipt->targetIncarnation != expected.endpoint.targetIncarnation ||
          receipt->vChainId.chainId != expected.endpoint.chainId || receipt->targetId != expected.endpoint.targetId ||
          receipt->length != expected.integrity.wholeLength || receipt->crc32c != expected.integrity.wholeCrc32c ||
          receipt->integrityRoot != expected.integrity.root) {
        co_return makeError(StatusCode::kDataCorruption, "repair seal receipt differs from fixed replacement");
      }
      result.receipts[target] = std::move(*receipt);
    }
    CO_RETURN_ON_ERROR(active(control));
    co_return result;
  } catch (const std::bad_alloc &) {
    co_return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    co_return makeError(StatusCode::kIOError, "EC repair raised an exception; retain stages for reconciliation");
  } catch (...) {
    co_return makeError(StatusCode::kIOError, "EC repair raised an unknown exception; retain stages");
  }
}

}  // namespace

CoTryTask<EcRepairSealed> EcRepairPipeline::run(std::shared_ptr<const storage::EcRepairPlan> plan,
                                                std::shared_ptr<EcRepairTransport> transport,
                                                EcRepairMode mode,
                                                EcRepairControl control,
                                                folly::CPUThreadPoolExecutor &executor,
                                                EcRepairObservation *observation,
                                                EcRepairDelivery delivery) {
  // Ignore ambient cancellation only for ownership/join. The explicit token
  // and absolute deadline are checked before every new transport operation.
  co_return co_await folly::coro::co_withCancellation(
      CancellationToken{},
      runOwned(std::move(plan), std::move(transport), mode, control, observation, delivery).scheduleOn(&executor));
}

}  // namespace hf3fs::client::ec
