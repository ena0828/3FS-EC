#include "EcRmwExecution.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::storage {
namespace {
Status mutationException(status_code_t cause) noexcept {
  try {
    return Status(StorageCode::kEcSealOutcomeUnknown,
                  "RMW stage outcome requires same-plan reconciliation",
                  Status(cause));
  } catch (...) {
    return Status(StorageCode::kEcSealOutcomeUnknown);
  }
}
Result<Void> receipt(const EcRmwPlan &plan,
                     size_t index,
                     const EcIntegrityDescriptor &descriptor,
                     const EcFragmentReceiptV2 &r) {
  const auto &p = plan.input();
  const auto &target = p.targets[index];
  if (r.version != kEcGrantVersionV2 || !serde::equals(r.identity, target.identity) || r.operationId != p.operationId ||
      r.engineUuid != target.endpoint.engineUuid || r.targetIncarnation != target.endpoint.targetIncarnation ||
      r.targetId != target.endpoint.targetId || r.vChainId.chainId != target.endpoint.chainId ||
      r.length != p.shardBytes || r.crc32c != descriptor.wholeCrc32c || r.integrityRoot != descriptor.root)
    return makeError(StatusCode::kDataCorruption, "RMW seal receipt differs from exact output");
  return Void{};
}
}  // namespace
CoTryTask<EcRmwSealedCandidate> EcRmwExecution::run(VerifiedEcRmwPlan authority,
                                                    std::string patch,
                                                    std::shared_ptr<EcRmwIo> io) {
  bool mutationCallEntered = false;
  try {
    if (authority.right() != EcRmwRight::Execute || !io) co_return makeError(StatusCode::kAuthenticationFail);
    const auto plan = authority.plan();
    const auto &p = plan->input();
    CO_RETURN_ON_ERROR(io->check());
    if (p.action == EcRmwAction::Repair)
      co_return makeError(StatusCode::kNotImplemented, "repair must execute its explicit repair strategy");
    if (patch.size() != p.patchLength) co_return makeError(StatusCode::kInvalidArg);
    auto patchHash = ec_rmw_detail::sha256(patch);
    CO_RETURN_ON_ERROR(patchHash);
    if (*patchHash != p.patchSha256) co_return makeError(StatusCode::kDataCorruption, "RMW input commitment differs");
    std::string logical(p.targetLogicalLength, '\0');
    if (p.sourceKind == EcRmwSourceKind::Data) {
      std::array<std::string, 10> bytes;
      std::vector<EcCodecShardView> selected;
      selected.reserve(10);
      Status lastError(StatusCode::kIOError);
      for (uint8_t source = 0; source < 12 && selected.size() < 10; ++source) {
        CO_RETURN_ON_ERROR(io->check());
        auto read = co_await io->readSource(source);
        if (!read) {
          lastError = std::move(read.error());
          continue;
        }
        const auto &expected = p.sources[source];
        auto actual = computeEcIntegrity(expected.identity, *read);
        if (!actual || *actual != expected.integrity) {
          lastError = Status(StatusCode::kDataCorruption);
          continue;
        }
        const size_t position = selected.size();
        bytes[position] = std::move(*read);
        selected.push_back({source, bytes[position]});
      }
      if (selected.size() != 10) co_return makeError(std::move(lastError));
      CO_RETURN_ON_ERROR(io->check());
      auto recovered = EcCodec::recover(selected, p.sourceLogicalLength, p.shardBytes);
      CO_RETURN_ON_ERROR(recovered);
      std::string original(p.sourceLogicalLength, '\0');
      size_t copied = 0;
      for (size_t i = 0; i < 10 && copied < p.sourceLogicalLength; ++i) {
        const size_t length = std::min<size_t>(p.shardBytes, p.sourceLogicalLength - copied);
        std::memcpy(original.data() + copied, (*recovered)[i].data(), length);
        copied += length;
      }
      auto oldHash = ec_rmw_detail::sha256(original);
      CO_RETURN_ON_ERROR(oldHash);
      if (*oldHash != p.sourceLogicalSha256)
        co_return makeError(StatusCode::kDataCorruption, "RMW old logical SHA differs");
      std::memcpy(logical.data(), original.data(), std::min(logical.size(), original.size()));
      // Full old SHA is checked even when TruncateTail discards suffix bytes.
      // All original shard/recovery buffers leave scope before output encode.
    }
    CO_RETURN_ON_ERROR(io->check());
    if (!patch.empty()) std::memcpy(logical.data() + p.patchOffset, patch.data(), patch.size());
    EcRmwSealedCandidate result;
    result.commitment.planDigest = plan->digest();
    auto outputHash = ec_rmw_detail::sha256(logical);
    CO_RETURN_ON_ERROR(outputHash);
    result.commitment.logicalSha256 = *outputHash;
    auto encoded = EcCodec::encode(logical, p.shardBytes);
    CO_RETURN_ON_ERROR(encoded);
    for (size_t i = 0; i < 12; ++i) {
      auto descriptor = computeEcIntegrity(p.targets[i].identity, (*encoded)[i]);
      CO_RETURN_ON_ERROR(descriptor);
      result.commitment.descriptors[i] = *descriptor;
    }
    CO_RETURN_ON_ERROR(io->check());
    auto bound = co_await io->bindOutput(result.commitment);
    if (!bound) co_return makeError(std::move(bound.error()));
    CO_RETURN_ON_ERROR(io->check());
    for (uint8_t i = 0; i < 12; ++i) {
      CO_RETURN_ON_ERROR(io->check());
      mutationCallEntered = true;  // Includes a throwing task factory, not just its await.
      auto sealed = co_await io->writeTarget(i, result.commitment.descriptors[i], std::move((*encoded)[i]));
      if (!sealed) co_return makeError(std::move(sealed.error()));
      auto valid = receipt(*plan, i, result.commitment.descriptors[i], *sealed);
      if (!valid) co_return makeError(valid.error().convert(StorageCode::kEcSealOutcomeUnknown));
      result.receipts[i] = std::move(*sealed);
    }
    auto checked = io->check();
    if (!checked) co_return makeError(checked.error().convert(StorageCode::kEcSealOutcomeUnknown));
    co_return result;
  } catch (const std::bad_alloc &) {
    co_return makeError(mutationCallEntered ? mutationException(StatusCode::kNotEnoughMemory)
                                            : Status(StatusCode::kNotEnoughMemory));
  } catch (...) {
    co_return makeError(mutationCallEntered ? mutationException(StatusCode::kIOError) : Status(StatusCode::kIOError));
  }
}
}  // namespace hf3fs::storage
