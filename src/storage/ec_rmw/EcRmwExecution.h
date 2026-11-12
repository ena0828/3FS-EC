#pragma once

#include "EcRmwAuthorization.h"
#include "common/utils/Coroutine.h"
#include "fbs/storage/EcStageResultV2.h"

namespace hf3fs::storage {
struct EcRmwOutputCommitment {
  EcSha256 planDigest{};
  EcSha256 logicalSha256{};
  std::array<EcIntegrityDescriptor, 12> descriptors;
};
struct EcRmwSealedCandidate {
  EcRmwOutputCommitment commitment;
  std::array<EcFragmentReceiptV2, 12> receipts;
};
// Internal owning data-plane dependency, never a caller-supplied wire object.
// Native implementation validates original internal grants and exact returned
// bytes/receipts. bindOutput is implemented by the committed Meta adapter; an
// in-memory callback is only a test seam, not production issuance evidence.
class EcRmwIo {
 public:
  virtual ~EcRmwIo() = default;
  // Fresh RMW capability/actual worker/route/deadline + execution ticket.
  virtual Result<Void> check() const = 0;
  virtual CoTryTask<std::string> readSource(uint8_t source) = 0;
  // No source data or credentials may be returned to the ordinary client.
  // No data mutation begins until this exact computed commitment is bound.
  virtual CoTryTask<Void> bindOutput(const EcRmwOutputCommitment &) = 0;
  virtual CoTryTask<EcFragmentReceiptV2> writeTarget(uint8_t target,
                                                     const EcIntegrityDescriptor &,
                                                     std::string ownedBytes) = 0;
};
class EcRmwExecution final {
 public:
  // The runtime owns/awaits this task, including after a public waiter leaves.
  // io holds the job's 96MiB reservation, session and actual worker ticket for
  // its whole lifetime. This function exposes only new commitments/receipts.
  static CoTryTask<EcRmwSealedCandidate> run(VerifiedEcRmwPlan, std::string ownedPatch, std::shared_ptr<EcRmwIo> io);
};
}  // namespace hf3fs::storage
