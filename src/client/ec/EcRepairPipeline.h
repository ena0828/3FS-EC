#pragma once

#include <chrono>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <memory>

#include "EcRepairObservation.h"
#include "common/utils/Coroutine.h"
#include "fbs/storage/EcStageResultV2.h"
#include "storage/ec_repair/EcRepairPlan.h"

namespace hf3fs::client::ec {

enum class EcRepairMode { CentralSerial, ClientPipeline, HelperChain };
enum class EcRepairDelivery { ClientAppend, HelperDirect };

struct EcRepairControl {
  std::chrono::steady_clock::time_point deadline;
  CancellationToken cancellation;
};

// Every operation owns arguments until its actual local completion. A timeout
// or cancellation may stop admission, but must not abandon a submitted RPC or
// borrowed worker frame. Implementations must enforce finite network deadlines.
class EcRepairTransport {
 public:
  using Plan = std::shared_ptr<const storage::EcRepairPlan>;
  virtual ~EcRepairTransport() = default;
  virtual bool supportsHelperChain() const { return false; }
  virtual bool supportsHelperDirect() const { return false; }
  virtual CoTryTask<void> begin(Plan, uint8_t target, EcRepairControl) = 0;
  virtual CoTryTask<std::string> read(Plan, uint8_t source, uint32_t block, EcRepairControl) = 0;
  virtual CoTryTask<void> append(Plan, uint8_t target, uint32_t block, std::string data, EcRepairControl) = 0;
  virtual CoTryTask<storage::EcFragmentReceiptV2> seal(Plan, uint8_t target, EcRepairControl) = 0;
  // Must execute a separately authorized native helper chain. Implementations
  // must not silently emulate this method with ten centralized ReadBlock calls.
  virtual CoTryTask<storage::EcRepairBlock> helperBlock(Plan, uint32_t block, EcRepairControl) = 0;
  // A mutation: the final helper appends to the fixed targets. The caller still
  // owns Begin/Reconcile and Seal; a small response does not authorize publish.
  virtual CoTryTask<void> helperDirectBlock(Plan, uint32_t, EcRepairControl) {
    co_return makeError(StatusCode::kNotImplemented, "transport has no native helper direct delivery");
  }
};

struct EcRepairSealed {
  EcRepairMode mode = EcRepairMode::CentralSerial;
  EcRepairDelivery delivery = EcRepairDelivery::ClientAppend;
  storage::EcSha256 planDigest{};
  std::array<storage::EcFragmentReceiptV2, 2> receipts;
  uint8_t targetCount = 0;
  uint16_t blocks = 0;
  // Local completion only. Meta must still fence the whole persisted endpoint
  // set, verify every durable Drained ACK and validate/publish in its own txn.
};

class EcRepairPipeline {
 public:
  // Owns and joins every started task. Caller must await this coroutine and keep
  // executor alive. No detached jobs, early success, implicit release or delete.
  // The transport is shared-owned until all children and final seal calls end.
  // Optional observation is borrowed for this entire joined call; caller must
  // keep it alive. It never changes the transport or cancellation policy.
  static CoTryTask<EcRepairSealed> run(std::shared_ptr<const storage::EcRepairPlan> plan,
                                       std::shared_ptr<EcRepairTransport> transport,
                                       EcRepairMode mode,
                                       EcRepairControl control,
                                       folly::CPUThreadPoolExecutor &executor,
                                       EcRepairObservation *observation = nullptr,
                                       EcRepairDelivery delivery = EcRepairDelivery::ClientAppend);
};

}  // namespace hf3fs::client::ec
