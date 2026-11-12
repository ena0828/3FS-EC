#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>

#include "EcRmwPatchBuffer.h"
#include "NativeEcRmwIo.h"

namespace hf3fs::storage {
namespace ec_rmw_detail {
struct RuntimeTestAccess;
}
enum class EcRmwLocalState : uint8_t { Receiving = 1, Queued = 2, Running = 3, Complete = 4 };
struct EcRmwObservation {
  Uuid planId = Uuid::zero();
  EcSha256 planDigest{};
  EcRmwLocalState state = EcRmwLocalState::Receiving;
  std::bitset<kEcRmwMaxPatchBlocks> received;
  status_code_t error = StatusCode::kOK;
  std::optional<EcRmwSealedCandidate> sealed;
};
// One dedicated thread, one owned job, one bounded observation. Submission and
// observation never wait for nested Meta/Storage traffic on a Processor slot.
// Observations are VOLATILE; Missing does not prove an earlier job did not run.
// The internal authenticated installer must already
// have acquired the job reservation and real worker scope ticket for nativeIo.
class EcRmwRuntime final {
 public:
  using Clock = std::function<uint64_t()>;
  static Result<std::unique_ptr<EcRmwRuntime>> create(std::shared_ptr<const EcRmwKey>,
                                                      Uuid authority,
                                                      flat::NodeId localNode,
                                                      Clock);
  ~EcRmwRuntime();
  // Receiving replay discards only volatile bytes and renews the same plan;
  // running/complete-success replay never restarts the job. The caller acquires
  // the one-job reservation and the actual scope ticket only when true.
  Result<bool> prepareInstall(std::shared_ptr<const EcRmwPlan>, const EcRmwGrant &);
  Result<Void> install(std::shared_ptr<const EcRmwPlan>, const EcRmwGrant &, std::shared_ptr<NativeEcRmwIo>);
  Result<Void> put(const Uuid &planId, const EcRmwGrant &, uint32_t block, std::string_view ownedCallBytes);
  Result<EcRmwObservation> submit(const Uuid &planId, const EcRmwGrant &);
  Result<EcRmwObservation> query(const Uuid &planId, const EcRmwGrant &) const;
  // Outside any callback/worker/network Processor. No timeout/detach. Closing
  // rejects new work; a running task is joined with all borrowed I/O alive.
  // The bootstrap must stop this before clients/target map/executors disappear.
  Result<Void> stopAndJoin();

 private:
  friend struct ec_rmw_detail::RuntimeTestAccess;
  struct Entry {
    std::shared_ptr<const EcRmwPlan> plan;
    std::unique_ptr<EcRmwPatchBuffer> patch;
    std::shared_ptr<EcRmwIo> io;
    EcRmwGrant installed;
    std::optional<VerifiedEcRmwPlan> execute;
    std::string ownedPatch;
    EcRmwObservation observation;
  };
  EcRmwRuntime(std::shared_ptr<const EcRmwKey> key, Uuid authority, flat::NodeId node, Clock clock)
      : key_(std::move(key)),
        authority_(authority),
        node_(node),
        clock_(std::move(clock)) {}
  Result<Void> installInternal(std::shared_ptr<const EcRmwPlan>, const EcRmwGrant &, std::shared_ptr<EcRmwIo>);
  Result<VerifiedEcRmwPlan> verify(const Entry &, const EcRmwGrant &, EcRmwRight) const;
  void work() noexcept;
  std::shared_ptr<const EcRmwKey> key_;
  Uuid authority_;
  flat::NodeId node_;
  Clock clock_;
  mutable std::mutex mutex_;
  std::mutex stopMutex_;
  std::condition_variable wake_;
  std::unique_ptr<Entry> entry_;
  bool closing_ = false;
  bool joined_ = false;
  std::thread worker_;
};
}  // namespace hf3fs::storage
