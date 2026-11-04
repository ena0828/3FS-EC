#pragma once

#include "client/ec/EcStripeRead.h"
#include "fbs/meta/EcV2.h"
#include "fbs/storage/EcStageResultV2.h"

namespace hf3fs::client::ec {

// A fixed manifest/allocation binding, never synthesized from current routing.
// Repair callers retain their fixed ten-source plan and call the transport
// directly. Per-block quorum selection below is only for ordinary pinned reads.
struct EcBlockBinding {
  storage::EcFragmentIdentity identity;
  Uuid originalOperation = Uuid::zero();
  storage::EcScopeEndpoint endpoint;
  storage::EcIntegrityDescriptor integrity;
};

// Checks consistency with an authoritative binding, not the token MAC. Storage
// performs authentication and checks current route/instance at execution time.
Result<storage::EcReadBlockV2Req> makeEcReadBlockRequest(const EcBlockBinding &binding,
                                                         const storage::EcCapabilityV2 &grant,
                                                         storage::VersionedChainId currentRoute,
                                                         uint32_t blockIndex);

class EcBlockReadTransport {
 public:
  virtual ~EcBlockReadTransport() = default;
  virtual CoTryTask<storage::EcReadBlockResultV2> read(storage::EcReadBlockV2Req owned, EcReadControl control) = 0;
};

struct EcBlockReadInput {
  meta::EcV2PinnedRead pinned;
  uint32_t blockIndex = 0;
  std::array<storage::EcReadBlockV2Req, 12> requests;
};
Result<EcBlockReadInput> makeEcBlockReadInput(meta::EcV2PinnedRead pinned,
                                              const std::array<storage::EcCapabilityV2, 12> &grants,
                                              const std::array<storage::VersionedChainId, 12> &currentRoutes,
                                              uint32_t blockIndex);

namespace detail {
struct EcBlockReadState;
}
struct EcSelectedBlock {
  uint16_t index = 0;
  storage::EcReadBlockResultV2 result;
};

class EcBlockSelection {
  friend struct detail::EcBlockReadState;
  // First member: payload members are destroyed before their charge is freed.
  std::shared_ptr<const detail::EcReadReservation> payloadReservation;

 public:
  EcBlockSelection() = default;
  EcBlockSelection(EcBlockSelection &&) noexcept = default;
  EcBlockSelection &operator=(EcBlockSelection &&) noexcept;
  EcBlockSelection(const EcBlockSelection &) = delete;
  EcBlockSelection &operator=(const EcBlockSelection &) = delete;
  meta::EcV2PinnedRead pinned;
  uint32_t blockIndex = 0;
  std::array<EcSelectedBlock, 10> shards;
  size_t attempted = 0, rejected = 0;
  std::chrono::steady_clock::duration quorumElapsed{};
};

class EcBlockReadHandle {
 public:
  EcBlockReadHandle(EcBlockReadHandle &&) noexcept;
  EcBlockReadHandle &operator=(EcBlockReadHandle &&) noexcept;
  EcBlockReadHandle(const EcBlockReadHandle &) = delete;
  EcBlockReadHandle &operator=(const EcBlockReadHandle &) = delete;
  ~EcBlockReadHandle();
  CoTryTask<EcBlockSelection> takeReady();
  CoTask<void> waitLocalCleanup();
  bool ready() const;
  bool localCleanupComplete() const;
  void cancel();

 private:
  friend class EcBlockRead;
  explicit EcBlockReadHandle(std::shared_ptr<detail::EcBlockReadState> state);
  std::shared_ptr<detail::EcBlockReadState> state_;
};

class EcBlockRead {
 public:
  struct Limits {
    size_t maxOperations = 4;  // Local block window, not a whole-file limit.
    // Owned payload bytes only; fixed descriptors, allocator capacity, network
    // frames and Serde buffers are separate from this admission accounting.
    size_t maxPayloadBytes = 4 * 12 * storage::kEcIntegrityBlockBytes;
    std::chrono::seconds maxOperationTime{60};
  };
  using Snapshot = EcStripeRead::Snapshot;
  EcBlockRead(std::shared_ptr<EcBlockReadTransport>, folly::CPUThreadPoolExecutor &, Limits);
  EcBlockRead(const EcBlockRead &) = delete;
  EcBlockRead &operator=(const EcBlockRead &) = delete;
  ~EcBlockRead();
  Result<EcBlockReadHandle> start(EcBlockReadInput input, EcStripeReadOptions options);
  // Required before destruction; keep executor and network alive until joined.
  // Local cleanup is not remote scope drain and never releases a Meta pin.
  CoTask<void> close();
  Snapshot snapshot() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace hf3fs::client::ec
