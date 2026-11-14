#pragma once

#include "client/ec/EcBlockRead.h"
#include "client/ec/NativeEcRepairTransport.h"
#include "client/meta/MetaClient.h"

namespace hf3fs::client::ec {

struct EcStripeControl {
  std::chrono::steady_clock::time_point deadline;
  CancellationToken cancellation;
};

// All IDs are supplied and persisted by the caller. Request UUIDs are separate
// from the durable operation/pin UUID and are never replaced on a retry.
struct EcStripeMutationIds {
  Uuid operation = Uuid::zero();
  Uuid beginRequest = Uuid::zero();
  Uuid bindRequest = Uuid::zero();
  Uuid publishRequest = Uuid::zero();
  Uuid getRequest = Uuid::zero();
  Uuid prepareRepairRequest = Uuid::zero();  // Required for Repair only (Meta37 or Meta71).
};
struct EcStripePinIds {
  meta::EcObjectRef object;
  uint64_t stripe = 0;
  Uuid pin = Uuid::zero();
  Uuid acquireRequest = Uuid::zero();
  Uuid releaseRequest = Uuid::zero();
};
struct EcStripeWrite {
  meta::EcObjectRecord object;
  uint64_t stripe = 0;
  uint64_t expectedRevision = 0;
  EcStripeMutationIds ids;
  std::string logicalData;
};
struct EcStripeRepair {
  meta::EcObjectRecord object;
  uint64_t expectedRevision = 0;
  EcStripeMutationIds ids;
  EcStripePinIds baseRead;
  Uuid planId = Uuid::zero();
  // Fixed plan order, not the adaptive quorum selector's completion order.
  std::array<uint16_t, 10> sources{};
  uint16_t replacementMask = 0;
  uint8_t blockWindow = 1;
  EcRepairMode mode = EcRepairMode::CentralSerial;
  // Persist before any RPC; Direct is HelperChain-only and never falls back.
  EcRepairDelivery delivery = EcRepairDelivery::ClientAppend;
};

enum class EcStripePhase { Validate, Observe, Encode, Begin, Bind, Stage, Repair, Publish, Published, Indeterminate };
struct EcStripeMutationOutcome {
  meta::EcObjectRef object;
  Uuid operation = Uuid::zero();
  EcStripePhase phase = EcStripePhase::Validate;
  std::optional<Status> failure;
  // Actual observed state only. A failed Get does not imply a missing object.
  std::optional<meta::EcV2MutationRsp> observation;
  std::array<std::optional<storage::EcStageStateV2>, 12> stages;
  std::chrono::steady_clock::duration elapsed{};
  // Optional data phase only: bounded fragment stages for Write; the complete
  // EcRepairPipeline::run for Repair. Excludes Meta preparation/publication.
  std::optional<std::chrono::steady_clock::duration> dataPhaseElapsed;
  bool published() const {
    return !failure && observation && observation->record.state == meta::EcOperationState::Published;
  }
};

namespace detail {
struct EcStripeClientCore;
struct EcStripeClientReadState;
struct EcFileClientCore;
}  // namespace detail

class EcStripeReadOutput {
  friend struct detail::EcStripeClientCore;
  // Payload is destroyed before its shared application-byte reservation.
  std::shared_ptr<const detail::EcReadReservation> reservation_;

 public:
  EcStripeReadOutput() = default;
  EcStripeReadOutput(EcStripeReadOutput &&) noexcept = default;
  EcStripeReadOutput &operator=(EcStripeReadOutput &&) noexcept;
  EcStripeReadOutput(const EcStripeReadOutput &) = delete;
  EcStripeReadOutput &operator=(const EcStripeReadOutput &) = delete;
  meta::EcV2PinnedRead pinned;
  storage::EcSha256 contentSha256{};
  std::string logicalData;
  std::chrono::steady_clock::duration readyElapsed{};
};

class EcStripeReadSession {
 public:
  EcStripeReadSession(EcStripeReadSession &&) noexcept;
  EcStripeReadSession &operator=(EcStripeReadSession &&) noexcept;
  EcStripeReadSession(const EcStripeReadSession &) = delete;
  EcStripeReadSession &operator=(const EcStripeReadSession &) = delete;
  ~EcStripeReadSession();
  CoTryTask<EcStripeReadOutput> takeReady();
  CoTask<void> waitLocalCleanup();
  bool ready() const;
  bool localCleanupComplete() const;
  const EcStripePinIds &pin() const;
  void cancel();

 private:
  friend class EcStripeClient;
  friend struct detail::EcStripeClientCore;
  explicit EcStripeReadSession(std::shared_ptr<detail::EcStripeClientReadState>);
  std::shared_ptr<detail::EcStripeClientReadState> state_;
};

// Single-stripe orchestration using actual Meta and Storage clients. This is
// neither a POSIX client nor permission to release/GC an uncertain allocation.
class EcStripeClient {
 public:
  struct Limits {
    size_t maxOperations = 2;
    size_t maxApplicationBytes = 64u << 20;
    uint8_t writeFragments = 2;
    uint8_t readBlocks = 2;
    uint8_t recoveryAttempts = 2;
    std::chrono::seconds maxOperationTime{300};
  };
  struct Snapshot {
    size_t activeOperations = 0, reservedApplicationBytes = 0;
  };

  static CoTryTask<std::shared_ptr<EcStripeClient>> connect(std::shared_ptr<meta::client::MetaClient> meta,
                                                            std::shared_ptr<storage::client::StorageClient> storage,
                                                            std::shared_ptr<hf3fs::client::ICommonMgmtdClient> mgmtd,
                                                            flat::UserInfo credentials,
                                                            Uuid expectedClientNamespace,
                                                            folly::CPUThreadPoolExecutor &executor,
                                                            Limits limits);

  // Request UUID is mandatory and preserved. Caller may repeat this exact
  // request after an unknown result; no new create identity is substituted.
  CoTryTask<meta::CreateEcFileRsp> createFile(meta::CreateEcFileV2Req request, EcStripeControl);
  CoTask<EcStripeMutationOutcome> write(EcStripeWrite request, EcStripeControl);
  CoTask<EcStripeMutationOutcome> repair(EcStripeRepair request, EcStripeControl);
  Result<EcStripeReadSession> startRead(EcStripePinIds request, EcStripeControl);

  // Normal path first awaits local cleanup. Reconstructed pin IDs after a
  // client restart can use the second overload; only Meta's complete durable
  // drain protocol, never this local object, proves remote release.
  CoTryTask<meta::ReleaseEcReadV2Rsp> release(EcStripeReadSession &, EcStripeControl);
  CoTryTask<meta::ReleaseEcReadV2Rsp> release(EcStripePinIds request, EcStripeControl);

  const meta::EcOwner &owner() const;
  Snapshot snapshot() const;
  // Mandatory after any operation has started, even when snapshot().activeOperations
  // is zero: await close before destroying this manager or stopping supplied
  // clients/executor. Dropping a waiter is safe; dropping the last unclosed
  // manager is not supported (Folly AsyncScope requires an explicit join).
  // Output bytes may outlive close and keep their own charge.
  CoTask<void> close();
  ~EcStripeClient();

 private:
  friend struct detail::EcFileClientCore;
  // Data transport only for an already acquired tree-range pin. No Meta34 or
  // Meta36 call belongs to this session; its range owner uses Meta55 for T2.
  Result<EcStripeReadSession> startPinnedRead(EcStripePinIds, meta::AcquireEcReadV2Rsp, EcStripeControl);
  explicit EcStripeClient(std::shared_ptr<detail::EcStripeClientCore>);
  std::shared_ptr<detail::EcStripeClientCore> core_;
};
}  // namespace hf3fs::client::ec
