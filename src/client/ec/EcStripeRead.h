#pragma once

#include <array>
#include <chrono>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <memory>

#include "common/utils/Coroutine.h"
#include "fbs/meta/Ec.h"
#include "fbs/storage/EcAuthorized.h"

namespace hf3fs::client::ec {

struct EcReadControl {
  std::chrono::steady_clock::time_point deadline;
  CancellationToken cancellation;
};

// The implementation owns its request across every suspension. Cancellation
// may stop admission; an already dispatched RPC must finish via its response
// or finite deadline without destroying a borrowed ClientContext/worker frame.
class EcReadTransport {
 public:
  virtual ~EcReadTransport() = default;
  virtual CoTryTask<storage::EcReadResult> read(storage::EcAuthorizedReadReq request, EcReadControl control) = 0;
};

// Construct only from one authoritative, pinned Acquire response. The selector
// checks internal consistency and actual bytes; it does not authenticate Meta.
struct EcStripeReadInput {
  meta::EcManifest manifest;
  std::array<storage::EcAuthorizedReadReq, 12> requests;
};

struct EcStripeReadOptions {
  std::chrono::steady_clock::time_point deadline;
  std::chrono::milliseconds hedgeAfter{10};
  std::array<uint16_t, 12> order{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
};

namespace detail {
struct EcReadState;
struct EcReadReservation;
}  // namespace detail

struct EcSelectedShard {
  uint16_t index = 0;
  storage::EcReadResult result;
};

// Ten verified sources, not decoded logical file bytes. The caller may use the
// existing EcCodec::recover with these actual indices. No remote pin is freed.
struct EcStripeSelection {
 private:
  friend class EcStripeRead;
  friend struct detail::EcReadState;
  // Declared first: payloads are destroyed before their shared charge.
  std::shared_ptr<const detail::EcReadReservation> payloadReservation;

 public:
  EcStripeSelection() = default;
  EcStripeSelection(EcStripeSelection &&) noexcept = default;
  EcStripeSelection &operator=(EcStripeSelection &&) noexcept;
  EcStripeSelection(const EcStripeSelection &) = delete;
  EcStripeSelection &operator=(const EcStripeSelection &) = delete;
  meta::EcManifest manifest;
  std::array<EcSelectedShard, 10> shards;
  size_t attempted = 0;
  size_t rejected = 0;
  std::chrono::steady_clock::duration quorumElapsed{};
};

class EcStripeReadHandle {
 public:
  EcStripeReadHandle(EcStripeReadHandle &&) noexcept;
  EcStripeReadHandle &operator=(EcStripeReadHandle &&) noexcept;
  EcStripeReadHandle(const EcStripeReadHandle &) = delete;
  EcStripeReadHandle &operator=(const EcStripeReadHandle &) = delete;
  ~EcStripeReadHandle();

  CoTryTask<EcStripeSelection> takeReady();
  CoTask<void> waitLocalCleanup();
  bool ready() const;
  bool localCleanupComplete() const;
  void cancel();

 private:
  friend class EcStripeRead;
  explicit EcStripeReadHandle(std::shared_ptr<detail::EcReadState> state);
  std::shared_ptr<detail::EcReadState> state_;
};

class EcStripeRead {
 public:
  struct Limits {
    size_t maxOperations = 4;
    // Owned response payload reservation only, not Serde/socket allocations.
    size_t maxPayloadBytes = 48u << 20;
    std::chrono::seconds maxOperationTime{60};
  };
  struct Snapshot {
    size_t activeOperations = 0;
    size_t activeRequests = 0;
    size_t reservedPayloadBytes = 0;
  };

  EcStripeRead(std::shared_ptr<EcReadTransport> transport, folly::CPUThreadPoolExecutor &executor, Limits limits);
  EcStripeRead(const EcStripeRead &) = delete;
  EcStripeRead &operator=(const EcStripeRead &) = delete;
  // As for folly::coro::AsyncScope, close() must finish before destruction if
  // start() was used. Keep the executor/network alive until close completes.
  ~EcStripeRead();

  Result<EcStripeReadHandle> start(EcStripeReadInput input, EcStripeReadOptions options);
  // Idempotent; cannot be abandoned because the caller's request was cancelled.
  CoTask<void> close();
  Snapshot snapshot() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace hf3fs::client::ec
