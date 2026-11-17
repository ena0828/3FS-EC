#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <variant>
#include <vector>

#include <folly/experimental/coro/Baton.h>

#include "common/utils/Coroutine.h"
#include "storage/store/StorageTarget.h"

namespace hf3fs::test {
struct ECShardWorkerTestHelper;
}

namespace hf3fs::storage::ec {

class ECShardWorker;

// One submission per Job. A rejected submission leaves the Job unsubmitted;
// only accepted Jobs have a completion obligation. Keep a shared_ptr while
// waiting or accessing the immutable result returned by wait().
class ECShardJob {
 public:
  enum class Type { Write, Read };
  using WriteResult = Result<StoreResult<IdempotentWriteDisposition>>;
  using ReadResult = Result<StoreResult<ShardRecord>>;
  using Completion = std::variant<WriteResult, ReadResult>;

  static std::shared_ptr<ECShardJob> write(
      std::shared_ptr<StorageTarget> target, erasure::ECShardKey key, uint64_t version,
      uint32_t validBytes, std::vector<uint8_t> payload,
      uint32_t scheme = erasure::ECLayout::kEncodingScheme,
      uint32_t format = erasure::ECLayout::kFormatVersion) {
    return std::shared_ptr<ECShardJob>(new ECShardJob(
        Type::Write, std::move(target), key, version, validBytes, std::move(payload), scheme, format));
  }

  static std::shared_ptr<ECShardJob> read(
      std::shared_ptr<StorageTarget> target, erasure::ECShardKey key, uint64_t version,
      uint32_t scheme = erasure::ECLayout::kEncodingScheme,
      uint32_t format = erasure::ECLayout::kFormatVersion) {
    return std::shared_ptr<ECShardJob>(new ECShardJob(
        Type::Read, std::move(target), key, version, 0, {}, scheme, format));
  }

  Type type() const { return type_; }
  uint64_t dataVersion() const { return version_; }

  // Blocking local-thread API; do not call from a worker thread or an RPC
  // executor that must remain nonblocking. No borrowed request data is stored.
  const Completion &wait() const {
    std::unique_lock lock(completionMutex_);
    completionCV_.wait(lock, [&] { return completion_.has_value(); });
    return *completion_;
  }

  bool waitFor(std::chrono::milliseconds timeout) const {
    std::unique_lock lock(completionMutex_);
    return completionCV_.wait_for(lock, timeout, [&] { return completion_.has_value(); });
  }

  // Lazy Task owns the Job from creation through completion, including when
  // the caller releases its reference before starting the Task. No early
  // cancellation: the accepted Job must finish before this waiter is destroyed.
  static CoTask<Completion> waitAsync(std::shared_ptr<const ECShardJob> job) {
    co_await job->completionBaton_;
    // Copy under the mutex; the returned result owns any read payload.
    std::lock_guard lock(job->completionMutex_);
    co_return *job->completion_;
  }

  size_t completionCount() const {
    std::lock_guard lock(completionMutex_);
    return completionCount_;
  }

 private:
  friend class ECShardWorker;
  friend struct hf3fs::test::ECShardWorkerTestHelper;
  ECShardJob(Type type, std::shared_ptr<StorageTarget> target, erasure::ECShardKey key,
             uint64_t version, uint32_t validBytes, std::vector<uint8_t> payload,
             uint32_t scheme, uint32_t format)
      : type_(type), target_(std::move(target)), key_(key), version_(version),
        validBytes_(validBytes), payload_(std::move(payload)), scheme_(scheme), format_(format) {}

  bool claim() {
    bool expected = false;
    return submitted_.compare_exchange_strong(expected, true);
  }

  void finish(Completion result) {
    // Result/vector moves cannot allocate or throw while publishing completion.
    static_assert(std::is_nothrow_move_constructible_v<Completion>);
    {
      std::lock_guard lock(completionMutex_);
      if (completion_) return;  // Defensive: never publish/notify a second time.
      completion_.emplace(std::move(result));
      ++completionCount_;
    }
    completionCV_.notify_all();
    completionBaton_.post();
  }

  const Type type_;
  const std::shared_ptr<StorageTarget> target_;
  const erasure::ECShardKey key_;
  const uint64_t version_;
  const uint32_t validBytes_;
  const std::vector<uint8_t> payload_;
  const uint32_t scheme_;
  const uint32_t format_;
  std::atomic<bool> submitted_{false};
  mutable std::mutex completionMutex_;
  mutable std::condition_variable completionCV_;
  mutable folly::coro::Baton completionBaton_;
  std::optional<Completion> completion_;
  size_t completionCount_ = 0;
};

}  // namespace hf3fs::storage::ec
