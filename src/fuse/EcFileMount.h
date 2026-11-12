#pragma once
#include <atomic>
#include <condition_variable>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/experimental/coro/Baton.h>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

#include "EcFileMountState.h"
#include "client/ec/EcFileAppendClient.h"
#include "client/ec/EcFileClient.h"
#include "client/ec/EcFilePwriteClient.h"

namespace hf3fs::fuse {
struct EcMountHandle {
  Uuid session = Uuid::zero();
  meta::EcObjectRef object;
  meta::EcOwner owner;
  uint32_t shardBytes = 0;
  uint8_t rights = 0;
};
struct EcMountOpenResult {
  EcMountHandle handle;
  meta::Inode inode;
};
struct EcMountReadResult {
  // Admission remains held until the payload is destroyed after reply/CQE copy.
  // Declare the lease first: bytes are destroyed before admission is released.
  std::shared_ptr<void> admission;
  client::ec::EcFilePayload data;
  uint64_t length = 0;
  bool allReleased = false;
  EcMountReadResult() = default;
  EcMountReadResult(EcMountReadResult &&) = default;
  EcMountReadResult &operator=(EcMountReadResult &&other) noexcept {
    if (this != &other) {
      // Assignment, like destruction, must release bytes before admission.
      data = client::ec::EcFilePayload{};
      admission.reset();
      admission = std::move(other.admission);
      data = std::move(other.data);
      length = other.length;
      allReleased = other.allReleased;
    }
    return *this;
  }
};
// All RPCs and blockingWait calls execute on one owned ordinary thread. The
// queued closures contain only owned values; they never contain fuse_req/SQE or
// shared-memory pointers. Dropping a waiting coroutine does not drop the job.
class EcFileMount final : public std::enable_shared_from_this<EcFileMount> {
 public:
  struct Dependencies {
    std::shared_ptr<meta::client::MetaClient> meta;
    std::shared_ptr<storage::client::StorageClient> storage;
    std::shared_ptr<client::ICommonMgmtdClient> mgmtd;
    std::shared_ptr<storage::client::EcRmwTransport> rmw;
    std::function<bool(const flat::UserInfo &)> readonly;
  };
  static Result<std::shared_ptr<EcFileMount>> start(std::shared_ptr<EcFileMountState>,
                                                    Dependencies,
                                                    flat::Token recoveryToken,
                                                    std::chrono::seconds maximumTime);
  ~EcFileMount();
  CoTryTask<Void> recoverState();
  CoTryTask<EcMountOpenResult> open(meta::Inode, flat::UserInfo, int flags);
  CoTryTask<EcMountOpenResult> create(meta::PathAt,
                                      flat::UserInfo,
                                      int flags,
                                      uint32_t permission,
                                      uint32_t shardBytes);
  CoTryTask<EcMountReadResult> read(EcMountHandle, flat::UserInfo, uint64_t offset, uint64_t length, bool shortWindow);
  // Copies bytes synchronously before returning the lazy task. Admission and
  // length are checked first; the worker never sees the caller's span.
  CoTryTask<uint64_t> write(EcMountHandle, flat::UserInfo, uint64_t offset, std::span<const uint8_t>);
  CoTryTask<uint64_t> truncate(EcMountHandle, flat::UserInfo, uint64_t length);
  CoTryTask<Void> release(EcMountHandle, flat::UserInfo);
  CoTryTask<Void> flush(EcMountHandle, flat::UserInfo);
  CoTryTask<meta::EcFileSyncRecord> fsync(EcMountHandle, flat::UserInfo);
  // Caller first joins all ring/watch/request users. Local uncertainty returns
  // failure, requiring the existing application-level fail-stop before globals.
  Result<Void> stop() noexcept;
  bool remoteCleanupComplete() const { return !remoteDebt_; }

 private:
  friend struct EcFileMountTestAccess;
  struct Session {
    EcMountOpenRecord original;
    std::filesystem::path directory;
    std::shared_ptr<client::ec::EcFilePwriteJournal> accepted;
    bool debt = false;
    bool archived = false;
    struct PendingRead {
      std::string name, evidence;
      std::weak_ptr<void> output;
    };
    std::optional<PendingRead> pendingRead;
  };
  struct JobBase {
    virtual ~JobBase() = default;
    virtual void run() noexcept = 0;
  };
  template <class T>
  struct Job final : JobBase {
    std::function<Result<T>()> invoke;
    Result<T> result = makeError(StatusCode::kIOError);
    folly::coro::Baton ready;
    void run() noexcept override {
      try {
        result = invoke();
      } catch (const std::bad_alloc &) {
        result = makeError(StatusCode::kNotEnoughMemory);
      } catch (...) {
        result = makeError(StatusCode::kIOError);
      }
      invoke = nullptr;
      ready.post();
    }
  };
  struct Admission {
    explicit Admission(std::shared_ptr<EcFileMount> c)
        : core(std::move(c)) {}
    Admission(const Admission &) = delete;
    std::shared_ptr<EcFileMount> core;
    ~Admission() { core->active_.store(false); }
  };
  Result<std::shared_ptr<Admission>> admit();
  template <class T>
  static CoTryTask<T> failed(Status s) {
    co_return makeError(std::move(s));
  }
  template <class T>
  static CoTryTask<T> wait(std::shared_ptr<Job<T>> j) {
    co_await folly::coro::co_withCancellation(CancellationToken{}, j->ready);
    co_return std::move(j->result);
  }
  template <class T, class F>
  CoTryTask<T> post(std::shared_ptr<Admission> held, F fn) {
    auto job = std::make_shared<Job<T>>();
    job->invoke = [held = std::move(held), fn = std::move(fn)]() mutable -> Result<T> {
      try {
        RETURN_ON_ERROR(held->core->reapCompleted());
        auto result = fn(held);
        held->core->pruneArchived();
        return result;
      } catch (...) {
        held->core->closing_ = true;
        held->core->changed_.notify_all();
        throw;
      }
    };
    auto waiter = wait(job);  // Factory before enqueue: allocation cannot abandon an accepted job.
    {
      std::lock_guard lock(mutex_);
      if (closing_ || queued_) return failed<T>(Status(StorageClientCode::kResourceBusy));
      queued_ = job;
    }
    changed_.notify_one();
    return waiter;
  }
  EcFileMount(std::shared_ptr<EcFileMountState> s, Dependencies d, std::chrono::seconds t)
      : state_(std::move(s)),
        deps_(std::move(d)),
        time_(t),
        executor_(std::make_unique<folly::CPUThreadPoolExecutor>(2)) {}
  client::ec::EcStripeControl control() const;
  bool readonly(const flat::UserInfo &u) const { return deps_.readonly && deps_.readonly(u); }
  void loop() noexcept;
  Result<Void> recover(flat::Token);
  Result<Session *> find(const EcMountHandle &, const flat::UserInfo &);
  Result<std::unique_ptr<client::ec::EcFilePwriteClient>> writer(const flat::UserInfo &);
  Result<std::shared_ptr<client::ec::EcFileClient>> reader(const flat::UserInfo &);
  Result<Void> closeReader(std::shared_ptr<client::ec::EcFileClient> &);
  Result<meta::OpenEcFileSessionRsp> reopen(Session &, flat::UserInfo);
  Result<EcMountOpenResult> openOwned(EcMountOpenRecord, flat::UserInfo);
  Result<Void> recoverSession(Session &, flat::UserInfo);
  Result<Void> closeSession(Session &, flat::UserInfo);
  Result<std::filesystem::path> next(Session &, std::string_view, uint64_t inputBytes = 0);
  Result<Void> reapCompleted();
  void pruneArchived();
  Result<uint64_t> truncateOwned(Session &, flat::UserInfo, uint64_t);
  std::shared_ptr<EcFileMountState> state_;
  Dependencies deps_;
  std::chrono::seconds time_;
  // Written/read only by the owned worker after accepted jobs have completed.
  std::optional<std::chrono::steady_clock::time_point> shutdownDeadline_;
  std::unique_ptr<folly::CPUThreadPoolExecutor> executor_;
  std::shared_ptr<client::ec::EcFileClient> retainedReader_;
  std::map<Uuid, Session> sessions_;
  std::atomic_bool active_{false}, closing_{false};
  std::mutex mutex_, stopMutex_;
  std::condition_variable changed_;
  std::shared_ptr<JobBase> queued_;
  std::thread thread_;
  flat::Token token_;
  bool remoteDebt_ = false;
  bool stopped_ = true;
};
}  // namespace hf3fs::fuse
