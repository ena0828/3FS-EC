#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "common/kv/IKVEngine.h"
#include "common/kv/KeyPrefix.h"
#include "fdb/FDBTransaction.h"
#include "meta/store/EcFileTreeTxnBudget.h"
#include "tests/GtestHelpers.h"
#include "tests/meta/EcMountedTruncateFault.h"

namespace hf3fs::meta::server::detail {
// Test-owned, fixed-capacity observation. No keys, values, credentials, callback
// registry or RPC fields. Only report after all Meta/Storage work has joined.
class EcNativeTxnObservation {
 public:
  using Budget = EcFileTreeTxnBudget;
  enum class RawCommit : uint8_t { NotCalled, Unconfirmed, Succeeded, Failed };
  struct Event {
    uint64_t rawId = 0;
    uint64_t rawAttempt = 1;
    Budget::Snapshot budget{};
    uint32_t rawCommitCalls = 0;
    RawCommit rawCommit = RawCommit::NotCalled;
    uint32_t rawError = StatusCode::kOK;
    bool approximateAttempted = false;
    bool approximateAvailable = false;
    int64_t approximateBytes = -1;
    uint32_t approximateError = StatusCode::kOK;
    int64_t rawLifetimeMicros = 0;
    int64_t approximateMicros = 0;
    int64_t commitMicros = 0;
    uint32_t writtenFamilies = 0;
  };
  static constexpr size_t kCapacity = 4096;
  uint64_t nextId() noexcept { return created_.fetch_add(1, std::memory_order_relaxed) + 1; }
  void started() noexcept { active_.fetch_add(1, std::memory_order_relaxed); }
  void ended() noexcept { active_.fetch_sub(1, std::memory_order_relaxed); }
  void record(Event event) noexcept {
    const size_t i = reserved_.fetch_add(1, std::memory_order_relaxed);
    if (i >= kCapacity) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    events_[i] = event;
    completed_.fetch_add(1, std::memory_order_release);
  }
  void report(bool expectRmw) const {
    const auto count = reserved_.load(std::memory_order_acquire);
    const auto active = active_.load(std::memory_order_acquire);
    const auto complete = completed_.load(std::memory_order_acquire);
    EXPECT_EQ(active, 0u) << "report requires all owned transaction work joined";
    EXPECT_EQ(dropped_.load(), 0u) << "bounded measurement overflow is not a successful measurement";
    EXPECT_EQ(complete, std::min(count, kCapacity));
    if (active || complete != std::min(count, kCapacity)) {
      // Do not inspect rows that may still be written, even after a failed
      // lifecycle assertion. The failed expectation already invalidates this run.
      ::testing::Test::RecordProperty("ec_txn_observation_trace_incomplete", "true");
      return;
    }
    size_t rmw = 0;
    std::array<size_t, 5> totals{}, operations{}, mutationsAndConflicts{};
    std::array<int64_t, 5> approximate{};
    approximate.fill(-1);
    std::array<size_t, 5> approximateCounts{};
    std::ostringstream trace;
    trace << "raw,raw_attempt,budget_attempt,point,profile,limit_bytes,limit_ops,read,mutation,conflict,ops,"
             "poison,budget_commit,budget_error,raw_commit_calls,raw_commit,raw_error,approx_attempted,"
             "approx_available,approx_bytes,approx_error,raw_lifetime_us,approx_us,commit_us,write_call_families\n";
    for (size_t i = 0; i < std::min(count, kCapacity); ++i) {
      const auto &e = events_[i];
      const auto &b = e.budget;
      const size_t profile = static_cast<size_t>(b.profile);
      EXPECT_LT(profile, totals.size());
      if (profile < totals.size()) {
        totals[profile] = std::max(totals[profile], b.usage.totalBytes());
        operations[profile] = std::max(operations[profile], b.usage.keyOperations);
        mutationsAndConflicts[profile] = std::max(mutationsAndConflicts[profile], b.usage.mutationAndConflictBytes());
        if (e.approximateAvailable) {
          approximate[profile] = std::max(approximate[profile], e.approximateBytes);
          ++approximateCounts[profile];
        }
      }
      if (b.profile == Budget::Profile::Rmw) ++rmw;
      EXPECT_LE(b.usage.totalBytes(), b.limits.bytes);
      EXPECT_LE(b.usage.keyOperations, b.limits.keyOperations);
      if (b.commitOutcome == Budget::CommitOutcome::Succeeded) {
        EXPECT_EQ(e.rawCommitCalls, 1u);
        EXPECT_EQ(e.rawCommit, RawCommit::Succeeded);
        EXPECT_TRUE(e.approximateAttempted);
        EXPECT_TRUE(e.approximateAvailable) << "successful native commit lacks an engine estimate";
        EXPECT_GE(e.approximateBytes, 0);
        EXPECT_EQ(e.approximateError, StatusCode::kOK);
      } else if (b.commitOutcome == Budget::CommitOutcome::Failed) {
        EXPECT_EQ(e.rawCommit, RawCommit::Failed);
        EXPECT_EQ(b.commitError, e.rawError);
      } else if (b.commitOutcome == Budget::CommitOutcome::Rejected) {
        EXPECT_EQ(e.rawCommitCalls, 0u);
      }
      trace << e.rawId << ',' << e.rawAttempt << ',' << b.attempt << ',' << unsigned(b.point) << ',' << profile << ','
            << b.limits.bytes << ',' << b.limits.keyOperations << ',' << b.usage.readBytes << ','
            << b.usage.mutationBytes << ',' << b.usage.conflictBytes << ',' << b.usage.keyOperations << ','
            << b.poisoned << ',' << unsigned(b.commitOutcome) << ',' << b.commitError << ',' << e.rawCommitCalls << ','
            << unsigned(e.rawCommit) << ',' << e.rawError << ',' << e.approximateAttempted << ','
            << e.approximateAvailable << ',' << e.approximateBytes << ',' << e.approximateError << ','
            << e.rawLifetimeMicros << ',' << e.approximateMicros << ',' << e.commitMicros << ',' << e.writtenFamilies
            << '\n';
    }
    if (expectRmw) EXPECT_GT(rmw, 0u) << "no actual outer Rmw wrapper was observed";
    ::testing::Test::RecordProperty("ec_txn_observation_event_count", std::to_string(count));
    ::testing::Test::RecordProperty("ec_txn_observation_events_dropped", std::to_string(dropped_.load()));
    ::testing::Test::RecordProperty("ec_txn_observation_rmw_events", std::to_string(rmw));
    ::testing::Test::RecordProperty("ec_txn_observation_trace_csv", trace.str());
    for (size_t p = 0; p < totals.size(); ++p) {
      const auto label = "ec_txn_observation_profile_" + std::to_string(p);
      ::testing::Test::RecordProperty(label + "_max_total_bytes", std::to_string(totals[p]));
      ::testing::Test::RecordProperty(label + "_max_operations", std::to_string(operations[p]));
      ::testing::Test::RecordProperty(label + "_max_mutation_conflict_bytes", std::to_string(mutationsAndConflicts[p]));
      ::testing::Test::RecordProperty(label + "_max_fdb_approximate_bytes", std::to_string(approximate[p]));
      ::testing::Test::RecordProperty(label + "_fdb_approximate_samples", std::to_string(approximateCounts[p]));
    }
  }

 private:
  std::array<Event, kCapacity> events_{};
  std::atomic<uint64_t> created_{0};
  std::atomic<size_t> active_{0}, reserved_{0}, completed_{0}, dropped_{0};
};

class EcObservedNativeTransaction final : public kv::IReadWriteTransaction,
                                          public EcFileTreeTxnBudget::SnapshotObserver {
 public:
  using Clock = std::chrono::steady_clock;
  EcObservedNativeTransaction(std::unique_ptr<kv::IReadWriteTransaction> inner,
                              std::shared_ptr<EcNativeTxnObservation> observation,
                              std::shared_ptr<EcMountedTruncateFault> fault = nullptr,
                              std::shared_ptr<kv::IKVEngine> rawEngine = nullptr)
      : inner_(std::move(inner)),
        observation_(std::move(observation)),
        fault_(std::move(fault)),
        rawEngine_(std::move(rawEngine)) {
    event_.rawId = observation_->nextId();
    observation_->started();
  }
  ~EcObservedNativeTransaction() override {
    inner_.reset();
    observation_->ended();
  }
  void observeEcTreeBudget(const EcFileTreeTxnBudget::Snapshot &snapshot) noexcept override {
    auto copy = event_;
    copy.budget = snapshot;
    copy.rawLifetimeMicros = micros(Clock::now() - started_);
    observation_->record(copy);
  }
  void setReadVersion(int64_t v) override { inner_->setReadVersion(v); }
  CoTryTask<std::optional<String>> snapshotGet(std::string_view k) override { return inner_->snapshotGet(k); }
  CoTryTask<std::optional<String>> get(std::string_view k) override { return inner_->get(k); }
  CoTryTask<GetRangeResult> snapshotGetRange(const KeySelector &a, const KeySelector &b, int32_t n) override {
    return inner_->snapshotGetRange(a, b, n);
  }
  CoTryTask<GetRangeResult> getRange(const KeySelector &a, const KeySelector &b, int32_t n) override {
    return inner_->getRange(a, b, n);
  }
  CoTryTask<void> cancel() override { return inner_->cancel(); }
  void reset() override {
    inner_->reset();
    const auto id = event_.rawId, nextAttempt = event_.rawAttempt + 1;
    event_ = {};
    event_.rawId = id;
    event_.rawAttempt = nextAttempt;
    started_ = Clock::now();
    faultToken_ = 0;
  }
  CoTryTask<void> addReadConflict(std::string_view k) override { return inner_->addReadConflict(k); }
  CoTryTask<void> addReadConflictRange(std::string_view a, std::string_view b) override {
    return inner_->addReadConflictRange(a, b);
  }
  CoTryTask<void> set(std::string_view k, std::string_view v) override {
    recordFamily(k);
    if (fault_) {
      try {
        const auto selected = fault_->selectSet(k, v);
        if (selected) faultToken_ = *selected;
      } catch (...) {
        fault_->setupFailed(StatusCode::kIOError);
      }
    }
    return inner_->set(k, v);
  }
  CoTryTask<void> clear(std::string_view k) override {
    recordFamily(k);
    return inner_->clear(k);
  }
  CoTryTask<void> setVersionstampedKey(std::string_view k, uint32_t o, std::string_view v) override {
    return inner_->setVersionstampedKey(k, o, v);
  }
  CoTryTask<void> setVersionstampedValue(std::string_view k, std::string_view v, uint32_t o) override {
    return inner_->setVersionstampedValue(k, v, o);
  }
  CoTryTask<void> commit() override {
    ++event_.rawCommitCalls;
    bool injected = false;
    if (fault_ && faultToken_) {
      try {
        if (rawEngine_ && dynamic_cast<kv::FDBTransaction *>(inner_.get())) {
          auto prepared = co_await fault_->beforeCommit(*inner_, *rawEngine_, faultToken_);
          if (prepared) injected = *prepared;
          else fault_->setupFailed(prepared.error().code());
        } else {
          fault_->setupFailed(StatusCode::kInvalidArg);
        }
      } catch (...) {
        fault_->setupFailed(StatusCode::kIOError);
      }
    }
    event_.approximateAttempted = true;
    const auto measuring = Clock::now();
    try {
      auto *fdb = dynamic_cast<kv::FDBTransaction *>(inner_.get());
      if (fdb) {
        auto size = co_await fdb->getApproximateSize();
        if (size && *size >= 0) {
          event_.approximateAvailable = true;
          event_.approximateBytes = *size;
        } else {
          event_.approximateError = size ? StatusCode::kDataCorruption : size.error().code();
        }
      } else {
        event_.approximateError = StatusCode::kNotImplemented;
      }
    } catch (...) {
      // The diagnostic never substitutes for the original commit outcome.
      // A successful commit with missing measurement fails report validation.
      event_.approximateError = StatusCode::kIOError;
    }
    event_.approximateMicros = micros(Clock::now() - measuring);
    event_.rawCommit = EcNativeTxnObservation::RawCommit::Unconfirmed;
    const auto committing = Clock::now();
    try {
      auto result = co_await inner_->commit();
      event_.commitMicros = micros(Clock::now() - committing);
      event_.rawCommit =
          result ? EcNativeTxnObservation::RawCommit::Succeeded : EcNativeTxnObservation::RawCommit::Failed;
      if (!result) event_.rawError = result.error().code();
      if (fault_) fault_->originalCommitted(injected, result ? StatusCode::kOK : result.error().code());
      co_return result;
    } catch (...) {
      event_.commitMicros = micros(Clock::now() - committing);
      throw;
    }
  }
  int64_t getCommittedVersion() override { return inner_->getCommittedVersion(); }

 private:
  static int64_t micros(Clock::duration elapsed) noexcept {
    return std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  }
  void recordFamily(std::string_view key) noexcept {
    // Bit positions record write calls, not commit/persistence proof or full IDs.
    constexpr std::array families{kv::KeyPrefix::EcFileExecution,
                                  kv::KeyPrefix::EcManifest,
                                  kv::KeyPrefix::EcTreeEdit,
                                  kv::KeyPrefix::EcTreeRoot,
                                  kv::KeyPrefix::EcFileSession,
                                  kv::KeyPrefix::EcTreeSourcePin};
    for (size_t i = 0; i < families.size(); ++i)
      if (key.starts_with(kv::toStr(families[i]))) event_.writtenFamilies |= uint32_t{1} << i;
  }
  std::unique_ptr<kv::IReadWriteTransaction> inner_;
  std::shared_ptr<EcNativeTxnObservation> observation_;
  std::shared_ptr<EcMountedTruncateFault> fault_;
  std::shared_ptr<kv::IKVEngine> rawEngine_;
  uint64_t faultToken_ = 0;
  EcNativeTxnObservation::Event event_;
  Clock::time_point started_ = Clock::now();
};

class EcObservedNativeEngine final : public kv::IKVEngine {
 public:
  EcObservedNativeEngine(std::shared_ptr<kv::IKVEngine> inner,
                         std::shared_ptr<EcNativeTxnObservation> observation,
                         std::shared_ptr<EcMountedTruncateFault> fault = nullptr)
      : inner_(std::move(inner)),
        observation_(std::move(observation)),
        fault_(std::move(fault)) {}
  std::unique_ptr<kv::IReadOnlyTransaction> createReadonlyTransaction() override {
    // Preserve the engine's read-only factory semantics. RMW service budgets
    // use createReadWriteTransaction even for their committed observations.
    return inner_->createReadonlyTransaction();
  }
  std::unique_ptr<kv::IReadWriteTransaction> createReadWriteTransaction() override {
    auto inner = inner_->createReadWriteTransaction();
    if (!inner) return nullptr;
    return std::make_unique<EcObservedNativeTransaction>(std::move(inner), observation_, fault_, inner_);
  }

 private:
  std::shared_ptr<kv::IKVEngine> inner_;
  std::shared_ptr<EcNativeTxnObservation> observation_;
  std::shared_ptr<EcMountedTruncateFault> fault_;
};
}  // namespace hf3fs::meta::server::detail
