#include "storage/worker/AllocateWorker.h"

#include <memory>

#include "common/monitor/Recorder.h"
#include "common/utils/Duration.h"
#include "common/utils/Result.h"
#include "common/utils/UtcTime.h"
#include "fbs/mgmtd/MgmtdTypes.h"
#include "storage/service/Components.h"

namespace hf3fs::storage {

AllocateWorker::AllocateWorker(const Config &config, Components &components)
    : config_(config),
      components_(components),
      executors_(std::make_pair(1u, 1u), std::make_shared<folly::NamedThreadFactory>("Allocate")) {}

Result<Void> AllocateWorker::start() {
  if (components_.storageTargets.ecOnly()) {
    XLOG(INFO, "EC-only storage disables legacy compaction until identity-preserving durable relocation is supported");
  }
  executors_.add([this] { loop(); });
  started_ = true;
  return Void{};
}

Result<Void> AllocateWorker::stopAndJoin() {
  stopping_ = true;
  cond_.notify_one();
  for (int i = 0; started_ && !stopped_; ++i) {
    XLOGF_IF(INFO, i % 5 == 0, "Waiting for AllocateWorker@{}::loop stop...", fmt::ptr(this));
    std::this_thread::sleep_for(100_ms);
  }
  executors_.join();
  return Void{};
}

void AllocateWorker::loop() {
  auto nextTrim = RelativeTime::zero();
  while (!stopping_) {
    auto lock = std::unique_lock(mutex_);
    if (cond_.wait_for(lock, 100_ms, [&] { return stopping_.load(); })) {
      break;
    }

    auto minRemainGroups = config_.min_remain_groups();
    auto maxRemainGroups = config_.max_remain_groups();
    auto minRemainUltraGroups = config_.min_remain_ultra_groups();
    auto maxRemainUltraGroups = config_.max_remain_ultra_groups();
    auto maxReserved = config_.max_reserved_chunks();
    for (auto &engine : components_.storageTargets.engines()) {
      engine->allocate_groups(minRemainGroups, maxRemainGroups, 128);
      engine->allocate_ultra_groups(minRemainUltraGroups, maxRemainUltraGroups, 32);
      // The legacy move path resets the operation etag and does not establish
      // the EC relocation durability contract. Preallocation remains enabled.
      if (!components_.storageTargets.ecOnly()) engine->compact_groups(maxReserved);
    }
    if (!stopping_ && config_.ec_empty_group_trim() && RelativeTime::now() >= nextTrim) {
      const chunk_engine::RawEcStageTrimLimits limits{config_.ec_trim_max_groups(),
                                                      config_.ec_trim_max_bytes().toInt(),
                                                      config_.ec_trim_keep_empty_groups()};
      // Synchronous owned call. stopAndJoin cannot return while a punch/fsync
      // is still in flight. There is no detached trim or timeout-as-success.
      const auto result = components_.storageTargets.trimEmptyGroups(limits);
      nextTrim = RelativeTime::now() + config_.ec_trim_interval();
      const auto &r = result.report;
      if (result.status.error_code || !r.complete) {
        XLOGF(ERR,
              "EC empty-group trim code={} error={} complete={} attempted={} charged={} "
              "punch_confirmed={} withdrawn={} extent_unconfirmed={} quarantined={} errno={}",
              result.status.error_code,
              std::string(result.status.error),
              r.complete,
              r.attempted_groups,
              r.charged_bytes,
              r.punch_confirmed_bytes,
              r.withdrawn_preallocation_bytes,
              r.unconfirmed_extent_bytes,
              r.quarantined_groups,
              r.os_errno);
      } else if (r.attempted_groups || r.oversized_classes) {
        XLOGF(INFO,
              "EC empty-group trim attempted={} charged={} punch_confirmed={} withdrawn={} "
              "extent_unconfirmed={} reconciled={} oversized={}; counts are not statfs free bytes",
              r.attempted_groups,
              r.charged_bytes,
              r.punch_confirmed_bytes,
              r.withdrawn_preallocation_bytes,
              r.unconfirmed_extent_bytes,
              r.reconciled_groups,
              r.oversized_classes);
      }
    }
  }

  XLOGF(INFO, "AllocateWorker@{}::loop stopped", fmt::ptr(this));
  stopped_ = true;
}

}  // namespace hf3fs::storage
