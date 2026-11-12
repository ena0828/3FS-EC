#pragma once

#include <atomic>
#include <condition_variable>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <mutex>

#include "storage/service/TargetMap.h"

namespace hf3fs::storage {

struct Components;

class AllocateWorker {
 public:
  class Config : public ConfigBase<Config> {
    CONFIG_HOT_UPDATED_ITEM(min_remain_groups, 4ul);
    CONFIG_HOT_UPDATED_ITEM(max_remain_groups, 8ul);
    CONFIG_HOT_UPDATED_ITEM(min_remain_ultra_groups, 0ul);  // greater than 4MiB
    CONFIG_HOT_UPDATED_ITEM(max_remain_ultra_groups, 4ul);
    CONFIG_HOT_UPDATED_ITEM(max_reserved_chunks, 1_GB);
    // Explicit opt-in. These are per-process round limits across all disks.
    CONFIG_HOT_UPDATED_ITEM(ec_empty_group_trim, false);
    CONFIG_HOT_UPDATED_ITEM(ec_trim_interval, 5_s, [](const auto &v) { return v >= 100_ms && v <= 1_h; });
    CONFIG_HOT_UPDATED_ITEM(ec_trim_max_groups, 1u, [](auto v) { return v >= 1 && v <= 64; });
    CONFIG_HOT_UPDATED_ITEM(ec_trim_max_bytes, 256_MB, [](auto v) { return v > 0_B && v <= 64_GB; });
    CONFIG_HOT_UPDATED_ITEM(ec_trim_keep_empty_groups, 1u, [](auto v) { return v <= 1024; });
  };

  AllocateWorker(const Config &config, Components &components);

  Result<Void> start();

  Result<Void> stopAndJoin();

 protected:
  void loop();

 private:
  ConstructLog<"storage::AllocateWorker"> constructLog_;
  const Config &config_;
  Components &components_;
  folly::CPUThreadPoolExecutor executors_;

  std::mutex mutex_;
  std::condition_variable cond_;
  std::atomic<bool> stopping_ = false;
  std::atomic<bool> started_ = false;
  std::atomic<bool> stopped_ = false;
};

}  // namespace hf3fs::storage
