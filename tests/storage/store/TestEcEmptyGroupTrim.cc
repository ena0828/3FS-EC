#include "storage/store/StorageTargets.h"
#include "storage/worker/AllocateWorker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
namespace {
TEST(TestEcEmptyGroupTrim, DefaultDisabledAndProfileBudgetRejectionsDoNotLoadOrMutateEngines) {
  AllocateWorker::Config worker;
  EXPECT_FALSE(worker.ec_empty_group_trim());
  EXPECT_EQ(worker.ec_trim_max_groups(), 1);
  EXPECT_EQ(worker.ec_trim_max_bytes().toInt(), 256ULL << 20);
  EXPECT_EQ(worker.ec_trim_keep_empty_groups(), 1);
  AtomicallyTargetMap map;
  StorageTargets::Config config;
  StorageTargets targets(config, map);
  const chunk_engine::RawEcStageTrimLimits valid{1, 256ULL << 20, 0};
  auto v1 = targets.trimEmptyGroups(valid);
  EXPECT_EQ(v1.status.error_code, StatusCode::kInvalidArg);
  EXPECT_EQ(v1.report.attempted_groups, 0);
  config.set_ec_only(true);
  config.set_ec_staging_v2(true);
  auto v2 = targets.trimEmptyGroups(valid);
  EXPECT_EQ(v2.status.error_code, StatusCode::kInvalidArg);
  EXPECT_EQ(v2.report.attempted_groups, 0);
  config.set_ec_exact_gc(true);
  for (auto invalid : {chunk_engine::RawEcStageTrimLimits{0, 1, 0},
                       chunk_engine::RawEcStageTrimLimits{65, 1, 0},
                       chunk_engine::RawEcStageTrimLimits{1, 0, 0},
                       chunk_engine::RawEcStageTrimLimits{1, (64ULL << 30) + 1, 0},
                       chunk_engine::RawEcStageTrimLimits{1, 1, 1025}}) {
    const auto result = targets.trimEmptyGroups(invalid);
    EXPECT_EQ(result.status.error_code, StatusCode::kInvalidArg);
    EXPECT_EQ(result.report.attempted_groups, 0);
    EXPECT_TRUE(result.report.complete);
  }
  const auto empty = targets.trimEmptyGroups(valid);
  EXPECT_EQ(empty.status.error_code, 0);
  EXPECT_EQ(empty.report.attempted_groups, 0);
}
}  // namespace
}  // namespace hf3fs::storage
