#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <gtest/gtest.h>

#include "client/ec/EcTreeRepairJournal.h"
#include "tests/GtestHelpers.h"
namespace hf3fs::client::ec {
TEST(TestEcTreeRepairJournal, FixedSelectionSurvivesUnknownAndExclusiveResume) {
  meta::EcFileSessionRecord s;
  s.intent.object = {meta::InodeId(712), Uuid::random()};
  s.intent.birth = Uuid::random();
  s.intent.owner = {flat::Uid(701), Uuid::random()};
  s.intent.session = Uuid::random();
  s.intent.openRequest = Uuid::random();
  s.intent.rights = 3;
  meta::EcTreeRoot root;
  root.object = s.intent.object;
  root.birth = s.intent.birth;
  root.root = Uuid::random();
  root.sequence = 9;
  root.epoch = 2;
  root.visibleLength = 4096;
  std::array<uint8_t, 10> selected{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  auto run = prepareEcTreeRepair(s, root, "tree-repair", 0, 3, meta::EcFileRepairMode::HelperChain, selected);
  ASSERT_OK(run);
  folly::test::TemporaryDirectory temp;
  auto path = std::filesystem::path(temp.path().string()) / "repair";
  auto created = EcTreeRepairJournal::create(path, *run);
  ASSERT_OK(created);
  auto journal = std::move(*created);
  EXPECT_FALSE(EcTreeRepairJournal::resume(path));
  EcTreeRepairState state;
  state.issued = true;
  ASSERT_OK(journal->append(state));
  // Issued with no response remains the original operation, never a new plan.
  journal.reset();
  auto resumed = EcTreeRepairJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*run));
  EXPECT_TRUE((*resumed)->latest()->issued);
  auto duplicate = *run;
  duplicate.intent.selection.sourceOrder[1] = 2;
  EXPECT_FALSE(duplicate.validate());
  auto selectedMissing = *run;
  selectedMissing.intent.selection.sourceOrder[0] = 0;
  EXPECT_FALSE(selectedMissing.validate());
  auto wrongRights = s;
  wrongRights.intent.rights = meta::kEcSessionWrite;
  EXPECT_FALSE(
      prepareEcTreeRepair(wrongRights, root, "tree-repair", 0, 3, meta::EcFileRepairMode::ClientPipeline, selected));
  auto forged = state;
  forged.progress.sourceReleased = true;
  EXPECT_FALSE((*resumed)->append(forged));
}
}  // namespace hf3fs::client::ec
