#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <gtest/gtest.h>

#include "client/ec/EcTruncateJournal.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
TEST(TestEcTruncateJournal, FixedCasAndTerminalProgressSurviveExclusiveResume) {
  meta::EcFileSessionRecord session;
  session.intent.object = {meta::InodeId(777), Uuid::random()};
  session.intent.birth = Uuid::random();
  session.intent.owner = {flat::Uid(1000), Uuid::random()};
  session.intent.session = Uuid::random();
  session.intent.openRequest = Uuid::random();
  session.intent.rights = meta::kEcSessionWrite;
  meta::EcTreeRoot root;
  root.object = session.intent.object;
  root.birth = session.intent.birth;
  root.root = Uuid::random();
  root.epoch = 4;
  root.sequence = 7;
  root.visibleLength = 999;
  auto made = prepareEcFileTruncate(session, root, "truncate-test", 33);
  ASSERT_OK(made);
  auto denied = session;
  denied.intent.rights = meta::kEcSessionRead;
  ASSERT_ERROR(prepareEcFileTruncate(denied, root, "truncate-test", 33), MetaCode::kNoPermission);
  auto bytes = encodeEcTruncateRun(*made);
  ASSERT_OK(bytes);
  auto parsed = decodeEcTruncateRun(*bytes);
  ASSERT_OK(parsed);
  EXPECT_EQ(serde::serialize(*made), serde::serialize(*parsed));
  EXPECT_FALSE(decodeEcTruncateRun(*bytes + "extra"));
  folly::test::TemporaryDirectory temp;
  const auto path = std::filesystem::path(temp.path().string()) / "truncate";
  auto created = EcTruncateJournal::create(path, *made);
  ASSERT_OK(created);
  auto j = std::move(*created);
  EXPECT_FALSE(EcTruncateJournal::resume(path));
  EcTruncateJournalState s;
  s.beginIssued = true;
  meta::EcFileTruncateProgress progress;
  progress.intent = made->intent;
  progress.observed.emplace();
  auto &o = *progress.observed;
  o.birth = root.birth;
  o.fencedRoot = root;
  ++o.fencedRoot.epoch;
  ++o.fencedRoot.sequence;
  o.tailRequired = true;
  s.progress = progress;
  ASSERT_OK(j->append(s));
  auto bad = s;
  bad.progress->intent.expectedSequence++;
  EXPECT_FALSE(j->append(bad));
  o.state = meta::EcFileTruncateState::Published;
  o.publishedRoot = o.fencedRoot;
  ++o.publishedRoot->sequence;
  o.publishedRoot->root = made->intent.nodeIds[15];
  o.publishedRoot->visibleLength = 33;
  o.outputDrained = true;
  s.progress = progress;
  s.advanceIssued = true;
  ASSERT_OK(j->append(s));
  auto missing = s;
  missing.progress->observed.reset();
  EXPECT_FALSE(j->append(missing));
  auto changed = s;
  changed.progress->observed->state = meta::EcFileTruncateState::Aborted;
  changed.progress->observed->publishedRoot.reset();
  EXPECT_FALSE(j->append(changed));
  s.closeIssued = true;
  s.progress->observed->sourceReleased = true;
  ASSERT_OK(j->append(s));
  j.reset();
  auto resumed = EcTruncateJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*made));
  ASSERT_TRUE((*resumed)->latest()->progress->observed);
  EXPECT_TRUE((*resumed)->latest()->progress->observed->outputDrained);
  EXPECT_TRUE((*resumed)->latest()->progress->observed->sourceReleased);
}
}  // namespace hf3fs::client::ec
