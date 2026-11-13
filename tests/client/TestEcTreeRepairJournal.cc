#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <gtest/gtest.h>

#include "client/ec/EcTreeRepairJournal.h"
#include "tests/GtestHelpers.h"
namespace hf3fs::client::ec {
namespace {
// Frozen 2119 v1 field order. Deliberately independent of the production mode
// enum and struct declarations; adding fields to those must not alter old bytes.
struct LegacyRepairIntentV1 {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, meta::EcObjectRef{});
  SERDE_STRUCT_FIELD(owner, meta::EcOwner{});
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(request, Uuid::zero());
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(child, Uuid::zero());
  SERDE_STRUCT_FIELD(sourcePin, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedRoot, Uuid::zero());
  SERDE_STRUCT_FIELD(expectedSequence, uint64_t{});
  SERDE_STRUCT_FIELD(expectedEpoch, uint64_t{});
  SERDE_STRUCT_FIELD(stripe, uint64_t{});
  SERDE_STRUCT_FIELD(replacementMask, uint16_t{});
  SERDE_STRUCT_FIELD(mode, uint8_t{1});
  SERDE_STRUCT_FIELD(selection, meta::EcV2RepairSelection{});
  SERDE_STRUCT_FIELD(nodeIds, (std::array<Uuid, 16>{}));
};
struct LegacyRepairRecordV1 {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(intent, LegacyRepairIntentV1{});
  SERDE_STRUCT_FIELD(state, uint8_t{1});
  SERDE_STRUCT_FIELD(child, meta::EcFileChildRecord{});
};
struct LegacyRepairRunV1 {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(intent, LegacyRepairIntentV1{});
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(prepareRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(publishRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(closeRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());
};
LegacyRepairIntentV1 legacyIntent(const meta::EcFileRepairIntent &i) {
  LegacyRepairIntentV1 old;
  old.version = i.version;
  old.object = i.object;
  old.owner = i.owner;
  old.session = i.session;
  old.request = i.request;
  old.operation = i.operation;
  old.child = i.child;
  old.sourcePin = i.sourcePin;
  old.expectedRoot = i.expectedRoot;
  old.expectedSequence = i.expectedSequence;
  old.expectedEpoch = i.expectedEpoch;
  old.stripe = i.stripe;
  old.replacementMask = i.replacementMask;
  old.mode = static_cast<uint8_t>(i.mode);
  old.selection = i.selection;
  old.nodeIds = i.nodeIds;
  return old;
}
}  // namespace

TEST(TestEcTreeRepairJournal, LegacyIntentRecordAndJournalBytesRemainCompatible) {
  meta::EcFileSessionRecord session;
  session.intent.object = {meta::InodeId(713), Uuid::random()};
  session.intent.birth = Uuid::random();
  session.intent.owner = {flat::Uid(703), Uuid::random()};
  session.intent.session = Uuid::random();
  session.intent.rights = 3;
  meta::EcTreeRoot root;
  root.object = session.intent.object;
  root.birth = session.intent.birth;
  root.root = Uuid::random();
  root.epoch = 4;
  root.sequence = 17;
  const std::array<uint8_t, 10> selected{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  for (uint8_t mode = 1; mode <= 3; ++mode) {
    auto run = prepareEcTreeRepair(session, root, "legacy-repair", 0, 3,
                                  static_cast<meta::EcFileRepairMode>(mode), selected, 4);
    ASSERT_OK(run);
    auto intent = legacyIntent(run->intent);
    EXPECT_EQ(serde::serialize(run->intent), serde::serialize(intent));
    meta::EcFileRepairRecord record;
    record.intent = run->intent;
    LegacyRepairRecordV1 oldRecord;
    oldRecord.intent = intent;
    EXPECT_EQ(serde::serialize(record), serde::serialize(oldRecord)); // ECFR value shape.
    LegacyRepairRunV1 old;
    old.cluster = run->cluster;
    old.birth = run->birth;
    old.intent = intent;
    old.queryRequest = run->queryRequest;
    old.prepareRequest = run->prepareRequest;
    old.publishRequest = run->publishRequest;
    old.closeRequest = run->closeRequest;
    old.outputRevocation = run->outputRevocation;
    old.sourceRevocation = run->sourceRevocation;
    const auto original = std::string("ECTREEREPAIR1\n") + serde::serialize(old);
    auto encoded = encodeEcTreeRepairRun(*run);
    ASSERT_OK(encoded);
    EXPECT_EQ(*encoded, original);
    auto decoded = decodeEcTreeRepairRun(original);
    ASSERT_OK(decoded);
    EXPECT_EQ(serde::serialize(*decoded), serde::serialize(*run));
  }
  auto direct = prepareEcTreeRepair(session, root, "direct-repair", 0, 3,
                                   meta::EcFileRepairMode::HelperChainDirect, selected, 4);
  ASSERT_OK(direct);
  folly::test::TemporaryDirectory temp;
  const auto path = std::filesystem::path(temp.path().string()) / "direct";
  auto made = EcTreeRepairJournal::create(path, *direct);
  ASSERT_OK(made);
  EcTreeRepairState state;
  state.issued = true;
  ASSERT_OK((*made)->append(state));
  made->reset();
  auto resumed = EcTreeRepairJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ((*resumed)->record().intent.mode, meta::EcFileRepairMode::HelperChainDirect);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*direct));
  EXPECT_TRUE((*resumed)->latest()->issued);
  EXPECT_FALSE((*resumed)->latest()->dataComplete);
  auto unknown = *direct;
  unknown.intent.mode = static_cast<meta::EcFileRepairMode>(5);
  EXPECT_FALSE(unknown.validate());
  const auto invalid = std::string("ECTREEREPAIR1\n") + serde::serialize(unknown);
  EXPECT_FALSE(decodeEcTreeRepairRun(invalid));
}

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
