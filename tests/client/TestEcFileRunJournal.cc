#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <folly/json.h>
#include <fstream>
#include <gtest/gtest.h>
#include <limits>
#include <sys/stat.h>

#include "client/ec/EcFileRunJournal.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
EcFileRunRecord readRecord(uint64_t offset = 70, uint64_t length = 120) {
  EcFileRunRecord r;
  r.cluster = "file-journal-test";
  r.owner = {flat::Uid(41), Uuid::random()};
  r.object = {meta::InodeId(100), Uuid::random()};
  r.epoch = 1;
  r.shardBytes = 8;
  r.offset = offset;
  r.length = length;
  r.describeRequest = Uuid::random();
  r.rangeId = Uuid::random();
  r.rangeRequest = Uuid::random();
  auto plan = planEcFileRead(r.shardBytes, offset, length);
  if (!plan) throw std::runtime_error("invalid test plan");
  r.count = plan->count;
  for (size_t i = 0; i != r.count; ++i) {
    auto &slot = r.slots[i];
    slot.stripe = plan->slices[i].stripe;
    slot.pin = Uuid::random();
    slot.acquireRequest = Uuid::random();
    slot.releaseRequest = Uuid::random();
  }
  return r;
}
EcFileRunRecord appendRecord() {
  auto r = readRecord(160, 160);
  r.kind = EcFileRunKind::AppendAt;
  r.rangeId = Uuid::zero();
  r.rangeRequest = Uuid::zero();
  r.appendId = Uuid::random();
  r.inputPath = "/explicit-input";
  r.contentSha256[0] = 1;
  for (size_t i = 0; i != r.count; ++i) {
    auto &slot = r.slots[i];
    slot.pin = slot.acquireRequest = slot.releaseRequest = Uuid::zero();
    slot.mutation = {Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random()};
    slot.contentSha256[0] = static_cast<uint8_t>(i + 1);
  }
  return r;
}
std::filesystem::path runPath(const folly::test::TemporaryDirectory &dir) {
  return std::filesystem::path(dir.path().string()) / "file-run";
}
}  // namespace
TEST(TestEcFileRunJournal, ExactDecimalAndFixedSlotsRejectCoercions) {
  auto r = readRecord(UINT64_MAX, 0);
  r.epoch = UINT64_MAX;
  auto text = encodeEcFileRunRecord(r);
  ASSERT_OK(text);
  auto reopened = decodeEcFileRunRecord(*text);
  ASSERT_OK(reopened);
  EXPECT_EQ(reopened->offset, UINT64_MAX);
  EXPECT_EQ(reopened->epoch, UINT64_MAX);
  auto value = folly::parseJson(*text);
  EXPECT_EQ(value["offset"].getString(), "18446744073709551615");
  value["offset"] = 1.0;
  EXPECT_FALSE(decodeEcFileRunRecord(folly::toJson(value)));
  value = folly::parseJson(*text);
  value["count"] = false;
  EXPECT_FALSE(decodeEcFileRunRecord(folly::toJson(value)));
  value = folly::parseJson(*text);
  value["offset"] = "01";
  EXPECT_FALSE(decodeEcFileRunRecord(folly::toJson(value)));
  value = folly::parseJson(*text);
  value["slots"].push_back(value["slots"][0]);
  EXPECT_FALSE(decodeEcFileRunRecord(folly::toJson(value)));
  value = folly::parseJson(*text);
  value["unexpected"] = true;
  EXPECT_FALSE(decodeEcFileRunRecord(folly::toJson(value)));
}
TEST(TestEcFileRunJournal, UnknownAcquireKeepsIdentityAndUnreadPinsNeedTerminalObservations) {
  folly::test::TemporaryDirectory temporary;
  auto r = readRecord();
  auto path = runPath(temporary);
  auto made = EcFileRunJournal::create(path, r);
  ASSERT_OK(made);
  auto &j = *made;
  EcFileRunProgress p;
  p.acquisitionIssued = true;
  p.errorCode = TransactionCode::kMaybeCommitted;
  ASSERT_OK(j->append(p));
  // Query missing is only another observation, not permission to discard IDs.
  p.errorCode = StatusCode::kKVStoreNotFound;
  ASSERT_OK(j->append(p));
  p.acquisitionIssued = false;
  EXPECT_FALSE(j->append(p));
  p.acquisitionIssued = true;
  j.reset();
  auto resumed = EcFileRunJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ((*resumed)->record().rangeId, r.rangeId);
  EXPECT_EQ((*resumed)->record().rangeRequest, r.rangeRequest);
  EXPECT_EQ((*resumed)->record().slots[2].pin, r.slots[2].pin);
  p = *(*resumed)->latest();
  p.snapshotObserved = true;
  p.actualPins = 3;
  p.snapshotBytes = "bounded fixture snapshot: format tests only";
  p.errorCode = 0;
  ASSERT_OK((*resumed)->append(p));
  p.localComplete = true;
  p.releasedMask = 1;
  ASSERT_OK((*resumed)->append(p));
  EXPECT_FALSE((*resumed)->latest()->allPinsReleased());
  p.releasedMask = 7;
  ASSERT_OK((*resumed)->append(p));
  EXPECT_TRUE((*resumed)->latest()->allPinsReleased());
  p.snapshotBytes += "different";
  EXPECT_FALSE((*resumed)->append(p));
}
TEST(TestEcFileRunJournal, AppendRequiresPersistedIssueAndPreservesTheConfirmedPrefix) {
  folly::test::TemporaryDirectory temporary;
  auto r = appendRecord();
  auto made = EcFileRunJournal::create(runPath(temporary), r);
  ASSERT_OK(made);
  EcFileRunProgress p;
  p.appendStates[0] = EcFileAppendState::Published;
  EXPECT_FALSE((*made)->append(p));
  p.appendStates[0] = EcFileAppendState::Issued;
  ASSERT_OK((*made)->append(p));
  p.appendStates[0] = EcFileAppendState::Published;
  p.appendStates[1] = EcFileAppendState::Issued;
  EXPECT_FALSE((*made)->append(p));  // The first Published observation must be durable before second dispatch.
  p.appendStates[1] = EcFileAppendState::NotStarted;
  ASSERT_OK((*made)->append(p));
  p.appendStates[1] = EcFileAppendState::Issued;
  ASSERT_OK((*made)->append(p));
  p.appendStates[1] = EcFileAppendState::Indeterminate;
  p.errorCode = StorageCode::kEcSealOutcomeUnknown;
  ASSERT_OK((*made)->append(p));
  EXPECT_EQ((*made)->latest()->confirmedPrefixBytes(r), 80);
  p.appendStates[1] = EcFileAppendState::NotStarted;
  EXPECT_FALSE((*made)->append(p));
  (*made).reset();
  auto restored = EcFileRunJournal::resume(runPath(temporary));
  ASSERT_OK(restored);
  EXPECT_EQ((*restored)->latest()->confirmedPrefixBytes(r), 80);
  EXPECT_EQ((*restored)->record().slots[1].mutation.operation, r.slots[1].mutation.operation);
}
TEST(TestEcFileRunJournal, RecordOnlyResumeExclusiveOwnerAndMalformedSequenceFailClosed) {
  folly::test::TemporaryDirectory temporary;
  const auto path = runPath(temporary);
  const auto r = readRecord();
  auto made = EcFileRunJournal::create(path, r);
  ASSERT_OK(made);
  EXPECT_FALSE(EcFileRunJournal::create(path, r));
  ASSERT_ERROR(EcFileRunJournal::resume(path), StorageClientCode::kResourceBusy);
  struct stat st {};
  ASSERT_EQ(::stat((path / "record.json").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600);
  made->reset();
  auto resumed = EcFileRunJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_FALSE((*resumed)->latest());
  EcFileRunProgress p;
  p.acquisitionIssued = true;
  ASSERT_OK((*resumed)->append(p));
  resumed->reset();
  std::filesystem::rename(path / "state-00000000000000000000.json", path / "state-00000000000000000002.json");
  EXPECT_FALSE(EcFileRunJournal::resume(path));
}
}  // namespace hf3fs::client::ec
