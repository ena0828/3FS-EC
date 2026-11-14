#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <fstream>
#include <gtest/gtest.h>
#include <utility>

#include "client/ec/EcNamespaceJournal.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
Result<std::unique_ptr<EcFilePwriteJournal>> acceptedSession(const std::filesystem::path &path) {
  CHECK_RESULT(record, prepareEcPwriteSession({flat::Uid(701), Uuid::random()}, "namespace-test", true,
                                            "/original", {}, Uuid::zero(), 64, meta::kEcSessionRead));
  CHECK_RESULT(journal, EcFilePwriteJournal::create(path, record));
  EcPwriteRunProgress state;
  state.issued = true;
  state.shardBytes = 64;
  state.session.emplace();
  auto &i = state.session->intent;
  i.object = {meta::InodeId(710), Uuid::random()};
  i.birth = Uuid::random();
  i.owner = record.owner;
  i.session = record.session;
  i.openRequest = record.openRequest;
  i.rights = record.rights;
  RETURN_ON_ERROR(journal->append(state));
  return std::move(journal);
}
}  // namespace
TEST(TestEcNamespaceJournal, AcceptedAndClosedSessionBindDurableIdentityWithoutChangingOriginal) {
  folly::test::TemporaryDirectory temp;
  const auto root = std::filesystem::path(temp.path().string());
  auto session = acceptedSession(root / "session");
  ASSERT_OK(session);
  auto record = prepareEcUnlink(**session, "/original");
  ASSERT_OK(record);
  EXPECT_EQ(serde::serialize(record->session), serde::serialize(*(*session)->latest()->session));
  auto made = EcNamespaceJournal::create(root / "unlink", *record);
  ASSERT_OK(made);
  auto journal = std::move(*made);
  EXPECT_FALSE(EcNamespaceJournal::resume(root / "unlink"));
  EcNamespaceJournalState issued;
  issued.issued = true;
  ASSERT_OK(journal->append(issued));
  journal.reset();
  auto resumed = EcNamespaceJournal::resume(root / "unlink");
  ASSERT_OK(resumed);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*record));
  EXPECT_FALSE((*resumed)->latest()->acknowledged);
  auto acknowledged = *(*resumed)->latest();
  acknowledged.acknowledged = true;
  ASSERT_OK((*resumed)->append(acknowledged));
  EXPECT_FALSE((*resumed)->append(issued));  // A historical acknowledgement cannot regress.
  auto closed = *(*session)->latest();
  closed.session->state = meta::EcFileSessionState::Closed;
  ASSERT_OK((*session)->append(closed));
  auto afterClose = prepareEcUnlink(**session, "/alias");
  ASSERT_OK(afterClose);
  EXPECT_EQ(afterClose->session.intent.object, record->session.intent.object);
  EXPECT_EQ(afterClose->session.intent.birth, record->session.intent.birth);
  EXPECT_EQ(afterClose->session.state, meta::EcFileSessionState::Closed);
  EXPECT_NE(afterClose->request, record->request);  // Only an explicit new run generates another request.
}
TEST(TestEcNamespaceJournal, RejectsUnacceptedSessionPathDriftAndNoncanonicalCodec) {
  folly::test::TemporaryDirectory temp;
  const auto root = std::filesystem::path(temp.path().string());
  auto record = prepareEcPwriteSession({flat::Uid(701), Uuid::random()}, "namespace-test", true,
                                     "/original", {}, Uuid::zero(), 64, meta::kEcSessionWrite);
  ASSERT_OK(record);
  auto empty = EcFilePwriteJournal::create(root / "empty", *record);
  ASSERT_OK(empty);
  EXPECT_FALSE(prepareEcUnlink(**empty, "/original"));
  auto session = acceptedSession(root / "session");
  ASSERT_OK(session);
  for (const auto &path : {"relative", "/", "/a/../b", "/a/./b", "/a/"})
    EXPECT_FALSE(prepareEcUnlink(**session, path));
  auto run = prepareEcUnlink(**session, "/original");
  ASSERT_OK(run);
  auto raw = encodeEcNamespaceRun(*run);
  ASSERT_OK(raw);
  EXPECT_FALSE(decodeEcNamespaceRun(*raw + "x"));
  auto wrong = *run;
  wrong.session.intent.birth = Uuid::zero();
  EXPECT_FALSE(encodeEcNamespaceRun(wrong));
  wrong = *run;
  wrong.session.state = meta::EcFileSessionState::Closing;
  EXPECT_FALSE(encodeEcNamespaceRun(wrong));
  wrong = *run;
  wrong.request = wrong.session.intent.openRequest;
  EXPECT_FALSE(encodeEcNamespaceRun(wrong));
  EcNamespaceJournalState impossible;
  impossible.acknowledged = true;
  EXPECT_FALSE(impossible.validate(*run));
}
TEST(TestEcNamespaceJournal, ResumeRejectsMissingLockGapsAndLinkedDirectory) {
  folly::test::TemporaryDirectory temp;
  const auto root = std::filesystem::path(temp.path().string());
  auto session = acceptedSession(root / "session");
  ASSERT_OK(session);
  auto record = prepareEcUnlink(**session, "/original");
  ASSERT_OK(record);
  auto made = EcNamespaceJournal::create(root / "unlink", *record);
  ASSERT_OK(made);
  auto journal = std::move(*made);
  EcNamespaceJournalState state;
  state.issued = true;
  ASSERT_OK(journal->append(state));
  journal.reset();
  std::filesystem::create_directory_symlink(root / "unlink", root / "alias");
  EXPECT_FALSE(EcNamespaceJournal::resume(root / "alias"));
  std::filesystem::rename(root / "unlink/state-00000000000000000000.data",
                          root / "unlink/state-00000000000000000001.data");
  EXPECT_FALSE(EcNamespaceJournal::resume(root / "unlink"));
  std::filesystem::rename(root / "unlink/state-00000000000000000001.data",
                          root / "unlink/state-00000000000000000000.data");
  std::filesystem::remove(root / "unlink/.lock");
  EXPECT_FALSE(EcNamespaceJournal::resume(root / "unlink"));
  EXPECT_FALSE(std::filesystem::exists(root / "unlink/.lock"));
}
}  // namespace hf3fs::client::ec
