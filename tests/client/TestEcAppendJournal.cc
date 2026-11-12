#include <array>
#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include "client/ec/EcAppendJournal.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
TEST(TestEcAppendJournal, AcceptedOffsetAndBarrierSurviveExclusiveResumeWithoutNewParent) {
  meta::EcFileSessionRecord s;
  s.intent.object = {meta::InodeId(710), Uuid::random()};
  s.intent.birth = Uuid::random();
  s.intent.owner = {flat::Uid(701), Uuid::random()};
  s.intent.session = Uuid::random();
  s.intent.openRequest = Uuid::random();
  s.intent.rights = meta::kEcSessionWrite;
  folly::test::TemporaryDirectory temp;
  const auto root = std::filesystem::path(temp.path().string());
  const std::string data = "actual append bytes";
  const auto bytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(data.data()), data.size());
  auto made =
      prepareEcAppend(s, 64, "append-journal", (root / "input").string(), (root / "append" / "pwrite").string(), bytes);
  ASSERT_OK(made);
  auto created = EcAppendJournal::create(root / "append", *made);
  ASSERT_OK(created);
  auto journal = std::move(*created);
  EXPECT_FALSE(EcAppendJournal::resume(root / "append"));
  EcAppendJournalState state;
  state.issued = true;
  ASSERT_OK(journal->append(state));
  meta::EcFileAppendRecord a;
  a.intent = made->appendIntent;
  a.birth = s.intent.birth;
  a.acceptedRoot.object = s.intent.object;
  a.acceptedRoot.birth = s.intent.birth;
  a.acceptedRoot.epoch = 3;
  a.acceptedRoot.sequence = 7;
  a.acceptedRoot.visibleLength = 639;
  auto &p = a.parent;
  p.epoch = 3;
  p.sessionSequence = 1;
  p.intent.object = s.intent.object;
  p.intent.owner = s.intent.owner;
  p.intent.session = s.intent.session;
  p.intent.request = a.intent.operation;
  p.intent.offset = 639;
  p.intent.length = data.size();
  p.intent.inputSha256 = a.intent.inputSha256;
  state.accepted = a;
  ASSERT_OK(journal->append(state));
  auto child = prepareEcPwriteFromAcceptedParent(s, 64, "append-journal", p, made->inputPath, bytes);
  ASSERT_OK(child);
  EXPECT_EQ(child->kind, EcPwriteRunKind::AcceptedAppend);
  EXPECT_EQ(child->operation, a.intent.operation);
  ASSERT_EQ(child->count, 2);
  EXPECT_EQ(child->children[1].intent.expectedPrefix, 1u);
  auto createdChild = EcFilePwriteJournal::create(made->childDirectory, *child);
  ASSERT_OK(createdChild);
  auto childJournal = std::move(*createdChild);
  childJournal.reset();
  auto drift = state;
  drift.accepted->parent.intent.offset++;
  EXPECT_FALSE(journal->append(drift));
  auto missing = state;
  missing.accepted.reset();
  EXPECT_FALSE(journal->append(missing));
  journal.reset();
  auto resumed = EcAppendJournal::resume(root / "append");
  ASSERT_OK(resumed);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*made));
  ASSERT_TRUE((*resumed)->latest()->accepted);
  EXPECT_EQ((*resumed)->latest()->accepted->parent.intent.offset, 639u);
  auto resumedChild = EcFilePwriteJournal::resume(made->childDirectory);
  ASSERT_OK(resumedChild);
  EXPECT_EQ(serde::serialize((*resumedChild)->record()), serde::serialize(*child));
  auto barrier = prepareEcSync(s, "append-journal");
  ASSERT_OK(barrier);
  auto sync = EcAppendJournal::create(root / "sync", *barrier);
  ASSERT_OK(sync);
  EcAppendJournalState bs;
  bs.issued = true;
  bs.synced.emplace();
  bs.synced->intent = barrier->syncIntent;
  bs.synced->root = a.acceptedRoot;
  ASSERT_OK((*sync)->append(bs));
  auto changed = bs;
  changed.synced->root.sequence++;
  EXPECT_FALSE((*sync)->append(changed));
}
TEST(TestEcAppendJournal, ResumeRejectsUnboundOrUnsafeChildrenAndKeepsSyncStrict) {
  const std::array<const char *, 9> cases = {"regular-file",
                                             "symlink",
                                             "public-directory",
                                             "unknown-directory",
                                             "different-child-name",
                                             "external-child-binding",
                                             "sync-has-no-child",
                                             "bound-child-plus-unknown-file",
                                             "nonlocal-lexical-binding"};
  for (size_t which = 0; which < cases.size(); ++which) {
    SCOPED_TRACE(cases[which]);
    meta::EcFileSessionRecord session;
    session.intent.object = {meta::InodeId(711), Uuid::random()};
    session.intent.birth = Uuid::random();
    session.intent.owner = {flat::Uid(701), Uuid::random()};
    session.intent.session = Uuid::random();
    session.intent.openRequest = Uuid::random();
    session.intent.rights = meta::kEcSessionWrite;
    folly::test::TemporaryDirectory temp;
    const auto root = std::filesystem::path(temp.path().string());
    const auto run = root / "append";
    auto child = run / "pwrite";
    if (which == 4) child = run / "other-child";
    if (which == 5) child = root / "pwrite";
    if (which == 8) child = run / "subdirectory" / ".." / "pwrite";
    const std::string data = "fixed append payload";
    const auto bytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(data.data()), data.size());
    auto record =
        which == 6
            ? prepareEcSync(session, "append-child-validation")
            : prepareEcAppend(session, 64, "append-child-validation", (root / "input").string(), child.string(), bytes);
    ASSERT_OK(record);
    auto created = EcAppendJournal::create(run, *record);
    ASSERT_OK(created);
    auto journal = std::move(*created);
    journal.reset();
    // A bound child need not exist before issuance; external child bindings
    // remain valid but cannot authorize a same-basename entry in this run.
    auto clean = EcAppendJournal::resume(run);
    ASSERT_OK(clean);
    journal = std::move(*clean);
    journal.reset();
    const auto entry = run / (which == 3 ? "unknown-child" : "pwrite");
    if (which == 0) {
      std::ofstream file(entry);
      ASSERT_TRUE(file.is_open());
      file << "not a directory";
      ASSERT_TRUE(file.good());
      file.close();
      ASSERT_EQ(::chmod(entry.c_str(), 0600), 0);
    } else if (which == 1) {
      const auto target = root / "symlink-target";
      ASSERT_TRUE(std::filesystem::create_directory(target));
      ASSERT_EQ(::chmod(target.c_str(), 0700), 0);
      std::filesystem::create_directory_symlink(target, entry);
    } else {
      ASSERT_TRUE(std::filesystem::create_directory(entry));
      ASSERT_EQ(::chmod(entry.c_str(), which == 2 ? 0750 : 0700), 0);
      if (which == 7) {
        std::ofstream file(run / "unrecognized.data");
        ASSERT_TRUE(file.is_open());
        file << "must not be ignored";
        ASSERT_TRUE(file.good());
      }
    }
    EXPECT_FALSE(EcAppendJournal::resume(run));
    // Rejection must not remove or rewrite the unexpected entry.
    EXPECT_NE(std::filesystem::symlink_status(entry).type(), std::filesystem::file_type::not_found);
  }
}
}  // namespace hf3fs::client::ec
