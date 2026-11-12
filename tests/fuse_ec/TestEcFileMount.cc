#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <future>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include "fuse/EcFileMount.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::fuse {
struct EcFileMountTestAccess {
  // Local persistence seams only: these deliberately do not certify remote T2.
  static Result<Void> archiveOperation(EcFileMountState &s,
                                       const std::filesystem::path &d,
                                       std::string_view n,
                                       std::string_view proof) {
    return s.archiveOperation(d, n, proof);
  }
  static Result<Void> archiveSession(EcFileMountState &s, const std::filesystem::path &d, std::string_view proof) {
    return s.archiveSession(d, proof);
  }
  static uint64_t inputBytes(const EcFileMountState &s) { return s.inputBytes_; }
  static void failIndexSync(EcFileMountState &s) { s.failNextIndexSyncForTest_ = true; }
  static void pendingOutput(std::shared_ptr<EcFileMount> core,
                            const std::filesystem::path &dir,
                            std::string name,
                            std::shared_ptr<void> output) {
    EcFileMount::Session s;
    s.directory = dir;
    s.debt = true;
    s.pendingRead = EcFileMount::Session::PendingRead{std::move(name), "local-test-only", output};
    core->sessions_.emplace(Uuid::random(), std::move(s));
  }
  static Result<Void> reap(std::shared_ptr<EcFileMount> core) { return core->reapCompleted(); }
  static void clearSyntheticSessions(std::shared_ptr<EcFileMount> core) { core->sessions_.clear(); }
  static std::shared_ptr<EcFileMount> local(std::shared_ptr<EcFileMountState> state) {
    auto core = std::shared_ptr<EcFileMount>(new EcFileMount(std::move(state), {}, std::chrono::seconds(2)));
    core->thread_ = std::thread([core] { core->loop(); });
    core->stopped_ = false;
    return core;
  }
  static CoTryTask<Void> pending(std::shared_ptr<EcFileMount> core,
                                 std::promise<void> &entered,
                                 std::shared_future<void> gate) {
    auto held = core->admit();
    if (!held) return EcFileMount::failed<Void>(std::move(held.error()));
    return core->post<Void>(*held, [&entered, gate](auto) -> Result<Void> {
      entered.set_value();
      gate.wait();
      return Void{};
    });
  }
  static CoTryTask<EcMountReadResult> output(std::shared_ptr<EcFileMount> core) {
    auto held = core->admit();
    if (!held) return EcFileMount::failed<EcMountReadResult>(std::move(held.error()));
    return core->post<EcMountReadResult>(*held, [](auto held) -> Result<EcMountReadResult> {
      CHECK_RESULT(b, client::ec::EcFilePayloadBudget::create());
      CHECK_RESULT(p, b->allocate(4096));
      p.bytes()[0] = 17;
      EcMountReadResult r;
      r.admission = std::move(held);
      r.data = std::move(p);
      return r;
    });
  }
  static bool accepts(std::shared_ptr<EcFileMount> core) { return bool(core->admit()); }
};
TEST(TestEcFileMount, DurableNamespaceExclusiveStateAndUnsupportedFlags) {
  folly::test::TemporaryDirectory temporary;
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0700), 0);
  const auto root = std::filesystem::path(temporary.path().string()) / "mount";
  // Folly's temporary directory inherits umask; the state requires a private
  // parent before creating format 2. Exercise that admission rule explicitly.
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0755), 0);
  auto publicParent = EcFileMountState::open({root, "cluster", true, 2, Uuid::zero()});
  ASSERT_ERROR(publicParent, StatusCode::kInvalidFormat);
  ASSERT_FALSE(std::filesystem::exists(root));
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0700), 0);
  auto first = EcFileMountState::open({root, "cluster", true, 2, Uuid::zero()});
  ASSERT_OK(first);
  auto format = (*first)->read(root, "index-version");
  ASSERT_OK(format);
  ASSERT_TRUE(*format);
  EXPECT_EQ(**format, "2\n");
  const auto ns = (*first)->clientNamespace();
  ASSERT_FALSE(ns.is_nil());
  auto duplicate = EcFileMountState::open({root, "cluster", false, 2, ns});
  ASSERT_FALSE(duplicate);
  auto a = (*first)->reserve("session");
  ASSERT_OK(a);
  ASSERT_OK((*first)->write(*a, "identity", "original"));
  auto listed = (*first)->sessions();
  ASSERT_OK(listed);
  ASSERT_EQ(listed->size(), 1u);
  auto relisted = (*first)->sessions();
  ASSERT_OK(relisted);
  ASSERT_EQ(relisted->size(), 1u);  // Fresh directory stream, not dup's shared offset.
  first->reset();
  auto resumed = EcFileMountState::open({root, "cluster", false, 2, ns});
  ASSERT_OK(resumed);
  auto bytes = (*resumed)->read(*a, "identity");
  ASSERT_OK(bytes);
  ASSERT_TRUE(*bytes);
  ASSERT_EQ(**bytes, "original");
  ASSERT_OK(validateEcMountOpenFlags(O_RDWR, false));
  ASSERT_FALSE(validateEcMountOpenFlags(O_WRONLY | O_APPEND, false));
  ASSERT_FALSE(validateEcMountOpenFlags(O_RDWR | O_SYNC, false));
  ASSERT_FALSE(validateEcMountOpenFlags(O_RDONLY | O_TRUNC, false));
}
TEST(TestEcFileMount, DroppedWaiterStillJoinsOwnedWorkerAndHeldOutputKeepsAdmission) {
  using folly::coro::blockingWait;
  folly::test::TemporaryDirectory temporary;
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0700), 0);
  auto state = EcFileMountState::open(
      {std::filesystem::path(temporary.path().string()) / "state", "cluster", true, 2, Uuid::zero()});
  ASSERT_OK(state);
  auto core = EcFileMountTestAccess::local(*state);
  std::promise<void> entered, release;
  auto ready = entered.get_future();
  auto gate = release.get_future().share();
  bool released = false;
  auto cleanup = folly::makeGuard([&] {
    if (!released) {
      release.set_value();
      released = true;
    }
    (void)core->stop();
  });
  {
    auto dropped = EcFileMountTestAccess::pending(core, entered, gate);
    (void)dropped;
  }
  ASSERT_EQ(ready.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  ASSERT_FALSE(EcFileMountTestAccess::accepts(core));
  auto stopped = std::async(std::launch::async, [core] { return core->stop(); });
  EXPECT_EQ(stopped.wait_for(std::chrono::milliseconds(30)), std::future_status::timeout);
  release.set_value();
  released = true;
  ASSERT_OK(stopped.get());
  cleanup.dismiss();

  auto second = EcFileMountTestAccess::local(*state);
  auto secondCleanup = folly::makeGuard([&] { (void)second->stop(); });
  auto output = blockingWait(EcFileMountTestAccess::output(second));
  ASSERT_OK(output);
  EXPECT_EQ(output->data.bytes()[0], 17);
  EXPECT_FALSE(EcFileMountTestAccess::accepts(second));
  // A byte-only output may survive shutdown. Executor/dependency teardown is
  // already confirmed; the retained lease only protects bytes/state/admission.
  ASSERT_OK(second->stop());
  EXPECT_EQ(output->data.bytes()[0], 17);
  secondCleanup.dismiss();
}
TEST(TestEcFileMount, TerminalHistoryDoesNotConsumeActiveQuotaAndNamesNeverRepeat) {
  // Exercise real exclusive files/fsync/index updates, with synthetic terminal
  // observations. Actual Meta/TCP cleanup is covered by the mount acceptance.
  folly::test::TemporaryDirectory temporary;
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0700), 0);
  const auto root = std::filesystem::path(temporary.path().string()) / "state";
  auto state = EcFileMountState::open({root, "cluster", true, 1, Uuid::zero(), uint64_t{32} << 20});
  ASSERT_OK(state);
  const auto ns = (*state)->clientNamespace();
  std::filesystem::path history;
  for (size_t session = 0; session < 3; ++session) {
    auto dir = (*state)->reserve("session");
    ASSERT_OK(dir);
    history = *dir;
    EXPECT_FALSE((*state)->reserve("session"));
    for (uint64_t n = 0; n < (session == 0 ? 70u : 1u); ++n) {
      auto op = (*state)->reserveOperation(*dir, "write", uint64_t{32} << 20);
      ASSERT_OK(op);
      EXPECT_EQ(op->filename().string(), "write-" + std::to_string(n));
      EXPECT_FALSE((*state)->reserveOperation(*dir, "write", 1));
      EXPECT_FALSE(EcFileMountTestAccess::archiveSession(**state, *dir, "not-closed"));
      const auto proof = "local-test-terminal-" + std::to_string(n);
      ASSERT_OK(EcFileMountTestAccess::archiveOperation(**state, *dir, op->filename().string(), proof));
      ASSERT_EQ(EcFileMountTestAccess::inputBytes(**state), 0u);
      // Same identity may be observed again without double-decrement.
      ASSERT_OK(EcFileMountTestAccess::archiveOperation(**state, *dir, op->filename().string(), proof));
      EXPECT_FALSE(
          EcFileMountTestAccess::archiveOperation(**state, *dir, op->filename().string(), "conflicting-proof"));
      EXPECT_TRUE(std::filesystem::exists(*dir / ("terminal-write-" + std::to_string(n))));
    }
    ASSERT_OK(EcFileMountTestAccess::archiveSession(**state, *dir, "local-closed"));
    EXPECT_TRUE(std::filesystem::exists(*dir / "terminal-session"));
  }
  state->reset();
  state = EcFileMountState::open({root, "cluster", false, 1, ns, uint64_t{32} << 20});
  ASSERT_OK(state);
  auto active = (*state)->sessions();
  ASSERT_OK(active);
  EXPECT_TRUE(active->empty());
  EXPECT_TRUE(std::filesystem::exists(history / "terminal-write-0"));
  auto dir = (*state)->reserve("session");
  ASSERT_OK(dir);
  auto pending = (*state)->reserveOperation(*dir, "write", uint64_t{32} << 20);
  ASSERT_OK(pending);
  state->reset();
  state = EcFileMountState::open({root, "cluster", false, 1, ns, uint64_t{32} << 20});
  ASSERT_OK(state);
  EXPECT_EQ(EcFileMountTestAccess::inputBytes(**state), uint64_t{32} << 20);
  EXPECT_FALSE((*state)->reserveOperation(*dir, "write", 1));
  auto unfinished = (*state)->operations(*dir);
  ASSERT_OK(unfinished);
  ASSERT_EQ(unfinished->size(), 1u);
  EXPECT_EQ(unfinished->front().name, pending->filename().string());
  EcFileMountTestAccess::failIndexSync(**state);
  EXPECT_FALSE(
      EcFileMountTestAccess::archiveOperation(**state, *dir, pending->filename().string(), "durable-before-index"));
  EXPECT_TRUE((*state)->poisoned());
  EXPECT_EQ(EcFileMountTestAccess::inputBytes(**state), uint64_t{32} << 20);
  EXPECT_FALSE((*state)->reserveOperation(*dir, "read"));
  EXPECT_TRUE(std::filesystem::exists(*dir / ("terminal-" + pending->filename().string())));
  state->reset();
  state = EcFileMountState::open({root, "cluster", false, 1, ns, uint64_t{32} << 20});
  ASSERT_OK(state);
  // Reopening syncs the actual index directory. This is ordinary reopen, not a
  // power-loss test; no in-process quota was released on the uncertain return.
  EXPECT_EQ(EcFileMountTestAccess::inputBytes(**state), 0u);
  auto later = (*state)->reserveOperation(*dir, "read");
  ASSERT_OK(later);
  EXPECT_EQ(later->filename().string(), "read-1");
}
TEST(TestEcFileMount, OutputLeaseDefersTerminalIndexRemovalAndLegacyFormatIsRejected) {
  folly::test::TemporaryDirectory temporary;
  ASSERT_EQ(::chmod(temporary.path().c_str(), 0700), 0);
  const auto root = std::filesystem::path(temporary.path().string()) / "state";
  auto state = EcFileMountState::open({root, "cluster", true, 1, Uuid::zero()});
  ASSERT_OK(state);
  const auto ns = (*state)->clientNamespace();
  auto dir = (*state)->reserve("session");
  ASSERT_OK(dir);
  auto op = (*state)->reserveOperation(*dir, "read");
  ASSERT_OK(op);
  auto core = EcFileMountTestAccess::local(*state);
  auto output = std::make_shared<int>(7);
  // No job is queued. The seam supplies only a synthetic already-T2 observation.
  EcFileMountTestAccess::pendingOutput(core, *dir, op->filename().string(), output);
  auto cleanup = folly::makeGuard([&] {
    EcFileMountTestAccess::clearSyntheticSessions(core);
    (void)core->stop();
  });
  ASSERT_OK(EcFileMountTestAccess::reap(core));
  auto held = (*state)->operations(*dir);
  ASSERT_OK(held);
  ASSERT_EQ(held->size(), 1u);
  EXPECT_FALSE(std::filesystem::exists(*dir / "terminal-read-0"));
  output.reset();
  ASSERT_OK(EcFileMountTestAccess::reap(core));
  auto released = (*state)->operations(*dir);
  ASSERT_OK(released);
  EXPECT_TRUE(released->empty());
  EXPECT_TRUE(std::filesystem::exists(*dir / "terminal-read-0"));
  EcFileMountTestAccess::clearSyntheticSessions(core);
  ASSERT_OK(core->stop());
  cleanup.dismiss();
  core.reset();
  state->reset();
  // A format-1 namespace must not be silently interpreted with active-only quotas.
  ASSERT_TRUE(std::filesystem::remove(root / "index-version"));
  auto old = EcFileMountState::open({root, "cluster", false, 1, ns});
  EXPECT_FALSE(old);
  EXPECT_TRUE(std::filesystem::exists(*dir / "terminal-read-0"));
}
}  // namespace hf3fs::fuse
