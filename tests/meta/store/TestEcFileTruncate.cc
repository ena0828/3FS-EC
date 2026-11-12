#include <cstdlib>
#include <cstring>
#include <filesystem>

#include "fdb/FDBKVEngine.h"
#include "meta/store/EcFileMutationCatalog.h"
#include "meta/store/EcFileTruncateCatalog.h"
#include "meta/store/Inode.h"
#include "meta/store/detail/EcFileMutationKeys.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using folly::coro::blockingWait;
using Tx = EcFileTreeTxnBudget;
using Truncate = EcFileTruncateCatalog;
class TestEcFileTruncate : public hf3fs::testing::SetupFDB {};
struct TruncateFixture {
  std::shared_ptr<kv::IKVEngine> engine;
  EcTreeBirth birth;
  EcFileOpenIntent opening;
  flat::UserInfo user;
  TruncateFixture() {
    uint64_t number = 0;
    const auto id = Uuid::random();
    std::memcpy(&number, id.data, sizeof(number));
    birth.object = {InodeId((number & InodeId::normalMax().u64()) | 0x101), Uuid::random()};
    birth.creator = {flat::Uid(811), Uuid::random()};
    birth.createRequest = Uuid::random();
    birth.shardBytes = 64;
    birth.allowColocated = true;
    opening.object = birth.object;
    opening.birth = birth.createRequest;
    opening.owner = birth.creator;
    opening.session = Uuid::random();
    opening.openRequest = Uuid::random();
    opening.rights = kEcSessionWrite;
    user = flat::UserInfo(birth.creator.uid, flat::Gid(811));
  }
  auto run(auto fn) {
    auto inner = engine->createReadWriteTransaction();
    Tx txn(*inner);
    auto result = blockingWait(fn(txn));
    if (result) {
      auto commit = blockingWait(txn.commit());
      if (!commit) return decltype(result)(makeError(std::move(commit.error())));
    }
    return result;
  }
  Result<Void> initialize() {
    const auto *catalog = std::getenv("EC_CATALOG_TEST_CLUSTER"), *unit = std::getenv("FDB_UNITTEST_CLUSTER");
    std::error_code error;
    if (!catalog || !unit || !std::filesystem::equivalent(catalog, unit, error) || error)
      return makeError(StatusCode::kInvalidConfig, "same runner-owned private FDB is required");
    kv::fdb::DB db(catalog, false);
    if (db.error()) return makeError(StatusCode::kInvalidConfig);
    engine = std::make_shared<kv::FDBKVEngine>(std::move(db));
    return run([&](Tx &txn) -> CoTryTask<Void> {
      auto existing = co_await Inode::load(txn, birth.object.inode);
      CO_RETURN_ON_ERROR(existing);
      if (*existing) co_return makeError(StatusCode::kTokenDuplicated);
      auto root = co_await EcFileTreeCatalog::createBirth(txn, birth);
      CO_RETURN_ON_ERROR(root);
      EcManifestLayoutV1 ec;
      ec.incarnation = birth.object.incarnation;
      ec.shardBytes = birth.shardBytes;
      Layout layout{ChainTableId(0), ChainTableVersion(0), ec.shardBytes, 10, ec};
      auto inode =
          Inode::newFile(birth.object.inode, Acl(user.uid, user.gid, Permission(0600)), layout, UtcClock::now());
      CO_RETURN_ON_ERROR(co_await inode.store(txn));
      auto session = co_await EcFileSessionCatalog::open(txn, user, opening);
      CO_RETURN_ON_ERROR(session);
      co_return Void{};
    });
  }
  Result<EcTreeRoot> root() {
    return run([&](Tx &txn) -> CoTryTask<EcTreeRoot> {
      auto c = co_await EcFileTreeCatalog::open(txn, birth.object);
      CO_RETURN_ON_ERROR(c);
      co_return co_await EcFileTreeCatalog::getRoot(*c);
    });
  }
  EcFileTruncateIntent intent(const EcTreeRoot &root, uint64_t length) {
    EcFileTruncateIntent i;
    i.object = birth.object;
    i.owner = opening.owner;
    i.session = opening.session;
    i.operation = Uuid::random();
    i.child = Uuid::random();
    i.plan = Uuid::random();
    i.sourcePin = Uuid::random();
    i.expectedRoot = root.root;
    i.expectedSequence = root.sequence;
    i.expectedEpoch = root.epoch;
    i.expectedLength = root.visibleLength;
    i.length = length;
    for (auto &id : i.nodeIds) id = Uuid::random();
    return i;
  }
};
TEST_F(TestEcFileTruncate, RealFdbFixedUnknownReplayPublishesRootObjectAndInodeTogether) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB required";
  TruncateFixture f;
  ASSERT_OK(f.initialize());
  auto original = f.root();
  ASSERT_OK(original);
  const auto request = f.intent(*original, 8193);
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner);
  auto begun = blockingWait(Truncate::begin(txn, request));
  ASSERT_OK(begun);
  auto loseBegin = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn.commit());
    co_return makeError(TransactionCode::kMaybeCommitted);
  };
  ASSERT_ERROR(blockingWait(loseBegin()), TransactionCode::kMaybeCommitted);
  auto replay = f.run([&](Tx &t) { return Truncate::begin(t, request); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*begun, *replay));
  auto visible = f.root();
  ASSERT_OK(visible);
  EXPECT_EQ(visible->visibleLength, 0);
  EXPECT_EQ(visible->epoch, original->epoch + 1);
  auto changed = request;
  changed.length = 8194;
  ASSERT_ERROR(f.run([&](Tx &t) { return Truncate::begin(t, changed); }), StatusCode::kTokenMismatch);
  auto finishInner = f.engine->createReadWriteTransaction();
  Tx finish(*finishInner);
  auto published = blockingWait(Truncate::publishWithoutTail(finish, request.owner, request.object, request.operation));
  ASSERT_OK(published);
  auto loseFinish = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await finish.commit());
    co_return makeError(TransactionCode::kMaybeCommitted);
  };
  ASSERT_ERROR(blockingWait(loseFinish()), TransactionCode::kMaybeCommitted);
  replay =
      f.run([&](Tx &t) { return Truncate::publishWithoutTail(t, request.owner, request.object, request.operation); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*published, *replay));
  ASSERT_TRUE(replay->publishedRoot);
  EXPECT_EQ(replay->publishedRoot->visibleLength, 8193);
  ASSERT_OK(f.run([&](Tx &t) { return Truncate::requireMutationOpen(t, request.object); }));
  auto inode = f.run([&](Tx &t) { return Inode::load(t, request.object.inode); });
  ASSERT_OK(inode);
  ASSERT_TRUE(*inode);
  EXPECT_EQ((**inode).asFile().length, 8193);
  auto shrink = f.intent(*replay->publishedRoot, 0);
  ASSERT_OK(f.run([&](Tx &t) { return Truncate::begin(t, shrink); }));
  auto zero =
      f.run([&](Tx &t) { return Truncate::publishWithoutTail(t, shrink.owner, shrink.object, shrink.operation); });
  ASSERT_OK(zero);
  ASSERT_TRUE(zero->publishedRoot);
  EXPECT_EQ(zero->publishedRoot->visibleLength, 0);
}
TEST_F(TestEcFileTruncate, RealFdbStructuralGateFencesWriterAndRetainsClosingSession) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB required";
  TruncateFixture f;
  ASSERT_OK(f.initialize());
  auto root = f.root();
  ASSERT_OK(root);
  auto readonly = f.opening;
  readonly.session = Uuid::random();
  readonly.openRequest = Uuid::random();
  readonly.rights = kEcSessionRead;
  ASSERT_OK(f.run([&](Tx &t) { return EcFileSessionCatalog::open(t, f.user, readonly); }));
  auto denied = f.intent(*root, 100);
  denied.session = readonly.session;
  ASSERT_ERROR(f.run([&](Tx &t) { return Truncate::begin(t, denied); }), MetaCode::kNoPermission);
  EcFilePwriteIntent write;
  write.object = f.birth.object;
  write.owner = f.opening.owner;
  write.session = f.opening.session;
  write.request = Uuid::random();
  write.length = 20;
  write.inputSha256.back() = 1;
  ASSERT_OK(f.run([&](Tx &t) { return EcFileMutationCatalog::begin(t, write); }));
  EcFileChildIntent child;
  child.object = write.object;
  child.parent = write.request;
  child.child = Uuid::random();
  child.plan = Uuid::random();
  child.sourcePin = Uuid::random();
  child.patchSha256.back() = 2;
  for (auto &id : child.nodeIds) id = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return EcFileMutationCatalog::planChild(t, write.owner, child); }));
  auto request = f.intent(*root, 128);
  ASSERT_OK(f.run([&](Tx &t) { return Truncate::begin(t, request); }));
  ASSERT_ERROR(f.run([&](Tx &t) {
    return EcFileMutationCatalog::preparePublication(t, write.object, child.child, write.owner);
  }),
               StatusCode::kTokenStale);
  auto closing = f.run([&](Tx &t) { return EcFileSessionCatalog::close(t, write.object, write.session, write.owner); });
  ASSERT_OK(closing);
  EXPECT_EQ(closing->state, EcFileSessionState::Closing);
  EXPECT_EQ(closing->activeStructural, request.operation);
  auto done =
      f.run([&](Tx &t) { return Truncate::publishWithoutTail(t, request.owner, request.object, request.operation); });
  ASSERT_OK(done);
  auto fenced =
      f.run([&](Tx &t) { return EcFileMutationCatalog::sealPrefix(t, write.object, write.request, write.owner); });
  ASSERT_OK(fenced);
  EXPECT_EQ(fenced->confirmedPrefix, 0);
  EXPECT_EQ(fenced->fencedChild, child.child);
  auto closed = f.run([&](Tx &t) { return EcFileSessionCatalog::close(t, write.object, write.session, write.owner); });
  ASSERT_OK(closed);
  EXPECT_EQ(closed->state, EcFileSessionState::Closed);
  EXPECT_TRUE(closed->activeStructural.is_nil());
  root = f.root();
  ASSERT_OK(root);
  auto aborted = f.intent(*root, 64);
  aborted.session = readonly.session;
  ASSERT_ERROR(f.run([&](Tx &t) { return Truncate::begin(t, aborted); }), MetaCode::kNoPermission);
}
}  // namespace
}  // namespace hf3fs::meta::server
