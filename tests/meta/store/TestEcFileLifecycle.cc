#include "common/kv/mem/MemKVEngine.h"
#include "fbs/meta/Service.h"
#include "meta/store/EcFileLifecycleCatalog.h"
#include "meta/store/EcFileMutationCatalog.h"
#include "meta/store/EcNamespaceGuard.h"
#include "meta/store/detail/EcFileMutationKeys.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using folly::coro::blockingWait;
using Tx = EcFileTreeTxnBudget;
using Life = EcFileLifecycleCatalog;
using Sessions = EcFileSessionCatalog;
using Tree = EcFileTreeCatalog;
struct Fixture {
  kv::MemKVEngine engine;
  EcTreeBirth birth;
  EcFileOpenIntent opening;
  flat::UserInfo user{flat::Uid(812), flat::Gid(812)};
  InodeId parent{0x301}, other{0x303};
  Fixture() {
    birth.object = {InodeId(0x305), Uuid::random()};
    birth.creator = {user.uid, Uuid::random()};
    birth.createRequest = Uuid::random();
    birth.shardBytes = 64;
    birth.allowColocated = true;
    opening.object = birth.object;
    opening.owner = birth.creator;
    opening.birth = birth.createRequest;
    opening.session = Uuid::random();
    opening.openRequest = Uuid::random();
    opening.rights = kEcSessionWrite;
  }
  auto run(auto fn) {
    auto raw = engine.createReadWriteTransaction();
    Tx t(*raw);
    auto r = blockingWait(fn(t));
    if (r) {
      auto c = blockingWait(t.commit());
      if (!c) return decltype(r)(makeError(std::move(c.error())));
    }
    return r;
  }
  Result<Void> initialize() {
    return run([&](Tx &t) -> CoTryTask<Void> {
      auto root = Inode::newDirectory(InodeId::root(), InodeId::root(), "", Acl::root(), Layout{}, UtcClock::now());
      CO_RETURN_ON_ERROR(co_await root.store(t));
      for (auto id : {parent, other}) {
        auto dir = Inode::newDirectory(id,
                                       InodeId::root(),
                                       "private",
                                       Acl(user.uid, user.gid, Permission(0700)),
                                       Layout{},
                                       UtcClock::now());
        CO_RETURN_ON_ERROR(co_await dir.store(t));
      }
      CO_RETURN_ON_ERROR(co_await Tree::createBirth(t, birth));
      EcManifestLayoutV1 desc;
      desc.incarnation = birth.object.incarnation;
      desc.shardBytes = 64;
      Layout layout;
      layout.chains = desc;
      auto file =
          Inode::newFile(birth.object.inode, Acl(user.uid, user.gid, Permission(0600)), layout, UtcClock::now());
      CO_RETURN_ON_ERROR(co_await file.store(t));
      CO_RETURN_ON_ERROR(co_await DirEntry::newFile(parent, "original", file.id).store(t));
      CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::registerFile(t, file, parent));
      CO_RETURN_ON_ERROR(co_await Sessions::open(t, user, opening));
      co_return Void{};
    });
  }
  HardLinkReq linkRequest() const {
    HardLinkReq r;
    r.user = user;
    r.client.uuid = birth.creator.client;
    r.uuid = Uuid::random();
    r.oldPath = PathAt(parent, "original");
    r.newPath = PathAt(other, "alias");
    return r;
  }
  RemoveReq removeRequest(InodeId dir, const char *name) const {
    RemoveReq r;
    r.user = user;
    r.client.uuid = birth.creator.client;
    r.uuid = Uuid::random();
    r.path = PathAt(dir, name);
    r.inodeId = birth.object.inode;
    return r;
  }
  Result<RemoveRsp> remove(const RemoveReq &r, InodeId dir, const char *name) {
    auto entry = DirEntry::newFile(dir, name, birth.object.inode);
    return run([&](Tx &t) { return Life::unlink(t, r, entry); });
  }
  Result<EcFileSessionRecord> close() {
    return run([&](Tx &t) { return Sessions::close(t, birth.object, opening.session, opening.owner); });
  }
};

TEST(TestEcFileLifecycle, LinkCountsUnlinkedOpenWriterAndPermanentRetirementReplay) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto link = f.linkRequest();
  // run() starts the returned lazy task after this lambda has returned.
  const String destinationName = link.newPath.path->filename().native();
  auto linked = f.run([&](Tx &t) { return Life::link(t, link, f.birth.object.inode, f.other, destinationName); });
  ASSERT_OK(linked);
  EXPECT_EQ(linked->stat.nlink, 2);
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto root = co_await EcNamespaceGuard::subtreeCount(t, InodeId::root());
    CO_RETURN_ON_ERROR(root);
    if (*root != 2) co_return makeError(StatusCode::kDataCorruption);
    co_return Void{};
  }));
  auto first = f.removeRequest(f.parent, "original");
  auto last = f.removeRequest(f.other, "alias");
  ASSERT_OK(f.remove(first, f.parent, "original"));
  ASSERT_OK(f.remove(last, f.other, "alias"));
  ASSERT_OK(f.run([&](Tx &t) { return EcNamespaceGuard::checkRemove(t, InodeId::root()); }));
  auto fresh = f.opening;
  fresh.session = Uuid::random();
  fresh.openRequest = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return Sessions::open(t, f.user, fresh); }), MetaCode::kNotFound);
  EcFilePwriteIntent write;
  write.object = f.birth.object;
  write.owner = f.opening.owner;
  write.session = f.opening.session;
  write.request = Uuid::random();
  write.length = 7;
  write.inputSha256[0] = 1;
  ASSERT_OK(f.run([&](Tx &t) { return EcFileMutationCatalog::begin(t, write); }));
  auto closing = f.close();
  ASSERT_OK(closing);
  EXPECT_EQ(closing->state, EcFileSessionState::Closing);
  ASSERT_OK(f.run([&](Tx &t) { return Life::requireUnlinkedSession(t, f.birth.object); }));
  auto sealed =
      f.run([&](Tx &t) { return EcFileMutationCatalog::sealPrefix(t, f.birth.object, write.request, write.owner); });
  ASSERT_OK(sealed);
  EXPECT_EQ(sealed->confirmedPrefix, 0);
  auto closed = f.close();
  ASSERT_OK(closed);
  EXPECT_EQ(closed->state, EcFileSessionState::Closed);
  ASSERT_OK(f.run([&](Tx &t) { return Tree::getBirth(t, f.birth.object); }));
  auto notLive = f.run([&](Tx &t) { return Tree::open(t, f.birth.object); });
  ASSERT_FALSE(notLive);
  ASSERT_OK(f.run([&](Tx &t) { return Life::historicalRoot(t, f.birth.object); }));
  ASSERT_OK(f.run([&](Tx &t) { return Sessions::open(t, f.user, f.opening); }));
  ASSERT_OK(f.run([&](Tx &t) { return EcFileMutationCatalog::query(t, f.birth.object, write.request, write.owner); }));
  auto replay = f.run([&](Tx &t) { return Life::replay(t, last); });
  ASSERT_OK(replay);
  ASSERT_TRUE(*replay);
  auto changed = last;
  changed.path = PathAt(f.other, "different");
  ASSERT_ERROR(f.run([&](Tx &t) { return Life::replay(t, changed); }), StatusCode::kTokenMismatch);
  changed = last;
  changed.user.uid = flat::Uid(913);
  ASSERT_ERROR(f.run([&](Tx &t) { return Life::replay(t, changed); }), StatusCode::kTokenMismatch);
  auto oldLink = f.run([&](Tx &t) { return Life::replay(t, link); });
  ASSERT_OK(oldLink);
  ASSERT_TRUE(*oldLink);
  EXPECT_EQ((**oldLink).stat.nlink, 2);  // original result; no resurrection/new mutation
}

TEST(TestEcFileLifecycle, OpenUnlinkConflictAndNodeDecrementOnlyOnce) {
  Fixture f;
  ASSERT_OK(f.initialize());
  EcTreeEdit edit;
  edit.object = f.birth.object;
  edit.operation = Uuid::random();
  edit.expectedEpoch = 1;
  edit.expectedSequence = 1;
  edit.visibleLength = 37;
  for (auto &id : edit.nodeIds) id = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto c = co_await Tree::open(t, f.birth.object);
    CO_RETURN_ON_ERROR(c);
    CO_RETURN_ON_ERROR(co_await Tree::replaceZero(*c, edit));
    auto inode = co_await Inode::load(t, f.birth.object.inode);
    CO_RETURN_ON_ERROR(inode);
    if (!*inode) co_return makeError(StatusCode::kDataCorruption);
    (**inode).asFile().length = 37;
    CO_RETURN_ON_ERROR(co_await (**inode).store(t));
    co_return Void{};
  }));
  auto raw = f.engine.createReadWriteTransaction();
  Tx pending(*raw);
  auto opening = f.opening;
  opening.session = Uuid::random();
  opening.openRequest = Uuid::random();
  ASSERT_OK(blockingWait(Sessions::open(pending, f.user, opening)));
  auto unlink = f.removeRequest(f.parent, "original");
  ASSERT_OK(f.remove(unlink, f.parent, "original"));
  ASSERT_ERROR(blockingWait(pending.commit()), TransactionCode::kConflict);
  ASSERT_OK(f.close());
  for (int level = 15; level >= 0; --level) {
    auto result = f.run([&](Tx &t) { return Life::reclaimRetiredNode(t, f.birth.object, edit.nodeIds[level]); });
    ASSERT_OK(result);
    EXPECT_EQ(result->references, 0);
    EXPECT_EQ(result->state, EcTreeRefState::Reclaimed);
    auto repeated = f.run([&](Tx &t) { return Life::reclaimRetiredNode(t, f.birth.object, edit.nodeIds[level]); });
    ASSERT_OK(repeated);
    EXPECT_TRUE(same(*repeated, *result));
  }
  // A lost lifecycle row cannot be synthesized from a permanent enrollment.
  const auto lifecycleKey = objectKey(kv::KeyPrefix::EcFileLifecycle, f.birth.object);
  ASSERT_OK(f.run([&](Tx &t) { return t.clear(lifecycleKey); }));
  auto corrupt = f.run([&](Tx &t) { return Life::historicalRoot(t, f.birth.object); });
  ASSERT_FALSE(corrupt);
}
TEST(TestEcFileLifecycle, ResolvedBirthBindsOriginalRequestAndReplaysClosedHistory) {
  Fixture f;
  ASSERT_OK(f.initialize());
  OpenEcFileSessionReq req;
  req.user = f.user;
  req.client.uuid = f.birth.creator.client;
  req.uuid = Uuid::random();
  req.object = f.birth.object;
  req.session = Uuid::random();
  req.resolveBirth = true;
  req.rights = kEcSessionRead;
  auto run = [&](const auto &r) { return f.run([&](Tx &t) { return Sessions::openExisting(t, f.user, r); }); };
  auto opened = run(req);
  ASSERT_OK(opened);
  EXPECT_EQ(opened->intent.birth, f.birth.createRequest);
  auto changed = req;
  changed.resolveBirth = false;
  changed.birth = f.birth.createRequest;
  ASSERT_ERROR(run(changed), StatusCode::kTokenMismatch);
  changed = req;
  changed.shardBytes = 17;
  ASSERT_ERROR(run(changed), StatusCode::kTokenMismatch);
  changed = req;
  changed.object.incarnation = Uuid::random();
  ASSERT_ERROR(run(changed), StatusCode::kTokenMismatch);
  ASSERT_OK(f.run([&](Tx &t) { return Sessions::close(t, req.object, req.session, f.opening.owner); }));
  auto remove = f.removeRequest(f.parent, "original");
  ASSERT_OK(f.remove(remove, f.parent, "original"));
  ASSERT_OK(f.close());
  auto replay = run(req);
  ASSERT_OK(replay);
  EXPECT_EQ(replay->state, EcFileSessionState::Closed);
  changed = req;
  changed.uuid = Uuid::random();
  changed.session = Uuid::random();
  ASSERT_FALSE(run(changed));
}
}  // namespace
}  // namespace hf3fs::meta::server
