#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <type_traits>

#include "common/kv/mem/MemKVEngine.h"
#include "core/user/UserStore.h"
#include "fdb/FDBKVEngine.h"
#include "meta/components/EcFileMutationCoordinator.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/EcFileAppendCatalog.h"
#include "meta/store/Inode.h"
#include "meta/store/detail/EcFileMutationKeys.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace detail {
// Exercises rejection by the final bookkeeping step. This seam cannot create
// a W1 publication proof or install a Data slot in the W0 tree.
struct EcFileMutationTestAccess {
  static CoTryTask<EcFileMutationRecord> finish(EcFileTreeTxnBudget &txn,
                                                const EcOwner &owner,
                                                const EcFilePublicationGate &gate,
                                                const EcTreeEditResult &edit) {
    co_return co_await EcFileMutationCatalog::finishPublished(txn, owner, gate, edit);
  }
};
}  // namespace detail
namespace {
using folly::coro::blockingWait;
using namespace ec_file_mutation_detail;
using Tx = EcFileTreeTxnBudget;
using Sessions = EcFileSessionCatalog;
using Mutations = EcFileMutationCatalog;
using Tree = EcFileTreeCatalog;
using kv::KeyPrefix;
static_assert(!std::is_default_constructible_v<EcFilePublicationGate>);
static_assert(!std::is_constructible_v<EcFilePublicationGate, Tx &, EcFileChildRecord, EcTreeRoot>);

class TestEcFileMutation : public hf3fs::testing::SetupFDB {};

struct Fixture {
  std::shared_ptr<kv::IKVEngine> engine;
  EcTreeBirth birth;
  EcFileOpenIntent opening;
  flat::UserInfo user;

  Fixture() {
    auto random = Uuid::random();
    uint64_t number = 0;
    std::memcpy(&number, random.data, sizeof(number));
    birth.object = {InodeId((number & InodeId::normalMax().u64()) | 0x101), Uuid::random()};
    birth.creator = {flat::Uid(701), Uuid::random()};
    birth.createRequest = Uuid::random();
    birth.shardBytes = 64;
    birth.allowColocated = true;
    opening.object = birth.object;
    opening.birth = birth.createRequest;
    opening.owner = birth.creator;
    opening.session = Uuid::random();
    opening.openRequest = Uuid::random();
    opening.rights = kEcSessionWrite;
    user = flat::UserInfo(birth.creator.uid, flat::Gid(701));
  }
  auto run(auto fn) {
    auto inner = engine->createReadWriteTransaction();
    Tx txn(*inner);
    auto result = blockingWait(fn(txn));
    if (result) {
      auto committed = blockingWait(txn.commit());
      if (!committed) return decltype(result)(makeError(std::move(committed.error())));
    }
    return result;
  }
  Result<Void> initialize(bool fdb = false) {
    if (fdb) {
      const auto *catalog = std::getenv("EC_CATALOG_TEST_CLUSTER");
      const auto *unit = std::getenv("FDB_UNITTEST_CLUSTER");
      std::error_code error;
      if (!catalog || !unit || !std::filesystem::equivalent(catalog, unit, error) || error)
        return makeError(StatusCode::kInvalidConfig, "both variables must name the same runner-owned private FDB");
      kv::fdb::DB db(catalog, false);
      if (db.error()) return makeError(StatusCode::kInvalidConfig, "private FDB open failed");
      engine = std::make_shared<kv::FDBKVEngine>(std::move(db));
    } else
      engine = std::make_shared<kv::MemKVEngine>();
    // No database clearing: every object/incarnation/inode is private to this fixture.
    return run([&](Tx &txn) -> CoTryTask<Void> {
      auto old = co_await Inode::load(txn, birth.object.inode);
      CO_RETURN_ON_ERROR(old);
      if (*old) co_return makeError(StatusCode::kTokenDuplicated, "random fixture inode already exists");
      CO_RETURN_ON_ERROR(co_await Tree::createBirth(txn, birth));
      EcManifestLayoutV1 ec;
      ec.incarnation = birth.object.incarnation;
      ec.shardBytes = birth.shardBytes;
      Layout layout{ChainTableId(0), ChainTableVersion(0), ec.shardBytes, 10, ec};
      auto inode =
          Inode::newFile(birth.object.inode, Acl(user.uid, user.gid, Permission(0200)), layout, UtcClock::now());
      CO_RETURN_ON_ERROR(co_await inode.store(txn));
      co_return Void{};
    });
  }
  Result<EcFileSessionRecord> open() {
    return run([&](Tx &txn) { return Sessions::open(txn, user, opening); });
  }
  EcFilePwriteIntent write(uint64_t offset = 5, uint64_t length = 41) const {
    EcFilePwriteIntent i;
    i.object = birth.object;
    i.owner = opening.owner;
    i.session = opening.session;
    i.request = Uuid::random();
    i.offset = offset;
    i.length = length;
    // Fixed synthetic content identity; these catalog tests do not upload bytes.
    i.inputSha256.back() = 7;
    return i;
  }
  EcFileChildIntent child(const EcFilePwriteIntent &parent) const {
    EcFileChildIntent i;
    i.object = birth.object;
    i.parent = parent.request;
    i.child = Uuid::random();
    i.plan = Uuid::random();
    i.sourcePin = Uuid::random();
    i.patchSha256.back() = 9;
    for (auto &id : i.nodeIds) id = Uuid::random();
    return i;
  }
  Result<EcFileSessionIndex> index() {
    return run([&](Tx &txn) {
      return require<EcFileSessionIndex>(txn, objectKey(KeyPrefix::EcFileSessionIndex, birth.object));
    });
  }
  Result<EcTreeRoot> root() {
    return run([&](Tx &txn) -> CoTryTask<EcTreeRoot> {
      auto context = co_await Tree::open(txn, birth.object);
      CO_RETURN_ON_ERROR(context);
      co_return co_await Tree::getRoot(*context);
    });
  }
  EcTreeEdit edit(const EcTreeRoot &r, uint64_t stripe, uint64_t length) const {
    EcTreeEdit e;
    e.object = birth.object;
    e.operation = Uuid::random();
    e.expectedRoot = r.root;
    e.expectedSequence = r.sequence;
    e.expectedEpoch = r.epoch;
    e.stripe = stripe;
    e.visibleLength = length;
    for (auto &id : e.nodeIds) id = Uuid::random();
    return e;
  }
  Result<EcTreeEditResult> zero(const EcTreeEdit &e) {
    return run([&](Tx &txn) -> CoTryTask<EcTreeEditResult> {
      auto context = co_await Tree::open(txn, birth.object);
      CO_RETURN_ON_ERROR(context);
      auto result = co_await Tree::replaceZero(*context, e);
      CO_RETURN_ON_ERROR(result);
      auto inode = co_await Inode::load(txn, birth.object.inode);
      CO_RETURN_ON_ERROR(inode);
      if (!*inode) co_return makeError(StatusCode::kDataCorruption);
      (**inode).asFile().length = e.visibleLength;
      CO_RETURN_ON_ERROR(co_await (**inode).store(txn));
      co_return result;
    });
  }
};

TEST_F(TestEcFileMutation, WriteOnlySessionFixedIdentityAndCloseRetainAcceptedParent) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.open());
  ASSERT_OK(f.open());
  auto count = f.index();
  ASSERT_OK(count);
  EXPECT_EQ(count->openCount, 1u);
  auto changedOpen = f.opening;
  changedOpen.session = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return Sessions::open(t, f.user, changedOpen); }), StatusCode::kTokenMismatch);
  auto readOpen = f.opening;
  readOpen.session = Uuid::random();
  readOpen.openRequest = Uuid::random();
  readOpen.rights = kEcSessionRead;
  ASSERT_ERROR(f.run([&](Tx &t) { return Sessions::open(t, f.user, readOpen); }), MetaCode::kNoPermission);
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto inode = co_await Inode::load(t, f.birth.object.inode);
    CO_RETURN_ON_ERROR(inode);
    if (!*inode) co_return makeError(StatusCode::kDataCorruption);
    (**inode).acl.perm = Permission(0);
    CO_RETURN_ON_ERROR(co_await (**inode).store(t));
    co_return Void{};
  }));
  auto request = f.write();
  auto accepted = f.run([&](Tx &t) { return Mutations::begin(t, request); });
  ASSERT_OK(accepted);
  EXPECT_EQ(accepted->sessionSequence, 1u);
  auto closing = f.run([&](Tx &t) { return Sessions::close(t, f.birth.object, f.opening.session, f.opening.owner); });
  ASSERT_OK(closing);
  EXPECT_EQ(closing->state, EcFileSessionState::Closing);
  count = f.index();
  ASSERT_OK(count);
  EXPECT_EQ(count->openCount, 1u);
  auto next = f.write();
  ASSERT_ERROR(f.run([&](Tx &t) { return Mutations::begin(t, next); }), StatusCode::kTokenStale);
  auto planned = f.child(request);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, planned); }));
  auto closed =
      f.run([&](Tx &t) { return Mutations::sealPrefix(t, f.birth.object, request.request, f.opening.owner); });
  ASSERT_OK(closed);
  EXPECT_EQ(closed->confirmedPrefix, 0u);
  EXPECT_EQ(closed->fencedChild, planned.child);
  ASSERT_OK(f.run([&](Tx &t) { return Sessions::close(t, f.birth.object, f.opening.session, f.opening.owner); }));
  ASSERT_OK(f.run([&](Tx &t) { return Sessions::close(t, f.birth.object, f.opening.session, f.opening.owner); }));
  count = f.index();
  ASSERT_OK(count);
  EXPECT_EQ(count->openCount, 0u);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  request.inputSha256[0] = 1;
  ASSERT_ERROR(f.run([&](Tx &t) { return Mutations::begin(t, request); }), StatusCode::kTokenMismatch);
  auto foreign = f.opening.owner;
  foreign.client = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return Mutations::query(t, f.birth.object, request.request, foreign); }),
               MetaCode::kNoPermission);
}

TEST_F(TestEcFileMutation, MissingSessionIndexCannotResetPermanentHistoryToZero) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.open());
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await t.clear(objectKey(KeyPrefix::EcFileSessionIndex, f.birth.object)));
    co_return Void{};
  }));
  auto next = f.opening;
  next.session = Uuid::random();
  next.openRequest = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return Sessions::open(t, f.user, next); }), StatusCode::kDataCorruption);
  ASSERT_ERROR(f.open(), StatusCode::kDataCorruption);
}

TEST_F(TestEcFileMutation, ChildReservationIsFixedAndDerivedFromNextContiguousPrefix) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.open());
  auto request = f.write(638, 11);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  auto child = f.child(request);
  auto planned = f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); });
  ASSERT_OK(planned);
  EXPECT_EQ(planned->stripe, 0u);
  EXPECT_EQ(planned->patchOffset, 638u);
  EXPECT_EQ(planned->patchLength, 2u);
  EXPECT_EQ(planned->targetLogicalLength, 640u);
  EXPECT_EQ(planned->targetGeneration, 1u);
  EXPECT_EQ(planned->targetRevision, 1u);
  auto replay = f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*planned, *replay));
  auto object = f.run([&](Tx &t) { return EcCatalog::getObject(t, f.birth.object); });
  ASSERT_OK(object);
  EXPECT_EQ(object->nextGeneration, 2u);
  EXPECT_EQ(object->nextRevision, 2u);
  auto alternative = f.child(request);
  ASSERT_ERROR(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, alternative); }),
               StorageClientCode::kResourceBusy);
  child.patchSha256[0] = 1;
  ASSERT_ERROR(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); }),
               StatusCode::kTokenMismatch);
}

TEST_F(TestEcFileMutation, SparseZeroBeforeEofPreservesWholeVisibleStripe) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto root = f.root();
  ASSERT_OK(root);
  ASSERT_OK(f.zero(f.edit(*root, 2, 1287)));
  ASSERT_OK(f.open());
  auto request = f.write(641, 3);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  auto child = f.child(request);
  auto planned = f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); });
  ASSERT_OK(planned);
  EXPECT_EQ(planned->source.kind, EcTreeSlotKind::Zero);
  EXPECT_EQ(planned->stripe, 1u);
  EXPECT_EQ(planned->targetLogicalLength, 640u);
  EXPECT_EQ(planned->patchOffset, 1u);
  EXPECT_EQ(planned->patchLength, 3u);
}

TEST_F(TestEcFileMutation, UnrelatedRootAdvanceRebasesButEpochChangeFencesChild) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.open());
  auto request = f.write();
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  auto child = f.child(request);
  auto planned = f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); });
  ASSERT_OK(planned);
  auto root = f.root();
  ASSERT_OK(root);
  auto advanced = f.zero(f.edit(*root, 9, 0));
  ASSERT_OK(advanced);
  auto gate =
      f.run([&](Tx &t) { return Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner); });
  ASSERT_OK(gate);
  EXPECT_EQ(gate->currentRoot().root, advanced->root.root);
  EXPECT_EQ(gate->child().sourceRoot, planned->sourceRoot);
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto current = co_await require<EcTreeRoot>(t, objectKey(KeyPrefix::EcTreeRoot, f.birth.object));
    CO_RETURN_ON_ERROR(current);
    auto object = co_await EcCatalog::getObject(t, f.birth.object);
    CO_RETURN_ON_ERROR(object);
    ++current->epoch;
    ++object->epoch;
    CO_RETURN_ON_ERROR(co_await store(t, objectKey(KeyPrefix::EcTreeRoot, f.birth.object), *current));
    co_return co_await store(t, objectKey(KeyPrefix::EcObject, f.birth.object), *object);
  }));
  ASSERT_ERROR(
      f.run([&](Tx &t) { return Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner); }),
      StatusCode::kTokenStale);
}

void publicationFenceConflict(Fixture &f) {
  ASSERT_OK(f.open());
  auto request = f.write();
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  auto child = f.child(request);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); }));
  auto inner = f.engine->createReadWriteTransaction();
  Tx publishing(*inner);
  auto gate = blockingWait(Mutations::preparePublication(publishing, f.birth.object, child.child, f.opening.owner));
  ASSERT_OK(gate);
  auto fenced =
      f.run([&](Tx &t) { return Mutations::sealPrefix(t, f.birth.object, request.request, f.opening.owner); });
  ASSERT_OK(fenced);
  EXPECT_EQ(fenced->confirmedPrefix, 0u);
  // Real distinct mutation prevents an optimized read-only commit. The key is
  // under this random incarnation and is not interpreted as a publication.
  auto key = objectKey(KeyPrefix::EcFileMutation, f.birth.object);
  key.append("-conflict-probe");
  ASSERT_OK(blockingWait(publishing.set(key, "first")));
  ASSERT_ERROR(blockingWait(publishing.commit()), TransactionCode::kConflict);
  ASSERT_ERROR(
      f.run([&](Tx &t) { return Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner); }),
      StatusCode::kTokenStale);
}
TEST_F(TestEcFileMutation, PrefixFenceConflictsWithPublicationGate) {
  Fixture f;
  ASSERT_OK(f.initialize());
  publicationFenceConflict(f);
}

TEST_F(TestEcFileMutation, PublicZeroEditCannotAdvanceConfirmedUserBytes) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.open());
  auto request = f.write();
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, request); }));
  auto child = f.child(request);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); }));
  auto rejected = f.run([&](Tx &t) -> CoTryTask<EcFileMutationRecord> {
    auto gate = co_await Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner);
    CO_RETURN_ON_ERROR(gate);
    auto edit = f.edit(gate->currentRoot(), 0, request.offset + request.length);
    edit.operation = child.child;
    edit.nodeIds = child.nodeIds;
    auto context = co_await Tree::open(t, f.birth.object);
    CO_RETURN_ON_ERROR(context);
    auto result = co_await Tree::replaceZero(*context, edit);
    CO_RETURN_ON_ERROR(result);
    co_return co_await detail::EcFileMutationTestAccess::finish(t, f.opening.owner, *gate, *result);
  });
  ASSERT_ERROR(rejected, StatusCode::kTokenMismatch);
  auto parent = f.run([&](Tx &t) { return Mutations::query(t, f.birth.object, request.request, f.opening.owner); });
  ASSERT_OK(parent);
  ASSERT_TRUE(*parent);
  EXPECT_EQ((**parent).confirmedPrefix, 0u);
  auto root = f.root();
  ASSERT_OK(root);
  EXPECT_EQ(root->visibleLength, 0u);
  EXPECT_EQ(root->sequence, 1u);
}

TEST_F(TestEcFileMutation, AuthenticatedCoordinatorOwnsInputsAndRejectsAssertedUid) {
  Fixture f;
  ASSERT_OK(f.initialize());
  core::UserStore users;
  // User provisioning uses snapshots; commit it before the coordinator's
  // independent authentication reads, without relaxing the tree budget.
  auto userTxn = f.engine->createReadWriteTransaction();
  ASSERT_TRUE(userTxn);
  auto added = blockingWait(users.addUser(*userTxn, f.user.uid, "w2-user", {}, false));
  ASSERT_OK(added);
  ASSERT_OK(blockingWait(userTxn->commit()));
  userTxn.reset();
  f.user.token = added->token;
  auto coordinator = std::make_unique<EcFileMutationCoordinator>(f.engine);
  auto bad = f.user;
  bad.token = "not-a-token";
  ASSERT_ERROR(blockingWait(coordinator->open(bad, f.opening)), StatusCode::kAuthenticationFail);
  auto claimed = f.user;
  claimed.uid = flat::Uid(702);
  ASSERT_ERROR(blockingWait(coordinator->open(claimed, f.opening)), StatusCode::kAuthenticationFail);
  auto pending = coordinator->open(f.user, f.opening);
  coordinator.reset();
  ASSERT_OK(blockingWait(std::move(pending)));  // copied state/request/token outlive facade
  coordinator = std::make_unique<EcFileMutationCoordinator>(f.engine);
  auto write = f.write();
  ASSERT_OK(blockingWait(coordinator->begin(f.user, write)));
  coordinator->closeAdmission();
  ASSERT_ERROR(blockingWait(coordinator->query(f.user, f.birth.object, write.request, f.opening.owner)),
               StorageClientCode::kResourceBusy);
  // Closing admission is not a physical drain or a cancellation of the record.
  EcFileMutationCoordinator restored(f.engine);
  auto queried = blockingWait(restored.query(f.user, f.birth.object, write.request, f.opening.owner));
  ASSERT_OK(queried);
  ASSERT_TRUE(*queried);
  EXPECT_EQ((**queried).intent.request, write.request);
}

TEST_F(TestEcFileMutation, PrivateFdbCommitThenLostAcknowledgementRetainsIdentityAndFenceConflict) {
  Fixture f;
  ASSERT_OK(f.initialize(true));
  ASSERT_OK(f.open());
  auto request = f.write();
  auto lost = [&]() -> CoTryTask<EcFileMutationRecord> {
    auto inner = f.engine->createReadWriteTransaction();
    Tx txn(*inner);
    auto accepted = co_await Mutations::begin(txn, request);
    CO_RETURN_ON_ERROR(accepted);
    CO_RETURN_ON_ERROR(co_await txn.commit());
    // Actual commit followed by a deliberately discarded acknowledgement;
    // this is not a FoundationDB 1021 fault injected inside the driver.
    co_return makeError(TransactionCode::kMaybeCommitted, "test discards acknowledgement after actual FDB commit");
  };
  ASSERT_ERROR(blockingWait(lost()), TransactionCode::kMaybeCommitted);
  auto query = f.run([&](Tx &t) { return Mutations::query(t, f.birth.object, request.request, f.opening.owner); });
  ASSERT_OK(query);
  ASSERT_TRUE(*query);
  EXPECT_EQ((**query).sessionSequence, 1u);
  auto replay = f.run([&](Tx &t) { return Mutations::begin(t, request); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*replay, **query));
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::sealPrefix(t, f.birth.object, request.request, f.opening.owner); }));
  publicationFenceConflict(f);
}
#include "EcFileAppendCatalogTests.inc"
}  // namespace
}  // namespace hf3fs::meta::server
