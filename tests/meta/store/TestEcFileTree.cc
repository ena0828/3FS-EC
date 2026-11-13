#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <type_traits>
#include <utility>

#include "common/kv/mem/MemKVEngine.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/EcV2Grants.h"
#include "fdb/FDBKVEngine.h"
#include "meta/store/EcExactGcCatalog.h"
#include "meta/store/EcTargetRetirementCatalog.h"
#include "meta/store/EcTerminalEvidence.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "storage/ec_scope/EcTargetRetirementExecutor.h"
#include "meta/store/EcFileExecutionCatalog.h"
#include "meta/store/EcFileRepairCatalog.h"
#include "meta/store/EcFileTreeCatalog.h"
#include "meta/store/EcFileTreeGcGuard.h"
#include "meta/store/EcFileTreeReadCatalog.h"
#include "meta/store/EcGcCompletionCatalog.h"
#include "meta/store/EcTreeGcCatalog.h"
#include "meta/store/EcTreeSourcePinCatalog.h"
#include "meta/store/EcV2BindingCatalog.h"
#include "meta/store/Inode.h"
#include "meta/store/detail/EcFileTreeKeys.h"
#include "storage/ec_codec/EcCodec.h"
#include "storage/ec_scope/EcScopeControlExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace detail {
struct EcTreeTestMetadata {
  EcObjectRef object;
  EcManifest manifest;
  EcV2AllocationBindings allocations;
  storage::EcSha256 contentSha256{};
};
// Metadata assembly only. This is intentionally not a production installer,
// seal, drain, publication certificate or claim. It never admits mode-2/3 data.
struct EcFileTreeTestAccess {
  static CoTryTask<EcTreeRoot> cut(EcTreeContext &context, const EcTreeCut &cut) {
    co_return co_await EcFileTreeCatalog::cut(context, cut);
  }
  static CoTryTask<EcTreeSlot> assemble(EcFileTreeTxnBudget &txn,
                                        const EcTreeBirth &birth,
                                        const EcTreeTestMetadata &installed) {
    using namespace ec_tree_detail;
    auto context = co_await EcFileTreeCatalog::open(txn, birth.object);
    CO_RETURN_ON_ERROR(context);
    if (!same(context->birth(), birth) || installed.object != birth.object)
      co_return makeError(StatusCode::kInvalidArg);
    const auto &m = installed.manifest;
    const auto mk = manifestKey(kv::KeyPrefix::EcTreeManifest, birth.object, m.stripe, m.revision);
    auto old = co_await txn.get(mk);
    CO_RETURN_ON_ERROR(old);
    if (*old) co_return makeError(StatusCode::kTokenDuplicated);
    EcManifestRecord record;
    record.manifest = m;
    CO_RETURN_ON_ERROR(
        co_await store(txn, manifestKey(kv::KeyPrefix::EcManifest, birth.object, m.stripe, m.revision), record));
    for (const auto &binding : installed.allocations) {
      auto bindingKey = allocationKey(kv::KeyPrefix::EcV2Allocation, binding.fragment.identity);
      CO_RETURN_ON_ERROR(bindingKey);
      CO_RETURN_ON_ERROR(co_await store(txn, *bindingKey, binding));
      auto refKey = allocationKey(kv::KeyPrefix::EcFragmentRef, binding.fragment.identity);
      CO_RETURN_ON_ERROR(refKey);
      EcFragmentRefRecord ref;
      ref.fragment = binding.fragment;
      ref.references = 1;
      CO_RETURN_ON_ERROR(co_await store(txn, *refKey, ref));
    }
    auto compact = EcFileTreeCatalog::commitment(birth.object, m, installed.allocations, installed.contentSha256);
    CO_RETURN_ON_ERROR(compact);
    CO_RETURN_ON_ERROR(co_await store(txn, mk, *compact));
    EcTreeSlot slot;
    slot.kind = EcTreeSlotKind::Data;
    slot.stripe = m.stripe;
    slot.revision = m.revision;
    slot.generation = m.generation;
    slot.logicalLength = m.logicalLength;
    slot.contentSha256 = installed.contentSha256;
    // Exercise the actual metadata validator before the seam can return a leaf.
    auto checked = co_await EcFileTreeCatalog::installed(*context, slot);
    CO_RETURN_ON_ERROR(checked);
    co_return slot;
  }
  static CoTryTask<EcTreeEditResult> data(EcTreeContext &context, const EcTreeEdit &edit) {
    co_return co_await EcFileTreeCatalog::replace(context, edit);
  }
  // Structural tree-layer fixture only: detach a whole validated root so one
  // final dense leaf can release all sixteen outgoing holds in one transaction.
  // This creates no public truncate/unlink path or data publication evidence.
  static CoTryTask<Void> detachRoot(EcFileTreeTxnBudget &txn, const EcTreeBirth &birth) {
    using namespace ec_tree_detail;
    auto context = co_await EcFileTreeCatalog::open(txn, birth.object);
    CO_RETURN_ON_ERROR(context);
    auto root = co_await EcFileTreeCatalog::getRoot(*context);
    CO_RETURN_ON_ERROR(root);
    if (root->root.is_nil() || root->sequence == std::numeric_limits<uint64_t>::max())
      co_return makeError(StatusCode::kInvalidArg);
    auto refs = co_await require<EcTreeNodeRefs>(txn, idKey(kv::KeyPrefix::EcTreeNodeRefs, birth.object, root->root));
    CO_RETURN_ON_ERROR(refs);
    if (refs->state != EcTreeRefState::Live || refs->references != 1 || refs->level != 15 || refs->prefix)
      co_return makeError(StatusCode::kDataCorruption);
    refs->references = 0;
    refs->state = EcTreeRefState::Reclaimable;
    EcTreeReclaimWork work;
    work.object = birth.object;
    work.node = root->root;
    CO_RETURN_ON_ERROR(co_await store(txn, idKey(kv::KeyPrefix::EcTreeReclaim, birth.object, root->root), work));
    CO_RETURN_ON_ERROR(co_await store(txn, idKey(kv::KeyPrefix::EcTreeNodeRefs, birth.object, root->root), *refs));
    root->root = Uuid::zero();
    root->visibleLength = 0;
    ++root->sequence;
    auto object = co_await EcCatalog::getObject(txn, birth.object);
    CO_RETURN_ON_ERROR(object);
    object->length = 0;
    CO_RETURN_ON_ERROR(co_await store(txn, objectKey(kv::KeyPrefix::EcObject, birth.object), *object));
    co_return co_await store(txn, objectKey(kv::KeyPrefix::EcTreeRoot, birth.object), *root);
  }
};
}  // namespace detail
namespace {
using namespace ec_tree_detail;
using folly::coro::blockingWait;
using Tree = EcFileTreeCatalog;
using Tx = EcFileTreeTxnBudget;
static_assert(!std::is_default_constructible_v<EcTreeContext>);
static_assert(!std::is_constructible_v<EcTreeContext, Tx &, EcTreeBirth>);

class TestEcFileTree : public hf3fs::testing::SetupFDB {};

struct Fixture {
  std::unique_ptr<kv::IKVEngine> engine;
  EcTreeBirth birth;
  Tx::Usage lastUsage;
  Fixture() {
    birth.object = {InodeId(2301), Uuid::random()};
    birth.creator = {flat::Uid(103), Uuid::random()};
    birth.createRequest = Uuid::random();
    birth.shardBytes = 64;
    birth.allowColocated = true;
  }
  auto run(auto fn, Tx::Limits limits = {}) {
    auto inner = engine->createReadWriteTransaction();
    Tx txn(*inner, limits);
    auto result = blockingWait(fn(txn));
    lastUsage = txn.usage();
    if (result) {
      auto committed = blockingWait(txn.commit());
      if (!committed) return decltype(result)(makeError(std::move(committed.error())));
    }
    return result;
  }
  auto runProfile(auto fn, Tx::Profile profile = Tx::Profile::Gc) {
    auto inner = engine->createReadWriteTransaction();
    Tx txn(*inner, profile);
    auto result = blockingWait(fn(txn));
    lastUsage = txn.usage();
    if (result) {
      auto committed = blockingWait(txn.commit());
      if (!committed) return decltype(result)(makeError(std::move(committed.error())));
    }
    return result;
  }
  Result<Void> initialize(bool fdb = false) {
    if (fdb) {
      const auto *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
      if (!cluster) return makeError(StatusCode::kInvalidConfig, "private FDB is required");
      kv::fdb::DB db(cluster, false);
      if (db.error()) return makeError(StatusCode::kInvalidConfig);
      engine = std::make_unique<kv::FDBKVEngine>(std::move(db));
    } else
      engine = std::make_unique<kv::MemKVEngine>();
    auto created = run([&](Tx &txn) { return Tree::createBirth(txn, birth); });
    RETURN_ON_ERROR(created);
    return Void{};
  }
  Result<EcTreeRoot> root() {
    return run([&](Tx &txn) -> CoTryTask<EcTreeRoot> {
      auto context = co_await Tree::open(txn, birth.object);
      CO_RETURN_ON_ERROR(context);
      co_return co_await Tree::getRoot(*context);
    });
  }
  EcTreeEdit edit(const EcTreeRoot &root, uint64_t stripe = 0) {
    EcTreeEdit value;
    value.object = birth.object;
    value.operation = Uuid::random();
    value.expectedRoot = root.root;
    value.expectedSequence = root.sequence;
    value.expectedEpoch = root.epoch;
    value.stripe = stripe;
    value.visibleLength = root.visibleLength;
    for (auto &id : value.nodeIds) id = Uuid::random();
    return value;
  }
  Result<EcTreeEditResult> apply(const EcTreeEdit &edit, bool testData = false, Tx::Limits limits = {}) {
    return run(
        [&](Tx &txn) -> CoTryTask<EcTreeEditResult> {
          auto context = co_await Tree::open(txn, birth.object);
          CO_RETURN_ON_ERROR(context);
          if (testData) co_return co_await detail::EcFileTreeTestAccess::data(*context, edit);
          co_return co_await Tree::replaceZero(*context, edit);
        },
        limits);
  }
  Result<EcTreeNodeRefs> reclaim(const Uuid &id) {
    return run([&](Tx &txn) -> CoTryTask<EcTreeNodeRefs> {
      auto context = co_await Tree::open(txn, birth.object);
      CO_RETURN_ON_ERROR(context);
      co_return co_await Tree::reclaimNode(*context, id);
    });
  }
  Result<detail::EcTreeTestMetadata> metadata(uint64_t stripe = 0) {
    const std::string logical(37, 'k');
    CHECK_RESULT(shards, storage::EcCodec::encode(logical, birth.shardBytes));
    std::array<std::string_view, 10> views;
    for (size_t i = 0; i < 10; ++i) views[i] = shards[i];
    CHECK_RESULT(sha, computeEcLogicalSha256(views, logical.size()));
    detail::EcTreeTestMetadata value;
    value.object = birth.object;
    value.contentSha256 = sha;
    auto &m = value.manifest;
    m.object = birth.object;
    m.stripe = stripe;
    m.revision = 1;
    m.generation = 1;
    m.logicalLength = logical.size();
    const auto operation = Uuid::random();
    for (size_t i = 0; i < 12; ++i) {
      auto &f = m.fragments[i];
      f.identity.object = birth.object.incarnation;
      f.identity.stripe = stripe;
      f.identity.generation = 1;
      f.identity.shard = i;
      f.identity.allocation = Uuid::random();
      f.operation = operation;
      f.placement = {storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(9)};
      CHECK_RESULT(descriptor, storage::computeEcIntegrity(f.identity, shards[i]));
      f.integrity = descriptor;
      auto &b = value.allocations[i];
      b.object = birth.object;
      b.fragment = f;
      b.writer = birth.creator;
      b.engineUuid = Uuid::random();
      b.targetIncarnation = Uuid::random();
    }
    return value;
  }
};

TEST_F(TestEcFileTree, FirstManifestActivationRejectsChangedEvidenceAndLeavesNoPartialHolds) {
  for (int corruption = 0; corruption < 4; ++corruption) {
    SCOPED_TRACE(corruption);
    Fixture f;
    ASSERT_OK(f.initialize());
    auto metadata = f.metadata();
    ASSERT_OK(metadata);
    auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
    ASSERT_OK(slot);
    auto root = f.root();
    ASSERT_OK(root);
    const auto &identity = metadata->manifest.fragments[11].identity;
    ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
      if (corruption == 0) {
        const auto key = manifestKey(kv::KeyPrefix::EcManifest, f.birth.object, slot->stripe, slot->revision);
        auto record = co_await EcCatalog::getManifest(t, f.birth.object, slot->stripe, slot->revision);
        CO_RETURN_ON_ERROR(record);
        record->manifest.fragments[11].operation = Uuid::random();
        co_return co_await store(t, key, *record);
      }
      if (corruption == 1) {
        auto key = allocationKey(kv::KeyPrefix::EcV2Allocation, identity);
        CO_RETURN_ON_ERROR(key);
        auto binding = co_await require<EcV2AllocationBinding>(t, *key);
        CO_RETURN_ON_ERROR(binding);
        binding->engineUuid = Uuid::random();
        co_return co_await store(t, *key, *binding);
      }
      if (corruption == 2) {
        auto key = allocationKey(kv::KeyPrefix::EcFragmentRef, identity);
        CO_RETURN_ON_ERROR(key);
        auto ref = co_await EcCatalog::getFragmentRef(t, identity);
        CO_RETURN_ON_ERROR(ref);
        ref->references = 0;
        co_return co_await store(t, *key, *ref);
      }
      auto key = allocationKey(kv::KeyPrefix::EcGcClaim, identity);
      CO_RETURN_ON_ERROR(key);
      // The last allocation fails after earlier hold writes in this attempt.
      CO_RETURN_ON_ERROR(co_await t.set(*key, "TEST-ONLY-PERMANENT-CLAIM-FENCE"));
      co_return Void{};
    }));
    auto edit = f.edit(*root);
    edit.replacement = *slot;
    edit.visibleLength = slot->logicalLength;
    auto rejected = f.apply(edit, true);
    ASSERT_ERROR(rejected, corruption == 3 ? StatusCode::kTokenStale : StatusCode::kDataCorruption);
    auto after = f.root();
    ASSERT_OK(after);
    EXPECT_EQ(serde::serialize(*after), serde::serialize(*root));
    ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
      auto compact = co_await require<EcTreeManifestHolds>(
          t,
          manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, slot->stripe, slot->revision));
      CO_RETURN_ON_ERROR(compact);
      if (compact->treeHolds) co_return makeError(StatusCode::kDataCorruption, "failed activation persisted a hold");
      for (const auto &fragment : metadata->manifest.fragments) {
        auto key = allocationKey(kv::KeyPrefix::EcTreeAllocationHold, fragment.identity);
        CO_RETURN_ON_ERROR(key);
        auto hold = co_await t.get(*key);
        CO_RETURN_ON_ERROR(hold);
        if (*hold) co_return makeError(StatusCode::kDataCorruption, "failed activation persisted an allocation hold");
      }
      auto node = co_await t.get(idKey(kv::KeyPrefix::EcTreeNode, f.birth.object, edit.nodeIds[0]));
      CO_RETURN_ON_ERROR(node);
      if (*node) co_return makeError(StatusCode::kDataCorruption, "failed activation persisted a new leaf");
      co_return Void{};
    }));
  }
}

TEST_F(TestEcFileTree, TreeRetirementRequiresZeroHoldsPinsAndCannotInventExecutionEvidence) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = 37;
  ASSERT_OK(f.apply(edit, true));
  EcRevisionRetirementReq req;
  req.object = f.birth.object;
  req.stripe = 0;
  req.revision = 1;
  req.client.uuid = Uuid::random();
  req.uuid = Uuid::random();
  auto retire = [&](const auto &q, bool query = false) {
    return f.run([&](Tx &t) { return EcTreeGcCatalog::retire(t, q, query); });
  };
  ASSERT_ERROR(retire(req), StatusCode::kTokenStale);
  auto current = f.root();
  ASSERT_OK(current);
  auto zero = f.edit(*current);
  ASSERT_OK(f.apply(zero));
  for (int level = 15; level >= 0; --level) ASSERT_OK(f.reclaim(edit.nodeIds[level]));
  for (const auto &id : edit.nodeIds) {
    ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
      auto body = co_await t.get(idKey(kv::KeyPrefix::EcTreeNode, f.birth.object, id));
      CO_RETURN_ON_ERROR(body);
      if (*body) co_return makeError(StatusCode::kDataCorruption, "terminal body was retained");
      auto refs =
          co_await ec_tree_detail::require<EcTreeNodeRefs>(t, idKey(kv::KeyPrefix::EcTreeNodeRefs, f.birth.object, id));
      CO_RETURN_ON_ERROR(refs);
      if (refs->state != EcTreeRefState::Reclaimed || refs->references)
        co_return makeError(StatusCode::kDataCorruption);
      co_return Void{};
    }));
    ASSERT_OK(f.reclaim(id));  // Tombstone-only replay, with no second decrement.
  }
  auto now = f.root();
  ASSERT_OK(now);
  auto reused = f.edit(*now);
  reused.nodeIds[0] = edit.nodeIds[0];
  ASSERT_ERROR(f.apply(reused), StatusCode::kTokenDuplicated);
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto m = co_await EcCatalog::getManifest(t, f.birth.object, 0, 1);
    CO_RETURN_ON_ERROR(m);
    m->pins = 1;
    co_return co_await ec_tree_detail::store(
        t,
        ec_tree_detail::manifestKey(kv::KeyPrefix::EcManifest, f.birth.object, 0, 1),
        *m);
  }));
  ASSERT_ERROR(retire(req), StatusCode::kTokenStale);
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto m = co_await EcCatalog::getManifest(t, f.birth.object, 0, 1);
    CO_RETURN_ON_ERROR(m);
    m->pins = 0;
    co_return co_await ec_tree_detail::store(
        t,
        ec_tree_detail::manifestKey(kv::KeyPrefix::EcManifest, f.birth.object, 0, 1),
        *m);
  }));
  auto retired = retire(req);
  ASSERT_OK(retired);
  ASSERT_TRUE(retired->referencesReleased);
  ASSERT_OK(retire(req));
  auto another = req;
  another.uuid = Uuid::random();
  ASSERT_OK(retire(another));
  auto changed = req;
  changed.stripe = 1;
  ASSERT_ERROR(retire(changed), StatusCode::kTokenMismatch);
  for (const auto &fragment : metadata->manifest.fragments) {
    auto ref = f.run([&](Tx &t) { return EcCatalog::getFragmentRef(t, fragment.identity); });
    ASSERT_OK(ref);
    EXPECT_EQ(ref->references, 0);
    EXPECT_TRUE(ref->gcCandidate);
  }
  // The W0 seam assembled real metadata but no production execution/T2. It
  // must never be promoted to physical eligibility by zero refcounts alone.
  folly::test::TemporaryDirectory directory;
  const auto path = directory.path() / "control.key";
  {
    std::ofstream out(path.string(), std::ios::binary);
    out << std::string(32, 'C');
  }
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  auto key = storage::EcScopeControlKey::loadFile(path.string());
  ASSERT_OK(key);
  const auto rejectedClaimId = Uuid::random();
  auto claim = f.run([&](Tx &t) {
    return EcTreeGcCatalog::claim(t, f.birth.object, metadata->manifest.fragments[0].identity, rejectedClaimId, **key);
  });
  ASSERT_FALSE(claim);
}

TEST_F(TestEcFileTree, NewBirthIsTypedAndCannotUpgradeFlatOrPartialHistory) {
  Fixture f;
  ASSERT_OK(f.initialize());
  ASSERT_OK(f.run([&](Tx &t) { return Tree::createBirth(t, f.birth); }));
  auto changed = f.birth;
  changed.createRequest = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return Tree::createBirth(t, changed); }), StatusCode::kTokenMismatch);
  auto oldApi = f.run([&](Tx &t) { return EcV2BindingCatalog::requireV2Mode(t, f.birth.object); });
  ASSERT_ERROR(oldApi, StatusCode::kDataCorruption);
  for (bool tracked : {false, true}) {
    const EcObjectRef old{InodeId(2502), Uuid::random()};
    const auto create = Uuid::random();
    ASSERT_OK(f.run([&](Tx &t) {
      return tracked ? EcV2BindingCatalog::createTrackedV2Object(t, old, 64, true, f.birth.creator, create)
                     : EcV2BindingCatalog::createV2Object(t, old, 64, true, f.birth.creator, create);
    }));
    auto attempt = f.birth;
    attempt.object = old;
    attempt.createRequest = create;
    ASSERT_ERROR(f.run([&](Tx &t) { return Tree::createBirth(t, attempt); }), StatusCode::kTokenMismatch);
  }
  const auto birthKey = objectKey(kv::KeyPrefix::EcTreeBirth, f.birth.object);
  ASSERT_OK(f.run([&](Tx &t) { return t.clear(birthKey); }));
  ASSERT_ERROR(f.root(), StatusCode::kDataCorruption);
  ASSERT_ERROR(f.run([&](Tx &t) { return Tree::createBirth(t, f.birth); }), StatusCode::kTokenMismatch);
}

TEST_F(TestEcFileTree, RealFdbSparseRootAndLostCommitReplayKeepAllFixedIds) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root, uint64_t{1} << 48);
  edit.visibleLength = (uint64_t{1} << 48) * 640 + 1;
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner);
  auto context = blockingWait(Tree::open(txn, f.birth.object));
  ASSERT_OK(context);
  auto saved = blockingWait(Tree::replaceZero(*context, edit));
  ASSERT_OK(saved);
  const auto observed = txn.usage();
  EXPECT_GT(observed.mutationBytes, 4096);
  EXPECT_LE(observed.totalBytes(), 256u << 10);
  EXPECT_GT(observed.keyOperations, 64);
  EXPECT_LE(observed.keyOperations, 1024);
  auto lost = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn.commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "test discards acknowledgement after actual FDB commit");
  };
  ASSERT_ERROR(blockingWait(lost()), TransactionCode::kMaybeCommitted);
  auto replay = f.apply(edit);
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*saved, *replay));
  auto changed = edit;
  changed.nodeIds[0] = Uuid::random();
  ASSERT_ERROR(f.apply(changed), StatusCode::kTokenMismatch);
  auto slot = f.run([&](Tx &t) -> CoTryTask<EcTreeSlot> {
    auto ctx = co_await Tree::open(t, f.birth.object);
    CO_RETURN_ON_ERROR(ctx);
    co_return co_await Tree::lookup(*ctx, edit.stripe);
  });
  ASSERT_OK(slot);
  EXPECT_EQ(slot->kind, EcTreeSlotKind::Zero);
  // New wrapper/transaction, original IDs, no recreated in-memory root proof.
  auto after = f.root();
  ASSERT_OK(after);
  EXPECT_EQ(after->root, edit.nodeIds[15]);
}

TEST_F(TestEcFileTree, RealFdbCompetingRootsConflictAndNodeTombstonesNeverReborn) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto root = f.root();
  ASSERT_OK(root);
  auto a = f.edit(*root, 1), b = f.edit(*root, 16);
  auto ra = f.engine->createReadWriteTransaction(), rb = f.engine->createReadWriteTransaction();
  Tx ta(*ra), tb(*rb);
  auto ca = blockingWait(Tree::open(ta, f.birth.object)), cb = blockingWait(Tree::open(tb, f.birth.object));
  ASSERT_OK(ca);
  ASSERT_OK(cb);
  ASSERT_OK(blockingWait(Tree::replaceZero(*ca, a)));
  ASSERT_OK(blockingWait(Tree::replaceZero(*cb, b)));
  ASSERT_OK(blockingWait(ta.commit()));
  ASSERT_ERROR(blockingWait(tb.commit()), TransactionCode::kConflict);
  auto current = f.root();
  ASSERT_OK(current);
  auto next = f.edit(*current, 1);
  ASSERT_OK(f.apply(next));
  for (int level = 15; level >= 0; --level) {
    auto reclaimed = f.reclaim(a.nodeIds[level]);
    ASSERT_OK(reclaimed);
    EXPECT_EQ(reclaimed->state, EcTreeRefState::Reclaimed);
    auto again = f.reclaim(a.nodeIds[level]);
    ASSERT_OK(again);
    EXPECT_TRUE(same(*again, *reclaimed));
  }
  current = f.root();
  ASSERT_OK(current);
  auto aba = f.edit(*current);
  aba.nodeIds[0] = a.nodeIds[0];
  ASSERT_ERROR(f.apply(aba), StatusCode::kTokenDuplicated);
  auto unchanged = f.root();
  ASSERT_OK(unchanged);
  EXPECT_TRUE(same(*unchanged, *current));
}

TEST_F(TestEcFileTree, BudgetCountsActualKeyValueBytesAndRejectsCommitAfterOverflow) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner, {128, 5});
  ASSERT_OK(blockingWait(txn.set("alpha", "1234567")));
  ASSERT_OK(blockingWait(txn.set("beta", "123")));
  EXPECT_EQ(txn.usage().mutationBytes, 5 + 7 + 4 + 3);
  EXPECT_EQ(txn.usage().conflictBytes, 5 + 4);
  ASSERT_ERROR(blockingWait(txn.set("gamma", std::string(128, 'x'))), StatusCode::kInvalidArg);
  EXPECT_TRUE(txn.poisoned());
  ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
  auto check = f.engine->createReadWriteTransaction();
  auto absent = blockingWait(check->get("alpha"));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  ASSERT_ERROR(f.apply(edit, false, {4096, 1024}), StatusCode::kInvalidArg);
  auto unchanged = f.root();
  ASSERT_OK(unchanged);
  EXPECT_TRUE(same(*root, *unchanged));
  ASSERT_OK(f.apply(edit));
  EXPECT_GT(f.lastUsage.mutationBytes, 4096);
  EXPECT_LE(f.lastUsage.totalBytes(), 256u << 10);
}

TEST_F(TestEcFileTree, ResetInvalidatesTypedContextAndSnapshotReadsCannotBypassConflicts) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner);
  auto context = blockingWait(Tree::open(txn, f.birth.object));
  ASSERT_OK(context);
  txn.reset();
  ASSERT_ERROR(blockingWait(Tree::getRoot(*context)), StatusCode::kTokenStale);
  ASSERT_ERROR(blockingWait(txn.snapshotGet("key")), StatusCode::kInvalidArg);
  ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
}

TEST_F(TestEcFileTree, FixedArrayCountsRangeOverflowAndUnusedZeroFieldsAreRejected) {
  std::array<Uuid, 16> output{};
  std::array<Uuid, 15> shortInput{};
  auto bytes = serde::serialize(shortInput);
  ASSERT_ERROR(serde::deserialize(output, bytes), StatusCode::kInvalidFormat);
  Fixture f;
  ASSERT_OK(f.initialize());
  auto root = f.root();
  ASSERT_OK(root);
  auto overflow = f.edit(*root, std::numeric_limits<uint64_t>::max());
  ASSERT_ERROR(f.apply(overflow), StatusCode::kInvalidArg);
  ASSERT_ERROR(rangeEnd(std::numeric_limits<uint64_t>::max(), 1), StatusCode::kInvalidArg);
  auto changed = f.edit(*root);
  changed.replacement.revision = 1;
  ASSERT_ERROR(f.apply(changed), StatusCode::kNotImplemented);
  auto duplicate = f.edit(*root);
  duplicate.nodeIds[1] = duplicate.nodeIds[0];
  ASSERT_ERROR(f.apply(duplicate), StatusCode::kInvalidArg);
}

TEST_F(TestEcFileTree, SameModeMetadataSeamHoldsUntilTheLastLeafThenReclaimIsIdempotent) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  auto slot = f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::assemble(txn, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto a = f.edit(*root);
  a.replacement = *slot;
  a.visibleLength = slot->logicalLength;
  ASSERT_ERROR(f.apply(a), StatusCode::kNotImplemented);
  ASSERT_OK(f.apply(a, true));
  const auto identity = metadata->manifest.fragments[0].identity;
  ASSERT_ERROR(f.run([&](Tx &txn) { return EcFileTreeGcGuard::requireUnheld(txn, f.birth.object, identity); }),
               StatusCode::kTokenStale);
  root = f.root();
  ASSERT_OK(root);
  auto b = f.edit(*root, 1);
  ASSERT_OK(f.apply(b));
  for (int level = 15; level >= 0; --level) ASSERT_OK(f.reclaim(a.nodeIds[level]));
  ASSERT_ERROR(f.run([&](Tx &txn) { return EcFileTreeGcGuard::requireUnheld(txn, f.birth.object, identity); }),
               StatusCode::kTokenStale);
  root = f.root();
  ASSERT_OK(root);
  auto zero = f.edit(*root, 0);
  ASSERT_OK(f.apply(zero));
  for (int level = 15; level >= 0; --level) {
    ASSERT_OK(f.reclaim(b.nodeIds[level]));
    ASSERT_OK(f.reclaim(b.nodeIds[level]));
  }
  ASSERT_OK(f.run([&](Tx &txn) { return EcFileTreeGcGuard::requireUnheld(txn, f.birth.object, identity); }));
  // Releasing a tree hold alone does NOT retire the manifest/allocation refs.
  auto ref = f.run([&](Tx &txn) { return EcCatalog::getFragmentRef(txn, identity); });
  ASSERT_OK(ref);
  EXPECT_EQ(ref->references, 1);
  EXPECT_FALSE(ref->gcCandidate);
}

TEST_F(TestEcFileTree, RealFdbHoldAndPermanentClaimFenceConflictInBothCommitOrders) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  for (bool claimFirst : {false, true}) {
    Fixture f;
    ASSERT_OK(f.initialize(true));
    auto metadata = f.metadata();
    ASSERT_OK(metadata);
    auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
    ASSERT_OK(slot);
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root);
    edit.replacement = *slot;
    edit.visibleLength = slot->logicalLength;
    const auto identity = metadata->manifest.fragments[0].identity;
    auto first = f.engine->createReadWriteTransaction(), second = f.engine->createReadWriteTransaction();
    Tx hold(*first), claim(*second);
    auto ctx = blockingWait(Tree::open(hold, f.birth.object));
    ASSERT_OK(ctx);
    ASSERT_OK(blockingWait(detail::EcFileTreeTestAccess::data(*ctx, edit)));
    ASSERT_OK(blockingWait(EcFileTreeGcGuard::requireUnheld(claim, f.birth.object, identity)));
    auto key = allocationKey(kv::KeyPrefix::EcGcClaim, identity);
    ASSERT_OK(key);
    // Exact conflict-key experiment, not a valid G0 claim or deletion permit.
    ASSERT_OK(blockingWait(claim.set(*key, "TEST-ONLY-CLAIM-FENCE-NOT-A-CERTIFICATE")));
    if (claimFirst) {
      ASSERT_OK(blockingWait(claim.commit()));
      ASSERT_ERROR(blockingWait(hold.commit()), TransactionCode::kConflict);
      ASSERT_ERROR(f.apply(edit, true), StatusCode::kTokenStale);
    } else {
      ASSERT_OK(blockingWait(hold.commit()));
      ASSERT_ERROR(blockingWait(claim.commit()), TransactionCode::kConflict);
    }
  }
}

TEST_F(TestEcFileTree, RealFdbDenseDataLeafAndSiblingCopiesStayWithinMeasuredBudget) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  f.birth.shardBytes = storage::kEcFragmentRpcMaxBytes;
  ASSERT_OK(f.initialize(true));
  std::array<EcTreeEditResult, 16> edits;
  size_t maximumBytes = 0, maximumKeys = 0;
  auto rememberUsage = [&] {
    maximumBytes = std::max(maximumBytes, f.lastUsage.totalBytes());
    maximumKeys = std::max(maximumKeys, f.lastUsage.keyOperations);
    EXPECT_LE(f.lastUsage.totalBytes(), 256u << 10);
    EXPECT_LE(f.lastUsage.keyOperations, 1024);
  };
  for (uint64_t stripe = 0; stripe < 16; ++stripe) {
    auto metadata = f.metadata(stripe);
    ASSERT_OK(metadata);
    ASSERT_EQ(metadata->manifest.fragments[0].integrity.blockCount, storage::kEcIntegrityMaxBlocks);
    auto slot = f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::assemble(txn, f.birth, *metadata); });
    ASSERT_OK(slot);
    rememberUsage();
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root, stripe);
    edit.replacement = *slot;
    auto start = stripeStart(stripe, f.birth.shardBytes);
    ASSERT_OK(start);
    edit.visibleLength = *start + slot->logicalLength;
    auto applied = f.apply(edit, true);
    ASSERT_OK(applied);
    edits[stripe] = *applied;
    rememberUsage();
    // Drain the previous path so the current dense leaf eventually owns the
    // last hold of every manifest; no old copy masks final release work.
    if (stripe)
      for (int level = 15; level >= 0; --level) {
        ASSERT_OK(f.reclaim(edits[stripe - 1].intent.nodeIds[level]));
        rememberUsage();
      }
  }
  // Populate every representable sibling position on the path of stripe zero.
  // Each insertion is its own bounded transaction, not one enormous FDB batch.
  for (uint8_t level = 1; level < 16; ++level)
    for (uint64_t child = 1; child < 16; ++child) {
      const uint64_t stripe = child << (4 * level);
      if (!stripeStart(stripe, f.birth.shardBytes)) continue;
      auto root = f.root();
      ASSERT_OK(root);
      auto edit = f.edit(*root, stripe);
      ASSERT_OK(f.apply(edit));
      rememberUsage();
    }
  auto root = f.root();
  ASSERT_OK(root);
  auto copy = f.edit(*root, 0);
  auto data = f.run([&](Tx &txn) -> CoTryTask<EcTreeSlot> {
    auto context = co_await Tree::open(txn, f.birth.object);
    CO_RETURN_ON_ERROR(context);
    co_return co_await Tree::lookup(*context, 0);
  });
  ASSERT_OK(data);
  rememberUsage();
  copy.replacement = *data;
  ASSERT_OK(f.apply(copy, true));
  rememberUsage();
  EXPECT_GT(maximumBytes, 32u << 10);
  EXPECT_GT(maximumKeys, 100);
  RecordProperty("w0_measured_dense_max_key_value_conflict_bytes", std::to_string(maximumBytes));
  RecordProperty("w0_measured_dense_max_key_operations", std::to_string(maximumKeys));
  // A normal successful wrapper transaction is the evidence, not a precomputed
  // depth estimate. This metadata seam is not a mode-4 data publication proof.
}

TEST_F(TestEcFileTree, RealFdbDenseLeafFinalReleaseIsBoundedAndDoesNotReleaseManifestReferences) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  f.birth.shardBytes = storage::kEcFragmentRpcMaxBytes;
  ASSERT_OK(f.initialize(true));
  std::array<EcTreeEditResult, 16> history;
  std::array<EcTreeSlot, 16> slots;
  std::array<std::array<storage::EcFragmentIdentity, 12>, 16> identities;
  for (uint64_t stripe = 0; stripe < 16; ++stripe) {
    auto metadata = f.metadata(stripe);
    ASSERT_OK(metadata);
    for (size_t shard = 0; shard < 12; ++shard)
      identities[stripe][shard] = metadata->manifest.fragments[shard].identity;
    auto slot = f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::assemble(txn, f.birth, *metadata); });
    ASSERT_OK(slot);
    slots[stripe] = *slot;
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root, stripe);
    edit.replacement = *slot;
    edit.visibleLength = stripe * uint64_t(f.birth.shardBytes) * 10 + slot->logicalLength;
    auto applied = f.apply(edit, true);
    ASSERT_OK(applied);
    history[stripe] = *applied;
    if (stripe)
      for (int level = 15; level >= 0; --level) ASSERT_OK(f.reclaim(history[stripe - 1].intent.nodeIds[level]));
  }
  // W0 has no public truncate; the private structural seam removes the root
  // reference atomically. Prior copies were already reclaimed, so leaf0 now
  // releases sixteen manifests / 192 allocation holds in a single real call.
  ASSERT_OK(f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::detachRoot(txn, f.birth); }));
  size_t maximumBytes = 0, maximumKeys = 0;
  for (int level = 15; level >= 0; --level) {
    ASSERT_OK(f.reclaim(history.back().intent.nodeIds[level]));
    maximumBytes = std::max(maximumBytes, f.lastUsage.totalBytes());
    maximumKeys = std::max(maximumKeys, f.lastUsage.keyOperations);
    EXPECT_LE(f.lastUsage.totalBytes(), 256u << 10);
    EXPECT_LE(f.lastUsage.keyOperations, 1024);
  }
  EXPECT_GT(maximumKeys, 384);  // Actual 192 ECTA get/set pairs, plus node/manifest accounting.
  // Reinstall the same immutable metadata under a new COW path. This second
  // pass measures the real RPC60 catalog path, including all sixteen complete
  // manifest hints and the permanent ECTJ result. It does not replace the W0
  // 256 KiB assertions above or model Storage deletion.
  for (uint64_t stripe = 0; stripe < 16; ++stripe) {
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root, stripe);
    edit.replacement = slots[stripe];
    edit.visibleLength = stripe * uint64_t(f.birth.shardBytes) * 10 + slots[stripe].logicalLength;
    auto applied = f.apply(edit, true);
    ASSERT_OK(applied);
    history[stripe] = *applied;
    if (stripe)
      for (int level = 15; level >= 0; --level) ASSERT_OK(f.reclaim(history[stripe - 1].intent.nodeIds[level]));
  }
  ASSERT_OK(f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::detachRoot(txn, f.birth); }));
  size_t gcBytes = 0, gcKeys = 0, gcMutationConflict = 0;
  for (int level = 15; level >= 0; --level) {
    AdvanceEcTreeReclaimReq request;
    request.object = f.birth.object;
    request.node = history.back().intent.nodeIds[level];
    request.client.uuid = f.birth.creator.client;
    request.uuid = Uuid::random();
    auto result = f.runProfile([&](Tx &txn) { return EcTreeGcCatalog::reclaimRequest(txn, request, false); });
    ASSERT_OK(result);
    ASSERT_TRUE(result->needsCommit);
    ASSERT_TRUE(result->response.progress.reclaimed);
    gcBytes = std::max(gcBytes, f.lastUsage.totalBytes());
    gcKeys = std::max(gcKeys, f.lastUsage.keyOperations);
    gcMutationConflict = std::max(gcMutationConflict, f.lastUsage.mutationAndConflictBytes());
    EXPECT_LE(f.lastUsage.totalBytes(), 2u << 20);
    EXPECT_LE(f.lastUsage.keyOperations, 8192);
    if (!level) {
      for (size_t stripe = 0; stripe < 16; ++stripe) {
        EXPECT_TRUE(same(result->response.progress.revisions[stripe], slots[stripe]));
        EXPECT_TRUE(same(result->response.progress.identities[stripe].fragments, identities[stripe]));
      }
    }
    // The same permanent identity recovers the complete response after the
    // deleting commit, even in readonly mode and after ECNT has disappeared.
    auto replay = f.runProfile([&](Tx &txn) { return EcTreeGcCatalog::reclaimRequest(txn, request, true); });
    ASSERT_OK(replay);
    EXPECT_FALSE(replay->needsCommit);
    EXPECT_TRUE(same(replay->response, result->response));
    auto changed = request;
    changed.node = Uuid::random();
    ASSERT_ERROR(f.runProfile([&](Tx &txn) { return EcTreeGcCatalog::reclaimRequest(txn, changed, false); }),
                 StatusCode::kTokenMismatch);
  }
  RecordProperty("gc_rpc60_max_key_value_conflict_bytes", std::to_string(gcBytes));
  RecordProperty("gc_rpc60_max_key_operations", std::to_string(gcKeys));
  RecordProperty("gc_rpc60_max_mutation_and_conflict_bytes", std::to_string(gcMutationConflict));
  for (const auto &stripe : identities)
    for (const auto &identity : stripe) {
      ASSERT_OK(f.run([&](Tx &txn) { return EcFileTreeGcGuard::requireUnheld(txn, f.birth.object, identity); }));
      auto ref = f.run([&](Tx &txn) { return EcCatalog::getFragmentRef(txn, identity); });
      ASSERT_OK(ref);
      EXPECT_EQ(ref->references, 1);
      EXPECT_FALSE(ref->gcCandidate);
    }
  RecordProperty("w0_measured_reclaim_max_key_value_conflict_bytes", std::to_string(maximumBytes));
  RecordProperty("w0_measured_reclaim_max_key_operations", std::to_string(maximumKeys));
}

// This fixture holds known test keys and models signed observations. It does
// not start Storage, create a physical fragment, or prove 22 failure domains.
// The actual catalogs still verify every MAC and the complete endpoint set.
std::string_view gcBudgetBytes(const auto &bytes) {
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}
Result<storage::EcSha256> gcBudgetSha(std::string_view input) {
  storage::EcSha256 result{};
  unsigned length = 0;
  if (EVP_Digest(input.data(), input.size(), result.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != result.size())
    return makeError(StatusCode::kIOError);
  return result;
}
Result<storage::EcSha256> gcBudgetMac(std::string_view key, std::string_view input) {
  storage::EcSha256 result{};
  unsigned length = 0;
  if (!HMAC(EVP_sha256(),
            key.data(),
            int(key.size()),
            reinterpret_cast<const unsigned char *>(input.data()),
            input.size(),
            result.data(),
            &length) ||
      length != result.size())
    return makeError(StatusCode::kIOError);
  return result;
}
Result<EcV2DrainObservation> gcBudgetObservation(const EcV2DrainRecord &drain,
                                                 size_t index,
                                                 const storage::EcScopeControlKey &key,
                                                 std::string_view rawKey) {
  constexpr uint64_t now = 1700000000;
  CHECK_RESULT(request, EcV2DrainCatalog::makeRequest(drain, index, storage::EcScopeControlAction::Revoke, key, now));
  const auto &r = request.claims;
  std::string deny = "3FSECDN1";
  const auto uuid = [&](const Uuid &id) { deny.append(id.asStringView()); };
  const auto integer = [&](uint64_t value, size_t width) {
    for (size_t n = width; n; --n) deny.push_back(char(value >> ((n - 1) * 8)));
  };
  uuid(r.engineUuid);
  uuid(r.targetIncarnation);
  integer(r.chainId.toUnderType(), 4);
  integer(r.targetId.toUnderType(), 8);
  uuid(r.object);
  integer(uint8_t(r.scopeKind), 1);
  uuid(r.scopeId);
  integer(r.ownerUid.toUnderType(), 4);
  uuid(r.clientNamespace);
  uuid(r.revocationId);
  deny.append(gcBudgetBytes(r.endpointSetDigest));
  if (deny.size() != 153) return makeError(StatusCode::kDataCorruption);
  storage::EcScopeControlAckClaims claims;
  CHECK_RESULT(requestHash, gcBudgetSha(gcBudgetBytes(storage::ec_scope_control_detail::Codec::encode(r))));
  CHECK_RESULT(denyHash, gcBudgetSha(deny));
  claims.requestDigest = requestHash;
  claims.revocationDigest = denyHash;
  claims.bootNonce = Uuid::random();
  claims.durable = true;
  claims.state = storage::EcScopeControlState::Drained;
  claims.observedAtSeconds = now;
  const auto encoded = storage::ec_scope_control_detail::Codec::encode(claims);
  CHECK_RESULT(mac, gcBudgetMac(rawKey, gcBudgetBytes(encoded)));
  // The production ACK uses an array of two fields, not a Serde table.
  const std::array<std::string, 2> wire{std::string(gcBudgetBytes(encoded)), std::string(gcBudgetBytes(mac))};
  storage::EcScopeControlAck ack;
  RETURN_ON_ERROR(serde::deserialize(ack, serde::serialize(wire)));
  RETURN_ON_ERROR(storage::verifyEcScopeControlAck(key, ack, request));
  return EcV2DrainObservation{std::move(request), std::move(ack)};
}

TEST_F(TestEcFileTree, RealFdbRepairTwentyTwoAckClaimAndCompletionUseOneMeasuredBudget) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  f.birth.shardBytes = storage::kEcFragmentRpcMaxBytes;
  uint64_t randomInode = 0;
  const auto randomId = Uuid::random();
  std::memcpy(&randomInode, randomId.data, sizeof(randomInode));
  f.birth.object.inode = InodeId((randomInode & InodeId::normalMax().u64()) | 0x101);
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  for (const auto &fragment : metadata->manifest.fragments) EXPECT_EQ(fragment.integrity.blockCount, 16);
  auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = slot->logicalLength;
  ASSERT_OK(f.apply(edit, true));
  root = f.root();
  ASSERT_OK(root);
  flat::UserInfo user(f.birth.creator.uid, flat::Gid(103));
  EcFileOpenIntent opening;
  opening.object = f.birth.object;
  opening.birth = f.birth.createRequest;
  opening.owner = f.birth.creator;
  opening.session = Uuid::random();
  opening.openRequest = Uuid::random();
  opening.rights = kEcSessionRead | kEcSessionWrite;
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto old = co_await Inode::load(t, f.birth.object.inode);
    CO_RETURN_ON_ERROR(old);
    if (*old) co_return makeError(StatusCode::kTokenDuplicated);
    EcManifestLayoutV1 ec;
    ec.incarnation = f.birth.object.incarnation;
    ec.shardBytes = f.birth.shardBytes;
    Layout layout{ChainTableId(0), ChainTableVersion(0), 0, 0, ec};
    auto inode =
        Inode::newFile(f.birth.object.inode, Acl(user.uid, user.gid, Permission(0600)), layout, UtcClock::now());
    inode.asFile().length = root->visibleLength;
    CO_RETURN_ON_ERROR(co_await inode.store(t));
    auto object = co_await EcCatalog::getObject(t, f.birth.object);
    CO_RETURN_ON_ERROR(object);
    object->nextGeneration = object->nextRevision = 2;
    CO_RETURN_ON_ERROR(co_await store(t, objectKey(kv::KeyPrefix::EcObject, f.birth.object), *object));
    auto opened = co_await EcFileSessionCatalog::open(t, user, opening);
    CO_RETURN_ON_ERROR(opened);
    co_return Void{};
  }));
  EcFileRepairIntent intent;
  intent.object = f.birth.object;
  intent.owner = f.birth.creator;
  intent.session = opening.session;
  intent.request = Uuid::random();
  intent.operation = Uuid::random();
  intent.child = Uuid::random();
  intent.sourcePin = Uuid::random();
  intent.expectedRoot = root->root;
  intent.expectedSequence = root->sequence;
  intent.expectedEpoch = root->epoch;
  intent.replacementMask = 3;
  intent.selection.planId = Uuid::random();
  intent.selection.maxBlocksInFlight = 4;
  for (size_t n = 0; n < 10; ++n) intent.selection.sourceOrder[n] = uint8_t(n + 2);
  for (auto &id : intent.nodeIds) id = Uuid::random();
  size_t maximumBytes = 0, maximumKeys = 0, maximumMutationConflict = 0;
  const auto measured = [&] {
    maximumBytes = std::max(maximumBytes, f.lastUsage.totalBytes());
    maximumKeys = std::max(maximumKeys, f.lastUsage.keyOperations);
    maximumMutationConflict = std::max(maximumMutationConflict, f.lastUsage.mutationAndConflictBytes());
    EXPECT_LE(f.lastUsage.totalBytes(), 2u << 20);
    EXPECT_LE(f.lastUsage.keyOperations, 8192);
  };
  auto accepted = f.runProfile([&](Tx &t) { return EcFileRepairCatalog::begin(t, intent); }, Tx::Profile::Repair);
  ASSERT_OK(accepted);
  measured();
  EcFileExecutionCatalog::TrustedPool fresh;
  for (size_t n = 0; n < 12; ++n)
    fresh[n] = {{storage::ChainId(300 + n), storage::TargetId(400 + n), flat::NodeId(19)},
                Uuid::random(),
                Uuid::random()};
  auto bound = f.runProfile(
      [&](Tx &t) -> CoTryTask<EcFileExecutionObservation> {
        auto reserved = co_await EcFileExecutionCatalog::reserveExecution(t,
                                                                          intent.owner,
                                                                          intent.object,
                                                                          intent.child,
                                                                          fresh,
                                                                          0,
                                                                          EcFileExecutionOwner::Repair);
        CO_RETURN_ON_ERROR(reserved);
        co_return co_await EcFileExecutionCatalog::bindRepairOutput(t, intent.owner, intent.object, intent.child);
      },
      Tx::Profile::Repair);
  ASSERT_OK(bound);
  measured();
  ASSERT_EQ(bound->record.endpoints.count, 22);
  ASSERT_TRUE(bound->record.allocations);
  for (const auto &allocation : *bound->record.allocations) EXPECT_EQ(allocation.fragment.integrity.blockCount, 16);

  folly::test::TemporaryDirectory keys;
  const std::string rawControl(32, 'C'), rawGc(32, 'G');
  const auto controlPath = keys.path() / "control.key", gcPath = keys.path() / "gc.key";
  {
    std::ofstream out(controlPath.string(), std::ios::binary);
    out << rawControl;
  }
  {
    std::ofstream out(gcPath.string(), std::ios::binary);
    out << rawGc;
  }
  ASSERT_EQ(::chmod(controlPath.c_str(), 0600), 0);
  ASSERT_EQ(::chmod(gcPath.c_str(), 0600), 0);
  auto control = storage::EcScopeControlKey::loadFile(controlPath.string());
  auto gc = storage::EcGcKey::loadFile(gcPath.string(), Uuid::random(), {});
  ASSERT_OK(control);
  ASSERT_OK(gc);
  const auto authority = Uuid::random(), revocation = Uuid::random();
  auto closing = f.runProfile(
      [&](Tx &t) {
        return EcFileExecutionCatalog::startCancelClosing(t,
                                                          intent.owner,
                                                          intent.object,
                                                          intent.child,
                                                          authority,
                                                          revocation);
      },
      Tx::Profile::Repair);
  ASSERT_OK(closing);
  measured();
  ASSERT_EQ(closing->identity.endpoints.count, 22);
  for (size_t n = 0; n < 22; ++n) {
    if (n == 21) {
      ASSERT_ERROR(
          f.runProfile(
              [&](Tx &t) {
                return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, **control);
              },
              Tx::Profile::Repair),
          StatusCode::kTokenStale);
    }
    auto observation = gcBudgetObservation(*closing, n, **control, rawControl);
    ASSERT_OK(observation);
    auto saved = f.runProfile(
        [&](Tx &t) {
          return EcFileExecutionCatalog::recordAck(t,
                                                   intent.owner,
                                                   intent.object,
                                                   intent.child,
                                                   n,
                                                   **control,
                                                   observation->request,
                                                   observation->ack);
        },
        Tx::Profile::Repair);
    ASSERT_OK(saved);
    measured();
  }
  // The release step may reconstruct inactive records only after get() has
  // checked every persisted field. Damage must not be overwritten as release.
  auto reservedKey = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, bound->record.candidates[11].identity);
  ASSERT_OK(reservedKey);
  auto reserved = f.runProfile([&](Tx &t) { return require<EcFileExecutionAllocation>(t, *reservedKey); });
  ASSERT_OK(reserved);
  ASSERT_TRUE(reserved->active);
  for (int corruption = 0; corruption < 6; ++corruption) {
    SCOPED_TRACE(corruption);
    auto damaged = *reserved;
    switch (corruption) {
      case 0:
        ++damaged.version;
        break;
      case 1:
        damaged.object.incarnation = Uuid::random();
        break;
      case 2:
        damaged.child = Uuid::random();
        break;
      case 3:
        damaged.allocation.writer.client = Uuid::random();
        break;
      case 4:
        damaged.allocation.endpoint.engineUuid = Uuid::random();
        break;
      case 5:
        damaged.active = false;
        break;
    }
    const auto bytes = serde::serialize(damaged);
    ASSERT_OK(f.runProfile([&](Tx &t) { return store(t, *reservedKey, damaged); }));
    ASSERT_ERROR(
        f.runProfile(
            [&](Tx &t) {
              return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, **control);
            },
            Tx::Profile::Repair),
        StatusCode::kDataCorruption);
    auto persisted = f.runProfile([&](Tx &t) { return t.get(*reservedKey); });
    ASSERT_OK(persisted);
    ASSERT_TRUE(*persisted);
    EXPECT_EQ(**persisted, bytes);
    ASSERT_OK(f.runProfile([&](Tx &t) -> CoTryTask<Void> {
      auto execution =
          co_await require<EcFileExecutionRecord>(t,
                                                  idKey(kv::KeyPrefix::EcFileExecution, intent.object, intent.child));
      CO_RETURN_ON_ERROR(execution);
      if (execution->state != EcFileExecutionState::Closing)
        co_return makeError(StatusCode::kDataCorruption, "failed release changed execution state");
      for (size_t n = 0; n < 11; ++n) {
        auto key = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, bound->record.candidates[n].identity);
        CO_RETURN_ON_ERROR(key);
        auto held = co_await require<EcFileExecutionAllocation>(t, *key);
        CO_RETURN_ON_ERROR(held);
        if (!held->active)
          co_return makeError(StatusCode::kDataCorruption, "failed release persisted a partial update");
      }
      co_return Void{};
    }));
    ASSERT_OK(f.runProfile([&](Tx &t) { return store(t, *reservedKey, *reserved); }));
  }
  auto drained = f.runProfile(
      [&](Tx &t) {
        return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, **control);
      },
      Tx::Profile::Repair);
  ASSERT_OK(drained);
  measured();
  ASSERT_EQ(drained->record.state, EcFileExecutionState::Aborted);
  auto drainReplay = f.runProfile(
      [&](Tx &t) {
        return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, **control);
      },
      Tx::Profile::Repair);
  ASSERT_OK(drainReplay);
  EXPECT_EQ(serde::serialize(drainReplay->record), serde::serialize(drained->record));
  ASSERT_OK(f.runProfile([&](Tx &t) -> CoTryTask<Void> {
    for (const auto &candidate : drained->record.candidates) {
      auto key = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, candidate.identity);
      CO_RETURN_ON_ERROR(key);
      auto released = co_await require<EcFileExecutionAllocation>(t, *key);
      CO_RETURN_ON_ERROR(released);
      if (released->active) co_return makeError(StatusCode::kDataCorruption, "terminal replay reactivated a candidate");
    }
    co_return Void{};
  }));
  const auto identity = (*drained->record.allocations)[0].fragment.identity;
  const auto claimId = Uuid::random();
  // A corrupted twenty-second MAC must block G0 although all earlier slots
  // remain valid and the serialized endpoint count is still exactly 22.
  auto corrupt = drained->record;
  corrupt.drain->observations[21]->ack.claims.bootNonce = Uuid::random();
  ASSERT_OK(f.runProfile(
      [&](Tx &t) { return store(t, idKey(kv::KeyPrefix::EcFileExecution, intent.object, intent.child), corrupt); }));
  ASSERT_ERROR(
      f.runProfile([&](Tx &t) { return EcExactGcCatalog::claim(t, intent.object, identity, claimId, **control); }),
      StatusCode::kAuthenticationFail);
  ASSERT_OK(f.runProfile([&](Tx &t) {
    return store(t, idKey(kv::KeyPrefix::EcFileExecution, intent.object, intent.child), drained->record);
  }));
  auto claim =
      f.runProfile([&](Tx &t) { return EcExactGcCatalog::claim(t, intent.object, identity, claimId, **control); });
  ASSERT_OK(claim);
  measured();
  auto replay =
      f.runProfile([&](Tx &t) { return EcExactGcCatalog::claim(t, intent.object, identity, claimId, **control); });
  ASSERT_OK(replay);
  measured();
  EXPECT_TRUE(same(*claim, *replay));
  const auto changedClaimId = Uuid::random();
  ASSERT_ERROR(f.runProfile([&](Tx &t) {
    return EcExactGcCatalog::claim(t, intent.object, identity, changedClaimId, **control);
  }),
               StatusCode::kTokenMismatch);

  using Codec = storage::ec_gc_control_detail::Codec;
  auto certificate = EcGcCompletionCatalog::project(*claim);
  ASSERT_OK(certificate);
  storage::EcGcRequestClaims requestClaims;
  requestClaims.keyId = (*gc)->keyId();
  requestClaims.authority = authority;
  requestClaims.nonce = Uuid::random();
  requestClaims.issuedAtSeconds = 1700000000;
  requestClaims.expiresAtSeconds = 1700000060;
  requestClaims.certificate = *certificate;
  const auto requestBytes = Codec::encode(requestClaims);
  auto requestMac = gcBudgetMac(rawGc, gcBudgetBytes(requestBytes));
  ASSERT_OK(requestMac);
  auto request = Codec::decodeRequest(gcBudgetBytes(requestBytes), gcBudgetBytes(*requestMac));
  ASSERT_OK(request);
  storage::EcGcAckClaims ackClaims;
  ackClaims.keyId = requestClaims.keyId;
  ackClaims.authority = authority;
  auto requestHash = gcBudgetSha(gcBudgetBytes(requestBytes)), claimHash = Codec::claimDigest(*certificate);
  ASSERT_OK(requestHash);
  ASSERT_OK(claimHash);
  ackClaims.requestDigest = *requestHash;
  ackClaims.claimDigest = *claimHash;
  ackClaims.claimId = claimId;
  ackClaims.eligibilityDigest = certificate->eligibilityDigest;
  ackClaims.endpoint = certificate->endpoint;
  ackClaims.ledgerSha256.back() = 17;
  ackClaims.terminalRevision = 2;
  ackClaims.observedAtSeconds = requestClaims.issuedAtSeconds;
  ackClaims.bootNonce = Uuid::random();
  const auto ackBytes = Codec::encode(ackClaims);
  auto ackMac = gcBudgetMac(rawGc, gcBudgetBytes(ackBytes));
  ASSERT_OK(ackMac);
  auto ack = Codec::decodeAck(gcBudgetBytes(ackBytes), gcBudgetBytes(*ackMac));
  ASSERT_OK(ack);
  auto completion = f.runProfile([&](Tx &t) {
    return EcGcCompletionCatalog::record(t, intent.object, identity, claimId, *request, *ack, **gc, authority);
  });
  ASSERT_OK(completion);
  measured();
  auto completedAgain = f.runProfile([&](Tx &t) {
    return EcGcCompletionCatalog::record(t, intent.object, identity, claimId, *request, *ack, **gc, authority);
  });
  ASSERT_OK(completedAgain);
  measured();
  EXPECT_TRUE(same(*completion, *completedAgain));
  auto queried = f.runProfile(
      [&](Tx &t) { return EcGcCompletionCatalog::get(t, intent.object, identity, claimId, **gc, authority); });
  ASSERT_OK(queried);
  ASSERT_TRUE(*queried);
  measured();
  EXPECT_TRUE(same(**queried, *completion));
  // Completing the fresh output's GC never invents T2 for the old source pin.
  auto source = f.runProfile([&](Tx &t) {
    return require<EcTreeSourcePinRecord>(t, idKey(kv::KeyPrefix::EcTreeSourcePin, intent.object, intent.sourcePin));
  });
  ASSERT_OK(source);
  EXPECT_EQ(source->state, EcTreeSourcePinState::Active);
  for (const auto &old : source->allocations) {
    auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, old.fragment.identity);
    ASSERT_OK(key);
    auto protection = f.runProfile([&](Tx &t) { return require<EcTreeSourceAllocationRecord>(t, *key); });
    ASSERT_OK(protection);
    EXPECT_EQ(protection->active, 1);
  }
  RecordProperty("gc_repair22_max_key_value_conflict_bytes", std::to_string(maximumBytes));
  RecordProperty("gc_repair22_max_key_operations", std::to_string(maximumKeys));
  RecordProperty("gc_repair22_max_mutation_and_conflict_bytes", std::to_string(maximumMutationConflict));
  RecordProperty("scope",
                 "private FDB; max descriptors; 22 synthetic signed endpoint observations; no Storage deletion");
}

TEST_F(TestEcFileTree, RealFdbConcurrentReclaimAndLostCommitReplayNeverRepeatChildDecrements) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto root = f.root();
  ASSERT_OK(root);
  auto old = f.edit(*root);
  ASSERT_OK(f.apply(old));
  root = f.root();
  ASSERT_OK(root);
  auto next = f.edit(*root);
  ASSERT_OK(f.apply(next));
  auto ia = f.engine->createReadWriteTransaction(), ib = f.engine->createReadWriteTransaction();
  Tx a(*ia), b(*ib);
  auto ca = blockingWait(Tree::open(a, f.birth.object)), cb = blockingWait(Tree::open(b, f.birth.object));
  ASSERT_OK(ca);
  ASSERT_OK(cb);
  auto ra = blockingWait(Tree::reclaimNode(*ca, old.nodeIds[15]));
  ASSERT_OK(ra);
  auto rb = blockingWait(Tree::reclaimNode(*cb, old.nodeIds[15]));
  ASSERT_OK(rb);
  auto lost = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await a.commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "test discards acknowledgement after actual reclaim commit");
  };
  ASSERT_ERROR(blockingWait(lost()), TransactionCode::kMaybeCommitted);
  ASSERT_ERROR(blockingWait(b.commit()), TransactionCode::kConflict);
  auto repeated = f.reclaim(old.nodeIds[15]);
  ASSERT_OK(repeated);
  EXPECT_TRUE(same(*repeated, *ra));
  auto child = f.run([&](Tx &txn) {
    return require<EcTreeNodeRefs>(txn, idKey(kv::KeyPrefix::EcTreeNodeRefs, f.birth.object, old.nodeIds[14]));
  });
  ASSERT_OK(child);
  EXPECT_EQ(child->references, 0);
  EXPECT_EQ(child->state, EcTreeRefState::Reclaimable);
  for (int level = 14; level >= 0; --level) ASSERT_OK(f.reclaim(old.nodeIds[level]));
  // The original successful edit is historical evidence, not an instruction
  // to restore an obsolete root or resurrect its reclaimed nodes/holds.
  auto history = f.apply(old);
  ASSERT_OK(history);
  EXPECT_EQ(history->root.root, old.nodeIds[15]);
  auto current = f.root();
  ASSERT_OK(current);
  EXPECT_EQ(current->root, next.nodeIds[15]);
}

TEST_F(TestEcFileTree, CompactCommitmentAndImmutableNodePathsRejectCorruption) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  auto slot = f.run([&](Tx &txn) { return detail::EcFileTreeTestAccess::assemble(txn, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = slot->logicalLength;
  ASSERT_OK(f.run([&](Tx &txn) -> CoTryTask<Void> {
    const auto key = manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, 0, 1);
    auto summary = co_await require<EcTreeManifestHolds>(txn, key);
    CO_RETURN_ON_ERROR(summary);
    summary->bindingsDigest[0] ^= 1;
    co_return co_await store(txn, key, *summary);
  }));
  ASSERT_ERROR(f.apply(edit, true), StatusCode::kDataCorruption);
  auto zero = f.edit(*root);
  ASSERT_OK(f.apply(zero));
  ASSERT_OK(f.run([&](Tx &txn) -> CoTryTask<Void> {
    const auto key = idKey(kv::KeyPrefix::EcTreeNodeRefs, f.birth.object, zero.nodeIds[0]);
    auto refs = co_await require<EcTreeNodeRefs>(txn, key);
    CO_RETURN_ON_ERROR(refs);
    refs->prefix = 16;
    co_return co_await store(txn, key, *refs);
  }));
  auto queried = f.run([&](Tx &txn) -> CoTryTask<EcTreeSlot> {
    auto context = co_await Tree::open(txn, f.birth.object);
    CO_RETURN_ON_ERROR(context);
    co_return co_await Tree::lookup(*context, 0);
  });
  ASSERT_ERROR(queried, StatusCode::kDataCorruption);
}

TEST_F(TestEcFileTree, MissingNodeIsCorruptionRatherThanAZeroHole) {
  Fixture f;
  ASSERT_OK(f.initialize());
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  ASSERT_OK(f.apply(edit));
  // The lazy clear task borrows its key until f.run finishes awaiting it.
  const auto nodeKey = idKey(kv::KeyPrefix::EcTreeNode, f.birth.object, edit.nodeIds[0]);
  auto before = f.run([&](Tx &txn) { return txn.get(nodeKey); });
  ASSERT_OK(before);
  ASSERT_TRUE(before->has_value());
  ASSERT_OK(f.run([&](Tx &txn) { return txn.clear(nodeKey); }));
  auto after = f.run([&](Tx &txn) { return txn.get(nodeKey); });
  ASSERT_OK(after);
  ASSERT_FALSE(after->has_value());
  auto read = f.run([&](Tx &txn) -> CoTryTask<EcTreeSlot> {
    auto ctx = co_await Tree::open(txn, f.birth.object);
    CO_RETURN_ON_ERROR(ctx);
    co_return co_await Tree::lookup(*ctx, 0);
  });
  ASSERT_ERROR(read, StatusCode::kDataCorruption);
}
// Shared fixture declarations must precede the tests that consume them.
// clang-format off
#include "TestEcTreeSourcePin.inc"
#include "TestEcTreeCut.inc"
#include "TestEcTreeRead.inc"
#include "TestEcTargetRetirementEvidence.inc"
// clang-format on
}  // namespace
}  // namespace hf3fs::meta::server
