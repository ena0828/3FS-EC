#include <folly/experimental/coro/BlockingWait.h>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "fbs/meta/Schema.h"
#include "fbs/meta/Service.h"
#include "meta/store/EcNamespaceGuard.h"
#include "tests/GtestHelpers.h"
#include "tests/meta/MetaTestBase.h"

namespace hf3fs::meta::server {
namespace {

Layout namespaceEcLayout() {
  EcManifestLayoutV1 descriptor;
  descriptor.incarnation.data[0] = 1;
  return Layout{ChainTableId(0), ChainTableVersion(0), descriptor.shardBytes, 10, descriptor};
}

struct NamespaceCountFixture {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(files, uint64_t(0));
};

std::string namespaceCountKey(InodeId inode) {
  std::string key("ECNS");
  for (int shift = 56; shift >= 0; shift -= 8) key.push_back(static_cast<char>(inode.u64() >> shift));
  return key;
}

using NamespaceSnapshot = std::vector<std::pair<std::string, std::string>>;

CoTryTask<NamespaceSnapshot> snapshotNamespace(IReadOnlyTransaction &txn) {
  NamespaceSnapshot snapshot;
  for (auto [begin, end] : {std::pair{"DENT", "DENU"}, {"ECN", "ECO"}, {"INOD", "INOE"}, {"INOS", "INOT"}}) {
    auto range = co_await txn.snapshotGetRange({begin, true}, {end, false}, 65535);
    CO_RETURN_ON_ERROR(range);
    if (range->hasMore) {
      co_return makeError(StatusCode::kInvalidArg, "namespace fixture exceeds snapshot bound");
    }
    for (const auto &kv : range->kvs) {
      snapshot.emplace_back(kv.key, kv.value);
    }
  }
  co_return snapshot;
}

template <typename KV>
class TestEcNamespaceGuards : public MetaTestBase<KV> {
 protected:
  static const MockCluster::Config &config() {
    static const auto config = [] {
      MockCluster::Config config;
      config.mock_meta().gc().set_enable(false);
      return config;
    }();
    return config;
  }

  CoTryTask<Inode> createEc(MetaOperator &meta, PathAt path) {
    auto parent = path.parent;
    if (path.path && !path.path->parent_path().empty()) {
      auto stat = co_await meta.stat({SUPER_USER, PathAt(parent, path.path->parent_path()), AtFlags()});
      CO_RETURN_ON_ERROR(stat);
      parent = stat->stat.id;
    }
    auto created = co_await meta.create({SUPER_USER, std::move(path), {}, O_RDONLY, p644});
    CO_RETURN_ON_ERROR(created);
    Inode inode(created->stat);
    inode.asFile().layout = namespaceEcLayout();
    inode.asFile().length = 2u << 20;
    auto txn = this->kvEngine()->createReadWriteTransaction();
    CO_RETURN_ON_ERROR(co_await inode.store(*txn));
    CO_RETURN_ON_ERROR(co_await EcNamespaceGuard::registerFile(*txn, inode, parent));
    CO_RETURN_ON_ERROR(co_await txn->commit());
    co_return inode;
  }

  template <typename Op>
  CoTask<void> expectRejectedWithoutNamespaceWrites(Op op) {
    auto txn = this->kvEngine()->createReadWriteTransaction();
    auto before = co_await snapshotNamespace(*txn);
    CO_ASSERT_OK(before);
    CO_ASSERT_ERROR(co_await op->run(*txn), StatusCode::kNotImplemented);
    // Read-your-writes detects partial mutation even when the operation returns an error.
    auto after = co_await snapshotNamespace(*txn);
    CO_ASSERT_OK(after);
    CO_ASSERT_EQ(*after, *before);
    CO_ASSERT_OK(co_await txn->commit());
  }
};

using NamespaceKVTypes = ::testing::Types<mem::MemKV, fdb::DB>;
TYPED_TEST_SUITE(TestEcNamespaceGuards, NamespaceKVTypes);

TYPED_TEST(TestEcNamespaceGuards, RejectsFileRemovalRenameOverwriteAndHardLinkBeforeMutation) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    auto ec = co_await this->createEc(meta, "ec");
    CO_ASSERT_OK(ec);
    CO_ASSERT_OK(co_await meta.create({SUPER_USER, "replicated", {}, O_RDONLY, p644}));
    CO_ASSERT_OK(co_await meta.symlink({SUPER_USER, "ec-symlink", "ec"}));

    for (bool recursive : {false, true}) {
      auto req = RemoveReq(SUPER_USER, "ec", AtFlags(), recursive);
      co_await this->expectRejectedWithoutNamespaceWrites(store.remove(req));
    }
    for (auto [src, dst] : {std::pair{"ec", "new-name"}, {"ec", "replicated"}, {"replicated", "ec"}}) {
      auto req = RenameReq(SUPER_USER, src, dst);
      co_await this->expectRejectedWithoutNamespaceWrites(store.rename(req));
    }
    for (auto oldPath : {PathAt("ec"), PathAt(ec->id), PathAt("ec-symlink")}) {
      auto req = HardLinkReq(SUPER_USER, oldPath, "hardlink", AtFlags(AT_SYMLINK_FOLLOW));
      co_await this->expectRejectedWithoutNamespaceWrites(store.hardLink(req));
    }

    // Removing a symlink never follows its EC target.
    CO_ASSERT_OK(co_await meta.remove({SUPER_USER, "ec-symlink", AtFlags(), false}));
    auto stat = co_await meta.stat({SUPER_USER, "ec", AtFlags()});
    CO_ASSERT_OK(stat);
    CO_ASSERT_EQ(stat->stat, *ec);
  }());
}

TYPED_TEST(TestEcNamespaceGuards, RejectsRecursiveRemovalBeforeDetachingRoot) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    auto parent = co_await meta.mkdirs({SUPER_USER, "tree/sub/deep", p755, true});
    CO_ASSERT_OK(parent);
    CO_ASSERT_OK(co_await meta.create({SUPER_USER, PathAt(parent->stat.id, "replicated"), {}, O_RDONLY, p644}));
    CO_ASSERT_OK(co_await this->createEc(meta, PathAt(parent->stat.id, "z-ec")));
    auto root = co_await meta.stat({SUPER_USER, "tree", AtFlags()});
    CO_ASSERT_OK(root);
    for (auto path : {PathAt("tree"), PathAt(root->stat.id)}) {
      auto req = RemoveReq(SUPER_USER, path, AtFlags(), true);
      co_await this->expectRejectedWithoutNamespaceWrites(store.remove(req));
    }
    CO_ASSERT_ERROR(co_await meta.remove({SUPER_USER, "tree", AtFlags(), false}), MetaCode::kNotEmpty);
  }());
}

TYPED_TEST(TestEcNamespaceGuards, PreservesDirectoryMovesAndReplicatedNamespaceOperations) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    CO_ASSERT_OK(co_await meta.mkdirs({SUPER_USER, "tree/sub", p755, true}));
    CO_ASSERT_OK(co_await meta.mkdirs({SUPER_USER, "destination", p755, false}));
    CO_ASSERT_OK(co_await meta.mkdirs({SUPER_USER, "trash/user", p755, true}));
    auto ec = co_await this->createEc(meta, "tree/sub/ec");
    CO_ASSERT_OK(ec);

    // Replacing an empty directory preserves all source descendants.
    CO_ASSERT_OK(co_await meta.rename({SUPER_USER, "tree", "destination"}));
    CO_ASSERT_OK(co_await meta.rename({SUPER_USER, "destination", "trash/user/tree", true}));
    auto stat = co_await meta.stat({SUPER_USER, "trash/user/tree/sub/ec", AtFlags()});
    CO_ASSERT_OK(stat);
    CO_ASSERT_EQ(stat->stat, *ec);
    auto remove = RemoveReq(SUPER_USER, "trash/user/tree", AtFlags(), true);
    co_await this->expectRejectedWithoutNamespaceWrites(store.remove(remove));

    CO_ASSERT_OK(co_await meta.mkdirs({SUPER_USER, "replicated/sub", p755, true}));
    CO_ASSERT_OK(co_await meta.create({SUPER_USER, "replicated/sub/file", {}, O_RDONLY, p644}));
    CO_ASSERT_OK(co_await meta.hardLink({SUPER_USER, "replicated/sub/file", "replicated/sub/link", AtFlags()}));
    CO_ASSERT_OK(co_await meta.rename({SUPER_USER, "replicated/sub/link", "replicated/sub/renamed"}));
    CO_ASSERT_OK(co_await meta.remove({SUPER_USER, "replicated/sub/renamed", AtFlags(), false}));
    CO_ASSERT_OK(co_await meta.remove({SUPER_USER, "replicated", AtFlags(), true}));
  }());
}

TYPED_TEST(TestEcNamespaceGuards, RegistrationConflictsWithRecursiveRemovalInBothCommitOrders) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    for (bool createFirst : {false, true}) {
      auto tree = createFirst ? "create-first" : "remove-first";
      auto directory = co_await meta.mkdirs({SUPER_USER, PathAt(std::string(tree) + "/sub"), p755, true});
      CO_ASSERT_OK(directory);
      auto removal = this->kvEngine()->createReadWriteTransaction();
      auto req = RemoveReq(SUPER_USER, tree, AtFlags(), true);
      CO_ASSERT_OK(co_await store.remove(req)->run(*removal));
      auto change = this->kvEngine()->createReadWriteTransaction();
      auto inode = Inode::newFile(MetaTestHelper::randomInodeId(), Acl::root(), namespaceEcLayout(), UtcClock::now());
      CO_ASSERT_OK(co_await inode.store(*change));
      CO_ASSERT_OK(co_await DirEntry::newFile(directory->stat.id, "ec", inode.id).store(*change));
      CO_ASSERT_OK(co_await EcNamespaceGuard::registerFile(*change, inode, directory->stat.id));
      if (createFirst) {
        CO_ASSERT_OK(co_await change->commit());
        CO_ASSERT_ERROR(co_await removal->commit(), TransactionCode::kConflict);
        co_await this->expectRejectedWithoutNamespaceWrites(store.remove(req));
      } else {
        CO_ASSERT_OK(co_await removal->commit());
        CO_ASSERT_ERROR(co_await change->commit(), TransactionCode::kConflict);
        auto retry = this->kvEngine()->createReadWriteTransaction();
        CO_ASSERT_ERROR(co_await EcNamespaceGuard::registerFile(*retry, inode, directory->stat.id),
                        MetaCode::kNotFound);
      }
    }
  }());
}

TYPED_TEST(TestEcNamespaceGuards, RemovesLargeReplicatedTreeWithoutInspectionLimit) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto parent = co_await meta.mkdirs({SUPER_USER, "large-tree", p755, false});
    CO_ASSERT_OK(parent);
    auto file = co_await meta.create({SUPER_USER, PathAt(parent->stat.id, "a0000"), {}, O_RDONLY, p644});
    CO_ASSERT_OK(file);
    // Populate valid hard links directly to keep this boundary fixture inexpensive.
    READ_WRITE_TRANSACTION_OK({
      Inode inode(file->stat);
      inode.nlink = 4097;
      CO_ASSERT_OK(co_await inode.store(*txn));
      for (unsigned i = 1; i != 4097; ++i) {
        CO_ASSERT_OK(co_await DirEntry::newFile(parent->stat.id, fmt::format("a{:04}", i), inode.id).store(*txn));
      }
    });
    auto req = RemoveReq(SUPER_USER, "large-tree", AtFlags(), true);
    CO_ASSERT_OK(co_await meta.remove(req));
  }());
}

TYPED_TEST(TestEcNamespaceGuards, DirectoryMoveMigratesCountsAndConflictsWithFirstRegistration) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    for (bool createFirst : {false, true}) {
      auto prefix = createFirst ? std::string("create-first") : std::string("move-first");
      auto source = co_await meta.mkdirs({SUPER_USER, PathAt(prefix + "/old/tree/sub"), p755, true});
      auto destination = co_await meta.mkdirs({SUPER_USER, PathAt(prefix + "/new"), p755, true});
      auto oldParent = co_await meta.stat({SUPER_USER, PathAt(prefix + "/old"), AtFlags()});
      CO_ASSERT_OK(source);
      CO_ASSERT_OK(destination);
      CO_ASSERT_OK(oldParent);
      auto move = this->kvEngine()->createReadWriteTransaction();
      auto req = RenameReq(SUPER_USER, PathAt(prefix + "/old/tree"), PathAt(destination->stat.id, "tree"));
      CO_ASSERT_OK(co_await store.rename(req)->run(*move));
      auto creation = this->kvEngine()->createReadWriteTransaction();
      auto inode = Inode::newFile(MetaTestHelper::randomInodeId(), Acl::root(), namespaceEcLayout(), UtcClock::now());
      CO_ASSERT_OK(co_await inode.store(*creation));
      CO_ASSERT_OK(co_await DirEntry::newFile(source->stat.id, "ec", inode.id).store(*creation));
      CO_ASSERT_OK(co_await EcNamespaceGuard::registerFile(*creation, inode, source->stat.id));
      if (createFirst) {
        CO_ASSERT_OK(co_await creation->commit());
        CO_ASSERT_ERROR(co_await move->commit(), TransactionCode::kConflict);
        CO_ASSERT_OK(co_await meta.rename(req));
      } else {
        CO_ASSERT_OK(co_await move->commit());
        CO_ASSERT_ERROR(co_await creation->commit(), TransactionCode::kConflict);
        READ_WRITE_TRANSACTION_OK({
          CO_ASSERT_OK(co_await inode.store(*txn));
          CO_ASSERT_OK(co_await DirEntry::newFile(source->stat.id, "ec", inode.id).store(*txn));
          CO_ASSERT_OK(co_await EcNamespaceGuard::registerFile(*txn, inode, source->stat.id));
        });
      }
      READ_WRITE_TRANSACTION_NO_COMMIT({
        auto oldCount = co_await EcNamespaceGuard::subtreeCount(*txn, oldParent->stat.id);
        auto newCount = co_await EcNamespaceGuard::subtreeCount(*txn, destination->stat.id);
        auto childCount = co_await EcNamespaceGuard::subtreeCount(*txn, source->stat.id);
        CO_ASSERT_OK(oldCount);
        CO_ASSERT_OK(newCount);
        CO_ASSERT_OK(childCount);
        CO_ASSERT_EQ(*oldCount, 0);
        CO_ASSERT_EQ(*newCount, 1);
        CO_ASSERT_EQ(*childCount, 1);
        // Direct parent IDs do not change when an ancestor moves: registration remains idempotent.
        CO_ASSERT_OK(co_await EcNamespaceGuard::registerFile(*txn, inode, source->stat.id));
        auto again = co_await EcNamespaceGuard::subtreeCount(*txn, destination->stat.id);
        CO_ASSERT_OK(again);
        CO_ASSERT_EQ(*again, 1);
      });
      CO_ASSERT_OK(co_await meta.remove({SUPER_USER, PathAt(prefix + "/old"), AtFlags(), true}));
      auto remove = RemoveReq(SUPER_USER, PathAt(destination->stat.id), AtFlags(), true);
      co_await this->expectRejectedWithoutNamespaceWrites(store.remove(remove));
    }
  }());
}

TYPED_TEST(TestEcNamespaceGuards, DirectoryMoveConflictsWithDestinationRemovalInBothCommitOrders) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    for (bool moveFirst : {false, true}) {
      auto prefix = moveFirst ? std::string("move-first") : std::string("remove-first");
      CO_ASSERT_OK(co_await meta.mkdirs({SUPER_USER, PathAt(prefix + "/source"), p755, true}));
      auto destination = co_await meta.mkdirs({SUPER_USER, PathAt(prefix + "/destination/sub"), p755, true});
      CO_ASSERT_OK(destination);
      CO_ASSERT_OK(co_await this->createEc(meta, PathAt(prefix + "/source/ec")));
      auto removal = this->kvEngine()->createReadWriteTransaction();
      auto removeReq = RemoveReq(SUPER_USER, PathAt(prefix + "/destination"), AtFlags(), true);
      CO_ASSERT_OK(co_await store.remove(removeReq)->run(*removal));
      auto move = this->kvEngine()->createReadWriteTransaction();
      auto moveReq = RenameReq(SUPER_USER, PathAt(prefix + "/source"), PathAt(destination->stat.id, "moved"));
      CO_ASSERT_OK(co_await store.rename(moveReq)->run(*move));
      if (moveFirst) {
        CO_ASSERT_OK(co_await move->commit());
        CO_ASSERT_ERROR(co_await removal->commit(), TransactionCode::kConflict);
        co_await this->expectRejectedWithoutNamespaceWrites(store.remove(removeReq));
      } else {
        CO_ASSERT_OK(co_await removal->commit());
        CO_ASSERT_ERROR(co_await move->commit(), TransactionCode::kConflict);
        CO_ASSERT_ERROR(co_await meta.rename(moveReq), MetaCode::kNotFound);
      }
    }
  }());
}

TYPED_TEST(TestEcNamespaceGuards, RejectsIndexOverflowUnderflowAndMalformedRecordsWithoutMutation) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto &store = cluster.meta().getStore();
    auto source = co_await meta.mkdirs({SUPER_USER, "old/tree", p755, true});
    auto oldParent = co_await meta.stat({SUPER_USER, "old", AtFlags()});
    auto destination = co_await meta.mkdirs({SUPER_USER, "new", p755, true});
    CO_ASSERT_OK(source);
    CO_ASSERT_OK(oldParent);
    CO_ASSERT_OK(destination);
    auto ec = co_await this->createEc(meta, "old/tree/ec");
    CO_ASSERT_OK(ec);
    for (unsigned scenario = 0; scenario != 4; ++scenario) {
      auto txn = this->kvEngine()->createReadWriteTransaction();
      if (scenario == 0) {
        CO_ASSERT_OK(co_await txn->clear(namespaceCountKey(oldParent->stat.id)));
      } else if (scenario == 1) {
        CO_ASSERT_OK(
            co_await txn->set(namespaceCountKey(destination->stat.id),
                              serde::serialize(NamespaceCountFixture{1, std::numeric_limits<uint64_t>::max()})));
      } else if (scenario == 2) {
        CO_ASSERT_OK(co_await txn->set(namespaceCountKey(source->stat.id), "invalid"));
      } else {
        CO_ASSERT_OK(
            co_await txn->set(namespaceCountKey(source->stat.id), serde::serialize(NamespaceCountFixture{2, 1})));
      }
      auto before = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(before);
      auto req = RenameReq(SUPER_USER, "old/tree", "new/tree");
      CO_ASSERT_ERROR(co_await store.rename(req)->run(*txn), StatusCode::kDataCorruption);
      auto after = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(after);
      CO_ASSERT_EQ(*before, *after);
    }
    READ_WRITE_TRANSACTION_NO_COMMIT({
      auto extra = Inode::newFile(MetaTestHelper::randomInodeId(), Acl::root(), namespaceEcLayout(), UtcClock::now());
      CO_ASSERT_OK(co_await txn->set(namespaceCountKey(InodeId::root()),
                                     serde::serialize(NamespaceCountFixture{1, std::numeric_limits<uint64_t>::max()})));
      auto before = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(before);
      CO_ASSERT_ERROR(co_await EcNamespaceGuard::registerFile(*txn, extra, source->stat.id),
                      StatusCode::kDataCorruption);
      auto after = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(after);
      CO_ASSERT_EQ(*before, *after);
    });
  }());
}

TYPED_TEST(TestEcNamespaceGuards, RegistrationRejectsInvalidAncestorsWithoutIndexWrites) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster(this->config());
    auto &meta = cluster.meta().getOperator();
    auto created = co_await meta.mkdirs({SUPER_USER, "parent", p755, false});
    CO_ASSERT_OK(created);
    const auto ec = Inode::newFile(MetaTestHelper::randomInodeId(), Acl::root(), namespaceEcLayout(), UtcClock::now());
    for (unsigned scenario = 0; scenario != 5; ++scenario) {
      auto txn = this->kvEngine()->createReadWriteTransaction();
      Inode parent(created->stat);
      auto code = MetaCode::kNotFound;
      if (scenario == 0) {
        parent.nlink = 0;
        CO_ASSERT_OK(co_await parent.store(*txn));
      } else if (scenario == 1) {
        parent.asDirectory().parent = parent.id;
        CO_ASSERT_OK(co_await parent.store(*txn));
        code = StatusCode::kDataCorruption;
      } else if (scenario == 2) {
        parent.asDirectory().parent = InodeId::gcRoot();
        CO_ASSERT_OK(co_await parent.store(*txn));
      } else if (scenario == 3) {
        auto file = Inode::newFile(parent.id, Acl::root(), namespaceEcLayout(), UtcClock::now());
        CO_ASSERT_OK(co_await file.store(*txn));
        code = MetaCode::kNotDirectory;
      } else {
        CO_ASSERT_OK(co_await parent.remove(*txn));
      }
      auto before = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(before);
      CO_ASSERT_ERROR(co_await EcNamespaceGuard::registerFile(*txn, ec, parent.id), code);
      auto after = co_await snapshotNamespace(*txn);
      CO_ASSERT_OK(after);
      CO_ASSERT_EQ(*before, *after);
    }
  }());
}

}  // namespace
}  // namespace hf3fs::meta::server
