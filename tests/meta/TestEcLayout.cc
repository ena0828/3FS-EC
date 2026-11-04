#include <array>
#include <folly/experimental/coro/BlockingWait.h>
#include <variant>

#include "fbs/meta/Schema.h"
#include "fbs/meta/Service.h"
#include "fbs/meta/Utils.h"
#include "tests/GtestHelpers.h"
#include "tests/meta/MetaTestBase.h"

namespace hf3fs::meta::server {
namespace {

// Preserve the pre-EC field list and variant independently of Layout.
struct LegacyLayout {
  SERDE_STRUCT_FIELD(tableId, ChainTableId());
  SERDE_STRUCT_FIELD(tableVersion, ChainTableVersion());
  SERDE_STRUCT_FIELD(chunkSize, Layout::ChunkSize(0));
  SERDE_STRUCT_FIELD(stripeSize, uint32_t(0));
  SERDE_STRUCT_FIELD(chains, (std::variant<Layout::Empty, Layout::ChainRange, Layout::ChainList>{}));
};

Layout ecLayout() {
  EcManifestLayoutV1 descriptor;
  descriptor.incarnation.data[0] = 1;
  // Nonzero sizes are legitimate geometry, not an invalid-layout sentinel.
  return Layout{ChainTableId(0), ChainTableVersion(0), descriptor.shardBytes, 10, descriptor};
}

TEST(TestEcLayout, LegacyWireCompatibility) {
  const auto list = Layout::newChainList(4096, std::vector<flat::ChainId>{flat::ChainId(7), flat::ChainId(9)});
  // Frozen little-endian pre-EC encoding: layout byte length; four u32
  // fields; "ChainList" variant name; nested table length; two u32 indexes.
  const std::array<uint8_t, 37> golden{0x24, 0,   0,   0,   0,   0,   0,   0,   0, 0, 0x10, 0, 0, 2, 0, 0, 0, 9, 'C',
                                       'h',  'a', 'i', 'n', 'L', 'i', 's', 't', 9, 2, 7,    0, 0, 0, 9, 0, 0, 0};
  ASSERT_EQ(serde::serialize(list), std::string(reinterpret_cast<const char *>(golden.data()), golden.size()));
  auto range =
      Layout{ChainTableId(1), ChainTableVersion(2), 4096, 2, Layout::ChainRange{7, Layout::ChainRange::NO_SHUFFLE, 0}};
  for (const auto &layout : {list, range}) {
    const auto bytes = serde::serialize(layout);
    LegacyLayout old;
    ASSERT_OK(serde::deserialize(old, bytes));
    ASSERT_EQ(serde::serialize(old), bytes);
    Layout current;
    ASSERT_OK(serde::deserialize(current, serde::serialize(old)));
    ASSERT_EQ(current, layout);
    ASSERT_FALSE(current.isErasureCoded());
    ASSERT_OK(current.checkReplicated());
  }

  // Legacy Empty is a copyable empty class: its one object-representation byte
  // has no semantic value and variant assignment need not preserve it. Retain
  // the historical wire width and accept every historical value of that byte.
  static_assert(sizeof(Layout::Empty) == 1);
  const auto empty = Layout::newEmpty(ChainTableId(1), 4096, 2);
  const std::array<uint8_t, 23> emptyPrefix{0x17, 1, 0, 0, 0, 0, 0,   0,   0,   0,   0x10, 0,
                                            0,    2, 0, 0, 0, 5, 'E', 'm', 'p', 't', 'y'};
  const std::string prefix(reinterpret_cast<const char *>(emptyPrefix.data()), emptyPrefix.size());
  for (unsigned padding = 0; padding != 256; ++padding) {
    auto bytes = prefix + static_cast<char>(padding);
    LegacyLayout old;
    Layout current;
    ASSERT_OK(serde::deserialize(old, bytes));
    ASSERT_OK(serde::deserialize(current, bytes));
    ASSERT_EQ(current, empty);
    ASSERT_TRUE(std::holds_alternative<Layout::Empty>(old.chains));
    for (const auto &encoded : {serde::serialize(old), serde::serialize(current)}) {
      ASSERT_EQ(encoded.size(), prefix.size() + 1);
      ASSERT_EQ(encoded.substr(0, prefix.size()), prefix);
    }
    Layout oldRoundTrip;
    ASSERT_OK(serde::deserialize(oldRoundTrip, serde::serialize(old)));
    ASSERT_EQ(oldRoundTrip, empty);
  }
}

TEST(TestEcLayout, EcWireIsExplicitAndRejectedByLegacyReader) {
  auto layout = ecLayout();
  ASSERT_TRUE(layout.isErasureCoded());
  ASSERT_EQ(layout.type(), Layout::Type::ErasureCoded);
  ASSERT_NE(layout.ecLayout(), nullptr);
  ASSERT_OK(layout.ecLayout()->valid());
  auto bytes = serde::serialize(layout);
  ASSERT_NE(bytes.find("EcManifestLayoutV1"), std::string::npos);
  LegacyLayout old;
  ASSERT_ERROR(serde::deserialize(old, bytes), StatusCode::kSerdeVariantIndexExceeded);
  Layout current;
  ASSERT_OK(serde::deserialize(current, bytes));
  ASSERT_EQ(current, layout);
  ASSERT_ERROR(current.valid(false), StatusCode::kNotImplemented);
  ASSERT_ERROR(current.valid(true), StatusCode::kNotImplemented);

  File file(current);
  ASSERT_ERROR(file.getChunkId(InodeId(123), 0), StatusCode::kNotImplemented);
  auto inode = Inode::newFile(InodeId(123), Acl::root(), current, UtcClock::now());
  flat::RoutingInfo routing;
  ASSERT_ERROR(file.getChainId(inode, 0, routing), StatusCode::kNotImplemented);
  ASSERT_FALSE(RoutingInfoChecker::checkRoutingInfo(static_cast<const meta::Inode &>(inode), routing));
}

TEST(TestEcLayout, DescriptorValidationAndLegacyCreationRemainDisabled) {
  auto layout = ecLayout();
  auto descriptor = *layout.ecLayout();
  for (unsigned field = 0; field != 8; ++field) {
    auto bad = descriptor;
    switch (field) {
      case 0:
        bad.version = 2;
        break;
      case 1:
        bad.incarnation = Uuid::zero();
        break;
      case 2:
        bad.shardBytes = 0;
        break;
      case 3:
        bad.shardBytes = (1u << 20) + 1;
        break;
      case 4:
        bad.dataShards = 9;
        break;
      case 5:
        bad.parityShards = 3;
        break;
      case 6:
        bad.codecId = 2;
        break;
      case 7:
        bad.matrixVersion = 2;
        break;
    }
    ASSERT_ERROR(bad.valid(), StatusCode::kInvalidArg);
  }
  descriptor.shardBytes = 1;
  ASSERT_OK(descriptor.valid());
  ASSERT_ERROR(CreateReq(SUPER_USER, "ec", {}, O_RDONLY, p644, layout).valid(), StatusCode::kNotImplemented);
  ASSERT_ERROR(MkdirsReq(SUPER_USER, "ec-dir", p755, false, layout).valid(), StatusCode::kNotImplemented);
  ASSERT_ERROR(SetAttrReq::setLayout(SUPER_USER, PathAt("ec"), AtFlags(), layout).valid(), StatusCode::kNotImplemented);
}

class TestEcLayoutGuards : public MetaTestBase<mem::MemKV> {};

TEST_F(TestEcLayoutGuards, BatchedCreateRejectsEcBeforeMatchingUuidFastPath) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    auto cluster = this->createMockCluster();
    auto &meta = cluster.meta().getOperator();
    CreateReq original(SUPER_USER, PathAt(InodeId::root(), "ec-batch-guard"), {}, O_RDONLY, p644);
    auto created = co_await meta.create(original);
    CO_ASSERT_OK(created);
    Inode inode(created->stat);
    inode.asFile().layout = ecLayout();
    inode.asFile().length = 2u << 20;
    inode.asFile().dynStripe = 1;
    const auto preserved = inode;
    auto entry = DirEntry::newFile(InodeId::root(), "ec-batch-guard", inode.id);
    entry.uuid = original.uuid;
    const auto preservedEntry = serde::serialize(static_cast<const meta::DirEntry &>(entry));
    const auto existingSession = MetaTestHelper::randomSession();
    READ_WRITE_TRANSACTION_OK({
      CO_ASSERT_OK(co_await inode.store(*txn));
      CO_ASSERT_OK(co_await entry.store(*txn));
      CO_ASSERT_OK(co_await FileSession::create(inode.id, existingSession).store(*txn));
    });

    CreateReq retry(SUPER_USER, original.path, MetaTestHelper::randomSession(), O_RDWR | O_TRUNC, p644);
    retry.uuid = original.uuid;
    CO_ASSERT_FALSE(retry.uuid.is_nil());
    CO_ASSERT_EQ(retry.uuid, entry.uuid);
    // MetaOperator::create dispatches this short name directly to runInBatch;
    // there is no preceding tryOpen call and no race is needed to hit the UUID
    // fast path. A different UUID also checks the ordinary batch-open branch.
    CO_ASSERT_FALSE(retry.path.path->has_parent_path());
    for (bool matchingUuid : {true, false}) {
      if (!matchingUuid) retry.uuid = Uuid::random();
      CO_ASSERT_ERROR(co_await meta.create(retry), StatusCode::kNotImplemented);
      READ_ONLY_TRANSACTION({
        auto current = co_await Inode::snapshotLoad(*txn, inode.id);
        CO_ASSERT_OK(current);
        CO_ASSERT_TRUE(current->has_value());
        CO_ASSERT_EQ(**current, preserved);
        auto currentEntry = co_await DirEntry::snapshotLoad(*txn, entry.parent, entry.name);
        CO_ASSERT_OK(currentEntry);
        CO_ASSERT_TRUE(currentEntry->has_value());
        CO_ASSERT_EQ(serde::serialize(static_cast<const meta::DirEntry &>(**currentEntry)), preservedEntry);
        auto sessions = co_await FileSession::list(*txn, inode.id, false);
        CO_ASSERT_OK(sessions);
        CO_ASSERT_EQ(sessions->size(), 1);
        CO_ASSERT_EQ(sessions->front().sessionId, existingSession.session);
      });
    }
  }());
}

TEST_F(TestEcLayoutGuards, RejectsLegacyMutationsBeforeChangingInodeOrSession) {
  folly::coro::blockingWait([&]() -> CoTask<void> {
    MockCluster::Config config;
    config.mock_meta().set_otrunc_replace_file(true);
    config.mock_meta().set_otrunc_replace_file_threshold(0);
    auto cluster = this->createMockCluster(config);
    auto &meta = cluster.meta().getOperator();
    auto created = co_await meta.create({SUPER_USER, "ec-guard", {}, O_RDONLY, p644});
    CO_ASSERT_OK(created);
    Inode inode(created->stat);
    inode.asFile().layout = ecLayout();
    inode.asFile().length = 2u << 20;
    inode.asFile().dynStripe = 1;
    const auto preserved = inode;
    const auto session = MetaTestHelper::randomSession();
    READ_WRITE_TRANSACTION_OK({ CO_ASSERT_OK(co_await inode.store(*txn)); });

    CO_ASSERT_ERROR(co_await meta.open({SUPER_USER, "ec-guard", MetaTestHelper::randomSession(), O_RDWR | O_TRUNC}),
                    StatusCode::kNotImplemented);
    CO_ASSERT_ERROR(co_await meta.open({SUPER_USER, inode.id, {}, O_RDONLY}), StatusCode::kNotImplemented);
    auto extend = SetAttrReq::extendStripe(SUPER_USER, inode.id, 4);
    extend.path = PathAt("ec-guard");
    CO_ASSERT_ERROR(co_await meta.setAttr(extend), StatusCode::kNotImplemented);
    READ_WRITE_TRANSACTION_OK({
      auto sessions = co_await FileSession::list(*txn, inode.id, false);
      CO_ASSERT_OK(sessions);
      CO_ASSERT_TRUE(sessions->empty());
      CO_ASSERT_OK(co_await FileSession::create(inode.id, session).store(*txn));
    });
    CO_ASSERT_ERROR(co_await meta.sync({SUPER_USER, inode.id, true, {}, {}, true}), StatusCode::kNotImplemented);
    CO_ASSERT_ERROR(co_await meta.close({SUPER_USER, inode.id, session, true, {}, {}}), StatusCode::kNotImplemented);
    CO_ASSERT_ERROR(co_await cluster.meta().getFileHelper().queryLength(SUPER_USER, inode),
                    StatusCode::kNotImplemented);
    CO_ASSERT_ERROR(co_await cluster.meta().getFileHelper().remove(SUPER_USER, inode, {}, 32),
                    StatusCode::kNotImplemented);

    auto stat = co_await meta.stat({SUPER_USER, "ec-guard", AtFlags()});
    CO_ASSERT_OK(stat);
    CO_ASSERT_EQ(stat->stat, preserved);
    READ_ONLY_TRANSACTION({
      auto sessions = co_await FileSession::list(*txn, inode.id, false);
      CO_ASSERT_OK(sessions);
      CO_ASSERT_EQ(sessions->size(), 1);
      CO_ASSERT_EQ(sessions->front().sessionId, session.session);
    });
  }());
}

}  // namespace
}  // namespace hf3fs::meta::server
