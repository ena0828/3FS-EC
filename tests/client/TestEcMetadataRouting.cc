#include <gtest/gtest.h>

#include "client/meta/MetadataRoutingInfoChecker.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta::client {
namespace {
// RPC 47..67 (50 is the pre-existing test RPC): none of these file replies
// embeds an Inode. Their native grant/manifest validators remain independent.
static_assert(!RoutingInfoChecker::hasInode<EcFilePwriteRsp>());
static_assert(!RoutingInfoChecker::hasInode<CloseEcFileSessionRsp>());
static_assert(!RoutingInfoChecker::hasInode<BindEcRmwOutputRsp>());
static_assert(!RoutingInfoChecker::hasInode<EcTreeReadRsp>());
static_assert(!RoutingInfoChecker::hasInode<EcFileTruncateRsp>());
static_assert(!RoutingInfoChecker::hasInode<AdvanceEcTreeReclaimRsp>());
static_assert(!RoutingInfoChecker::hasInode<EcFileAppendRsp>());
static_assert(!RoutingInfoChecker::hasInode<SyncEcFileSessionRsp>());
static_assert(!RoutingInfoChecker::hasInode<EcFileRepairRsp>());

TEST(TestEcMetadataRouting, MetadataAllowsValidEcButPreservesBindingsAndReplicatedRouting) {
  EcManifestLayoutV1 descriptor;
  descriptor.incarnation = Uuid::random();
  descriptor.shardBytes = 4096;
  Layout layout;
  layout.chains = descriptor;
  const Inode ec{InodeId(777), {File{layout}, Acl::root()}};
  flat::RoutingInfo routing;
  const auto ready = [&](const auto &rsp) {
    auto checked = MetadataRoutingInfoChecker::check(rsp, routing);
    ASSERT_OK(checked);
    EXPECT_TRUE(*checked);
  };
  const auto waiting = [&](const auto &rsp) {
    auto checked = MetadataRoutingInfoChecker::check(rsp, routing);
    ASSERT_OK(checked);
    EXPECT_FALSE(*checked);
  };

  OpenEcFileSessionRsp opened;
  opened.inode = ec;
  opened.object.object = {ec.id, descriptor.incarnation};
  opened.object.shardBytes = descriptor.shardBytes;
  opened.root.object = opened.session.intent.object = opened.object.object;
  opened.root.birth = opened.session.intent.birth = Uuid::random();
  ready(opened);
  ready(StatRsp(ec));
  ready(RenameRsp(ec));
  ready(HardLinkRsp(ec));
  ready(SetAttrRsp(ec));
  ready(BatchStatRsp({ec, std::nullopt}));
  BatchStatByPathRsp paths;
  paths.inodes.emplace_back(ec);
  paths.inodes.emplace_back(makeError(MetaCode::kNotFound));
  ready(paths);
  ready(ListRsp({}, {ec}, false));

  // Describing EC metadata never enables legacy replicated data operations.
  EXPECT_FALSE(RoutingInfoChecker::checkRoutingInfo(ec, routing));
  ASSERT_ERROR(layout.valid(false), StatusCode::kNotImplemented);
  waiting(OpenRsp(ec, false));
  waiting(SyncRsp(ec));
  waiting(CloseRsp(ec));

  // One missing replicated table still blocks the entire mixed response.
  const Inode replica{
      InodeId(778),
      {File{Layout::newChainRange(flat::ChainTableId(5), flat::ChainTableVersion(2), 4096, 16, 1)}, Acl::root()}};
  waiting(StatRsp(replica));
  waiting(BatchStatRsp({ec, replica}));
  paths.inodes.emplace_back(replica);
  waiting(paths);
  waiting(ListRsp({}, {ec, replica}, false));

  // Invalid EC fields are corruption, not a reason to await a chain table.
  for (unsigned field = 0; field != 12; ++field) {
    auto bad = ec;
    auto &badLayout = bad.asFile().layout;
    auto &d = std::get<EcManifestLayoutV1>(badLayout.chains);
    switch (field) {
      case 0:
        d.version = 2;
        break;
      case 1:
        d.incarnation = Uuid::zero();
        break;
      case 2:
        d.shardBytes = 0;
        break;
      case 3:
        d.shardBytes = (1u << 20) + 1;
        break;
      case 4:
        d.dataShards = 9;
        break;
      case 5:
        d.parityShards = 3;
        break;
      case 6:
        d.codecId = 2;
        break;
      case 7:
        d.matrixVersion = 2;
        break;
      case 8:
        badLayout.tableId = flat::ChainTableId(1);
        break;
      case 9:
        badLayout.tableVersion = flat::ChainTableVersion(1);
        break;
      case 10:
        badLayout.chunkSize = Layout::ChunkSize(4096);
        break;
      case 11:
        badLayout.stripeSize = 1;
        break;
    }
    ASSERT_ERROR(MetadataRoutingInfoChecker::check(StatRsp(bad), routing), StatusCode::kDataCorruption);
    ASSERT_ERROR(MetadataRoutingInfoChecker::check(BatchStatRsp({replica, bad}), routing), StatusCode::kDataCorruption);
  }
  for (unsigned field = 0; field != 5; ++field) {
    auto bad = opened;
    switch (field) {
      case 0:
        bad.object.object.incarnation = Uuid::random();
        break;
      case 1:
        bad.root.object.inode = InodeId(778);
        break;
      case 2:
        bad.session.intent.object.incarnation = Uuid::random();
        break;
      case 3:
        ++bad.object.shardBytes;
        break;
      case 4:
        bad.session.intent.birth = Uuid::random();
        break;
    }
    ASSERT_ERROR(MetadataRoutingInfoChecker::check(bad, routing), StatusCode::kDataCorruption);
  }
}
}  // namespace
}  // namespace hf3fs::meta::client
