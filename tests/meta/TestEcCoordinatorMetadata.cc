#include <folly/experimental/coro/BlockingWait.h>

#include "common/kv/KeyPrefix.h"
#include "common/kv/mem/MemKVEngine.h"
#include "core/user/UserStore.h"
#include "fbs/meta/EcRequestDigest.h"
#include "meta/service/MetaOperator.h"
#include "meta/store/EcNamespaceGuard.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;

// Actual experimental v1 shape: no creator, request UUID, or owner defaults.
struct LegacyEcObjectRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(allowColocated, false);
  SERDE_STRUCT_FIELD(epoch, uint64_t{1});
  SERDE_STRUCT_FIELD(nextGeneration, uint64_t{1});
  SERDE_STRUCT_FIELD(nextRevision, uint64_t{1});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(deleting, false);
};

// Metadata/authentication tests deliberately use the InMem storage client.
// They do not assert real byte verification; the native service fixture does.
class TestEcCoordinatorMetadata : public ::testing::Test {
 protected:
  void SetUp() override {
    config.set_enable_ec_catalog(true);
    config.set_authenticate(true);
    config.set_ec_allow_colocated_test_targets(true);
    config.set_ec_allow_unauthorized_storage_for_tests(true);
    config.set_ec_targets_length(12);
    config.event_trace_log().set_enabled(false);
    config.gc().set_enable(false);
    config.session_manager().set_enable(false);
    engine = std::make_shared<kv::MemKVEngine>();
    mgmtd = tests::FakeMgmtdClient::create({{flat::ChainTableId(1), 12, 1}}, 1, 1);
    auto routing = mgmtd->cloneRoutingInfo();
    for (uint32_t i = 0; i != 12; ++i) {
      auto *chain = routing->raw()->getChain(flat::ChainId(100001 + i));
      ASSERT_NE(chain, nullptr);
      const auto targetId = flat::TargetId(20001 + i);
      chain->targets.front().targetId = targetId;
      flat::TargetInfo target;
      target.targetId = targetId;
      target.chainId = chain->chainId;
      target.nodeId = flat::NodeId(10000);
      target.publicState = flat::PublicTargetState::SERVING;
      routing->raw()->targets[targetId] = target;
      config.ec_targets(i).set_chain(chain->chainId.toUnderType());
      config.ec_targets(i).set_target(targetId.toUnderType());
      config.ec_targets(i).set_node(10000);
    }
    mgmtd->setRoutingInfo(routing);
    storageConfig.set_implementation_type(storage::client::StorageClient::ImplementationType::InMem);
    storageClient = storage::client::StorageClient::create(ClientId::random(), storageConfig, *mgmtd);
    meta = std::make_unique<MetaOperator>(config, flat::NodeId(50), engine, mgmtd, storageClient, nullptr);
    ASSERT_OK(blockingWait(meta->init(Layout::newEmpty(flat::ChainTableId(1), 4096, 12))));
    auto txn = engine->createReadWriteTransaction();
    core::UserStore users;
    auto admin = blockingWait(users.addUser(*txn, flat::Uid(0), "root", {}, true));
    auto alice = blockingWait(users.addUser(*txn, flat::Uid(7), "alice", {}, false));
    ASSERT_OK(admin);
    ASSERT_OK(alice);
    root = UserInfo{admin->uid, admin->gid, admin->token};
    user = UserInfo{alice->uid, alice->gid, alice->token};
    ASSERT_OK(blockingWait(txn->commit()));
  }
  void TearDown() override {
    if (meta) {
      meta->beforeStop();
      meta->afterStop();
    }
  }
  template <typename Req>
  Req request(bool administrator = false) {
    Req req;
    req.user = administrator ? root : user;
    req.client = client;
    req.uuid = Uuid::random();
    return req;
  }
  CreateEcFileReq createRequest(std::string name = "ec-file") {
    auto req = request<CreateEcFileReq>(true);
    req.path = PathAt(InodeId::root(), std::move(name));
    req.perm = Permission(0666);
    req.shardBytes = 64;
    return req;
  }
  BeginEcMutationReq beginRequest(const EcObjectRef &object) {
    auto req = request<BeginEcMutationReq>();
    req.object = object;
    req.operation = Uuid::random();
    req.expectedEpoch = 1;
    req.logicalLength = 613;
    req.contentSha256.back() = 1;
    return req;
  }

  Config config;
  storage::client::StorageClient::Config storageConfig;
  std::shared_ptr<kv::IKVEngine> engine;
  std::shared_ptr<tests::FakeMgmtdClient> mgmtd;
  std::shared_ptr<storage::client::StorageClient> storageClient;
  std::unique_ptr<MetaOperator> meta;
  ClientId client = ClientId::random();
  UserInfo root;
  UserInfo user;
};

TEST_F(TestEcCoordinatorMetadata, AtomicCreateOwnerAndDurableOperationIdentity) {
  auto create = createRequest();
  auto created = blockingWait(meta->createEcFile(create));
  ASSERT_OK(created);
  auto repeated = blockingWait(meta->createEcFile(create));
  ASSERT_OK(repeated);
  ASSERT_EQ(created->inode.id, repeated->inode.id);
  ASSERT_EQ(created->object.object.incarnation, repeated->object.object.incarnation);
  auto reused = create;
  reused.path = PathAt(InodeId::root(), "another-file");
  ASSERT_ERROR(blockingWait(meta->createEcFile(reused)), StatusCode::kTokenMismatch);
  auto txn = engine->createReadWriteTransaction();
  ASSERT_RESULT_EQ(uint64_t{1}, blockingWait(EcNamespaceGuard::subtreeCount(*txn, InodeId::root())));
  txn.reset();

  auto begin = beginRequest(created->object.object);
  auto begun = blockingWait(meta->beginEcMutation(begin));
  ASSERT_OK(begun);
  ASSERT_EQ(begun->record.owner.uid, user.uid);
  ASSERT_EQ(begun->record.owner.client, client.uuid);
  auto duplicate = blockingWait(meta->beginEcMutation(begin));
  ASSERT_OK(duplicate);
  ASSERT_EQ(duplicate->record.candidate.generation, begun->record.candidate.generation);
  auto different = begin;
  different.contentSha256[0] ^= 1;
  ASSERT_ERROR(blockingWait(meta->beginEcMutation(different)), StatusCode::kTokenMismatch);
  different = begin;
  different.fragmentCrc32c[11] ^= 1;
  ASSERT_ERROR(blockingWait(meta->beginEcMutation(different)), StatusCode::kTokenMismatch);
  auto get = request<GetEcOperationReq>();
  get.object = begin.object;
  get.operation = begin.operation;
  get.client = ClientId::random();
  ASSERT_ERROR(blockingWait(meta->getEcOperation(get)), MetaCode::kNoPermission);
  auto cancel = request<CancelEcMutationReq>();
  cancel.object = begin.object;
  cancel.operation = begin.operation;
  cancel.client = get.client;
  ASSERT_ERROR(blockingWait(meta->cancelEcMutation(cancel)), MetaCode::kNoPermission);
  // Client UUID is a retry namespace. The same authenticated UID can recover
  // its known namespace; this does not assert isolation between its processes.
  get.client = client;
  ASSERT_OK(blockingWait(meta->getEcOperation(get)));
  get.user = root;
  ASSERT_ERROR(blockingWait(meta->getEcOperation(get)), MetaCode::kNoPermission);
  cancel.client = client;
  auto canceled = blockingWait(meta->cancelEcMutation(cancel));
  ASSERT_OK(canceled);
  ASSERT_EQ(canceled->record.state, EcOperationState::Aborted);
  ASSERT_OK(blockingWait(meta->cancelEcMutation(cancel)));
}

TEST_F(TestEcCoordinatorMetadata, AuthenticationIncarnationAndDisabledPathsFailClosed) {
  auto create = createRequest();
  auto invalid = create;
  invalid.user.token = "not-a-token";
  ASSERT_ERROR(blockingWait(meta->createEcFile(invalid)), StatusCode::kAuthenticationFail);
  auto created = blockingWait(meta->createEcFile(create));
  ASSERT_OK(created);
  auto begin = beginRequest(created->object.object);
  begin.object.incarnation = Uuid::random();
  ASSERT_ERROR(blockingWait(meta->beginEcMutation(begin)), StatusCode::kTokenMismatch);
  begin.object = created->object.object;
  begin.user.groups = {flat::Gid(0)};
  begin.user.uid = flat::Uid(0);
  ASSERT_ERROR(blockingWait(meta->beginEcMutation(begin)), StatusCode::kAuthenticationFail);
  config.set_authenticate(false);
  ASSERT_ERROR(blockingWait(meta->createEcFile(createRequest("second"))), StatusCode::kAuthenticationFail);
  config.set_authenticate(true);
  config.set_ec_allow_unauthorized_storage_for_tests(false);
  ASSERT_ERROR(blockingWait(meta->createEcFile(createRequest("second"))), StatusCode::kNotImplemented);
}

TEST_F(TestEcCoordinatorMetadata, LivePinCannotBeReleasedByOwnerOrRoot) {
  auto created = blockingWait(meta->createEcFile(createRequest()));
  ASSERT_OK(created);
  auto begin = beginRequest(created->object.object);
  auto begun = blockingWait(meta->beginEcMutation(begin));
  ASSERT_OK(begun);
  // Seed a catalog-only publication to test pin authorization, not I/O proof.
  // The independent native fixture verifies the real coordinator's proof path.
  auto manifest = begun->record.candidate;
  std::array<storage::EcReadResult, 12> reads;
  std::array<storage::EcFragmentReceipt, 12> receipts;
  for (size_t i = 0; i != 12; ++i) {
    auto &f = manifest.fragments[i];
    reads[i].payload.data.assign(64, '\0');
    auto integrity = storage::computeEcIntegrity(f.identity, reads[i].payload.data);
    ASSERT_OK(integrity);
    f.integrity = *integrity;
    auto &r = reads[i].receipt;
    r.identity = f.identity;
    r.operationId = f.operation;
    r.vChainId = {f.placement.chain, storage::ChainVer(1)};
    r.targetId = f.placement.target;
    r.length = 64;
    r.checksum = {storage::ChecksumType::CRC32C, ~integrity->wholeCrc32c};
    receipts[i] = r;
  }
  auto verified = EcVerifiedManifest::fromStorageResponses(manifest, reads, receipts);
  ASSERT_OK(verified);
  auto txn = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcCatalog::publish(*txn, begin.object, begin.operation, *verified)));
  auto inode = blockingWait(Inode::load(*txn, begin.object.inode));
  ASSERT_OK(inode);
  ASSERT_TRUE(inode->has_value());
  (**inode).asFile().length = begin.logicalLength;
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  auto acquire = request<AcquireEcReadReq>();
  acquire.object = begin.object;
  acquire.pin = Uuid::random();
  config.set_readonly(true);
  auto pinned = blockingWait(meta->acquireEcRead(acquire));
  ASSERT_OK(pinned);
  auto release = request<ReleaseEcReadReq>();
  release.object = begin.object;
  release.pin = acquire.pin;
  ASSERT_ERROR(blockingWait(meta->releaseEcRead(release)), StatusCode::kNotImplemented);
  release.user = root;
  ASSERT_ERROR(blockingWait(meta->releaseEcRead(release)), MetaCode::kNoPermission);
  release.user = user;
  txn = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcCatalog::releaseRead(*txn, begin.object, acquire.pin)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  ASSERT_OK(blockingWait(meta->releaseEcRead(release)));
}

TEST_F(TestEcCoordinatorMetadata, PermanentCreateResultSurvivesChmodAndParentMove) {
  auto mkdir = request<MkdirsReq>(true);
  mkdir.path = PathAt(InodeId::root(), "parent");
  mkdir.perm = Permission(0777);
  ASSERT_OK(blockingWait(meta->mkdirs(mkdir)));
  auto create = createRequest("parent/file");
  auto created = blockingWait(meta->createEcFile(create));
  ASSERT_OK(created);
  auto txn = engine->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, created->inode.id));
  ASSERT_OK(inode);
  ASSERT_TRUE(inode->has_value());
  (**inode).acl.perm = Permission(0600);
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  auto rename = request<RenameReq>(true);
  rename.src = PathAt(InodeId::root(), "parent");
  rename.dest = PathAt(InodeId::root(), "moved");
  ASSERT_OK(blockingWait(meta->rename(rename)));
  auto duplicate = blockingWait(meta->createEcFile(create));
  ASSERT_OK(duplicate);
  ASSERT_EQ(duplicate->inode.id, created->inode.id);
  ASSERT_EQ(duplicate->inode.acl.perm, created->inode.acl.perm);
  auto changed = create;
  changed.perm = Permission(0600);
  ASSERT_ERROR(blockingWait(meta->createEcFile(changed)), StatusCode::kTokenMismatch);
}

TEST_F(TestEcCoordinatorMetadata, CatalogV1AndMissingOwnerAreRejected) {
  auto created = blockingWait(meta->createEcFile(createRequest()));
  ASSERT_OK(created);
  auto begin = beginRequest(created->object.object);
  auto begun = blockingWait(meta->beginEcMutation(begin));
  ASSERT_OK(begun);
  auto record = begun->record;
  record.owner = EcOwner{};
  auto txn = engine->createReadWriteTransaction();
  std::string operationKey(kv::toStr(kv::KeyPrefix::EcOperation));
  operationKey.append(begin.object.incarnation.asStringView());
  operationKey.append(begin.operation.asStringView());
  ASSERT_OK(blockingWait(txn->set(operationKey, serde::serialize(record))));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  auto query = request<GetEcOperationReq>();
  query.object = begin.object;
  query.operation = begin.operation;
  ASSERT_ERROR(blockingWait(meta->getEcOperation(query)), MetaCode::kNoPermission);
  LegacyEcObjectRecord legacy;
  legacy.object = begin.object;
  legacy.shardBytes = created->object.shardBytes;
  std::string objectKey(kv::toStr(kv::KeyPrefix::EcObject));
  objectKey.append(begin.object.incarnation.asStringView());
  txn = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(objectKey, serde::serialize(legacy))));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  ASSERT_ERROR(blockingWait(meta->getEcOperation(query)), StatusCode::kDataCorruption);
}

TEST_F(TestEcCoordinatorMetadata, PublishRechecksCurrentPermissionBeforeStorage) {
  auto created = blockingWait(meta->createEcFile(createRequest()));
  ASSERT_OK(created);
  auto begin = beginRequest(created->object.object);
  ASSERT_OK(blockingWait(meta->beginEcMutation(begin)));
  auto txn = engine->createReadWriteTransaction();
  auto inode = blockingWait(Inode::load(*txn, created->inode.id));
  ASSERT_OK(inode);
  ASSERT_TRUE(inode->has_value());
  (**inode).acl.perm = Permission(0600);
  ASSERT_OK(blockingWait((**inode).store(*txn)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  auto publish = request<PublishEcMutationReq>();
  publish.object = begin.object;
  publish.operation = begin.operation;
  ASSERT_ERROR(blockingWait(meta->publishEcMutation(publish)), MetaCode::kNoPermission);
}
}  // namespace
}  // namespace hf3fs::meta::server
