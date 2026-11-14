#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <sys/stat.h>

#include "client/ec/NativeEcBlockTransport.h"
#include "client/ec/NativeEcReadTransport.h"
#include "client/ec/NativeEcRepairTransport.h"
#include "client/ec/detail/EcStripeClientCore.h"
#include "client/storage/StorageClientInMem.h"
#include "storage/ec_repair/EcHelperDirectAuthorization.h"
#include "tests/EcRepairTestData.h"
#include "tests/FakeMgmtdClient.h"

namespace hf3fs::client::ec {
namespace {
using namespace storage;
using folly::coro::blockingWait;
using Policy = EcStorageTransportPolicy;
using Control = storage::client::EcRequestControl;

// Exercise the real Native adapters at their virtual SDK boundary. No socket,
// hardware RDMA, target persistence, MAC verification or successful RPC is claimed.
class CapturingStorage final : public storage::client::StorageClientInMem {
 public:
  using StorageClientInMem::StorageClientInMem;
  struct Call {
    std::string method;
    Policy transport;
    std::chrono::steady_clock::time_point deadline;
  };
  std::vector<Call> calls;
  void note(std::string method, const Control &control) {
    calls.push_back({std::move(method), control.transport, control.deadline});
  }
  CoTryTask<EcReadResult> authorizedReadEcFragmentControlled(EcAuthorizedReadReq, Control c) override {
    note("read", c);
    co_return makeError(StatusCode::kNotImplemented);
  }
  CoTryTask<EcReadBlockResultV2> readEcBlockV2Controlled(EcReadBlockV2Req, Control c) override {
    note("block", c);
    co_return makeError(StatusCode::kNotImplemented);
  }
  CoTryTask<EcStageStateV2> beginEcStageV2Controlled(EcBeginStageV2Req, Control c) override {
    note("begin", c);
    // Force the adapter's actual recovery Query/Reconcile path.
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  CoTryTask<EcStageStateV2> queryEcStageV2Controlled(EcQueryStageV2Req, Control c) override {
    note("query", c);
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  CoTryTask<EcStageStateV2> reconcileEcStageV2Controlled(EcReconcileStageV2Req, Control c) override {
    note("reconcile", c);
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  CoTryTask<EcStageStateV2> appendEcStageV2Controlled(EcAppendStageV2Req, Control c) override {
    note("append", c);
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  CoTryTask<EcFragmentReceiptV2> sealEcStageV2Controlled(EcSealStageV2Req, Control c) override {
    note("seal", c);
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
  CoTryTask<EcHelperHopResult> executeEcHelper(EcHelperHopReq, Control c) override {
    note("helper", c);
    co_return makeError(StatusCode::kNotImplemented);
  }
  CoTryTask<EcHelperDirectHopResult> executeEcHelperDirect(EcHelperDirectHopReq, Control c) override {
    note("direct", c);
    co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  }
};

Result<EcCapabilityV2> grant(const EcRepairPlanInput &plan, const EcRepairFragment &fragment,
                            uint16_t rights, const EcCapabilityKey &key) {
  EcGrantClaimsV2 c;
  c.identity = fragment.identity;
  c.fragmentOperationId = fragment.operationId;
  c.engineUuid = fragment.endpoint.engineUuid;
  c.targetIncarnation = fragment.endpoint.targetIncarnation;
  c.nodeId = fragment.endpoint.nodeId;
  c.chainId = fragment.endpoint.chainId;
  c.targetId = fragment.endpoint.targetId;
  c.expectedLength = fragment.integrity.wholeLength;
  c.expectedCrc32c = fragment.integrity.wholeCrc32c;
  CHECK_RESULT(digest, digestEcIntegrityV2(fragment.identity, fragment.integrity));
  c.integrityDigest = digest;
  c.ownerUid = plan.ownerUid;
  c.clientNamespace = plan.clientNamespace;
  c.scopeObject = fragment.identity.object;
  c.scopeKind = EcGrantScope::WriteOperation;
  c.scopeId = plan.operationId;
  c.rights = rights;
  c.grantId = Uuid::random();
  c.issuedAtSeconds = 1000;
  c.expiresAtSeconds = 1030;
  return signEcGrantV2(key, c, 1000);
}
EcFragmentAccessV2 access(const EcRepairFragment &fragment) {
  EcFragmentAccessV2 r;
  r.identity = fragment.identity;
  r.operationId = fragment.operationId;
  r.vChainId = {fragment.endpoint.chainId, ChainVer(1)};
  r.targetId = fragment.endpoint.targetId;
  r.integrity = fragment.integrity;
  return r;
}

TEST(TestEcNativeTransportPolicy, ParserAndPublicControlRejectImplicitSelection) {
  ASSERT_OK(parseEcStorageTransport("tcp"));
  ASSERT_OK(parseEcStorageTransport("rdma"));
  EXPECT_EQ(*parseEcStorageTransport("tcp"), Policy::TcpOnly);
  EXPECT_EQ(*parseEcStorageTransport("rdma"), Policy::RdmaOnly);
  for (auto value : {"", "automatic", "TCP", "rdma ", "other"}) {
    ASSERT_ERROR(parseEcStorageTransport(value), StatusCode::kInvalidConfig);
  }
  folly::CPUThreadPoolExecutor pool(1);
  EcStripeClient::Limits limits;
  auto core = std::make_shared<detail::EcStripeClientCore>(
      nullptr, nullptr, nullptr, flat::UserInfo{}, Uuid::random(), pool, limits);
  EcStripeControl c{std::chrono::steady_clock::now() + std::chrono::seconds(10), {}};
  EXPECT_EQ(c.transport, Policy::TcpOnly);
  for (auto policy : {Policy::TcpOnly, Policy::RdmaOnly}) {
    c.transport = policy;
    ASSERT_OK(core->validControl(c));
  }
  for (auto policy : {Policy::Automatic, static_cast<Policy>(255)}) {
    c.transport = policy;
    meta::CreateEcFileV2Req request;
    request.uuid = Uuid::random();
    // A metadata call would dereference nullptr. Rejection must precede it.
    ASSERT_ERROR(blockingWait(core->createOwned(request, c)), StatusCode::kInvalidArg);
  }
  blockingWait(detail::EcStripeClientCore::close(core));
}

TEST(TestEcNativeTransportPolicy, ReadAdaptersPreservePolicyAndRejectInvalidBeforeDispatch) {
  auto mgmtd = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
  storage::client::StorageClient::Config config;
  auto client = std::make_shared<CapturingStorage>(ClientId::random(), config, *mgmtd);
  EcReadControl control{std::chrono::steady_clock::now() + std::chrono::seconds(10), {}};
  NativeEcReadTransport defaultRead(client);
  NativeEcBlockTransport defaultBlock(client);
  EXPECT_FALSE(blockingWait(defaultRead.read({}, control)));
  EXPECT_FALSE(blockingWait(defaultBlock.read({}, control)));
  ASSERT_EQ(client->calls.size(), 2u);
  for (const auto &call : client->calls) EXPECT_EQ(call.transport, Policy::TcpOnly);
  for (auto policy : {Policy::TcpOnly, Policy::RdmaOnly}) {
    client->calls.clear();
    NativeEcReadTransport read(client, policy);
    NativeEcBlockTransport block(client, nullptr, policy);
    EXPECT_FALSE(blockingWait(read.read({}, control)));
    EXPECT_FALSE(blockingWait(block.read({}, control)));
    ASSERT_EQ(client->calls.size(), 2u);
    for (const auto &call : client->calls) {
      EXPECT_EQ(call.transport, policy);
      EXPECT_EQ(call.deadline, control.deadline);
    }
  }
  for (auto policy : {Policy::Automatic, static_cast<Policy>(255)}) {
    client->calls.clear();
    NativeEcReadTransport read(client, policy);
    NativeEcBlockTransport block(client, nullptr, policy);
    ASSERT_ERROR(blockingWait(read.read({}, control)), StatusCode::kInvalidArg);
    ASSERT_ERROR(blockingWait(block.read({}, control)), StatusCode::kInvalidArg);
    EXPECT_TRUE(client->calls.empty());
  }
}

TEST(TestEcNativeTransportPolicy, RepairPolicyReachesRecoveryStagesAndBothHelperModes) {
  auto mgmtd = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
  storage::client::StorageClient::Config config;
  auto client = std::make_shared<CapturingStorage>(ClientId::random(), config, *mgmtd);
  const auto data = repair_test::makeData(17);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  std::array<uint8_t, 32> secret;
  secret.fill(71);
  EcCapabilityKey key(secret);
  folly::test::TemporaryDirectory directory;
  const auto keyPath = std::filesystem::path(directory.path().string()) / "helper.key";
  {
    std::ofstream out(keyPath, std::ios::binary);
    out.write(reinterpret_cast<const char *>(secret.data()), secret.size());
    out.close();
    ASSERT_TRUE(out.good());
  }
  ASSERT_EQ(::chmod(keyPath.c_str(), 0600), 0);
  auto helperKey = EcHelperKey::loadFile(keyPath);
  ASSERT_OK(helperKey);
  EcRepairNativeBindings bindings;
  std::array<EcHelperCapability, 10> helpers;
  for (size_t i = 0; i != 10; ++i) {
    auto read = grant(data.input, data.input.sources[i], uint16_t(EcGrantRightV2::ReadBlock), key);
    ASSERT_OK(read);
    bindings.sources[i].request = access(data.input.sources[i]);
    bindings.sources[i].grant = *read;
    auto claims = makeEcHelperClaims(**plan, i, 1, 1000, 30);
    ASSERT_OK(claims);
    auto helper = signEcHelperGrant(**helperKey, *claims, 1000);
    ASSERT_OK(helper);
    helpers[i] = *helper;
  }
  std::array<EcCapabilityV2, 2> append, query;
  for (size_t i = 0; i != data.input.targetCount; ++i) {
    auto stage = grant(data.input, data.input.targets[i], kEcGrantAllRightsV2, key);
    auto a = grant(data.input, data.input.targets[i], uint16_t(EcGrantRightV2::Append), key);
    auto q = grant(data.input, data.input.targets[i], uint16_t(EcGrantRightV2::Query), key);
    ASSERT_OK(stage);
    ASSERT_OK(a);
    ASSERT_OK(q);
    bindings.targets[i].request = access(data.input.targets[i]);
    bindings.targets[i].grant = *stage;
    append[i] = *a;
    query[i] = *q;
  }
  auto direct = issueEcHelperDirectDelegation(**helperKey, **plan, append, query, 1, 1000, 30);
  ASSERT_OK(direct);
  EcRepairControl control{std::chrono::steady_clock::now() + std::chrono::seconds(30), {}};
  for (auto policy : {Policy::TcpOnly, Policy::RdmaOnly}) {
    auto transport = NativeEcRepairTransport::create(*plan, client, bindings, helpers, nullptr, *direct, policy);
    ASSERT_OK(transport);
    client->calls.clear();
    ASSERT_ERROR(blockingWait((*transport)->begin(*plan, 0, control)), StorageCode::kEcSealOutcomeUnknown);
    EXPECT_FALSE(blockingWait((*transport)->read(*plan, 0, 0, control)));
    EXPECT_FALSE(blockingWait((*transport)->append(*plan, 0, 0, data.shards[data.input.targets[0].identity.shard], control)));
    EXPECT_FALSE(blockingWait((*transport)->seal(*plan, 0, control)));
    EXPECT_FALSE(blockingWait((*transport)->helperBlock(*plan, 0, control)));
    ASSERT_ERROR(blockingWait((*transport)->helperDirectBlock(*plan, 0, control)), StorageCode::kEcSealOutcomeUnknown);
    const std::vector<std::string> expected{"begin", "query", "reconcile", "block", "append", "seal", "helper", "direct"};
    ASSERT_EQ(client->calls.size(), expected.size());
    for (size_t i = 0; i != expected.size(); ++i) {
      EXPECT_EQ(client->calls[i].method, expected[i]);
      EXPECT_EQ(client->calls[i].transport, policy);
      EXPECT_EQ(client->calls[i].deadline, control.deadline);
    }
  }
  for (auto policy : {Policy::Automatic, static_cast<Policy>(255)}) {
    client->calls.clear();
    ASSERT_ERROR(NativeEcRepairTransport::create(*plan, client, bindings, helpers, nullptr, *direct, policy),
                 StatusCode::kInvalidArg);
    EXPECT_TRUE(client->calls.empty());
  }
}
}  // namespace
}  // namespace hf3fs::client::ec
