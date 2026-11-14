#include <atomic>
#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/json.h>
#include <fstream>
#include <gtest/gtest.h>
#include <mutex>
#include <sys/stat.h>

#include "client/ec/EcAllocationExport.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fbs/meta/MockService.h"
#include "tests/FakeMgmtdClient.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
using folly::coro::blockingWait;
struct Calls {
  std::atomic<size_t> auth{0}, get{0}, mutations{0};
  uint32_t authenticatedUid = 123;
  std::optional<Status> getError;
  meta::EcV2MutationRsp response;
  std::mutex mutex;
  std::optional<meta::GetEcOperationV2Req> request;
};
class ExportService : public meta::MockMetaService {
 public:
  explicit ExportService(std::shared_ptr<Calls> calls)
      : calls_(std::move(calls)) {}
  CoTryTask<meta::AuthRsp> authenticate(serde::CallContext &, const meta::AuthReq &req) override {
    ++calls_->auth;
    auto verified = req.user;
    verified.uid = flat::Uid(calls_->authenticatedUid);
    verified.token.clear();  // The client must retain the credential for RPC 33.
    co_return meta::AuthRsp{verified};
  }
  CoTryTask<meta::EcV2MutationRsp> getEcOperationV2(serde::CallContext &,
                                                    const meta::GetEcOperationV2Req &req) override {
    ++calls_->get;
    {
      std::lock_guard lock(calls_->mutex);
      calls_->request = req;
    }
    if (calls_->getError) co_return makeError(*calls_->getError);
    co_return calls_->response;
  }
#define REJECT_MUTATION(NAME, REQ, RSP)                                         \
  CoTryTask<meta::RSP> NAME(serde::CallContext &, const meta::REQ &) override { \
    ++calls_->mutations;                                                        \
    co_return makeError(StatusCode::kFoundBug);                                 \
  }
  REJECT_MUTATION(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  REJECT_MUTATION(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  REJECT_MUTATION(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  REJECT_MUTATION(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  REJECT_MUTATION(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  REJECT_MUTATION(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  REJECT_MUTATION(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  REJECT_MUTATION(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  REJECT_MUTATION(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  REJECT_MUTATION(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  REJECT_MUTATION(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  REJECT_MUTATION(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  REJECT_MUTATION(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  REJECT_MUTATION(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
#undef REJECT_MUTATION
 private:
  std::shared_ptr<Calls> calls_;
};

class TestEcAllocationExport : public ::testing::Test {
 protected:
  void SetUp() override {
    config_.set_network_type(net::Address::TCP);
    config_.retry_default().set_retry_init_wait(0_ms);
    mgmtd_ = hf3fs::tests::FakeMgmtdClient::create({}, 1, 0);
  }
  void TearDown() override {
    EXPECT_EQ(calls_->mutations.load(), 0);
    if (metadata_) metadata_->stop();
  }
  void openClient(Uuid id) {
    if (metadata_) metadata_->stop();
    serde::ClientMockContext context;
    context.setService(std::make_unique<ExportService>(calls_));
    metadata_ =
        std::make_shared<meta::client::MetaClient>(ClientId(id),
                                                   config_,
                                                   std::make_unique<meta::client::MetaClient::StubFactory>(context),
                                                   mgmtd_,
                                                   nullptr,
                                                   false);
  }
  void prepare(bool repair = false, std::string state = "Published", bool direct = false) {
    run_ = {};
    run_.action = repair ? "repair" : "write";
    run_.cluster = "allocation-export-unit";
    run_.clientNamespace = Uuid::random();
    run_.inputPath = "/original-input";
    run_.inputBytes = 11;
    run_.inputSha256[0] = 1;  // Metadata fixture; not an actual logical-data validation.
    run_.remotePath = "/original-path";
    run_.shardBytes = 8;
    run_.createRequest = Uuid::random();
    run_.operation = Uuid::random();
    run_.beginRequest = Uuid::random();
    run_.bindRequest = Uuid::random();
    run_.publishRequest = Uuid::random();
    run_.getRequest = Uuid::random();
    run_.prepareRepairRequest = Uuid::random();
    run_.pin = Uuid::random();
    run_.acquireRequest = Uuid::random();
    run_.releaseRequest = Uuid::random();
    run_.planId = Uuid::random();
    meta::EcObjectRecord object;
    object.object = {meta::InodeId((1ull << 56) + 0x12345), Uuid::random()};
    object.shardBytes = 8;
    object.allowColocated = true;
    object.epoch = 7;
    object.nextGeneration = 13;
    object.nextRevision = 20;
    object.length = 11;
    object.creator = {flat::Uid(123), run_.clientNamespace};
    object.createRequest = run_.createRequest;
    if (repair) {
      if (direct) {
        run_.version = 3;
        run_.delivery = "direct";
      }
      run_.object = object;
      run_.expectedOwnerUid = 123;
      run_.expectedRevision = 18;
      run_.replacementMask = 3;
      run_.strategy = "helper";
      run_.sourceOrder = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    }
    observed_ = {};
    observed_.ownerUid = 123;
    observed_.object = object;
    observed_.revision = 19;
    observed_.mutationPublished = true;
    observed_.state = std::move(state);
    observed_.logicalBytes = 11;
    observed_.shardBytes = 8;
    const auto runPath = path("run-" + std::to_string(runNumber_++));
    auto created = EcStripeRunJournal::create(runPath, run_);
    ASSERT_OK(created);
    ASSERT_OK((*created)->append(observed_));
    created->reset();
    // Use the actual JSON reopen/lock path used by the CLI, not a direct record substitute.
    auto resumed = EcStripeRunJournal::resume(runPath);
    ASSERT_OK(resumed);
    journal_ = std::move(*resumed);
    openClient(run_.clientNamespace);

    auto &rsp = calls_->response;
    rsp = {};
    rsp.object = object;
    // A later head/object counter may already exist. Export names the original
    // operation's candidate revision, never the current head inferred from it.
    rsp.object.nextRevision = 900;
    rsp.object.length = 42;
    auto &op = rsp.record;
    op.owner = object.creator;
    op.state = meta::EcOperationState::Published;
    auto &intent = op.intent;
    intent.object = object.object;
    intent.operation = run_.operation;
    intent.stripe = 0;
    intent.expectedEpoch = object.epoch;
    intent.expectedRevision = run_.expectedRevision;
    intent.logicalLength = 11;
    intent.kind = repair ? meta::EcMutationKind::Repair : meta::EcMutationKind::Write;
    intent.replacementMask = repair ? run_.replacementMask : meta::kEcAllShards;
    auto &manifest = op.candidate;
    manifest.object = object.object;
    manifest.stripe = 0;
    manifest.generation = 12;
    manifest.revision = 19;
    manifest.logicalLength = 11;
    rsp.allocations.emplace();
    rsp.reservation.emplace();
    auto &reservation = *rsp.reservation;
    reservation.contentSha256 = run_.inputSha256;
    reservation.operationEndpoints.count = 12;
    const auto engine = Uuid::random();
    const meta::EcOwner priorWriter{flat::Uid(456), Uuid::random()};
    const auto priorOperation = Uuid::random();
    std::array<storage::EcScopeEndpoint, 12> endpoints{};
    for (size_t i = 0; i != 12; ++i) {
      auto &binding = (*rsp.allocations)[i];
      auto &fragment = binding.fragment;
      binding.object = object.object;
      fragment.identity.object = object.object.incarnation;
      fragment.identity.stripe = 0;
      fragment.identity.generation = 12;
      fragment.identity.shard = i;
      fragment.identity.allocation = Uuid::random();
      fragment.placement = {storage::ChainId(100 + i), storage::TargetId((1ull << 60) + i), flat::NodeId(9)};
      fragment.operation = repair && i >= 2 ? priorOperation : run_.operation;
      binding.writer = repair && i >= 2 ? priorWriter : op.owner;
      auto integrity = storage::computeEcIntegrity(fragment.identity, std::string(8, char('a' + i)));
      ASSERT_OK(integrity);
      fragment.integrity = *integrity;
      binding.engineUuid = engine;
      binding.targetIncarnation = Uuid::random();
      intent.placements[i] = fragment.placement;
      intent.fragmentCrc32c[i] = fragment.integrity.wholeCrc32c;
      manifest.fragments[i] = fragment;
      reservation.candidates[i] = {fragment.identity, fragment.operation, binding.endpoint(), binding.writer};
      reservation.operationEndpoints.endpoints[i] = binding.endpoint();
      endpoints[i] = binding.endpoint().controlEndpoint();
    }
    auto digest = meta::computeEcRequestDigest(intent, 8, run_.inputSha256);
    ASSERT_OK(digest);
    intent.requestDigest = *digest;
    auto endpointDigest = storage::computeEcScopeEndpointDigest(endpoints);
    ASSERT_OK(endpointDigest);
    reservation.operationEndpoints.digest = *endpointDigest;
    reservation.original = op;
    reservation.original.state = meta::EcOperationState::Preparing;
    if (!repair)
      for (auto &fragment : reservation.original.candidate.fragments) fragment.integrity = {};
  }
  Result<Void> exportTo(std::string name) {
    return blockingWait(exportEcAllocations(metadata_,
                                            *journal_,
                                            flat::UserInfo{flat::Uid(123), flat::Gid(123), token_},
                                            path(name),
                                            {std::chrono::steady_clock::now() + std::chrono::seconds(10), {}}));
  }
  std::string path(const std::string &name) const { return (temp_.path() / name).string(); }
  std::string read(const std::string &name) const {
    std::ifstream input(path(name));
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  }
  folly::test::TemporaryDirectory temp_;
  meta::client::MetaClient::Config config_;
  std::shared_ptr<hf3fs::tests::FakeMgmtdClient> mgmtd_;
  std::shared_ptr<meta::client::MetaClient> metadata_;
  std::shared_ptr<Calls> calls_ = std::make_shared<Calls>();
  std::unique_ptr<EcStripeRunJournal> journal_;
  EcStripeRunRecord run_;
  EcStripeRunObservation observed_;
  size_t runNumber_ = 0;
  const std::string token_ = "fixture-secret-must-not-be-exported";
};

TEST_F(TestEcAllocationExport, OriginalNamespaceQueriesRpc33AndExportsAllExactBindings) {
  for (bool repair : {false, true}) {
    prepare(repair, repair ? "ReadReleased" : "Published");
    ASSERT_NE(journal_, nullptr);
    const auto original = serde::serialize(journal_->record());
    const auto originalState = serde::serialize(*journal_->latest());
    const auto filename = repair ? "repair.json" : "write.json";
    const auto before = calls_->get.load();
    ASSERT_OK(exportTo(filename));
    EXPECT_EQ(calls_->get.load(), before + 1);
    {
      std::lock_guard lock(calls_->mutex);
      ASSERT_TRUE(calls_->request);
      EXPECT_EQ(calls_->request->uuid, run_.getRequest);
      EXPECT_EQ(calls_->request->operation, run_.operation);
      EXPECT_EQ(calls_->request->client.uuid, run_.clientNamespace);
      EXPECT_EQ(calls_->request->user.uid, flat::Uid(123));
      EXPECT_EQ(calls_->request->user.token, token_);
      EXPECT_EQ(calls_->request->object, observed_.object->object);
    }
    const auto bytes = read(filename);
    const auto json = folly::parseJson(bytes);
    EXPECT_EQ(json["object"]["inode_decimal"].asString(), std::to_string(observed_.object->object.inode.u64()));
    EXPECT_EQ(json["revision_decimal"].asString(), "19");
    EXPECT_EQ(json["operation"].asString(), run_.operation.toHexString());
    EXPECT_EQ(json["request_id"].asString(), run_.getRequest.toHexString());
    EXPECT_EQ(json["query_rpc"].asInt(), 33);
    EXPECT_EQ(json["mutation_state"].asString(), "Published");
    EXPECT_FALSE(json["gc_authorized"].asBool());
    ASSERT_EQ(json["allocations"].size(), 12);
    for (size_t i = 0; i != 12; ++i) {
      const auto &expected = (*calls_->response.allocations)[i];
      const auto &actual = json["allocations"][i];
      EXPECT_EQ(actual["identity"]["allocation"].asString(), expected.fragment.identity.allocation.toHexString());
      EXPECT_EQ(actual["identity"]["shard"].asInt(), i);
      EXPECT_EQ(actual["placement"]["target_decimal"].asString(),
                std::to_string(expected.fragment.placement.target.toUnderType()));
      EXPECT_EQ(actual["engine_uuid"].asString(), expected.engineUuid.toHexString());
      EXPECT_EQ(actual["target_incarnation"].asString(), expected.targetIncarnation.toHexString());
      EXPECT_EQ(actual["fragment_operation"].asString(), expected.fragment.operation.toHexString());
      EXPECT_EQ(actual["writer"]["uid"].asInt(), expected.writer.uid.toUnderType());
      EXPECT_EQ(actual["integrity"]["blocks"].size(), 16);
    }
    EXPECT_EQ(bytes.find(token_), std::string::npos);
    EXPECT_EQ(bytes.find("grants"), std::string::npos);
    EXPECT_EQ(serde::serialize(journal_->record()), original);
    EXPECT_EQ(serde::serialize(*journal_->latest()), originalState);
    struct stat info {};
    ASSERT_EQ(::stat(path(filename).c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0600);
  }
}

TEST_F(TestEcAllocationExport, WrongAuthenticatedOwnerOrActualNamespaceNeverQueriesOperation) {
  prepare();
  calls_->authenticatedUid = 0;  // A successful root authentication is not the original owner.
  ASSERT_ERROR(exportTo("wrong-owner.json"), StatusCode::kAuthenticationFail);
  EXPECT_EQ(calls_->auth.load(), 1);
  EXPECT_EQ(calls_->get.load(), 0);
  EXPECT_TRUE(read("wrong-owner.json").empty());
  calls_->authenticatedUid = 123;
  openClient(Uuid::random());
  ASSERT_ERROR(exportTo("wrong-namespace.json"), StatusCode::kTokenMismatch);
  EXPECT_EQ(calls_->auth.load(), 1);
  EXPECT_EQ(calls_->get.load(), 0);
  EXPECT_FALSE(std::filesystem::exists(path("wrong-namespace.json")));
}

TEST_F(TestEcAllocationExport, PublishedHelperDirectJournalExportsOriginalAllocationsAfterReadRelease) {
  prepare(true, "ReadReleased", true);
  ASSERT_EQ(journal_->record().version, 3);
  ASSERT_EQ(journal_->record().delivery, "direct");
  const auto original = serde::serialize(journal_->record());
  ASSERT_OK(exportTo("direct.json"));
  EXPECT_EQ(calls_->get.load(), 1);
  EXPECT_EQ(calls_->mutations.load(), 0);
  const auto json = folly::parseJson(read("direct.json"));
  ASSERT_EQ(json["allocations"].size(), 12);
  EXPECT_EQ(json["operation"].asString(), run_.operation.toHexString());
  EXPECT_EQ(json["request_id"].asString(), run_.getRequest.toHexString());
  EXPECT_EQ(json["query_rpc"].asInt(), 33);
  EXPECT_FALSE(json["gc_authorized"].asBool());
  EXPECT_EQ(serde::serialize(journal_->record()), original);
}

TEST_F(TestEcAllocationExport, RejectsMixedMetadataRemoteStatesAndUnavailableHistoricalPermissions) {
  prepare();
  const auto valid = calls_->response;
  for (int fault = 0; fault != 13; ++fault) {
    calls_->response = valid;
    auto &rsp = calls_->response;
    switch (fault) {
      case 0:
        rsp.record.owner.client = Uuid::random();
        break;
      case 1:
        rsp.record.candidate.generation++;
        break;
      case 2:
        (*rsp.allocations)[0].fragment.identity.allocation = Uuid::random();
        break;
      case 3:
        (*rsp.allocations)[0].fragment.placement.node = flat::NodeId(99);
        break;
      case 4:
        (*rsp.allocations)[0].engineUuid = Uuid::random();
        break;
      case 5:
        rsp.reservation->candidates[0].endpoint.targetIncarnation = Uuid::random();
        break;
      case 6:
        (*rsp.allocations)[0].fragment.integrity.root[0] ^= 1;
        break;
      case 7:
        rsp.allocations.reset();
        break;
      case 8:
        rsp.record.state = meta::EcOperationState::Preparing;
        break;
      case 9:
        rsp.record.state = meta::EcOperationState::Aborted;
        break;
      case 10:
        rsp.record.candidate.revision++;
        break;
      case 11:
        rsp.object.object.incarnation = Uuid::random();
        break;
      case 12:
        rsp.reservation->original.intent.fragmentCrc32c[0] ^= 1;
        break;
    }
    const auto filename = "mismatch-" + std::to_string(fault) + ".json";
    ASSERT_FALSE(exportTo(filename)) << fault;
    EXPECT_TRUE(read(filename).empty()) << fault;
  }
  calls_->response = valid;
  calls_->getError = Status(StatusCode::kAuthenticationFail);
  ASSERT_ERROR(exportTo("permissions-changed.json"), StatusCode::kAuthenticationFail);
  EXPECT_TRUE(read("permissions-changed.json").empty());
  EXPECT_EQ(journal_->latest()->revision, 19);
}

TEST_F(TestEcAllocationExport, ExistingOutputAndUnpublishedLocalObservationDoNotDispatch) {
  prepare();
  {
    std::ofstream output(path("existing.json"));
    output << "preserve-original";
  }
  ASSERT_FALSE(exportTo("existing.json"));
  EXPECT_EQ(read("existing.json"), "preserve-original");
  EXPECT_EQ(calls_->auth.load() + calls_->get.load(), 0);
  prepare(false, "Preparing");
  ASSERT_ERROR(exportTo("pending.json"), StatusCode::kInvalidArg);
  EXPECT_FALSE(std::filesystem::exists(path("pending.json")));
  EXPECT_EQ(calls_->auth.load() + calls_->get.load(), 0);
  prepare(false, "ReadReleased");  // Only a published Repair may retain this final state.
  ASSERT_ERROR(exportTo("wrong-final-state.json"), StatusCode::kInvalidArg);
  EXPECT_EQ(calls_->auth.load() + calls_->get.load(), 0);
}
}  // namespace
}  // namespace hf3fs::client::ec
