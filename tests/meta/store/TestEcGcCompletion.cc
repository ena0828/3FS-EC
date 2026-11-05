#include <algorithm>
#include <atomic>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <new>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/stat.h>
#include <type_traits>
#include <utility>

#include "common/kv/mem/MemKVEngine.h"
#include "meta/components/EcGcCoordinator.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::storage {
// Test-only cryptographic observation model. These are not Rust ledger/WAL or
// Storage TCP receipts. The production coordinator has no ACK signing access.
class EcGcControlTestAccess {
 public:
  static Result<EcGcRequest> sign(const EcGcKey &key, const EcGcRequestClaims &claims) {
    return ec_gc_control_detail::RequestSigner::sign(key, claims, claims.issuedAtSeconds);
  }
  static Result<EcGcAck> confirm(const EcGcKey &key,
                                 const EcGcRequest &request,
                                 const EcGcLocalTarget &target,
                                 EcSha256 ledger,
                                 uint64_t revision,
                                 Uuid boot) {
    CHECK_RESULT(verified,
                 ec_gc_control_detail::Codec::verifyRequest(key,
                                                            request,
                                                            request.claims.authority,
                                                            request.claims.action,
                                                            target,
                                                            request.claims.issuedAtSeconds));
    return ec_gc_control_detail::AckSigner::sign(
        key,
        verified,
        EcGcLedgerReceipt{request.claims.certificate.claimId, ledger, revision},
        target,
        request.claims.authority,
        boot,
        request.claims.issuedAtSeconds);
  }
};
}  // namespace hf3fs::storage

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;
using Codec = storage::ec_gc_control_detail::Codec;
using Access = storage::EcGcControlTestAccess;
using Control = storage::client::EcRequestControl;
static_assert(!std::is_default_constructible_v<EcConfirmedGcClaim>);
static_assert(!std::is_constructible_v<EcConfirmedGcClaim, EcGcClaim, storage::EcGcCertificate>);

storage::EcSha256 hash(std::string_view bytes) {
  storage::EcSha256 digest{};
  unsigned int size = 0;
  if (!EVP_Digest(bytes.data(), bytes.size(), digest.data(), &size, EVP_sha256(), nullptr) || size != digest.size())
    throw std::runtime_error("test SHA-256 failed");
  return digest;
}
std::string allocationKey(kv::KeyPrefix prefix, const storage::EcFragmentIdentity &identity) {
  auto chunk = identity.chunkId();
  if (!chunk) throw std::runtime_error("invalid fixture identity");
  return std::string(kv::toStr(prefix)) + std::string(chunk->data());
}
Control control() {
  return {std::chrono::steady_clock::now() + std::chrono::seconds(10), {}, Control::TransportPolicy::TcpOnly};
}

struct CommitFault {
  bool failBefore = false;
  bool loseAfter = false;
};
class CompletionTransaction : public kv::MemTransaction {
 public:
  CompletionTransaction(kv::mem::MemKV &mem, std::shared_ptr<CommitFault> fault)
      : kv::MemTransaction(mem),
        fault_(std::move(fault)) {}
  CoTryTask<void> set(std::string_view key, std::string_view value) override {
    if (key.starts_with(kv::toStr(kv::KeyPrefix::EcGcCompletion))) completion_ = true;
    co_return co_await kv::MemTransaction::set(key, value);
  }
  CoTryTask<void> commit() override {
    if (completion_ && std::exchange(fault_->failBefore, false))
      co_return makeError(TransactionCode::kConflict, "model fails before completion commit");
    auto result = co_await kv::MemTransaction::commit();
    CO_RETURN_ON_ERROR(result);
    if (completion_ && std::exchange(fault_->loseAfter, false))
      co_return makeError(TransactionCode::kMaybeCommitted, "model loses ACK after actual MemKV commit");
    co_return Void{};
  }

 private:
  std::shared_ptr<CommitFault> fault_;
  bool completion_ = false;
};
class CompletionEngine : public kv::MemKVEngine {
 public:
  std::shared_ptr<CommitFault> fault = std::make_shared<CommitFault>();
  std::unique_ptr<kv::IReadWriteTransaction> createReadWriteTransaction() override {
    return std::make_unique<CompletionTransaction>(getKV(), fault);
  }
};

class ObservationModel : public EcGcTransport {
 public:
  std::shared_ptr<const storage::EcGcKey> key;
  storage::EcGcLocalTarget actual;
  storage::EcSha256 ledger = hash("synthetic-local-GC-ledger-not-a-Storage-proof");
  uint64_t revision = 7;
  Uuid boot = Uuid::random();
  std::optional<status_code_t> error;
  bool throws = false;
  size_t calls = 0;
  std::optional<storage::EcGcRequest> lastRequest;
  std::optional<storage::EcGcAck> lastAck;
  CoTryTask<storage::EcGcAck> exchange(storage::EcGcRequest request, Control) override {
    ++calls;
    lastRequest = request;
    if (throws) throw std::bad_alloc();
    if (error) co_return makeError(*error, "synthetic transport result");
    auto ack = Access::confirm(*key, request, actual, ledger, revision, boot);
    if (ack) lastAck = *ack;
    co_return ack;
  }
};

class TestEcGcCompletion : public ::testing::Test {
 protected:
  void SetUp() override {
    engine = std::make_shared<CompletionEngine>();
    object = {InodeId(1234), Uuid::random()};
    owner = {flat::Uid(101), Uuid::random()};
    auto txn = engine->createReadWriteTransaction();
    createRequest = Uuid::random();
    ASSERT_OK(blockingWait(EcV2BindingCatalog::createTrackedV2Object(*txn, object, 64, true, owner, createRequest)));
    ASSERT_OK(blockingWait(txn->commit()));
    claim.claimId = Uuid::random();
    claim.enrollment.object = object;
    claim.enrollment.creator = owner;
    claim.enrollment.createRequest = createRequest;
    claim.allocation.object = object;
    auto &fragment = claim.allocation.fragment;
    fragment.identity.object = object.incarnation;
    fragment.identity.generation = 1;
    fragment.identity.allocation = Uuid::random();
    fragment.operation = Uuid::random();
    fragment.placement = {storage::ChainId(101), storage::TargetId(201), flat::NodeId(301)};
    auto integrity = storage::computeEcIntegrity(fragment.identity, std::string(64, 'a'));
    ASSERT_OK(integrity);
    fragment.integrity = *integrity;
    claim.allocation.writer = owner;
    claim.allocation.engineUuid = Uuid::random();
    claim.allocation.targetIncarnation = Uuid::random();
    claim.registeredScopes = claim.releasedScopes = 3;
    claim.releaseHistory = hash("synthetic-released-GC-memberships");
    claim.originDrainEvidence = hash("synthetic-origin-T2-ACK-set");
    claim.eligibilityDigest = hash(std::string("3FSECGC-CLAIM-v1") + std::string(serde::serialize(claim)));

    const auto path = directory.path() / "gc.key";
    std::ofstream file(path.string(), std::ios::binary);
    std::array<char, 32> bytes{};
    std::fill(bytes.begin(), bytes.end(), char{23});
    file.write(bytes.data(), bytes.size());
    file.close();
    ASSERT_TRUE(file.good());
    ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
    auto loaded = storage::EcGcKey::loadFile(std::filesystem::path(path.string()), Uuid::random(), {});
    ASSERT_OK(loaded);
    key = std::shared_ptr<const storage::EcGcKey>(std::move(*loaded));
    model = std::make_shared<ObservationModel>();
    model->key = key;
    model->actual = {claim.allocation.endpoint().controlEndpoint(), 2, 3, 1, true};
    config.authority = Uuid::random();
    config.targets = {model->actual};
    config.nowSeconds = [] { return uint64_t{1700000000}; };
    auto value = EcGcCoordinator::create(config, engine, key, model);
    ASSERT_OK(value);
    coordinator = std::move(*value);
  }

  // Deliberate metadata fixture: models already-qualified claim records and
  // their consistent immutable links. It does not exercise eligibility/T2 or
  // create an actual fragment. Those belong to TestEcV2GcCatalog/native tests.
  Result<Void> seed(kv::IReadWriteTransaction &txn) {
    EcGcAllocationRecord allocation;
    allocation.object = object;
    allocation.allocation = {claim.allocation.fragment.identity,
                             claim.allocation.fragment.operation,
                             claim.allocation.endpoint(),
                             claim.allocation.writer};
    allocation.registered = allocation.released = claim.registeredScopes;
    allocation.releaseHistory = claim.releaseHistory;
    allocation.claimId = claim.claimId;
    RETURN_ON_ERROR(blockingWait(
        txn.set(allocationKey(kv::KeyPrefix::EcV2Allocation, identity()), serde::serialize(claim.allocation))));
    RETURN_ON_ERROR(
        blockingWait(txn.set(allocationKey(kv::KeyPrefix::EcGcAllocation, identity()), serde::serialize(allocation))));
    RETURN_ON_ERROR(
        blockingWait(txn.set(allocationKey(kv::KeyPrefix::EcGcClaim, identity()), serde::serialize(claim))));
    return Void{};
  }
  Result<Void> seedCommitted() {
    auto txn = engine->createReadWriteTransaction();
    RETURN_ON_ERROR(seed(*txn));
    RETURN_ON_ERROR(blockingWait(txn->commit()));
    return Void{};
  }
  const storage::EcFragmentIdentity &identity() const { return claim.allocation.fragment.identity; }
  Result<storage::EcGcRequest> signedRequest(storage::EcGcAction action = storage::EcGcAction::Collect) {
    CHECK_RESULT(certificate, EcGcCompletionCatalog::project(claim));
    storage::EcGcRequestClaims claims;
    claims.certificate = certificate;
    claims.authority = config.authority;
    claims.keyId = key->keyId();
    claims.nonce = Uuid::random();
    claims.action = action;
    claims.issuedAtSeconds = config.nowSeconds();
    claims.expiresAtSeconds = claims.issuedAtSeconds + 60;
    return Access::sign(*key, claims);
  }
  CoTryTask<EcGcCompletion> record(kv::IReadWriteTransaction &txn,
                                   const storage::EcGcRequest &request,
                                   const storage::EcGcAck &ack) {
    co_return co_await EcGcCompletionCatalog::record(txn,
                                                     object,
                                                     identity(),
                                                     claim.claimId,
                                                     request,
                                                     ack,
                                                     *key,
                                                     config.authority);
  }
  folly::test::TemporaryDirectory directory;
  std::shared_ptr<CompletionEngine> engine;
  EcObjectRef object;
  EcOwner owner;
  Uuid createRequest;
  EcGcClaim claim;
  std::shared_ptr<const storage::EcGcKey> key;
  std::shared_ptr<ObservationModel> model;
  EcGcCoordinator::Config config;
  std::unique_ptr<EcGcCoordinator> coordinator;
};

TEST_F(TestEcGcCompletion, FullProjectionKeepsIdentityEvidenceAndIndependentVersions) {
  auto projected = EcGcCompletionCatalog::project(claim);
  ASSERT_OK(projected);
  EXPECT_EQ(projected->objectInode, object.inode.u64());
  EXPECT_EQ(projected->creatorUid, owner.uid);
  EXPECT_EQ(projected->writerClient, owner.client);
  EXPECT_EQ(projected->fragmentOperation, claim.allocation.fragment.operation);
  EXPECT_EQ(projected->integrity, claim.allocation.fragment.integrity);
  EXPECT_EQ(projected->eligibilityDigest, claim.eligibilityDigest);
  EXPECT_EQ(projected->releaseHistory, claim.releaseHistory);
  EXPECT_EQ(projected->originDrainEvidence, claim.originDrainEvidence);
  EXPECT_EQ(projected->dataProtocol, 2);
  EXPECT_EQ(projected->diskFormat, 3);
  claim.enrollment.object.inode = InodeId(1235);
  ASSERT_ERROR(EcGcCompletionCatalog::project(claim), StatusCode::kDataCorruption);
}

TEST_F(TestEcGcCompletion, UncommittedClaimCannotReachSignerOrTransport) {
  auto pending = engine->createReadWriteTransaction();
  ASSERT_OK(seed(*pending));
  auto before = blockingWait(coordinator->collect(object, identity(), claim.claimId, control()));
  ASSERT_FALSE(before);
  EXPECT_EQ(model->calls, 0);
  ASSERT_OK(blockingWait(pending->commit()));
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), Uuid::random(), control())),
               StatusCode::kTokenMismatch);
  EXPECT_EQ(model->calls, 0);
  ASSERT_OK(blockingWait(coordinator->collect(object, identity(), claim.claimId, control())));
  EXPECT_EQ(model->calls, 1);
}

TEST_F(TestEcGcCompletion, NewQueryNonceTimeAndBootRetainFirstPermanentProof) {
  ASSERT_OK(seedCommitted());
  auto first = blockingWait(coordinator->collect(object, identity(), claim.claimId, control()));
  ASSERT_OK(first);
  auto request = signedRequest(storage::EcGcAction::Query);
  ASSERT_OK(request);
  auto renewed = request->claims;
  renewed.issuedAtSeconds += 1000;
  renewed.expiresAtSeconds += 1000;
  request = Access::sign(*key, renewed);
  ASSERT_OK(request);
  auto ack = Access::confirm(*key, *request, model->actual, model->ledger, model->revision, Uuid::random());
  ASSERT_OK(ack);
  auto txn = engine->createReadWriteTransaction();
  auto duplicate = blockingWait(record(*txn, *request, *ack));
  ASSERT_OK(duplicate);
  EXPECT_EQ(std::string(serde::serialize(*duplicate)), std::string(serde::serialize(*first)));
  ASSERT_OK(blockingWait(txn->commit()));
  auto after = blockingWait(coordinator->getCompletion(object, identity(), claim.claimId));
  ASSERT_OK(after);
  ASSERT_TRUE(*after);
  EXPECT_EQ(Codec::frame((**after).ack), Codec::frame(first->ack));
}

TEST_F(TestEcGcCompletion, AuthenticatedDifferentInstanceOrClaimCannotComplete) {
  ASSERT_OK(seedCommitted());
  auto request = signedRequest();
  ASSERT_OK(request);
  auto changed = request->claims;
  changed.certificate.endpoint.targetIncarnation = Uuid::random();
  auto signedChanged = Access::sign(*key, changed);
  ASSERT_OK(signedChanged);
  auto actual = model->actual;
  actual.endpoint = changed.certificate.endpoint;
  auto ack = Access::confirm(*key, *signedChanged, actual, model->ledger, model->revision, model->boot);
  ASSERT_OK(ack);
  auto txn = engine->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(record(*txn, *signedChanged, *ack)), StatusCode::kTokenMismatch);
  txn.reset();
  auto absent = blockingWait(coordinator->getCompletion(object, identity(), claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  txn = engine->createReadWriteTransaction();
  auto goodAck = Access::confirm(*key, *request, model->actual, model->ledger, model->revision, model->boot);
  ASSERT_OK(goodAck);
  goodAck->claims.claimId = Uuid::random();
  ASSERT_FALSE(blockingWait(record(*txn, *request, *goodAck)));
}

TEST_F(TestEcGcCompletion, ConcurrentCompletionConflictsAndStableLedgerCannotChange) {
  ASSERT_OK(seedCommitted());
  auto one = signedRequest();
  auto two = signedRequest(storage::EcGcAction::Query);
  ASSERT_OK(one);
  ASSERT_OK(two);
  auto ack1 = Access::confirm(*key, *one, model->actual, model->ledger, model->revision, model->boot);
  auto ack2 = Access::confirm(*key, *two, model->actual, model->ledger, model->revision, Uuid::random());
  ASSERT_OK(ack1);
  ASSERT_OK(ack2);
  auto a = engine->createReadWriteTransaction();
  auto b = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(record(*a, *one, *ack1)));
  ASSERT_OK(blockingWait(record(*b, *two, *ack2)));
  ASSERT_OK(blockingWait(a->commit()));
  ASSERT_ERROR(blockingWait(b->commit()), TransactionCode::kConflict);
  b = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(record(*b, *two, *ack2)));
  ASSERT_OK(blockingWait(b->commit()));
  auto changed = Access::confirm(*key, *two, model->actual, hash("different-ledger"), model->revision, model->boot);
  ASSERT_OK(changed);
  b = engine->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(record(*b, *two, *changed)), StatusCode::kDataCorruption);
}

TEST_F(TestEcGcCompletion, HistoricalProofStillRequiresExactExchangeAuthorityAndConfiguredKey) {
  ASSERT_OK(seedCommitted());
  auto first = blockingWait(coordinator->collect(object, identity(), claim.claimId, control()));
  ASSERT_OK(first);
  auto renewed = signedRequest(storage::EcGcAction::Query);
  ASSERT_OK(renewed);
  auto txn = engine->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(record(*txn, *renewed, first->ack)), StatusCode::kTokenMismatch);
  txn.reset();
  txn = engine->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(EcGcCompletionCatalog::get(*txn, object, identity(), claim.claimId, *key, Uuid::random())),
               StatusCode::kTokenMismatch);
  const auto path = directory.path() / "gc.key";
  auto wrongId = storage::EcGcKey::loadFile(std::filesystem::path(path.string()), Uuid::random(), {});
  ASSERT_OK(wrongId);
  txn = engine->createReadWriteTransaction();
  ASSERT_ERROR(
      blockingWait(EcGcCompletionCatalog::get(*txn, object, identity(), claim.claimId, **wrongId, config.authority)),
      StatusCode::kTokenMismatch);
}

TEST_F(TestEcGcCompletion, MissingUnknownAndThrownMutationNeverBecomeCompletion) {
  ASSERT_OK(seedCommitted());
  model->error = StorageCode::kChunkMetadataNotFound;
  ASSERT_ERROR(blockingWait(coordinator->query(object, identity(), claim.claimId, control())),
               StorageCode::kChunkMetadataNotFound);
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  model->error = StorageCode::kEcSealOutcomeUnknown;
  ASSERT_ERROR(blockingWait(coordinator->query(object, identity(), claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  model->error.reset();
  model->throws = true;
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  auto absent = blockingWait(coordinator->getCompletion(object, identity(), claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
}

TEST_F(TestEcGcCompletion, CommittedButLostCompletionAckIsRecoveredWithoutRedispatch) {
  ASSERT_OK(seedCommitted());
  engine->fault->loseAfter = true;
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(model->calls, 1);
  auto recreated = EcGcCoordinator::create(config, engine, key, model);
  ASSERT_OK(recreated);
  ASSERT_OK(blockingWait((*recreated)->query(object, identity(), claim.claimId, control())));
  EXPECT_EQ(model->calls, 1);
}

TEST_F(TestEcGcCompletion, FailedCompletionCommitLeavesClaimForExplicitQuery) {
  ASSERT_OK(seedCommitted());
  engine->fault->failBefore = true;
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), claim.claimId, control())),
               StorageCode::kEcSealOutcomeUnknown);
  auto absent = blockingWait(coordinator->getCompletion(object, identity(), claim.claimId));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  model->boot = Uuid::random();
  ASSERT_OK(blockingWait(coordinator->query(object, identity(), claim.claimId, control())));
  EXPECT_EQ(model->calls, 2);
  ASSERT_EQ(model->lastRequest->claims.action, storage::EcGcAction::Query);
}

TEST_F(TestEcGcCompletion, OwnedTaskKeepsDependenciesAndFiniteDeadlineStopsDispatch) {
  ASSERT_OK(seedCommitted());
  auto expired = control();
  expired.deadline = std::chrono::steady_clock::now();
  ASSERT_ERROR(blockingWait(coordinator->collect(object, identity(), claim.claimId, expired)),
               StorageClientCode::kTimeout);
  EXPECT_EQ(model->calls, 0);
  auto task = coordinator->collect(object, identity(), claim.claimId, control());
  coordinator.reset();
  ASSERT_OK(blockingWait(std::move(task)));
  EXPECT_EQ(model->calls, 1);
}
}  // namespace
}  // namespace hf3fs::meta::server
