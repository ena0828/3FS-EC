#include <algorithm>
#include <cstdlib>
#include <folly/experimental/coro/BlockingWait.h>
#include <fstream>
#include <limits>
#include <sys/stat.h>
#include <type_traits>

#include "common/kv/KeyPrefix.h"
#include "common/kv/mem/MemKVEngine.h"
#include "fbs/meta/EcRequestDigest.h"
#include "fdb/FDBKVEngine.h"
#include "meta/store/EcFileTreeGcGuard.h"
#include "meta/store/EcV2GcCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "meta/store/detail/EcFileTreeKeys.h"
#include "storage/ec_codec/EcCodec.h"
#include "storage/ec_scope/EcScopeControlExecutor.h"
#include "storage/store/StorageTargets.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;
using Reserve = EcV2ReservationCatalog;
using Drain = EcV2DrainCatalog;
using Kind = storage::EcGrantScope;
constexpr uint64_t kNow = 1700000000;
static_assert(!std::is_default_constructible_v<EcV2PublishEvidence>);
static_assert(!std::is_constructible_v<EcV2PublishEvidence, EcOperationRecord, EcManifest, storage::EcSha256>);
static_assert(!std::is_default_constructible_v<EcVerifiedDrainAck>);
static_assert(!std::is_constructible_v<EcVerifiedDrainAck, EcV2DrainIdentity, size_t, EcV2DrainObservation>);

Uuid uuid(const std::array<uint8_t, 16> &bytes) {
  Uuid out = Uuid::zero();
  std::copy(bytes.begin(), bytes.end(), std::begin(out.data));
  return out;
}
Result<std::shared_ptr<const storage::EcScopeControlKey>> loadKey(const Path &directory) {
  const auto path = directory / "control.key";
  std::array<uint8_t, 32> bytes{};
  for (size_t i = 0; i != bytes.size(); ++i) bytes[i] = i + 1;
  std::ofstream out(path.string(), std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  out.close();
  if (!out.good() || ::chmod(path.c_str(), 0600) != 0) return makeError(StatusCode::kIOError);
  CHECK_RESULT(key, storage::EcScopeControlKey::loadFile(std::filesystem::path(path.string())));
  return std::shared_ptr<const storage::EcScopeControlKey>(std::move(key));
}

// Metadata fixtures use computed codewords but synthetic read/seal receipts.
// They establish database state, not a V2 publication/drain acceptance claim.
struct CatalogFixture {
  std::unique_ptr<kv::IKVEngine> engine;
  EcObjectRef object{InodeId(1234), Uuid::random()};
  EcOwner owner{flat::Uid(101), Uuid::random()};
  Uuid createRequest = Uuid::random();
  Uuid authority = Uuid::random();
  Reserve::PhysicalPool pool;
  storage::EcCodec::Shards shards;
  storage::EcSha256 content{};
  const std::string logical = std::string(613, 'd');

  auto run(auto fn) {
    auto txn = engine->createReadWriteTransaction();
    auto result = blockingWait(fn(*txn));
    if (result) {
      auto committed = blockingWait(txn->commit());
      if (!committed) return decltype(result)(makeError(committed.error()));
    }
    return result;
  }
  Result<Void> initialize(bool fdb) {
    if (fdb) {
      const auto *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
      if (!cluster) return makeError(StatusCode::kInvalidConfig, "EC_CATALOG_TEST_CLUSTER is unset");
      kv::fdb::DB db(cluster, false);
      if (db.error()) return makeError(StatusCode::kInvalidConfig, "private FDB could not open");
      engine = std::make_unique<kv::FDBKVEngine>(std::move(db));
    } else {
      engine = std::make_unique<kv::MemKVEngine>();
    }
    CHECK_RESULT(codeword, storage::EcCodec::encode(logical, 64));
    shards = std::move(codeword);
    std::array<std::string_view, 10> views;
    for (size_t i = 0; i != 10; ++i) views[i] = shards[i];
    CHECK_RESULT(hash, computeEcLogicalSha256(views, logical.size()));
    content = hash;
    for (size_t i = 0; i != 12; ++i) {
      pool[i] = {{storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(300)},
                 Uuid::random(),
                 Uuid::random()};
    }
    auto created = run([&](auto &txn) {
      return EcV2BindingCatalog::createTrackedV2Object(txn, object, 64, true, owner, createRequest);
    });
    RETURN_ON_ERROR(created);
    return Void{};
  }
  Result<EcMutationIntent> intent(uint64_t revision = 0, uint16_t repair = 0) {
    EcMutationIntent value;
    value.object = object;
    value.operation = Uuid::random();
    value.expectedEpoch = 1;
    value.expectedRevision = revision;
    value.logicalLength = logical.size();
    value.kind = repair ? EcMutationKind::Repair : EcMutationKind::Write;
    value.replacementMask = repair ? repair : kEcAllShards;
    for (size_t i = 0; i != 12; ++i) {
      value.placements[i] = pool[i].placement;
      storage::EcFragmentIdentity identity;
      identity.object = object.incarnation;
      identity.generation = 1;
      identity.shard = i;
      identity.allocation = Uuid::random();
      CHECK_RESULT(integrity, storage::computeEcIntegrity(identity, shards[i]));
      value.fragmentCrc32c[i] = integrity.wholeCrc32c;
    }
    CHECK_RESULT(digest, computeEcRequestDigest(value, 64, content));
    value.requestDigest = digest;
    return value;
  }
  Result<EcV2Reservation> begin(const EcMutationIntent &request) {
    return run([&](auto &txn) -> CoTryTask<EcV2Reservation> {
      auto op = co_await EcCatalog::begin(txn, request, owner);
      CO_RETURN_ON_ERROR(op);
      co_return co_await Reserve::reserve(txn, *op, owner, content, pool);
    });
  }
  Result<std::array<storage::EcIntegrityDescriptor, 12>> descriptors(const EcOperationRecord &op) {
    std::array<storage::EcIntegrityDescriptor, 12> result;
    for (size_t i = 0; i != 12; ++i) {
      CHECK_RESULT(value, storage::computeEcIntegrity(op.candidate.fragments[i].identity, shards[i]));
      result[i] = value;
    }
    return result;
  }
  Result<EcOperationRecord> publishedFixture() {
    CHECK_RESULT(request, intent());
    CHECK_RESULT(reserved, begin(request));
    CHECK_RESULT(integrities, descriptors(reserved.original));
    CHECK_RESULT(bound,
                 run([&](auto &txn) { return Reserve::bind(txn, object, request.operation, owner, integrities); }));
    auto manifest = reserved.original.candidate;
    std::array<storage::EcReadResult, 12> reads;
    std::array<storage::EcFragmentReceipt, 12> seals;
    for (size_t i = 0; i != 12; ++i) {
      manifest.fragments[i] = bound.allocations[i].fragment;
      const auto &fragment = manifest.fragments[i];
      auto &read = reads[i];
      read.payload.data = shards[i];
      read.receipt.identity = fragment.identity;
      read.receipt.operationId = fragment.operation;
      read.receipt.vChainId = {fragment.placement.chain, storage::ChainVer(3)};
      read.receipt.targetId = fragment.placement.target;
      read.receipt.length = 64;
      read.receipt.checksum = {storage::ChecksumType::CRC32C, ~fragment.integrity.wholeCrc32c};
      seals[i] = read.receipt;
    }
    CHECK_RESULT(proof, EcVerifiedManifest::fromStorageResponses(manifest, reads, seals));
    return run([&](auto &txn) { return EcCatalog::publish(txn, object, request.operation, proof); });
  }
};

template <typename UseFDB>
class TestEcV2GcCatalog : public hf3fs::testing::SetupFDB {
 protected:
  void SetUp() override {
    if constexpr (UseFDB::value) {
      if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
    }
    ASSERT_OK(fixture.initialize(UseFDB::value));
    auto loaded = loadKey(keys.path());
    ASSERT_OK(loaded);
    key = *loaded;
  }
  CatalogFixture fixture;
  folly::test::TemporaryDirectory keys;
  std::shared_ptr<const storage::EcScopeControlKey> key;
};
using Backends = ::testing::Types<std::false_type, std::true_type>;
TYPED_TEST_SUITE(TestEcV2GcCatalog, Backends);

TYPED_TEST(TestEcV2GcCatalog, FreshEnrollmentIsAtomicAndOldModeNeverUpgrades) {
  auto &f = this->fixture;
  auto mode = f.run([&](auto &txn) { return EcV2BindingCatalog::requireV2Mode(txn, f.object); });
  ASSERT_OK(mode);
  EXPECT_EQ(mode->mode, kEcGcTrackedObjectMode);
  EcObjectRef old{InodeId(1235), Uuid::random()};
  const auto create = Uuid::random();
  ASSERT_OK(f.run([&](auto &txn) { return EcV2BindingCatalog::createV2Object(txn, old, 64, true, f.owner, create); }));
  ASSERT_OK(
      f.run([&](auto &txn) { return EcV2BindingCatalog::createTrackedV2Object(txn, old, 64, true, f.owner, create); }));
  mode = f.run([&](auto &txn) { return EcV2BindingCatalog::requireV2Mode(txn, old); });
  ASSERT_OK(mode);
  EXPECT_EQ(mode->mode, 2);
  storage::EcFragmentIdentity identity;
  identity.object = old.incarnation;
  identity.generation = 1;
  identity.allocation = Uuid::random();
  ASSERT_ERROR(f.run([&](auto &txn) { return EcV2GcCatalog::getClaim(txn, old, identity); }),
               StatusCode::kNotImplemented);

  EcObjectRef rolledBack{InodeId(1236), Uuid::random()};
  auto transaction = f.engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(
      EcV2BindingCatalog::createTrackedV2Object(*transaction, rolledBack, 64, true, f.owner, Uuid::random())));
  transaction.reset();
  auto absent = f.run([&](auto &txn) { return EcV2BindingCatalog::getObjectMode(txn, rolledBack); });
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
  std::string key(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  key.append(rolledBack.incarnation.asStringView());
  auto check = f.engine->createReadWriteTransaction();
  auto birth = blockingWait(check->get(key));
  ASSERT_OK(birth);
  EXPECT_FALSE(*birth);
}

TYPED_TEST(TestEcV2GcCatalog, ReservationProtectsEveryCandidateOnceBeforeBinding) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reserved = f.begin(*request);
  ASSERT_OK(reserved);
  ASSERT_OK(f.begin(*request));
  for (const auto &fragment : reserved->original.candidate.fragments) {
    auto value = f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, fragment.identity); });
    ASSERT_OK(value);
    EXPECT_EQ(value->active, 1);
    EXPECT_EQ(value->registered, 1);
    EXPECT_EQ(value->released, 0);
    ASSERT_ERROR(f.run([&](auto &txn) {
      return EcV2GcCatalog::claim(txn, f.object, fragment.identity, Uuid::random(), *this->key);
    }),
                 StatusCode::kTokenStale);
  }
  ASSERT_OK(f.run([&](auto &txn) {
    return Reserve::checkIssuanceOpen(txn, f.object, Kind::WriteOperation, request->operation, f.owner);
  }));
}

TYPED_TEST(TestEcV2GcCatalog, MissingHistoryNeverDefaultsToZeroOrPermitsIssuance) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reserved = f.begin(*request);
  ASSERT_OK(reserved);
  auto identity = reserved->candidates[0].identity;
  auto chunk = identity.chunkId();
  ASSERT_OK(chunk);
  std::string key(kv::toStr(kv::KeyPrefix::EcGcAllocation));
  key.append(chunk->data());
  auto corrupt = f.engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(corrupt->clear(key)));
  ASSERT_OK(blockingWait(corrupt->commit()));
  ASSERT_ERROR(f.run([&](auto &txn) {
    return Reserve::checkIssuanceOpen(txn, f.object, Kind::WriteOperation, request->operation, f.owner);
  }),
               StatusCode::kDataCorruption);
  ASSERT_ERROR(f.run([&](auto &txn) { return EcV2GcCatalog::getClaim(txn, f.object, identity); }),
               StatusCode::kDataCorruption);
  ASSERT_ERROR(f.begin(*request), StatusCode::kDataCorruption);
}

TYPED_TEST(TestEcV2GcCatalog, LostEnrollmentCannotBeRecreatedFromEmptyCounters) {
  auto &f = this->fixture;
  std::string key(kv::toStr(kv::KeyPrefix::EcGcEnrollment));
  key.append(f.object.incarnation.asStringView());
  auto transaction = f.engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(transaction->clear(key)));
  ASSERT_OK(blockingWait(transaction->commit()));
  ASSERT_ERROR(f.run([&](auto &txn) {
    return EcV2BindingCatalog::createTrackedV2Object(txn, f.object, 64, true, f.owner, f.createRequest);
  }),
               StatusCode::kDataCorruption);
}

TYPED_TEST(TestEcV2GcCatalog, RepairProtectsEntireBaseAndCandidatesAndReadAddsSeparateProtection) {
  auto &f = this->fixture;
  // Synthetic publication only establishes reference state; the original
  // write protection intentionally remains active because there was no T2.
  auto published = f.publishedFixture();
  ASSERT_OK(published);
  auto request = f.intent(published->candidate.revision, 1u << 0);
  ASSERT_OK(request);
  auto repair = f.begin(*request);
  ASSERT_OK(repair);
  auto read =
      f.run([&](auto &txn) { return EcV2BindingCatalog::acquireRead(txn, f.object, 0, Uuid::random(), f.owner); });
  ASSERT_OK(read);
  for (const auto &fragment : published->candidate.fragments) {
    auto value = f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, fragment.identity); });
    ASSERT_OK(value);
    EXPECT_EQ(value->active, 3);  // original write, entire repair base, read pin
  }
  auto replacement =
      f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, repair->candidates[0].identity); });
  ASSERT_OK(replacement);
  EXPECT_EQ(replacement->active, 1);
  ASSERT_ERROR(f.run([&](auto &txn) {
    return EcV2GcCatalog::finishScope(txn, f.object, Kind::ReadPin, read->snapshot.pin, f.owner, *this->key);
  }),
               StatusCode::kTokenStale);
}

TYPED_TEST(TestEcV2GcCatalog, IssuanceClosingConflictCannotEscapeTrackedProtection) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reserved = f.begin(*request);
  ASSERT_OK(reserved);
  auto issuer = f.engine->createReadWriteTransaction();
  ASSERT_OK(
      blockingWait(Reserve::checkIssuanceOpen(*issuer, f.object, Kind::WriteOperation, request->operation, f.owner)));
  ASSERT_OK(f.run([&](auto &txn) {
    return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, Uuid::random());
  }));
  ASSERT_ERROR(blockingWait(issuer->commit()), TransactionCode::kConflict);
  auto value =
      f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, reserved->candidates[0].identity); });
  ASSERT_OK(value);
  EXPECT_EQ(value->active, 1);
}
// This fixture exercises real V2 Rust target identities, durable denies and
// controller-signed ACKs. It invokes the control executor locally, not TCP;
// public Meta/Storage network acceptance belongs to the subsequent RPC batch.
class TestEcGcDrainPersistence : public hf3fs::testing::SetupFDB {
 protected:
  void SetUp() override {
    auto loaded = loadKey(keys.path());
    ASSERT_OK(loaded);
    key = *loaded;
    config.set_target_paths({directory.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    targets = std::make_unique<storage::StorageTargets>(config, map);
    ASSERT_OK(targets->load(cpu));
    for (size_t i = 0; i != physical.size(); ++i) {
      storage::CreateTargetReq request;
      request.chainId = storage::ChainId(100 + i);
      request.targetId = storage::TargetId(200 + i);
      request.onlyChunkEngine = true;
      ASSERT_OK(targets->create(request, true));
      auto found = map.getByTargetId(request.targetId);
      ASSERT_OK(found);
      physical[i] = (*found)->storageTarget;
      auto state = physical[i]->ecScopeState();
      ASSERT_OK(state);
      endpoints[i] = {{request.chainId, request.targetId, flat::NodeId(300)},
                      uuid(state->second.engine),
                      uuid(state->second.incarnation)};
    }
  }
  void TearDown() override {
    control.reset();
    for (auto &target : physical) target.reset();
    map.release().reset();
    targets.reset();
    key.reset();
  }
  void initialize(CatalogFixture &f, bool fdb) {
    ASSERT_OK(f.initialize(fdb));
    std::copy_n(endpoints.begin(), 12, f.pool.begin());
    auto opened = storage::EcScopeControlExecutor::create(key, f.authority, flat::NodeId(300), [] { return kNow + 1; });
    ASSERT_OK(opened);
    control = std::move(*opened);
  }
  Result<storage::EcScopeTicket> hold(const EcV2DrainRecord &record, size_t index) {
    const auto &endpoint = record.identity.endpoints.endpoints[index];
    CHECK_RESULT(target, map.getByTargetId(endpoint.placement.target));
    CHECK_RESULT(state, target->storageTarget->ecScopeState());
    storage::EcScopeBinding binding{};
    binding.target = state.second;
    std::copy(std::begin(record.identity.object.incarnation.data),
              std::end(record.identity.object.incarnation.data),
              binding.object.begin());
    binding.kind = static_cast<uint8_t>(record.identity.kind);
    std::copy(std::begin(record.identity.scopeId.data), std::end(record.identity.scopeId.data), binding.scope.begin());
    binding.owner_uid = record.identity.owner.uid;
    std::copy(std::begin(record.identity.owner.client.data),
              std::end(record.identity.owner.client.data),
              binding.client_namespace.begin());
    RETURN_ON_ERROR(state.first->prepare(binding));
    return state.first->tryAdmit(binding);
  }
  Result<std::pair<storage::EcScopeControlRequest, storage::EcScopeControlAck>>
  observe(const EcV2DrainRecord &record, size_t index, storage::EcScopeControlAction action) {
    CHECK_RESULT(request, Drain::makeRequest(record, index, action, *key, kNow));
    CHECK_RESULT(target, map.getByTargetId(request.claims.targetId));
    CHECK_RESULT(ack, blockingWait(control->execute(action, request, target->storageTarget)));
    return std::pair{std::move(request), std::move(ack)};
  }
  Result<EcV2DrainRecord> record(CatalogFixture &f,
                                 const EcV2DrainRecord &snapshot,
                                 size_t index,
                                 storage::EcScopeControlAction action) {
    CHECK_RESULT(observation, observe(snapshot, index, action));
    CHECK_RESULT(verified, EcVerifiedDrainAck::verify(*key, snapshot, index, observation.first, observation.second));
    return f.run([&](auto &txn) { return Drain::recordAck(txn, verified); });
  }
  folly::test::TemporaryDirectory directory, keys;
  CPUExecutorGroup cpu{1, "EcMetaDrainTest"};
  storage::StorageTargets::Config config;
  storage::AtomicallyTargetMap map;
  std::unique_ptr<storage::StorageTargets> targets;
  std::array<std::shared_ptr<storage::StorageTarget>, 24> physical;
  std::array<EcV2PhysicalEndpoint, 24> endpoints;
  std::shared_ptr<const storage::EcScopeControlKey> key;
  std::unique_ptr<storage::EcScopeControlExecutor> control;
};

TEST_F(TestEcGcDrainPersistence, ExactClaimRequiresAllAckT2AndSurvivesUnknownCommitWithoutDoubleRelease) {
  for (bool fdb : {false, true}) {
    if (fdb && !std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
    CatalogFixture f;
    ASSERT_NO_FATAL_FAILURE(initialize(f, fdb));
    auto request = f.intent();
    ASSERT_OK(request);
    auto reserved = f.begin(*request);
    ASSERT_OK(reserved);
    auto descriptors = f.descriptors(reserved->original);
    ASSERT_OK(descriptors);
    ASSERT_OK(
        f.run([&](auto &txn) { return Reserve::bind(txn, f.object, request->operation, f.owner, *descriptors); }));
    auto closing = f.run([&](auto &txn) {
      return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, Uuid::random());
    });
    ASSERT_OK(closing);
    for (size_t i = 0; i != 11; ++i) ASSERT_OK(record(f, *closing, i, storage::EcScopeControlAction::Revoke));
    ASSERT_ERROR(
        f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *key); }),
        StatusCode::kTokenStale);
    auto before =
        f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, reserved->candidates[0].identity); });
    ASSERT_OK(before);
    EXPECT_EQ(before->active, 1);
    ASSERT_OK(record(f, *closing, 11, storage::EcScopeControlAction::Revoke));
    auto txn = f.engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(Drain::finishCancel(*txn, f.object, request->operation, f.owner, *key)));
    auto lostT2 = [&]() -> CoTryTask<Void> {
      CO_RETURN_ON_ERROR(co_await txn->commit());
      co_return makeError(TransactionCode::kMaybeCommitted, "test loses acknowledgement after real T2 commit");
    };
    ASSERT_ERROR(blockingWait(lostT2()), TransactionCode::kMaybeCommitted);
    txn.reset();
    ASSERT_OK(
        f.run([&](auto &next) { return Drain::finishCancel(next, f.object, request->operation, f.owner, *key); }));
    const auto &identity = reserved->candidates[0].identity;
    auto after = f.run([&](auto &next) { return EcV2GcCatalog::getAllocation(next, f.object, identity); });
    ASSERT_OK(after);
    EXPECT_EQ(after->active, 0);
    EXPECT_EQ(after->registered, 1);
    EXPECT_EQ(after->released, 1);
    const auto claimId = Uuid::random();
    // Extra tree-hold invariant at the actual mode-3 G0 entry, including its
    // private-FDB run. Deliberately injected metadata is not a mode-4 publisher.
    auto holdKey = ec_tree_detail::allocationKey(kv::KeyPrefix::EcTreeAllocationHold, identity);
    ASSERT_OK(holdKey);
    EcTreeAllocationHolds hold;
    hold.object = f.object;
    hold.identity = identity;
    hold.holds = 1;
    ASSERT_OK(f.run([&](auto &next) { return ec_tree_detail::store(next, *holdKey, hold); }));
    ASSERT_ERROR(f.run([&](auto &next) { return EcV2GcCatalog::claim(next, f.object, identity, claimId, *key); }),
                 StatusCode::kTokenStale);
    hold.holds = 0;
    ASSERT_OK(f.run([&](auto &next) { return ec_tree_detail::store(next, *holdKey, hold); }));
    txn = f.engine->createReadWriteTransaction();
    auto claimed = blockingWait(EcV2GcCatalog::claim(*txn, f.object, identity, claimId, *key));
    ASSERT_OK(claimed);
    auto competitor = f.engine->createReadWriteTransaction();
    const auto competingId = Uuid::random();
    ASSERT_OK(blockingWait(EcV2GcCatalog::claim(*competitor, f.object, identity, competingId, *key)));
    auto lostClaim = [&]() -> CoTryTask<Void> {
      CO_RETURN_ON_ERROR(co_await txn->commit());
      co_return makeError(TransactionCode::kMaybeCommitted, "test loses acknowledgement after real claim commit");
    };
    ASSERT_ERROR(blockingWait(lostClaim()), TransactionCode::kMaybeCommitted);
    ASSERT_ERROR(blockingWait(competitor->commit()), TransactionCode::kConflict);
    txn.reset();
    competitor.reset();
    auto retry = f.run([&](auto &next) { return EcV2GcCatalog::claim(next, f.object, identity, claimId, *key); });
    ASSERT_OK(retry);
    EXPECT_TRUE(ec_v2_lifecycle::same(*claimed, *retry));
    EXPECT_EQ(retry->allocation.fragment.operation, request->operation);
    EXPECT_EQ(retry->allocation.engineUuid, f.pool[0].engineUuid);
    EXPECT_EQ(retry->allocation.targetIncarnation, f.pool[0].targetIncarnation);
    EXPECT_EQ(retry->allocation.fragment.integrity, (*descriptors)[0]);
    EXPECT_NE(retry->eligibilityDigest, storage::EcSha256{});
    ASSERT_ERROR(f.run([&](auto &next) { return EcV2GcCatalog::claim(next, f.object, identity, competingId, *key); }),
                 StatusCode::kTokenMismatch);
    ASSERT_ERROR(f.run([&](auto &next) { return EcV2GcCatalog::protectOperation(next, *reserved); }),
                 StatusCode::kTokenMismatch);
    // Even terminal T2 replay after claim does not increment/decrement again.
    ASSERT_OK(
        f.run([&](auto &next) { return Drain::finishCancel(next, f.object, request->operation, f.owner, *key); }));
    after = f.run([&](auto &next) { return EcV2GcCatalog::getAllocation(next, f.object, identity); });
    ASSERT_OK(after);
    EXPECT_EQ(after->released, 1);
    EXPECT_EQ(after->claimId, claimId);
    control.reset();
  }
}

TEST_F(TestEcGcDrainPersistence, UnboundCanceledAllocationCannotBecomeADeletionClaim) {
  for (bool fdb : {false, true}) {
    if (fdb && !std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
    CatalogFixture f;
    ASSERT_NO_FATAL_FAILURE(initialize(f, fdb));
    auto request = f.intent();
    ASSERT_OK(request);
    auto reserved = f.begin(*request);
    ASSERT_OK(reserved);
    auto closing = f.run([&](auto &txn) {
      return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, Uuid::random());
    });
    ASSERT_OK(closing);
    for (size_t i = 0; i != 12; ++i) ASSERT_OK(record(f, *closing, i, storage::EcScopeControlAction::Revoke));
    ASSERT_OK(f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *key); }));
    auto &identity = reserved->candidates[0].identity;
    auto status = f.run([&](auto &txn) { return EcV2GcCatalog::getAllocation(txn, f.object, identity); });
    ASSERT_OK(status);
    EXPECT_EQ(status->active, 0);
    ASSERT_ERROR(f.run([&](auto &txn) { return EcV2GcCatalog::claim(txn, f.object, identity, Uuid::random(), *key); }),
                 StatusCode::kNotImplemented);
    auto absent = f.run([&](auto &txn) { return EcV2GcCatalog::getClaim(txn, f.object, identity); });
    ASSERT_OK(absent);
    EXPECT_FALSE(*absent);
    control.reset();
  }
}
}  // namespace
}  // namespace hf3fs::meta::server
