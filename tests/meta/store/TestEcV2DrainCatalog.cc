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
#include "meta/store/EcV2DrainCatalog.h"
#include "meta/store/EcV2LifecycleUtils.h"
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
    auto created =
        run([&](auto &txn) { return EcV2BindingCatalog::createV2Object(txn, object, 64, true, owner, createRequest); });
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
class TestEcV2DrainCatalog : public hf3fs::testing::SetupFDB {
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
TYPED_TEST_SUITE(TestEcV2DrainCatalog, Backends);

TYPED_TEST(TestEcV2DrainCatalog, ReservationFixesInstancesBeforeBindingAndCancelClosesIssuance) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reservation = f.begin(*request);
  ASSERT_OK(reservation);
  auto pool = f.pool;
  pool[0].engineUuid = Uuid::random();
  ASSERT_ERROR(f.run([&](auto &txn) { return Reserve::reserve(txn, reservation->original, f.owner, f.content, pool); }),
               StatusCode::kTokenMismatch);
  auto descriptors = f.descriptors(reservation->original);
  ASSERT_OK(descriptors);
  auto bound =
      f.run([&](auto &txn) { return Reserve::bind(txn, f.object, request->operation, f.owner, *descriptors); });
  ASSERT_OK(bound);
  EXPECT_EQ(bound->allocations[0].engineUuid, f.pool[0].engineUuid);
  const auto revoke = Uuid::random();
  auto closing = f.run(
      [&](auto &txn) { return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, revoke); });
  ASSERT_OK(closing);
  ASSERT_ERROR(f.run([&](auto &txn) {
    return Reserve::checkIssuanceOpen(txn, f.object, Kind::WriteOperation, request->operation, f.owner);
  }),
               StatusCode::kTokenStale);
  ASSERT_ERROR(
      f.run([&](auto &txn) { return Reserve::bind(txn, f.object, request->operation, f.owner, *descriptors); }),
      StatusCode::kTokenStale);
  ASSERT_ERROR(
      f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *this->key); }),
      StatusCode::kTokenStale);
  auto current = f.run([&](auto &txn) { return EcCatalog::getOperation(txn, f.object, request->operation); });
  ASSERT_OK(current);
  EXPECT_EQ(current->state, EcOperationState::Preparing);
}

TYPED_TEST(TestEcV2DrainCatalog, ClosingBeforeBindingStillFixesTwelveEndpointsAndSurvivesLostCommitAck) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reserved = f.begin(*request);
  ASSERT_OK(reserved);
  const auto revoke = Uuid::random();
  auto txn = f.engine->createReadWriteTransaction();
  auto closing = blockingWait(Drain::startCancel(*txn, f.object, request->operation, f.owner, f.authority, revoke));
  ASSERT_OK(closing);
  auto loseAck = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn->commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "lost T0 ACK after actual commit");
  };
  ASSERT_ERROR(blockingWait(loseAck()), TransactionCode::kMaybeCommitted);
  txn.reset();
  const auto retryRevoke = Uuid::random();
  auto retry = f.run([&](auto &next) {
    return Drain::startCancel(next, f.object, request->operation, f.owner, f.authority, retryRevoke);
  });
  ASSERT_OK(retry);
  EXPECT_EQ(retry->identity.revocationId, revoke);
  EXPECT_EQ(retry->identity.endpoints.count, 12);
  EXPECT_EQ(retry->identity.endpoints.digest, reserved->operationEndpoints.digest);
  ASSERT_ERROR(
      f.run([&](auto &next) { return Drain::finishPublish(next, f.object, request->operation, f.owner, *this->key); }),
      StatusCode::kTokenStale);
}

TYPED_TEST(TestEcV2DrainCatalog, ConcurrentBindingCannotCommitAfterClosingAndFailedTxnAddsNoBinding) {
  auto &f = this->fixture;
  auto request = f.intent();
  ASSERT_OK(request);
  auto reserved = f.begin(*request);
  ASSERT_OK(reserved);
  auto descriptors = f.descriptors(reserved->original);
  ASSERT_OK(descriptors);
  auto binder = f.engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(Reserve::bind(*binder, f.object, request->operation, f.owner, *descriptors)));
  const auto revoke = Uuid::random();
  ASSERT_OK(f.run(
      [&](auto &txn) { return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, revoke); }));
  ASSERT_ERROR(blockingWait(binder->commit()), TransactionCode::kConflict);
  binder.reset();
  ASSERT_ERROR(f.run([&](auto &txn) {
    return EcV2BindingCatalog::getOperationBinding(txn, f.object, request->operation, f.owner);
  }),
               StatusCode::kNotImplemented);
  ASSERT_ERROR(f.run([&](auto &txn) {
    return Reserve::checkIssuanceOpen(txn, f.object, Kind::WriteOperation, request->operation, f.owner);
  }),
               StatusCode::kTokenStale);
}

TYPED_TEST(TestEcV2DrainCatalog, ReadClosingPreservesPinAndRejectsOwnerOrFabricatedAck) {
  auto &f = this->fixture;
  auto published = f.publishedFixture();
  ASSERT_OK(published);
  const auto pin = Uuid::random();
  ASSERT_OK(f.run([&](auto &txn) { return EcV2BindingCatalog::acquireRead(txn, f.object, 0, pin, f.owner); }));
  const auto revoke = Uuid::random();
  auto closing = f.run([&](auto &txn) { return Drain::startRead(txn, f.object, pin, f.owner, f.authority, revoke); });
  ASSERT_OK(closing);
  auto other = f.owner;
  other.uid = flat::Uid(999);
  ASSERT_ERROR(f.run([&](auto &txn) { return Drain::finishRead(txn, f.object, pin, other, *this->key); }),
               MetaCode::kNoPermission);
  ASSERT_ERROR(f.run([&](auto &txn) { return Reserve::checkIssuanceOpen(txn, f.object, Kind::ReadPin, pin, f.owner); }),
               StatusCode::kTokenStale);
  auto request = Drain::makeRequest(*closing, 0, storage::EcScopeControlAction::Revoke, *this->key, kNow);
  ASSERT_OK(request);
  storage::EcScopeControlAck fake;
  fake.claims.state = storage::EcScopeControlState::Drained;
  fake.claims.durable = true;
  fake.claims.bootNonce = Uuid::random();
  fake.claims.requestDigest.fill(1);
  fake.claims.revocationDigest.fill(2);
  fake.claims.observedAtSeconds = kNow;
  ASSERT_FALSE(EcVerifiedDrainAck::verify(*this->key, *closing, 0, *request, fake));
  ASSERT_ERROR(f.run([&](auto &txn) { return Drain::finishRead(txn, f.object, pin, f.owner, *this->key); }),
               StatusCode::kTokenStale);
  auto original = f.run([&](auto &txn) { return EcCatalog::getPin(txn, f.object, pin); });
  ASSERT_OK(original);
  EXPECT_FALSE(original->released);
  auto manifest =
      f.run([&](auto &txn) { return EcCatalog::getManifest(txn, f.object, 0, published->candidate.revision); });
  ASSERT_OK(manifest);
  EXPECT_EQ(manifest->pins, 1);
}

TYPED_TEST(TestEcV2DrainCatalog, IssuanceAndClosingSerializeInEitherCommitOrder) {
  auto &f = this->fixture;
  for (bool issuanceFirst : {false, true}) {
    auto request = f.intent();
    ASSERT_OK(request);
    request->stripe = issuanceFirst ? 1 : 0;
    auto digest = computeEcRequestDigest(*request, 64, f.content);
    ASSERT_OK(digest);
    request->requestDigest = *digest;
    auto reserved = f.begin(*request);
    ASSERT_OK(reserved);
    auto issuance = f.engine->createReadWriteTransaction();
    auto closer = f.engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(
        Reserve::checkIssuanceOpen(*issuance, f.object, Kind::WriteOperation, request->operation, f.owner)));
    const auto revoke = Uuid::random();
    ASSERT_OK(blockingWait(Drain::startCancel(*closer, f.object, request->operation, f.owner, f.authority, revoke)));
    ASSERT_OK(blockingWait((issuanceFirst ? issuance : closer)->commit()));
    if (issuanceFirst) {
      ASSERT_OK(blockingWait(closer->commit()));
    } else {
      ASSERT_ERROR(blockingWait(issuance->commit()), TransactionCode::kConflict);
    }
    issuance.reset();
    closer.reset();
    auto count = f.run([&](auto &txn) {
      return ec_v2_lifecycle::readIssuanceSequence(txn, f.object, Kind::WriteOperation, request->operation);
    });
    ASSERT_OK(count);
    EXPECT_EQ(*count, issuanceFirst ? 1u : 0u);
    ASSERT_OK(f.run([&](auto &txn) {
      return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, revoke);
    }));
    ASSERT_ERROR(f.run([&](auto &txn) {
      return Reserve::checkIssuanceOpen(txn, f.object, Kind::WriteOperation, request->operation, f.owner);
    }),
                 StatusCode::kTokenStale);
  }
}

TYPED_TEST(TestEcV2DrainCatalog, IssuanceSequenceActuallyChangesWithoutChangingImmutableBindings) {
  auto &f = this->fixture;
  auto published = f.publishedFixture();
  ASSERT_OK(published);
  const auto pin = Uuid::random();
  ASSERT_OK(f.run([&](auto &txn) { return EcV2BindingCatalog::acquireRead(txn, f.object, 0, pin, f.owner); }));
  auto request = f.intent();
  ASSERT_OK(request);
  request->stripe = 9;
  auto digest = computeEcRequestDigest(*request, 64, f.content);
  ASSERT_OK(digest);
  request->requestDigest = *digest;
  ASSERT_OK(f.begin(*request));
  for (const auto kind : {Kind::ReadPin, Kind::WriteOperation}) {
    const auto scope = kind == Kind::ReadPin ? pin : request->operation;
    std::string bindingKey = kind == Kind::WriteOperation ? ec_v2_lifecycle::reservationKey(f.object, scope)
                                                          : std::string(kv::toStr(kv::KeyPrefix::EcV2Pin)) +
                                                                std::string(f.object.incarnation.asStringView()) +
                                                                std::string(scope.asStringView());
    auto before = f.run([&](auto &txn) { return txn.get(bindingKey); });
    ASSERT_OK(before);
    ASSERT_TRUE(*before);
    for (uint64_t expected = 1; expected != 3; ++expected) {
      ASSERT_OK(f.run([&](auto &txn) { return Reserve::checkIssuanceOpen(txn, f.object, kind, scope, f.owner); }));
      auto sequence =
          f.run([&](auto &txn) { return ec_v2_lifecycle::readIssuanceSequence(txn, f.object, kind, scope); });
      ASSERT_OK(sequence);
      EXPECT_EQ(*sequence, expected);
      auto after = f.run([&](auto &txn) { return txn.get(bindingKey); });
      ASSERT_OK(after);
      EXPECT_EQ(*after, *before);
    }
    ec_v2_lifecycle::IssuanceSequence exhausted;
    exhausted.sequence = std::numeric_limits<uint64_t>::max();
    ASSERT_OK(f.run([&](auto &txn) {
      return ec_v2_lifecycle::save(txn, ec_v2_lifecycle::issuanceKey(f.object, kind, scope), exhausted);
    }));
    ASSERT_ERROR(f.run([&](auto &txn) { return Reserve::checkIssuanceOpen(txn, f.object, kind, scope, f.owner); }),
                 StatusCode::kInvalidArg);
    auto unchanged =
        f.run([&](auto &txn) { return ec_v2_lifecycle::readIssuanceSequence(txn, f.object, kind, scope); });
    ASSERT_OK(unchanged);
    EXPECT_EQ(*unchanged, exhausted.sequence);
    exhausted.sequence = 0;
    ASSERT_OK(f.run([&](auto &txn) {
      return ec_v2_lifecycle::save(txn, ec_v2_lifecycle::issuanceKey(f.object, kind, scope), exhausted);
    }));
    ASSERT_ERROR(f.run([&](auto &txn) { return Reserve::checkIssuanceOpen(txn, f.object, kind, scope, f.owner); }),
                 StatusCode::kDataCorruption);
  }
}

TYPED_TEST(TestEcV2DrainCatalog, ReadIssuanceAndClosingSerializeInEitherCommitOrder) {
  auto &f = this->fixture;
  ASSERT_OK(f.publishedFixture());
  for (const bool issuanceFirst : {false, true}) {
    const auto pin = Uuid::random();
    ASSERT_OK(f.run([&](auto &txn) { return EcV2BindingCatalog::acquireRead(txn, f.object, 0, pin, f.owner); }));
    auto issuer = f.engine->createReadWriteTransaction();
    auto closer = f.engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(Reserve::checkIssuanceOpen(*issuer, f.object, Kind::ReadPin, pin, f.owner)));
    const auto revoke = Uuid::random();
    ASSERT_OK(blockingWait(Drain::startRead(*closer, f.object, pin, f.owner, f.authority, revoke)));
    ASSERT_OK(blockingWait((issuanceFirst ? issuer : closer)->commit()));
    if (issuanceFirst) {
      ASSERT_OK(blockingWait(closer->commit()));
    } else {
      ASSERT_ERROR(blockingWait(issuer->commit()), TransactionCode::kConflict);
    }
    issuer.reset();
    closer.reset();
    auto count =
        f.run([&](auto &txn) { return ec_v2_lifecycle::readIssuanceSequence(txn, f.object, Kind::ReadPin, pin); });
    ASSERT_OK(count);
    EXPECT_EQ(*count, issuanceFirst ? 1u : 0u);
    ASSERT_OK(f.run([&](auto &txn) { return Drain::startRead(txn, f.object, pin, f.owner, f.authority, revoke); }));
    ASSERT_ERROR(
        f.run([&](auto &txn) { return Reserve::checkIssuanceOpen(txn, f.object, Kind::ReadPin, pin, f.owner); }),
        StatusCode::kTokenStale);
  }
}

// This fixture exercises real V2 Rust target identities, durable denies and
// controller-signed ACKs. It invokes the control executor locally, not TCP;
// public Meta/Storage network acceptance belongs to the subsequent RPC batch.
class TestEcV2DrainPersistence : public hf3fs::testing::SetupFDB {
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

TEST_F(TestEcV2DrainPersistence, RealPendingThenAllAckReleaseSurvivesCommitRetryAndEpochAdvance) {
  for (bool fdb : {false, true}) {
    if (fdb && !std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
    CatalogFixture f;
    ASSERT_NO_FATAL_FAILURE(initialize(f, fdb));
    auto published = f.publishedFixture();
    ASSERT_OK(published);
    const auto pin = Uuid::random();
    ASSERT_OK(f.run([&](auto &txn) { return EcV2BindingCatalog::acquireRead(txn, f.object, 0, pin, f.owner); }));
    const auto revoke = Uuid::random();
    auto closing = f.run([&](auto &txn) { return Drain::startRead(txn, f.object, pin, f.owner, f.authority, revoke); });
    ASSERT_OK(closing);
    auto admitted = hold(*closing, 11);
    ASSERT_OK(admitted);
    std::optional<storage::EcScopeTicket> ticket(std::move(*admitted));
    for (size_t i = 0; i != 11; ++i) ASSERT_OK(record(f, *closing, i, storage::EcScopeControlAction::Revoke));
    auto pending = observe(*closing, 11, storage::EcScopeControlAction::Revoke);
    ASSERT_OK(pending);
    ASSERT_EQ(pending->second.claims.state, storage::EcScopeControlState::Pending);
    ASSERT_ERROR(EcVerifiedDrainAck::verify(*key, *closing, 11, pending->first, pending->second),
                 StatusCode::kTokenStale);
    ASSERT_ERROR(f.run([&](auto &txn) { return Drain::finishRead(txn, f.object, pin, f.owner, *key); }),
                 StatusCode::kTokenStale);
    ticket.reset();
    auto observed = observe(*closing, 11, storage::EcScopeControlAction::Query);
    ASSERT_OK(observed);
    ASSERT_FALSE(EcVerifiedDrainAck::verify(*key, *closing, 10, observed->first, observed->second));
    auto forged = observed->second;
    forged.claims.bootNonce.data[0] ^= 1;
    ASSERT_FALSE(EcVerifiedDrainAck::verify(*key, *closing, 11, observed->first, forged));
    auto verified = EcVerifiedDrainAck::verify(*key, *closing, 11, observed->first, observed->second);
    ASSERT_OK(verified);
    ASSERT_OK(f.run([&](auto &txn) { return Drain::recordAck(txn, *verified); }));
    ASSERT_OK(f.run([&](auto &txn) { return Drain::recordAck(txn, *verified); }));
    // An advanced inode epoch stops new publication but is not permission to
    // leak the historical read reference of its authenticated owner forever.
    ASSERT_OK(f.run([&](auto &txn) -> CoTryTask<Void> {
      auto object = co_await EcCatalog::getObject(txn, f.object);
      CO_RETURN_ON_ERROR(object);
      ++object->epoch;
      std::string packed(kv::toStr(kv::KeyPrefix::EcObject));
      packed.append(f.object.incarnation.asStringView());
      const auto bytes = serde::serialize(*object);
      CO_RETURN_ON_ERROR(co_await txn.set(packed, bytes));
      co_return Void{};
    }));
    auto txn = f.engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(Drain::finishRead(*txn, f.object, pin, f.owner, *key)));
    auto loseFinalAck = [&]() -> CoTryTask<Void> {
      CO_RETURN_ON_ERROR(co_await txn->commit());
      co_return makeError(TransactionCode::kMaybeCommitted, "lost T2 ACK after actual commit");
    };
    ASSERT_ERROR(blockingWait(loseFinalAck()), TransactionCode::kMaybeCommitted);
    txn.reset();
    auto retry = f.run([&](auto &next) { return Drain::finishRead(next, f.object, pin, f.owner, *key); });
    ASSERT_OK(retry);
    EXPECT_TRUE(retry->released);
    auto manifest =
        f.run([&](auto &next) { return EcCatalog::getManifest(next, f.object, 0, published->candidate.revision); });
    ASSERT_OK(manifest);
    EXPECT_EQ(manifest->pins, 0);
    control.reset();
  }
}

TEST_F(TestEcV2DrainPersistence, RepairCancellationRequiresEveryOldAndNewInstanceBeforeReleasingImplicitPin) {
  for (bool fdb : {false, true}) {
    if (fdb && !std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
    CatalogFixture f;
    ASSERT_NO_FATAL_FAILURE(initialize(f, fdb));
    auto published = f.publishedFixture();
    ASSERT_OK(published);
    std::copy_n(endpoints.begin() + 12, 12, f.pool.begin());
    auto request = f.intent(published->candidate.revision, kEcAllShards);
    ASSERT_OK(request);
    auto reserved = f.begin(*request);
    ASSERT_OK(reserved);
    ASSERT_EQ(reserved->operationEndpoints.count, 24);
    const auto revoke = Uuid::random();
    auto closing = f.run(
        [&](auto &txn) { return Drain::startCancel(txn, f.object, request->operation, f.owner, f.authority, revoke); });
    ASSERT_OK(closing);
    auto admitted = hold(*closing, 0);
    ASSERT_OK(admitted);
    std::optional<storage::EcScopeTicket> ticket(std::move(*admitted));
    auto pending = observe(*closing, 0, storage::EcScopeControlAction::Revoke);
    ASSERT_OK(pending);
    ASSERT_EQ(pending->second.claims.state, storage::EcScopeControlState::Pending);
    // Draining all twelve candidates (and eleven other sources) is insufficient.
    for (size_t i = 1; i != 24; ++i) ASSERT_OK(record(f, *closing, i, storage::EcScopeControlAction::Revoke));
    ASSERT_ERROR(
        f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *key); }),
        StatusCode::kTokenStale);
    auto base =
        f.run([&](auto &txn) { return EcCatalog::getManifest(txn, f.object, 0, published->candidate.revision); });
    ASSERT_OK(base);
    EXPECT_EQ(base->pins, 1);
    ticket.reset();
    ASSERT_OK(record(f, *closing, 0, storage::EcScopeControlAction::Query));
    auto canceled =
        f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *key); });
    ASSERT_OK(canceled);
    EXPECT_EQ(canceled->state, EcOperationState::Aborted);
    ASSERT_OK(f.run([&](auto &txn) { return Drain::finishCancel(txn, f.object, request->operation, f.owner, *key); }));
    base = f.run([&](auto &txn) { return EcCatalog::getManifest(txn, f.object, 0, published->candidate.revision); });
    ASSERT_OK(base);
    EXPECT_EQ(base->pins, 0);
    for (const auto &fragment : reserved->original.candidate.fragments) {
      auto reference = f.run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, fragment.identity); });
      ASSERT_OK(reference);
      EXPECT_TRUE(reference->gcCandidate);
      EXPECT_EQ(reference->references, 0);
    }
    control.reset();
  }
}
}  // namespace
}  // namespace hf3fs::meta::server
