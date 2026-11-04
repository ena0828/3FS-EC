#include <algorithm>
#include <cstdlib>
#include <folly/experimental/coro/BlockingWait.h>

#include "common/kv/KeyPrefix.h"
#include "common/kv/mem/MemKVEngine.h"
#include "fdb/FDBKVEngine.h"
#include "meta/store/EcV2BindingCatalog.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;
using Bindings = EcV2BindingCatalog;

std::string objectKey(kv::KeyPrefix prefix, const EcObjectRef &object) {
  std::string key(kv::toStr(prefix));
  key.append(object.incarnation.asStringView());
  return key;
}
std::string allocationKey(const storage::EcFragmentIdentity &identity) {
  auto chunk = identity.chunkId();
  if (!chunk) std::terminate();
  std::string key(kv::toStr(kv::KeyPrefix::EcV2Allocation));
  key.append(chunk->data());
  return key;
}

// Real MemKV/FDB transaction semantics, not Storage/RPC acceptance. Physical
// registration inputs and storage receipts below are synthetic fixture data.
// Fresh object incarnations avoid deleting any pre-existing database records.
template <typename UseFDB>
class TestEcV2BindingCatalog : public hf3fs::testing::SetupFDB {
 protected:
  void SetUp() override {
    if constexpr (UseFDB::value) {
      const auto *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
      if (!cluster) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
      kv::fdb::DB db(cluster, false);
      ASSERT_FALSE(db.error());
      engine = std::make_unique<kv::FDBKVEngine>(std::move(db));
    } else {
      engine = std::make_unique<kv::MemKVEngine>();
    }
    object = {InodeId(1234), Uuid::random()};
    owner = {flat::Uid(100), Uuid::random()};
    createRequest = Uuid::random();
    ASSERT_OK(run([&](auto &txn) { return Bindings::createV2Object(txn, object, 64, false, owner, createRequest); }));
  }

  auto run(auto fn) {
    auto txn = engine->createReadWriteTransaction();
    auto result = blockingWait(fn(*txn));
    if (result) {
      auto committed = blockingWait(txn->commit());
      if (!committed) return decltype(result)(makeError(committed.error()));
    }
    // Any failed operation discards all tentative pin/reference mutations.
    return result;
  }

  std::string data(size_t shard) { return std::string(64, static_cast<char>('a' + shard)); }
  EcMutationIntent intent(uint64_t revision = 0, uint16_t repairMask = 0) {
    EcMutationIntent value;
    value.object = object;
    value.operation = Uuid::random();
    value.requestDigest.back() = 1;  // Synthetic canonical-intent hash for KV tests only.
    value.expectedEpoch = 1;
    value.expectedRevision = revision;
    value.logicalLength = 613;
    value.kind = repairMask ? EcMutationKind::Repair : EcMutationKind::Write;
    value.replacementMask = repairMask ? repairMask : kEcAllShards;
    for (size_t i = 0; i != 12; ++i) {
      value.placements[i] = {storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(300 + i)};
      storage::EcFragmentIdentity identity;
      identity.object = object.incarnation;
      identity.generation = 1;
      identity.shard = i;
      identity.allocation = Uuid::random();
      auto integrity = storage::computeEcIntegrity(identity, data(i));
      if (!integrity) std::terminate();
      value.fragmentCrc32c[i] = integrity->wholeCrc32c;
    }
    return value;
  }
  Result<EcOperationRecord> begin(const EcMutationIntent &intent) {
    return run([&](auto &txn) { return EcCatalog::begin(txn, intent, owner); });
  }
  Result<EcV2AllocationBindings> allocations(const EcOperationRecord &op) {
    EcV2AllocationBindings values;
    for (size_t i = 0; i != 12; ++i) {
      if (!(op.intent.replacementMask & (1u << i))) {
        CHECK_RESULT(old, run([&](auto &txn) {
                       return Bindings::getAllocationBinding(txn, op.candidate.fragments[i].identity);
                     }));
        values[i] = old;
        continue;
      }
      auto &value = values[i];
      value.object = object;
      value.fragment = op.candidate.fragments[i];
      CHECK_RESULT(integrity, storage::computeEcIntegrity(value.fragment.identity, data(i)));
      value.fragment.integrity = integrity;
      value.engineUuid = Uuid::random();
      value.targetIncarnation = Uuid::random();
      value.writer = op.owner;
    }
    return values;
  }
  Result<EcV2OperationBinding> bind(const EcOperationRecord &op, const EcV2AllocationBindings &values) {
    return run([&](auto &txn) { return Bindings::bindPreparing(txn, op, owner, values); });
  }
  Result<EcVerifiedManifest> proof(EcManifest manifest, const EcV2AllocationBindings &values) {
    std::array<storage::EcReadResult, 12> reads;
    std::array<storage::EcFragmentReceipt, 12> receipts;
    for (size_t i = 0; i != 12; ++i) {
      manifest.fragments[i] = values[i].fragment;
      const auto &fragment = manifest.fragments[i];
      auto &read = reads[i];
      read.payload.data = data(i);
      read.receipt.identity = fragment.identity;
      read.receipt.operationId = fragment.operation;
      read.receipt.vChainId = {fragment.placement.chain, storage::ChainVer(3)};
      read.receipt.targetId = fragment.placement.target;
      read.receipt.length = 64;
      read.receipt.checksum = {storage::ChecksumType::CRC32C, ~fragment.integrity.wholeCrc32c};
      receipts[i] = read.receipt;
    }
    return EcVerifiedManifest::fromStorageResponses(std::move(manifest), reads, receipts);
  }
  Result<EcOperationRecord> publishWrite(const EcMutationIntent &request) {
    CHECK_RESULT(op, begin(request));
    CHECK_RESULT(values, allocations(op));
    CHECK_RESULT(bound, bind(op, values));
    (void)bound;
    CHECK_RESULT(verified, proof(op.candidate, values));
    // Setup only: public V2 publication must first durably revoke/drain the
    // operation set. This fixture cannot prove that distributed protocol.
    return run([&](auto &txn) { return EcCatalog::publish(txn, object, request.operation, verified); });
  }

  std::unique_ptr<kv::IKVEngine> engine;
  EcObjectRef object;
  EcOwner owner;
  Uuid createRequest;
};

using BindingBackends = ::testing::Types<std::false_type, std::true_type>;
TYPED_TEST_SUITE(TestEcV2BindingCatalog, BindingBackends);

TYPED_TEST(TestEcV2BindingCatalog, ObjectModeCreationIsAtomicIdempotentAndCannotUpgradeV1) {
  auto mode = this->run([&](auto &txn) { return Bindings::requireV2Mode(txn, this->object); });
  ASSERT_OK(mode);
  ASSERT_EQ(mode->mode, 2);
  ASSERT_OK(this->run([&](auto &txn) {
    return Bindings::createV2Object(txn, this->object, 64, false, this->owner, this->createRequest);
  }));
  ASSERT_ERROR(this->run([&](auto &txn) {
    return Bindings::createV2Object(txn, this->object, 65, false, this->owner, this->createRequest);
  }),
               StatusCode::kTokenMismatch);
  auto unmarked = this->object;
  unmarked.incarnation = Uuid::random();
  ASSERT_OK(this->run(
      [&](auto &txn) { return EcCatalog::createObject(txn, unmarked, 64, false, this->owner, this->createRequest); }));
  ASSERT_ERROR(this->run([&](auto &txn) {
    return Bindings::createV2Object(txn, unmarked, 64, false, this->owner, this->createRequest);
  }),
               StatusCode::kNotImplemented);
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::requireV2Mode(txn, unmarked); }),
               StatusCode::kNotImplemented);
  const auto unmarkedPin = Uuid::random();
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::acquireRead(txn, unmarked, 0, unmarkedPin, this->owner); }),
               StatusCode::kNotImplemented);

  auto aborted = unmarked;
  aborted.incarnation = Uuid::random();
  auto txn = this->engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(Bindings::createV2Object(*txn, aborted, 64, false, this->owner, Uuid::random())));
  txn.reset();
  ASSERT_ERROR(this->run([&](auto &next) { return EcCatalog::getObject(next, aborted); }),
               StatusCode::kKVStoreNotFound);
  auto absent = this->run([&](auto &next) { return Bindings::getObjectMode(next, aborted); });
  ASSERT_OK(absent);
  ASSERT_FALSE(absent->has_value());
}

TYPED_TEST(TestEcV2BindingCatalog, LostCommitAcknowledgementReplaysExactBindingWithoutReallocation) {
  auto op = this->begin(this->intent());
  ASSERT_OK(op);
  auto values = this->allocations(*op);
  ASSERT_OK(values);
  auto txn = this->engine->createReadWriteTransaction();
  auto bound = blockingWait(Bindings::bindPreparing(*txn, *op, this->owner, *values));
  ASSERT_OK(bound);
  auto loseAcknowledgement = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn->commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "injected lost bind commit acknowledgement");
  };
  ASSERT_ERROR(blockingWait(loseAcknowledgement()), TransactionCode::kMaybeCommitted);
  txn.reset();
  auto replay = this->bind(*op, *values);
  ASSERT_OK(replay);
  ASSERT_EQ(replay->allocations, bound->allocations);
  ASSERT_EQ(replay->operationEndpoints.count, 12);
  auto object = this->run([&](auto &next) { return EcCatalog::getObject(next, this->object); });
  ASSERT_OK(object);
  ASSERT_EQ(object->nextGeneration, op->candidate.generation + 1);
  ASSERT_EQ(object->nextRevision, op->candidate.revision + 1);
  auto loaded = this->run(
      [&](auto &next) { return Bindings::getOperationBinding(next, this->object, op->intent.operation, this->owner); });
  ASSERT_OK(loaded);
  ASSERT_EQ(loaded->allocations, *values);
  auto changed = *values;
  changed[3].targetIncarnation = Uuid::random();
  ASSERT_ERROR(this->bind(*op, changed), StatusCode::kTokenMismatch);
}

TYPED_TEST(TestEcV2BindingCatalog, OwnerFixedReservationLengthCrcAndIntegrityAreRequired) {
  auto op = this->begin(this->intent());
  ASSERT_OK(op);
  auto values = this->allocations(*op);
  ASSERT_OK(values);
  auto other = this->owner;
  other.uid = flat::Uid(101);
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::bindPreparing(txn, *op, other, *values); }),
               MetaCode::kNoPermission);
  other = this->owner;
  other.client = Uuid::random();
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::bindPreparing(txn, *op, other, *values); }),
               MetaCode::kNoPermission);
  auto expected = *op;
  ++expected.candidate.generation;
  ASSERT_ERROR(this->bind(expected, *values), StatusCode::kTokenMismatch);
  expected = *op;
  expected.intent.requestDigest[0] ^= 1;
  ASSERT_ERROR(this->bind(expected, *values), StatusCode::kTokenMismatch);
  auto wrong = *values;
  wrong[0].writer.uid = flat::Uid(102);
  ASSERT_ERROR(this->bind(*op, wrong), StatusCode::kTokenMismatch);
  wrong = *values;
  auto different = storage::computeEcIntegrity(wrong[0].fragment.identity, std::string(64, 'z'));
  ASSERT_OK(different);
  wrong[0].fragment.integrity = *different;
  ASSERT_ERROR(this->bind(*op, wrong), StatusCode::kTokenMismatch);
  auto shortData = storage::computeEcIntegrity(wrong[0].fragment.identity, std::string(63, 'a'));
  ASSERT_OK(shortData);
  wrong[0].fragment.integrity = *shortData;
  ASSERT_ERROR(this->bind(*op, wrong), StatusCode::kTokenMismatch);
  wrong = *values;
  wrong[0].fragment.integrity.root[0] ^= 1;
  ASSERT_FALSE(this->bind(*op, wrong));
  wrong = *values;
  wrong[0].engineUuid = Uuid::zero();
  ASSERT_ERROR(this->bind(*op, wrong), StatusCode::kInvalidArg);
  ASSERT_ERROR(
      this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, values->at(0).fragment.identity); }),
      StatusCode::kNotImplemented);
  ASSERT_OK(this->bind(*op, *values));
}

TYPED_TEST(TestEcV2BindingCatalog, ConcurrentBindingsConflictAndCannotChangePhysicalInstance) {
  auto op = this->begin(this->intent());
  ASSERT_OK(op);
  auto first = this->allocations(*op);
  ASSERT_OK(first);
  auto second = *first;
  second[0].engineUuid = Uuid::random();
  auto a = this->engine->createReadWriteTransaction();
  auto b = this->engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(Bindings::bindPreparing(*a, *op, this->owner, *first)));
  ASSERT_OK(blockingWait(Bindings::bindPreparing(*b, *op, this->owner, second)));
  ASSERT_OK(blockingWait(a->commit()));
  ASSERT_ERROR(blockingWait(b->commit()), TransactionCode::kConflict);
  b.reset();
  ASSERT_ERROR(this->bind(*op, second), StatusCode::kTokenMismatch);
  ASSERT_OK(this->bind(*op, *first));
}

TYPED_TEST(TestEcV2BindingCatalog, ConcurrentCancellationAndEpochChangeFencePreparingBinding) {
  for (bool epochChange : {false, true}) {
    auto request = this->intent();
    request.stripe = epochChange ? 1 : 0;
    auto op = this->begin(request);
    ASSERT_OK(op);
    auto values = this->allocations(*op);
    ASSERT_OK(values);
    auto binder = this->engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(Bindings::bindPreparing(*binder, *op, this->owner, *values)));
    if (epochChange) {
      ASSERT_OK(this->run([&](auto &txn) -> CoTryTask<Void> {
        auto object = co_await EcCatalog::getObject(txn, this->object);
        CO_RETURN_ON_ERROR(object);
        ++object->epoch;
        const auto bytes = serde::serialize(*object);
        CO_RETURN_ON_ERROR(co_await txn.set(objectKey(kv::KeyPrefix::EcObject, this->object), bytes));
        co_return Void{};
      }));
    } else {
      // Deliberately exercise the low-level legacy mutation. Public legacy
      // Cancel must be guarded by ECVM before any V2 object can be exposed.
      ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::cancel(txn, this->object, request.operation); }));
    }
    ASSERT_ERROR(blockingWait(binder->commit()), TransactionCode::kConflict);
    binder.reset();
    ASSERT_ERROR(this->bind(*op, *values), StatusCode::kTokenStale);
    ASSERT_ERROR(
        this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, values->at(0).fragment.identity); }),
        StatusCode::kNotImplemented);
  }
}

TYPED_TEST(TestEcV2BindingCatalog, RepairPreservesHealthyWritersAndIncludesEveryOldAndNewInstance) {
  auto published = this->publishWrite(this->intent());
  ASSERT_OK(published);
  const auto base = published->candidate;
  // A different authorized writer may repair the object; it does not replace
  // the original namespace embedded in healthy fragments' stable stage spec.
  this->owner = {flat::Uid(102), Uuid::random()};
  for (uint16_t mask : {uint16_t{1}, kEcAllShards}) {
    auto request = this->intent(base.revision, mask);
    auto op = this->begin(request);
    ASSERT_OK(op);
    auto values = this->allocations(*op);
    ASSERT_OK(values);
    if (mask == 1) {
      ASSERT_NE(values->at(1).writer.client, this->owner.client);
      auto changed = *values;
      changed[1].targetIncarnation = Uuid::random();
      ASSERT_ERROR(this->bind(*op, changed), StatusCode::kTokenMismatch);
      changed = *values;
      changed[1].writer = this->owner;
      ASSERT_ERROR(this->bind(*op, changed), StatusCode::kTokenMismatch);
    }
    auto bound = this->bind(*op, *values);
    ASSERT_OK(bound);
    ASSERT_EQ(bound->operationEndpoints.count, mask == 1 ? 13 : 24);
    // New physical incarnations share logical chain/target/node with old
    // ones here: deduplication must not silently drop those old instances.
    for (const auto &old : base.fragments) {
      auto physical = this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, old.identity); });
      ASSERT_OK(physical);
      const auto &set = bound->operationEndpoints;
      ASSERT_NE(std::find(set.endpoints.begin(), set.endpoints.begin() + set.count, physical->endpoint()),
                set.endpoints.begin() + set.count);
    }
    auto pinned = this->run([&](auto &txn) { return EcCatalog::getManifest(txn, this->object, 0, base.revision); });
    ASSERT_OK(pinned);
    ASSERT_EQ(pinned->pins, mask == 1 ? 1 : 2);
  }
}

TYPED_TEST(TestEcV2BindingCatalog, RepairRejectsUnboundBaseEvenWhenEveryCandidateIsNew) {
  auto published = this->publishWrite(this->intent());
  ASSERT_OK(published);
  auto request = this->intent(published->candidate.revision, kEcAllShards);
  auto op = this->begin(request);
  ASSERT_OK(op);
  auto values = this->allocations(*op);
  ASSERT_OK(values);
  const auto missingKey = allocationKey(published->candidate.fragments[11].identity);
  ASSERT_OK(this->run([&](auto &txn) { return txn.clear(missingKey); }));
  ASSERT_ERROR(this->bind(*op, *values), StatusCode::kNotImplemented);
  ASSERT_ERROR(
      this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, values->at(0).fragment.identity); }),
      StatusCode::kNotImplemented);
}

TYPED_TEST(TestEcV2BindingCatalog, PinRetryKeepsHistoricalEndpointsAndDoesNotDoubleReference) {
  auto first = this->publishWrite(this->intent());
  ASSERT_OK(first);
  const auto pin = Uuid::random();
  auto pinned = this->run([&](auto &txn) { return Bindings::acquireRead(txn, this->object, 0, pin, this->owner); });
  ASSERT_OK(pinned);
  auto next = this->publishWrite(this->intent(first->candidate.revision));
  ASSERT_OK(next);
  auto retried = this->run([&](auto &txn) { return Bindings::acquireRead(txn, this->object, 0, pin, this->owner); });
  ASSERT_OK(retried);
  ASSERT_EQ(retried->snapshot.revision, first->candidate.revision);
  ASSERT_EQ(retried->snapshot.endpoints, pinned->snapshot.endpoints);
  ASSERT_EQ(retried->snapshot.endpointSetDigest, pinned->snapshot.endpointSetDigest);
  auto old =
      this->run([&](auto &txn) { return EcCatalog::getManifest(txn, this->object, 0, first->candidate.revision); });
  ASSERT_OK(old);
  ASSERT_TRUE(old->retired);
  ASSERT_EQ(old->pins, 1);
  auto current =
      this->run([&](auto &txn) { return EcCatalog::getManifest(txn, this->object, 0, next->candidate.revision); });
  ASSERT_OK(current);
  ASSERT_EQ(current->pins, 0);
  auto other = this->owner;
  other.uid = flat::Uid(101);
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::acquireRead(txn, this->object, 0, pin, other); }),
               MetaCode::kNoPermission);
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::getPinSnapshot(txn, this->object, pin, other); }),
               MetaCode::kNoPermission);
  auto snapshot = this->run([&](auto &txn) { return Bindings::getPinSnapshot(txn, this->object, pin, this->owner); });
  ASSERT_OK(snapshot);
  ASSERT_EQ(snapshot->endpoints, pinned->snapshot.endpoints);
}

TYPED_TEST(TestEcV2BindingCatalog, MissingBindingDiscardsTentativePinAndReferenceIncrement) {
  auto first = this->publishWrite(this->intent());
  ASSERT_OK(first);
  const auto missing = allocationKey(first->candidate.fragments[11].identity);
  ASSERT_OK(this->run([&](auto &txn) { return txn.clear(missing); }));
  const auto pin = Uuid::random();
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::acquireRead(txn, this->object, 0, pin, this->owner); }),
               StatusCode::kNotImplemented);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::getPin(txn, this->object, pin); }),
               StatusCode::kKVStoreNotFound);
  auto manifest =
      this->run([&](auto &txn) { return EcCatalog::getManifest(txn, this->object, 0, first->candidate.revision); });
  ASSERT_OK(manifest);
  ASSERT_EQ(manifest->pins, 0);
  for (const auto &fragment : first->candidate.fragments) {
    auto ref = this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, fragment.identity); });
    ASSERT_OK(ref);
    ASSERT_EQ(ref->references, 1);
  }
}

TYPED_TEST(TestEcV2BindingCatalog, ConcurrentPinCreationConflictsAndRetryUsesOneReference) {
  auto first = this->publishWrite(this->intent());
  ASSERT_OK(first);
  const auto pin = Uuid::random();
  auto a = this->engine->createReadWriteTransaction();
  auto b = this->engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(Bindings::acquireRead(*a, this->object, 0, pin, this->owner)));
  ASSERT_OK(blockingWait(Bindings::acquireRead(*b, this->object, 0, pin, this->owner)));
  ASSERT_OK(blockingWait(a->commit()));
  ASSERT_ERROR(blockingWait(b->commit()), TransactionCode::kConflict);
  b.reset();
  ASSERT_OK(this->run([&](auto &txn) { return Bindings::acquireRead(txn, this->object, 0, pin, this->owner); }));
  auto old =
      this->run([&](auto &txn) { return EcCatalog::getManifest(txn, this->object, 0, first->candidate.revision); });
  ASSERT_OK(old);
  ASSERT_EQ(old->pins, 1);
}

TYPED_TEST(TestEcV2BindingCatalog, InvalidSideVersionAndOversizedRecordFailClosed) {
  auto op = this->begin(this->intent());
  ASSERT_OK(op);
  auto values = this->allocations(*op);
  ASSERT_OK(values);
  ASSERT_OK(this->bind(*op, *values));
  auto invalid = values->at(0);
  invalid.version = 2;
  const auto key = allocationKey(invalid.fragment.identity);
  ASSERT_OK(this->run([&](auto &txn) -> CoTryTask<Void> {
    const auto encoded = serde::serialize(invalid);
    CO_RETURN_ON_ERROR(co_await txn.set(key, encoded));
    co_return Void{};
  }));
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, invalid.fragment.identity); }),
               StatusCode::kDataCorruption);
  const std::string oversized(65537, 'x');
  ASSERT_OK(this->run([&](auto &txn) { return txn.set(key, oversized); }));
  ASSERT_ERROR(this->run([&](auto &txn) { return Bindings::getAllocationBinding(txn, invalid.fragment.identity); }),
               StatusCode::kDataCorruption);
}

TEST(TestEcV2BindingSerde, FixedArraysRejectWrongExtentsBeforeReadingElements) {
  EcV2AllocationBindings allocations;
  std::array<EcV2ReadEndpoint, 12> reads;
  std::array<EcV2PhysicalEndpoint, 24> endpoints;
  for (uint8_t count : {uint8_t{0}, uint8_t{11}, uint8_t{13}, uint8_t{23}, uint8_t{25}}) {
    const std::string malformed(1, static_cast<char>(count));
    ASSERT_FALSE(serde::deserialize(allocations, malformed));
    ASSERT_FALSE(serde::deserialize(reads, malformed));
    ASSERT_FALSE(serde::deserialize(endpoints, malformed));
  }
  ASSERT_FALSE(serde::fromJsonString(allocations, "[]"));
  ASSERT_FALSE(serde::fromJsonString(reads, "[]"));
  ASSERT_FALSE(serde::fromJsonString(endpoints, "[]"));
  EcV2PinSnapshot original;
  original.object = {InodeId(1234), Uuid::random()};
  original.pin = Uuid::random();
  original.endpoints[0].endpoint.engineUuid = Uuid::random();
  EcV2PinSnapshot decoded;
  ASSERT_OK(serde::deserialize(decoded, serde::serialize(original)));
  ASSERT_EQ(decoded.endpoints, original.endpoints);
  ASSERT_EQ(std::string(serde::serialize(decoded)), std::string(serde::serialize(original)));
  // InodeId uses its existing hexadecimal diagnostic formatter for JSON,
  // while the readable parser still expects an integer. Snapshot text is for
  // inspection; persistence and RPC round trips use the binary schema above.
  const auto readable = serde::toJsonString(original);
  ASSERT_NE(readable.find(original.object.inode.toHexString()), std::string::npos);
  ASSERT_NE(readable.find(original.pin.toHexString()), std::string::npos);
  ASSERT_ERROR(serde::fromJsonString(decoded, readable), StatusCode::kSerdeNotInteger);
}
}  // namespace
}  // namespace hf3fs::meta::server
