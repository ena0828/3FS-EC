#include <cstdlib>
#include <folly/experimental/coro/BlockingWait.h>

#include "common/kv/KeyPrefix.h"
#include "common/utils/SerDeser.h"
#include "fdb/FDBKVEngine.h"
#include "meta/store/EcFileTreeTxnBudget.h"
#include "meta/store/EcTargetRetirementCatalog.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;
class TestEcTargetRetirementCatalog : public hf3fs::testing::SetupFDB {
 protected:
  void SetUp() override {
    const auto *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
    if (!cluster || !*cluster) GTEST_SKIP() << "requires runner-owned private FDB";
    kv::fdb::DB db(cluster, false);
    ASSERT_FALSE(db.error());
    engine = std::make_unique<kv::FDBKVEngine>(std::move(db));
    intent.endpoint = {{storage::ChainId(901), storage::TargetId(902), flat::NodeId(903)},
                       Uuid::random(), Uuid::random()};
    intent.authority = Uuid::random();
    intent.retirementId = Uuid::random();
    intent.owner = {flat::Uid(0), Uuid::random()};
    intent.requestId = Uuid::random();
  }
  template <class F>
  auto transaction(F fn) {
    auto raw = engine->createReadWriteTransaction();
    EcFileTreeTxnBudget txn(*raw);
    auto result = blockingWait(fn(txn));
    if (result) {
      auto committed = blockingWait(txn.commit());
      if (!committed) return decltype(result)(makeError(std::move(committed.error())));
    }
    return result;
  }
  std::unique_ptr<kv::FDBKVEngine> engine;
  EcTargetRetirementIntent intent;
};
TEST_F(TestEcTargetRetirementCatalog, RealFdbImmutableIntentAndRequestIdentity) {
  intent.endpoint.placement = {storage::ChainId(0x11121314),
                               storage::TargetId(0x2122232425262728ULL),
                               flat::NodeId(0x01020304)};
  ASSERT_OK(transaction([&](auto &t) { return EcTargetRetirementCatalog::requireAssignable(t, intent.endpoint); }));
  auto accepted = transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, intent); });
  ASSERT_OK(accepted);
  ASSERT_FALSE(accepted->completion);
  ASSERT_LT(serde::serialize(*accepted).size(), EcTargetRetirementCatalog::kMaximumRecordBytes);
  // Independent on-disk key oracle for the supported little-endian Linux
  // layout: ETRI + node uint32 + chain uint32 + target uint64 + two UUIDs.
  // Do not call Serializer here: using the same key builder would hide a field
  // order/width regression in the real prepare transaction above.
  std::string expectedKey = "ETRI\x04\x03\x02\x01\x14\x13\x12\x11\x28\x27\x26\x25\x24\x23\x22\x21";
  expectedKey.append(intent.endpoint.engineUuid.asStringView());
  expectedKey.append(intent.endpoint.targetIncarnation.asStringView());
  ASSERT_EQ(expectedKey.size(), 52u);
  auto raw = engine->createReadWriteTransaction();
  auto stored = blockingWait(raw->get(expectedKey));
  ASSERT_OK(stored);
  ASSERT_TRUE(*stored);
  ASSERT_EQ(**stored, serde::serialize(*accepted));
  auto replay = transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, intent); });
  ASSERT_OK(replay);
  ASSERT_EQ(serde::serialize(*accepted), serde::serialize(*replay));
  ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::requireAssignable(t, intent.endpoint); }),
               StatusCode::kTokenStale);
  for (unsigned field = 0; field != 4; ++field) {
    auto changed = intent;
    if (field == 0) changed.retirementId = Uuid::random();
    if (field == 1) changed.authority = Uuid::random();
    if (field == 2) changed.endpoint.targetIncarnation = Uuid::random();
    if (field == 3) changed.owner.client = Uuid::random();
    ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, changed); }),
                 StatusCode::kTokenMismatch);
  }
  auto missing = intent;
  missing.endpoint.engineUuid = Uuid::random();
  missing.requestId = Uuid::random();
  ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::get(t, missing); }),
               StatusCode::kTokenStale);
  ASSERT_OK(transaction([&](auto &t) { return EcTargetRetirementCatalog::requireAssignable(t, missing.endpoint); }));
}
TEST_F(TestEcTargetRetirementCatalog, RealFdbAcceptedIntentConflictsWithAssignmentSnapshot) {
  auto assigning = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::requireAssignable(*assigning, intent.endpoint)));
  ASSERT_OK(transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, intent); }));
  // Force a real write transaction: a read-only commit need not validate its
  // read conflict set. This represents the caller's output reservation write.
  const auto marker = Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirementRequest, Uuid::random());
  const std::string value = "assignment after accepted retirement";
  ASSERT_OK(blockingWait(assigning->set(marker, value)));
  ASSERT_ERROR(blockingWait(assigning->commit()), TransactionCode::kConflict);
  auto check = engine->createReadWriteTransaction();
  auto absent = blockingWait(check->get(marker));
  ASSERT_OK(absent);
  ASSERT_FALSE(*absent);
}
TEST_F(TestEcTargetRetirementCatalog, RealFdbMissingIndexAndInvalidVersionFailClosed) {
  ASSERT_OK(transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, intent); }));
  const auto key = Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirement,
                                         intent.endpoint.placement.node.toUnderType(),
                                         intent.endpoint.placement.chain.toUnderType(),
                                         intent.endpoint.placement.target.toUnderType(),
                                         intent.endpoint.engineUuid,
                                         intent.endpoint.targetIncarnation);
  auto txn = engine->createReadWriteTransaction();
  auto original = blockingWait(txn->get(key));
  ASSERT_OK(original);
  ASSERT_TRUE(*original);
  EcTargetRetirementRecord corrupt;
  ASSERT_OK(serde::deserialize(corrupt, **original));
  corrupt.version = 2;
  const auto bytes = serde::serialize(corrupt);
  ASSERT_OK(blockingWait(txn->set(key, bytes)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::requireAssignable(t, intent.endpoint); }),
               StatusCode::kDataCorruption);
  txn = engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(key, **original)));
  const auto index = Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirementRequest, intent.owner.client, intent.requestId);
  ASSERT_OK(blockingWait(txn->clear(index)));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::get(t, intent); }),
               StatusCode::kDataCorruption);
  ASSERT_ERROR(transaction([&](auto &t) { return EcTargetRetirementCatalog::prepare(t, intent); }),
               StatusCode::kDataCorruption);
}
}  // namespace
}  // namespace hf3fs::meta::server
