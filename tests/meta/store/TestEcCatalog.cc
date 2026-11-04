#include <cstdlib>
#include <folly/experimental/coro/BlockingWait.h>

#include "common/kv/mem/MemKVEngine.h"
#include "fdb/FDBKVEngine.h"
#include "meta/store/EcCatalog.h"
#include "tests/GtestHelpers.h"
#include "tests/fdb/SetupFDB.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;

// This fixture never clears an FDB database. Every test uses a fresh incarnation.
// FDB execution is explicitly opt-in through the dedicated test-cluster variable.
template <typename UseFDB>
class TestEcCatalog : public hf3fs::testing::SetupFDB {
 protected:
  void SetUp() override {
    if constexpr (UseFDB::value) {
      const char *cluster = std::getenv("EC_CATALOG_TEST_CLUSTER");
      if (!cluster) GTEST_SKIP() << "EC_CATALOG_TEST_CLUSTER not set";
      kv::fdb::DB db(cluster, false);
      ASSERT_FALSE(db.error());
      engine = std::make_unique<kv::FDBKVEngine>(std::move(db));
    } else {
      engine = std::make_unique<kv::MemKVEngine>();
    }
    object.inode = InodeId(1234);
    object.incarnation = Uuid::random();
    ASSERT_OK(run([&](auto &txn) { return EcCatalog::createObject(txn, object, 64); }));
  }

  auto run(auto fn) {
    auto txn = engine->createReadWriteTransaction();
    auto result = blockingWait(fn(*txn));
    if (result) {
      auto committed = blockingWait(txn->commit());
      if (!committed) return decltype(result)(makeError(committed.error()));
    }
    return result;
  }

  EcMutationIntent intent(uint64_t revision = 0, EcMutationKind kind = EcMutationKind::Write) {
    EcMutationIntent value;
    value.object = object;
    value.operation = Uuid::random();
    // Synthetic request digest: these transaction tests do not implement the
    // trusted coordinator's canonical request encoding or hashing.
    value.requestDigest.back() = 1;
    value.expectedEpoch = 1;
    value.expectedRevision = revision;
    value.logicalLength = 613;
    value.kind = kind;
    value.replacementMask = kind == EcMutationKind::Write ? kEcAllShards : 1;
    for (size_t i = 0; i != 12; ++i) {
      value.placements[i].chain = storage::ChainId(100 + i);
      value.placements[i].target = storage::TargetId(200 + i);
      value.placements[i].node = flat::NodeId(300 + i);
    }
    return value;
  }

  Result<EcVerifiedManifest> verified(EcManifest manifest, bool corruptBytes = false) {
    std::array<storage::EcReadResult, 12> reads;
    std::array<storage::EcFragmentReceipt, 12> receipts;
    for (size_t i = 0; i != 12; ++i) {
      auto &f = manifest.fragments[i];
      auto &read = reads[i];
      read.payload.data.assign(64, static_cast<char>('a' + i));
      CHECK_RESULT(integrity, storage::computeEcIntegrity(f.identity, read.payload.data));
      f.integrity = integrity;
      auto &receipt = read.receipt;
      receipt.identity = f.identity;
      receipt.operationId = f.operation;
      receipt.vChainId = {f.placement.chain, storage::ChainVer(3)};
      receipt.targetId = f.placement.target;
      receipt.length = integrity.wholeLength;
      receipt.checksum = {storage::ChecksumType::CRC32C, ~integrity.wholeCrc32c};
      receipts[i] = receipt;
    }
    if (corruptBytes) reads[7].payload.data[11] ^= 1;
    return EcVerifiedManifest::fromStorageResponses(std::move(manifest), reads, receipts);
  }

  Result<EcOperationRecord> publish(const EcMutationIntent &request) {
    CHECK_RESULT(op, run([&](auto &txn) { return EcCatalog::begin(txn, request); }));
    CHECK_RESULT(proof, verified(op.candidate));
    return run([&](auto &txn) { return EcCatalog::publish(txn, object, request.operation, proof); });
  }

  std::unique_ptr<kv::IKVEngine> engine;
  EcObjectRef object;
};

using CatalogBackends = ::testing::Types<std::false_type, std::true_type>;
TYPED_TEST_SUITE(TestEcCatalog, CatalogBackends);

TYPED_TEST(TestEcCatalog, PublicationPinsAndRetirement) {
  auto first = this->intent();
  auto result = this->publish(first);
  ASSERT_OK(result);
  auto old = result->candidate;
  auto pin = Uuid::random();
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::acquireRead(txn, this->object, 0, pin); }));
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::acquireRead(txn, this->object, 0, pin); }));
  auto next = this->intent(old.revision);
  ASSERT_OK(this->publish(next));
  auto pinned = this->run([&](auto &txn) { return EcCatalog::acquireRead(txn, this->object, 0, pin); });
  ASSERT_OK(pinned);
  ASSERT_EQ(pinned->revision, old.revision);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::retireRevision(txn, this->object, 0, old.revision); }),
               StatusCode::kTokenStale);
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::releaseRead(txn, this->object, pin); }));
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::releaseRead(txn, this->object, pin); }));
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::acquireRead(txn, this->object, 0, pin); }),
               StatusCode::kTokenStale);
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::retireRevision(txn, this->object, 0, old.revision); }));
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::retireRevision(txn, this->object, 0, old.revision); }));
  auto ref = this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, old.fragments[0].identity); });
  ASSERT_OK(ref);
  ASSERT_EQ(ref->references, 0);
  ASSERT_TRUE(ref->gcCandidate);
  auto terminal = this->run([&](auto &txn) { return EcCatalog::begin(txn, first); });
  ASSERT_OK(terminal);
  ASSERT_EQ(terminal->state, EcOperationState::Published);
  ASSERT_EQ(terminal->candidate.revision, old.revision);
}

TYPED_TEST(TestEcCatalog, RepairSharesHealthyFragmentsAndPinsItsBase) {
  auto first = this->publish(this->intent());
  ASSERT_OK(first);
  const auto base = first->candidate;
  auto repair = this->intent(base.revision, EcMutationKind::Repair);
  repair.placements[0].target = storage::TargetId(900);
  repair.placements[0].chain = storage::ChainId(901);
  repair.placements[0].node = flat::NodeId(902);
  auto repaired = this->publish(repair);
  ASSERT_OK(repaired);
  ASSERT_EQ(repaired->candidate.generation, base.generation);
  ASSERT_EQ(repaired->candidate.fragments[1].operation, base.fragments[1].operation);
  ASSERT_NE(repaired->candidate.fragments[0].identity.allocation, base.fragments[0].identity.allocation);
  ASSERT_EQ(repaired->candidate.fragments[0].integrity.root, base.fragments[0].integrity.root);
  auto shared = this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, base.fragments[1].identity); });
  ASSERT_OK(shared);
  ASSERT_EQ(shared->references, 2);
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::retireRevision(txn, this->object, 0, base.revision); }));
  shared = this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, base.fragments[1].identity); });
  ASSERT_OK(shared);
  ASSERT_EQ(shared->references, 1);
  ASSERT_FALSE(shared->gcCandidate);
  auto replaced = this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, base.fragments[0].identity); });
  ASSERT_OK(replaced);
  ASSERT_TRUE(replaced->gcCandidate);

  auto pending = this->intent(repaired->candidate.revision, EcMutationKind::Repair);
  for (size_t i = 0; i != 12; ++i) pending.placements[i] = repaired->candidate.fragments[i].placement;
  auto reservation = this->run([&](auto &txn) { return EcCatalog::begin(txn, pending); });
  ASSERT_OK(reservation);
  ASSERT_OK(this->publish(this->intent(repaired->candidate.revision)));
  ASSERT_ERROR(this->run([&](auto &txn) {
    return EcCatalog::retireRevision(txn, this->object, 0, repaired->candidate.revision);
  }),
               StatusCode::kTokenStale);
  ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::cancel(txn, this->object, pending.operation); }));
  ASSERT_OK(this->run(
      [&](auto &txn) { return EcCatalog::retireRevision(txn, this->object, 0, repaired->candidate.revision); }));
}

TYPED_TEST(TestEcCatalog, TwoPublishersConflictWithoutChangingExpectedHead) {
  auto a = this->intent();
  auto b = this->intent();
  auto ra = this->run([&](auto &txn) { return EcCatalog::begin(txn, a); });
  auto rb = this->run([&](auto &txn) { return EcCatalog::begin(txn, b); });
  ASSERT_OK(ra);
  ASSERT_OK(rb);
  ASSERT_NE(ra->candidate.generation, rb->candidate.generation);
  auto va = this->verified(ra->candidate);
  auto vb = this->verified(rb->candidate);
  ASSERT_OK(va);
  ASSERT_OK(vb);
  auto ta = this->engine->createReadWriteTransaction();
  auto tb = this->engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcCatalog::publish(*ta, this->object, a.operation, *va)));
  ASSERT_OK(blockingWait(EcCatalog::publish(*tb, this->object, b.operation, *vb)));
  ASSERT_OK(blockingWait(ta->commit()));
  ASSERT_ERROR(blockingWait(tb->commit()), TransactionCode::kConflict);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::publish(txn, this->object, b.operation, *vb); }),
               StatusCode::kTokenStale);
  auto rejected =
      this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, rb->candidate.fragments[0].identity); });
  ASSERT_OK(rejected);
  ASSERT_EQ(rejected->references, 0);
  ASSERT_FALSE(rejected->gcCandidate);
}

TYPED_TEST(TestEcCatalog, PublishAndCancelConflictInEitherCommitOrder) {
  for (bool publishFirst : {false, true}) {
    auto request = this->intent();
    request.stripe = publishFirst ? 1 : 0;
    auto op = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
    ASSERT_OK(op);
    auto proof = this->verified(op->candidate);
    ASSERT_OK(proof);
    auto publisher = this->engine->createReadWriteTransaction();
    auto canceler = this->engine->createReadWriteTransaction();
    ASSERT_OK(blockingWait(EcCatalog::publish(*publisher, this->object, request.operation, *proof)));
    ASSERT_OK(blockingWait(EcCatalog::cancel(*canceler, this->object, request.operation)));
    ASSERT_OK(blockingWait((publishFirst ? publisher : canceler)->commit()));
    ASSERT_ERROR(blockingWait((publishFirst ? canceler : publisher)->commit()), TransactionCode::kConflict);
    auto state = this->run([&](auto &txn) { return EcCatalog::cancel(txn, this->object, request.operation); });
    ASSERT_OK(state);
    ASSERT_EQ(state->state, publishFirst ? EcOperationState::Published : EcOperationState::Aborted);
    auto ref =
        this->run([&](auto &txn) { return EcCatalog::getFragmentRef(txn, op->candidate.fragments[0].identity); });
    ASSERT_OK(ref);
    ASSERT_EQ(ref->references, publishFirst ? 1 : 0);
    ASSERT_EQ(ref->gcCandidate, !publishFirst);
  }
}

TYPED_TEST(TestEcCatalog, LostCommitAcknowledgementReconcilesWithoutDoubleReferences) {
  auto request = this->intent();
  auto reserved = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
  ASSERT_OK(reserved);
  auto proof = this->verified(reserved->candidate);
  ASSERT_OK(proof);
  auto txn = this->engine->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcCatalog::publish(*txn, this->object, request.operation, *proof)));
  // Deterministically inject loss at the observation boundary: commit really
  // succeeds, while the caller sees MaybeCommitted and drops its transaction.
  auto loseAcknowledgement = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn->commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "injected lost commit acknowledgement");
  };
  ASSERT_ERROR(blockingWait(loseAcknowledgement()), TransactionCode::kMaybeCommitted);
  txn.reset();
  auto outcome = this->run([&](auto &next) { return EcCatalog::getOperation(next, this->object, request.operation); });
  ASSERT_OK(outcome);
  ASSERT_EQ(outcome->state, EcOperationState::Published);
  ASSERT_OK(this->run([&](auto &next) { return EcCatalog::publish(next, this->object, request.operation, *proof); }));
  auto ref =
      this->run([&](auto &next) { return EcCatalog::getFragmentRef(next, outcome->candidate.fragments[0].identity); });
  ASSERT_OK(ref);
  ASSERT_EQ(ref->references, 1);
}

TYPED_TEST(TestEcCatalog, RejectsChangedIntentForgedBytesAndColocatedPlacements) {
  auto request = this->intent();
  auto reserved = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
  ASSERT_OK(reserved);
  auto changed = request;
  --changed.logicalLength;
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::begin(txn, changed); }), StatusCode::kTokenMismatch);
  ASSERT_ERROR(this->verified(reserved->candidate, true), StatusCode::kDataCorruption);
  auto colocated = this->intent();
  colocated.placements[1].node = colocated.placements[0].node;
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::begin(txn, colocated); }), StatusCode::kInvalidArg);
  auto wrongObject = this->object;
  wrongObject.inode = InodeId(4321);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::getOperation(txn, wrongObject, request.operation); }),
               StatusCode::kTokenMismatch);
  auto terminal = this->run([&](auto &txn) { return EcCatalog::cancel(txn, this->object, request.operation); });
  ASSERT_OK(terminal);
  ASSERT_EQ(terminal->state, EcOperationState::Aborted);
  auto replay = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
  ASSERT_OK(replay);
  ASSERT_EQ(replay->state, EcOperationState::Aborted);
}

TYPED_TEST(TestEcCatalog, RequestDigestBindsPreparingAndTerminalRetries) {
  auto zeroDigest = this->intent();
  zeroDigest.requestDigest.fill(0);
  auto before = this->run([&](auto &txn) { return EcCatalog::getObject(txn, this->object); });
  ASSERT_OK(before);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::begin(txn, zeroDigest); }), StatusCode::kInvalidArg);
  ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::getOperation(txn, this->object, zeroDigest.operation); }),
               StatusCode::kKVStoreNotFound);
  auto after = this->run([&](auto &txn) { return EcCatalog::getObject(txn, this->object); });
  ASSERT_OK(after);
  ASSERT_EQ(after->nextGeneration, before->nextGeneration);
  ASSERT_EQ(after->nextRevision, before->nextRevision);

  uint64_t stripe = 0;
  for (auto state : {EcOperationState::Preparing, EcOperationState::Published, EcOperationState::Aborted}) {
    auto request = this->intent();
    request.stripe = stripe++;
    auto reserved = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
    ASSERT_OK(reserved);
    ASSERT_EQ(reserved->intent.requestDigest, request.requestDigest);
    if (state == EcOperationState::Published) {
      auto proof = this->verified(reserved->candidate);
      ASSERT_OK(proof);
      ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::publish(txn, this->object, request.operation, *proof); }));
    } else if (state == EcOperationState::Aborted) {
      ASSERT_OK(this->run([&](auto &txn) { return EcCatalog::cancel(txn, this->object, request.operation); }));
    }

    auto changed = request;
    changed.requestDigest.front() ^= 0x80;
    ASSERT_ERROR(this->run([&](auto &txn) { return EcCatalog::begin(txn, changed); }), StatusCode::kTokenMismatch);
    auto replay = this->run([&](auto &txn) { return EcCatalog::begin(txn, request); });
    ASSERT_OK(replay);
    ASSERT_EQ(replay->state, state);
    ASSERT_EQ(replay->intent.requestDigest, request.requestDigest);
    ASSERT_EQ(replay->candidate.generation, reserved->candidate.generation);
    ASSERT_EQ(replay->candidate.revision, reserved->candidate.revision);
    for (size_t shard = 0; shard != 12; ++shard) {
      ASSERT_EQ(replay->candidate.fragments[shard].identity.allocation,
                reserved->candidate.fragments[shard].identity.allocation);
    }
  }
}

}  // namespace
}  // namespace hf3fs::meta::server
