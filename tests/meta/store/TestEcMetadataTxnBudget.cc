#include <array>

#include "common/kv/mem/MemKVEngine.h"
#include "meta/store/EcFileTreeTxnBudget.h"
#include "meta/store/detail/EcGcTxnScope.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::meta::server {
namespace {
using folly::coro::blockingWait;
using Tx = EcFileTreeTxnBudget;
constexpr std::array kProfiles{Tx::Profile::Range, Tx::Profile::Gc, Tx::Profile::Repair, Tx::Profile::Rmw};

TEST(TestEcMetadataTxnBudget, NumericLimitsCannotUpgradeW0AndInvalidProfilesStayPoisoned) {
  kv::MemKVEngine engine;
  auto raw = engine.createReadWriteTransaction();
  Tx ordinary(*raw);
  EXPECT_EQ(ordinary.profile(), Tx::Profile::W0);
  EXPECT_EQ(ordinary.limits().bytes, 256u << 10);
  EXPECT_EQ(ordinary.limits().keyOperations, 1024);
  Tx rejected(*raw, Tx::Limits{2u << 20, 8192});
  EXPECT_TRUE(rejected.poisoned());
  ASSERT_ERROR(blockingWait(rejected.set("uncommitted", "value")), StatusCode::kInvalidArg);
  rejected.reset();
  EXPECT_EQ(rejected.attempt(), 2);
  EXPECT_EQ(rejected.profile(), Tx::Profile::W0);
  ASSERT_ERROR(blockingWait(rejected.commit()), StatusCode::kInvalidArg);
  Tx invalid(*raw, static_cast<Tx::Profile>(255));
  EXPECT_TRUE(invalid.poisoned());
  invalid.reset();
  ASSERT_ERROR(blockingWait(invalid.commit()), StatusCode::kInvalidArg);
  auto check = engine.createReadWriteTransaction();
  auto absent = blockingWait(check->get("uncommitted"));
  ASSERT_OK(absent);
  EXPECT_FALSE(*absent);
}

TEST(TestEcMetadataTxnBudget, NamedProfilesCountReadValuesExactlyAndResetTheSameProfile) {
  kv::MemKVEngine engine;
  // One normal read charges one key byte twice and this full value: 32 KiB.
  const String value((32u << 10) - 2, 'v');
  auto seed = engine.createReadWriteTransaction();
  ASSERT_OK(blockingWait(seed->set("p", value)));
  ASSERT_OK(blockingWait(seed->commit()));
  for (const auto profile : kProfiles) {
    SCOPED_TRACE(static_cast<unsigned>(profile));
    auto raw = engine.createReadWriteTransaction();
    Tx txn(*raw, profile);
    EXPECT_EQ(txn.limits().bytes, 2u << 20);
    EXPECT_EQ(txn.limits().keyOperations, 8192);
    for (size_t i = 0; i < 64; ++i) ASSERT_OK(blockingWait(txn.get("p")));
    EXPECT_EQ(txn.usage().totalBytes(), 2u << 20);
    EXPECT_EQ(txn.usage().keyOperations, 64);
    EXPECT_EQ(txn.usage().mutationAndConflictBytes(), 64);
    ASSERT_ERROR(blockingWait(txn.get("p")), StatusCode::kInvalidArg);
    ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
    txn.reset();
    EXPECT_EQ(txn.profile(), profile);
    EXPECT_EQ(txn.attempt(), 2);
    EXPECT_EQ(txn.usage().totalBytes(), 0);
    ASSERT_OK(blockingWait(txn.get("p")));
    ASSERT_OK(blockingWait(txn.commit()));
  }
  auto raw = engine.createReadWriteTransaction();
  Tx w0(*raw);
  for (size_t i = 0; i < 8; ++i) ASSERT_OK(blockingWait(w0.get("p")));
  EXPECT_EQ(w0.usage().totalBytes(), 256u << 10);
  ASSERT_ERROR(blockingWait(w0.get("p")), StatusCode::kInvalidArg);
}

TEST(TestEcMetadataTxnBudget, NamedProfilesShareOneOperationLedgerAndCannotCommitAfterOverflow) {
  kv::MemKVEngine engine;
  for (const auto profile : kProfiles) {
    SCOPED_TRACE(static_cast<unsigned>(profile));
    auto raw = engine.createReadWriteTransaction();
    Tx txn(*raw, profile);
    // These two helpers receive the same wrapper; the second does not obtain
    // another 8192 operations or reset the raw transaction's first mutations.
    auto mutate = [](Tx &same) { return same.set("pending", "value"); };
    auto observe = [](Tx &same) { return same.get("missing"); };
    ASSERT_OK(blockingWait(mutate(txn)));
    for (size_t i = 1; i < 8192; ++i) ASSERT_OK(blockingWait(observe(txn)));
    EXPECT_EQ(txn.usage().keyOperations, 8192);
    EXPECT_LT(txn.usage().totalBytes(), txn.limits().bytes);
    ASSERT_ERROR(blockingWait(observe(txn)), StatusCode::kInvalidArg);
    ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
    auto check = engine.createReadWriteTransaction();
    auto absent = blockingWait(check->get("pending"));
    ASSERT_OK(absent);
    EXPECT_FALSE(*absent);
    txn.reset();
    ASSERT_ERROR(blockingWait(txn.snapshotGet("missing")), StatusCode::kInvalidArg);
    ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
    txn.reset();
    ASSERT_OK(blockingWait(txn.set("after-reset", "confirmed")));
    ASSERT_OK(blockingWait(txn.commit()));
  }
}

TEST(TestEcMetadataTxnBudget, NestedGcScopeRetainsTheOuterRmwOrW0LedgerAndCannotCommitPartialWork) {
  kv::MemKVEngine engine;
  const String value((32u << 10) - 2, 'v');
  auto seed = engine.createReadWriteTransaction();
  ASSERT_OK(blockingWait(seed->set("p", value)));
  ASSERT_OK(blockingWait(seed->commit()));
  for (const auto profile : {Tx::Profile::Rmw, Tx::Profile::W0}) {
    SCOPED_TRACE(static_cast<unsigned>(profile));
    auto raw = engine.createReadWriteTransaction();
    Tx txn(*raw, profile);
    ASSERT_OK(blockingWait(txn.set("pending", "value")));
    const auto initialBytes = txn.usage().totalBytes();
    // Exercise the real nested adapter after an outer mutation. It must not
    // replace the ledger with a fresh Gc profile or erase the earlier charge.
    EcGcTxnScope nested(txn);
    auto &same = nested.transaction();
    EXPECT_EQ(&same, &txn);
    EXPECT_EQ(same.profile(), profile);
    EXPECT_EQ(same.usage().totalBytes(), initialBytes);
    const auto reads = (txn.limits().bytes - initialBytes) / (32u << 10);
    for (size_t i = 0; i < reads; ++i) ASSERT_OK(blockingWait(same.get("p")));
    EXPECT_EQ(txn.usage().totalBytes(), initialBytes + reads * (32u << 10));
    EXPECT_EQ(txn.usage().keyOperations, reads + 1);
    ASSERT_ERROR(blockingWait(same.get("p")), StatusCode::kInvalidArg);
    EXPECT_TRUE(txn.poisoned());
    ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
    auto check = engine.createReadWriteTransaction();
    auto absent = blockingWait(check->get("pending"));
    ASSERT_OK(absent);
    EXPECT_FALSE(*absent);
  }
}
}  // namespace
}  // namespace hf3fs::meta::server
