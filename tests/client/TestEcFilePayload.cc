#include <gtest/gtest.h>

#include "client/ec/EcFilePayload.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
TEST(TestEcFilePayload, OutputRetainsThePartitionAndMovingReleasesOldBytesFirst) {
  auto created = EcFilePayloadBudget::create();
  ASSERT_OK(created);
  auto budget = *created;
  auto first = budget->allocate(16);
  auto second = budget->allocate(32);
  ASSERT_OK(first);
  ASSERT_OK(second);
  first->bytes()[0] = 91;
  EXPECT_EQ(budget->usedBytes(), 48);
  *second = std::move(*first);
  EXPECT_EQ(budget->usedBytes(), 16);
  EXPECT_EQ(first->size(), 0);
  EXPECT_EQ(second->bytes()[0], 91);
  *second = EcFilePayload{};
  EXPECT_EQ(budget->usedBytes(), 0);
}
TEST(TestEcFilePayload, NoNewPayloadFitsUntilTheRetainedOutputIsDestroyed) {
  auto created = EcFilePayloadBudget::create();
  ASSERT_OK(created);
  auto budget = *created;
  auto other = EcFilePayloadBudget::create();
  ASSERT_OK(other);
  auto foreign = (*other)->allocate(1);
  ASSERT_OK(foreign);
  EXPECT_FALSE(budget->owns(*foreign));
  EXPECT_TRUE((*other)->owns(*foreign));
  auto full = budget->allocate(EcFilePayloadBudget::limitBytes());
  ASSERT_OK(full);
  EXPECT_EQ(full->bytes().back(), 0);
  ASSERT_ERROR(budget->allocate(1), StorageClientCode::kResourceBusy);
  ASSERT_ERROR(budget->allocate(EcFilePayloadBudget::limitBytes() + 1), StatusCode::kInvalidArg);
  auto moved = std::move(*full);
  EXPECT_EQ(full->size(), 0);
  EXPECT_TRUE(full->bytes().empty());
  EXPECT_EQ(budget->usedBytes(), EcFilePayloadBudget::limitBytes());
  budget.reset();
  created->reset();
  // The payload retains its counter independently of the public budget handle.
  moved.bytes()[0] = 7;
  EXPECT_EQ(moved.bytes()[0], 7);
}
}  // namespace hf3fs::client::ec
