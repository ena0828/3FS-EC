#include <gtest/gtest.h>
#include <limits>

#include "client/ec/EcFilePlanning.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
TEST(TestEcFilePlanning, RequestedPinsIncludeAlignmentAndClippingDoesNotReplaceIdentity) {
  auto request = planEcFileRead(8, 70, 120);
  ASSERT_OK(request);
  ASSERT_EQ(request->count, 3);
  EXPECT_EQ(request->slices[0], (EcFileSlice{0, 70, 70, 10}));
  EXPECT_EQ(request->slices[1], (EcFileSlice{1, 80, 0, 80}));
  EXPECT_EQ(request->slices[2], (EcFileSlice{2, 160, 0, 30}));
  auto clipped = clipEcFileRead(*request, 170);
  ASSERT_OK(clipped);
  EXPECT_EQ(clipped->length, 100);
  EXPECT_EQ(clipped->slices[2].length, 10);
  EXPECT_EQ(request->length, 120);
  auto empty = clipEcFileRead(*request, 65);
  ASSERT_OK(empty);
  EXPECT_EQ(empty->count, 0);
  EXPECT_EQ(empty->length, 0);
}
TEST(TestEcFilePlanning, ExactUint64AndBothIndependentBoundsAreChecked) {
  const auto maximum = std::numeric_limits<uint64_t>::max();
  ASSERT_OK(planEcFileRead(1, maximum, 0));
  ASSERT_OK(planEcFileRead(1, maximum - 1, 1));
  ASSERT_ERROR(planEcFileRead(1, maximum, 1), StatusCode::kInvalidArg);
  ASSERT_OK(planEcFileRead(8, 0, 640));
  ASSERT_ERROR(planEcFileRead(8, 1, 640), StatusCode::kInvalidArg);
  ASSERT_OK(planEcFileRead(1u << 20, 9u << 20, 32u << 20));
  ASSERT_ERROR(planEcFileRead(1u << 20, 0, (32u << 20) + 1), StatusCode::kInvalidArg);
  ASSERT_ERROR(planEcFileRead(0, 0, 0), StatusCode::kInvalidArg);
  auto plan = planEcFileRead(8, 0, 80);
  ASSERT_OK(plan);
  plan->slices[0].stripe = 99;
  ASSERT_ERROR(clipEcFileRead(*plan, 80), StatusCode::kInvalidArg);
}
TEST(TestEcFilePlanning, AppendOnlyAcceptsWholeStripesAtTheExplicitExpectedEOF) {
  auto plan = planEcFileAppend(1u << 20, 20u << 20, 30u << 20);
  ASSERT_OK(plan);
  EXPECT_EQ(plan->count, 3);
  EXPECT_EQ(plan->slices[0].stripe, 2);
  EXPECT_EQ(plan->slices[2].stripe, 4);
  ASSERT_ERROR(planEcFileAppend(8, 79, 80), StatusCode::kInvalidArg);
  ASSERT_ERROR(planEcFileAppend(8, 80, 79), StatusCode::kInvalidArg);
  ASSERT_ERROR(planEcFileAppend(8, 0, 0), StatusCode::kInvalidArg);
}
}  // namespace hf3fs::client::ec
