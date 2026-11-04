#include "fbs/storage/EcStageResultV2.h"
#include "tests/EcRepairTestData.h"

namespace hf3fs::storage {
namespace {
using namespace repair_test;

TEST(TestEcRepairPlan, IndependentAllSingleAndDoubleErasures) {
  for (uint16_t first = 0; first != 12; ++first) {
    for (uint16_t second = first; second != 12; ++second) {
      auto data = makeData(17, first == second ? std::vector<uint16_t>{first} : std::vector<uint16_t>{second, first});
      auto plan = EcRepairPlan::create(data.input);
      ASSERT_OK(plan);
      auto block = EcRepairBlockCore::begin(**plan, 0);
      ASSERT_OK(block);
      for (uint8_t hop = 0; hop != 10; ++hop) {
        block =
            EcRepairBlockCore::advance(**plan, hop, std::move(*block), blockBytes(data, data.input.sources[hop], 0));
        ASSERT_OK(block);
      }
      ASSERT_OK(EcRepairBlockCore::validateComplete(**plan, *block));
      for (size_t target = 0; target != block->targetCount; ++target) {
        ASSERT_EQ(block->outputs[target], data.shards[data.input.targets[target].identity.shard]);
      }
    }
  }
}

TEST(TestEcRepairPlan, FullBlockAndShortTailUseSameFixedPlan) {
  auto data = makeData(kEcIntegrityBlockBytes + 19);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  ASSERT_EQ((*plan)->blockCount(), 2);
  for (uint32_t index = 0; index != 2; ++index) {
    auto block = EcRepairBlockCore::begin(**plan, index);
    ASSERT_OK(block);
    for (uint8_t hop = 0; hop != 10; ++hop) {
      block =
          EcRepairBlockCore::advance(**plan, hop, std::move(*block), blockBytes(data, data.input.sources[hop], index));
      ASSERT_OK(block);
    }
    ASSERT_OK(EcRepairBlockCore::validateComplete(**plan, *block));
    for (size_t target = 0; target != 2; ++target) {
      EXPECT_EQ(block->outputs[target], blockBytes(data, data.input.targets[target], index));
    }
  }
  ASSERT_ERROR(EcRepairBlockCore::begin(**plan, 2), StatusCode::kInvalidArg);
}

TEST(TestEcRepairPlan, RejectsWrongHopDuplicateContributionAndStalePlan) {
  auto data = makeData(37);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto first = EcRepairBlockCore::begin(**plan, 0);
  ASSERT_OK(first);
  auto source = blockBytes(data, data.input.sources[0], 0);
  auto advanced = EcRepairBlockCore::advance(**plan, 0, *first, source);
  ASSERT_OK(advanced);
  auto retry = EcRepairBlockCore::advance(**plan, 0, *first, source);
  ASSERT_OK(retry);
  EXPECT_EQ(retry->outputs, advanced->outputs);
  ASSERT_ERROR(EcRepairBlockCore::advance(**plan, 0, *advanced, source), StatusCode::kInvalidArg);
  advanced->contributorMask = 0;
  ASSERT_ERROR(EcRepairBlockCore::validate(**plan, *advanced, 1), StatusCode::kInvalidArg);
  auto changed = data.input;
  changed.planId = Uuid::random();
  auto newer = EcRepairPlan::create(changed);
  ASSERT_OK(newer);
  ASSERT_ERROR(EcRepairBlockCore::advance(**newer, 0, *first, source), StatusCode::kInvalidArg);
}

TEST(TestEcRepairPlan, RejectsSourceCorruptionAndSelfConsistentWrongTarget) {
  auto data = makeData(37);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto block = EcRepairBlockCore::begin(**plan, 0);
  ASSERT_OK(block);
  auto source = blockBytes(data, data.input.sources[0], 0);
  source[3] ^= 1;
  ASSERT_ERROR(EcRepairBlockCore::advance(**plan, 0, *block, source), StatusCode::kDataCorruption);
  auto wrong = computeEcIntegrity(data.input.targets[0].identity, std::string(37, 'x'));
  ASSERT_OK(wrong);
  data.input.targets[0].integrity = *wrong;
  auto wrongPlan = EcRepairPlan::create(data.input);
  ASSERT_OK(wrongPlan);  // Plan consistency is not proof of the issuer's intent.
  block = EcRepairBlockCore::begin(**wrongPlan, 0);
  ASSERT_OK(block);
  for (uint8_t hop = 0; hop != 10; ++hop) {
    block =
        EcRepairBlockCore::advance(**wrongPlan, hop, std::move(*block), blockBytes(data, data.input.sources[hop], 0));
    if (hop < 9) ASSERT_OK(block);
  }
  ASSERT_ERROR(block, StatusCode::kDataCorruption);
}

TEST(TestEcRepairPlan, BindsFullEndpointSetAndOriginalOperation) {
  auto data = makeData(11, {0});
  auto original = EcRepairPlan::create(data.input);
  ASSERT_OK(original);
  auto changed = data.input;
  changed.sources[0].operationId = Uuid::random();
  auto other = EcRepairPlan::create(changed);
  ASSERT_OK(other);
  EXPECT_NE((*original)->digest(), (*other)->digest());
  changed = data.input;
  changed.operationEndpoints[12] = changed.operationEndpoints[0];
  changed.operationEndpoints[12].targetIncarnation = Uuid::random();
  changed.operationEndpointCount = 13;
  other = EcRepairPlan::create(changed);
  ASSERT_OK(other);
  EXPECT_NE((*original)->digest(), (*other)->digest());
  EXPECT_NE((*original)->endpointSetDigest(), (*other)->endpointSetDigest());
  std::reverse(changed.operationEndpoints.begin(), changed.operationEndpoints.begin() + 13);
  auto reordered = EcRepairPlan::create(changed);
  ASSERT_OK(reordered);
  EXPECT_EQ((*other)->digest(), (*reordered)->digest());
}

TEST(TestEcRepairPlan, RejectsExtentAndOwnershipChangesBeforeArithmetic) {
  auto data = makeData(11);
  auto changed = data.input;
  changed.sources[1] = changed.sources[0];
  EXPECT_FALSE(EcRepairPlan::create(changed));
  changed = data.input;
  changed.targets[0].operationId = Uuid::random();
  EXPECT_FALSE(EcRepairPlan::create(changed));
  changed = data.input;
  changed.sources[0].endpoint.engineUuid = Uuid::random();
  EXPECT_FALSE(EcRepairPlan::create(changed));
  changed = data.input;
  changed.operationEndpointCount = 25;
  EXPECT_FALSE(EcRepairPlan::create(changed));
  changed = data.input;
  changed.maxBlocksInFlight = 5;
  EXPECT_FALSE(EcRepairPlan::create(changed));
}

TEST(TestEcRepairPlan, PacketHashBindsPayloadAndRejectsOversizedOrNonzeroSeed) {
  auto data = makeData(11);
  auto plan = EcRepairPlan::create(data.input);
  ASSERT_OK(plan);
  auto block = EcRepairBlockCore::begin(**plan, 0);
  ASSERT_OK(block);
  block->outputs[0][0] = 1;
  EXPECT_FALSE(EcRepairBlockCore::digestPacket(**plan, *block));
  block = EcRepairBlockCore::begin(**plan, 0);
  block = EcRepairBlockCore::advance(**plan, 0, *block, blockBytes(data, data.input.sources[0], 0));
  ASSERT_OK(block);
  auto first = EcRepairBlockCore::digestPacket(**plan, *block);
  ASSERT_OK(first);
  block->outputs[0][0] ^= 1;
  auto changed = EcRepairBlockCore::digestPacket(**plan, *block);
  ASSERT_OK(changed);
  EXPECT_NE(*first, *changed);
  block->outputs[0].push_back('x');
  EXPECT_FALSE(EcRepairBlockCore::digestPacket(**plan, *block));
}

}  // namespace
}  // namespace hf3fs::storage
