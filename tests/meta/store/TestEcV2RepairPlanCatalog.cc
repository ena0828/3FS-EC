#include <fstream>
#include <sys/stat.h>

#include "meta/components/EcV2RepairIssuer.h"
#include "meta/store/EcV2LifecycleUtils.h"
#include "tests/EcRepairTestData.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
using Plans = EcV2RepairPlanCatalog;

// Independent pre-direct ECRP shape: no new field and a literal uint16 v1.
struct LegacyRepairPlanRecordV1 {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(object, EcObjectRef{});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(owner, EcOwner{});
  SERDE_STRUCT_FIELD(selection, EcV2RepairSelection{});
  SERDE_STRUCT_FIELD(plan, storage::EcRepairPlanInput{});
  SERDE_STRUCT_FIELD(digest, storage::EcSha256{});
};

// These are internally consistent synthetic metadata snapshots, not proofs of
// authentication, committed issuance, TCP forwarding or distributed drain.
// The byte oracle is independent of the production EC codec.
struct RepairSnapshot {
  storage::repair_test::Data data = storage::repair_test::makeData(65543);
  EcObjectRef object{InodeId(1234), data.input.sources[0].identity.object};
  EcOwner owner{data.input.ownerUid, data.input.clientNamespace};
  EcManifest base;
  EcV2AllocationBindings bases;
  EcOperationRecord operation;
  EcV2Reservation reservation;
  EcV2OperationBinding binding;
  EcV2PublishedContent content;
  EcV2RepairSelection selection;

  explicit RepairSnapshot(std::vector<uint16_t> missing = {0, 11}, uint32_t shardBytes = 65543)
      : data(storage::repair_test::makeData(shardBytes, missing)) {
    base.object = object;
    base.stripe = data.input.sources[0].identity.stripe;
    base.generation = data.input.sources[0].identity.generation;
    base.revision = data.input.baseRevision;
    base.logicalLength = data.logical.size();
    content.object = object;
    content.stripe = base.stripe;
    content.revision = base.revision;
    content.generation = base.generation;
    content.logicalLength = base.logicalLength;
    content.operation = Uuid::random();
    content.owner = {flat::Uid(900), Uuid::random()};
    content.contentSha256 = data.input.logicalSha256;
    auto &intent = operation.intent;
    intent.object = object;
    intent.operation = data.input.operationId;
    intent.requestDigest.back() = 1;
    intent.stripe = base.stripe;
    intent.expectedEpoch = data.input.baseEpoch;
    intent.expectedRevision = base.revision;
    intent.logicalLength = base.logicalLength;
    intent.kind = EcMutationKind::Repair;
    intent.replacementMask = 0;
    for (auto index : missing) intent.replacementMask |= uint16_t{1} << index;
    operation.owner = owner;
    for (uint16_t i = 0; i != 12; ++i) {
      auto &old = bases[i];
      old.object = object;
      auto &fragment = old.fragment;
      fragment.identity.object = object.incarnation;
      fragment.identity.stripe = base.stripe;
      fragment.identity.generation = base.generation;
      fragment.identity.shard = i;
      fragment.identity.allocation = Uuid::random();
      fragment.placement = {storage::ChainId(200 + i), storage::TargetId(300 + i), flat::NodeId(100 + i)};
      fragment.operation = content.operation;
      auto integrity = storage::computeEcIntegrity(fragment.identity, data.shards[i]);
      EXPECT_TRUE(integrity);
      if (integrity) fragment.integrity = *integrity;
      old.engineUuid = Uuid::random();
      old.targetIncarnation = Uuid::random();
      old.writer = content.owner;
      base.fragments[i] = fragment;
      auto next = old;
      if (intent.replacementMask & (uint16_t{1} << i)) {
        next.fragment.identity.allocation = Uuid::random();
        next.fragment.operation = intent.operation;
        next.writer = owner;
        // Same logical placement, different retained physical incarnation.
        next.targetIncarnation = Uuid::random();
      }
      binding.allocations[i] = next;
      intent.placements[i] = next.fragment.placement;
      intent.fragmentCrc32c[i] = next.fragment.integrity.wholeCrc32c;
      EXPECT_TRUE(addEndpoint(reservation.operationEndpoints, old.endpoint()));
      EXPECT_TRUE(addEndpoint(reservation.operationEndpoints, next.endpoint()));
      reservation.candidates[i] = {next.fragment.identity, next.fragment.operation, next.endpoint(), next.writer};
    }
    operation.candidate = base;
    operation.candidate.revision++;
    for (size_t i = 0; i != 12; ++i) operation.candidate.fragments[i] = binding.allocations[i].fragment;
    reservation.original = operation;
    reservation.contentSha256 = content.contentSha256;
    auto digest = setDigest(reservation.operationEndpoints);
    EXPECT_TRUE(digest);
    if (digest) reservation.operationEndpoints.digest = *digest;
    binding.intent = intent;
    binding.owner = owner;
    binding.generation = operation.candidate.generation;
    binding.revision = operation.candidate.revision;
    binding.operationEndpoints = reservation.operationEndpoints;
    selection.planId = data.input.planId;
    selection.maxBlocksInFlight = 2;
    for (uint8_t i = 0; i != 10; ++i) selection.sourceOrder[i] = data.input.sources[i].identity.shard;
  }
  Result<EcV2RepairPlanRecord> build() const {
    return Plans::build({operation, reservation, binding, base, bases, content}, selection);
  }
};

TEST(TestEcV2RepairPlanCatalog, ReconstructsFullPlanAndKeepsAllOldAndNewInstances) {
  RepairSnapshot state;
  auto record = state.build();
  ASSERT_OK(record);
  auto plan = Plans::validate(*record);
  ASSERT_OK(plan);
  EXPECT_EQ((*plan)->input().operationEndpointCount, 14);
  EXPECT_EQ((*plan)->input().targetCount, 2);
  EXPECT_EQ((*plan)->input().targets[0].identity.shard, 0);
  EXPECT_EQ((*plan)->input().targets[1].identity.shard, 11);
  EXPECT_EQ((*plan)->input().logicalSha256, state.content.contentSha256);
  EXPECT_EQ((*plan)->input().sources[0].writerNamespace, state.content.owner.client);
  EXPECT_EQ((*plan)->input().sources[0].operationId, state.content.operation);
  EXPECT_EQ((*plan)->input().targets[0].writerNamespace, state.owner.client);
  EXPECT_NE((*plan)->input().sources[0].writerNamespace, (*plan)->input().clientNamespace);
  auto replay = state.build();
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*record, *replay));
}

TEST(TestEcV2RepairPlanCatalog, DirectDeliveryVersionsOnlyPermanentRecord) {
  RepairSnapshot state;
  auto legacy = state.build();
  auto direct = Plans::build({state.operation, state.reservation, state.binding, state.base, state.bases, state.content},
                            state.selection, EcV2RepairDelivery::HelperDirect);
  ASSERT_OK(legacy);
  ASSERT_OK(direct);
  LegacyRepairPlanRecordV1 old;
  old.object = legacy->object;
  old.operation = legacy->operation;
  old.owner = legacy->owner;
  old.selection = legacy->selection;
  old.plan = legacy->plan;
  old.digest = legacy->digest;
  EXPECT_EQ(serde::serialize(old), serde::serialize(*legacy));
  EXPECT_EQ(legacy->version, 1);
  EXPECT_EQ(direct->version, 2);
  EXPECT_EQ(serde::serialize(legacy->plan), serde::serialize(direct->plan));
  EXPECT_EQ(legacy->digest, direct->digest);
  EXPECT_NE(serde::serialize(*legacy), serde::serialize(*direct));
  ASSERT_OK(Plans::validate(*direct));
  direct->version = 3;
  ASSERT_ERROR(Plans::validate(*direct), StatusCode::kDataCorruption);
}

TEST(TestEcV2RepairPlanCatalog, RejectsSourcesThatAreDuplicateMissingOrOutOfBounds) {
  for (auto bad : {uint8_t{0}, uint8_t{11}, uint8_t{12}, uint8_t{255}, uint8_t{9}}) {
    RepairSnapshot state;
    state.selection.sourceOrder[0] = bad;
    ASSERT_ERROR(state.build(), StatusCode::kInvalidArg);
  }
  for (auto window : {uint8_t{0}, uint8_t{5}, uint8_t{255}}) {
    RepairSnapshot state;
    state.selection.maxBlocksInFlight = window;
    ASSERT_ERROR(state.build(), StatusCode::kInvalidArg);
  }
}

TEST(TestEcV2RepairPlanCatalog, SingleReplacementChoosesTenOfElevenButRetainsAllThirteenInstances) {
  RepairSnapshot state({3}, 17);
  auto first = state.build();
  ASSERT_OK(first);
  EXPECT_EQ(first->plan.targetCount, 1);
  EXPECT_EQ(first->plan.targets[0].identity.shard, 3);
  EXPECT_EQ(first->plan.operationEndpointCount, 13);
  EXPECT_EQ(first->plan.sources[0].identity.shard, 11);
  EXPECT_EQ(first->plan.sources[9].identity.shard, 1);
  state.selection.sourceOrder[0] = 0;  // The unselected healthy shard.
  auto alternate = state.build();
  ASSERT_OK(alternate);
  EXPECT_NE(first->digest, alternate->digest);
  // Persistence, not this pure constructor, rejects changing an existing ECRP.
  EXPECT_EQ(first->plan.operationEndpointCount, alternate->plan.operationEndpointCount);
}

TEST(TestEcV2RepairPlanCatalog, RejectsForgedHistoricalShaAndChangedHealthyBinding) {
  RepairSnapshot state;
  state.content.contentSha256[0] ^= 1;
  ASSERT_ERROR(state.build(), StatusCode::kDataCorruption);
  state.content.contentSha256[0] ^= 1;
  state.binding.allocations[5].writer.client = Uuid::random();
  state.reservation.candidates[5].writer = state.binding.allocations[5].writer;
  ASSERT_ERROR(state.build(), StatusCode::kDataCorruption);
}

TEST(TestEcV2RepairPlanCatalog, PreviouslyRepairedHealthyFragmentKeepsItsOwnWriterAndOperation) {
  RepairSnapshot state({0, 11}, 17);
  auto &old = state.bases[5];
  old.fragment.operation = Uuid::random();
  old.writer = {flat::Uid(777), Uuid::random()};
  state.base.fragments[5] = old.fragment;
  state.binding.allocations[5] = old;
  state.operation.candidate.fragments[5] = old.fragment;
  state.reservation.original = state.operation;
  state.reservation.candidates[5].operation = old.fragment.operation;
  state.reservation.candidates[5].writer = old.writer;
  auto record = state.build();
  ASSERT_OK(record);
  const auto &source = record->plan.sources[5];
  EXPECT_EQ(source.identity.shard, 5);
  EXPECT_EQ(source.operationId, old.fragment.operation);
  EXPECT_EQ(source.writerNamespace, old.writer.client);
  EXPECT_NE(source.operationId, state.content.operation);
  EXPECT_EQ(record->plan.logicalSha256, state.content.contentSha256);
}

TEST(TestEcV2RepairPlanCatalog, RejectsOmittedOldInstanceEvenWithSelfConsistentSetDigest) {
  RepairSnapshot state;
  EcV2OperationEndpoints reduced;
  for (const auto &value : state.binding.allocations) ASSERT_OK(addEndpoint(reduced, value.endpoint()));
  auto hash = setDigest(reduced);
  ASSERT_OK(hash);
  reduced.digest = *hash;
  state.reservation.operationEndpoints = reduced;
  state.binding.operationEndpoints = reduced;
  ASSERT_ERROR(state.build(), StatusCode::kDataCorruption);
}

TEST(TestEcV2RepairPlanCatalog, RejectsDescriptorSubstitutionAndReplacementReallocation) {
  RepairSnapshot state;
  auto different = storage::computeEcIntegrity(state.binding.allocations[0].fragment.identity, std::string(65543, 'x'));
  ASSERT_OK(different);
  state.binding.allocations[0].fragment.integrity = *different;
  state.operation.candidate.fragments[0].integrity = *different;
  state.reservation.original = state.operation;
  ASSERT_ERROR(state.build(), StatusCode::kDataCorruption);
  RepairSnapshot replacement;
  replacement.binding.allocations[0].targetIncarnation = Uuid::random();
  ASSERT_ERROR(replacement.build(), StatusCode::kDataCorruption);
}

TEST(TestEcV2RepairPlanCatalog, PersistentEnvelopeRejectsChangedSelectionOrDigest) {
  RepairSnapshot state;
  auto record = state.build();
  ASSERT_OK(record);
  auto bad = *record;
  std::swap(bad.selection.sourceOrder[0], bad.selection.sourceOrder[1]);
  ASSERT_ERROR(Plans::validate(bad), StatusCode::kDataCorruption);
  bad = *record;
  bad.digest[0] ^= 1;
  ASSERT_ERROR(Plans::validate(bad), StatusCode::kDataCorruption);
  bad = *record;
  bad.owner.client = Uuid::random();
  ASSERT_ERROR(Plans::validate(bad), StatusCode::kDataCorruption);
  EcV2RepairPlanRecord decoded;
  ASSERT_TRUE(serde::deserialize(decoded, serde::serialize(*record)));
  EXPECT_TRUE(same(decoded, *record));
}

TEST(TestEcV2RepairPlanCatalog, SourceOrderSerdeRequiresExactCountBeforeReadingElements) {
  std::array<uint8_t, 10> output;
  output.fill(77);
  for (size_t count : {size_t{9}, size_t{11}}) {
    const auto encoded = serde::serialize(std::vector<uint8_t>(count, 1));
    EXPECT_FALSE(serde::deserialize(output, encoded));
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](auto value) { return value == 77; }));
  }
  std::array<uint8_t, 10> expected{10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  ASSERT_TRUE(serde::deserialize(output, serde::serialize(expected)));
  EXPECT_EQ(output, expected);
}

TEST(TestEcV2RepairPlanCatalog, IssuerSignsOnlyExactHopsAndRenewalKeepsPlanIdentity) {
  RepairSnapshot state;
  auto record = state.build();
  ASSERT_OK(record);
  auto plan = Plans::validate(*record);
  ASSERT_OK(plan);
  folly::test::TemporaryDirectory directory;
  const auto path = directory.path() / "helper.key";
  {
    std::ofstream stream(path.string(), std::ios::binary);
    std::array<uint8_t, 32> bytes;
    for (size_t i = 0; i != bytes.size(); ++i) bytes[i] = 1 + i;
    stream.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    ASSERT_TRUE(stream.good());
  }
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  auto key = storage::EcHelperKey::loadFile(std::filesystem::path(path.string()));
  ASSERT_OK(key);
  constexpr uint64_t now = 1700000000;
  auto grants = EcV2RepairIssuer::sign(*record, **key, now, 30);
  auto renewed = EcV2RepairIssuer::sign(*record, **key, now + 1, 60);
  ASSERT_OK(grants);
  ASSERT_OK(renewed);
  for (uint8_t hop = 0; hop != 10; ++hop) {
    const auto &endpoint = (*plan)->input().sources[hop].endpoint;
    EXPECT_EQ((*grants)[hop].claims.planDigest, record->digest);
    EXPECT_EQ((*grants)[hop].claims.blockMask, 3);
    EXPECT_NE((*grants)[hop].claims.grantId, (*renewed)[hop].claims.grantId);
    EXPECT_EQ((*renewed)[hop].claims.planDigest, record->digest);
    for (uint32_t block = 0; block != 2; ++block)
      ASSERT_OK(storage::verifyEcHelperGrant(**key, (*grants)[hop], **plan, endpoint, hop, block, now));
    ASSERT_FALSE(storage::verifyEcHelperGrant(**key, (*grants)[hop], **plan, endpoint, hop, 2, now));
  }
  ASSERT_ERROR(EcV2RepairIssuer::sign(*record, **key, now, 301), StatusCode::kInvalidArg);
}
}  // namespace
}  // namespace hf3fs::meta::server
