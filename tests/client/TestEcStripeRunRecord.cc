#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <folly/json.h>
#include <fstream>
#include <gtest/gtest.h>
#include <limits>
#include <sys/stat.h>

#include "client/ec/EcStripeRecoveryWrite.h"
#include "client/ec/EcStripeRunRecord.h"
#include "fbs/meta/EcRequestDigest.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec::test {
namespace {
EcStripeRunRecord record() {
  EcStripeRunRecord value;
  value.action = "write";
  value.cluster = "journal-unit-test";
  value.clientNamespace = Uuid::random();
  value.inputPath = "/explicit-input";
  value.inputBytes = 11;
  value.inputSha256[0] = 1;  // Format fixture only; no remote write uses it.
  value.remotePath = "/explicit-remote";
  value.shardBytes = 8;
  value.createRequest = Uuid::random();
  value.operation = Uuid::random();
  value.beginRequest = Uuid::random();
  value.bindRequest = Uuid::random();
  value.publishRequest = Uuid::random();
  value.getRequest = Uuid::random();
  value.prepareRepairRequest = Uuid::random();
  value.pin = Uuid::random();
  value.acquireRequest = Uuid::random();
  value.releaseRequest = Uuid::random();
  value.planId = Uuid::random();
  return value;
}

meta::EcObjectRecord completeObject(const EcStripeRunRecord &run) {
  meta::EcObjectRecord value;
  // An odd inode above 2^53 detects accidental double/decimal-string coercion.
  value.object = {meta::InodeId((1ull << 56) + 0x12345), Uuid::random()};
  value.shardBytes = run.shardBytes;
  value.allowColocated = true;
  value.epoch = 7;
  value.nextGeneration = 13;
  value.nextRevision = 19;
  value.length = run.inputBytes;
  value.creator = {flat::Uid(123), run.clientNamespace};
  value.createRequest = run.createRequest;
  return value;
}

void completeObjectResume(std::string action) {
  SCOPED_TRACE(action);
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  auto initial = record();
  initial.action = std::move(action);
  initial.object = completeObject(initial);
  initial.expectedOwnerUid = initial.object->creator.uid.toUnderType();
  initial.expectedRevision = 18;
  if (initial.action == "repair") {
    initial.strategy = "helper";
    initial.replacementMask = (1u << 10) | (1u << 11);
    initial.sourceOrder = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    initial.blockWindow = 2;
  }
  auto created = EcStripeRunJournal::create(path, initial);
  ASSERT_OK(created);
  EcStripeRunObservation observation;
  observation.ownerUid = *initial.expectedOwnerUid;
  observation.object = *initial.object;
  observation.object->nextGeneration = 14;
  observation.object->nextRevision = 20;
  observation.revision = 19;
  observation.state = initial.action == "read" ? "ReadReady" : "Published";
  observation.mutationPublished = initial.action != "read";
  observation.logicalBytes = initial.inputBytes;
  observation.shardBytes = initial.shardBytes;
  observation.coreElapsedNanoseconds = 1234567;
  observation.dataPhaseElapsedNanoseconds = 765432;
  ASSERT_OK((*created)->append(observation));
  created->reset();

  // Exercise exactly the JSON files consumed by the CLI resume path, including
  // object-bearing record.json and state files. No binary roundtrip substitutes
  // for the persistent representation.
  auto recordText = readEcStripeInput(path / "record.json", 65536);
  auto stateText = readEcStripeInput(path / "state-00000000000000000000.json", 65536);
  ASSERT_OK(recordText);
  ASSERT_OK(stateText);
  const auto numericInode = fmt::format("\"inode\": {}", initial.object->object.inode.u64());
  EXPECT_NE(recordText->find(numericInode), std::string::npos);
  EXPECT_NE(stateText->find(numericInode), std::string::npos);
  auto resumed = EcStripeRunJournal::resume(path);
  ASSERT_OK(resumed);
  // Compare every field after the real JSON recovery above. The generic
  // equals helper cannot recurse through optional<EcObjectRecord>; binary
  // serialization is used only as an exact value comparison, not for recovery.
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(initial));
  ASSERT_TRUE((*resumed)->latest());
  EXPECT_EQ(serde::serialize(*(*resumed)->latest()), serde::serialize(observation));
  EXPECT_EQ((*resumed)->record().mutationIds().operation, initial.operation);
  EXPECT_EQ((*resumed)->record().pinIds(initial.object->object).object, initial.object->object);

  // A second attempt appends a different complete observation and reopens the
  // same namespace; it must not silently fall back to the original object.
  observation.sequence = 1;
  observation.object->epoch = 8;
  observation.object->deleting = true;
  observation.state = "ExplicitFinalObservation";
  ASSERT_OK((*resumed)->append(observation));
  resumed->reset();
  auto twice = EcStripeRunJournal::resume(path);
  ASSERT_OK(twice);
  ASSERT_TRUE((*twice)->latest());
  EXPECT_EQ(serde::serialize((*twice)->record()), serde::serialize(initial));
  EXPECT_EQ(serde::serialize(*(*twice)->latest()), serde::serialize(observation));
}

TEST(TestEcStripeRunRecord, WriteResumesCompleteObjectAndObservationFromJson) { completeObjectResume("write"); }
TEST(TestEcStripeRunRecord, ReadResumesCompleteObjectAndObservationFromJson) { completeObjectResume("read"); }
TEST(TestEcStripeRunRecord, RepairResumesCompleteObjectAndObservationFromJson) { completeObjectResume("repair"); }

TEST(TestEcStripeRunRecord, RecoveryWritePersistsIndependentIdentityAndKeepsV1Representation) {
  folly::test::TemporaryDirectory temporary;
  const auto parent = std::filesystem::path(temporary.path().string());
  auto source = record();
  const std::string input("restore\0me!", 11);
  std::array<std::string_view, 10> parts{};
  parts[0] = input;
  auto hash = meta::computeEcLogicalSha256(parts, input.size());
  ASSERT_OK(hash);
  source.inputSha256 = *hash;
  EcStripeRunObservation published;
  published.state = "Published";
  published.object = completeObject(source);
  published.ownerUid = 123;
  published.revision = 18;
  published.mutationPublished = true;
  auto old = EcStripeRunJournal::create(parent / "source", source);
  ASSERT_OK(old);
  ASSERT_OK((*old)->append(published));
  old->reset();
  auto oldBytes = readEcStripeInput(parent / "source" / "record.json", 65536);
  ASSERT_OK(oldBytes);
  EXPECT_EQ(oldBytes->find("recoverySource"), std::string::npos);
  auto oldAgain = EcStripeRunJournal::resume(parent / "source");
  ASSERT_OK(oldAgain);
  EXPECT_EQ(serde::serialize((*oldAgain)->record()), serde::serialize(source));
  oldAgain->reset();
  // Digests here are local provenance fixtures, not forged remote authority.
  auto fresh = prepareEcRecoveryWrite(record(),
                                      source,
                                      published,
                                      (parent / "source").string(),
                                      *hash,
                                      *hash,
                                      (parent / "input").string(),
                                      input);
  ASSERT_OK(fresh);
  EXPECT_EQ(fresh->expectedRevision, 18);
  EXPECT_EQ(fresh->object->object, published.object->object);
  EXPECT_EQ(fresh->clientNamespace, source.clientNamespace);
  EXPECT_NE(fresh->operation, source.operation);
  auto created = EcStripeRunJournal::create(parent / "recovery", *fresh);
  ASSERT_OK(created);
  EcStripeRunObservation unknown;
  unknown.state = "Indeterminate";
  unknown.ownerUid = *fresh->expectedOwnerUid;
  unknown.object = fresh->object;
  unknown.errorCode = TransactionCode::kMaybeCommitted;
  ASSERT_OK((*created)->append(unknown));
  created->reset();
  auto resumed = EcStripeRunJournal::resume(parent / "recovery");
  ASSERT_OK(resumed);
  EXPECT_EQ(serde::serialize((*resumed)->record()), serde::serialize(*fresh));
  EXPECT_EQ((*resumed)->latest()->errorCode, unknown.errorCode);
  auto overlap = *fresh;
  overlap.publishRequest = overlap.recoverySource->getRequest;
  EXPECT_FALSE(overlap.validate());
  auto downgrade = *fresh;
  downgrade.version = 1;
  EXPECT_FALSE(downgrade.validate());
  auto changedEpoch = *fresh;
  ++changedEpoch.object->epoch;
  EXPECT_FALSE(changedEpoch.validate());
  auto oldBytesAfter = readEcStripeInput(parent / "source" / "record.json", 65536);
  ASSERT_OK(oldBytesAfter);
  EXPECT_EQ(*oldBytes, *oldBytesAfter);
}

TEST(TestEcStripeRunRecord, RecoveryWriteRejectsUnconfirmedSourceChangedInputAndReusedRequests) {
  auto source = record();
  const std::string input = "hello world";
  std::array<std::string_view, 10> parts{};
  parts[0] = input;
  auto hash = meta::computeEcLogicalSha256(parts, input.size());
  ASSERT_OK(hash);
  source.inputSha256 = *hash;
  EcStripeRunObservation published;
  published.state = "Published";
  published.object = completeObject(source);
  published.ownerUid = 123;
  published.revision = 18;
  published.mutationPublished = true;
  auto attempt = [&](EcStripeRunRecord fresh, EcStripeRunObservation state, std::string_view data) {
    return prepareEcRecoveryWrite(std::move(fresh), source, state, "/source", *hash, *hash, "/input", data);
  };
  EXPECT_TRUE(attempt(record(), published, input));
  EXPECT_FALSE(attempt(record(), published, "hello worle"));
  EXPECT_FALSE(attempt(record(), published, "hello"));
  auto incomplete = published;
  incomplete.mutationPublished = false;
  EXPECT_FALSE(attempt(record(), incomplete, input));
  incomplete = published;
  incomplete.errorCode = StatusCode::kIOError;
  EXPECT_FALSE(attempt(record(), incomplete, input));
  auto fresh = record();
  fresh.getRequest = source.publishRequest;
  EXPECT_FALSE(attempt(fresh, published, input));
  fresh = record();
  fresh.getRequest = fresh.beginRequest;
  EXPECT_FALSE(attempt(fresh, published, input));
  fresh = record();
  fresh.cluster = "another-cluster";
  EXPECT_FALSE(attempt(fresh, published, input));
}

TEST(TestEcStripeRunRecord, ResumeRejectsNarrowingNegativeAndFractionalNumbers) {
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  auto initial = record();
  initial.object = completeObject(initial);
  initial.expectedOwnerUid = 123;
  auto created = EcStripeRunJournal::create(path, initial);
  ASSERT_OK(created);
  created->reset();
  auto text = readEcStripeInput(path / "record.json", 65536);
  ASSERT_OK(text);
  const auto original = folly::parseJson(*text);
  auto rejectText = [&](const std::string &encoded, const char *field) {
    SCOPED_TRACE(field);
    SCOPED_TRACE(encoded);
    {
      std::ofstream stream(path / "record.json", std::ios::binary | std::ios::trunc);
      stream << encoded;
      ASSERT_TRUE(stream.good());
    }
    ASSERT_ERROR(EcStripeRunJournal::resume(path), StatusCode::kInvalidFormat);
  };
  auto reject = [&](folly::dynamic damaged, const char *field) { rejectText(folly::toJson(damaged), field); };
  for (const auto &[field, number] : std::vector<std::pair<std::string, int64_t>>{{"version", 65537},
                                                                                  {"blockWindow", 257},
                                                                                  {"expectedOwnerUid", 4294967419},
                                                                                  {"expectedRevision", -1},
                                                                                  {"replacementMask", 65536}}) {
    SCOPED_TRACE(field);
    auto damaged = original;
    damaged[field] = number;
    reject(std::move(damaged), field.c_str());
  }
  auto damaged = original;
  damaged["object"]["creator"]["uid"] = int64_t(4294967419);
  reject(damaged, "object.creator.uid");
  damaged = original;
  damaged["object"]["epoch"] = int64_t(-1);
  reject(damaged, "object.epoch");

  // SHORTEST/NO_FLAGS may print a double 1.0 as the legal JSON integer 1.
  // Preserve the actual encoder output in XML rather than requiring its rejection.
  RecordProperty("integral_double_json", folly::toJson(folly::dynamic(1.0)));
  const auto integerField = std::string("\"blockWindow\":") + folly::toJson(original["blockWindow"]);
  for (const auto *literal : {"1.0", "1.5"}) {
    auto encoded = folly::toJson(original);
    const auto offset = encoded.find(integerField);
    ASSERT_NE(offset, std::string::npos);
    ASSERT_EQ(encoded.find(integerField, offset + integerField.size()), std::string::npos);
    encoded.replace(offset, integerField.size(), std::string("\"blockWindow\":") + literal);
    ASSERT_TRUE(folly::parseJson(encoded)["blockWindow"].isDouble());
    rejectText(encoded, literal);
  }
  damaged = original;
  damaged["sourceOrder"] = folly::dynamic::array(65536);
  reject(damaged, "sourceOrder");
}

TEST(TestEcStripeRunRecord, ObservationNumbersRemainExactAtResume) {
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  auto created = EcStripeRunJournal::create(path, record());
  ASSERT_OK(created);
  EcStripeRunObservation observation;
  observation.ownerUid = std::numeric_limits<uint32_t>::max();
  observation.coreElapsedNanoseconds = std::numeric_limits<int64_t>::max();
  ASSERT_OK((*created)->append(observation));
  created->reset();
  auto resumed = EcStripeRunJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ((*resumed)->latest()->ownerUid, observation.ownerUid);
  EXPECT_EQ((*resumed)->latest()->coreElapsedNanoseconds, observation.coreElapsedNanoseconds);
  resumed->reset();
  const auto state = path / "state-00000000000000000000.json";
  auto text = readEcStripeInput(state, 65536);
  ASSERT_OK(text);
  const auto original = folly::parseJson(*text);
  for (const auto &[field, number] :
       std::vector<std::pair<std::string, int64_t>>{{"ownerUid", 4294967296},
                                                    {"errorCode", 65536},
                                                    {"readBlockWindow", 256},
                                                    {"dataPhaseElapsedNanoseconds", -1}}) {
    SCOPED_TRACE(field);
    auto damaged = original;
    damaged[field] = number;
    {
      std::ofstream stream(state, std::ios::binary | std::ios::trunc);
      stream << folly::toJson(damaged);
      ASSERT_TRUE(stream.good());
    }
    ASSERT_ERROR(EcStripeRunJournal::resume(path), StatusCode::kInvalidFormat);
  }
}

TEST(TestEcStripeRunRecord, AppendRejectsNumbersOutsideJournalRepresentationBeforePublication) {
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  auto created = EcStripeRunJournal::create(path, record());
  ASSERT_OK(created);
  EcStripeRunObservation observation;
  observation.coreElapsedNanoseconds = std::numeric_limits<uint64_t>::max();
  ASSERT_ERROR((*created)->append(observation), StatusCode::kInvalidFormat);
  EXPECT_FALSE((*created)->latest());
  EXPECT_FALSE(std::filesystem::exists(path / "state-00000000000000000000.json"));
  observation.coreElapsedNanoseconds = 17;
  ASSERT_OK((*created)->append(observation));
  EXPECT_EQ((*created)->latest()->sequence, 0);
}

TEST(TestEcStripeRunRecord, ExclusiveLockAndResumePreservePermanentIdentity) {
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  const auto initial = record();
  auto created = EcStripeRunJournal::create(path, initial);
  ASSERT_OK(created);
  ASSERT_ERROR(EcStripeRunJournal::resume(path), StorageClientCode::kResourceBusy);
  EXPECT_FALSE(EcStripeRunJournal::create(path, record()));
  EcStripeRunObservation observed;
  observed.ownerUid = 123;
  // A new write starts before Create has returned an object; the observation
  // receives the real object later and must survive resume independently.
  observed.object = completeObject(initial);
  observed.revision = 1;
  observed.state = "MutationPending";
  ASSERT_OK((*created)->append(observed));
  EXPECT_EQ((*created)->latest()->sequence, 0);
  observed.state = "Published";
  observed.mutationPublished = true;
  ASSERT_OK((*created)->append(observed));
  created->reset();
  auto resumed = EcStripeRunJournal::resume(path);
  ASSERT_OK(resumed);
  EXPECT_EQ((*resumed)->record().clientNamespace, initial.clientNamespace);
  EXPECT_EQ((*resumed)->record().operation, initial.operation);
  EXPECT_EQ((*resumed)->record().pin, initial.pin);
  ASSERT_TRUE((*resumed)->latest());
  EXPECT_EQ((*resumed)->latest()->sequence, 1);
  EXPECT_EQ((*resumed)->latest()->ownerUid, 123);
  ASSERT_TRUE((*resumed)->latest()->object);
  EXPECT_TRUE(serde::equals(*(*resumed)->latest()->object, *observed.object));
  EXPECT_TRUE(std::filesystem::is_regular_file(path / "state-00000000000000000000.json"));
  EXPECT_TRUE(std::filesystem::is_regular_file(path / "state-00000000000000000001.json"));
  const auto text = serde::toJsonString((*resumed)->record());
  EXPECT_EQ(text.find("token"), std::string::npos);
  EXPECT_EQ(text.find("grant"), std::string::npos);
}

TEST(TestEcStripeRunRecord, MissingObservationCannotBeSilentlySkipped) {
  folly::test::TemporaryDirectory temporary;
  const auto path = std::filesystem::path(temporary.path().string()) / "run";
  auto created = EcStripeRunJournal::create(path, record());
  ASSERT_OK(created);
  ASSERT_OK((*created)->append({}));
  created->reset();
  std::filesystem::rename(path / "state-00000000000000000000.json", path / "state-00000000000000000002.json");
  ASSERT_ERROR(EcStripeRunJournal::resume(path), StatusCode::kInvalidFormat);
}

TEST(TestEcStripeRunRecord, InputsAreBoundedRegularFilesAndOutputsNeverReplace) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::path(temporary.path().string());
  const auto file = base / "input.bin";
  {
    std::ofstream stream(file, std::ios::binary);
    stream << "bounded input";
  }
  auto bytes = readEcStripeInput(file, 100);
  ASSERT_OK(bytes);
  EXPECT_EQ(*bytes, "bounded input");
  EXPECT_FALSE(readEcStripeInput(file, 2));
  std::filesystem::create_symlink(file, base / "link");
  EXPECT_FALSE(readEcStripeInput(base / "link", 100));
  ASSERT_EQ(::mkfifo((base / "fifo").c_str(), 0600), 0);
  EXPECT_FALSE(readEcStripeInput(base / "fifo", 100));
  auto created = EcStripeRunJournal::create(base / "run", record());
  ASSERT_OK(created);
  auto one = (*created)->saveReadOutput("one");
  auto two = (*created)->saveReadOutput("two");
  ASSERT_OK(one);
  ASSERT_OK(two);
  EXPECT_NE(*one, *two);
  ASSERT_OK(readEcStripeInput(base / "run" / *one, 10));
  EXPECT_EQ(*readEcStripeInput(base / "run" / *one, 10), "one");
}
}  // namespace
}  // namespace hf3fs::client::ec::test
