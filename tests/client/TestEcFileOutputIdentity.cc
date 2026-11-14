#include <filesystem>
#include <folly/experimental/TestUtil.h>
#include <folly/json.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <sys/stat.h>
#include <vector>

#include "client/ec/EcFileOutputIdentity.h"
#include "client/ec/EcFilePwriteJournal.h"
#include "client/ec/EcTreeRepairJournal.h"
#include "client/ec/EcTruncateJournal.h"
#include "fbs/meta/EcRequestDigest.h"
#include "tests/GtestHelpers.h"

namespace hf3fs::client::ec {
namespace {
std::string read(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void write(const std::filesystem::path &path, std::string_view bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(bytes.data(), bytes.size());
}
using Files = std::map<std::filesystem::path, std::pair<std::string, std::filesystem::file_time_type>>;
Files files(const std::filesystem::path &run) {
  Files result;
  for (const auto &entry : std::filesystem::directory_iterator(run))
    result.emplace(entry.path().filename(), std::make_pair(read(entry.path()), entry.last_write_time()));
  return result;
}
meta::EcFileSessionRecord session() {
  meta::EcFileSessionRecord s;
  s.intent.object = {meta::InodeId(781), Uuid::random()};
  s.intent.birth = Uuid::random();
  s.intent.owner = {flat::Uid(1007), Uuid::random()};
  s.intent.session = Uuid::random();
  s.intent.openRequest = Uuid::random();
  s.intent.rights = meta::kEcSessionRead | meta::kEcSessionWrite;
  return s;
}
meta::EcTreeRoot rootFor(const meta::EcFileSessionRecord &s) {
  meta::EcTreeRoot root;
  root.object = s.intent.object;
  root.birth = s.intent.birth;
  root.root = Uuid::random();
  root.sequence = 9;
  root.epoch = 3;
  root.visibleLength = 999;
  return root;
}
Result<EcPwriteRunRecord> pwrite(const std::filesystem::path &base) {
  const auto s = session();
  CHECK_RESULT(r, prepareEcPwriteSession(s.intent.owner, "identity-test", false, "", s.intent.object,
                                         s.intent.birth, 8, s.intent.rights));
  CHECK_RESULT(journal, EcFilePwriteJournal::create(base / "session", r));
  EcPwriteRunProgress state;
  state.session = s;
  state.session->intent.session = r.session;
  state.session->intent.openRequest = r.openRequest;
  state.shardBytes = 8;
  RETURN_ON_ERROR(journal->append(state));
  std::vector<uint8_t> data(180, 0x63);
  return prepareEcPwrite(*journal, 7, (base / "private-payload-not-exported").string(), data);
}
void expectIdentity(const folly::dynamic &i, const meta::EcObjectRef &object, const meta::EcOwner &owner,
                    Uuid parent, Uuid child, const char *kind) {
  ASSERT_TRUE(i.isObject());
  EXPECT_EQ(i.size(), 7);
  EXPECT_EQ(i["inode_decimal"], std::to_string(object.inode.u64()));
  EXPECT_EQ(i["object_incarnation"], object.incarnation.toHexString());
  EXPECT_EQ(i["owner_uid"].asInt(), owner.uid.toUnderType());
  EXPECT_EQ(i["owner_client"], owner.client.toHexString());
  EXPECT_EQ(i["parent"], parent.toHexString());
  EXPECT_EQ(i["child"], child.toHexString());
  EXPECT_EQ(i["owner_kind"], kind);
}
void expectBoundary(const folly::dynamic &value) {
  EXPECT_EQ(value["schema"], 1);
  EXPECT_EQ(value["kind"], "ec_file_output_identities");
  EXPECT_EQ(value["candidate_identities_only"], true);
  EXPECT_EQ(value["network_io_performed"], false);
  EXPECT_EQ(value["metadata_observation_performed"], false);
  EXPECT_EQ(value["remote_absence_confirmed"], false);
  EXPECT_EQ(value["physical_reclamation_confirmed"], false);
  EXPECT_EQ(value["source_record_sha256"].getString().size(), 64);
}
template <class Journal, class Record, class State>
void inspection(const std::filesystem::path &path, Record record, State state) {
  auto made = Journal::create(path, record);
  ASSERT_OK(made);
  auto owner = std::move(*made);
  EXPECT_FALSE(Journal::inspectExisting(path));
  ASSERT_OK(owner->append(state));
  owner.reset();
  const auto before = files(path);
  auto inspected = Journal::inspectExisting(path);
  ASSERT_OK(inspected);
  auto reader = std::move(*inspected);
  EXPECT_FALSE(reader->inspectionRecordBytes().empty());
  EXPECT_FALSE(reader->inspectionLatestStateBytes().empty());
  EXPECT_FALSE(Journal::resume(path));
  ASSERT_ERROR(reader->append(state), StatusCode::kInvalidArg);
  reader.reset();
  EXPECT_EQ(files(path), before);
  std::filesystem::remove(path / ".lock");
  EXPECT_FALSE(Journal::inspectExisting(path));
  EXPECT_FALSE(std::filesystem::exists(path / ".lock"));
  const auto recordPath = path / (std::filesystem::exists(path / "record.json") ? "record.json" : "record.data");
  std::filesystem::create_symlink(recordPath, path / ".lock");
  EXPECT_FALSE(Journal::inspectExisting(path));
}
}  // namespace

TEST(TestEcFileOutputIdentity, PwriteExportsOnlyFixedChildrenAndRejectsSessionAndUnusedSlots) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::canonical(temporary.path().string());
  auto r = pwrite(base);
  ASSERT_OK(r);
  ASSERT_EQ(r->count, 3);
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "session", "pwrite", base / "session.json"));
  EXPECT_FALSE(std::filesystem::exists(base / "session.json"));
  for (bool append : {false, true}) {
    auto record = *r;
    if (append) {
      meta::EcFileSessionRecord s;
      s.intent.object = r->object;
      s.intent.birth = r->birth;
      s.intent.owner = r->owner;
      s.intent.session = r->session;
      s.intent.openRequest = r->openRequest;
      s.intent.rights = r->rights;
      meta::EcFileMutationRecord parent;
      parent.intent.object = r->object;
      parent.intent.owner = r->owner;
      parent.intent.session = r->session;
      parent.intent.request = r->operation;
      parent.intent.offset = r->offset;
      parent.intent.length = r->length;
      parent.intent.inputSha256 = r->inputSha256;
      parent.sessionSequence = 1;
      parent.epoch = 1;
      std::vector<uint8_t> data(180, 0x63);
      auto accepted = prepareEcPwriteFromAcceptedParent(s, r->shardBytes, r->cluster, parent, r->inputPath, data);
      ASSERT_OK(accepted);
      record = *accepted;
    }
    const auto path = base / (append ? "append" : "write");
    auto made = EcFilePwriteJournal::create(path, record);
    ASSERT_OK(made);
    made->reset();
    const auto before = files(path);
    const auto output = base / (append ? "append.json" : "write.json");
    ASSERT_OK(exportEcFileOutputIdentities(path, "pwrite", output));
    const auto value = folly::parseJson(read(output));
    expectBoundary(value);
    EXPECT_TRUE(value["tail_requirement"].isNull());
    EXPECT_TRUE(value["source_latest_state_sha256"].isNull());
    ASSERT_EQ(value["identities"].size(), 3);
    for (size_t i = 0; i < 3; ++i)
      expectIdentity(value["identities"][i], record.object, record.owner, record.operation,
                     record.children[i].intent.child, "pwrite");
    EXPECT_EQ(files(path), before);
    EXPECT_EQ(read(output).find("private-payload-not-exported"), std::string::npos);
    struct stat status {};
    ASSERT_EQ(::stat(output.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777, 0600);
  }
  auto unused = *r;
  unused.children[unused.count].intent.child = Uuid::random();
  EXPECT_FALSE(EcFilePwriteJournal::create(base / "invalid", unused));
}

TEST(TestEcFileOutputIdentity, RepairExportsOriginalIntentWithoutInventingRemoteObservation) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::canonical(temporary.path().string());
  const auto s = session();
  auto r = prepareEcTreeRepair(s, rootFor(s), "identity-test", 0, 3, meta::EcFileRepairMode::HelperChainDirect,
                               {2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, 4);
  ASSERT_OK(r);
  auto made = EcTreeRepairJournal::create(base / "repair", *r);
  ASSERT_OK(made);
  EcTreeRepairState state;
  state.issued = true;  // A sent request without a reply is still only a candidate.
  ASSERT_OK((*made)->append(state));
  made->reset();
  const auto before = files(base / "repair");
  ASSERT_OK(exportEcFileOutputIdentities(base / "repair", "repair", base / "repair.json"));
  const auto value = folly::parseJson(read(base / "repair.json"));
  expectBoundary(value);
  ASSERT_EQ(value["identities"].size(), 1);
  expectIdentity(value["identities"][0], r->intent.object, r->intent.owner, r->intent.operation, r->intent.child, "repair");
  EXPECT_EQ(value["source_latest_state_sha256"].getString().size(), 64);
  EXPECT_EQ(files(base / "repair"), before);
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "repair", "truncate", base / "wrong-kind.json"));
}

TEST(TestEcFileOutputIdentity, TruncateDistinguishesUnknownRequiredAndUnusedTailWithoutAbsenceProof) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::canonical(temporary.path().string());
  const auto s = session();
  const auto root = rootFor(s);
  for (const auto *name : {"unknown", "required", "not_required"}) {
    const std::string tail = name;
    SCOPED_TRACE(tail);
    auto r = prepareEcFileTruncate(s, root, "identity-test", 33);
    ASSERT_OK(r);
    auto made = EcTruncateJournal::create(base / tail, *r);
    ASSERT_OK(made);
    EcTruncateJournalState state;
    state.beginIssued = true;
    if (tail != "unknown") {
      state.progress.emplace();
      state.progress->intent = r->intent;
      state.progress->observed.emplace();
      auto &o = *state.progress->observed;
      o.birth = s.intent.birth;
      o.fencedRoot = root;
      ++o.fencedRoot.sequence;
      ++o.fencedRoot.epoch;
      o.tailRequired = tail == "required";
      o.outputDrained = o.sourceReleased = !o.tailRequired;
    }
    ASSERT_OK((*made)->append(state));
    made->reset();
    const auto before = files(base / tail);
    ASSERT_OK(exportEcFileOutputIdentities(base / tail, "truncate", base / (tail + ".json")));
    const auto value = folly::parseJson(read(base / (tail + ".json")));
    expectBoundary(value);
    EXPECT_EQ(value["tail_requirement"], tail);
    ASSERT_EQ(value["identities"].size(), tail == "not_required" ? 0 : 1);
    if (tail != "not_required")
      expectIdentity(value["identities"][0], r->intent.object, r->intent.owner, r->intent.operation,
                     r->intent.child, "truncate-tail");
    EXPECT_EQ(files(base / tail), before);
  }
}

TEST(TestEcFileOutputIdentity, ExistingLocksRejectWritersMissingLocksAndReadonlyAppendForAllKinds) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::canonical(temporary.path().string());
  auto writeRun = pwrite(base);
  ASSERT_OK(writeRun);
  inspection<EcFilePwriteJournal>(base / "write", *writeRun, EcPwriteRunProgress{});
  const auto s = session();
  auto repair = prepareEcTreeRepair(s, rootFor(s), "identity-test", 0, 3, meta::EcFileRepairMode::CentralSerial,
                                    {2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
  ASSERT_OK(repair);
  inspection<EcTreeRepairJournal>(base / "repair", *repair, EcTreeRepairState{});
  auto truncate = prepareEcFileTruncate(s, rootFor(s), "identity-test", 33);
  ASSERT_OK(truncate);
  inspection<EcTruncateJournal>(base / "truncate", *truncate, EcTruncateJournalState{});
}

TEST(TestEcFileOutputIdentity, HashesOriginalBytesAndPreservesSourceOnOutputAndStateFailures) {
  folly::test::TemporaryDirectory temporary;
  const auto base = std::filesystem::canonical(temporary.path().string());
  auto r = pwrite(base);
  ASSERT_OK(r);
  auto made = EcFilePwriteJournal::create(base / "write", *r);
  ASSERT_OK(made);
  made->reset();
  const auto record = base / "write" / "record.json";
  const auto raw = " \n" + read(record) + "\n "; // Valid envelope; hash the original bytes, not canonical JSON.
  write(record, raw);
  const auto before = files(base / "write");
  const auto output = base / "identities.json";
  ASSERT_OK(exportEcFileOutputIdentities(base / "write", "pwrite", output));
  std::array<std::string_view, 10> parts{};
  parts[0] = raw;
  auto expected = meta::computeEcLogicalSha256(parts, raw.size());
  ASSERT_OK(expected);
  EXPECT_EQ(folly::parseJson(read(output))["source_record_sha256"],
            serde::SerdeMethod<storage::EcSha256>::serdeToReadable(*expected));
  const auto originalOutput = read(output);
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", output));
  EXPECT_EQ(read(output), originalOutput);
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", base / "write" / "new.json"));
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", base / "missing" / "new.json"));
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "invalid", base / "invalid.json"));
  const auto truncatedName = base / "nul-output.json";
  const auto nulOutput = std::filesystem::path(truncatedName.string() + std::string("\0suffix", 7));
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", nulOutput));
  EXPECT_FALSE(std::filesystem::exists(truncatedName));
  const auto nulRun = std::filesystem::path((base / "write").string() + std::string("\0suffix", 7));
  EXPECT_FALSE(exportEcFileOutputIdentities(nulRun, "pwrite", base / "nul-run.json"));
  EXPECT_FALSE(std::filesystem::exists(base / "nul-run.json"));
  EXPECT_EQ(files(base / "write"), before);
  // A malformed/gapped state must fail before creating an output archive.
  const auto bad = base / "write" / "state-00000000000000000001.json";
  write(bad, "not-a-state");
  ASSERT_EQ(::chmod(bad.c_str(), 0600), 0);
  const auto damaged = files(base / "write");
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", base / "bad-state.json"));
  EXPECT_FALSE(std::filesystem::exists(base / "bad-state.json"));
  EXPECT_EQ(files(base / "write"), damaged);
  std::filesystem::rename(bad, base / "write" / "state-00000000000000000000.json");
  const auto malformed = files(base / "write");
  EXPECT_FALSE(exportEcFileOutputIdentities(base / "write", "pwrite", base / "malformed-state.json"));
  EXPECT_FALSE(std::filesystem::exists(base / "malformed-state.json"));
  EXPECT_EQ(files(base / "write"), malformed);
}
}  // namespace hf3fs::client::ec
