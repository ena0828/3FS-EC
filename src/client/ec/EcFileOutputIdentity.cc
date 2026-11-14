#include "client/ec/EcFileOutputIdentity.h"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <folly/json.h>
#include <sys/stat.h>
#include <unistd.h>

#include "client/ec/EcFilePwriteJournal.h"
#include "client/ec/EcTreeRepairJournal.h"
#include "client/ec/EcTruncateJournal.h"
#include "fbs/meta/EcFileOutput.h"
#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::client::ec {
namespace {
struct Fd {
  int value;
  explicit Fd(int fd) : value(fd) {}
  ~Fd() { if (value >= 0) ::close(value); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
};
Result<std::string> digest(std::string_view bytes) {
  std::array<std::string_view, 10> parts{};
  parts[0] = bytes;
  CHECK_RESULT(sha, meta::computeEcLogicalSha256(parts, bytes.size()));
  return serde::SerdeMethod<storage::EcSha256>::serdeToReadable(sha);
}
Result<Void> add(folly::dynamic &identities,
                   const meta::EcObjectRef &object,
                   const meta::EcOwner &owner,
                   Uuid parent,
                   Uuid child,
                   meta::EcFileOutputOwner kind,
                   std::string_view name) {
  meta::EcFileOutputIdentity identity;
  identity.object = object;
  identity.owner = owner;
  identity.parent = parent;
  identity.child = child;
  identity.ownerKind = kind;
  RETURN_ON_ERROR(identity.valid());
  identities.push_back(folly::dynamic::object("inode_decimal", std::to_string(object.inode.u64()))(
      "object_incarnation", object.incarnation.toHexString())("owner_uid", owner.uid.toUnderType())(
      "owner_client", owner.client.toHexString())("parent", parent.toHexString())("child", child.toHexString())(
      "owner_kind", std::string(name)));
  return Void{};
}
Result<Void> writeNew(const std::filesystem::path &output, const folly::dynamic &value) {
  // Creation is exclusive and outside the journal. A failed write may leave a
  // partial archive; it is never reused as a successful export.
  Fd directory(::open(output.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.value < 0) return makeError(StatusCode::kIOError, "cannot open identity output directory");
  Fd file(::openat(directory.value, output.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (file.value < 0) return makeError(StatusCode::kIOError, "identity output must be a new exclusive file");
  if (::fchmod(file.value, 0600)) return makeError(StatusCode::kIOError, "cannot restrict identity output");
  const auto bytes = folly::toJson(value) + "\n";
  std::string_view remaining = bytes;
  while (!remaining.empty()) {
    auto count = ::write(file.value, remaining.data(), remaining.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StatusCode::kIOError, "cannot write identity output");
    remaining.remove_prefix(static_cast<size_t>(count));
  }
  if (::fsync(file.value) || ::fsync(directory.value))
    return makeError(StatusCode::kIOError, "cannot persist identity output");
  return Void{};
}
template <typename Journal>
Result<Void> finish(const Journal &journal,
                      std::string_view kind,
                      std::string_view recordName,
                      folly::dynamic identities,
                      folly::dynamic tailRequirement,
                      const std::filesystem::path &output) {
  CHECK_RESULT(recordSha, digest(journal.inspectionRecordBytes()));
  folly::dynamic stateSha = nullptr;
  if (journal.latest()) {
    CHECK_RESULT(sha, digest(journal.inspectionLatestStateBytes()));
    stateSha = std::move(sha);
  }
  folly::dynamic value = folly::dynamic::object("schema", 1)("kind", "ec_file_output_identities")(
      "cluster", journal.record().cluster)("output_kind", std::string(kind))(
      "source_record_file", std::string(recordName))("source_record_sha256", recordSha)(
      "source_latest_state_sha256", std::move(stateSha))("tail_requirement", std::move(tailRequirement))(
      "candidate_identities_only", true)("network_io_performed", false)("metadata_observation_performed", false)(
      "remote_absence_confirmed", false)("physical_reclamation_confirmed", false)(
      "identities", std::move(identities));
  // The caller still holds the journal lock until the new archive is durable.
  return writeNew(output, value);
}
}  // namespace

Result<Void> exportEcFileOutputIdentities(const std::filesystem::path &run,
                                          std::string_view outputKind,
                                          const std::filesystem::path &output) {
  try {
    if (outputKind != "pwrite" && outputKind != "repair" && outputKind != "truncate")
      return makeError(StatusCode::kInvalidArg, "output_kind must be pwrite, repair or truncate");
    if (run.string().find('\0') != std::string::npos || output.string().find('\0') != std::string::npos ||
        !run.is_absolute() || !output.is_absolute() || output.filename().empty() ||
        output.filename() == "." || output.filename() == ".." || run != std::filesystem::canonical(run) ||
        output.parent_path() != std::filesystem::canonical(output.parent_path()) || output == run)
      return makeError(StatusCode::kInvalidArg, "identity export requires canonical separate absolute paths");
    for (auto parent = output.parent_path(); !parent.empty(); parent = parent.parent_path()) {
      if (parent == run) return makeError(StatusCode::kInvalidArg, "identity export cannot modify its journal");
      if (parent == parent.parent_path()) break;
    }
    folly::dynamic identities = folly::dynamic::array;
    if (outputKind == "pwrite") {
      CHECK_RESULT(journal, EcFilePwriteJournal::inspectExisting(run));
      const auto &r = journal->record();
      if (r.kind == EcPwriteRunKind::Session)
        return makeError(StatusCode::kInvalidArg, "a session has no output children");
      for (size_t index = 0; index < r.count; ++index) {
        const auto &intent = r.children[index].intent;
        RETURN_ON_ERROR(add(identities, intent.object, r.owner, intent.parent, intent.child,
                            meta::EcFileOutputOwner::Pwrite, "pwrite"));
      }
      return finish(*journal, outputKind, "record.json", std::move(identities), nullptr, output);
    }
    if (outputKind == "repair") {
      CHECK_RESULT(journal, EcTreeRepairJournal::inspectExisting(run));
      const auto &i = journal->record().intent;
      RETURN_ON_ERROR(add(identities, i.object, i.owner, i.operation, i.child, meta::EcFileOutputOwner::Repair, "repair"));
      return finish(*journal, outputKind, "record.data", std::move(identities), nullptr, output);
    }
    CHECK_RESULT(journal, EcTruncateJournal::inspectExisting(run));
    const auto &i = journal->record().intent;
    std::string tail = "unknown";
    if (journal->latest() && journal->latest()->progress && journal->latest()->progress->observed)
      tail = journal->latest()->progress->observed->tailRequired ? "required" : "not_required";
    // Unknown can include an issued Begin/Advance whose reply was lost. Its
    // fixed candidate is useful for Meta observation but proves no ECFE/stage.
    // Known not_required omits the unused child; empty is not remote absence.
    if (tail != "not_required")
      RETURN_ON_ERROR(add(identities, i.object, i.owner, i.operation, i.child,
                          meta::EcFileOutputOwner::TruncateTail, "truncate-tail"));
    return finish(*journal, outputKind, "record.data", std::move(identities), tail, output);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kIOError, "local identity export failed");
  }
}
}  // namespace hf3fs::client::ec
