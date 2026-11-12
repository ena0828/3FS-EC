#include <algorithm>

#include "EcReadSpool.h"
#include "detail/EcReadSpoolScan.h"

namespace hf3fs::client::ec {
using namespace detail;
namespace {
Result<Void> externalArchive(const std::filesystem::path &archive, const std::filesystem::path &spool) {
  if (!archive.is_absolute() || archive != archive.lexically_normal() || archive.filename().empty() ||
      archive.filename() == "." || archive.filename() == ".." || archive.string().size() > 4096 ||
      archive.native().find('\0') != std::string::npos)
    return makeError(StatusCode::kInvalidArg, "retirement requires an explicit normalized external archive path");
  std::error_code error;
  const auto root = std::filesystem::canonical(spool, error);
  if (error) return makeError(StatusCode::kIOError, "cannot resolve spool for retirement");
  const auto parent = std::filesystem::canonical(archive.parent_path(), error);
  if (error) return makeError(StatusCode::kIOError, "archive parent must already exist");
  auto mismatch = std::mismatch(root.begin(), root.end(), parent.begin(), parent.end());
  if (mismatch.first == root.end())
    return makeError(StatusCode::kInvalidArg, "final read summary must be outside the production spool");
  return Void{};
}
Result<Void> exportArchive(const std::filesystem::path &path, std::string_view bytes) {
  SpoolFd parent(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (parent.value < 0) return spoolIo("open read archive parent");
  SpoolFd file(
      ::openat(parent.value, path.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (file.value < 0) {
    if (errno != EEXIST) return spoolIo("create read retirement archive exclusively");
    CHECK_RESULT(previous, spoolRead(parent.value, path.filename().string(), 1u << 20));
    if (previous != bytes)
      return makeError(StatusCode::kTokenMismatch, "existing archive differs; never overwrite recovery evidence");
  } else {
    if (::fchmod(file.value, 0600)) return spoolIo("set read archive permissions");
    RETURN_ON_ERROR(spoolWriteAll(file.value, bytes));
    if (::fsync(file.value)) return spoolIo("persist read retirement archive");
  }
  if (::fsync(parent.value)) return spoolIo("persist read archive directory");
  return Void{};
}
Result<Void> validateRemainingFiles(int directory, const EcReadArchive &archive) {
  CHECK_RESULT(entries, spoolEntries(directory, kReadSpoolMaximumStates + 66));
  CHECK_RESULT(recordText, encodeEcFileRunRecord(archive.record));
  CHECK_RESULT(progressText, encodeEcFileRunProgress(archive.progress));
  for (const auto &entry : entries) {
    if (entry.directory || !spoolJournalName(entry.name) || entry.bytes > kReadSpoolEntryBytes)
      return makeError(StatusCode::kInvalidFormat, "retirement found an unrecognized local file; preserve it");
    if (entry.name == ".lock") {
      if (entry.bytes) return makeError(StatusCode::kInvalidFormat, "nonempty journal lock");
      continue;
    }
    CHECK_RESULT(text, spoolRead(directory, entry.name, kReadSpoolEntryBytes));
    if (entry.name == "record.json") {
      if (text != recordText) return makeError(StatusCode::kTokenMismatch, "retirement record changed after export");
    } else if (entry.name.starts_with("state-")) {
      CHECK_RESULT(progress, decodeEcFileRunProgress(text));
      if (entry.name != fmt::format("state-{:020}.json", progress.sequence) ||
          progress.sequence > archive.progress.sequence)
        return makeError(StatusCode::kInvalidFormat, "retirement state exceeds exported terminal sequence");
      if (progress.sequence == archive.progress.sequence && text != progressText)
        return makeError(StatusCode::kTokenMismatch, "retirement terminal state changed after export");
    } else {
      // Only our own canonical temporary names may remain after an interrupted
      // exclusive publication. An unknown filename is never recursively erased.
      if (!spoolPendingName(entry.name)) return makeError(StatusCode::kInvalidFormat);
    }
  }
  return Void{};
}
}  // namespace
Result<storage::EcSha256> EcReadSpool::retire(const Run &run, const std::filesystem::path &archivePath) {
  try {
    RETURN_ON_ERROR(validReceipt(run.receipt));
    if (poisoned_ || run.journal->poisoned()) return makeError(StatusCode::kIOError, "reopen before retirement");
    RETURN_ON_ERROR(spoolOwnedRecord(run.journal->record(), cluster_, namespace_));
    if (!run.journal->latest()) return makeError(StatusCode::kTokenStale, "read has no terminal observation");
    // Called only after the dispatcher independently authenticates the original
    // owner, confirms Query44 Released and all original Release36 T2 tuples,
    // with no active data task/output lease. No F3 progress is appended here.
    const EcReadArchive archive{run.receipt, run.journal->record(), *run.journal->latest()};
    CHECK_RESULT(bytes, encodeReadArchive(archive));
    RETURN_ON_ERROR(externalArchive(archivePath, path_));
    RETURN_ON_ERROR(inspect(&run));
    RETURN_ON_ERROR(exportArchive(archivePath, bytes));
    CHECK_RESULT(digest, readArchiveDigest(bytes));
    const EcReadRetirementMarker marker{run.receipt, archivePath, digest};
    CHECK_RESULT(markerText, encodeReadRetirementMarker(marker));
    // Any failure from marker publication onward requires reopen and explicit
    // same-receipt recovery. The marker always survives partial file deletion.
    poisoned_ = true;
    RETURN_ON_ERROR(writeNew(readRetirementMarkerName(run.receipt.sequence), markerText));
    auto finished = finishRetirement(run.receipt, archivePath);
    if (!finished) return makeError(std::move(finished.error()));
    poisoned_ = false;
    return *finished;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kIOError, "retirement interrupted; preserve receipt and archive");
  }
}
Result<storage::EcSha256> EcReadSpool::finishRetirement(const EcReadReceipt &receipt,
                                                        const std::filesystem::path &archivePath) {
  try {
    RETURN_ON_ERROR(validReceipt(receipt));
    RETURN_ON_ERROR(externalArchive(archivePath, path_));
    const auto markerName = readRetirementMarkerName(receipt.sequence);
    CHECK_RESULT(exists, spoolExists(directory_, markerName));
    if (!exists) return makeError(StatusCode::kKVStoreNotFound, "NoRetainedEvidence: retirement marker is absent");
    CHECK_RESULT(text, read(markerName, 16384));
    CHECK_RESULT(marker, decodeReadRetirementMarker(text));
    if (!sameReadReceipt(marker.receipt, receipt) || marker.archive != archivePath)
      return makeError(StatusCode::kTokenMismatch, "retirement recovery must retain exact receipt and archive path");
    CHECK_RESULT(archive, loadReadArchive(marker));
    RETURN_ON_ERROR(spoolOwnedRecord(archive.record, cluster_, namespace_));
    const auto original = spoolRunName(receipt.sequence), retired = spoolRunName(receipt.sequence, true);
    CHECK_RESULT(hasOriginal, spoolExists(directory_, original));
    CHECK_RESULT(hasRetired, spoolExists(directory_, retired));
    if (hasOriginal && hasRetired)
      return makeError(StatusCode::kInvalidFormat, "two local directories for one receipt");
    // Both fresh retirement and explicit recovery enter this mutation phase.
    // Any uncertain local result now requires reopening before further work.
    poisoned_ = true;
    if (hasOriginal) {
      SpoolFd directory(::openat(directory_, original.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
      if (directory.value < 0) return makeError(spoolIo("open run for retirement").error());
      RETURN_ON_ERROR(spoolStat(directory.value, true));
      RETURN_ON_ERROR(validateRemainingFiles(directory.value, archive));
      if (::renameat(directory_, original.c_str(), directory_, retired.c_str()) || ::fsync(directory_))
        return makeError(spoolIo("persist retiring read directory").error());
    }
    if (hasOriginal || hasRetired) {
      SpoolFd directory(::openat(directory_, retired.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
      if (directory.value < 0) return makeError(spoolIo("open retiring read directory").error());
      RETURN_ON_ERROR(spoolStat(directory.value, true));
      RETURN_ON_ERROR(validateRemainingFiles(directory.value, archive));
      CHECK_RESULT(entries, spoolEntries(directory.value, kReadSpoolMaximumStates + 66));
      for (const auto &entry : entries) {
        if (::unlinkat(directory.value, entry.name.c_str(), 0))
          return makeError(spoolIo("remove verified local read metadata").error());
      }
      if (::fsync(directory.value) || ::unlinkat(directory_, retired.c_str(), AT_REMOVEDIR) || ::fsync(directory_))
        return makeError(spoolIo("persist completed local read retirement").error());
    }
    // If a crash removed the directory already, the still-durable marker and
    // exact exported summary are sufficient to finish this local-only step.
    if (::unlinkat(directory_, markerName.c_str(), 0) || ::fsync(directory_))
      return makeError(spoolIo("persist retirement marker removal").error());
    poisoned_ = false;
    return marker.digest;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kIOError, "local retirement recovery failed");
  }
}
}  // namespace hf3fs::client::ec
