#pragma once

#include <dirent.h>
#include <map>

#include "EcReadSpoolArchive.h"

namespace hf3fs::client::ec::detail {
struct SpoolEntry {
  std::string name;
  bool directory = false;
  uint64_t bytes = 0;
};
inline bool spoolPendingName(std::string_view name) {
  if (!name.starts_with(".pending-")) return false;
  const auto text = name.substr(9);
  auto id = Uuid::fromHexString(std::string(text));
  return id && !id->is_nil() && id->toHexString() == text;
}
inline bool spoolJournalName(std::string_view name) {
  if (name == ".lock" || name == "record.json" || spoolPendingName(name)) return true;
  if (name.size() != 31 || !name.starts_with("state-") || !name.ends_with(".json")) return false;
  uint64_t sequence = 0;
  const auto parsed = std::from_chars(name.data() + 6, name.data() + 26, sequence);
  return parsed.ec == std::errc{} && parsed.ptr == name.data() + 26 && sequence < kReadSpoolMaximumStates &&
         name == fmt::format("state-{:020}.json", sequence);
}
inline Result<std::vector<SpoolEntry>> spoolEntries(int directory, size_t maximum) {
  // openat(".") gives an independent directory offset. dup() would share the
  // previous scan's end offset with the persistent directory descriptor.
  SpoolFd scan(::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (scan.value < 0) return makeError(spoolIo("open spool scan").error());
  DIR *raw = ::fdopendir(scan.value);
  if (!raw) return makeError(spoolIo("scan spool directory").error());
  scan.release();
  std::unique_ptr<DIR, decltype(&::closedir)> entries(raw, &::closedir);
  std::vector<SpoolEntry> result;
  errno = 0;
  while (const auto *entry = ::readdir(entries.get())) {
    const std::string name(entry->d_name);
    if (name == "." || name == "..") {
      errno = 0;
      continue;
    }
    if (result.size() == maximum) return makeError(StatusCode::kInvalidFormat, "excessive spool directory entries");
    struct stat st {};
    if (::fstatat(directory, name.c_str(), &st, AT_SYMLINK_NOFOLLOW))
      return makeError(spoolIo("stat spool entry").error());
    if ((!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) || st.st_uid != ::geteuid() || (st.st_mode & 0077) ||
        st.st_size < 0)
      return makeError(StatusCode::kInvalidFormat, "unsafe spool entry type/ownership/permissions");
    result.push_back({name, S_ISDIR(st.st_mode), S_ISDIR(st.st_mode) ? 0 : uint64_t(st.st_size)});
    errno = 0;
  }
  if (errno) return makeError(spoolIo("read spool directory").error());
  return result;
}
inline Result<uint64_t> spoolJournalBytes(int directory) {
  CHECK_RESULT(entries, spoolEntries(directory, kReadSpoolMaximumStates + 66));
  uint64_t total = 0;
  for (const auto &entry : entries) {
    if (entry.directory || !spoolJournalName(entry.name) || entry.bytes > kReadSpoolEntryBytes)
      return makeError(StatusCode::kInvalidFormat, "unrecognized/excessive local read journal entry");
    total += entry.bytes;  // Bounded count and size above; aliases count separately.
  }
  return total;
}
inline EcReadDebt spoolDebt(const EcReadReceipt &receipt,
                            const EcFileRunRecord &record,
                            const std::optional<EcFileRunProgress> &p,
                            uint64_t bytes,
                            bool retiring = false) {
  EcReadDebt result;
  result.receipt = receipt;
  result.object = record.object;
  result.logicalFileBytes = bytes;
  result.retirementPending = retiring;
  if (p) {
    result.acquisitionIssued = p->acquisitionIssued;
    result.snapshotObserved = p->snapshotObserved;
    result.localComplete = p->localComplete;
    result.allPinsReleased = p->allPinsReleased();
    result.actualPins = p->actualPins;
    result.releasedMask = p->releasedMask;
    result.lastErrorCode = p->errorCode;
  }
  return result;
}
inline Result<Void> spoolOwnedRecord(const EcFileRunRecord &record, std::string_view cluster, const Uuid &ns) {
  RETURN_ON_ERROR(record.validate());
  if (record.kind != EcFileRunKind::RangeRead || record.cluster != cluster || record.owner.client != ns)
    return makeError(StatusCode::kTokenMismatch, "read spool record belongs to another cluster/namespace/kind");
  return Void{};
}
inline Result<bool> spoolExists(int directory, std::string_view name) {
  struct stat st {};
  if (!::fstatat(directory, std::string(name).c_str(), &st, AT_SYMLINK_NOFOLLOW)) return true;
  if (errno == ENOENT) return false;
  return makeError(spoolIo("locate spool entry").error());
}
}  // namespace hf3fs::client::ec::detail
