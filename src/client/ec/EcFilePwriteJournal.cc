#include "EcFilePwriteJournal.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace hf3fs::client::ec {
namespace {
constexpr uint64_t kMaximumStates = 4096;
constexpr size_t kMaximumFileBytes = 256u << 10;
struct Fd {
  int value = -1;
  explicit Fd(int fd)
      : value(fd) {}
  ~Fd() {
    if (value >= 0) ::close(value);
  }
  int release() { return std::exchange(value, -1); }
};
Result<Void> io(const char *what) { return makeError(StatusCode::kIOError, fmt::format("{} (errno={})", what, errno)); }
Result<Void> privateRegular(int fd) {
  struct stat st {};
  if (::fstat(fd, &st)) return io("stat journal file");
  if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0077) || st.st_size < 0)
    return makeError(StatusCode::kInvalidFormat, "journal file must be an owner-only regular file");
  return Void{};
}
std::string stateName(uint64_t sequence) { return fmt::format("state-{:020}.json", sequence); }
Result<Void> writeAll(int fd, std::string_view bytes) {
  while (!bytes.empty()) {
    auto count = ::write(fd, bytes.data(), bytes.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return io("write journal");
    bytes.remove_prefix(static_cast<size_t>(count));
  }
  return Void{};
}
}  // namespace
EcFilePwriteJournal::~EcFilePwriteJournal() {
  if (lock_ >= 0) ::close(lock_);
  if (directory_ >= 0) ::close(directory_);
}
Result<std::unique_ptr<EcFilePwriteJournal>> EcFilePwriteJournal::create(const std::filesystem::path &path,
                                                                         EcPwriteRunRecord record) {
  return open(path, std::move(record));
}
Result<std::unique_ptr<EcFilePwriteJournal>> EcFilePwriteJournal::resume(const std::filesystem::path &path) {
  return open(path, std::nullopt);
}
Result<std::unique_ptr<EcFilePwriteJournal>> EcFilePwriteJournal::inspectExisting(const std::filesystem::path &path) {
  return open(path, std::nullopt, true);
}
Result<std::unique_ptr<EcFilePwriteJournal>> EcFilePwriteJournal::open(const std::filesystem::path &path,
                                                                       std::optional<EcPwriteRunRecord> initial, bool readOnly) {
  try {
    if (path.string().find('\0') != std::string::npos || !path.is_absolute() || path.filename().empty() ||
        path.filename() == "." || path.filename() == "..")
      return makeError(StatusCode::kInvalidArg, "file run requires an explicit absolute directory");
    std::optional<std::string> encoded;
    if (initial) {
      CHECK_RESULT(value, encodeEcPwriteRunRecord(*initial));
      encoded = std::move(value);
    }
    Fd parent(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (parent.value < 0) return makeError(io("open run parent").error());
    const auto name = path.filename().string();
    if (initial && ::mkdirat(parent.value, name.c_str(), 0700))
      return makeError(io("create new run directory").error());
    Fd directory(::openat(parent.value, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (directory.value < 0) return makeError(io("open run directory").error());
    struct stat st {};
    if (::fstat(directory.value, &st)) return makeError(io("stat run directory").error());
    if (!S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0077))
      return makeError(StatusCode::kInvalidFormat, "run directory must be owner-only");
    if (initial && (::fchmod(directory.value, 0700) || ::fsync(parent.value)))
      return makeError(io("persist new run directory").error());
    Fd lock(::openat(directory.value,
                     ".lock",
                     (readOnly ? O_RDONLY : (O_RDWR | O_CREAT)) | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                     0600));
    if (lock.value < 0) return makeError(io("open run lock").error());
    RETURN_ON_ERROR(privateRegular(lock.value));
    if (::flock(lock.value, LOCK_EX | LOCK_NB))
      return makeError(StorageClientCode::kResourceBusy, "file run is already owned");
    auto journal =
        std::unique_ptr<EcFilePwriteJournal>(new EcFilePwriteJournal(directory.release(), lock.release(), {}));
    journal->readOnly_ = readOnly;
    if (initial) {
      journal->record_ = std::move(*initial);
      RETURN_ON_ERROR(journal->writeNew("record.json", *encoded));
      return journal;
    }
    CHECK_RESULT(recordText, journal->read("record.json"));
    CHECK_RESULT(record, decodeEcPwriteRunRecord(recordText));
    journal->record_ = std::move(record);
    if (readOnly) journal->inspectionRecordBytes_ = std::move(recordText);
    uint64_t count = 0, maximum = 0;
    Fd duplicate(::dup(journal->directory_));
    if (duplicate.value < 0) return makeError(io("duplicate run directory").error());
    DIR *raw = ::fdopendir(duplicate.value);
    if (!raw) return makeError(io("scan run directory").error());
    duplicate.release();
    std::unique_ptr<DIR, decltype(&::closedir)> entries(raw, &::closedir);
    errno = 0;
    while (const auto *entry = ::readdir(entries.get())) {
      const std::string_view name(entry->d_name);
      if (name == "." || name == ".." || name == ".lock" || name == "record.json" || name.starts_with(".pending-")) {
        errno = 0;
        continue;
      }
      if (!name.starts_with("state-") || name.size() != 31 || !name.ends_with(".json"))
        return makeError(StatusCode::kInvalidFormat, "unrecognized file run entry");
      uint64_t sequence = 0;
      const auto parsed = std::from_chars(name.data() + 6, name.data() + 26, sequence);
      if (parsed.ec != std::errc{} || parsed.ptr != name.data() + 26 || name != stateName(sequence) ||
          ++count > kMaximumStates)
        return makeError(StatusCode::kInvalidFormat, "invalid/excessive file run sequence");
      maximum = std::max(maximum, sequence);
      errno = 0;
    }
    if (errno) return makeError(io("scan run entries").error());
    if (count && maximum != count - 1) return makeError(StatusCode::kInvalidFormat, "file run observation gap");
    for (uint64_t sequence = 0; sequence != count; ++sequence) {
      CHECK_RESULT(text, journal->read(stateName(sequence)));
      CHECK_RESULT(progress, decodeEcPwriteRunProgress(text));
      if (progress.sequence != sequence) return makeError(StatusCode::kInvalidFormat, "sequence/name mismatch");
      RETURN_ON_ERROR(progress.validate(journal->record_, journal->latest_ ? &*journal->latest_ : nullptr));
      journal->latest_ = std::move(progress);
      if (readOnly) journal->inspectionLatestStateBytes_ = std::move(text);
    }
    // Visibility after an uncertain local fsync is not enough. Reconfirm every
    // immutable file above and this directory before permitting another RPC.
    // Inspection is metadata-only and never grants permission for an RPC.
    if (!readOnly && (::fsync(journal->directory_) || ::fsync(parent.value)))
      return makeError(io("reconfirm run directory").error());
    return journal;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kIOError);
  }
}
Result<std::string> EcFilePwriteJournal::read(std::string_view name) const {
  Fd fd(::openat(directory_, std::string(name).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (fd.value < 0) return makeError(io("open journal entry").error());
  RETURN_ON_ERROR(privateRegular(fd.value));
  struct stat st {};
  if (::fstat(fd.value, &st)) return makeError(io("stat journal length").error());
  if (uint64_t(st.st_size) > kMaximumFileBytes) return makeError(StatusCode::kInvalidFormat, "journal entry too large");
  std::string text(static_cast<size_t>(st.st_size), '\0');
  size_t offset = 0;
  while (offset != text.size()) {
    const auto count = ::read(fd.value, text.data() + offset, text.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(io("read journal entry").error());
    offset += static_cast<size_t>(count);
  }
  char trailing = 0;
  ssize_t tail;
  do {
    tail = ::read(fd.value, &trailing, 1);
  } while (tail < 0 && errno == EINTR);
  if (tail != 0) return makeError(StatusCode::kInvalidFormat, "journal entry changed length");
  if (!readOnly_ && ::fsync(fd.value)) return makeError(io("reconfirm immutable journal file").error());
  return text;
}
Result<Void> EcFilePwriteJournal::writeNew(std::string_view name, std::string_view bytes) {
  const auto temporary = fmt::format(".pending-{}", Uuid::random().toHexString());
  Fd fd(::openat(directory_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd.value < 0) return io("create journal temporary");
  if (::fchmod(fd.value, 0600)) return io("set journal file permissions");
  RETURN_ON_ERROR(writeAll(fd.value, bytes));
  if (::fsync(fd.value)) return io("sync journal entry");
  if (::linkat(directory_, temporary.c_str(), directory_, std::string(name).c_str(), 0))
    return io("publish journal entry exclusively");
  if (::unlinkat(directory_, temporary.c_str(), 0)) return io("unlink own temporary name");
  if (::fsync(directory_)) return io("sync journal directory");
  return Void{};
}
Result<Void> EcFilePwriteJournal::append(EcPwriteRunProgress progress) {
  if (readOnly_) return makeError(StatusCode::kInvalidArg, "inspection cannot append journal state");
  if (poisoned_)
    return makeError(StatusCode::kIOError, "file run requires close and explicit resume after persistence error");
  try {
    if (latest_ && latest_->sequence >= kMaximumStates - 1)
      return makeError(StatusCode::kInvalidArg, "file run observation limit");
    progress.sequence = latest_ ? latest_->sequence + 1 : 0;
    RETURN_ON_ERROR(progress.validate(record_, latest_ ? &*latest_ : nullptr));
    CHECK_RESULT(encoded, encodeEcPwriteRunProgress(progress));
    poisoned_ = true;  // Any failure after publication may have left a new name.
    auto result = writeNew(stateName(progress.sequence), encoded);
    if (!result) return makeError(std::move(result.error()));
    latest_ = std::move(progress);
    poisoned_ = false;
    return Void{};
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kIOError);
  }
}
}  // namespace hf3fs::client::ec
