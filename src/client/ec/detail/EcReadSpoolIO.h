#pragma once

#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/json.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "client/ec/EcReadSpool.h"

namespace hf3fs::client::ec::detail {
inline constexpr size_t kReadSpoolEntryBytes = 160u << 10;
inline constexpr uint64_t kReadSpoolAttemptBytes = uint64_t{32} * kReadSpoolEntryBytes;
inline constexpr uint64_t kReadSpoolMaximumStates = 4096;

struct SpoolFd {
  int value = -1;
  explicit SpoolFd(int fd = -1)
      : value(fd) {}
  ~SpoolFd() {
    if (value >= 0) ::close(value);
  }
  SpoolFd(const SpoolFd &) = delete;
  SpoolFd &operator=(const SpoolFd &) = delete;
  int release() noexcept { return std::exchange(value, -1); }
};
inline Result<Void> spoolIo(std::string_view what) {
  return makeError(StatusCode::kIOError, fmt::format("{} (errno={})", what, errno));
}
inline Result<struct stat> spoolStat(int fd, bool directory) {
  struct stat st {};
  if (::fstat(fd, &st)) return makeError(spoolIo("stat EC read spool entry").error());
  if ((directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) || st.st_uid != ::geteuid() || (st.st_mode & 0077) ||
      st.st_size < 0)
    return makeError(StatusCode::kInvalidFormat, "EC read spool entry must be private and owned by this process UID");
  return st;
}
inline Result<std::string> spoolRead(int directory, std::string_view name, size_t maximum) {
  SpoolFd fd(::openat(directory, std::string(name).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (fd.value < 0) return makeError(spoolIo("open EC read spool entry").error());
  CHECK_RESULT(st, spoolStat(fd.value, false));
  if (uint64_t(st.st_size) > maximum) return makeError(StatusCode::kInvalidFormat, "EC read spool entry exceeds bound");
  std::string result(static_cast<size_t>(st.st_size), '\0');
  size_t offset = 0;
  while (offset < result.size()) {
    const auto count = ::read(fd.value, result.data() + offset, result.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(spoolIo("read EC read spool entry").error());
    offset += static_cast<size_t>(count);
  }
  char extra = 0;
  ssize_t end;
  do {
    end = ::read(fd.value, &extra, 1);
  } while (end < 0 && errno == EINTR);
  if (end != 0) return makeError(StatusCode::kInvalidFormat, "EC read spool entry changed length");
  if (::fsync(fd.value)) return makeError(spoolIo("reconfirm EC read spool entry").error());
  return result;
}
inline Result<Void> spoolWriteAll(int fd, std::string_view value) {
  while (!value.empty()) {
    const auto count = ::write(fd, value.data(), value.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return spoolIo("write EC read spool entry");
    value.remove_prefix(static_cast<size_t>(count));
  }
  return Void{};
}
inline Result<uint64_t> spoolUnsigned(const folly::dynamic &value) {
  if (!value.isString()) return makeError(StatusCode::kInvalidFormat, "spool integer must be a decimal string");
  const auto &text = value.getString();
  uint64_t parsed = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || std::to_string(parsed) != text)
    return makeError(StatusCode::kInvalidFormat, "noncanonical spool integer");
  return parsed;
}
inline Result<Uuid> spoolUuid(const folly::dynamic &value) {
  if (!value.isString()) return makeError(StatusCode::kInvalidFormat);
  CHECK_RESULT(uuid, Uuid::fromHexString(value.getString()));
  if (uuid.is_nil() || uuid.toHexString() != value.getString()) return makeError(StatusCode::kInvalidFormat);
  return uuid;
}
inline std::string spoolRunName(uint64_t sequence, bool retiring = false) {
  return fmt::format("{}-{:020}", retiring ? "retired" : "run", sequence);
}
inline Result<uint64_t> spoolRunSequence(std::string_view name, bool retiring = false) {
  const auto prefix = retiring ? std::string_view("retired-") : std::string_view("run-");
  if (!name.starts_with(prefix) || name.size() != prefix.size() + 20)
    return makeError(StatusCode::kInvalidFormat, "noncanonical EC read run name");
  uint64_t value = 0;
  const auto result = std::from_chars(name.data() + prefix.size(), name.data() + name.size(), value);
  if (result.ec != std::errc{} || result.ptr != name.data() + name.size() || !value ||
      spoolRunName(value, retiring) != name)
    return makeError(StatusCode::kInvalidFormat);
  return value;
}
}  // namespace hf3fs::client::ec::detail
