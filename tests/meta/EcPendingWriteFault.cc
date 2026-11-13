#include "EcPendingWriteFault.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace hf3fs::test::ec_pending {
namespace {
enum class Mode { Off, Capture, Fail };
struct State {
  std::mutex mutex;
  Mode mode = Mode::Off;
  std::set<std::pair<uint64_t, uint64_t>> allowed;
  std::string bytes;
  Observation result;
};
constinit std::atomic<bool> enabled{false};
constinit std::atomic<uint64_t> interceptionErrors{0};
State &state() {
  static State value;
  return value;
}
void require(bool valid, const char *message) {
  if (!valid) throw std::runtime_error(message);
}
}  // namespace

void captureNext(const std::filesystem::path &directory, std::string bytes) {
  require(!bytes.empty(), "pending-write capture requires exact bytes");
  require(std::filesystem::canonical(directory) == directory, "non-canonical data class path");
  std::set<std::pair<uint64_t, uint64_t>> allowed;
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    const auto name = entry.path().filename().string();
    require(name.size() == 2 && name.find_first_not_of("0123456789ABCDEF") == std::string::npos,
            "unexpected allocator data file");
    struct stat info {};
    require(::lstat(entry.path().c_str(), &info) == 0 && S_ISREG(info.st_mode) &&
                info.st_uid == ::geteuid() && info.st_nlink == 1,
            "allocator data file is not owned regular storage");
    require(allowed.emplace(info.st_dev, info.st_ino).second, "duplicate allocator data inode");
  }
  require(allowed.size() == 256, "allocator data file set differs");
  auto &value = state();
  std::lock_guard lock(value.mutex);
  require(value.mode == Mode::Off && !enabled.load(), "pending-write interception is already armed");
  value.allowed = std::move(allowed);
  value.bytes = std::move(bytes);
  value.result = {};
  interceptionErrors.store(0);
  value.mode = Mode::Capture;
  enabled.store(true);
}

void failNext(const Observation &first, uint64_t blockBytes, std::string bytes) {
  require(first.captures == 1 && first.failures == 0 && !bytes.empty() && bytes.size() == blockBytes &&
              first.offset <= uint64_t(std::numeric_limits<int64_t>::max()) - blockBytes,
          "missing exact first-block call capture");
  auto &value = state();
  std::lock_guard lock(value.mutex);
  require(value.mode == Mode::Off && !enabled.load() && value.result.device == first.device &&
              value.result.inode == first.inode && value.result.offset == first.offset &&
              value.result.captures == 1 && value.result.failures == 0,
          "capture changed before pending-write fault");
  value.bytes = std::move(bytes);
  value.result.offset += blockBytes;
  value.mode = Mode::Fail;
  enabled.store(true);
}

Observation observation() {
  auto &value = state();
  std::lock_guard lock(value.mutex);
  auto result = value.result;
  result.interceptionErrors = interceptionErrors.load();
  return result;
}
void reset() {
  auto &value = state();
  std::lock_guard lock(value.mutex);
  enabled.store(false);
  value.mode = Mode::Off;
  value.bytes.clear();
  value.allowed.clear();
}

// All nonmatching calls pass through without changing their incoming errno.
// No allocation, filesystem path lookup, callbacks, or recursive I/O occurs
// while handling the actual matching write. The caller still owns the fd.
bool intercept(int fd, const void *buffer, size_t count, off_t offset) {
  if (!enabled.load()) return false;
  auto &value = state();
  std::lock_guard lock(value.mutex);
  if (value.mode == Mode::Off || offset < 0 || count != value.bytes.size())
    return false;
  struct stat info {};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) return false;
  const std::pair<uint64_t, uint64_t> identity{info.st_dev, info.st_ino};
  if (value.mode == Mode::Capture ? !value.allowed.contains(identity)
                                 : identity != std::pair{value.result.device, value.result.inode} ||
                                       uint64_t(offset) != value.result.offset)
    return false;
  if (std::memcmp(buffer, value.bytes.data(), count) != 0) return false;
  if (value.mode == Mode::Capture) {
    value.result.device = identity.first;
    value.result.inode = identity.second;
    value.result.offset = offset;
    ++value.result.captures;
    value.mode = Mode::Off;
    enabled.store(false);
    return false;
  }
  ++value.result.failures;
  value.mode = Mode::Off;
  enabled.store(false);
  return true;
}
bool safeIntercept(int fd, const void *bytes, size_t count, off_t offset) noexcept {
  try {
    return intercept(fd, bytes, count, offset);
  } catch (...) {
    // Never unwind a C++ exception through Rust/libc. This is a failed test
    // seam, not a claimed injected write: the fixture requires this count=0.
    interceptionErrors.fetch_add(1);
    enabled.store(false);
    return true;
  }
}
}  // namespace hf3fs::test::ec_pending

// GNU/lld --wrap rewrites only the test_meta executable's undefined references.
// Rust's static FileExt::write_at calls pwrite64 on this Linux 64-bit target.
// Both spellings are covered; real shared-library internals are not claimed.
static_assert(sizeof(off_t) == sizeof(int64_t));
extern "C" ssize_t __real_pwrite(int, const void *, size_t, off_t);
extern "C" ssize_t __real_pwrite64(int, const void *, size_t, off_t);
extern "C" ssize_t __wrap_pwrite(int fd, const void *bytes, size_t count, off_t offset) {
  const int saved = errno;
  if (hf3fs::test::ec_pending::safeIntercept(fd, bytes, count, offset)) {
    errno = EIO;
    return -1;
  }
  errno = saved;
  return __real_pwrite(fd, bytes, count, offset);
}
extern "C" ssize_t __wrap_pwrite64(int fd, const void *bytes, size_t count, off_t offset) {
  const int saved = errno;
  if (hf3fs::test::ec_pending::safeIntercept(fd, bytes, count, offset)) {
    errno = EIO;
    return -1;
  }
  errno = saved;
  return __real_pwrite64(fd, bytes, count, offset);
}
