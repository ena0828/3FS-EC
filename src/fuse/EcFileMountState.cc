#include "EcFileMountState.h"

#include <cerrno>
#include <charconv>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace hf3fs::fuse {
namespace {
struct Fd {
  int value = -1;
  explicit Fd(int f)
      : value(f) {}
  ~Fd() {
    if (value >= 0) ::close(value);
  }
  int take() { return std::exchange(value, -1); }
};
Result<Void> io() { return makeError(StatusCode::kIOError, "mode4 mount state I/O unconfirmed"); }
Result<Void> regular(int fd, size_t limit) {
  struct stat s {};
  if (::fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_uid != ::geteuid() || (s.st_mode & 0077) || s.st_size < 0 ||
      uint64_t(s.st_size) > limit)
    return makeError(StatusCode::kInvalidFormat);
  return Void{};
}
bool component(std::string_view n) {
  return !n.empty() && n.size() <= 128 && n != "." && n != ".." && n.find('/') == n.npos && n.find('\0') == n.npos;
}
Result<Void> privateDirectory(int fd) {
  struct stat s {};
  if (::fstat(fd, &s) || !S_ISDIR(s.st_mode) || s.st_uid != ::geteuid() || (s.st_mode & 0077))
    return makeError(StatusCode::kInvalidFormat);
  return Void{};
}
Result<std::string> bytes(int fd) {
  RETURN_ON_ERROR(regular(fd, 256u << 10));
  struct stat s {};
  if (::fstat(fd, &s)) return makeError(io().error());
  std::string out(size_t(s.st_size), '\0');
  size_t n = 0;
  while (n < out.size()) {
    auto got = ::read(fd, out.data() + n, out.size() - n);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) return makeError(io().error());
    n += size_t(got);
  }
  char more;
  ssize_t last;
  do {
    last = ::read(fd, &more, 1);
  } while (last < 0 && errno == EINTR);
  if (last || ::fsync(fd)) return makeError(io().error());
  return out;
}
Result<uint64_t> number(std::string_view text) {
  uint64_t n = 0;
  auto r = std::from_chars(text.data(), text.data() + text.size(), n);
  if (text.empty() || r.ec != std::errc{} || r.ptr != text.data() + text.size() || std::to_string(n) != text)
    return makeError(StatusCode::kInvalidFormat);
  return n;
}
Result<Void> operationName(std::string_view n) {
  auto dash = n.find('-');
  if (dash == n.npos) return makeError(StatusCode::kInvalidFormat);
  const auto kind = n.substr(0, dash);
  if (kind != "write" && kind != "read" && kind != "truncate" && kind != "sync")
    return makeError(StatusCode::kInvalidFormat);
  CHECK_RESULT(id, number(n.substr(dash + 1)));
  (void)id;
  return Void{};
}
Result<Void> sessionName(std::string_view n) {
  if (!n.starts_with("session-")) return makeError(StatusCode::kInvalidFormat);
  CHECK_RESULT(id, Uuid::fromHexString(n.substr(8)));
  if (id.is_nil() || id.toHexString() != n.substr(8)) return makeError(StatusCode::kInvalidFormat);
  return Void{};
}
Result<std::vector<std::string>> indexNames(int fd, size_t maximum) {
  Fd copy(::openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (copy.value < 0) return makeError(io().error());
  DIR *raw = ::fdopendir(copy.value);
  if (!raw) return makeError(io().error());
  copy.take();
  std::unique_ptr<DIR, decltype(&::closedir)> dir(raw, &::closedir);
  std::vector<std::string> out;
  size_t visited = 0;
  errno = 0;
  while (auto *e = ::readdir(dir.get())) {
    std::string_view n(e->d_name);
    if (++visited > maximum * 2 + 64) return makeError(StatusCode::kInvalidFormat);
    if (n == "." || n == ".." || n.starts_with(".pending-")) {
      errno = 0;
      continue;
    }
    if (!component(n) || out.size() >= maximum) return makeError(StatusCode::kInvalidFormat);
    out.emplace_back(n);
    errno = 0;
  }
  if (errno) return makeError(io().error());
  return out;
}

}  // namespace
Result<Void> validateEcMountOpenFlags(int flags, bool creating) {
  if ((flags & O_ACCMODE) > O_RDWR || (flags & (O_APPEND | O_SYNC | O_DSYNC | O_PATH)) ||
      ((flags & O_TMPFILE) == O_TMPFILE) || (!creating && (flags & (O_CREAT | O_EXCL))) ||
      ((flags & O_TRUNC) && (flags & O_ACCMODE) == O_RDONLY))
    return makeError(StatusCode::kNotImplemented, "mode4 open flag needs an unsupported atomic/durability contract");
  return Void{};
}
EcFileMountState::~EcFileMountState() {
  if (lockFd_ >= 0) ::close(lockFd_);
  if (directoryFd_ >= 0) ::close(directoryFd_);
}
Result<std::shared_ptr<EcFileMountState>> EcFileMountState::open(Config c) {
  if (!c.directory.is_absolute() || c.directory != c.directory.lexically_normal() ||
      c.directory.string().find('\0') != std::string::npos || c.cluster.empty() || c.cluster.size() > 256 ||
      c.cluster.find('\0') != std::string::npos || !c.maximumRuns || c.maximumRuns > 4096 ||
      c.maximumInputBytes < (uint64_t{32} << 20) || c.maximumInputBytes > (uint64_t{1} << 40))
    return makeError(StatusCode::kInvalidArg);
  Fd parent(::open(c.directory.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (parent.value < 0) return makeError(io().error());
  RETURN_ON_ERROR(privateDirectory(parent.value));
  if (c.create && ::mkdirat(parent.value, c.directory.filename().c_str(), 0700)) return makeError(io().error());
  Fd dir(::openat(parent.value, c.directory.filename().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (dir.value < 0) return makeError(io().error());
  RETURN_ON_ERROR(privateDirectory(dir.value));
  Fd lock(::openat(dir.value, ".lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
  if (lock.value < 0) return makeError(io().error());
  RETURN_ON_ERROR(regular(lock.value, 0));
  if (::flock(lock.value, LOCK_EX | LOCK_NB)) return makeError(StorageClientCode::kResourceBusy);
  Uuid ns = c.expectedNamespace.is_nil() ? Uuid::random() : c.expectedNamespace;
  auto state = std::shared_ptr<EcFileMountState>(new EcFileMountState(c, dir.take(), lock.take(), ns));
  if (c.create) {
    RETURN_ON_ERROR(state->write(c.directory, "namespace", ns.toHexString() + "\n" + c.cluster));
    if (::mkdirat(state->directoryFd_, "active-sessions", 0700)) return makeError(io().error());
    RETURN_ON_ERROR(state->write(c.directory, "index-version", "2\n"));
  } else {
    CHECK_RESULT(header, state->read(c.directory, "namespace"));
    if (!header || header->size() < 33) return makeError(StatusCode::kInvalidFormat);
    const auto split = header->find('\n');
    if (split == std::string::npos || header->substr(split + 1) != c.cluster)
      return makeError(StatusCode::kTokenMismatch);
    CHECK_RESULT(found, Uuid::fromHexString(std::string_view(*header).substr(0, split)));
    if (found.is_nil() || found.toHexString() != header->substr(0, split) ||
        (!c.expectedNamespace.is_nil() && found != c.expectedNamespace))
      return makeError(StatusCode::kTokenMismatch);
    state->namespace_ = found;
  }

  CHECK_RESULT(format, state->read(c.directory, "index-version"));
  if (!format || *format != "2\n")
    return makeError(StatusCode::kInvalidFormat, "mode4 mount active-index format 2 required; old state is preserved");
  CHECK_RESULT(all, state->sessions());
  state->runs_ = all.size();
  for (const auto &path : all) {
    CHECK_RESULT(ops, state->operations(path));
    for (const auto &op : ops) {
      if (op.inputBytes > c.maximumInputBytes - state->inputBytes_) return makeError(StorageClientCode::kResourceBusy);
      state->inputBytes_ += op.inputBytes;
    }
  }
  if (::fsync(state->directoryFd_) || ::fsync(parent.value)) return makeError(io().error());
  return state;
}
Result<int> EcFileMountState::directory(const std::filesystem::path &where) const {
  if (where.lexically_normal() != where) return makeError(StatusCode::kInvalidArg);
  Fd fd(::openat(directoryFd_, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (fd.value < 0) return makeError(io().error());
  if (where == config_.directory) return fd.take();
  const bool operations =
      where.filename() == "active-operations" && where.parent_path().parent_path() == config_.directory;
  const auto name = (operations ? where.parent_path() : where).filename().string();
  if ((!operations && where.parent_path() != config_.directory) || (name != "active-sessions" && !sessionName(name)))
    return makeError(StatusCode::kInvalidArg);
  if (operations) RETURN_ON_ERROR(sessionName(name));
  Fd child(::openat(fd.value, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (child.value < 0) return makeError(io().error());
  RETURN_ON_ERROR(privateDirectory(child.value));
  if (!operations) return child.take();
  Fd index(::openat(child.value, "active-operations", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (index.value < 0) return makeError(io().error());
  RETURN_ON_ERROR(privateDirectory(index.value));
  return index.take();
}
Result<std::vector<std::filesystem::path>> EcFileMountState::sessions() const {
  const auto index = config_.directory / "active-sessions";
  CHECK_RESULT(raw, directory(index));
  Fd fd(raw);
  CHECK_RESULT(names, indexNames(fd.value, config_.maximumRuns));
  std::vector<std::filesystem::path> out;
  for (const auto &n : names) {
    RETURN_ON_ERROR(sessionName(n));
    CHECK_RESULT(value, read(index, n));
    if (!value || *value != "2\n" + n) return makeError(StatusCode::kInvalidFormat);
    const auto path = config_.directory / n;
    CHECK_RESULT(child, directory(path));
    Fd checked(child);
    out.push_back(path);
  }
  if (::fsync(fd.value)) return makeError(io().error());
  return out;
}
Result<std::vector<EcFileMountState::Operation>> EcFileMountState::operations(
    const std::filesystem::path &session) const {
  if (session.parent_path() != config_.directory) return makeError(StatusCode::kInvalidArg);
  RETURN_ON_ERROR(sessionName(session.filename().string()));
  CHECK_RESULT(next, read(session, "next-operation"));
  if (!next) return makeError(StatusCode::kInvalidFormat);
  CHECK_RESULT(high, number(*next));
  const auto index = session / "active-operations";
  CHECK_RESULT(raw, directory(index));
  Fd fd(raw);
  CHECK_RESULT(names, indexNames(fd.value, 64));
  std::vector<Operation> out;
  for (const auto &n : names) {
    RETURN_ON_ERROR(operationName(n));
    CHECK_RESULT(id, number(std::string_view(n).substr(n.find('-') + 1)));
    if (id >= high) return makeError(StatusCode::kInvalidFormat);
    CHECK_RESULT(value, read(index, n));
    if (!value) return makeError(StatusCode::kInvalidFormat);
    CHECK_RESULT(charge, number(*value));
    if ((n.starts_with("write-") ? (!charge || charge > (uint64_t{32} << 20)) : charge != 0))
      return makeError(StatusCode::kInvalidFormat);
    out.push_back({n, charge});
  }
  if (::fsync(fd.value)) return makeError(io().error());
  return out;
}
Result<std::filesystem::path> EcFileMountState::reserve(std::string_view kind) {
  if (poisoned_ || kind != "session" || runs_ >= config_.maximumRuns)
    return makeError(StorageClientCode::kResourceBusy);
  const auto name = "session-" + Uuid::random().toHexString();
  const auto path = config_.directory / name;
  if (::mkdirat(directoryFd_, name.c_str(), 0700)) return makeError(io().error());
  poisoned_ = true;
  if (::fsync(directoryFd_)) return makeError(io().error());
  poisoned_ = false;
  CHECK_RESULT(raw, directory(path));
  Fd fd(raw);
  if (::mkdirat(fd.value, "active-operations", 0700)) return makeError(io().error());
  RETURN_ON_ERROR(write(path, "next-operation", "0"));
  RETURN_ON_ERROR(write(config_.directory / "active-sessions", name, "2\n" + name));
  ++runs_;
  return path;
}
Result<std::filesystem::path> EcFileMountState::reserveOperation(const std::filesystem::path &session,
                                                                 std::string_view kind,
                                                                 uint64_t input) {
  if (poisoned_) return makeError(StorageClientCode::kResourceBusy);
  RETURN_ON_ERROR(operationName(std::string(kind) + "-0"));
  if ((kind == "write" ? (!input || input > (uint64_t{32} << 20)) : input != 0))
    return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(held, read(config_.directory / "active-sessions", session.filename().string()));
  if (!held || *held != "2\n" + session.filename().string()) return makeError(StatusCode::kTokenStale);
  CHECK_RESULT(ops, operations(session));
  if (ops.size() >= 64 || input > config_.maximumInputBytes - inputBytes_)
    return makeError(StorageClientCode::kResourceBusy);
  // This is point-in-time headroom, not a bound on retained historical bytes.
  // Leave journal/recovery space even when a new payload would fit exactly.
  struct statvfs space {};
  if (::fstatvfs(directoryFd_, &space)) return makeError(io().error());
  constexpr uint64_t reserveBytes = 4u << 20;
  const auto unit = uint64_t(space.f_frsize);
  const auto needed = input + reserveBytes;
  if (!unit || uint64_t(space.f_bavail) < needed / unit + (needed % unit != 0))
    return makeError(StorageClientCode::kNoSpace);
  CHECK_RESULT(text, read(session, "next-operation"));
  if (!text) return makeError(StatusCode::kInvalidFormat);
  CHECK_RESULT(id, number(*text));
  if (id == UINT64_MAX) return makeError(StorageClientCode::kResourceBusy);
  // Persist monotonic high-water BEFORE publishing the active identity. Gaps
  // are harmless; no prior operation name may ever be allocated again.
  RETURN_ON_ERROR(publish(session, "next-operation", std::to_string(id + 1), true));
  const auto name = std::string(kind) + "-" + std::to_string(id);
  RETURN_ON_ERROR(write(session / "active-operations", name, std::to_string(input)));
  inputBytes_ += input;
  return session / name;
}
Result<Void> EcFileMountState::retainEvidence(const std::filesystem::path &where,
                                              std::string_view name,
                                              std::string_view evidence) {
  if (evidence.empty() || poisoned_) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(previous, read(where, name));
  if (previous) {
    if (*previous != evidence) return makeError(StatusCode::kTokenMismatch);
    return Void{};
  }
  return write(where, name, evidence);
}
Result<Void> EcFileMountState::eraseIndex(const std::filesystem::path &where, std::string_view name) {
  if (poisoned_ || !component(name)) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(raw, directory(where));
  Fd fd(raw);
  poisoned_ = true;
  if (::unlinkat(fd.value, std::string(name).c_str(), 0)) return io();
  if (std::exchange(failNextIndexSyncForTest_, false) || ::fsync(fd.value)) return io();
  poisoned_ = false;
  return Void{};
}
Result<Void> EcFileMountState::archiveOperation(const std::filesystem::path &session,
                                                std::string_view name,
                                                std::string_view evidence) {
  RETURN_ON_ERROR(operationName(name));
  CHECK_RESULT(marker, read(session / "active-operations", name));
  // A replay with an already removed marker may verify the original evidence,
  // but never decrement counters for the same operation twice.
  if (!marker) {
    CHECK_RESULT(old, read(session, "terminal-" + std::string(name)));
    if (!old || *old != evidence) return makeError(StatusCode::kTokenMismatch);
    return Void{};
  }
  CHECK_RESULT(charge, number(*marker));
  if (charge > inputBytes_) return makeError(StatusCode::kDataCorruption);
  RETURN_ON_ERROR(retainEvidence(session, "terminal-" + std::string(name), evidence));
  RETURN_ON_ERROR(eraseIndex(session / "active-operations", name));
  inputBytes_ -= charge;
  return Void{};
}
Result<Void> EcFileMountState::archiveSession(const std::filesystem::path &session, std::string_view evidence) {
  CHECK_RESULT(ops, operations(session));
  if (!ops.empty()) return makeError(StorageClientCode::kResourceBusy);
  const auto name = session.filename().string();
  CHECK_RESULT(marker, read(config_.directory / "active-sessions", name));
  if (!marker) {
    CHECK_RESULT(old, read(session, "terminal-session"));
    if (!old || *old != evidence) return makeError(StatusCode::kTokenMismatch);
    return Void{};
  }
  if (!runs_ || *marker != "2\n" + name) return makeError(StatusCode::kDataCorruption);
  RETURN_ON_ERROR(retainEvidence(session, "terminal-session", evidence));
  RETURN_ON_ERROR(eraseIndex(config_.directory / "active-sessions", name));
  --runs_;
  return Void{};
}
Result<Void> EcFileMountState::write(const std::filesystem::path &where,
                                     std::string_view name,
                                     std::string_view content) {
  return publish(where, name, content, false);
}
Result<Void> EcFileMountState::publish(const std::filesystem::path &where,
                                       std::string_view name,
                                       std::string_view content,
                                       bool replace) {
  if (poisoned_ || !component(name) || content.size() > 256u * 1024 || (replace && name != "next-operation"))
    return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(raw, directory(where));
  Fd dir(raw);
  const auto tmp = ".pending-" + Uuid::random().toHexString();
  Fd out(::openat(dir.value, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (out.value < 0) return io();
  poisoned_ = true;
  if (::fchmod(out.value, 0600)) return io();
  while (!content.empty()) {
    auto n = ::write(out.value, content.data(), content.size());
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return io();
    content.remove_prefix(size_t(n));
  }
  if (::fsync(out.value)) return io();
  if (replace) {
    if (::renameat(dir.value, tmp.c_str(), dir.value, std::string(name).c_str())) return io();
  } else if (::linkat(dir.value, tmp.c_str(), dir.value, std::string(name).c_str(), 0) ||
             ::unlinkat(dir.value, tmp.c_str(), 0))
    return io();
  if (::fsync(dir.value)) return io();
  poisoned_ = false;
  return Void{};
}
Result<std::optional<std::string>> EcFileMountState::read(const std::filesystem::path &where,
                                                          std::string_view name) const {
  if (!component(name)) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(raw, directory(where));
  Fd dir(raw);
  Fd input(::openat(dir.value, std::string(name).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (input.value < 0) {
    if (errno == ENOENT) return std::nullopt;
    return makeError(io().error());
  }
  CHECK_RESULT(value, bytes(input.value));
  if (::fsync(dir.value)) return makeError(io().error());
  return std::optional<std::string>{std::move(value)};
}

}  // namespace hf3fs::fuse
