#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "EcFilePwriteJournal.h"
namespace hf3fs::client::ec {
namespace {
struct Fd {
  int value;
  explicit Fd(int v)
      : value(v) {}
  ~Fd() {
    if (value >= 0) ::close(value);
  }
};
}  // namespace
Result<EcFilePayload> readEcPwriteInput(EcFilePayloadBudget &budget, const std::filesystem::path &path) {
  if (!path.is_absolute() || path.string().find('\0') != std::string::npos) return makeError(StatusCode::kInvalidArg);
  Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat st {};
  if (fd.value < 0 || ::fstat(fd.value, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      uint64_t(st.st_size) > kEcFileMaxPayloadBytes)
    return makeError(StatusCode::kInvalidArg, "file input must be a bounded regular file");
  CHECK_RESULT(payload, budget.allocate(static_cast<size_t>(st.st_size)));
  size_t offset = 0;
  while (offset != payload.size()) {
    const auto count = ::read(fd.value, payload.bytes().data() + offset, payload.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StatusCode::kIOError, "input shortened or failed during read");
    offset += static_cast<size_t>(count);
  }
  char extra;
  ssize_t tail;
  do {
    tail = ::read(fd.value, &extra, 1);
  } while (tail < 0 && errno == EINTR);
  if (tail != 0) return makeError(StatusCode::kIOError, "input changed length");
  return std::move(payload);
}
}  // namespace hf3fs::client::ec
