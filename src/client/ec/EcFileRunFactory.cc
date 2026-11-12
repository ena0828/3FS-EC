#include "EcFileRunFactory.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "detail/EcFileValidation.h"
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
Result<EcFileRunRecord> base(const meta::EcFileState &file,
                             const meta::EcOwner &owner,
                             std::string cluster,
                             uint64_t offset,
                             uint64_t length,
                             Uuid describe) {
  RETURN_ON_ERROR(file.layout.valid());
  if (file.object.incarnation != file.layout.incarnation || !file.epoch || owner.client.is_nil() || describe.is_nil())
    return makeError(StatusCode::kInvalidArg);
  EcFileRunRecord r;
  r.cluster = std::move(cluster);
  r.owner = owner;
  r.object = file.object;
  r.epoch = file.epoch;
  r.shardBytes = file.layout.shardBytes;
  r.offset = offset;
  r.length = length;
  r.describeRequest = describe;
  CHECK_RESULT(plan, planEcFileRead(r.shardBytes, offset, length));
  r.count = plan.count;
  for (size_t i = 0; i != r.count; ++i) r.slots[i].stripe = plan.slices[i].stripe;
  return r;
}
}  // namespace
Result<EcFileRunRecord> prepareEcFileRead(const meta::EcFileState &file,
                                          const meta::EcOwner &owner,
                                          std::string cluster,
                                          uint64_t offset,
                                          uint64_t length,
                                          Uuid describe) {
  CHECK_RESULT(r, base(file, owner, std::move(cluster), offset, length, describe));
  r.rangeId = Uuid::random();
  r.rangeRequest = Uuid::random();
  for (size_t i = 0; i != r.count; ++i) {
    r.slots[i].pin = Uuid::random();
    r.slots[i].acquireRequest = Uuid::random();
    r.slots[i].releaseRequest = Uuid::random();
  }
  RETURN_ON_ERROR(r.validate());
  return std::move(r);
}
Result<EcFileRunRecord> prepareEcFileAppend(const meta::EcFileState &file,
                                            const meta::EcOwner &owner,
                                            std::string cluster,
                                            uint64_t expectedEOF,
                                            std::string inputPath,
                                            std::span<const uint8_t> input,
                                            Uuid describe) {
  if (file.length != expectedEOF || !std::filesystem::path(inputPath).is_absolute())
    return makeError(StatusCode::kTokenMismatch, "expected EOF/input path differs from new append preparation");
  RETURN_ON_ERROR(planEcFileAppend(file.layout.shardBytes, expectedEOF, input.size()));
  CHECK_RESULT(r, base(file, owner, std::move(cluster), expectedEOF, input.size(), describe));
  r.kind = EcFileRunKind::AppendAt;
  r.appendId = Uuid::random();
  r.inputPath = std::move(inputPath);
  CHECK_RESULT(whole, detail::fileContentSha(input));
  r.contentSha256 = whole;
  const size_t size = size_t(r.shardBytes) * 10;
  for (size_t i = 0; i != r.count; ++i) {
    r.slots[i]
        .mutation = {Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random(), Uuid::random()};
    CHECK_RESULT(part, detail::fileContentSha(input.subspan(i * size, size)));
    r.slots[i].contentSha256 = part;
  }
  RETURN_ON_ERROR(r.validate());
  return std::move(r);
}
Result<EcFilePayload> readEcFileInput(EcFileClient &client, const std::filesystem::path &path) {
  Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat st {};
  if (fd.value < 0 || ::fstat(fd.value, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      uint64_t(st.st_size) > kEcFileMaxPayloadBytes)
    return makeError(StatusCode::kInvalidArg, "file input must be a bounded regular file");
  CHECK_RESULT(payload, client.allocatePayload(static_cast<size_t>(st.st_size)));
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
Result<Void> saveEcFileReadOutput(const std::filesystem::path &path, std::span<const uint8_t> bytes) {
  if (!path.is_absolute() || path.filename().empty() || path.filename() == "." || path.filename() == "..")
    return makeError(StatusCode::kInvalidArg, "read output requires an explicit new absolute path");
  Fd directory(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.value < 0) return makeError(StatusCode::kIOError);
  Fd fd(::openat(directory.value, path.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd.value < 0 || ::fchmod(fd.value, 0600))
    return makeError(StatusCode::kIOError, "read output must be a new private file");
  while (!bytes.empty()) {
    const auto count = ::write(fd.value, bytes.data(), bytes.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StatusCode::kIOError);
    bytes = bytes.subspan(static_cast<size_t>(count));
  }
  if (::fsync(fd.value) || ::fsync(directory.value))
    return makeError(StatusCode::kIOError, "read output could not be locally persisted");
  return Void{};
}
}  // namespace hf3fs::client::ec
