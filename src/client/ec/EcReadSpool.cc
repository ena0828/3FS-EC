#include "EcReadSpool.h"

#include <folly/ScopeGuard.h>
#include <limits>
#include <sys/file.h>

#include "detail/EcReadSpoolIO.h"

namespace hf3fs::client::ec {
using namespace detail;
namespace {
Result<Void> validLimits(const EcReadSpool::Limits &limits) {
  if (!limits.maximumRetainedRuns || limits.maximumRetainedRuns > 1024 || !limits.maximumOutstandingRuns ||
      limits.maximumOutstandingRuns > limits.maximumRetainedRuns ||
      limits.maximumLogicalFileBytes < kReadSpoolAttemptBytes || limits.maximumLogicalFileBytes > (uint64_t{16} << 30))
    return makeError(StatusCode::kInvalidArg, "invalid bounded EC read spool limits");
  return Void{};
}
std::string identityJson(std::string_view cluster, const Uuid &id) {
  const folly::dynamic value =
      folly::dynamic::object("version", "1")("cluster", std::string(cluster))("client_namespace", id.toHexString());
  return folly::toJson(value);
}
std::string counterJson(uint64_t next) {
  const folly::dynamic value = folly::dynamic::object("next_sequence", std::to_string(next));
  return folly::toJson(value);
}
}  // namespace

EcReadSpool::~EcReadSpool() {
  if (lock_ >= 0) ::close(lock_);
  if (directory_ >= 0) ::close(directory_);
}
Result<EcReadSpoolSnapshot> EcReadSpool::inspectExclusive() { return inspectExclusiveImpl(nullptr, nullptr); }
Result<EcReadSpoolSnapshot> EcReadSpool::inspectExclusiveImpl(void (*afterAttach)(void *), void *context) {
  bool unattached = false;
  if (!attached_.compare_exchange_strong(unattached, true))
    return makeError(StorageClientCode::kResourceBusy, "local inspection requires an unattached exclusive spool");
  auto release = folly::makeGuard([this]() noexcept { attached_.store(false); });
  if (afterAttach) afterAttach(context);  // Private deterministic exception/competition seam.
  return inspect();
}
Result<std::shared_ptr<EcReadSpool>> EcReadSpool::create(const std::filesystem::path &path,
                                                         std::string cluster,
                                                         Limits limits) {
  return load(path, std::move(cluster), limits, true);
}
Result<std::shared_ptr<EcReadSpool>> EcReadSpool::open(const std::filesystem::path &path,
                                                       std::string cluster,
                                                       Limits limits) {
  return load(path, std::move(cluster), limits, false);
}
Result<std::shared_ptr<EcReadSpool>> EcReadSpool::load(const std::filesystem::path &path,
                                                       std::string cluster,
                                                       Limits limits,
                                                       bool create,
                                                       OwnershipHook ownershipHook,
                                                       void *hookContext) {
  try {
    RETURN_ON_ERROR(validLimits(limits));
    if (!path.is_absolute() || path.filename().empty() || path.filename() == "." || path.filename() == ".." ||
        path != path.lexically_normal() || path.native().find('\0') != std::string::npos || cluster.empty() ||
        cluster.size() > 1024 || cluster.find('\0') != std::string::npos)
      return makeError(StatusCode::kInvalidArg, "spool requires explicit normalized absolute path and cluster");
    SpoolFd parent(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (parent.value < 0) return makeError(spoolIo("open EC read spool parent").error());
    if (create && ::mkdirat(parent.value, path.filename().c_str(), 0700))
      return makeError(spoolIo("create new EC read spool directory").error());
    SpoolFd directory(::openat(parent.value, path.filename().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (directory.value < 0) return makeError(spoolIo("open EC read spool directory").error());
    RETURN_ON_ERROR(spoolStat(directory.value, true));
    if (create && (::fchmod(directory.value, 0700) || ::fsync(parent.value)))
      return makeError(spoolIo("persist EC read spool directory").error());
    SpoolFd lock(::openat(directory.value, ".lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
    if (lock.value < 0) return makeError(spoolIo("open EC read spool lock").error());
    RETURN_ON_ERROR(spoolStat(lock.value, false));
    if (::flock(lock.value, LOCK_EX | LOCK_NB))
      return makeError(StorageClientCode::kResourceBusy, "EC read spool has another owner");
    if (ownershipHook) ownershipHook(hookContext, 0, directory.value, lock.value);
    // Keep both descriptors in their guards until path/object/control-block
    // allocations have all succeeded. The temporary object owns no descriptor,
    // including when shared_ptr construction deletes it after allocation failure.
    auto value = std::shared_ptr<EcReadSpool>(new EcReadSpool(path, std::move(cluster), limits, -1, -1));
    if (ownershipHook) ownershipHook(hookContext, 1, directory.value, lock.value);
    value->directory_ = directory.release();
    value->lock_ = lock.release();
    if (create) {
      value->namespace_ = Uuid::random();
      RETURN_ON_ERROR(value->writeNew("namespace.json", identityJson(value->cluster_, value->namespace_)));
      RETURN_ON_ERROR(value->writeNew("sequence.json", counterJson(1)));
    } else {
      CHECK_RESULT(identityText, value->read("namespace.json", 4096));
      const auto identity = folly::parseJson(identityText);
      if (!identity.isObject() || identity.size() != 3 || !identity.count("version") || !identity.count("cluster") ||
          !identity.count("client_namespace") || !identity["version"].isString() ||
          identity["version"].getString() != "1" || !identity["cluster"].isString() ||
          identity["cluster"].getString() != value->cluster_)
        return makeError(StatusCode::kTokenMismatch, "spool identity differs from explicit cluster/schema");
      CHECK_RESULT(id, spoolUuid(identity["client_namespace"]));
      value->namespace_ = id;
      CHECK_RESULT(counterText, value->read("sequence.json", 4096));
      const auto counter = folly::parseJson(counterText);
      if (!counter.isObject() || counter.size() != 1 || !counter.count("next_sequence"))
        return makeError(StatusCode::kInvalidFormat, "invalid EC read sequence high-water mark");
      CHECK_RESULT(next, spoolUnsigned(counter["next_sequence"]));
      if (!next) return makeError(StatusCode::kInvalidFormat);
      value->nextSequence_ = next;
    }
    // Reconfirm visible files and parent after any interrupted local attempt.
    // No network client is constructed and no request can precede this point.
    if (::fsync(value->directory_) || ::fsync(parent.value))
      return makeError(spoolIo("reconfirm EC read spool").error());
    RETURN_ON_ERROR(value->inspect());
    return value;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat, "malformed EC read spool");
  }
}
Result<Void> EcReadSpool::validReceipt(const EcReadReceipt &receipt) const {
  if (receipt.clientNamespace != namespace_ || !receipt.sequence || receipt.sequence >= nextSequence_ ||
      receipt.rangeId.is_nil())
    return makeError(StatusCode::kTokenMismatch, "receipt differs from retained spool identity");
  return Void{};
}
std::filesystem::path EcReadSpool::runPath(uint64_t sequence) const { return path_ / spoolRunName(sequence); }
Result<std::string> EcReadSpool::read(std::string_view name, size_t maximum) const {
  return spoolRead(directory_, name, maximum);
}
Result<Void> EcReadSpool::writeNew(std::string_view name, std::string_view bytes) {
  const auto temporary = fmt::format(".pending-{}", Uuid::random().toHexString());
  SpoolFd fd(::openat(directory_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd.value < 0) return spoolIo("create EC read spool temporary");
  if (::fchmod(fd.value, 0600)) return spoolIo("set EC read spool file mode");
  RETURN_ON_ERROR(spoolWriteAll(fd.value, bytes));
  if (::fsync(fd.value)) return spoolIo("sync EC read spool file");
  if (::linkat(directory_, temporary.c_str(), directory_, std::string(name).c_str(), 0))
    return spoolIo("publish EC read spool file exclusively");
  if (::unlinkat(directory_, temporary.c_str(), 0)) return spoolIo("unlink own EC read spool temporary");
  if (::fsync(directory_)) return spoolIo("sync EC read spool directory");
  return Void{};
}
Result<Void> EcReadSpool::writeCounter(uint64_t next) {
  const auto temporary = fmt::format(".pending-{}", Uuid::random().toHexString());
  SpoolFd fd(::openat(directory_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd.value < 0) return spoolIo("create EC read sequence temporary");
  if (::fchmod(fd.value, 0600)) return spoolIo("set EC read sequence file mode");
  RETURN_ON_ERROR(spoolWriteAll(fd.value, counterJson(next)));
  if (::fsync(fd.value)) return spoolIo("sync EC read sequence high-water mark");
  if (::renameat(directory_, temporary.c_str(), directory_, "sequence.json"))
    return spoolIo("replace EC read sequence high-water mark");
  if (::fsync(directory_)) return spoolIo("persist EC read sequence replacement");
  return Void{};
}
Result<uint64_t> EcReadSpool::reserveSequence() {
  if (poisoned_) return makeError(StatusCode::kIOError, "reopen spool after uncertain local persistence");
  if (nextSequence_ == std::numeric_limits<uint64_t>::max())
    return makeError(StatusCode::kInvalidArg, "spool sequence exhausted");
  // A failed rename/fsync never permits reuse through this live handle.
  poisoned_ = true;
  RETURN_ON_ERROR(writeCounter(nextSequence_ + 1));
  const auto allocated = nextSequence_++;
  poisoned_ = false;
  return allocated;
}
}  // namespace hf3fs::client::ec
