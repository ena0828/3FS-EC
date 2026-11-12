#include "EcFuseRead.h"

#include <algorithm>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace hf3fs::fuse {
void reportEcLocalMaintenanceFailure() noexcept {
  constexpr char message[] = "3FS EC post-delivery maintenance failed; original spool evidence is retained.\n";
  (void)::write(STDERR_FILENO, message, sizeof(message) - 1);
}
Result<Void> validateEcArchiveDirectory(const std::filesystem::path &archive, const std::filesystem::path &spool) {
  if (!archive.is_absolute() || archive != archive.lexically_normal() ||
      archive.native().find('\0') != std::string::npos)
    return makeError(StatusCode::kInvalidArg, "automatic EC retirement requires an explicit private archive directory");
  std::error_code error;
  const auto canonicalArchive = std::filesystem::canonical(archive, error);
  if (error || canonicalArchive != archive) return makeError(StatusCode::kInvalidArg);
  const auto canonicalSpool = std::filesystem::canonical(spool, error);
  if (error) return makeError(StatusCode::kInvalidArg);
  if (std::mismatch(canonicalSpool.begin(), canonicalSpool.end(), archive.begin(), archive.end()).first ==
      canonicalSpool.end())
    return makeError(StatusCode::kInvalidArg, "archive must be outside the retained production spool");
  struct stat st {};
  if (::lstat(archive.c_str(), &st) || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0077))
    return makeError(StatusCode::kInvalidArg, "EC archive directory must be private and owned by daemon UID");
  return Void{};
}
Result<Void> validateEcReadOpenFlags(int flags) {
  if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_PATH)) ||
      ((flags & O_TMPFILE) == O_TMPFILE))
    return makeError(StatusCode::kNotImplemented, "EC mount supports explicit read-only opens only");
  return Void{};
}
Result<meta::EcObjectRef> ecReadObject(const meta::Inode &inode) {
  if (!inode.isFile()) return makeError(MetaCode::kNotFile);
  const auto *layout = inode.asFile().layout.ecLayout();
  if (!layout) return makeError(StatusCode::kInvalidArg, "replicated inode cannot enter EC adapter");
  RETURN_ON_ERROR(layout->valid());
  return meta::EcObjectRef{inode.id, layout->incarnation};
}
Result<uint64_t> ecReadWindowLength(const meta::EcManifestLayoutV1 &layout,
                                    uint64_t offset,
                                    uint64_t requested,
                                    bool allowShortWindow) {
  RETURN_ON_ERROR(layout.valid());
  if (offset > std::numeric_limits<uint64_t>::max() - requested)
    return makeError(StatusCode::kInvalidArg, "EC read offset/length overflow");
  const uint64_t stripeBytes = uint64_t(layout.shardBytes) * 10;
  const uint64_t available = meta::kEcFileRangeMaxStripes * stripeBytes - offset % stripeBytes;
  const auto maximum = std::min(meta::kEcFileRangeMaxBytes, available);
  if (!allowShortWindow && requested > maximum)
    return makeError(StatusCode::kNotImplemented, "USRBIO EC request exceeds one bounded snapshot window");
  return std::min(requested, maximum);
}
CoTryTask<client::ec::EcReadHandle> EcFuseReadAdapter::open(const meta::Inode &inode,
                                                            flat::UserInfo user,
                                                            int flags,
                                                            client::ec::EcStripeControl control) {
  // Copy immutable input before creating the coroutine; it never retains a
  // pointer to FileHandle, fuse_req_t, an inode cache slot or a ring SQE.
  auto checked = validateEcReadOpenFlags(flags);
  if (!checked)
    return [](Status e) -> CoTryTask<client::ec::EcReadHandle> {
      co_return makeError(std::move(e));
    }(std::move(checked.error()));
  auto object = ecReadObject(inode);
  if (!object)
    return [](Status e) -> CoTryTask<client::ec::EcReadHandle> {
      co_return makeError(std::move(e));
    }(std::move(object.error()));
  return openOwned(shared_from_this(), *object, *inode.asFile().layout.ecLayout(), std::move(user), control);
}
CoTryTask<client::ec::EcReadHandle> EcFuseReadAdapter::openOwned(std::shared_ptr<EcFuseReadAdapter> self,
                                                                 meta::EcObjectRef object,
                                                                 meta::EcManifestLayoutV1 expected,
                                                                 flat::UserInfo user,
                                                                 client::ec::EcStripeControl control) {
  if (!self->dispatcher_) co_return makeError(StatusCode::kNotImplemented, "EC mount read gate is disabled");
  auto result = co_await self->dispatcher_->openRead(object, std::move(user), control);
  CO_RETURN_ON_ERROR(result);
  if (result->described().object != object || result->described().layout != expected)
    co_return makeError(StatusCode::kDataCorruption, "Describe42 differs from the inode incarnation/layout");
  co_return std::move(*result);
}
CoTryTask<client::ec::EcDispatchReadOutcome> EcFuseReadAdapter::read(client::ec::EcReadHandle handle,
                                                                     flat::UserInfo user,
                                                                     uint64_t offset,
                                                                     uint64_t requested,
                                                                     bool allowShortWindow,
                                                                     client::ec::EcStripeControl control) {
  auto length = ecReadWindowLength(handle.described().layout, offset, requested, allowShortWindow);
  if (!length)
    return [](Status e) -> CoTryTask<client::ec::EcDispatchReadOutcome> {
      co_return makeError(std::move(e));
    }(std::move(length.error()));
  return readOwned(shared_from_this(), std::move(handle), std::move(user), offset, *length, control);
}
CoTryTask<client::ec::EcDispatchReadOutcome> EcFuseReadAdapter::readOwned(std::shared_ptr<EcFuseReadAdapter> self,
                                                                          client::ec::EcReadHandle handle,
                                                                          flat::UserInfo user,
                                                                          uint64_t offset,
                                                                          uint64_t length,
                                                                          client::ec::EcStripeControl control) {
  if (!self->dispatcher_) co_return makeError(StatusCode::kNotImplemented);
  // Preserve the full outcome, including receipt and local/T2 state. A caller
  // may copy/reply only when localJoined and data are both present.
  co_return co_await self->dispatcher_->read(std::move(handle), std::move(user), offset, length, control);
}
}  // namespace hf3fs::fuse
