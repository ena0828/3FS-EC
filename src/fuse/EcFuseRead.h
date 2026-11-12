#pragma once

#include <cstdint>
#include <memory>

#include "client/ec/EcReadDispatcher.h"
#include "fbs/meta/Schema.h"

namespace hf3fs::fuse {
// This adapter adds no authorization: Describe42 and Acquire43 still use the
// real request credentials and the mount's actual persistent Meta namespace.
Result<Void> validateEcReadOpenFlags(int flags);
Result<uint64_t> ecReadWindowLength(const meta::EcManifestLayoutV1 &,
                                    uint64_t offset,
                                    uint64_t requested,
                                    bool allowShortWindow);
Result<meta::EcObjectRef> ecReadObject(const meta::Inode &);
Result<Void> validateEcArchiveDirectory(const std::filesystem::path &, const std::filesystem::path &spool);
void reportEcLocalMaintenanceFailure() noexcept;

class EcFuseReadAdapter : public std::enable_shared_from_this<EcFuseReadAdapter> {
 public:
  explicit EcFuseReadAdapter(std::shared_ptr<client::ec::EcReadDispatcher> dispatcher)
      : dispatcher_(std::move(dispatcher)) {}
  CoTryTask<client::ec::EcReadHandle> open(const meta::Inode &, flat::UserInfo, int flags, client::ec::EcStripeControl);
  CoTryTask<client::ec::EcDispatchReadOutcome> read(client::ec::EcReadHandle,
                                                    flat::UserInfo,
                                                    uint64_t offset,
                                                    uint64_t requested,
                                                    bool allowShortWindow,
                                                    client::ec::EcStripeControl);
  const std::shared_ptr<client::ec::EcReadDispatcher> &dispatcher() const { return dispatcher_; }

 private:
  static CoTryTask<client::ec::EcReadHandle> openOwned(std::shared_ptr<EcFuseReadAdapter>,
                                                       meta::EcObjectRef,
                                                       meta::EcManifestLayoutV1,
                                                       flat::UserInfo,
                                                       client::ec::EcStripeControl);
  static CoTryTask<client::ec::EcDispatchReadOutcome> readOwned(std::shared_ptr<EcFuseReadAdapter>,
                                                                client::ec::EcReadHandle,
                                                                flat::UserInfo,
                                                                uint64_t,
                                                                uint64_t,
                                                                client::ec::EcStripeControl);
  std::shared_ptr<client::ec::EcReadDispatcher> dispatcher_;
};
}  // namespace hf3fs::fuse
