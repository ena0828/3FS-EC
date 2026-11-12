#pragma once
#include <atomic>
#include <filesystem>
#include <memory>
#include <utility>
#include <vector>

#include "client/ec/EcFilePwriteJournal.h"
#include "client/ec/EcTreeReadJournal.h"
#include "client/ec/EcTruncateJournal.h"

namespace hf3fs::fuse {
// Private mount-owned storage. These records confer no metadata authority.
// Every entry has an immutable original request; status/result is only an
// observation and must be revalidated with the original server identifiers.
class EcFileMountState {
 public:
  // Quotas count active, not historical entries. Retained inputs still consume
  // disk space; this is NOT a bound on total on-disk history.
  struct Config {
    std::filesystem::path directory;
    std::string cluster;
    bool create = false;
    size_t maximumRuns = 128;
    Uuid expectedNamespace = Uuid::zero();
    uint64_t maximumInputBytes = uint64_t{256} << 20;
  };
  static Result<std::shared_ptr<EcFileMountState>> open(Config);
  ~EcFileMountState();
  const Uuid &clientNamespace() const { return namespace_; }
  const std::filesystem::path &directory() const { return config_.directory; }
  const std::string &cluster() const { return config_.cluster; }
  Result<std::filesystem::path> reserve(std::string_view kind);
  struct Operation {
    std::string name;
    uint64_t inputBytes = 0;
  };
  Result<std::filesystem::path> reserveOperation(const std::filesystem::path &,
                                                 std::string_view kind,
                                                 uint64_t inputBytes = 0);
  Result<std::vector<Operation>> operations(const std::filesystem::path &) const;
  Result<std::vector<std::filesystem::path>> sessions() const;
  Result<Void> write(const std::filesystem::path &, std::string_view name, std::string_view bytes);
  Result<std::optional<std::string>> read(const std::filesystem::path &, std::string_view name) const;
  bool poisoned() const { return poisoned_; }

 private:
  friend class EcFileMount;
  friend struct EcFileMountTestAccess;
  EcFileMountState(Config c, int directory, int lock, Uuid ns)
      : config_(std::move(c)),
        directoryFd_(directory),
        lockFd_(lock),
        namespace_(ns) {}
  // Only the mount's checked terminal paths may remove admission markers.
  // These local records confer no remote authority; no original data is deleted.
  Result<Void> archiveOperation(const std::filesystem::path &, std::string_view name, std::string_view evidence);
  Result<Void> archiveSession(const std::filesystem::path &, std::string_view evidence);
  Result<Void> retainEvidence(const std::filesystem::path &, std::string_view name, std::string_view evidence);
  Result<Void> publish(const std::filesystem::path &, std::string_view name, std::string_view bytes, bool replace);
  Result<Void> eraseIndex(const std::filesystem::path &, std::string_view name);
  Result<int> directory(const std::filesystem::path &) const;
  uint64_t inputBytes_ = 0;
  bool failNextIndexSyncForTest_ = false;  // private one-shot uncertainty seam, never configured in production
  Config config_;
  int directoryFd_ = -1, lockFd_ = -1;
  Uuid namespace_;
  std::atomic_bool poisoned_{false};
  size_t runs_ = 0;
};
struct EcMountOpenRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  // Original request has a nil token. Runtime supplies the real current token,
  // preserving original effective UID/GID, namespace and fixed open/session IDs.
  SERDE_STRUCT_FIELD(request, meta::OpenEcFileSessionReq{});
  SERDE_STRUCT_FIELD(flags, int32_t{});
};
Result<Void> validateEcMountOpenFlags(int flags, bool creating);
}  // namespace hf3fs::fuse
