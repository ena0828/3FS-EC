#pragma once

#include <memory>
#include <optional>
#include <string>

#include "common/utils/Path.h"
#include "fbs/storage/EcGcControl.h"
#include "fbs/storage/EcGcAbsentControl.h"
#include "fbs/storage/EcIntegrity.h"
#include "storage/ec_scope/EcScope.h"

namespace hf3fs::storage {

enum class EcStageOperation : uint8_t {
  ReadBlock = 40,
  Begin = 41,
  Append = 42,
  Query = 43,
  Reconcile = 44,
  Seal = 45
};

// Internal request after capability and routing checks. This owning type keeps
// at most one 64 KiB block across a bounded worker queue. It is not a wire grant.
struct EcStageRequest {
  EcStageOperation operation = EcStageOperation::Query;
  EcFragmentIdentity identity;
  VersionedChainId vChainId;
  TargetId targetId;
  Uuid operationId = Uuid::zero();
  EcIntegrityDescriptor integrity;
  // Only Begin consumes the original, authenticated writer namespace.
  Uuid writerNamespace = Uuid::zero();
  uint8_t blockIndex = 0;
  std::string payload;

  bool durable() const { return operation != EcStageOperation::ReadBlock && operation != EcStageOperation::Query; }
  Result<Void> validate() const;
};

struct EcStageResult {
  // Present only for Begin/Append/Query/Reconcile. Query is never a barrier.
  std::optional<chunk_engine::RawEcStageState> state;
  // Present only for a successful Seal, after content verification.
  std::optional<EcFragmentReceipt> sealed;
  std::string data;
};

class EcStagingEngine {
 public:
  static Result<std::shared_ptr<EcStagingEngine>> open(
      const Path &path,
      bool create,
      chunk_engine::RawEcStageLimits limits = chunk_engine::RawEcStageLimits{4096, 64, 8});
  // Explicit, local format-3 opener. The directory must already have exact
  // format-3 blockers; this neither upgrades format 2 nor authorizes collection.
  // It owns the same Rust facade used by execute(), not a second Engine.
  static Result<std::shared_ptr<EcStagingEngine>> openExactGc(
      const Path &path,
      bool create,
      chunk_engine::RawEcStageLimits limits = chunk_engine::RawEcStageLimits{4096, 64, 8});
  // Actual persisted namespace format, independent of data protocol 2 and
  // Meta object mode 3. No inference from target configuration or request.
  Result<uint16_t> actualDiskFormat() const;
  Result<std::shared_ptr<EcScope>> scope() const;
  Result<EcStageResult> execute(const EcStageRequest &request) const;
  Result<uint64_t> committedSize(ChainId chain) const;
  Result<chunk_engine::RawUsedSize> physicalUsedSize() const;
  Result<chunk_engine::Metrics> sampleMetrics() const;
  Result<Void> setAllowToAllocate(bool allow) const;
  // Always inspect status AND report. Successful punch bytes are not statfs
  // bytes, and failed/unknown physical extents are reported separately.
  chunk_engine::RawEcStageTrimResult trimEmptyGroups(const chunk_engine::RawEcStageTrimLimits &limits) const;

 private:
  friend class StorageTarget;
  // Only the loaded target adapter supplies its actual chain. The key is
  // constructed here from that chain and the authenticated fragment identity.
  Result<EcGcLedgerReceipt> executeGc(const VerifiedEcGcRequest &, ChainId actualChain) const;
  Result<EcGcAbsentLedgerReceipt> executeGcAbsent(const VerifiedEcGcAbsentRequest &, ChainId actualChain) const;
  explicit EcStagingEngine(rust::Box<chunk_engine::EcStageHandle> handle)
      : handle_(std::move(handle)) {}
  rust::Box<chunk_engine::EcStageHandle> handle_;
};

}  // namespace hf3fs::storage
