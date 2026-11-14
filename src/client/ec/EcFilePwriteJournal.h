#pragma once
#include <filesystem>

#include "client/ec/EcFilePayload.h"
#include "fbs/meta/Service.h"

namespace hf3fs::client::ec {
// Local recovery format, never a network authority or bearer container.
inline constexpr size_t kEcPwriteClientMaxChildren = 64;
enum class EcPwriteRunKind : uint8_t { Session = 1, Write = 2, AcceptedAppend = 3 };
struct EcPwriteChildIds {
  SERDE_STRUCT_FIELD(intent, meta::EcFileChildIntent{});
  SERDE_STRUCT_FIELD(query, Uuid::zero());
  SERDE_STRUCT_FIELD(planRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(publish, Uuid::zero());
  SERDE_STRUCT_FIELD(cleanup, Uuid::zero());
  SERDE_STRUCT_FIELD(outputRevocation, Uuid::zero());
  SERDE_STRUCT_FIELD(sourceRevocation, Uuid::zero());
};
}  // namespace hf3fs::client::ec
template <>
struct hf3fs::serde::SerdeMethod<std::array<hf3fs::client::ec::EcPwriteChildIds, 64>> {
  using Array = std::array<client::ec::EcPwriteChildIds, 64>;
  static void serialize(const Array &v, auto &out) {
    out.arrayBegin();
    if constexpr (requires { typename std::decay_t<decltype(out)>::is_binary_out; }) {
      for (auto it = v.rbegin(); it != v.rend(); ++it) serde::serialize(*it, out);
    } else {
      for (const auto &x : v) serde::serialize(x, out);
    }
    out.arrayEnd(64);
  }
  static Result<Void> deserialize(Array &v, auto &in) {
    if constexpr (!requires { typename std::decay_t<decltype(in)>::is_binary_in; })
      return makeError(StatusCode::kInvalidFormat);
    else {
      Varint64 n = 0;
      RETURN_ON_ERROR(serde::deserialize(n, in));
      if (n != 64) return makeError(StatusCode::kInvalidFormat);
      for (auto &x : v) RETURN_ON_ERROR(serde::deserialize(x, in));
      return Void{};
    }
  }
};
namespace hf3fs::client::ec {
struct EcPwriteRunRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(kind, EcPwriteRunKind::Session);
  SERDE_STRUCT_FIELD(cluster, std::string{});
  SERDE_STRUCT_FIELD(owner, meta::EcOwner{});
  SERDE_STRUCT_FIELD(createNew, false);
  SERDE_STRUCT_FIELD(path, std::string{});
  SERDE_STRUCT_FIELD(permission, uint32_t{0600});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{1u << 20});
  SERDE_STRUCT_FIELD(object, meta::EcObjectRef{});
  SERDE_STRUCT_FIELD(birth, Uuid::zero());
  SERDE_STRUCT_FIELD(session, Uuid::zero());
  SERDE_STRUCT_FIELD(openRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(closeRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(rights, uint8_t{meta::kEcSessionRead | meta::kEcSessionWrite});
  SERDE_STRUCT_FIELD(operation, Uuid::zero());
  SERDE_STRUCT_FIELD(beginRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(queryRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(sealRequest, Uuid::zero());
  SERDE_STRUCT_FIELD(offset, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(inputPath, std::string{});
  SERDE_STRUCT_FIELD(inputSha256, storage::EcSha256{});
  SERDE_STRUCT_FIELD(count, uint16_t{});
  SERDE_STRUCT_FIELD(children, (std::array<EcPwriteChildIds, kEcPwriteClientMaxChildren>{}));

 public:
  Result<Void> validate() const;
};
struct EcPwriteRunProgress {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(sequence, uint64_t{});
  SERDE_STRUCT_FIELD(issued, false);
  SERDE_STRUCT_FIELD(session, (std::optional<meta::EcFileSessionRecord>{}));
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(root, (std::optional<meta::EcTreeRoot>{}));
  SERDE_STRUCT_FIELD(parent, (std::optional<meta::EcFileMutationRecord>{}));
  SERDE_STRUCT_FIELD(cleanedMask, uint64_t{});
  SERDE_STRUCT_FIELD(errorCode, uint16_t{});

 public:
  Result<Void> validate(const EcPwriteRunRecord &, const EcPwriteRunProgress *previous = nullptr) const;
};
Result<std::string> encodeEcPwriteRunRecord(const EcPwriteRunRecord &);
Result<EcPwriteRunRecord> decodeEcPwriteRunRecord(std::string_view);
Result<std::string> encodeEcPwriteRunProgress(const EcPwriteRunProgress &);
Result<EcPwriteRunProgress> decodeEcPwriteRunProgress(std::string_view);
class EcFilePwriteJournal {
 public:
  static Result<std::unique_ptr<EcFilePwriteJournal>> create(const std::filesystem::path &, EcPwriteRunRecord);
  static Result<std::unique_ptr<EcFilePwriteJournal>> resume(const std::filesystem::path &);
  // Existing lock only; no journal writes or durability reconfirmation.
  static Result<std::unique_ptr<EcFilePwriteJournal>> inspectExisting(const std::filesystem::path &);
  ~EcFilePwriteJournal();
  EcFilePwriteJournal(const EcFilePwriteJournal &) = delete;
  EcFilePwriteJournal &operator=(const EcFilePwriteJournal &) = delete;
  const EcPwriteRunRecord &record() const { return record_; }
  const std::optional<EcPwriteRunProgress> &latest() const { return latest_; }
  bool poisoned() const { return poisoned_; }
  // Exact bytes retained only by inspectExisting; never serialize them to a public archive.
  std::string_view inspectionRecordBytes() const { return inspectionRecordBytes_; }
  std::string_view inspectionLatestStateBytes() const { return inspectionLatestStateBytes_; }
  Result<Void> append(EcPwriteRunProgress);

 private:
  EcFilePwriteJournal(int d, int l, EcPwriteRunRecord r)
      : directory_(d),
        lock_(l),
        record_(std::move(r)) {}
  static Result<std::unique_ptr<EcFilePwriteJournal>> open(const std::filesystem::path &,
                                                           std::optional<EcPwriteRunRecord>, bool readOnly = false);
  Result<Void> writeNew(std::string_view, std::string_view);
  Result<std::string> read(std::string_view) const;
  int directory_ = -1, lock_ = -1;
  EcPwriteRunRecord record_;
  std::optional<EcPwriteRunProgress> latest_;
  bool poisoned_ = false;
  bool readOnly_ = false;
  std::string inspectionRecordBytes_, inspectionLatestStateBytes_;
};
// Factories generate IDs only for an explicit NEW run. Caller fsyncs create()
// before any RPC. prepareWrite consumes an accepted session, never an fd claim.
Result<EcPwriteRunRecord> prepareEcPwriteSession(meta::EcOwner,
                                                 std::string cluster,
                                                 bool createNew,
                                                 std::string path,
                                                 meta::EcObjectRef,
                                                 Uuid birth,
                                                 uint32_t shardBytes,
                                                 uint8_t rights,
                                                 uint32_t permission = 0600);
Result<EcPwriteRunRecord> prepareEcPwrite(const EcFilePwriteJournal &session,
                                          uint64_t offset,
                                          std::string inputPath,
                                          std::span<const uint8_t> input);
Result<EcPwriteRunRecord> prepareEcPwriteFromAcceptedParent(const meta::EcFileSessionRecord &,
                                                            uint32_t shardBytes,
                                                            std::string cluster,
                                                            const meta::EcFileMutationRecord &,
                                                            std::string inputPath,
                                                            std::span<const uint8_t> input);
Result<EcFilePayload> readEcPwriteInput(EcFilePayloadBudget &, const std::filesystem::path &);
}  // namespace hf3fs::client::ec
