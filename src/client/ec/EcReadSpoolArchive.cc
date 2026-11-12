#include "detail/EcReadSpoolArchive.h"

#include "detail/EcFileValidation.h"
#include "fbs/meta/EcRequestDigest.h"

namespace hf3fs::client::ec::detail {
namespace {
constexpr size_t kArchiveBytes = 1u << 20;
folly::dynamic receiptJson(const EcReadReceipt &r) {
  return folly::dynamic::object("namespace", r.clientNamespace.toHexString())("sequence", std::to_string(r.sequence))(
      "owner_uid",
      std::to_string(r.ownerUid))("range_id", r.rangeId.toHexString());
}
Result<EcReadReceipt> parseReceipt(const folly::dynamic &v) {
  if (!v.isObject() || v.size() != 4 || !v.count("namespace") || !v.count("sequence") || !v.count("owner_uid") ||
      !v.count("range_id"))
    return makeError(StatusCode::kInvalidFormat);
  EcReadReceipt r;
  CHECK_RESULT(ns, spoolUuid(v["namespace"]));
  r.clientNamespace = ns;
  CHECK_RESULT(sequence, spoolUnsigned(v["sequence"]));
  r.sequence = sequence;
  CHECK_RESULT(uid, spoolUnsigned(v["owner_uid"]));
  if (uid > UINT32_MAX || !sequence) return makeError(StatusCode::kInvalidFormat);
  r.ownerUid = static_cast<uint32_t>(uid);
  CHECK_RESULT(range, spoolUuid(v["range_id"]));
  r.rangeId = range;
  return r;
}
std::string hashHex(const storage::EcSha256 &hash) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(64, '0');
  for (size_t i = 0; i != hash.size(); ++i) {
    result[2 * i] = digits[hash[i] >> 4];
    result[2 * i + 1] = digits[hash[i] & 15];
  }
  return result;
}
Result<storage::EcSha256> parseHash(const folly::dynamic &value) {
  if (!value.isString() || value.getString().size() != 64) return makeError(StatusCode::kInvalidFormat);
  storage::EcSha256 result{};
  const auto digit = [](char c) -> int {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
  };
  for (size_t i = 0; i != result.size(); ++i) {
    const auto high = digit(value.getString()[2 * i]), low = digit(value.getString()[2 * i + 1]);
    if (high < 0 || low < 0) return makeError(StatusCode::kInvalidFormat);
    result[i] = static_cast<uint8_t>((high << 4) | low);
  }
  if (result == storage::EcSha256{}) return makeError(StatusCode::kInvalidFormat);
  return result;
}
Result<Void> validArchive(const EcReadArchive &a) {
  RETURN_ON_ERROR(a.record.validate());
  // This is a final summary, not a replacement history. Its creator first
  // reopens/validates the entire journal; do not call validate(previous=null)
  // on this terminal state, since that correctly requires an initial state.
  const auto &p = a.progress;
  if (p.version != 1 || p.sequence >= kReadSpoolMaximumStates || p.localAttempt > p.sequence || !p.acquisitionIssued ||
      !p.snapshotObserved || p.actualPins > a.record.count || p.releasedMask != ((1u << p.actualPins) - 1) ||
      p.snapshotBytes.empty() || p.snapshotBytes.size() > meta::kEcFileRangeMaxRecordBytes)
    return makeError(StatusCode::kInvalidFormat);
  for (auto state : p.appendStates)
    if (state != EcFileAppendState::NotStarted) return makeError(StatusCode::kInvalidFormat);
  meta::EcRangeSnapshot snapshot;
  RETURN_ON_ERROR(serde::deserialize(snapshot, p.snapshotBytes));
  RETURN_ON_ERROR(validateFileSnapshot(a.record, snapshot));
  if (snapshot.stripeCount != p.actualPins) return makeError(StatusCode::kInvalidFormat);
  if (a.record.kind != EcFileRunKind::RangeRead || a.receipt.clientNamespace.is_nil() || !a.receipt.sequence ||
      a.receipt.clientNamespace != a.record.owner.client || a.receipt.ownerUid != a.record.owner.uid.toUnderType() ||
      a.receipt.rangeId != a.record.rangeId || !a.progress.localComplete || !a.progress.allPinsReleased() ||
      a.progress.errorCode)
    return makeError(StatusCode::kTokenStale,
                     "archive requires the exact completed local read and all observed T2 pins");
  return Void{};
}
}  // namespace

bool sameReadReceipt(const EcReadReceipt &a, const EcReadReceipt &b) {
  return a.clientNamespace == b.clientNamespace && a.sequence == b.sequence && a.ownerUid == b.ownerUid &&
         a.rangeId == b.rangeId;
}
Result<std::string> encodeReadArchive(const EcReadArchive &archive) {
  RETURN_ON_ERROR(validArchive(archive));
  CHECK_RESULT(record, encodeEcFileRunRecord(archive.record));
  CHECK_RESULT(progress, encodeEcFileRunProgress(archive.progress));
  const folly::dynamic value = folly::dynamic::object("version", "1")("receipt", receiptJson(archive.receipt))(
      "record_json",
      record)("progress_json", progress);
  auto encoded = folly::toJson(value);
  if (encoded.size() > kArchiveBytes) return makeError(StatusCode::kInvalidArg);
  return encoded;
}
Result<EcReadArchive> decodeReadArchive(std::string_view text) {
  try {
    if (text.size() > kArchiveBytes) return makeError(StatusCode::kInvalidFormat);
    const auto v = folly::parseJson(folly::StringPiece(text.data(), text.size()));
    if (!v.isObject() || v.size() != 4 || !v.count("version") || !v.count("receipt") || !v.count("record_json") ||
        !v.count("progress_json") || !v["version"].isString() || v["version"].getString() != "1" ||
        !v["record_json"].isString() || !v["progress_json"].isString())
      return makeError(StatusCode::kInvalidFormat);
    EcReadArchive result;
    CHECK_RESULT(receipt, parseReceipt(v["receipt"]));
    result.receipt = receipt;
    CHECK_RESULT(record, decodeEcFileRunRecord(v["record_json"].getString()));
    result.record = std::move(record);
    CHECK_RESULT(progress, decodeEcFileRunProgress(v["progress_json"].getString()));
    result.progress = std::move(progress);
    RETURN_ON_ERROR(validArchive(result));
    return result;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
Result<std::string> encodeReadRetirementMarker(const EcReadRetirementMarker &marker) {
  if (marker.receipt.clientNamespace.is_nil() || !marker.receipt.sequence || marker.receipt.rangeId.is_nil() ||
      !marker.archive.is_absolute() || marker.archive != marker.archive.lexically_normal() ||
      marker.archive.string().size() > 4096 || marker.archive.native().find('\0') != std::string::npos ||
      marker.digest == storage::EcSha256{})
    return makeError(StatusCode::kInvalidArg);
  const folly::dynamic v = folly::dynamic::object("version", "1")("receipt", receiptJson(marker.receipt))(
      "archive",
      marker.archive.string())("sha256", hashHex(marker.digest));
  return folly::toJson(v);
}
Result<EcReadRetirementMarker> decodeReadRetirementMarker(std::string_view text) {
  try {
    if (text.size() > 16384) return makeError(StatusCode::kInvalidFormat);
    const auto v = folly::parseJson(folly::StringPiece(text.data(), text.size()));
    if (!v.isObject() || v.size() != 4 || !v.count("version") || !v.count("receipt") || !v.count("archive") ||
        !v.count("sha256") || !v["version"].isString() || v["version"].getString() != "1" || !v["archive"].isString())
      return makeError(StatusCode::kInvalidFormat);
    EcReadRetirementMarker result;
    CHECK_RESULT(receipt, parseReceipt(v["receipt"]));
    result.receipt = receipt;
    result.archive = v["archive"].getString();
    CHECK_RESULT(hash, parseHash(v["sha256"]));
    result.digest = hash;
    RETURN_ON_ERROR(encodeReadRetirementMarker(result));
    return result;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
Result<storage::EcSha256> readArchiveDigest(std::string_view bytes) {
  std::array<std::string_view, 10> parts{};
  parts[0] = bytes;
  return meta::computeEcLogicalSha256(parts, bytes.size());
}
Result<EcReadArchive> loadReadArchive(const EcReadRetirementMarker &marker) {
  SpoolFd parent(::open(marker.archive.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (parent.value < 0) return makeError(spoolIo("open EC read archive parent").error());
  CHECK_RESULT(bytes, spoolRead(parent.value, marker.archive.filename().string(), kArchiveBytes));
  CHECK_RESULT(hash, readArchiveDigest(bytes));
  if (hash != marker.digest) return makeError(StatusCode::kDataCorruption, "retirement archive bytes changed");
  CHECK_RESULT(archive, decodeReadArchive(bytes));
  if (!sameReadReceipt(archive.receipt, marker.receipt)) return makeError(StatusCode::kTokenMismatch);
  return archive;
}
}  // namespace hf3fs::client::ec::detail
