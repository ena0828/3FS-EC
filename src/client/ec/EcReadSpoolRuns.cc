#include "EcReadSpool.h"
#include "detail/EcReadSpoolScan.h"

namespace hf3fs::client::ec {
using namespace detail;
Result<EcReadSpoolSnapshot> EcReadSpool::inspect(const Run *active) {
  try {
    struct Group {
      std::string directory;
      std::string marker;
      bool retired = false;
    };
    std::map<uint64_t, Group> groups;
    EcReadSpoolSnapshot result;
    CHECK_RESULT(entries, spoolEntries(directory_, 3 * 1024 + 35));
    size_t pending = 0;
    for (const auto &entry : entries) {
      if (!entry.directory && (entry.name == ".lock" || entry.name == "namespace.json" ||
                               entry.name == "sequence.json" || spoolPendingName(entry.name))) {
        if (entry.bytes > 16384 || (spoolPendingName(entry.name) && ++pending > 32))
          return makeError(StatusCode::kInvalidFormat, "excessive spool control files");
        result.logicalFileBytes += entry.bytes;
        continue;
      }
      if (entry.directory) {
        const bool retired = entry.name.starts_with("retired-");
        CHECK_RESULT(sequence, spoolRunSequence(entry.name, retired));
        if (sequence >= nextSequence_ || !groups[sequence].directory.empty())
          return makeError(StatusCode::kInvalidFormat, "spool sequence reused or beyond durable high-water mark");
        groups[sequence].directory = entry.name;
        groups[sequence].retired = retired;
      } else {
        if (!entry.name.starts_with("retire-") || !entry.name.ends_with(".json") || entry.name.size() != 32 ||
            entry.bytes > 16384)
          return makeError(StatusCode::kInvalidFormat, "unrecognized read spool control entry");
        CHECK_RESULT(sequence, spoolRunSequence("run-" + entry.name.substr(7, 20)));
        if (sequence >= nextSequence_ || entry.name != readRetirementMarkerName(sequence))
          return makeError(StatusCode::kInvalidFormat, "invalid retirement sequence");
        groups[sequence].marker = entry.name;
        result.logicalFileBytes += entry.bytes;
      }
    }
    if (groups.size() > 1024) return makeError(StatusCode::kInvalidFormat, "too many retained read records");
    for (const auto &[sequence, group] : groups) {
      uint64_t bytes = 0;
      if (!group.directory.empty()) {
        SpoolFd directory(
            ::openat(directory_, group.directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (directory.value < 0) return makeError(spoolIo("open retained read directory").error());
        RETURN_ON_ERROR(spoolStat(directory.value, true));
        CHECK_RESULT(size, spoolJournalBytes(directory.value));
        bytes = size;
      }
      EcReadDebt debt;
      if (!group.marker.empty()) {
        CHECK_RESULT(text, read(group.marker, 16384));
        CHECK_RESULT(marker, decodeReadRetirementMarker(text));
        RETURN_ON_ERROR(validReceipt(marker.receipt));
        if (marker.receipt.sequence != sequence) return makeError(StatusCode::kTokenMismatch);
        CHECK_RESULT(archive, loadReadArchive(marker));
        RETURN_ON_ERROR(spoolOwnedRecord(archive.record, cluster_, namespace_));
        debt = spoolDebt(marker.receipt, archive.record, archive.progress, bytes, true);
      } else {
        if (group.retired || group.directory.empty())
          return makeError(StatusCode::kInvalidFormat, "retiring run lacks durable export marker");
        std::shared_ptr<EcFileRunJournal> journal;
        if (active && active->receipt.sequence == sequence)
          journal = active->journal;
        else {
          CHECK_RESULT(opened, EcFileRunJournal::resume(path_ / group.directory));
          journal = std::move(opened);
        }
        RETURN_ON_ERROR(spoolOwnedRecord(journal->record(), cluster_, namespace_));
        EcReadReceipt receipt{namespace_,
                              sequence,
                              journal->record().owner.uid.toUnderType(),
                              journal->record().rangeId};
        if (active && active->receipt.sequence == sequence && !sameReadReceipt(active->receipt, receipt))
          return makeError(StatusCode::kTokenMismatch);
        debt = spoolDebt(receipt, journal->record(), journal->latest(), bytes);
      }
      result.logicalFileBytes += bytes;
      ++result.retainedRuns;
      if (!debt.localComplete || !debt.allPinsReleased || debt.lastErrorCode) ++result.outstandingRuns;
      result.records.push_back(std::move(debt));
    }
    // Above hard bounds control parsing. A configured quota may be reduced on
    // reopen: inspection/retirement remain available, new admissions do not.
    return result;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat, "invalid retained read spool");
  }
}
Result<EcReadSpool::Run> EcReadSpool::prepare(EcFileRunRecord record) {
  if (poisoned_) return makeError(StatusCode::kIOError, "reopen poisoned spool");
  RETURN_ON_ERROR(spoolOwnedRecord(record, cluster_, namespace_));
  CHECK_RESULT(snapshot, inspect());
  if (snapshot.retainedRuns >= limits_.maximumRetainedRuns ||
      snapshot.outstandingRuns >= limits_.maximumOutstandingRuns ||
      snapshot.logicalFileBytes > limits_.maximumLogicalFileBytes - kReadSpoolAttemptBytes)
    return makeError(StorageClientCode::kResourceBusy,
                     "read spool quota requires explicit confirmed retirement/cleanup");
  CHECK_RESULT(sequence, reserveSequence());
  // Allocation is already durable. Any partial directory remains visible for
  // diagnosis and this sequence will never be reused after a failed create.
  CHECK_RESULT(created, EcFileRunJournal::create(runPath(sequence), std::move(record)));
  Run run;
  run.receipt = {namespace_, sequence, created->record().owner.uid.toUnderType(), created->record().rangeId};
  run.journal = std::move(created);
  return run;
}
Result<EcReadSpool::Run> EcReadSpool::resume(const EcReadReceipt &receipt) {
  RETURN_ON_ERROR(validReceipt(receipt));
  CHECK_RESULT(marker, spoolExists(directory_, readRetirementMarkerName(receipt.sequence)));
  CHECK_RESULT(retired, spoolExists(directory_, spoolRunName(receipt.sequence, true)));
  CHECK_RESULT(present, spoolExists(directory_, spoolRunName(receipt.sequence)));
  if (marker || retired || !present)
    return makeError(StatusCode::kKVStoreNotFound,
                     "NoRetainedEvidence: receipt is absent/retiring; never generate a replacement Acquire");
  CHECK_RESULT(opened, EcFileRunJournal::resume(runPath(receipt.sequence)));
  RETURN_ON_ERROR(spoolOwnedRecord(opened->record(), cluster_, namespace_));
  const EcReadReceipt actual{namespace_,
                             receipt.sequence,
                             opened->record().owner.uid.toUnderType(),
                             opened->record().rangeId};
  if (!sameReadReceipt(receipt, actual)) return makeError(StatusCode::kTokenMismatch);
  Run run;
  run.receipt = receipt;
  run.journal = std::move(opened);
  return run;
}
Result<Void> EcReadSpool::reserveAttempt(const Run &run) {
  if (poisoned_ || run.journal->poisoned())
    return makeError(StatusCode::kIOError, "reopen after uncertain local persistence");
  if (run.journal->latest() && run.journal->latest()->sequence >= kReadSpoolMaximumStates - 32)
    return makeError(StorageClientCode::kResourceBusy,
                     "read journal lacks bounded attempt capacity; preserve remote identity");
  CHECK_RESULT(snapshot, inspect(&run));
  if (snapshot.logicalFileBytes > limits_.maximumLogicalFileBytes - kReadSpoolAttemptBytes)
    return makeError(StorageClientCode::kResourceBusy, "read spool lacks bounded attempt quota");
  return Void{};
}
}  // namespace hf3fs::client::ec
