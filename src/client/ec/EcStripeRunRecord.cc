#include "EcStripeRunRecord.h"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <charconv>
#include <dirent.h>
#include <fcntl.h>
#include <folly/json.h>
#include <limits>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace hf3fs::client::ec {
namespace {
// Persistence uses integers for inode/UID, independently of the native
// diagnostic formatter. InodeId::serdeToReadable() emits a hexadecimal string,
// whereas its JSON deserializer requires an integer. Preserve the existing
// field hierarchy so the normal native deserializer reads this explicit DTO.
struct JournalObjectRef {
  SERDE_STRUCT_FIELD(inode, uint64_t{});
  SERDE_STRUCT_FIELD(incarnation, Uuid::zero());
};
struct JournalOwner {
  SERDE_STRUCT_FIELD(uid, uint32_t{});
  SERDE_STRUCT_FIELD(client, Uuid::zero());
};
struct JournalObjectRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{});
  SERDE_STRUCT_FIELD(object, JournalObjectRef{});
  SERDE_STRUCT_FIELD(shardBytes, uint32_t{});
  SERDE_STRUCT_FIELD(allowColocated, false);
  SERDE_STRUCT_FIELD(epoch, uint64_t{});
  SERDE_STRUCT_FIELD(nextGeneration, uint64_t{});
  SERDE_STRUCT_FIELD(nextRevision, uint64_t{});
  SERDE_STRUCT_FIELD(length, uint64_t{});
  SERDE_STRUCT_FIELD(deleting, false);
  SERDE_STRUCT_FIELD(creator, JournalOwner{});
  SERDE_STRUCT_FIELD(createRequest, Uuid::zero());
};
JournalObjectRecord persistedObject(const meta::EcObjectRecord &value) {
  return {value.version,
          {value.object.inode.u64(), value.object.incarnation},
          value.shardBytes,
          value.allowColocated,
          value.epoch,
          value.nextGeneration,
          value.nextRevision,
          value.length,
          value.deleting,
          {value.creator.uid.toUnderType(), value.creator.client},
          value.createRequest};
}
template <typename T>
std::string journalJson(const T &value) {
  static_assert(std::is_same_v<T, EcStripeRunRecord> || std::is_same_v<T, EcStripeRunObservation>);
  serde::Out<serde::JsonObject> out;
  const auto table = out.tableBegin(false);
  refl::Helper::iterate<T>([&](auto field) {
    if constexpr (std::is_same_v<T, EcStripeRunRecord>) {
      if (value.version == 1 && field.name == "recoverySource") return;
    }
    out.key(field.name);
    const auto &item = value.*field.getter;
    if constexpr (std::is_same_v<std::decay_t<decltype(item)>, std::optional<meta::EcObjectRecord>>) {
      std::optional<JournalObjectRecord> object;
      if (item) object.emplace(persistedObject(*item));
      serde::serialize(object, out);
    } else {
      serde::serialize(item, out);
    }
  });
  out.tableEnd(table);
  return out.toString(true, true);
}

// Both journal versions contain only unsigned integral numbers, represented exactly in
// JSON's signed int64 range. Check before native Serde can narrow an integer.
// This is a local persistence contract, not a change to the RPC JSON formatter.
bool exactJournalNumbers(const folly::dynamic &value, unsigned depth = 0) {
  if (depth > 32 || value.isDouble()) return false;
  if (value.isInt()) return value.getInt() >= 0;
  if (value.isArray()) {
    for (const auto &item : value)
      if (!exactJournalNumbers(item, depth + 1)) return false;
  } else if (value.isObject()) {
    for (const auto &item : value.items())
      if (!exactJournalNumbers(item.second, depth + 1)) return false;
  }
  return true;
}

Result<std::string> checkedJournalJson(const auto &value) {
  auto text = journalJson(value);
  if (!exactJournalNumbers(folly::parseJson(text)))
    return makeError(StatusCode::kInvalidFormat, "journal integers must be in [0, INT64_MAX]");
  return text;
}

template <typename T>
Result<T> readJournalJson(std::string_view text) {
  try {
    const auto input = folly::parseJson(folly::StringPiece(text.data(), text.size()));
    if (!input.isObject() || !exactJournalNumbers(input))
      return makeError(StatusCode::kInvalidFormat, "journal requires exact nonnegative integral numbers");
    T value;
    RETURN_ON_ERROR(serde::fromJsonString(value, text));
    // The generated representation includes every field. Equality also rejects
    // overflow of narrow fields, omitted defaults and unknown schema fields.
    // Inode/UID use the journal DTO, not the native readable formatter.
    if (input != folly::parseJson(journalJson(value)))
      return makeError(StatusCode::kInvalidFormat, "journal differs from its exact versioned representation");
    return value;
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat, "malformed journal JSON");
  }
}

struct Fd {
  int value = -1;
  explicit Fd(int fd)
      : value(fd) {}
  ~Fd() {
    if (value >= 0) ::close(value);
  }
  int release() { return std::exchange(value, -1); }
};
Result<Void> ioError(const char *operation) {
  return makeError(StatusCode::kIOError, fmt::format("{} failed (errno={})", operation, errno));
}
Result<Void> writeAll(int fd, std::string_view bytes) {
  while (!bytes.empty()) {
    auto count = ::write(fd, bytes.data(), bytes.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return ioError("write journal");
    bytes.remove_prefix(static_cast<size_t>(count));
  }
  return Void{};
}
Result<std::string> readRegular(int fd, size_t limit) {
  struct stat stat {};
  if (::fstat(fd, &stat) != 0) return makeError(ioError("fstat input").error());
  if (!S_ISREG(stat.st_mode) || stat.st_size < 0 || uint64_t(stat.st_size) > limit)
    return makeError(StatusCode::kInvalidArg, "input must be a bounded regular file");
  std::string result(static_cast<size_t>(stat.st_size), '\0');
  size_t offset = 0;
  while (offset != result.size()) {
    auto count = ::read(fd, result.data() + offset, result.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StatusCode::kIOError, "input shortened during read");
    offset += static_cast<size_t>(count);
  }
  char extra;
  ssize_t count;
  do {
    count = ::read(fd, &extra, 1);
  } while (count < 0 && errno == EINTR);
  if (count != 0) return makeError(StatusCode::kTokenMismatch, "input changed or read failed at expected EOF");
  return result;
}
std::string observationName(uint64_t sequence) { return fmt::format("state-{:020}.json", sequence); }
}  // namespace

EcStripeMutationIds EcStripeRunRecord::mutationIds() const {
  return {operation, beginRequest, bindRequest, publishRequest, getRequest, prepareRepairRequest};
}
EcStripePinIds EcStripeRunRecord::pinIds(const meta::EcObjectRef &value) const {
  return {value, 0, pin, acquireRequest, releaseRequest};
}
Result<Void> EcStripeRunRecord::validate() const {
  const bool recovery = version == 2 && action == "recovery-write" && recoverySource.has_value();
  if ((!recovery &&
       (version != 1 || recoverySource || (action != "write" && action != "read" && action != "repair"))) ||
      cluster.empty() || cluster.size() > 1024 || inputPath.size() > 4096 || remotePath.size() > 4096 ||
      sourceOrder.size() > 10 || command.size() > 16384 || resumeCommand.size() > 16384 || clientNamespace.is_nil() ||
      !shardBytes || shardBytes > (1u << 20) || inputBytes > uint64_t(shardBytes) * 10 || !inputBytes ||
      createRequest.is_nil() || operation.is_nil() || beginRequest.is_nil() || bindRequest.is_nil() ||
      publishRequest.is_nil() || getRequest.is_nil() || prepareRepairRequest.is_nil() || pin.is_nil() ||
      acquireRequest.is_nil() || releaseRequest.is_nil() || planId.is_nil() || blockWindow == 0 || blockWindow > 4) {
    return makeError(StatusCode::kInvalidArg, "invalid fixed stripe run record");
  }
  if (std::all_of(inputSha256.begin(), inputSha256.end(), [](uint8_t byte) { return byte == 0; }))
    return makeError(StatusCode::kInvalidArg, "run record requires a fixed nonzero content digest");
  if (action == "write") {
    if (inputPath.empty() || remotePath.empty() || remotePath.front() != '/')
      return makeError(StatusCode::kInvalidArg, "write requires input and an absolute 3FS path");
  } else if (!object || object->object.incarnation.is_nil() || !expectedRevision || object->shardBytes != shardBytes) {
    return makeError(StatusCode::kInvalidArg, "read/repair require the recorded published object and revision");
  }
  if (action == "repair") {
    if ((strategy != "central" && strategy != "pipeline" && strategy != "helper") || sourceOrder.size() != 10 ||
        !replacementMask || (replacementMask & ~meta::kEcAllShards) || std::popcount(replacementMask) > 2)
      return makeError(StatusCode::kInvalidArg, "invalid repair strategy or fixed sources/targets");
    uint16_t seen = replacementMask;
    for (auto index : sourceOrder) {
      if (index >= 12 || (seen & (1u << index)))
        return makeError(StatusCode::kInvalidArg, "duplicate/invalid repair source");
      seen |= uint16_t(1u << index);
    }
  }
  if (recovery) {
    const auto &source = *recoverySource;
    const std::array ids{createRequest,
                         operation,
                         beginRequest,
                         bindRequest,
                         publishRequest,
                         getRequest,
                         prepareRepairRequest,
                         pin,
                         acquireRequest,
                         releaseRequest,
                         planId};
    for (size_t i = 0; i != ids.size(); ++i) {
      if (ids[i] == source.operation || ids[i] == source.getRequest ||
          std::find(ids.begin(), ids.begin() + i, ids[i]) != ids.begin() + i)
        return makeError(StatusCode::kTokenMismatch, "recovery request identities overlap");
    }
    const auto nonzero = [](const storage::EcSha256 &hash) { return hash != storage::EcSha256{}; };
    if (!expectedOwnerUid || inputPath.empty() || !std::filesystem::path(inputPath).is_absolute() ||
        !remotePath.empty() || !object || object->deleting || !object->epoch || source.version != 1 ||
        source.runPath.size() > 4096 || !std::filesystem::path(source.runPath).is_absolute() ||
        (source.action != "write" && source.action != "repair" && source.action != "recovery-write") ||
        source.operation.is_nil() || source.getRequest.is_nil() || source.operation == operation ||
        !source.expectedEpoch || source.expectedEpoch != object->epoch || !nonzero(source.recordSha256) ||
        !nonzero(source.observationSha256) ||
        (source.action == "repair" &&
         (!source.expectedRevision || !source.replacementMask || (source.replacementMask & ~meta::kEcAllShards) ||
          std::popcount(source.replacementMask) > 2)) ||
        (source.action != "repair" && source.replacementMask != meta::kEcAllShards) || !strategy.empty() ||
        replacementMask || !sourceOrder.empty())
      return makeError(StatusCode::kInvalidArg, "invalid fixed recovery-write source or input");
  }
  return Void{};
}

EcStripeRunJournal::~EcStripeRunJournal() {
  if (lock_ >= 0) ::close(lock_);
  if (directory_ >= 0) ::close(directory_);
}
Result<std::unique_ptr<EcStripeRunJournal>> EcStripeRunJournal::create(const std::filesystem::path &path,
                                                                       EcStripeRunRecord record) {
  RETURN_ON_ERROR(record.validate());
  return open(path, std::move(record));
}
Result<std::unique_ptr<EcStripeRunJournal>> EcStripeRunJournal::resume(const std::filesystem::path &path) {
  return open(path, std::nullopt);
}
Result<std::unique_ptr<EcStripeRunJournal>> EcStripeRunJournal::open(const std::filesystem::path &path,
                                                                     std::optional<EcStripeRunRecord> initial) {
  if (!path.is_absolute() || path.filename().empty())
    return makeError(StatusCode::kInvalidArg, "run directory must be absolute");
  if (initial) {
    if (::mkdir(path.c_str(), 0700) != 0)
      return makeError(ioError("create new run directory (must not exist)").error());
    Fd parent(::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (parent.value < 0 || ::fsync(parent.value) != 0) return makeError(ioError("sync run parent directory").error());
  }
  Fd directory(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.value < 0) return makeError(ioError("open run directory").error());
  struct stat directoryStat {};
  if (::fstat(directory.value, &directoryStat) != 0) return makeError(ioError("stat run directory").error());
  if (directoryStat.st_uid != ::geteuid() || (directoryStat.st_mode & 0077))
    return makeError(StatusCode::kInvalidArg,
                     "run directory must be owned by the current user with owner-only permissions");
  Fd lock(::openat(directory.value, "lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600));
  if (lock.value < 0) return makeError(ioError("open run lock").error());
  struct stat lockStat {};
  if (::fstat(lock.value, &lockStat) != 0) return makeError(ioError("stat run lock").error());
  if (!S_ISREG(lockStat.st_mode) || lockStat.st_uid != ::geteuid() || (lockStat.st_mode & 0077))
    return makeError(StatusCode::kInvalidArg, "run lock must be an owner-only regular file");
  if (::flock(lock.value, LOCK_EX | LOCK_NB) != 0)
    return makeError(StorageClientCode::kResourceBusy, "another process owns this run record");
  auto journal = std::unique_ptr<EcStripeRunJournal>(new EcStripeRunJournal(directory.release(), lock.release(), {}));
  if (initial) {
    journal->record_ = std::move(*initial);
    CHECK_RESULT(encoded, checkedJournalJson(journal->record_));
    RETURN_ON_ERROR(journal->writeNew("record.json", encoded));
    return journal;
  }
  CHECK_RESULT(text, journal->read("record.json", 65536));
  CHECK_RESULT(record, readJournalJson<EcStripeRunRecord>(text));
  journal->record_ = std::move(record);
  RETURN_ON_ERROR(journal->record_.validate());
  uint64_t count = 0, maximum = 0;
  Fd duplicate(::dup(journal->directory_));
  if (duplicate.value < 0) return makeError(ioError("duplicate journal directory").error());
  DIR *raw = ::fdopendir(duplicate.value);
  if (!raw) return makeError(ioError("scan journal directory").error());
  duplicate.release();
  std::unique_ptr<DIR, decltype(&::closedir)> entries(raw, &::closedir);
  errno = 0;
  while (auto *entry = ::readdir(entries.get())) {
    const std::string_view name(entry->d_name);
    if (!name.starts_with("state-")) continue;
    if (name.size() != 31 || !name.ends_with(".json"))
      return makeError(StatusCode::kInvalidFormat, "invalid observation name");
    uint64_t sequence;
    const auto parsed = std::from_chars(name.data() + 6, name.data() + 26, sequence);
    if (parsed.ec != std::errc{} || parsed.ptr != name.data() + 26 || ++count > 100000)
      return makeError(StatusCode::kInvalidFormat, "invalid/excessive journal sequence");
    maximum = std::max(maximum, sequence);
    errno = 0;
  }
  if (errno) return makeError(ioError("scan journal").error());
  if (count) {
    if (maximum != count - 1) return makeError(StatusCode::kInvalidFormat, "journal sequence has a gap");
    CHECK_RESULT(latest, journal->read(observationName(maximum), 65536));
    CHECK_RESULT(observation, readJournalJson<EcStripeRunObservation>(latest));
    if (observation.version != 1 || observation.sequence != maximum)
      return makeError(StatusCode::kInvalidFormat, "observation sequence differs from its filename");
    journal->latest_ = std::move(observation);
  }
  return journal;
}
Result<Void> EcStripeRunJournal::writeNew(std::string_view name, std::string_view data) {
  const auto temporary = fmt::format(".pending-{}", Uuid::random().toHexString());
  Fd fd(::openat(directory_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd.value < 0) return ioError("create journal temporary");
  RETURN_ON_ERROR(writeAll(fd.value, data));
  if (::fsync(fd.value) != 0) return ioError("sync journal file");
  // linkat refuses an existing destination. An interrupted temporary remains
  // for inspection; it is never confused with a committed observation.
  if (::linkat(directory_, temporary.c_str(), directory_, std::string(name).c_str(), 0) != 0)
    return ioError("publish journal without replacement");
  if (::unlinkat(directory_, temporary.c_str(), 0) != 0) return ioError("remove own journal temporary name");
  if (::fsync(directory_) != 0) return ioError("sync journal directory");
  return Void{};
}
Result<std::string> EcStripeRunJournal::read(std::string_view name, size_t limit) const {
  Fd fd(::openat(directory_, std::string(name).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (fd.value < 0) return makeError(ioError("open journal file").error());
  return readRegular(fd.value, limit);
}
Result<Void> EcStripeRunJournal::append(EcStripeRunObservation observation) {
  if (latest_ && latest_->sequence == std::numeric_limits<uint64_t>::max()) return makeError(StatusCode::kInvalidArg);
  observation.sequence = latest_ ? latest_->sequence + 1 : 0;
  CHECK_RESULT(encoded, checkedJournalJson(observation));
  RETURN_ON_ERROR(writeNew(observationName(observation.sequence), encoded));
  latest_ = std::move(observation);
  return Void{};
}
Result<std::string> EcStripeRunJournal::saveReadOutput(std::string_view data) {
  auto name = fmt::format("read-{}.bin", Uuid::random().toHexString());
  RETURN_ON_ERROR(writeNew(name, data));
  return name;
}
Result<std::string> readEcStripeInput(const std::filesystem::path &path, size_t maximumBytes) {
  Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (fd.value < 0) return makeError(ioError("open stripe input").error());
  return readRegular(fd.value, maximumBytes);
}
}  // namespace hf3fs::client::ec
