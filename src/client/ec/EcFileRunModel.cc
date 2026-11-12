#include <algorithm>
#include <charconv>
#include <folly/json.h>
#include <limits>
#include <set>
#include <stdexcept>

#include "EcFileRunJournal.h"

namespace hf3fs::client::ec {
namespace {
using D = folly::dynamic;
constexpr size_t kSnapshotLimit = 64u << 10;
constexpr size_t kJsonLimit = 160u << 10;
std::array<Uuid, 6> ids(const EcStripeMutationIds &m) {
  return {m.operation, m.beginRequest, m.bindRequest, m.publishRequest, m.getRequest, m.prepareRepairRequest};
}
bool empty(const storage::EcSha256 &sha) { return sha == storage::EcSha256{}; }
bool noMutation(const EcStripeMutationIds &m) {
  auto values = ids(m);
  return std::all_of(values.begin(), values.end(), [](const Uuid &id) { return id.is_nil(); });
}
bool unused(const EcFileRunSlot &s) {
  return s.stripe == 0 && s.pin.is_nil() && s.acquireRequest.is_nil() && s.releaseRequest.is_nil() &&
         noMutation(s.mutation) && empty(s.contentSha256);
}
Result<Void> bad(std::string_view why) { return makeError(StatusCode::kInvalidFormat, why); }
std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (unsigned char value : bytes) {
    result.push_back(digits[value >> 4]);
    result.push_back(digits[value & 15]);
  }
  return result;
}
std::string unhex(const D &value, size_t maximum) {
  if (!value.isString()) throw std::invalid_argument("hex must be a string");
  const auto &text = value.getString();
  if (text.size() % 2 || text.size() / 2 > maximum) throw std::invalid_argument("hex length");
  std::string bytes(text.size() / 2, '\0');
  const auto nibble = [](char ch) -> unsigned {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    throw std::invalid_argument("noncanonical hex");
  };
  for (size_t i = 0; i != bytes.size(); ++i)
    bytes[i] = static_cast<char>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
  return bytes;
}
std::string hash(const storage::EcSha256 &sha) { return hex({reinterpret_cast<const char *>(sha.data()), sha.size()}); }
storage::EcSha256 parseHash(const D &value) {
  auto bytes = unhex(value, 32);
  if (bytes.size() != 32) throw std::invalid_argument("SHA size");
  storage::EcSha256 result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}
uint64_t decimal(const D &value) {
  if (!value.isString()) throw std::invalid_argument("u64 must be a decimal string");
  const auto &text = value.getString();
  uint64_t result = 0;
  if (text.empty() || text.size() > 20 || (text.size() > 1 && text[0] == '0'))
    throw std::invalid_argument("decimal spelling");
  for (char ch : text)
    if (ch < '0' || ch > '9') throw std::invalid_argument("decimal digit");
  auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) throw std::invalid_argument("u64 overflow");
  return result;
}
uint64_t small(const D &value, uint64_t maximum) {
  if (!value.isInt() || value.getInt() < 0 || static_cast<uint64_t>(value.getInt()) > maximum)
    throw std::invalid_argument("narrow exact integer");
  return static_cast<uint64_t>(value.getInt());
}
bool boolean(const D &value) {
  if (!value.isBool()) throw std::invalid_argument("boolean required");
  return value.getBool();
}
std::string string(const D &value) {
  if (!value.isString()) throw std::invalid_argument("string required");
  return value.getString();
}
Uuid uuid(const D &value) {
  auto text = string(value);
  auto result = Uuid::fromHexString(text);
  if (!result || result->toHexString() != text) throw std::invalid_argument("canonical UUID required");
  return *result;
}
D slotJson(const EcFileRunSlot &s) {
  D mutation =
      D::object("operation", s.mutation.operation.toHexString())("begin", s.mutation.beginRequest.toHexString())(
          "bind",
          s.mutation.bindRequest.toHexString())("publish", s.mutation.publishRequest.toHexString())(
          "get",
          s.mutation.getRequest.toHexString())("prepare_repair", s.mutation.prepareRepairRequest.toHexString());
  return D::object("stripe", std::to_string(s.stripe))("pin", s.pin.toHexString())("acquire_request",
                                                                                   s.acquireRequest.toHexString())(
      "release_request",
      s.releaseRequest.toHexString())("mutation", std::move(mutation))("content_sha256", hash(s.contentSha256));
}
D json(const EcFileRunRecord &r) {
  D slots = D::array;
  for (const auto &slot : r.slots) slots.push_back(slotJson(slot));
  D owner = D::object("uid", r.owner.uid.toUnderType())("client_namespace", r.owner.client.toHexString());
  D object =
      D::object("inode", std::to_string(r.object.inode.u64()))("incarnation", r.object.incarnation.toHexString());
  return D::object("version", r.version)("kind", static_cast<unsigned>(r.kind))("cluster", r.cluster)(
      "owner",
      std::move(owner))("object", std::move(object))("epoch", std::to_string(r.epoch))("shard_bytes", r.shardBytes)(
      "offset",
      std::to_string(r.offset))("length", std::to_string(r.length))("describe_request",
                                                                    r.describeRequest.toHexString())(
      "range_id",
      r.rangeId.toHexString())("range_request", r.rangeRequest.toHexString())("append_id", r.appendId.toHexString())(
      "input_path",
      r.inputPath)("content_sha256", hash(r.contentSha256))("count", r.count)("slots", std::move(slots));
}
D json(const EcFileRunProgress &p) {
  D states = D::array;
  for (auto state : p.appendStates) states.push_back(static_cast<unsigned>(state));
  return D::object("version", p.version)("sequence", std::to_string(p.sequence))("local_attempt",
                                                                                 std::to_string(p.localAttempt))(
      "acquisition_issued",
      p.acquisitionIssued)("snapshot_observed", p.snapshotObserved)("actual_pins", p.actualPins)(
      "released_mask",
      p.releasedMask)("snapshot_hex", hex(p.snapshotBytes))("data_ready", p.dataReady)(
      "local_complete",
      p.localComplete)("append_states", std::move(states))("error_code", p.errorCode);
}
D parse(std::string_view text) {
  if (text.size() > kJsonLimit) throw std::invalid_argument("journal JSON too large");
  auto value = folly::parseJson(folly::StringPiece(text.data(), text.size()));
  if (!value.isObject()) throw std::invalid_argument("journal object required");
  return value;
}
}  // namespace

Result<Void> EcFileRunRecord::validate() const {
  if (version != 1 || cluster.empty() || cluster.size() > 1024 || inputPath.size() > 4096 ||
      cluster.find('\0') != std::string::npos || inputPath.find('\0') != std::string::npos || owner.client.is_nil() ||
      object.incarnation.is_nil() || !object.inode.u64() || object.inode.isTreeRoot() || !epoch)
    return bad("invalid file run identity");
  if (kind != EcFileRunKind::RangeRead && kind != EcFileRunKind::AppendAt) return bad("unknown file run kind");
  CHECK_RESULT(plan,
               kind == EcFileRunKind::RangeRead ? planEcFileRead(shardBytes, offset, length)
                                                : planEcFileAppend(shardBytes, offset, length));
  if (count != plan.count) return bad("file run slots differ from original requested extent");
  std::set<Uuid> all;
  const auto accept = [&](const Uuid &id) { return !id.is_nil() && all.insert(id).second; };
  if (!accept(describeRequest)) return bad("missing describe identity");
  if (kind == EcFileRunKind::RangeRead) {
    if (!accept(rangeId) || !accept(rangeRequest) || !appendId.is_nil() || !inputPath.empty() || !empty(contentSha256))
      return bad("read contains invalid or write-only identity");
  } else if (!rangeId.is_nil() || !rangeRequest.is_nil() || !accept(appendId) || inputPath.empty() ||
             empty(contentSha256)) {
    return bad("append contains invalid or read-only identity");
  }
  for (size_t i = 0; i != slots.size(); ++i) {
    const auto &slot = slots[i];
    if (i >= count) {
      if (!unused(slot)) return bad("nonzero unused file slot");
      continue;
    }
    if (slot.stripe != plan.slices[i].stripe) return bad("file slot stripe differs from extent");
    if (kind == EcFileRunKind::RangeRead) {
      if (!accept(slot.pin) || !accept(slot.acquireRequest) || !accept(slot.releaseRequest) ||
          !noMutation(slot.mutation) || !empty(slot.contentSha256))
        return bad("read slot identity mismatch");
    } else {
      if (!slot.pin.is_nil() || !slot.acquireRequest.is_nil() || !slot.releaseRequest.is_nil() ||
          empty(slot.contentSha256))
        return bad("append slot identity mismatch");
      for (const auto &id : ids(slot.mutation))
        if (!accept(id)) return bad("missing/reused append identity");
    }
  }
  return Void{};
}
uint16_t EcFileRunProgress::confirmedStripes() const {
  uint16_t count = 0;
  while (count != appendStates.size() && appendStates[count] == EcFileAppendState::Published) ++count;
  return count;
}
uint64_t EcFileRunProgress::confirmedPrefixBytes(const EcFileRunRecord &r) const {
  return r.kind == EcFileRunKind::AppendAt ? uint64_t(confirmedStripes()) * r.shardBytes * 10 : 0;
}
bool EcFileRunProgress::allPinsReleased() const {
  return snapshotObserved && actualPins <= kEcFileMaxStripes && localComplete &&
         releasedMask == static_cast<uint16_t>((1u << actualPins) - 1);
}
Result<Void> EcFileRunProgress::validate(const EcFileRunRecord &r, const EcFileRunProgress *previous) const {
  RETURN_ON_ERROR(r.validate());
  if (version != 1 || snapshotBytes.size() > kSnapshotLimit || actualPins > r.count ||
      (releasedMask & ~((1u << actualPins) - 1)))
    return bad("invalid file progress bounds");
  if (previous) {
    if (previous->sequence == std::numeric_limits<uint64_t>::max() || sequence != previous->sequence + 1 ||
        localAttempt < previous->localAttempt || localAttempt - previous->localAttempt > 1)
      return bad("noncontiguous progress/attempt");
    if (localAttempt == previous->localAttempt && previous->localComplete && !localComplete)
      return bad("completed local attempt cannot restart without a new attempt number");
  } else if (sequence != 0 || localAttempt != 0)
    return bad("first progress must start at zero");
  if (r.kind == EcFileRunKind::RangeRead) {
    if (snapshotObserved && (!acquisitionIssued || snapshotBytes.empty())) return bad("snapshot lacks issued identity");
    if (!snapshotObserved && (actualPins || releasedMask || !snapshotBytes.empty() || dataReady))
      return bad("unobserved range cannot claim data or released pins");
    for (auto state : appendStates)
      if (state != EcFileAppendState::NotStarted) return bad("append state in read run");
    if (previous) {
      if ((previous->acquisitionIssued && !acquisitionIssued) || (previous->snapshotObserved && !snapshotObserved) ||
          (previous->dataReady && !dataReady) || (previous->releasedMask & ~releasedMask))
        return bad("range observation regressed");
      if (previous->snapshotObserved &&
          (previous->snapshotBytes != snapshotBytes || previous->actualPins != actualPins))
        return bad("first fixed range snapshot was replaced");
      if (!previous->acquisitionIssued && snapshotObserved)
        return bad("Acquire must be journaled before snapshot observation");
    } else if (snapshotObserved)
      return bad("first state cannot skip pre-dispatch Acquire record");
    return Void{};
  }
  if (acquisitionIssued || snapshotObserved || actualPins || releasedMask || !snapshotBytes.empty() || dataReady)
    return bad("range state in append run");
  const size_t prefix = confirmedStripes();
  if (prefix > r.count) return bad("published prefix exceeds append plan");
  const size_t oldPrefix = previous ? previous->confirmedStripes() : 0;
  for (size_t i = 0; i != appendStates.size(); ++i) {
    const auto state = appendStates[i];
    if (static_cast<unsigned>(state) > static_cast<unsigned>(EcFileAppendState::Indeterminate))
      return bad("unknown append state");
    if ((i >= r.count || i > prefix) && state != EcFileAppendState::NotStarted)
      return bad("append is not a contiguous prefix");
    const auto old = previous ? previous->appendStates[i] : EcFileAppendState::NotStarted;
    if (old == EcFileAppendState::Published || old == EcFileAppendState::Aborted) {
      if (state != old) return bad("terminal append state changed");
    } else if (old != EcFileAppendState::NotStarted && state == EcFileAppendState::NotStarted) {
      return bad("issued append identity cannot be discarded");
    }
    if (old == EcFileAppendState::NotStarted && state != old && (i != oldPrefix || state != EcFileAppendState::Issued))
      return bad("append must persist issue after confirmed prefix");
  }
  return Void{};
}

Result<std::string> encodeEcFileRunRecord(const EcFileRunRecord &value) {
  try {
    RETURN_ON_ERROR(value.validate());
    return folly::toJson(json(value));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
Result<EcFileRunRecord> decodeEcFileRunRecord(std::string_view text) {
  try {
    const auto in = parse(text);
    EcFileRunRecord r;
    r.version = small(in.at("version"), UINT16_MAX);
    r.kind = static_cast<EcFileRunKind>(small(in.at("kind"), UINT8_MAX));
    r.cluster = string(in.at("cluster"));
    r.owner = {flat::Uid(small(in.at("owner").at("uid"), UINT32_MAX)), uuid(in.at("owner").at("client_namespace"))};
    r.object = {meta::InodeId(decimal(in.at("object").at("inode"))), uuid(in.at("object").at("incarnation"))};
    r.epoch = decimal(in.at("epoch"));
    r.shardBytes = small(in.at("shard_bytes"), UINT32_MAX);
    r.offset = decimal(in.at("offset"));
    r.length = decimal(in.at("length"));
    r.describeRequest = uuid(in.at("describe_request"));
    r.rangeId = uuid(in.at("range_id"));
    r.rangeRequest = uuid(in.at("range_request"));
    r.appendId = uuid(in.at("append_id"));
    r.inputPath = string(in.at("input_path"));
    r.contentSha256 = parseHash(in.at("content_sha256"));
    r.count = small(in.at("count"), kEcFileMaxStripes);
    const auto &slots = in.at("slots");
    if (!slots.isArray() || slots.size() != kEcFileMaxStripes) return makeError(StatusCode::kInvalidFormat);
    for (size_t i = 0; i != r.slots.size(); ++i) {
      const auto &value = slots[i];
      auto &slot = r.slots[i];
      const auto &m = value.at("mutation");
      slot.stripe = decimal(value.at("stripe"));
      slot.pin = uuid(value.at("pin"));
      slot.acquireRequest = uuid(value.at("acquire_request"));
      slot.releaseRequest = uuid(value.at("release_request"));
      slot.mutation = {uuid(m.at("operation")),
                       uuid(m.at("begin")),
                       uuid(m.at("bind")),
                       uuid(m.at("publish")),
                       uuid(m.at("get")),
                       uuid(m.at("prepare_repair"))};
      slot.contentSha256 = parseHash(value.at("content_sha256"));
    }
    if (json(r) != in)
      return makeError(StatusCode::kInvalidFormat, "file record contains omitted/extra/noncanonical fields");
    RETURN_ON_ERROR(r.validate());
    return r;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
Result<std::string> encodeEcFileRunProgress(const EcFileRunProgress &value) {
  try {
    if (value.snapshotBytes.size() > kSnapshotLimit) return makeError(StatusCode::kInvalidFormat);
    return folly::toJson(json(value));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
Result<EcFileRunProgress> decodeEcFileRunProgress(std::string_view text) {
  try {
    const auto in = parse(text);
    EcFileRunProgress p;
    p.version = small(in.at("version"), UINT16_MAX);
    p.sequence = decimal(in.at("sequence"));
    p.localAttempt = decimal(in.at("local_attempt"));
    p.acquisitionIssued = boolean(in.at("acquisition_issued"));
    p.snapshotObserved = boolean(in.at("snapshot_observed"));
    p.actualPins = small(in.at("actual_pins"), kEcFileMaxStripes);
    p.releasedMask = small(in.at("released_mask"), 255);
    p.snapshotBytes = unhex(in.at("snapshot_hex"), kSnapshotLimit);
    p.dataReady = boolean(in.at("data_ready"));
    p.localComplete = boolean(in.at("local_complete"));
    p.errorCode = small(in.at("error_code"), UINT16_MAX);
    const auto &states = in.at("append_states");
    if (!states.isArray() || states.size() != kEcFileMaxStripes) return makeError(StatusCode::kInvalidFormat);
    for (size_t i = 0; i != states.size(); ++i) p.appendStates[i] = static_cast<EcFileAppendState>(small(states[i], 5));
    if (json(p) != in)
      return makeError(StatusCode::kInvalidFormat, "file progress contains omitted/extra/noncanonical fields");
    return p;
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  } catch (const std::exception &) {
    return makeError(StatusCode::kInvalidFormat);
  }
}
}  // namespace hf3fs::client::ec
