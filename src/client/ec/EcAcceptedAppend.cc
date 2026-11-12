#include <algorithm>

#include "EcFilePwriteJournal.h"
#include "detail/EcFileValidation.h"

namespace hf3fs::client::ec {
Result<EcPwriteRunRecord> prepareEcPwriteFromAcceptedParent(const meta::EcFileSessionRecord &s,
                                                            uint32_t shardBytes,
                                                            std::string cluster,
                                                            const meta::EcFileMutationRecord &parent,
                                                            std::string inputPath,
                                                            std::span<const uint8_t> input) {
  const auto &p = parent.intent;
  const auto &i = s.intent;
  CHECK_RESULT(hash, detail::fileContentSha(input));
  if (s.state != meta::EcFileSessionState::Open || !(i.rights & meta::kEcSessionWrite) || p.object != i.object ||
      p.owner.uid != i.owner.uid || p.owner.client != i.owner.client || p.session != i.session || p.request.is_nil() ||
      p.length != input.size() || p.inputSha256 != hash || !p.length || p.length > meta::kEcPwriteMaxBytes ||
      p.offset > UINT64_MAX - p.length || !shardBytes || shardBytes > (1u << 20) || !parent.sessionSequence ||
      !parent.epoch || parent.confirmedPrefix || !parent.activeChild.is_nil() || !parent.fencedChild.is_nil() ||
      parent.state != meta::EcFileMutationState::Open)
    return makeError(StatusCode::kTokenMismatch, "new child journal requires untouched exact accepted append parent");
  EcPwriteRunRecord r;
  r.kind = EcPwriteRunKind::AcceptedAppend;
  r.cluster = std::move(cluster);
  r.owner = i.owner;
  r.object = i.object;
  r.birth = i.birth;
  r.session = i.session;
  r.openRequest = i.openRequest;
  r.closeRequest = Uuid::random();
  r.rights = i.rights;
  r.shardBytes = shardBytes;
  r.operation = p.request;
  r.offset = p.offset;
  r.length = p.length;
  r.inputSha256 = p.inputSha256;
  r.inputPath = std::move(inputPath);
  r.beginRequest = Uuid::random();
  r.queryRequest = Uuid::random();
  r.sealRequest = Uuid::random();
  const uint64_t width = uint64_t(shardBytes) * 10;
  const auto count = (r.offset % width + r.length + width - 1) / width;
  if (count > kEcPwriteClientMaxChildren) return makeError(StatusCode::kInvalidArg);
  r.count = uint16_t(count);
  uint64_t prefix = 0;
  for (size_t n = 0; n < r.count; ++n) {
    auto &c = r.children[n];
    auto &a = c.intent;
    a.object = r.object;
    a.parent = r.operation;
    a.child = Uuid::random();
    a.plan = Uuid::random();
    a.sourcePin = Uuid::random();
    a.expectedPrefix = prefix;
    for (auto &id : a.nodeIds) id = Uuid::random();
    const auto size = std::min(r.length - prefix, width - (r.offset + prefix) % width);
    CHECK_RESULT(part, detail::fileContentSha(input.subspan(prefix, size)));
    a.patchSha256 = part;
    c.query = Uuid::random();
    c.planRequest = Uuid::random();
    c.publish = Uuid::random();
    c.cleanup = Uuid::random();
    c.outputRevocation = Uuid::random();
    c.sourceRevocation = Uuid::random();
    prefix += size;
  }
  RETURN_ON_ERROR(r.validate());
  return r;
}
}  // namespace hf3fs::client::ec
