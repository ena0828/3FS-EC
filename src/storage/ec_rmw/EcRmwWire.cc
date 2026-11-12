#include "EcRmwWire.h"

#include <cstring>

namespace hf3fs::storage {
namespace {
struct Writer {
  std::string out;
  void n(uint64_t v, size_t width) {
    for (size_t i = width; i; --i) out.push_back(char(v >> ((i - 1) * 8)));
  }
  void uuid(const Uuid &v) { out.append(v.asStringView()); }
  void hash(const EcSha256 &v) { out.append(reinterpret_cast<const char *>(v.data()), v.size()); }
  void endpoint(const EcScopeEndpoint &v) {
    n(v.nodeId.toUnderType(), 4);
    n(v.chainId.toUnderType(), 4);
    n(v.targetId.toUnderType(), 8);
    uuid(v.engineUuid);
    uuid(v.targetIncarnation);
  }
  void identity(const EcFragmentIdentity &v) {
    n(v.version, 2);
    uuid(v.object);
    n(v.stripe, 8);
    n(v.generation, 8);
    n(v.shard, 2);
    uuid(v.allocation);
  }
  void descriptor(const EcIntegrityDescriptor &v) {
    n(v.version, 2);
    n(v.codecId, 2);
    n(v.matrixVersion, 2);
    n(v.dataShards, 2);
    n(v.parityShards, 2);
    n(v.fieldPolynomial, 2);
    n(v.blockBytes, 4);
    n(v.wholeLength, 4);
    n(v.wholeCrc32c, 4);
    n(v.blockCount, 2);
    for (const auto &b : v.blocks) {
      n(b.validLength, 4);
      n(b.crc32c, 4);
      hash(b.sha256);
    }
    hash(v.root);
  }
};
// All decoders first require the complete exact width. Only fixed loops and
// fixed-width fields follow; no attacker count controls allocation or indexing.
struct Reader {
  std::string_view bytes;
  size_t cursor = 0;
  uint64_t n(size_t width) {
    uint64_t v = 0;
    for (size_t i = 0; i < width; ++i) v = (v << 8) | uint8_t(bytes[cursor++]);
    return v;
  }
  Uuid uuid() {
    Uuid v = Uuid::zero();
    std::memcpy(v.data, bytes.data() + cursor, 16);
    cursor += 16;
    return v;
  }
  EcSha256 hash() {
    EcSha256 v{};
    std::memcpy(v.data(), bytes.data() + cursor, 32);
    cursor += 32;
    return v;
  }
  EcScopeEndpoint endpoint() {
    EcScopeEndpoint v;
    v.nodeId = NodeId(n(4));
    v.chainId = ChainId(n(4));
    v.targetId = TargetId(n(8));
    v.engineUuid = uuid();
    v.targetIncarnation = uuid();
    return v;
  }
  EcFragmentIdentity identity() {
    EcFragmentIdentity v;
    v.version = n(2);
    v.object = uuid();
    v.stripe = n(8);
    v.generation = n(8);
    v.shard = n(2);
    v.allocation = uuid();
    return v;
  }
  EcIntegrityDescriptor descriptor() {
    EcIntegrityDescriptor v;
    v.version = n(2);
    v.codecId = n(2);
    v.matrixVersion = n(2);
    v.dataShards = n(2);
    v.parityShards = n(2);
    v.fieldPolynomial = n(2);
    v.blockBytes = n(4);
    v.wholeLength = n(4);
    v.wholeCrc32c = n(4);
    v.blockCount = n(2);
    for (auto &b : v.blocks) {
      b.validLength = n(4);
      b.crc32c = n(4);
      b.sha256 = hash();
    }
    v.root = hash();
    return v;
  }
};
}  // namespace
std::string EcRmwWireCodec::encode(const EcRmwPlanWire &v) {
  Writer w;
  w.out.reserve(kEcRmwPlanWireBytes);
  const auto &p = v.input;
  w.n(p.version, 2);
  w.n(uint8_t(p.action), 1);
  w.n(p.inode, 8);
  w.uuid(p.object);
  w.uuid(p.birth);
  w.uuid(p.planId);
  w.uuid(p.sessionId);
  w.uuid(p.parentId);
  w.uuid(p.operationId);
  w.n(p.ownerUid.toUnderType(), 4);
  w.uuid(p.clientNamespace);
  w.n(p.fenceEpoch, 8);
  w.uuid(p.sourceRoot);
  w.n(p.sourceSequence, 8);
  w.n(p.lengthAtPlan, 8);
  w.n(p.stripe, 8);
  w.n(p.shardBytes, 4);
  w.n(uint8_t(p.sourceKind), 1);
  w.uuid(p.sourcePin);
  w.n(p.sourceRevision, 8);
  w.n(p.sourceGeneration, 8);
  w.n(p.sourceLogicalLength, 4);
  w.hash(p.sourceLogicalSha256);
  for (const auto &s : p.sources) {
    w.identity(s.identity);
    w.uuid(s.operationId);
    w.uuid(s.writerNamespace);
    w.endpoint(s.endpoint);
    w.descriptor(s.integrity);
  }
  w.n(p.targetRevision, 8);
  w.n(p.targetGeneration, 8);
  for (const auto &t : p.targets) {
    w.identity(t.identity);
    w.endpoint(t.endpoint);
  }
  w.n(p.workerIndex, 1);
  w.n(p.patchOffset, 4);
  w.n(p.patchLength, 4);
  w.hash(p.patchSha256);
  w.n(p.targetLogicalLength, 4);
  return std::move(w.out);
}
Result<EcRmwPlanWire> EcRmwWireCodec::plan(std::string_view bytes) {
  if (bytes.size() != kEcRmwPlanWireBytes) return makeError(StatusCode::kInvalidFormat);
  Reader r{bytes};
  EcRmwPlanWire v;
  auto &p = v.input;
  p.version = r.n(2);
  p.action = EcRmwAction(r.n(1));
  p.inode = r.n(8);
  p.object = r.uuid();
  p.birth = r.uuid();
  p.planId = r.uuid();
  p.sessionId = r.uuid();
  p.parentId = r.uuid();
  p.operationId = r.uuid();
  p.ownerUid = flat::Uid(r.n(4));
  p.clientNamespace = r.uuid();
  p.fenceEpoch = r.n(8);
  p.sourceRoot = r.uuid();
  p.sourceSequence = r.n(8);
  p.lengthAtPlan = r.n(8);
  p.stripe = r.n(8);
  p.shardBytes = r.n(4);
  p.sourceKind = EcRmwSourceKind(r.n(1));
  p.sourcePin = r.uuid();
  p.sourceRevision = r.n(8);
  p.sourceGeneration = r.n(8);
  p.sourceLogicalLength = r.n(4);
  p.sourceLogicalSha256 = r.hash();
  for (auto &s : p.sources) {
    s.identity = r.identity();
    s.operationId = r.uuid();
    s.writerNamespace = r.uuid();
    s.endpoint = r.endpoint();
    s.integrity = r.descriptor();
  }
  p.targetRevision = r.n(8);
  p.targetGeneration = r.n(8);
  for (auto &t : p.targets) {
    t.identity = r.identity();
    t.endpoint = r.endpoint();
  }
  p.workerIndex = r.n(1);
  p.patchOffset = r.n(4);
  p.patchLength = r.n(4);
  p.patchSha256 = r.hash();
  p.targetLogicalLength = r.n(4);
  if (r.cursor != bytes.size()) return makeError(StatusCode::kInvalidFormat);
  RETURN_ON_ERROR(EcRmwPlan::create(p));
  return v;
}
std::string EcRmwWireCodec::encode(const EcRmwGrant &v) {
  Writer w;
  w.out.reserve(kEcRmwGrantWireBytes);
  const auto &c = v.claims;
  w.n(c.version, 2);
  w.n(c.rights, 2);
  w.uuid(c.authority);
  w.hash(c.planDigest);
  w.endpoint(c.worker);
  w.uuid(c.grantId);
  w.n(c.issuedAtSeconds, 8);
  w.n(c.expiresAtSeconds, 8);
  w.hash(v.signature_);
  return std::move(w.out);
}
Result<EcRmwGrant> EcRmwWireCodec::grant(std::string_view bytes) {
  if (bytes.size() != kEcRmwGrantWireBytes) return makeError(StatusCode::kInvalidFormat);
  Reader r{bytes};
  EcRmwGrant v;
  auto &c = v.claims;
  c.version = r.n(2);
  c.rights = r.n(2);
  c.authority = r.uuid();
  c.planDigest = r.hash();
  c.worker = r.endpoint();
  c.grantId = r.uuid();
  c.issuedAtSeconds = r.n(8);
  c.expiresAtSeconds = r.n(8);
  v.signature_ = r.hash();
  if (r.cursor != bytes.size()) return makeError(StatusCode::kInvalidFormat);
  return v;
}
std::string EcRmwWireCodec::encode(const EcRmwComputedCommitment &v) {
  Writer w;
  w.out.reserve(kEcRmwComputedWireBytes);
  w.hash(v.output.planDigest);
  w.hash(v.output.logicalSha256);
  for (const auto &d : v.output.descriptors) w.descriptor(d);
  w.endpoint(v.worker);
  w.hash(v.signature_);
  return std::move(w.out);
}
Result<EcRmwComputedCommitment> EcRmwWireCodec::computed(std::string_view bytes) {
  if (bytes.size() != kEcRmwComputedWireBytes) return makeError(StatusCode::kInvalidFormat);
  Reader r{bytes};
  EcRmwComputedCommitment v;
  v.output.planDigest = r.hash();
  v.output.logicalSha256 = r.hash();
  for (auto &d : v.output.descriptors) d = r.descriptor();
  v.worker = r.endpoint();
  v.signature_ = r.hash();
  if (r.cursor != bytes.size()) return makeError(StatusCode::kInvalidFormat);
  return v;
}
}  // namespace hf3fs::storage
