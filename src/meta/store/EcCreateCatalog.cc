#include "meta/store/EcCreateCatalog.h"

#include "common/kv/KeyPrefix.h"

namespace hf3fs::meta::server {
namespace {
EcOwner owner(const CreateEcFileReq &req) {
  EcOwner value;
  value.uid = req.user.uid;
  value.client = req.client.uuid;
  return value;
}
PathAt canonicalInput(const CreateEcFileReq &req) {
  auto path = req.path;
  // Absolute paths do not use the supplied directory descriptor. Preserve
  // components (including '..'): lexical collapse can change symlink meaning.
  if (path.path && path.path->is_absolute()) path.parent = InodeId::root();
  return path;
}
std::string key(const CreateEcFileReq &req) {
  std::string value(kv::toStr(kv::KeyPrefix::EcCreateOperation));
  const auto uid = req.user.uid.toUnderType();
  for (int shift = 24; shift >= 0; shift -= 8) value.push_back(static_cast<char>(uid >> shift));
  value.append(req.client.uuid.asStringView());
  value.append(req.uuid.asStringView());
  return value;
}
}  // namespace

CoTryTask<std::optional<EcCreateRecord>> EcCreateCatalog::load(kv::IReadWriteTransaction &txn,
                                                               const CreateEcFileReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  auto bytes = co_await txn.get(key(req));
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  EcCreateRecord record;
  auto decoded = serde::deserialize(record, **bytes);
  if (!decoded || record.version != 1) co_return makeError(StatusCode::kDataCorruption, "invalid EC create record");
  if (!serde::equals(record.owner, owner(req)) || record.requestId != req.uuid ||
      record.inputPath != canonicalInput(req) || record.gid != req.user.gid ||
      record.perm != Permission(req.perm & ALLPERMS) || record.shardBytes != req.shardBytes) {
    co_return makeError(StatusCode::kTokenMismatch, "EC create UUID reused for another request");
  }
  if (!record.result.inode.isFile() || !record.result.inode.asFile().layout.ecLayout() ||
      record.result.inode.id != record.result.object.object.inode ||
      record.result.inode.asFile().layout.ecLayout()->incarnation != record.result.object.object.incarnation) {
    co_return makeError(StatusCode::kDataCorruption, "EC create record result is inconsistent");
  }
  co_return record;
}

CoTryTask<void> EcCreateCatalog::store(kv::IReadWriteTransaction &txn,
                                       const CreateEcFileReq &req,
                                       InodeId parent,
                                       std::string name,
                                       const CreateEcFileRsp &result) {
  auto previous = co_await load(txn, req);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) co_return makeError(StatusCode::kTokenDuplicated, "EC create operation is already recorded");
  EcCreateRecord record;
  record.owner = owner(req);
  record.requestId = req.uuid;
  record.inputPath = canonicalInput(req);
  record.gid = req.user.gid;
  record.perm = Permission(req.perm & ALLPERMS);
  record.shardBytes = req.shardBytes;
  record.resolvedParent = parent;
  record.name = std::move(name);
  record.result = result;
  co_return co_await txn.set(key(req), serde::serialize(record));
}
}  // namespace hf3fs::meta::server
