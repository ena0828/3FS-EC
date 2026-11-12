#include "meta/store/EcFileAccess.h"

#include "meta/store/EcV2BindingCatalog.h"
#include "meta/store/EcV2GcCatalog.h"

namespace hf3fs::meta::server {
CoTryTask<LoadedEcFile> loadV2File(IReadWriteTransaction &txn,
                                   const UserInfo &user,
                                   const EcObjectRef &object,
                                   std::optional<AccessType> access) {
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  auto loaded = co_await Inode::load(txn, object.inode);
  CO_RETURN_ON_ERROR(loaded);
  if (!*loaded || !(**loaded).nlink) co_return makeError(MetaCode::kNotFound, "EC inode is absent or unlinked");
  auto inode = std::move(**loaded);
  if (!inode.isFile()) co_return makeError(MetaCode::kNotFile);
  const auto *layout = inode.asFile().layout.ecLayout();
  if (!layout || layout->incarnation != object.incarnation) {
    co_return makeError(StatusCode::kTokenMismatch, "EC inode incarnation differs from the request");
  }
  CO_RETURN_ON_ERROR(layout->valid());
  if (access) {
    if (*access != AccessType::READ && (inode.acl.iflags & FS_IMMUTABLE_FL)) {
      co_return makeError(MetaCode::kNoPermission, "EC inode is immutable");
    }
    CO_RETURN_ON_ERROR(inode.acl.checkPermission(user, *access));
  }
  auto catalog = co_await EcCatalog::getObject(txn, object);
  CO_RETURN_ON_ERROR(catalog);
  if (catalog->shardBytes != layout->shardBytes || catalog->length != inode.asFile().length) {
    co_return makeError(StatusCode::kDataCorruption, "EC catalog and inode metadata disagree");
  }
  if (catalog->deleting) co_return makeError(StatusCode::kTokenStale, "EC object is deleting");
  co_return LoadedEcFile{std::move(inode), std::move(*catalog)};
}

CoTryTask<Void> requireTrackedEcFile(kv::IReadWriteTransaction &txn, const EcObjectRef &object) {
  auto mode = co_await EcV2BindingCatalog::requireV2Mode(txn, object);
  CO_RETURN_ON_ERROR(mode);
  if (mode->mode != kEcGcTrackedObjectMode)
    co_return makeError(StatusCode::kNotImplemented, "file ranges require GC tracking from object birth");
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::validateEnrollment(txn, *mode));
  co_return Void{};
}

EcFileState ecFileState(const LoadedEcFile &file) {
  EcFileState state;
  state.object = file.object.object;
  state.layout = *file.inode.asFile().layout.ecLayout();
  state.length = file.object.length;
  state.epoch = file.object.epoch;
  return state;
}
}  // namespace hf3fs::meta::server
