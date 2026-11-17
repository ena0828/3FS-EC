#pragma once

#include "common/serde/Service.h"
#include "fbs/storage/Common.h"
#include "fbs/storage/ECShard.h"

namespace hf3fs::storage {

SERDE_SERVICE(StorageSerde, 3) {
  SERDE_SERVICE_METHOD(batchRead, 1, BatchReadReq, BatchReadRsp);
  SERDE_SERVICE_METHOD(write, 2, WriteReq, WriteRsp);
  SERDE_SERVICE_METHOD(update, 3, UpdateReq, UpdateRsp);
  SERDE_SERVICE_METHOD(queryLastChunk, 5, QueryLastChunkReq, QueryLastChunkRsp);
  SERDE_SERVICE_METHOD(truncateChunks, 6, TruncateChunksReq, TruncateChunksRsp);
  SERDE_SERVICE_METHOD(removeChunks, 7, RemoveChunksReq, RemoveChunksRsp);
  SERDE_SERVICE_METHOD(syncStart, 8, SyncStartReq, TargetSyncInfo);
  SERDE_SERVICE_METHOD(syncDone, 9, SyncDoneReq, SyncDoneRsp);
  SERDE_SERVICE_METHOD(spaceInfo, 10, SpaceInfoReq, SpaceInfoRsp);
  SERDE_SERVICE_METHOD(createTarget, 11, CreateTargetReq, CreateTargetRsp);
  SERDE_SERVICE_METHOD(queryChunk, 12, QueryChunkReq, QueryChunkRsp);
  SERDE_SERVICE_METHOD(getAllChunkMetadata, 13, GetAllChunkMetadataReq, GetAllChunkMetadataRsp);
  SERDE_SERVICE_METHOD(offlineTarget, 16, OfflineTargetReq, OfflineTargetRsp);
  SERDE_SERVICE_METHOD(removeTarget, 17, RemoveTargetReq, RemoveTargetRsp);

  SERDE_SERVICE_METHOD_SENDER(writeECShard, 18, WriteECShardReq, WriteECShardRsp);
  SERDE_SERVICE_METHOD_SENDER(readECShard, 19, ReadECShardReq, ReadECShardRsp);

 private:
  // Protocol/client reflection includes both new methods. During the DTO-only
  // stage the existing server has neither handler: leave its dispatch table
  // unchanged instead of inventing handlers or binding missing members. When
  // BOTH handlers exist the normal typed MethodInfo entries are enabled.
  using BeforeEC = REFL_NOW;
  static auto CollectField(::hf3fs::refl::Rank<std::tuple_size_v<BeforeEC> + 1>) {
    if constexpr (std::is_void_v<T>) {
      return std::tuple_cat(
          BeforeEC{},
          std::tuple<::hf3fs::serde::MethodInfo<"writeECShard", T, WriteECShardReq, WriteECShardRsp, 18, nullptr>,
                     ::hf3fs::serde::MethodInfo<"readECShard", T, ReadECShardReq, ReadECShardRsp, 19, nullptr>>{});
    } else if constexpr (requires {
                           &T::writeECShard;
                           &T::readECShard;
                         }) {
      return std::tuple_cat(
          BeforeEC{},
          std::tuple<
              ::hf3fs::serde::MethodInfo<"writeECShard", T, WriteECShardReq, WriteECShardRsp, 18, &T::writeECShard>,
              ::hf3fs::serde::MethodInfo<"readECShard", T, ReadECShardReq, ReadECShardRsp, 19, &T::readECShard>>{});
    } else {
      return BeforeEC{};
    }
  }
};

}  // namespace hf3fs::storage
