#pragma once

#include "fbs/meta/Utils.h"

namespace hf3fs::meta::client {
// Admission for metadata replies only. It neither validates native placement
// nor authorizes replicated I/O; that checker deliberately rejects EC inodes.
struct MetadataRoutingInfoChecker {
  template <typename T>
  static Result<bool> check(const T &value, const flat::RoutingInfo &routing) {
    return RoutingInfoChecker::checkRoutingInfo(value, routing);
  }

  static Result<bool> check(const OpenEcFileSessionRsp &rsp, const flat::RoutingInfo &routing) {
    if (!rsp.inode.isFile() || !rsp.inode.asFile().layout.isErasureCoded()) return invalid();
    RETURN_ON_ERROR(inode(rsp.inode, routing));
    const auto &layout = *rsp.inode.asFile().layout.ecLayout();
    const EcObjectRef object{rsp.inode.id, layout.incarnation};
    if (rsp.object.object != object || rsp.root.object != object || rsp.session.intent.object != object ||
        rsp.object.shardBytes != layout.shardBytes || rsp.root.birth.is_nil() ||
        rsp.root.birth != rsp.session.intent.birth)
      return invalid();
    return true;
  }
  static Result<bool> check(const StatRsp &rsp, const flat::RoutingInfo &routing) { return inode(rsp.stat, routing); }
  static Result<bool> check(const RenameRsp &rsp, const flat::RoutingInfo &routing) {
    return rsp.stat ? inode(*rsp.stat, routing) : Result<bool>(true);
  }
  static Result<bool> check(const HardLinkRsp &rsp, const flat::RoutingInfo &routing) {
    return inode(rsp.stat, routing);
  }
  static Result<bool> check(const SetAttrRsp &rsp, const flat::RoutingInfo &routing) {
    return inode(rsp.stat, routing);
  }
  static Result<bool> check(const BatchStatRsp &rsp, const flat::RoutingInfo &routing) {
    bool ready = true;
    for (const auto &item : rsp.inodes) {
      if (!item) continue;
      CHECK_RESULT(found, inode(*item, routing));
      ready &= found;
    }
    return ready;
  }
  static Result<bool> check(const BatchStatByPathRsp &rsp, const flat::RoutingInfo &routing) {
    bool ready = true;
    for (const auto &item : rsp.inodes) {
      if (!item) continue;  // Preserve the server's per-path error.
      CHECK_RESULT(found, inode(*item, routing));
      ready &= found;
    }
    return ready;
  }
  static Result<bool> check(const ListRsp &rsp, const flat::RoutingInfo &routing) {
    bool ready = RoutingInfoChecker::checkRoutingInfo(rsp.entries, routing);
    for (const auto &item : rsp.inodes) {
      CHECK_RESULT(found, inode(item, routing));
      ready &= found;
    }
    return ready;
  }

 private:
  static Result<bool> invalid() {
    return makeError(StatusCode::kDataCorruption, "invalid EC inode in metadata response");
  }
  static Result<bool> inode(const Inode &value, const flat::RoutingInfo &routing) {
    if (!value.isFile() || !value.asFile().layout.isErasureCoded())
      return RoutingInfoChecker::checkRoutingInfo(value, routing);
    const auto &layout = value.asFile().layout;
    if (!layout.ecLayout()->valid() || value.id.isTreeRoot() || value.id > InodeId::normalMax() ||
        layout.tableId != flat::ChainTableId(0) || layout.tableVersion != flat::ChainTableVersion(0) ||
        layout.chunkSize.u64() != 0 || layout.stripeSize != 0)
      return invalid();
    return true;
  }
};
}  // namespace hf3fs::meta::client
