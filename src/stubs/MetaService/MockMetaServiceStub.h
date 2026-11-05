#pragma once

#include <folly/concurrency/AtomicSharedPtr.h>
#include <optional>

#include "common/serde/ClientContext.h"
#include "common/serde/MessagePacket.h"
#include "common/utils/Coroutine.h"
#include "common/utils/Result.h"
#include "fbs/meta/Service.h"
#include "fbs/mgmtd/ChainRef.h"
#include "stubs/MetaService/IMetaServiceStub.h"
#include "stubs/MetaService/MetaServiceStub.h"
#include "stubs/common/Stub.h"

namespace hf3fs::meta {

using flat::ChainTableId;
using flat::Uid;
using flat::UserInfo;

class DummyMetaServiceStub : public IMetaServiceStub {
 public:
  ~DummyMetaServiceStub() override = default;

#define NOT_IMPLEMENTED_FUNC(NAME, REQ, RESP)                                                          \
  CoTryTask<RESP> NAME(const REQ &req, const net::UserRequestOptions &, serde::Timestamp *) override { \
    co_return co_await NAME(req);                                                                      \
  }                                                                                                    \
  virtual CoTryTask<RESP> NAME(const REQ &) { co_return makeError(StatusCode::kNotImplemented); }

  NOT_IMPLEMENTED_FUNC(statFs, StatFsReq, StatFsRsp);
  NOT_IMPLEMENTED_FUNC(stat, StatReq, StatRsp);
  NOT_IMPLEMENTED_FUNC(create, CreateReq, CreateRsp);
  NOT_IMPLEMENTED_FUNC(mkdirs, MkdirsReq, MkdirsRsp);
  NOT_IMPLEMENTED_FUNC(symlink, SymlinkReq, SymlinkRsp);
  NOT_IMPLEMENTED_FUNC(hardLink, HardLinkReq, HardLinkRsp);
  NOT_IMPLEMENTED_FUNC(remove, RemoveReq, RemoveRsp);
  NOT_IMPLEMENTED_FUNC(open, OpenReq, OpenRsp);
  NOT_IMPLEMENTED_FUNC(sync, SyncReq, SyncRsp);
  NOT_IMPLEMENTED_FUNC(close, CloseReq, CloseRsp);
  NOT_IMPLEMENTED_FUNC(rename, RenameReq, RenameRsp);
  NOT_IMPLEMENTED_FUNC(list, ListReq, ListRsp);
  NOT_IMPLEMENTED_FUNC(truncate, TruncateReq, TruncateRsp);
  NOT_IMPLEMENTED_FUNC(getRealPath, GetRealPathReq, GetRealPathRsp);
  NOT_IMPLEMENTED_FUNC(setAttr, SetAttrReq, SetAttrRsp);
  NOT_IMPLEMENTED_FUNC(pruneSession, PruneSessionReq, PruneSessionRsp);
  NOT_IMPLEMENTED_FUNC(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
  NOT_IMPLEMENTED_FUNC(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
  NOT_IMPLEMENTED_FUNC(testRpc, TestRpcReq, TestRpcRsp);
  NOT_IMPLEMENTED_FUNC(batchStat, BatchStatReq, BatchStatRsp);
  NOT_IMPLEMENTED_FUNC(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
  NOT_IMPLEMENTED_FUNC(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  NOT_IMPLEMENTED_FUNC(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  NOT_IMPLEMENTED_FUNC(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  NOT_IMPLEMENTED_FUNC(getEcOperation, GetEcOperationReq, EcOperationRsp);
  NOT_IMPLEMENTED_FUNC(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  NOT_IMPLEMENTED_FUNC(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  NOT_IMPLEMENTED_FUNC(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  NOT_IMPLEMENTED_FUNC(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  NOT_IMPLEMENTED_FUNC(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  NOT_IMPLEMENTED_FUNC(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  NOT_IMPLEMENTED_FUNC(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  NOT_IMPLEMENTED_FUNC(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
  NOT_IMPLEMENTED_FUNC(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  NOT_IMPLEMENTED_FUNC(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  NOT_IMPLEMENTED_FUNC(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  NOT_IMPLEMENTED_FUNC(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  NOT_IMPLEMENTED_FUNC(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
  NOT_IMPLEMENTED_FUNC(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
  NOT_IMPLEMENTED_FUNC(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  NOT_IMPLEMENTED_FUNC(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);

  virtual CoTryTask<AuthRsp> authenticate(const AuthReq &req) { co_return AuthRsp{req.user}; }
  CoTryTask<AuthRsp> authenticate(const AuthReq &req, const net::UserRequestOptions &, serde::Timestamp *) override {
    co_return co_await authenticate(req);
  }

#undef NOT_IMPLEMENTED_FUNC
};

struct MockMetaStubHolder {
  void setStub(std::unique_ptr<DummyMetaServiceStub> st) { stub = std::move(st); }

  folly::atomic_shared_ptr<IMetaServiceStub> stub;
};

class DummyMetaServiceStubWithInode : public DummyMetaServiceStub {
 public:
  DummyMetaServiceStubWithInode(std::variant<File, Directory, Symlink> data)
      : inode_({InodeId(0x10de1d), {data, Acl{Uid(0), Gid(0), Permission(0777)}}}) {}

  CoTryTask<CreateRsp> create(const CreateReq &) override { co_return CreateRsp(inode_, false); }
  CoTryTask<OpenRsp> open(const OpenReq &) override { co_return OpenRsp(inode_, false); }
  CoTryTask<StatRsp> stat(const StatReq &) override { co_return StatRsp(inode_); }

 protected:
  Inode inode_;
};
class DummyMetaServiceStubWithDir : public DummyMetaServiceStubWithInode {
 public:
  DummyMetaServiceStubWithDir()
      : DummyMetaServiceStubWithInode(Directory{InodeId(0x10de1dff), Layout::newEmpty(ChainTableId(1), 512 << 10, 8)}) {
  }
};
class DummyMetaServiceStubWithFile : public DummyMetaServiceStubWithInode {
 public:
  DummyMetaServiceStubWithFile()
      : DummyMetaServiceStubWithInode(File(Layout::newEmpty(ChainTableId(1), 512 << 10, 8))) {}
};
class DummyMetaServiceStubWithSymlink : public DummyMetaServiceStubWithInode {
 public:
  DummyMetaServiceStubWithSymlink()
      : DummyMetaServiceStubWithInode(Symlink{"/b"}) {}
};
}  // namespace hf3fs::meta

template <>
struct ::hf3fs::stubs::StubMockContext<hf3fs::meta::IMetaServiceStub> {
  std::shared_ptr<meta::MockMetaStubHolder> stub;
};

namespace hf3fs::meta {

template <>
class MetaServiceStub<hf3fs::stubs::StubMockContext<IMetaServiceStub>> : public IMetaServiceStub {
 public:
  using ContextType = hf3fs::stubs::StubMockContext<IMetaServiceStub>;

  MetaServiceStub(ContextType ctx)
      : stub_(std::move(ctx.stub)) {}
  ~MetaServiceStub() override = default;

#define FORWARD_RPC_FUNC(NAME, REQ, RESP)                                                                           \
  CoTryTask<RESP> NAME(const REQ &req, const net::UserRequestOptions &opts, serde::Timestamp *timestamp) override { \
    co_return co_await stub_->stub.load()->NAME(req, opts, timestamp);                                              \
  }

  FORWARD_RPC_FUNC(statFs, StatFsReq, StatFsRsp);
  FORWARD_RPC_FUNC(stat, StatReq, StatRsp);
  FORWARD_RPC_FUNC(create, CreateReq, CreateRsp);
  FORWARD_RPC_FUNC(mkdirs, MkdirsReq, MkdirsRsp);
  FORWARD_RPC_FUNC(symlink, SymlinkReq, SymlinkRsp);
  FORWARD_RPC_FUNC(hardLink, HardLinkReq, HardLinkRsp);
  FORWARD_RPC_FUNC(remove, RemoveReq, RemoveRsp);
  FORWARD_RPC_FUNC(open, OpenReq, OpenRsp);
  FORWARD_RPC_FUNC(sync, SyncReq, SyncRsp);
  FORWARD_RPC_FUNC(close, CloseReq, CloseRsp);
  FORWARD_RPC_FUNC(rename, RenameReq, RenameRsp);
  FORWARD_RPC_FUNC(list, ListReq, ListRsp);
  FORWARD_RPC_FUNC(truncate, TruncateReq, TruncateRsp);
  FORWARD_RPC_FUNC(getRealPath, GetRealPathReq, GetRealPathRsp);
  FORWARD_RPC_FUNC(setAttr, SetAttrReq, SetAttrRsp);
  FORWARD_RPC_FUNC(pruneSession, PruneSessionReq, PruneSessionRsp);
  FORWARD_RPC_FUNC(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
  FORWARD_RPC_FUNC(authenticate, AuthReq, AuthRsp);
  FORWARD_RPC_FUNC(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
  FORWARD_RPC_FUNC(testRpc, TestRpcReq, TestRpcRsp);
  FORWARD_RPC_FUNC(batchStat, BatchStatReq, BatchStatRsp);
  FORWARD_RPC_FUNC(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
  FORWARD_RPC_FUNC(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  FORWARD_RPC_FUNC(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  FORWARD_RPC_FUNC(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  FORWARD_RPC_FUNC(getEcOperation, GetEcOperationReq, EcOperationRsp);
  FORWARD_RPC_FUNC(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  FORWARD_RPC_FUNC(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  FORWARD_RPC_FUNC(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  FORWARD_RPC_FUNC(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  FORWARD_RPC_FUNC(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  FORWARD_RPC_FUNC(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  FORWARD_RPC_FUNC(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  FORWARD_RPC_FUNC(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
  FORWARD_RPC_FUNC(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  FORWARD_RPC_FUNC(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  FORWARD_RPC_FUNC(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  FORWARD_RPC_FUNC(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  FORWARD_RPC_FUNC(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
  FORWARD_RPC_FUNC(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
  FORWARD_RPC_FUNC(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  FORWARD_RPC_FUNC(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);

#undef FORWARD_RPC_FUNC

 private:
  std::shared_ptr<MockMetaStubHolder> stub_;
};

}  // namespace hf3fs::meta
