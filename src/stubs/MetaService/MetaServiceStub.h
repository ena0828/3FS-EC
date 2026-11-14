#pragma once

#include "common/serde/ClientContext.h"
#include "fbs/meta/Service.h"
#include "stubs/MetaService/IMetaServiceStub.h"

namespace hf3fs::meta {

template <typename Ctx>
class MetaServiceStub : public IMetaServiceStub {
 public:
  explicit MetaServiceStub(Ctx ctx)
      : context_(std::move(ctx)) {}

#define META_STUB_METHOD(NAME, REQ, RESP)                                                                             \
  CoTryTask<RESP> NAME(const REQ &req, const net::UserRequestOptions &options, serde::Timestamp *timestamp = nullptr) \
      override

  META_STUB_METHOD(statFs, StatFsReq, StatFsRsp);
  META_STUB_METHOD(stat, StatReq, StatRsp);
  META_STUB_METHOD(create, CreateReq, CreateRsp);
  META_STUB_METHOD(mkdirs, MkdirsReq, MkdirsRsp);
  META_STUB_METHOD(symlink, SymlinkReq, SymlinkRsp);
  META_STUB_METHOD(hardLink, HardLinkReq, HardLinkRsp);
  META_STUB_METHOD(remove, RemoveReq, RemoveRsp);
  META_STUB_METHOD(open, OpenReq, OpenRsp);
  META_STUB_METHOD(sync, SyncReq, SyncRsp);
  META_STUB_METHOD(close, CloseReq, CloseRsp);
  META_STUB_METHOD(rename, RenameReq, RenameRsp);
  META_STUB_METHOD(list, ListReq, ListRsp);
  META_STUB_METHOD(truncate, TruncateReq, TruncateRsp);
  META_STUB_METHOD(getRealPath, GetRealPathReq, GetRealPathRsp);
  META_STUB_METHOD(setAttr, SetAttrReq, SetAttrRsp);
  META_STUB_METHOD(pruneSession, PruneSessionReq, PruneSessionRsp);
  META_STUB_METHOD(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
  META_STUB_METHOD(authenticate, AuthReq, AuthRsp);
  META_STUB_METHOD(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
  META_STUB_METHOD(testRpc, TestRpcReq, TestRpcRsp);
  META_STUB_METHOD(batchStat, BatchStatReq, BatchStatRsp);
  META_STUB_METHOD(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
  META_STUB_METHOD(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  META_STUB_METHOD(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  META_STUB_METHOD(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  META_STUB_METHOD(getEcOperation, GetEcOperationReq, EcOperationRsp);
  META_STUB_METHOD(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  META_STUB_METHOD(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  META_STUB_METHOD(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  META_STUB_METHOD(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  META_STUB_METHOD(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  META_STUB_METHOD(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  META_STUB_METHOD(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  META_STUB_METHOD(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
  META_STUB_METHOD(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  META_STUB_METHOD(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  META_STUB_METHOD(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  META_STUB_METHOD(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  META_STUB_METHOD(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
  META_STUB_METHOD(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
  META_STUB_METHOD(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  META_STUB_METHOD(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);
  META_STUB_METHOD(prepareEcTargetRetirement, PrepareEcTargetRetirementReq, EcTargetRetirementRsp);
  META_STUB_METHOD(queryEcTargetRetirement, QueryEcTargetRetirementReq, EcTargetRetirementRsp);
  META_STUB_METHOD(describeEcFileV2, DescribeEcFileV2Req, DescribeEcFileV2Rsp);
  META_STUB_METHOD(acquireEcRangeV2, AcquireEcRangeV2Req, EcRangeRsp);
  META_STUB_METHOD(queryEcRangeV2, QueryEcRangeV2Req, EcRangeRsp);
  META_STUB_METHOD(queryEcOwnedMutationV2, QueryEcOwnedMutationV2Req, EcOwnedMutationRsp);
  META_STUB_METHOD(openEcFileSession, OpenEcFileSessionReq, OpenEcFileSessionRsp);
  META_STUB_METHOD(beginEcFilePwrite, BeginEcFilePwriteReq, EcFilePwriteRsp);
  META_STUB_METHOD(queryEcFilePwrite, QueryEcFilePwriteReq, EcFilePwriteRsp);
  META_STUB_METHOD(advanceEcFilePwrite, AdvanceEcFilePwriteReq, EcFilePwriteRsp);
  META_STUB_METHOD(closeEcFileSession, CloseEcFileSessionReq, CloseEcFileSessionRsp);
  META_STUB_METHOD(acquireEcTreeRead, AcquireEcTreeReadReq, EcTreeReadRsp);
  META_STUB_METHOD(queryEcTreeRead, QueryEcTreeReadReq, EcTreeReadRsp);
  META_STUB_METHOD(releaseEcTreeRead, ReleaseEcTreeReadReq, EcTreeReadRsp);
  META_STUB_METHOD(advanceEcTreeReclaim, AdvanceEcTreeReclaimReq, AdvanceEcTreeReclaimRsp);
  META_STUB_METHOD(beginEcFileTruncate, BeginEcFileTruncateReq, EcFileTruncateRsp);
  META_STUB_METHOD(queryEcFileTruncate, QueryEcFileTruncateReq, EcFileTruncateRsp);
  META_STUB_METHOD(advanceEcFileTruncate, AdvanceEcFileTruncateReq, EcFileTruncateRsp);
  META_STUB_METHOD(closeEcFileTruncateDebt, CloseEcFileTruncateDebtReq, EcFileTruncateRsp);
  META_STUB_METHOD(beginEcFileAppend, BeginEcFileAppendReq, EcFileAppendRsp);
  META_STUB_METHOD(queryEcFileAppend, QueryEcFileAppendReq, EcFileAppendRsp);
  META_STUB_METHOD(syncEcFileSession, SyncEcFileSessionReq, SyncEcFileSessionRsp);
  META_STUB_METHOD(beginEcFileRepair, BeginEcFileRepairReq, EcFileRepairRsp);
  META_STUB_METHOD(queryEcFileRepair, QueryEcFileRepairReq, EcFileRepairRsp);
  META_STUB_METHOD(advanceEcFileRepair, AdvanceEcFileRepairReq, EcFileRepairRsp);
  META_STUB_METHOD(prepareEcFileRepairDirect, PrepareEcFileRepairDirectReq, EcFileRepairDirectRsp);
  META_STUB_METHOD(prepareEcRepairDirectV2, PrepareEcRepairDirectV2Req, PrepareEcRepairDirectV2Rsp);
  META_STUB_METHOD(queryEcFileOutput, QueryEcFileOutputReq, QueryEcFileOutputRsp);
  META_STUB_METHOD(confirmEcFileOutputResolution, ConfirmEcFileOutputResolutionReq, ConfirmEcFileOutputResolutionRsp);
  META_STUB_METHOD(queryEcFileOutputResolution, QueryEcFileOutputResolutionReq, QueryEcFileOutputResolutionRsp);
  META_STUB_METHOD(confirmEcFragmentAbsent, ConfirmEcFragmentAbsentReq, EcAbsentAdminRsp);
  META_STUB_METHOD(queryEcFragmentAbsent, QueryEcFragmentAbsentReq, EcAbsentAdminRsp);
  META_STUB_METHOD(closeEcFileRepairDebt, CloseEcFileRepairDebtReq, EcFileRepairRsp);

#undef META_STUB_METHOD

 private:
  Ctx context_;
};

}  // namespace hf3fs::meta
