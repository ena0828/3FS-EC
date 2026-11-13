#pragma once

#include "common/serde/CallContext.h"
#include "common/serde/Service.h"
#include "common/utils/Result.h"
#include "fbs/meta/Service.h"

namespace hf3fs::meta {

class MockMetaService : public serde::ServiceWrapper<MockMetaService, MetaSerde> {
 public:
  virtual ~MockMetaService() = default;

#define META_MOCK_SERVICE_METHOD(NAME, REQ, RESP)                         \
  virtual CoTryTask<RESP> NAME(serde::CallContext &ctx, const REQ &req) { \
    co_return makeError(StatusCode::kNotImplemented);                     \
  }

  META_MOCK_SERVICE_METHOD(statFs, StatFsReq, StatFsRsp);
  META_MOCK_SERVICE_METHOD(stat, StatReq, StatRsp);
  META_MOCK_SERVICE_METHOD(create, CreateReq, CreateRsp);
  META_MOCK_SERVICE_METHOD(mkdirs, MkdirsReq, MkdirsRsp);
  META_MOCK_SERVICE_METHOD(symlink, SymlinkReq, SymlinkRsp);
  META_MOCK_SERVICE_METHOD(hardLink, HardLinkReq, HardLinkRsp);
  META_MOCK_SERVICE_METHOD(remove, RemoveReq, RemoveRsp);
  META_MOCK_SERVICE_METHOD(open, OpenReq, OpenRsp);
  META_MOCK_SERVICE_METHOD(sync, SyncReq, SyncRsp);
  META_MOCK_SERVICE_METHOD(close, CloseReq, CloseRsp);
  META_MOCK_SERVICE_METHOD(rename, RenameReq, RenameRsp);
  META_MOCK_SERVICE_METHOD(list, ListReq, ListRsp);
  META_MOCK_SERVICE_METHOD(truncate, TruncateReq, TruncateRsp);
  META_MOCK_SERVICE_METHOD(getRealPath, GetRealPathReq, GetRealPathRsp);
  META_MOCK_SERVICE_METHOD(setAttr, SetAttrReq, SetAttrRsp);
  META_MOCK_SERVICE_METHOD(pruneSession, PruneSessionReq, PruneSessionRsp);
  META_MOCK_SERVICE_METHOD(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
  META_MOCK_SERVICE_METHOD(authenticate, AuthReq, AuthRsp);
  META_MOCK_SERVICE_METHOD(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
  META_MOCK_SERVICE_METHOD(testRpc, TestRpcReq, TestRpcRsp);
  META_MOCK_SERVICE_METHOD(batchStat, BatchStatReq, BatchStatRsp);
  META_MOCK_SERVICE_METHOD(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
  META_MOCK_SERVICE_METHOD(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  META_MOCK_SERVICE_METHOD(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  META_MOCK_SERVICE_METHOD(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  META_MOCK_SERVICE_METHOD(getEcOperation, GetEcOperationReq, EcOperationRsp);
  META_MOCK_SERVICE_METHOD(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  META_MOCK_SERVICE_METHOD(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  META_MOCK_SERVICE_METHOD(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  META_MOCK_SERVICE_METHOD(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  META_MOCK_SERVICE_METHOD(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  META_MOCK_SERVICE_METHOD(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  META_MOCK_SERVICE_METHOD(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  META_MOCK_SERVICE_METHOD(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
  META_MOCK_SERVICE_METHOD(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  META_MOCK_SERVICE_METHOD(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  META_MOCK_SERVICE_METHOD(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  META_MOCK_SERVICE_METHOD(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  META_MOCK_SERVICE_METHOD(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
  META_MOCK_SERVICE_METHOD(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
  META_MOCK_SERVICE_METHOD(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  META_MOCK_SERVICE_METHOD(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);
  META_MOCK_SERVICE_METHOD(prepareEcTargetRetirement, PrepareEcTargetRetirementReq, EcTargetRetirementRsp);
  META_MOCK_SERVICE_METHOD(queryEcTargetRetirement, QueryEcTargetRetirementReq, EcTargetRetirementRsp);
  META_MOCK_SERVICE_METHOD(describeEcFileV2, DescribeEcFileV2Req, DescribeEcFileV2Rsp);
  META_MOCK_SERVICE_METHOD(acquireEcRangeV2, AcquireEcRangeV2Req, EcRangeRsp);
  META_MOCK_SERVICE_METHOD(queryEcRangeV2, QueryEcRangeV2Req, EcRangeRsp);
  META_MOCK_SERVICE_METHOD(queryEcOwnedMutationV2, QueryEcOwnedMutationV2Req, EcOwnedMutationRsp);
  META_MOCK_SERVICE_METHOD(openEcFileSession, OpenEcFileSessionReq, OpenEcFileSessionRsp);
  META_MOCK_SERVICE_METHOD(beginEcFilePwrite, BeginEcFilePwriteReq, EcFilePwriteRsp);
  META_MOCK_SERVICE_METHOD(queryEcFilePwrite, QueryEcFilePwriteReq, EcFilePwriteRsp);
  META_MOCK_SERVICE_METHOD(advanceEcFilePwrite, AdvanceEcFilePwriteReq, EcFilePwriteRsp);
  META_MOCK_SERVICE_METHOD(closeEcFileSession, CloseEcFileSessionReq, CloseEcFileSessionRsp);
  META_MOCK_SERVICE_METHOD(acquireEcTreeRead, AcquireEcTreeReadReq, EcTreeReadRsp);
  META_MOCK_SERVICE_METHOD(queryEcTreeRead, QueryEcTreeReadReq, EcTreeReadRsp);
  META_MOCK_SERVICE_METHOD(releaseEcTreeRead, ReleaseEcTreeReadReq, EcTreeReadRsp);
  META_MOCK_SERVICE_METHOD(advanceEcTreeReclaim, AdvanceEcTreeReclaimReq, AdvanceEcTreeReclaimRsp);
  META_MOCK_SERVICE_METHOD(beginEcFileTruncate, BeginEcFileTruncateReq, EcFileTruncateRsp);
  META_MOCK_SERVICE_METHOD(queryEcFileTruncate, QueryEcFileTruncateReq, EcFileTruncateRsp);
  META_MOCK_SERVICE_METHOD(advanceEcFileTruncate, AdvanceEcFileTruncateReq, EcFileTruncateRsp);
  META_MOCK_SERVICE_METHOD(closeEcFileTruncateDebt, CloseEcFileTruncateDebtReq, EcFileTruncateRsp);
  META_MOCK_SERVICE_METHOD(beginEcFileAppend, BeginEcFileAppendReq, EcFileAppendRsp);
  META_MOCK_SERVICE_METHOD(queryEcFileAppend, QueryEcFileAppendReq, EcFileAppendRsp);
  META_MOCK_SERVICE_METHOD(syncEcFileSession, SyncEcFileSessionReq, SyncEcFileSessionRsp);
  META_MOCK_SERVICE_METHOD(beginEcFileRepair, BeginEcFileRepairReq, EcFileRepairRsp);
  META_MOCK_SERVICE_METHOD(queryEcFileRepair, QueryEcFileRepairReq, EcFileRepairRsp);
  META_MOCK_SERVICE_METHOD(advanceEcFileRepair, AdvanceEcFileRepairReq, EcFileRepairRsp);
  META_MOCK_SERVICE_METHOD(closeEcFileRepairDebt, CloseEcFileRepairDebtReq, EcFileRepairRsp);

  META_MOCK_SERVICE_METHOD(bindEcRmwOutput, BindEcRmwOutputReq, BindEcRmwOutputRsp);
};
}  // namespace hf3fs::meta
