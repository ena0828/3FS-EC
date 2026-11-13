#pragma once

#include "common/serde/ClientContext.h"
#include "common/serde/MessagePacket.h"
#include "common/utils/Coroutine.h"
#include "fbs/meta/Common.h"
#include "fbs/meta/Service.h"

namespace hf3fs::meta {

class IMetaServiceStub {
 public:
  using InterfaceType = IMetaServiceStub;

  virtual ~IMetaServiceStub() = default;

#define IMETA_STUB_METHOD(NAME, REQ, RESP)                             \
  virtual CoTryTask<RESP> NAME(const REQ &req,                         \
                               const net::UserRequestOptions &options, \
                               serde::Timestamp *timestamp = nullptr) = 0

  IMETA_STUB_METHOD(statFs, StatFsReq, StatFsRsp);
  IMETA_STUB_METHOD(stat, StatReq, StatRsp);
  IMETA_STUB_METHOD(create, CreateReq, CreateRsp);
  IMETA_STUB_METHOD(mkdirs, MkdirsReq, MkdirsRsp);
  IMETA_STUB_METHOD(symlink, SymlinkReq, SymlinkRsp);
  IMETA_STUB_METHOD(hardLink, HardLinkReq, HardLinkRsp);
  IMETA_STUB_METHOD(remove, RemoveReq, RemoveRsp);
  IMETA_STUB_METHOD(open, OpenReq, OpenRsp);
  IMETA_STUB_METHOD(sync, SyncReq, SyncRsp);
  IMETA_STUB_METHOD(close, CloseReq, CloseRsp);
  IMETA_STUB_METHOD(rename, RenameReq, RenameRsp);
  IMETA_STUB_METHOD(list, ListReq, ListRsp);
  IMETA_STUB_METHOD(truncate, TruncateReq, TruncateRsp);
  IMETA_STUB_METHOD(getRealPath, GetRealPathReq, GetRealPathRsp);
  IMETA_STUB_METHOD(setAttr, SetAttrReq, SetAttrRsp);
  IMETA_STUB_METHOD(pruneSession, PruneSessionReq, PruneSessionRsp);
  IMETA_STUB_METHOD(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
  IMETA_STUB_METHOD(authenticate, AuthReq, AuthRsp);
  IMETA_STUB_METHOD(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
  IMETA_STUB_METHOD(testRpc, TestRpcReq, TestRpcRsp);
  IMETA_STUB_METHOD(batchStat, BatchStatReq, BatchStatRsp);
  IMETA_STUB_METHOD(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
  IMETA_STUB_METHOD(createEcFile, CreateEcFileReq, CreateEcFileRsp);
  IMETA_STUB_METHOD(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
  IMETA_STUB_METHOD(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
  IMETA_STUB_METHOD(getEcOperation, GetEcOperationReq, EcOperationRsp);
  IMETA_STUB_METHOD(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
  IMETA_STUB_METHOD(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
  IMETA_STUB_METHOD(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
  IMETA_STUB_METHOD(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
  IMETA_STUB_METHOD(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
  IMETA_STUB_METHOD(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
  IMETA_STUB_METHOD(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
  IMETA_STUB_METHOD(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
  IMETA_STUB_METHOD(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
  IMETA_STUB_METHOD(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
  IMETA_STUB_METHOD(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
  IMETA_STUB_METHOD(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
  IMETA_STUB_METHOD(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
  IMETA_STUB_METHOD(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
  IMETA_STUB_METHOD(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
  IMETA_STUB_METHOD(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);
  IMETA_STUB_METHOD(prepareEcTargetRetirement, PrepareEcTargetRetirementReq, EcTargetRetirementRsp);
  IMETA_STUB_METHOD(queryEcTargetRetirement, QueryEcTargetRetirementReq, EcTargetRetirementRsp);
  IMETA_STUB_METHOD(describeEcFileV2, DescribeEcFileV2Req, DescribeEcFileV2Rsp);
  IMETA_STUB_METHOD(acquireEcRangeV2, AcquireEcRangeV2Req, EcRangeRsp);
  IMETA_STUB_METHOD(queryEcRangeV2, QueryEcRangeV2Req, EcRangeRsp);
  IMETA_STUB_METHOD(queryEcOwnedMutationV2, QueryEcOwnedMutationV2Req, EcOwnedMutationRsp);
  IMETA_STUB_METHOD(openEcFileSession, OpenEcFileSessionReq, OpenEcFileSessionRsp);
  IMETA_STUB_METHOD(beginEcFilePwrite, BeginEcFilePwriteReq, EcFilePwriteRsp);
  IMETA_STUB_METHOD(queryEcFilePwrite, QueryEcFilePwriteReq, EcFilePwriteRsp);
  IMETA_STUB_METHOD(advanceEcFilePwrite, AdvanceEcFilePwriteReq, EcFilePwriteRsp);
  IMETA_STUB_METHOD(closeEcFileSession, CloseEcFileSessionReq, CloseEcFileSessionRsp);
  IMETA_STUB_METHOD(acquireEcTreeRead, AcquireEcTreeReadReq, EcTreeReadRsp);
  IMETA_STUB_METHOD(queryEcTreeRead, QueryEcTreeReadReq, EcTreeReadRsp);
  IMETA_STUB_METHOD(releaseEcTreeRead, ReleaseEcTreeReadReq, EcTreeReadRsp);
  IMETA_STUB_METHOD(advanceEcTreeReclaim, AdvanceEcTreeReclaimReq, AdvanceEcTreeReclaimRsp);
  IMETA_STUB_METHOD(beginEcFileTruncate, BeginEcFileTruncateReq, EcFileTruncateRsp);
  IMETA_STUB_METHOD(queryEcFileTruncate, QueryEcFileTruncateReq, EcFileTruncateRsp);
  IMETA_STUB_METHOD(advanceEcFileTruncate, AdvanceEcFileTruncateReq, EcFileTruncateRsp);
  IMETA_STUB_METHOD(closeEcFileTruncateDebt, CloseEcFileTruncateDebtReq, EcFileTruncateRsp);
  IMETA_STUB_METHOD(beginEcFileAppend, BeginEcFileAppendReq, EcFileAppendRsp);
  IMETA_STUB_METHOD(queryEcFileAppend, QueryEcFileAppendReq, EcFileAppendRsp);
  IMETA_STUB_METHOD(syncEcFileSession, SyncEcFileSessionReq, SyncEcFileSessionRsp);
  IMETA_STUB_METHOD(beginEcFileRepair, BeginEcFileRepairReq, EcFileRepairRsp);
  IMETA_STUB_METHOD(queryEcFileRepair, QueryEcFileRepairReq, EcFileRepairRsp);
  IMETA_STUB_METHOD(advanceEcFileRepair, AdvanceEcFileRepairReq, EcFileRepairRsp);
  IMETA_STUB_METHOD(prepareEcFileRepairDirect, PrepareEcFileRepairDirectReq, EcFileRepairDirectRsp);
  IMETA_STUB_METHOD(closeEcFileRepairDebt, CloseEcFileRepairDebtReq, EcFileRepairRsp);

#undef IMETA_STUB_METHOD
};

}  // namespace hf3fs::meta
