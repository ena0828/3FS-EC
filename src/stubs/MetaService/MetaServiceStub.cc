#include "MetaServiceStub.h"

#include "common/serde/ClientContext.h"
#include "common/serde/ClientMockContext.h"
#include "common/utils/Coroutine.h"
#include "common/utils/UtcTimeSerde.h"
#include "fbs/meta/Service.h"

#define IMPL_META_STUB_METHOD(NAME, REQ, RESP)                                           \
  template <typename Context>                                                            \
  CoTryTask<RESP> MetaServiceStub<Context>::NAME(const REQ &req,                         \
                                                 const net::UserRequestOptions &options, \
                                                 hf3fs::serde::Timestamp *timestamp) {   \
    co_return co_await MetaSerde<>::NAME<Context>(context_, req, &options, timestamp);   \
  }

namespace hf3fs::meta {

IMPL_META_STUB_METHOD(statFs, StatFsReq, StatFsRsp);
IMPL_META_STUB_METHOD(stat, StatReq, StatRsp);
IMPL_META_STUB_METHOD(create, CreateReq, CreateRsp);
IMPL_META_STUB_METHOD(mkdirs, MkdirsReq, MkdirsRsp);
IMPL_META_STUB_METHOD(symlink, SymlinkReq, SymlinkRsp);
IMPL_META_STUB_METHOD(hardLink, HardLinkReq, HardLinkRsp);
IMPL_META_STUB_METHOD(remove, RemoveReq, RemoveRsp);
IMPL_META_STUB_METHOD(open, OpenReq, OpenRsp);
IMPL_META_STUB_METHOD(sync, SyncReq, SyncRsp);
IMPL_META_STUB_METHOD(close, CloseReq, CloseRsp);
IMPL_META_STUB_METHOD(rename, RenameReq, RenameRsp);
IMPL_META_STUB_METHOD(list, ListReq, ListRsp);
IMPL_META_STUB_METHOD(truncate, TruncateReq, TruncateRsp);
IMPL_META_STUB_METHOD(getRealPath, GetRealPathReq, GetRealPathRsp);
IMPL_META_STUB_METHOD(setAttr, SetAttrReq, SetAttrRsp);
IMPL_META_STUB_METHOD(pruneSession, PruneSessionReq, PruneSessionRsp);
IMPL_META_STUB_METHOD(dropUserCache, DropUserCacheReq, DropUserCacheRsp);
IMPL_META_STUB_METHOD(authenticate, AuthReq, AuthRsp);
IMPL_META_STUB_METHOD(lockDirectory, LockDirectoryReq, LockDirectoryRsp);
IMPL_META_STUB_METHOD(testRpc, TestRpcReq, TestRpcRsp);
IMPL_META_STUB_METHOD(batchStat, BatchStatReq, BatchStatRsp);
IMPL_META_STUB_METHOD(batchStatByPath, BatchStatByPathReq, BatchStatByPathRsp);
IMPL_META_STUB_METHOD(createEcFile, CreateEcFileReq, CreateEcFileRsp);
IMPL_META_STUB_METHOD(beginEcMutation, BeginEcMutationReq, EcOperationRsp);
IMPL_META_STUB_METHOD(publishEcMutation, PublishEcMutationReq, EcOperationRsp);
IMPL_META_STUB_METHOD(getEcOperation, GetEcOperationReq, EcOperationRsp);
IMPL_META_STUB_METHOD(cancelEcMutation, CancelEcMutationReq, EcOperationRsp);
IMPL_META_STUB_METHOD(acquireEcRead, AcquireEcReadReq, AcquireEcReadRsp);
IMPL_META_STUB_METHOD(releaseEcRead, ReleaseEcReadReq, ReleaseEcReadRsp);
IMPL_META_STUB_METHOD(createEcFileV2, CreateEcFileV2Req, CreateEcFileRsp);
IMPL_META_STUB_METHOD(beginEcMutationV2, BeginEcMutationV2Req, EcV2MutationRsp);
IMPL_META_STUB_METHOD(bindEcMutationV2, BindEcMutationV2Req, EcV2MutationRsp);
IMPL_META_STUB_METHOD(publishEcMutationV2, PublishEcMutationV2Req, EcV2MutationRsp);
IMPL_META_STUB_METHOD(getEcOperationV2, GetEcOperationV2Req, EcV2MutationRsp);
IMPL_META_STUB_METHOD(cancelEcMutationV2, CancelEcMutationV2Req, EcV2MutationRsp);
IMPL_META_STUB_METHOD(acquireEcReadV2, AcquireEcReadV2Req, AcquireEcReadV2Rsp);
IMPL_META_STUB_METHOD(releaseEcReadV2, ReleaseEcReadV2Req, ReleaseEcReadV2Rsp);
IMPL_META_STUB_METHOD(prepareEcRepairV2, PrepareEcRepairV2Req, PrepareEcRepairV2Rsp);
IMPL_META_STUB_METHOD(collectEcFragmentV2, CollectEcFragmentV2Req, EcGcAdminRsp);
IMPL_META_STUB_METHOD(queryEcFragmentGcV2, QueryEcFragmentGcV2Req, EcGcAdminRsp);
IMPL_META_STUB_METHOD(retireEcRevisionV2, RetireEcRevisionV2Req, EcRevisionRetirementRsp);
IMPL_META_STUB_METHOD(queryEcRevisionRetirementV2, QueryEcRevisionRetirementV2Req, EcRevisionRetirementRsp);
IMPL_META_STUB_METHOD(prepareEcTargetRetirement, PrepareEcTargetRetirementReq, EcTargetRetirementRsp);
IMPL_META_STUB_METHOD(queryEcTargetRetirement, QueryEcTargetRetirementReq, EcTargetRetirementRsp);
IMPL_META_STUB_METHOD(describeEcFileV2, DescribeEcFileV2Req, DescribeEcFileV2Rsp);
IMPL_META_STUB_METHOD(acquireEcRangeV2, AcquireEcRangeV2Req, EcRangeRsp);
IMPL_META_STUB_METHOD(queryEcRangeV2, QueryEcRangeV2Req, EcRangeRsp);
IMPL_META_STUB_METHOD(queryEcOwnedMutationV2, QueryEcOwnedMutationV2Req, EcOwnedMutationRsp);
IMPL_META_STUB_METHOD(openEcFileSession, OpenEcFileSessionReq, OpenEcFileSessionRsp);
IMPL_META_STUB_METHOD(beginEcFilePwrite, BeginEcFilePwriteReq, EcFilePwriteRsp);
IMPL_META_STUB_METHOD(queryEcFilePwrite, QueryEcFilePwriteReq, EcFilePwriteRsp);
IMPL_META_STUB_METHOD(advanceEcFilePwrite, AdvanceEcFilePwriteReq, EcFilePwriteRsp);
IMPL_META_STUB_METHOD(closeEcFileSession, CloseEcFileSessionReq, CloseEcFileSessionRsp);
IMPL_META_STUB_METHOD(acquireEcTreeRead, AcquireEcTreeReadReq, EcTreeReadRsp);
IMPL_META_STUB_METHOD(queryEcTreeRead, QueryEcTreeReadReq, EcTreeReadRsp);
IMPL_META_STUB_METHOD(releaseEcTreeRead, ReleaseEcTreeReadReq, EcTreeReadRsp);
IMPL_META_STUB_METHOD(advanceEcTreeReclaim, AdvanceEcTreeReclaimReq, AdvanceEcTreeReclaimRsp);
IMPL_META_STUB_METHOD(beginEcFileTruncate, BeginEcFileTruncateReq, EcFileTruncateRsp);
IMPL_META_STUB_METHOD(queryEcFileTruncate, QueryEcFileTruncateReq, EcFileTruncateRsp);
IMPL_META_STUB_METHOD(advanceEcFileTruncate, AdvanceEcFileTruncateReq, EcFileTruncateRsp);
IMPL_META_STUB_METHOD(closeEcFileTruncateDebt, CloseEcFileTruncateDebtReq, EcFileTruncateRsp);
IMPL_META_STUB_METHOD(beginEcFileAppend, BeginEcFileAppendReq, EcFileAppendRsp);
IMPL_META_STUB_METHOD(queryEcFileAppend, QueryEcFileAppendReq, EcFileAppendRsp);
IMPL_META_STUB_METHOD(syncEcFileSession, SyncEcFileSessionReq, SyncEcFileSessionRsp);
IMPL_META_STUB_METHOD(beginEcFileRepair, BeginEcFileRepairReq, EcFileRepairRsp);
IMPL_META_STUB_METHOD(queryEcFileRepair, QueryEcFileRepairReq, EcFileRepairRsp);
IMPL_META_STUB_METHOD(advanceEcFileRepair, AdvanceEcFileRepairReq, EcFileRepairRsp);
IMPL_META_STUB_METHOD(closeEcFileRepairDebt, CloseEcFileRepairDebtReq, EcFileRepairRsp);

template class MetaServiceStub<serde::ClientContext>;
template class MetaServiceStub<serde::ClientMockContext>;
}  // namespace hf3fs::meta
