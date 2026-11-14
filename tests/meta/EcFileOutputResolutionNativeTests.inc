// Real private FDB, authenticated Meta73/74 and actual Storage control T2.
// No missing stage or candidate is converted into a physical reclamation ACK.
class TestEcFileOutputResolution : public TestEcFileNativeWrite {
 protected:
  void reserveWithoutIssuance(const AdvanceEcFilePwriteReq &req) {
    EcV2Coordinator coordinator(metaConfig_, mgmtd_, storageClient_);
    auto pool = coordinator.configuredPool();
    ASSERT_OK(pool);
    const EcOwner owner{user_.uid, metaClientId_.uuid};
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      ASSERT_OK(blockingWait(EcFileMutationCatalog::planChild(tx, owner, req.intent)));
      ASSERT_OK(blockingWait(tx.commit()));
    }
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto reserved = blockingWait(EcFileExecutionCatalog::reserveExecution(tx, owner, req.object, req.child, *pool, 0));
      ASSERT_OK(reserved);
      ASSERT_EQ(reserved->record.issuanceSequence, 0);
      ASSERT_FALSE(reserved->record.allocations);
      ASSERT_OK(blockingWait(tx.commit()));
    }
  }
  void cleanupOutput(const AdvanceEcFilePwriteReq &req) {
    auto cleanup = req;
    cleanup.action = EcFileAdvanceAction::CleanupChild;
    cleanup.outputRevocation = Uuid::random();
    cleanup.sourceRevocation = Uuid::random();
    ASSERT_OK(blockingWait(metaClient_->advanceEcFilePwrite(cleanup)));
  }
  void closeOutputBeforeSource(const AdvanceEcFilePwriteReq &req) {
    EcV2Coordinator coordinator(metaConfig_, mgmtd_, storageClient_);
    ASSERT_OK(coordinator.checkEnabled());
    const EcOwner owner{user_.uid, metaClientId_.uuid};
    EcV2DrainRecord frozen;
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto started = blockingWait(EcFileExecutionCatalog::startCancelClosing(
          tx, owner, req.object, req.child, coordinator.authority(), Uuid::random()));
      ASSERT_OK(started);
      frozen = *started;
      ASSERT_OK(blockingWait(tx.commit()));
    }
    for (size_t n = 0; n < frozen.identity.endpoints.count; ++n) {
      const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
      auto request = EcV2DrainCatalog::makeRequest(frozen, n, storage::EcScopeControlAction::Revoke,
                                                   coordinator.controlKey(), seconds);
      ASSERT_OK(request);
      auto ack = blockingWait(storageClient_->revokeEcScope(*request));
      ASSERT_OK(ack);
      ASSERT_EQ(ack->claims.state, storage::EcScopeControlState::Drained);
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      ASSERT_OK(blockingWait(EcFileExecutionCatalog::recordAck(
          tx, owner, req.object, req.child, n, coordinator.controlKey(), *request, *ack)));
      ASSERT_OK(blockingWait(tx.commit()));
    }
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
    auto done = blockingWait(EcFileExecutionCatalog::finishDrain(tx, owner, req.object, req.child,
                                                                coordinator.controlKey()));
    ASSERT_OK(done);
    ASSERT_EQ(done->record.state, EcFileExecutionState::Aborted);
    ASSERT_OK(blockingWait(tx.commit()));
  }
  Result<ConfirmEcFileOutputResolutionReq> confirmation(const AdvanceEcFilePwriteReq &accepted) {
    EcFileOutputIdentity i;
    i.object = accepted.object;
    i.owner = {user_.uid, metaClientId_.uuid};
    i.parent = accepted.operation;
    i.child = accepted.child;
    i.ownerKind = EcFileOutputOwner::Pwrite;
    CHECK_RESULT(observation, fileOutputRequest(i));
    ConfirmEcFileOutputResolutionReq req;
    static_cast<ReqBase &>(req) = static_cast<const ReqBase &>(observation);
    req.identity = i;
    req.resolutionId = Uuid::random();
    return req;
  }
  QueryEcFileOutputResolutionReq queryFor(const ConfirmEcFileOutputResolutionReq &req) {
    QueryEcFileOutputResolutionReq query;
    static_cast<ReqBase &>(query) = static_cast<const ReqBase &>(req);
    query.uuid = Uuid::random();
    query.identity = req.identity;
    query.resolutionId = req.resolutionId;
    return query;
  }
};

TEST_F(TestEcFileOutputResolution, UnissuedZeroAndIssuedDataCloseBeforePermanentQualification) {
  std::optional<Uuid> originalResolution;
  for (bool data : {false, true}) {
    SCOPED_TRACE(data ? "Data source, installed RMW, never bound" : "Zero source, no issuance");
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, data ? "resolution-data" : "resolution-zero");
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = kEcSessionWrite;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    if (data) {
      AdvanceEcFilePwriteReq initial;
      ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, bytes(kShardBytes + 31, 201), false, initial));
    }
    AdvanceEcFilePwriteReq accepted;
    ASSERT_NO_FATAL_FAILURE(acceptPatch(*opened, 0, bytes(kShardBytes + 7, 202), accepted));
    if (data) {
      auto installed = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
      ASSERT_OK(installed);
      ASSERT_TRUE(installed->progress.worker);
      ASSERT_TRUE(installed->progress.child);
      // WRITE-only public progress omits the source; inspect the exact committed child.
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto child = blockingWait(EcFileMutationCatalog::queryChild(
          tx, accepted.object, accepted.child, EcOwner{user_.uid, metaClientId_.uuid}));
      ASSERT_OK(child);
      ASSERT_TRUE(*child);
      ASSERT_EQ((**child).source.kind, EcTreeSlotKind::Data);
    } else ASSERT_NO_FATAL_FAILURE(reserveWithoutIssuance(accepted));
    auto confirm = confirmation(accepted);
    ASSERT_OK(confirm);
    if (originalResolution) {
      auto reused = *confirm;
      reused.resolutionId = *originalResolution;
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(reused)), StatusCode::kTokenMismatch);
    }
    auto query = queryFor(*confirm);
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutputResolution(query)), MetaCode::kNotFound);
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm)), StatusCode::kTokenStale);
    if (data) {
      ASSERT_NO_FATAL_FAILURE(closeOutputBeforeSource(accepted));
      // Actual output T2 alone cannot retire the original active Data source debt.
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm)), StatusCode::kTokenStale);
    }
    ASSERT_NO_FATAL_FAILURE(cleanupOutput(accepted));
    auto closed = observeFileOutput(accepted.object, accepted.operation, accepted.child, EcFileOutputOwner::Pwrite);
    ASSERT_OK(closed);
    ASSERT_EQ(closed->observation.state, EcFileOutputState::Aborted);
    ASSERT_FALSE(closed->observation.allocations);
    ASSERT_TRUE(closed->observation.outputT2Confirmed);
    auto result = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
    ASSERT_OK(result);
    originalResolution = confirm->resolutionId;
    const auto frozen = result->resolution;
    ASSERT_OK(frozen.valid());
    EXPECT_EQ(frozen.kind, data ? EcFileOutputResolutionKind::NeverBoundAfterClose
                               : EcFileOutputResolutionKind::NoIssuanceAfterClose);
    EXPECT_EQ(frozen.issuanceSequence == 0, !data);
    EXPECT_EQ(frozen.sourceKind, data ? EcTreeSlotKind::Data : EcTreeSlotKind::Zero);
    EXPECT_EQ(frozen.sourceClosure.has_value(), data);
    EXPECT_EQ(frozen.sourcePin.is_nil(), !data);
    EXPECT_TRUE(frozen.candidateReservationsReleaseEligible);
    EXPECT_FALSE(frozen.collected);
    EXPECT_FALSE(frozen.physicalReclamationConfirmed);
    EXPECT_EQ(serde::serialize(frozen.candidates), serde::serialize(closed->observation.candidates));
    // An acknowledged record can be recovered after the first reply is ignored.
    // A fresh transport request UUID does not change the permanent resolution.
    confirm->uuid = Uuid::random();
    auto replay = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
    ASSERT_OK(replay);
    EXPECT_EQ(serde::serialize(replay->resolution), serde::serialize(frozen));
    {
      // MetaClient supplies its own namespace; changing ReqBase.client alone
      // would not exercise another administrative namespace over actual TCP.
      const ClientId otherIdentity(Uuid::random());
      auto factory = std::make_unique<meta::client::MetaClient::StubFactory>(
          [this](net::Address address) { return metaNet_->serdeCtx(address); });
      meta::client::MetaClient other(otherIdentity, metaClientConfig_, std::move(factory), mgmtd_, storageClient_, false);
      SCOPE_EXIT { other.stop(); };
      auto observer = blockingWait(other.queryEcFileOutputResolution(query));
      ASSERT_OK(observer);
      EXPECT_EQ(observer->clientNamespace, otherIdentity.uuid);
      EXPECT_EQ(serde::serialize(observer->resolution), serde::serialize(frozen));
      ASSERT_ERROR(blockingWait(other.confirmEcFileOutputResolution(*confirm)), StatusCode::kTokenMismatch);
    }
    auto changed = *confirm;
    changed.resolutionId = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(changed)), StatusCode::kTokenMismatch);
    changed = *confirm;
    changed.user = user_;
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(changed)), MetaCode::kNoPermission);
    query.user = user_;
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutputResolution(query)), MetaCode::kNoPermission);
    auto key = storage::EcScopeControlKey::loadFile(controlKeyPath_.string());
    ASSERT_OK(key);
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto read = blockingWait(EcFileOutputResolutionCatalog::query(tx, confirm->identity, confirm->resolutionId, **key));
      ASSERT_OK(read);
      EXPECT_EQ(tx.usage().mutationBytes, 0);
      EXPECT_LE(tx.usage().totalBytes(), tx.limits().bytes);
      EXPECT_LE(tx.usage().keyOperations, tx.limits().keyOperations);
      RecordProperty(data ? "data_resolution_query_bytes" : "zero_resolution_query_bytes",
                     std::to_string(tx.usage().totalBytes()));
    }
    auto close = request<CloseEcFileSessionReq>();
    close.object = accepted.object;
    close.session = open.session;
    ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
    auto history = blockingWait(metaClient_->queryEcFileOutputResolution(queryFor(*confirm)));
    ASSERT_OK(history);
    EXPECT_EQ(serde::serialize(history->resolution), serde::serialize(frozen));
  }
  RecordProperty("scope", "Meta candidate reservation eligibility only; no physical collection or external debit");
}

TEST_F(TestEcFileOutputResolution, BoundAndInconsistentPermanentEvidenceNeverQualify) {
  using namespace ec_tree_detail;
  for (bool bound : {true, false}) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, bound ? "resolution-bound" : "resolution-corruption");
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = kEcSessionWrite;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    AdvanceEcFilePwriteReq accepted;
    if (bound) ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, bytes(kShardBytes + 3, 203), false, accepted, true));
    else {
      ASSERT_NO_FATAL_FAILURE(acceptPatch(*opened, 0, bytes(kShardBytes + 3, 204), accepted));
      ASSERT_NO_FATAL_FAILURE(reserveWithoutIssuance(accepted));
    }
    ASSERT_NO_FATAL_FAILURE(cleanupOutput(accepted));
    auto confirm = confirmation(accepted);
    ASSERT_OK(confirm);
    if (bound) {
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm)), StatusCode::kTokenStale);
    } else {
      auto observation = observeFileOutput(accepted.object, accepted.operation, accepted.child, EcFileOutputOwner::Pwrite);
      ASSERT_OK(observation);
      // The last candidate must be checked even though ECFE.allocations is absent.
      auto residual = allocationKey(kv::KeyPrefix::EcV2Allocation, observation->observation.candidates[11].identity);
      ASSERT_OK(residual);
      auto raw = kv_->createReadWriteTransaction();
      ASSERT_OK(blockingWait(raw->set(*residual, "unexpected-permanent-binding")));
      ASSERT_OK(blockingWait(raw->commit()));
      auto rejected = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
      raw = kv_->createReadWriteTransaction();
      ASSERT_OK(blockingWait(raw->clear(*residual)));
      ASSERT_OK(blockingWait(raw->commit()));
      ASSERT_ERROR(rejected, StatusCode::kDataCorruption);
      ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutputResolution(queryFor(*confirm))), MetaCode::kNotFound);
      auto good = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
      ASSERT_OK(good);
      // Losing either permanent index cannot be repaired by another Confirm.
      std::string reverse(kv::toStr(kv::KeyPrefix::EcFileOutputResolutionRequest));
      reverse.append(confirm->client.uuid.asStringView());
      reverse.append(confirm->resolutionId.asStringView());
      const auto primary = idKey(kv::KeyPrefix::EcFileOutputResolution, accepted.object, accepted.child);
      for (const auto &key : {reverse, primary}) {
        raw = kv_->createReadWriteTransaction();
        auto saved = blockingWait(raw->get(key));
        ASSERT_OK(saved);
        ASSERT_TRUE(*saved);
        ASSERT_OK(blockingWait(raw->clear(key)));
        ASSERT_OK(blockingWait(raw->commit()));
        auto missing = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
        raw = kv_->createReadWriteTransaction();
        ASSERT_OK(blockingWait(raw->set(key, **saved)));
        ASSERT_OK(blockingWait(raw->commit()));
        ASSERT_ERROR(missing, StatusCode::kDataCorruption);
      }
      // Historical T2 remains mandatory on Query; it is not replaced by a bool.
      const auto executionKey = idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child);
      raw = kv_->createReadWriteTransaction();
      auto saved = blockingWait(raw->get(executionKey));
      ASSERT_OK(saved);
      ASSERT_TRUE(*saved);
      EcFileExecutionRecord damaged;
      ASSERT_TRUE(serde::deserialize(damaged, **saved));
      ASSERT_TRUE(damaged.drain);
      damaged.drain->observations[0].reset();
      ASSERT_OK(blockingWait(raw->set(executionKey, serde::serialize(damaged))));
      ASSERT_OK(blockingWait(raw->commit()));
      auto missingAck = blockingWait(metaClient_->queryEcFileOutputResolution(queryFor(*confirm)));
      raw = kv_->createReadWriteTransaction();
      ASSERT_OK(blockingWait(raw->set(executionKey, **saved)));
      ASSERT_OK(blockingWait(raw->commit()));
      ASSERT_ERROR(missingAck, StatusCode::kDataCorruption);
      ASSERT_OK(blockingWait(metaClient_->queryEcFileOutputResolution(queryFor(*confirm))));
      auto altered = good->resolution;
      altered.candidates[11].identity.allocation = Uuid::random();
      EXPECT_FALSE(altered.valid());
      altered = good->resolution;
      altered.physicalReclamationConfirmed = true;
      EXPECT_FALSE(altered.valid());
      altered = good->resolution;
      altered.issuanceSequence = 1;
      EXPECT_FALSE(altered.valid());
    }
    auto close = request<CloseEcFileSessionReq>();
    close.object = accepted.object;
    close.session = open.session;
    ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
  }
}

TEST_F(TestEcFileOutputResolution, OriginalFenceConflictsWithLateIssuanceAndCannotReopen) {
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "resolution-late-issuance");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = kEcSessionWrite;
  open.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(opened);
  AdvanceEcFilePwriteReq accepted;
  ASSERT_NO_FATAL_FAILURE(acceptPatch(*opened, 0, bytes(kShardBytes + 3, 205), accepted));
  ASSERT_NO_FATAL_FAILURE(reserveWithoutIssuance(accepted));
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  auto lateRaw = kv_->createReadWriteTransaction();
  EcFileTreeTxnBudget late(*lateRaw, EcFileTreeTxnBudget::Profile::Repair);
  auto staged = blockingWait(EcFileExecutionCatalog::reserveIssuance(late, owner, accepted.object, accepted.child));
  ASSERT_OK(staged);
  EXPECT_EQ(staged->record.issuanceSequence, 1);
  // Real T0 commits between a stale issuer's reads/writes and commit.
  // The production issuer signs only after commit; this transaction cannot win.
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget closing(*raw, EcFileTreeTxnBudget::Profile::Repair);
    ASSERT_OK(blockingWait(EcFileExecutionCatalog::startCancelClosing(
        closing, owner, accepted.object, accepted.child, authority_, Uuid::random())));
    ASSERT_OK(blockingWait(closing.commit()));
  }
  auto conflict = blockingWait(late.commit());
  ASSERT_ERROR(conflict, TransactionCode::kConflict);
  auto confirm = confirmation(accepted);
  ASSERT_OK(confirm);
  ASSERT_ERROR(blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm)), StatusCode::kTokenStale);
  ASSERT_NO_FATAL_FAILURE(cleanupOutput(accepted));
  auto qualified = blockingWait(metaClient_->confirmEcFileOutputResolution(*confirm));
  ASSERT_OK(qualified);
  EXPECT_EQ(qualified->resolution.kind, EcFileOutputResolutionKind::NoIssuanceAfterClose);
  EXPECT_EQ(qualified->resolution.issuanceSequence, 0);
  auto raw = kv_->createReadWriteTransaction();
  EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
  ASSERT_ERROR(blockingWait(EcFileExecutionCatalog::reserveIssuance(tx, owner, accepted.object, accepted.child)),
               StatusCode::kTokenStale);
  ASSERT_ERROR(blockingWait(metaClient_->advanceEcFilePwrite(accepted)), StatusCode::kTokenStale);
  auto close = request<CloseEcFileSessionReq>();
  close.object = accepted.object;
  close.session = open.session;
  ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
}
