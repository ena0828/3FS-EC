// Real Meta/FDB and TCP Storage/Rust Engine. All twelve allocations are bound
// by the existing repair issuer; only the selected subset is ever materialized.
class TestEcFileNativeAbsent : public TestEcFileNativeRepair {
 protected:
  struct CandidateRun {
    OpenEcFileSessionRsp opened;
    hf3fs::client::ec::EcTreeRepairRun run;
    EcFileRepairAccess access;
    UserInfo root;
  };
  void prepareCandidates(CandidateRun &out, uint16_t materialized, std::string name) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, name);
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = kEcSessionRead | kEcSessionWrite;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    AdvanceEcFilePwriteReq written;
    ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, bytes(2 * kShardBytes + 7, 151), false, written));
    opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    out.opened = *opened;
    const std::array<uint8_t, 10> selected{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    auto run = hf3fs::client::ec::prepareEcTreeRepair(opened->session, opened->root, name, 0, 3,
                                                   EcFileRepairMode::CentralSerial, selected);
    ASSERT_OK(run);
    out.run = *run;
    auto begin = request<BeginEcFileRepairReq>();
    begin.uuid = run->intent.request;
    begin.intent = run->intent;
    ASSERT_OK(blockingWait(metaClient_->beginEcFileRepair(begin)));
    auto prepare = request<AdvanceEcFileRepairReq>();
    prepare.uuid = run->prepareRequest;
    prepare.intent = run->intent;
    prepare.action = EcFileRepairAdvance::Prepare;
    auto issued = blockingWait(metaClient_->advanceEcFileRepair(prepare));
    ASSERT_OK(issued);
    ASSERT_TRUE(issued->access);
    out.access = *issued->access;
    for (size_t n = 0; n < 12; ++n) {
      if (!(materialized & (uint16_t{1} << n))) continue;
      storage::EcReadBlockV2Req read;
      read.request = access(out.access.sources[n]);
      read.grant = out.access.reads[n];
      auto payload = blockingWait(storageClient_->readEcBlockV2Controlled(read, control()));
      ASSERT_OK(payload);
      ASSERT_OK(storage::validateEcReadBlockV2(*payload, read));
      storage::EcBeginStageV2Req target;
      target.request = access(out.access.targets[n]);
      target.grant = out.access.writes[n];
      ASSERT_OK(blockingWait(storageClient_->beginEcStageV2Controlled(target, control())));
      storage::EcAppendStageV2Req append;
      append.request = target.request;
      append.grant = target.grant;
      append.payload = payload->payload;
      ASSERT_OK(blockingWait(storageClient_->appendEcStageV2Controlled(append, control())));
      auto sealed = blockingWait(storageClient_->sealEcStageV2Controlled({target.request, target.grant}, control()));
      ASSERT_OK(sealed);
      ASSERT_OK(storage::validateEcReceiptV2(*sealed, target.request, target.grant.claims));
    }
    auto query = observeFileOutput(run->intent.object, run->intent.operation, run->intent.child,
                                  EcFileOutputOwner::Repair);
    ASSERT_OK(query);
    ASSERT_EQ(query->observation.state, EcFileOutputState::Bound);
    ASSERT_TRUE(query->observation.allocations);
    ASSERT_EQ(query->observation.allocations->size(), 12);
    auto admin = fileOutputRequest(query->observation.identity);
    ASSERT_OK(admin);
    out.root = admin->user;
  }
  void closeCandidates(const CandidateRun &run) {
    auto close = request<CloseEcFileRepairDebtReq>();
    close.intent = run.run.intent;
    close.outputRevocation = Uuid::random();
    close.sourceRevocation = Uuid::random();
    auto closed = blockingWait(metaClient_->closeEcFileRepairDebt(close));
    ASSERT_OK(closed);
    ASSERT_TRUE(closed->progress.record);
    ASSERT_EQ(closed->progress.record->state, EcFileRepairState::Aborted);
    ASSERT_TRUE(closed->progress.outputDrained);
    ASSERT_TRUE(closed->progress.sourceReleased);
  }
  template <class Req>
  Req adminRequest(const CandidateRun &run, size_t shard, const Uuid &claim) {
    auto req = request<Req>();
    req.user = run.root;
    req.object = run.run.intent.object;
    req.identity = run.access.targets[shard].fragment.identity;
    req.claimId = claim;
    return req;
  }
  void lateBeginIsClosed(const CandidateRun &run, size_t shard) {
    storage::EcBeginStageV2Req late;
    late.request = access(run.access.targets[shard]);
    late.grant = run.access.writes[shard];
    const auto now = uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    // A failure caused only by expiry would not exercise the permanent fence.
    ASSERT_GT(late.grant.claims.expiresAtSeconds, now);
    ASSERT_ERROR(blockingWait(storageClient_->beginEcStageV2Controlled(late, control())), StatusCode::kTokenStale);
  }
};

TEST_F(TestEcFileNativeAbsent, MixedBoundCandidatesRequireDistinctCollectedOrAbsentFacts) {
  constexpr uint16_t present = (1u << 0) | (1u << 3) | (1u << 7) | (1u << 11);
  CandidateRun run;
  ASSERT_NO_FATAL_FAILURE(prepareCandidates(run, present, "mixed-bound-absence"));
  const auto earlyId = Uuid::random();
  auto early = adminRequest<ConfirmEcFragmentAbsentReq>(run, 1, earlyId);
  // Bound alone is not a closure certificate, even for a never-Begun target.
  ASSERT_FALSE(blockingWait(metaClient_->confirmEcFragmentAbsent(early)));
  ASSERT_NO_FATAL_FAILURE(closeCandidates(run));
  ASSERT_NO_FATAL_FAILURE(lateBeginIsClosed(run, 1));
  size_t absent = 0, collected = 0;
  for (size_t n = 0; n < 12; ++n) {
    SCOPED_TRACE(n);
    const auto claim = n == 1 ? earlyId : Uuid::random();
    auto confirm = adminRequest<ConfirmEcFragmentAbsentReq>(run, n, claim);
    auto query = adminRequest<QueryEcFragmentAbsentReq>(run, n, claim);
    auto collect = adminRequest<CollectEcFragmentV2Req>(run, n, claim);
    if (present & (uint16_t{1} << n)) {
      ASSERT_FALSE(blockingWait(metaClient_->confirmEcFragmentAbsent(confirm)));
      auto done = blockingWait(metaClient_->collectEcFragmentV2(collect));
      ASSERT_OK(done);
      EXPECT_NE(done->ledgerSha256, storage::EcSha256{});
      ASSERT_ERROR(blockingWait(metaClient_->queryEcFragmentAbsent(query)), StatusCode::kTokenStale);
      ++collected;
    } else {
      // Query does not manufacture the claim or a Storage absence ledger.
      ASSERT_FALSE(blockingWait(metaClient_->queryEcFragmentAbsent(query)));
      // Original G2 still refuses Missing; no semantic upgrade to Collected.
      ASSERT_FALSE(blockingWait(metaClient_->collectEcFragmentV2(collect)));
      auto done = blockingWait(metaClient_->confirmEcFragmentAbsent(confirm));
      ASSERT_OK(done);
      ASSERT_OK(done->valid());
      EXPECT_EQ(done->state, storage::EcGcAbsentState::AbsentAfterClose);
      EXPECT_TRUE(done->candidateReservationReleaseEligible);
      EXPECT_FALSE(done->collected);
      EXPECT_FALSE(done->physicalReclamationConfirmed);
      auto repeated = blockingWait(metaClient_->queryEcFragmentAbsent(query));
      ASSERT_OK(repeated);
      EXPECT_EQ(repeated->claimDigest, done->claimDigest);
      EXPECT_EQ(repeated->closureDigest, done->closureDigest);
      EXPECT_EQ(repeated->ledgerSha256, done->ledgerSha256);
      EXPECT_EQ(repeated->recordRevision, 1);
      ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(collect)), StatusCode::kTokenStale);
      ++absent;
    }
    // Both persistent tables are read from actual FDB, not response flags.
    auto tx = kv_->createReadWriteTransaction();
    auto oldKey = ec_tree_detail::allocationKey(kv::KeyPrefix::EcGcCompletion, confirm.identity);
    auto newKey = ec_tree_detail::allocationKey(kv::KeyPrefix::EcGcAbsentCompletion, confirm.identity);
    ASSERT_OK(oldKey);
    ASSERT_OK(newKey);
    auto old = blockingWait(tx->get(*oldKey));
    auto fresh = blockingWait(tx->get(*newKey));
    ASSERT_OK(old);
    ASSERT_OK(fresh);
    EXPECT_NE(bool(*old), bool(*fresh));
    EXPECT_EQ(bool(*old), bool(present & (uint16_t{1} << n)));
  }
  EXPECT_EQ(absent, 8);
  EXPECT_EQ(collected, 4);
  RecordProperty("absence_scope", "12 bound candidates; 4 actual sealed fragments and 8 never-Begun allocations");
  RecordProperty("capacity", "AbsentAfterClose permits only candidate reservation classification; no reclaimed bytes claim");
}

TEST_F(TestEcFileNativeAbsent, LostAbsentReplyReopensAndQueryRecordsTheOriginalFact) {
  CandidateRun run;
  ASSERT_NO_FATAL_FAILURE(prepareCandidates(run, 0, "lost-absence-reply"));
  ASSERT_NO_FATAL_FAILURE(closeCandidates(run));
  const auto claim = Uuid::random();
  auto confirm = adminRequest<ConfirmEcFragmentAbsentReq>(run, 0, claim);
  auto query = adminRequest<QueryEcFragmentAbsentReq>(run, 0, claim);
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.dropGcAbsentReply = claim;
  }
  auto unknown = blockingWait(metaClient_->confirmEcFragmentAbsent(confirm));
  ASSERT_ERROR(unknown, StorageCode::kEcSealOutcomeUnknown);
  storage::EcGcAbsentAck acknowledged;
  {
    std::unique_lock lock(controlFault_.mutex);
    ASSERT_TRUE(controlFault_.absentShutdown.wait_for(lock, std::chrono::seconds(5), [&] {
      return controlFault_.absentShutdownFinished;
    }));
    ASSERT_EQ(controlFault_.absentShutdownResult, 0);
    ASSERT_EQ(controlFault_.actualAbsentConfirms, 1);
    ASSERT_TRUE(controlFault_.observedAbsent);
    acknowledged = *controlFault_.observedAbsent;
  }
  auto key = ec_tree_detail::allocationKey(kv::KeyPrefix::EcGcAbsentCompletion, confirm.identity);
  ASSERT_OK(key);
  {
    auto tx = kv_->createReadWriteTransaction();
    auto before = blockingWait(tx->get(*key));
    ASSERT_OK(before);
    ASSERT_FALSE(*before); // Storage committed, but Meta never received that reply.
  }
  ASSERT_NO_FATAL_FAILURE(reopenStorageKeepingMeta());
  ASSERT_NO_FATAL_FAILURE(lateBeginIsClosed(run, 0));
  auto recovered = blockingWait(metaClient_->queryEcFragmentAbsent(query));
  ASSERT_OK(recovered);
  ASSERT_OK(recovered->valid());
  EXPECT_EQ(recovered->ledgerSha256, acknowledged.claims.ledgerSha256);
  EXPECT_EQ(recovered->claimDigest, acknowledged.claims.claimDigest);
  EXPECT_EQ(recovered->closureDigest, acknowledged.claims.closureDigest);
  EXPECT_EQ(recovered->recordRevision, acknowledged.claims.recordRevision);
  {
    std::lock_guard lock(controlFault_.mutex);
    EXPECT_EQ(controlFault_.actualAbsentConfirms, 1);
    EXPECT_EQ(controlFault_.actualAbsentQueries, 1);
  }
  auto tx = kv_->createReadWriteTransaction();
  auto saved = blockingWait(ec_tree_detail::load<EcGcAbsentCompletion>(*tx, *key));
  ASSERT_OK(saved);
  ASSERT_TRUE(*saved);
  EXPECT_EQ((**saved).request.claims.action, storage::EcGcAbsentAction::QueryAbsent);
  EXPECT_EQ((**saved).ack.claims.ledgerSha256, acknowledged.claims.ledgerSha256);
  auto changed = query;
  changed.claimId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->queryEcFragmentAbsent(changed)), StatusCode::kTokenMismatch);
  RecordProperty("recovery", "actual successful Rust absence WAL followed by TCP shutdown; Engine reopen; Query-only receipt recovery");
  RecordProperty("limits", "normal Engine close/reopen; no process-kill or power-loss claim");
}
