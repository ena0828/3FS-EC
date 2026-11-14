// Private FDB and actual Storage RMW -> Meta52 -> candidate writes. Only the
// competing metadata transaction / commit-ack boundary is test-controlled.
class TestEcRmwBindConflict : public TestEcFileNativeWrite {
 protected:
  using Fault = detail::EcRmwBindConflictFault;
  bool enableRmwBindConflictFault() const override { return true; }
  struct Attempt {
    AdvanceEcFilePwriteReq accepted;
    EcFileExecutionObservation before;
    storage::EcRmwStatus worker;
    storage::EcSha256 expectedContent{};
    status_code_t metaStatus = StorageClientCode::kNotInitialized;
  };
  Result<EcFileExecutionObservation> execution(const AdvanceEcFilePwriteReq &accepted) {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Rmw);
    return blockingWait(EcFileExecutionCatalog::get(
        tx, EcOwner{user_.uid, metaClientId_.uuid}, accepted.object, accepted.child));
  }
  void runWorker(Fault::Mode mode, size_t count, Attempt &attempt) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, "bind-conflict");
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = kEcSessionWrite;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    auto logical = bytes(kShardBytes + 31, 211);
    AdvanceEcFilePwriteReq initial;
    ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, logical, false, initial));
    const auto patch = bytes(37, 212);
    logical.replace(3, patch.size(), patch);
    auto expected = storage::ec_rmw_detail::sha256(logical);
    ASSERT_OK(expected);
    attempt.expectedContent = *expected;
    ASSERT_NO_FATAL_FAILURE(acceptPatch(*opened, 3, patch, attempt.accepted));
    auto installed = blockingWait(metaClient_->advanceEcFilePwrite(attempt.accepted));
    ASSERT_OK(installed);
    ASSERT_TRUE(installed->progress.worker);
    auto original = execution(attempt.accepted);
    ASSERT_OK(original);
    ASSERT_EQ(original->record.state, EcFileExecutionState::Reserved);
    ASSERT_EQ(original->record.child.source.kind, EcTreeSlotKind::Data);
    ASSERT_FALSE(original->record.allocations);
    attempt.before = *original;
    replyDrop_.bindConflict->arm(attempt.accepted.object, EcOwner{user_.uid, metaClientId_.uuid},
                                 attempt.accepted.child, authority_, mode, count);
    {
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.bindTrackedChild = attempt.accepted.child;
      replyDrop_.bindReplies = 0;
    }
    const auto access = *installed->progress.worker;
    net::Client::Config config;
    smallClient(config);
    auto transport = std::make_shared<storage::client::EcRmwTransport>(config);
    ASSERT_OK(transport->start());
    auto stopped = folly::makeGuard([&] { transport->stopAndJoin(); });
    storage::EcRmwPutReq put;
    put.planId = attempt.accepted.intent.plan;
    put.grant = access.grant;
    put.blockIndex = 0;
    put.payload.data = patch;
    const auto address = workerAddressFor(access.worker);
    ASSERT_OK(blockingWait(transport->put(address, std::move(put), control())));
    storage::EcRmwActionReq action;
    action.planId = attempt.accepted.intent.plan;
    action.grant = access.grant;
    action.action = storage::EcRmwActionRequest::Submit;
    auto result = blockingWait(transport->action(address, action, control()));
    ASSERT_OK(result);
    action.action = storage::EcRmwActionRequest::Query;
    const auto deadline = SteadyClock::now() + 30_s;
    while (result->state != 4 && SteadyClock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      result = blockingWait(transport->action(address, action, control()));
      ASSERT_OK(result);
    }
    ASSERT_EQ(result->state, 4);
    attempt.worker = *result;
    {
      std::lock_guard lock(replyDrop_.mutex);
      ASSERT_EQ(replyDrop_.bindReplies, 1);
      attempt.metaStatus = replyDrop_.bindStatus;
    }
  }
  void fixedBinding(const Attempt &attempt, const EcFileExecutionObservation &observed) {
    EXPECT_EQ(serde::serialize(observed.record.child.intent), serde::serialize(attempt.accepted.intent));
    EXPECT_EQ(serde::serialize(observed.record.candidates), serde::serialize(attempt.before.record.candidates));
    EXPECT_EQ(observed.record.planDigest, attempt.before.record.planDigest);
    const auto trace = replyDrop_.bindConflict->snapshot();
    EXPECT_EQ(trace.setupErrors, 0);
    EXPECT_EQ(trace.active, 0);
    EXPECT_FALSE(trace.changed);
    EXPECT_FALSE(trace.overflow);
    EXPECT_EQ(trace.planDigest, attempt.before.record.planDigest);
    EXPECT_EQ(trace.contentSha256, attempt.expectedContent);
  }
  void closeOriginal(const Attempt &attempt) {
    auto cleanup = attempt.accepted;
    cleanup.action = EcFileAdvanceAction::CleanupChild;
    auto observed = execution(attempt.accepted);
    ASSERT_OK(observed);
    cleanup.outputRevocation = observed->record.drain ? observed->record.drain->identity.revocationId : Uuid::random();
    cleanup.sourceRevocation = Uuid::random();
    const auto deadline = SteadyClock::now() + 10_s;
    auto closed = blockingWait(metaClient_->advanceEcFilePwrite(cleanup));
    while (!closed && closed.error().code() == StorageClientCode::kResourceBusy) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      ASSERT_LT(SteadyClock::now(), deadline);
      closed = blockingWait(metaClient_->advanceEcFilePwrite(cleanup));
    }
    ASSERT_OK(closed);
    EXPECT_TRUE(closed->progress.outputDrained);
    EXPECT_TRUE(closed->progress.sourceReleased);
  }
};

TEST_F(TestEcRmwBindConflict, OneConflictBindsOriginalComputedOutput) {
  Attempt attempt;
  ASSERT_NO_FATAL_FAILURE(runWorker(Fault::Mode::Conflict, 1, attempt));
  ASSERT_EQ(attempt.worker.executionError, StatusCode::kOK);
  EXPECT_EQ(attempt.metaStatus, StatusCode::kOK);
  const auto trace = replyDrop_.bindConflict->snapshot();
  EXPECT_EQ(trace.attempts, 2);
  EXPECT_EQ(trace.injections, 1);
  EXPECT_EQ(trace.competingCommits, 1);
  EXPECT_EQ(trace.originalCommits, 2);
  EXPECT_EQ(trace.originalConflicts, 1);
  EXPECT_EQ(trace.rawSucceeded, 1);
  EXPECT_EQ(trace.ackLost, 0);
  auto bound = execution(attempt.accepted);
  ASSERT_OK(bound);
  ASSERT_EQ(bound->record.state, EcFileExecutionState::Bound);
  ASSERT_TRUE(bound->record.allocations);
  EXPECT_EQ(bound->record.contentSha256, attempt.expectedContent);
  EXPECT_EQ(bound->record.issuanceSequence, attempt.before.record.issuanceSequence + 2);
  ASSERT_NO_FATAL_FAILURE(fixedBinding(attempt, *bound));
  auto publish = attempt.accepted;
  publish.action = EcFileAdvanceAction::Publish;
  auto published = blockingWait(metaClient_->advanceEcFilePwrite(publish));
  ASSERT_OK(published);
  ASSERT_TRUE(published->progress.child);
  EXPECT_EQ(published->progress.child->state, EcFileChildState::Published);
  ASSERT_NO_FATAL_FAILURE(closeOriginal(attempt));
}

TEST_F(TestEcRmwBindConflict, FourConflictsStopWithoutBinding) {
  Attempt attempt;
  ASSERT_NO_FATAL_FAILURE(runWorker(Fault::Mode::Conflict, 4, attempt));
  EXPECT_EQ(attempt.worker.executionError, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(attempt.metaStatus, TransactionCode::kConflict);
  const auto trace = replyDrop_.bindConflict->snapshot();
  EXPECT_EQ(trace.attempts, 4);
  EXPECT_EQ(trace.injections, 4);
  EXPECT_EQ(trace.competingCommits, 4);
  EXPECT_EQ(trace.originalCommits, 4);
  EXPECT_EQ(trace.originalConflicts, 4);
  EXPECT_EQ(trace.rawSucceeded, 0);
  EXPECT_EQ(trace.ackLost, 0);
  auto unbound = execution(attempt.accepted);
  ASSERT_OK(unbound);
  EXPECT_EQ(unbound->record.state, EcFileExecutionState::Reserved);
  EXPECT_FALSE(unbound->record.allocations);
  EXPECT_EQ(unbound->record.issuanceSequence, attempt.before.record.issuanceSequence + 4);
  ASSERT_NO_FATAL_FAILURE(fixedBinding(attempt, *unbound));
  ASSERT_NO_FATAL_FAILURE(closeOriginal(attempt));
}

TEST_F(TestEcRmwBindConflict, CommittedUnknownIsNotRetried) {
  Attempt attempt;
  ASSERT_NO_FATAL_FAILURE(runWorker(Fault::Mode::CommitAckLost, 1, attempt));
  EXPECT_EQ(attempt.worker.executionError, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(attempt.metaStatus, TransactionCode::kMaybeCommitted);
  const auto trace = replyDrop_.bindConflict->snapshot();
  EXPECT_EQ(trace.attempts, 1);
  EXPECT_EQ(trace.originalCommits, 1);
  EXPECT_EQ(trace.originalConflicts, 0);
  EXPECT_EQ(trace.competingCommits, 0);
  EXPECT_EQ(trace.rawSucceeded, 1);
  EXPECT_EQ(trace.ackLost, 1);
  EXPECT_EQ(trace.events[0].rawStatus, StatusCode::kOK);
  EXPECT_EQ(trace.events[0].deliveredStatus, TransactionCode::kMaybeCommitted);
  auto bound = execution(attempt.accepted);
  ASSERT_OK(bound);
  EXPECT_EQ(bound->record.state, EcFileExecutionState::Bound);
  ASSERT_TRUE(bound->record.allocations);
  EXPECT_EQ(bound->record.contentSha256, attempt.expectedContent);
  EXPECT_EQ(bound->record.issuanceSequence, attempt.before.record.issuanceSequence + 1);
  ASSERT_NO_FATAL_FAILURE(fixedBinding(attempt, *bound));
  ASSERT_NO_FATAL_FAILURE(closeOriginal(attempt));
}

TEST_F(TestEcRmwBindConflict, ClosingDuringConflictPreventsIssuance) {
  Attempt attempt;
  ASSERT_NO_FATAL_FAILURE(runWorker(Fault::Mode::CloseBeforeRetry, 1, attempt));
  EXPECT_EQ(attempt.worker.executionError, StorageCode::kEcSealOutcomeUnknown);
  EXPECT_EQ(attempt.metaStatus, StatusCode::kTokenStale);
  const auto trace = replyDrop_.bindConflict->snapshot();
  EXPECT_EQ(trace.attempts, 1);
  EXPECT_EQ(trace.injections, 1);
  EXPECT_EQ(trace.closingCommits, 1);
  EXPECT_EQ(trace.competingCommits, 1);
  EXPECT_EQ(trace.originalCommits, 1);
  EXPECT_EQ(trace.originalConflicts, 1);
  EXPECT_EQ(trace.rawSucceeded, 0);
  EXPECT_EQ(trace.ackLost, 0);
  auto closing = execution(attempt.accepted);
  ASSERT_OK(closing);
  EXPECT_EQ(closing->record.state, EcFileExecutionState::Closing);
  EXPECT_FALSE(closing->record.allocations);
  EXPECT_EQ(closing->record.issuanceSequence, attempt.before.record.issuanceSequence);
  ASSERT_TRUE(closing->record.drain);
  EXPECT_EQ(closing->record.drain->identity.revocationId, trace.revocation);
  ASSERT_NO_FATAL_FAILURE(fixedBinding(attempt, *closing));
  ASSERT_NO_FATAL_FAILURE(closeOriginal(attempt));
}
