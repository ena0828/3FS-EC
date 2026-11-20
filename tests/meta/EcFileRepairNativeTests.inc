// Actual private FDB/Meta/TCP/Engine path. The mask is a controlled erasure
// selection, not an assertion that a physical machine has failed.
class TestEcFileNativeRepair : public TestEcFileNativeWrite {
 protected:
  bool enableHelperIssuance() const override { return true; }
};
TEST_F(TestEcFileNativeRepair, ThreeStrategiesPublishFreshTwelveAndKeepSourceDebtExplicit) {
  using namespace hf3fs::client::ec;
  const auto directory = std::filesystem::path(traces_.path().string());
  auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected = EcFileRepairClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid);
  ASSERT_OK(connected);
  auto client = std::move(*connected);
  const auto ctl = [] { return EcStripeControl{SteadyClock::now() + std::chrono::seconds(120), {}}; };
  for (auto mode : {EcFileRepairMode::CentralSerial, EcFileRepairMode::ClientPipeline, EcFileRepairMode::HelperChain}) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, fmt::format("native-repair-{}", uint8_t(mode)));
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = 3;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    const auto expected = bytes(2 * kShardBytes + 7, 127 + uint8_t(mode));
    AdvanceEcFilePwriteReq written;
    ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, expected, false, written));
    opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    const std::array<uint8_t, 10> selected{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    auto run = prepareEcTreeRepair(opened->session, opened->root, "native-mode4-repair", 0, 3, mode, selected);
    ASSERT_OK(run);
    if (mode == EcFileRepairMode::CentralSerial) {
      auto wo = request<OpenEcFileSessionReq>();
      wo.object = opened->object.object;
      wo.birth = opened->root.birth;
      wo.session = Uuid::random();
      wo.rights = kEcSessionWrite;
      auto writeOnly = blockingWait(metaClient_->openEcFileSession(wo));
      ASSERT_OK(writeOnly);
      auto denied = request<BeginEcFileRepairReq>();
      denied.intent = run->intent;
      denied.intent.session = wo.session;
      denied.uuid = run->intent.request;
      ASSERT_ERROR(blockingWait(metaClient_->beginEcFileRepair(denied)), MetaCode::kNoPermission);
      auto close = request<CloseEcFileSessionReq>();
      close.object = opened->object.object;
      close.session = wo.session;
      ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
    }
    auto path = directory / fmt::format("repair-{}", uint8_t(mode));
    auto made = EcTreeRepairJournal::create(path, *run);
    ASSERT_OK(made);
    auto journal = std::move(*made);
    EcTreeRepairState issued;
    issued.issued = true;
    ASSERT_OK(journal->append(issued));
    auto begin = request<BeginEcFileRepairReq>();
    begin.uuid = run->intent.request;
    begin.intent = run->intent;
    {
      auto accepted = blockingWait(metaClient_->beginEcFileRepair(begin));
      ASSERT_OK(accepted);
      ASSERT_TRUE(accepted->progress.record);
    }
    // Discard a genuinely committed acceptance, reopen the identical journal.
    journal.reset();
    auto resumed = EcTreeRepairJournal::resume(path);
    ASSERT_OK(resumed);
    journal = std::move(*resumed);
    auto changed = begin;
    changed.intent.mode =
        mode == EcFileRepairMode::CentralSerial ? EcFileRepairMode::ClientPipeline : EcFileRepairMode::CentralSerial;
    ASSERT_ERROR(blockingWait(metaClient_->beginEcFileRepair(changed)), StatusCode::kTokenMismatch);
    auto prepared = request<AdvanceEcFileRepairReq>();
    prepared.uuid = run->prepareRequest;
    prepared.intent = run->intent;
    prepared.action = EcFileRepairAdvance::Prepare;
    auto access = blockingWait(metaClient_->advanceEcFileRepair(prepared));
    ASSERT_OK(access);
    ASSERT_TRUE(access->access);
    std::set<Uuid> oldIds;
    for (const auto &a : access->access->sources) oldIds.insert(a.fragment.identity.allocation);
    ASSERT_EQ(oldIds.size(), 12);
    for (size_t n = 0; n < 12; ++n) {
      const auto &a = access->access->targets[n];
      EXPECT_FALSE(oldIds.contains(a.fragment.identity.allocation));
      EXPECT_EQ(a.fragment.identity.generation, access->access->sources[n].fragment.identity.generation);
    }
    for (const auto &g : access->access->reads) {
      EXPECT_EQ(g.claims.scopeKind, storage::EcGrantScope::ReadPin);
      EXPECT_EQ(g.claims.scopeId, run->intent.sourcePin);
    }
    for (const auto &g : access->access->pipelineReads) {
      EXPECT_EQ(g.claims.scopeKind, storage::EcGrantScope::WriteOperation);
      EXPECT_EQ(g.claims.scopeId, run->intent.child);
    }
    // An explicit cancelled call records no new RPC and leaves the old journal
    // sequence unchanged. The next call uses the same original operation IDs.
    const auto priorSequence = journal->latest()->sequence;
    CancellationSource cancelled;
    cancelled.requestCancellation();
    auto cancelledControl = ctl();
    cancelledControl.cancellation = cancelled.getToken();
    auto stopped = client->repair(*journal, cancelledControl, true);
    ASSERT_TRUE(stopped.failure);
    EXPECT_EQ(stopped.failure->code(), StorageClientCode::kRequestCanceled);
    EXPECT_TRUE(stopped.metrics.available);
    EXPECT_TRUE(stopped.metrics.journalStateObserved);
    EXPECT_TRUE(stopped.metrics.cancellationRequested);
    EXPECT_EQ(stopped.metrics.priorJournalSequence, priorSequence);
    EXPECT_EQ(journal->latest()->sequence, priorSequence);
    for (const auto &point : stopped.metrics.points) EXPECT_EQ(point.entered, 0);
    for (const auto &method : stopped.metrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
    for (const auto &method : stopped.metrics.selectedRepairRpc.methods) EXPECT_EQ(method.entered, 0);
    for (const auto &method : stopped.metrics.healthyCopyRpc.methods) EXPECT_EQ(method.entered, 0);
    auto completed = client->repair(*journal, ctl(), true);
    ASSERT_FALSE(completed.failure);
    ASSERT_TRUE(completed.revalidated);
    ASSERT_TRUE(completed.progress.record);
    EXPECT_EQ(completed.progress.record->state, EcFileRepairState::Published);
    EXPECT_TRUE(completed.progress.outputDrained);
    EXPECT_FALSE(completed.progress.sourceReleased);
    auto output = observeFileOutput(run->intent.object, run->intent.operation, run->intent.child,
                                    EcFileOutputOwner::Repair);
    ASSERT_OK(output);
    EXPECT_EQ(output->observation.state, EcFileOutputState::Published);
    EXPECT_TRUE(output->observation.outputT2Confirmed);
    EXPECT_FALSE(output->observation.physicalReclamationConfirmed);
    ASSERT_TRUE(output->observation.allocations);
    EXPECT_EQ(output->observation.allocations->size(), 12);
    EXPECT_EQ(output->observation.identity.ownerKind, EcFileOutputOwner::Repair);
    const auto &metrics = completed.metrics;
    ASSERT_TRUE(metrics.available);
    EXPECT_FALSE(metrics.overflow);
    EXPECT_FALSE(metrics.clockAnomaly);
    EXPECT_EQ(metrics.action, 1);
    EXPECT_EQ(metrics.at(EcRepairPoint::Query).succeeded, 1);
    EXPECT_EQ(metrics.at(EcRepairPoint::Prepare).succeeded, 1);
    EXPECT_EQ(metrics.at(EcRepairPoint::Publish).succeeded, 1);
    EXPECT_EQ(metrics.at(EcRepairPoint::SelectedRepair).succeeded, 1);
    EXPECT_EQ(metrics.at(EcRepairPoint::HealthyCopy).succeeded, 10);
    EXPECT_EQ(metrics.at(EcRepairPoint::CopyRead).validatedReturnedPayloadBytes, 10ULL * kShardBytes);
    EXPECT_EQ(metrics.at(EcRepairPoint::CopyAppend).submittedPayloadBytes, 10ULL * kShardBytes);
    EXPECT_EQ(metrics.at(EcRepairPoint::NativeAppend).submittedPayloadBytes, 2ULL * kShardBytes);
    EXPECT_EQ(metrics.at(EcRepairPoint::NativeSeal).succeeded, 2);
    EXPECT_EQ(metrics.blockActorsApplicable, mode != EcFileRepairMode::CentralSerial);
    EXPECT_LE(metrics.at(EcRepairPoint::BlockActor).peakActive, run->intent.selection.maxBlocksInFlight);
    EXPECT_EQ(metrics.at(EcRepairPoint::CentralCodecRecover).entered,
              mode == EcFileRepairMode::CentralSerial ? 1 : 0);
    EXPECT_EQ(metrics.at(EcRepairPoint::ClientBlockAdvance).entered,
              mode == EcFileRepairMode::ClientPipeline ? 10 : 0);
    if (mode == EcFileRepairMode::HelperChain) {
      EXPECT_EQ(metrics.at(EcRepairPoint::NativeRead).apiInvocations, 0);
      EXPECT_EQ(metrics.at(EcRepairPoint::NativeHelper).validatedReturnedPayloadBytes, 2ULL * kShardBytes);
    } else {
      EXPECT_EQ(metrics.at(EcRepairPoint::NativeRead).validatedReturnedPayloadBytes, 10ULL * kShardBytes);
      EXPECT_EQ(metrics.at(EcRepairPoint::NativeHelper).apiInvocations, 0);
    }
    for (const auto &point : metrics.points) {
      EXPECT_EQ(point.active, 0);
      EXPECT_EQ(point.entered, point.finished);
    }
    using storage::client::EcRpcMethod;
    const auto &rpc = metrics.storageRpc;
    EXPECT_FALSE(rpc.overflow);
    EXPECT_FALSE(rpc.clockAnomaly);
    // Real TCP first-hop samples, including healthy-copy and the selected
    // repair's NativeEcBlockTransport adapter. No downstream Helper claims.
    EXPECT_EQ(rpc.at(EcRpcMethod::Read).entered, mode == EcFileRepairMode::HelperChain ? 10 : 20);
    EXPECT_EQ(rpc.at(EcRpcMethod::Begin).entered, 12);
    EXPECT_EQ(rpc.at(EcRpcMethod::Append).entered, 12);
    EXPECT_EQ(rpc.at(EcRpcMethod::Seal).entered, 12);
    EXPECT_EQ(rpc.at(EcRpcMethod::Helper).entered, mode == EcFileRepairMode::HelperChain ? 1 : 0);
    const auto &repairRpc = metrics.selectedRepairRpc;
    const auto &copyRpc = metrics.healthyCopyRpc;
    EXPECT_FALSE(repairRpc.overflow);
    EXPECT_FALSE(copyRpc.overflow);
    EXPECT_FALSE(repairRpc.clockAnomaly);
    EXPECT_FALSE(copyRpc.clockAnomaly);
    // One block per fragment, two reconstructed outputs and ten copied outputs.
    // Copy always Reconciles its original allocation; the fresh repair does not.
    const std::array<uint64_t, static_cast<size_t>(EcRpcMethod::Count)> repairCalls{
        mode == EcFileRepairMode::HelperChain ? 0ULL : 10ULL, 2, 2, 0, 0, 2,
        mode == EcFileRepairMode::HelperChain ? 1ULL : 0ULL};
    const std::array<uint64_t, static_cast<size_t>(EcRpcMethod::Count)> copyCalls{10, 10, 10, 0, 10, 10, 0};
    for (size_t i = 0; i != rpc.methods.size(); ++i) {
      const auto &method = rpc.methods[i];
      const auto &repairMethod = repairRpc.methods[i];
      const auto &copyMethod = copyRpc.methods[i];
      EXPECT_EQ(repairMethod.entered, repairCalls[i]);
      EXPECT_EQ(copyMethod.entered, copyCalls[i]);
      EXPECT_EQ(repairMethod.active, 0);
      EXPECT_EQ(copyMethod.active, 0);
      // All local children have joined. These successful samples do not
      // overflow; additive fields partition the original total exactly.
      using storage::client::EcRpcMethodSample;
      for (auto field : {&EcRpcMethodSample::entered, &EcRpcMethodSample::finished, &EcRpcMethodSample::active,
                         &EcRpcMethodSample::outerOk, &EcRpcMethodSample::outerError,
                         &EcRpcMethodSample::withoutResult, &EcRpcMethodSample::messengerInvocations,
                         &EcRpcMethodSample::withoutMessenger, &EcRpcMethodSample::observedEncodedRequestFrames,
                         &EcRpcMethodSample::missingEncodedRequestFrames, &EcRpcMethodSample::requestFrameBytes,
                         &EcRpcMethodSample::compressedRequestFrames, &EcRpcMethodSample::observedEncodedResponseFrames,
                         &EcRpcMethodSample::missingEncodedResponseFrames, &EcRpcMethodSample::responseFrameBytes,
                         &EcRpcMethodSample::compressedResponseFrames})
        EXPECT_EQ(method.*field, repairMethod.*field + copyMethod.*field);
      for (size_t l = 0; l != method.limiters.size(); ++l) {
        using storage::client::EcRpcLimiterSample;
        for (auto field : {&EcRpcLimiterSample::entered, &EcRpcLimiterSample::acquired, &EcRpcLimiterSample::finished,
                           &EcRpcLimiterSample::withoutPermit, &EcRpcLimiterSample::active,
                           &EcRpcLimiterSample::acquiredWaitNs, &EcRpcLimiterSample::unacquiredSpanNs,
                           &EcRpcLimiterSample::heldNs})
          EXPECT_EQ(method.limiters[l].*field, repairMethod.limiters[l].*field + copyMethod.limiters[l].*field);
        // peakActive is an observed aggregate, not an additive counter.
        EXPECT_GE(method.limiters[l].peakActive, repairMethod.limiters[l].peakActive);
        EXPECT_GE(method.limiters[l].peakActive, copyMethod.limiters[l].peakActive);
      }
      for (auto clock : {&EcRpcMethodSample::client, &EcRpcMethodSample::server}) {
        using storage::client::EcRpcClockSample;
        for (auto field : {&EcRpcClockSample::valid, &EcRpcClockSample::missing,
                           &EcRpcClockSample::reversed, &EcRpcClockSample::outOfRange})
          EXPECT_EQ((method.*clock).*field, (repairMethod.*clock).*field + (copyMethod.*clock).*field);
        for (size_t n = 0; n != 3; ++n)
          EXPECT_EQ((method.*clock).spanNs[n], (repairMethod.*clock).spanNs[n] + (copyMethod.*clock).spanNs[n]);
      }
      EXPECT_EQ(method.active, 0);
      EXPECT_EQ(method.finished, method.entered);
      EXPECT_EQ(method.outerOk, method.entered);
      EXPECT_EQ(method.outerError, 0);
      EXPECT_EQ(method.withoutResult, 0);
      EXPECT_EQ(method.messengerInvocations, method.entered);
      EXPECT_EQ(method.withoutMessenger, 0);
      EXPECT_EQ(method.observedEncodedRequestFrames, method.entered);
      EXPECT_EQ(method.observedEncodedResponseFrames, method.entered);
      EXPECT_EQ(method.missingEncodedRequestFrames, 0);
      EXPECT_EQ(method.missingEncodedResponseFrames, 0);
      // These actual TCP frames include framing, independently of payload bytes.
      EXPECT_GE(method.requestFrameBytes, method.entered * uint64_t{8});
      EXPECT_GE(method.responseFrameBytes, method.entered * uint64_t{8});
      EXPECT_LE(method.compressedRequestFrames, method.observedEncodedRequestFrames);
      EXPECT_LE(method.compressedResponseFrames, method.observedEncodedResponseFrames);
      if (method.entered == 0) {
        EXPECT_EQ(method.requestFrameBytes, 0);
        EXPECT_EQ(method.responseFrameBytes, 0);
      }
      for (const auto &limiter : method.limiters) {
        const auto expected = i == size_t(EcRpcMethod::Helper) ? 0 : method.entered;
        EXPECT_EQ(limiter.entered, expected);
        EXPECT_EQ(limiter.acquired, expected);
        EXPECT_EQ(limiter.finished, expected);
        EXPECT_EQ(limiter.withoutPermit, 0);
        EXPECT_EQ(limiter.active, 0);
        EXPECT_LE(limiter.peakActive, expected);
      }
      EXPECT_EQ(method.client.valid, method.entered);
      EXPECT_EQ(method.server.valid, method.entered);
      EXPECT_EQ(method.client.missing + method.client.reversed + method.client.outOfRange, 0);
      EXPECT_EQ(method.server.missing + method.server.reversed + method.server.outOfRange, 0);
      RecordProperty(fmt::format("repair_rpc_{}_{}", uint8_t(mode), storage::client::kEcRpcMethodNames[i]),
                     fmt::format("frames={},client_valid={},server_valid={},active={},request_frames={},"
                                 "request_frame_bytes={},response_frames={},response_frame_bytes={}", method.entered,
                                 method.client.valid, method.server.valid, method.active,
                                 method.observedEncodedRequestFrames, method.requestFrameBytes,
                                 method.observedEncodedResponseFrames, method.responseFrameBytes));
      RecordProperty(fmt::format("repair_rpc_phases_{}_{}", uint8_t(mode), storage::client::kEcRpcMethodNames[i]),
                     fmt::format("selected_frames={},copy_frames={},selected_request_bytes={},copy_request_bytes={},"
                                 "selected_response_bytes={},copy_response_bytes={}", repairMethod.entered,
                                 copyMethod.entered, repairMethod.requestFrameBytes, copyMethod.requestFrameBytes,
                                 repairMethod.responseFrameBytes, copyMethod.responseFrameBytes));
    }
    const auto &child = completed.progress.record->child;
    EXPECT_EQ(child.targetGeneration, child.source.generation);
    EXPECT_GT(child.targetRevision, child.source.revision);
    auto replay = client->repair(*journal, ctl(), true);
    ASSERT_FALSE(replay.failure);
    EXPECT_TRUE(replay.metrics.available);
    EXPECT_EQ(replay.metrics.at(EcRepairPoint::Query).succeeded, 1);
    EXPECT_EQ(replay.metrics.at(EcRepairPoint::Prepare).entered, 0);
    EXPECT_EQ(replay.metrics.at(EcRepairPoint::SelectedRepair).entered, 0);
    EXPECT_EQ(replay.metrics.at(EcRepairPoint::NativeAppend).apiInvocations, 0);
    for (const auto &method : replay.metrics.storageRpc.methods) {
      EXPECT_EQ(method.entered, 0);
      EXPECT_EQ(method.observedEncodedRequestFrames, 0);
      EXPECT_EQ(method.observedEncodedResponseFrames, 0);
      EXPECT_EQ(method.requestFrameBytes, 0);
      EXPECT_EQ(method.responseFrameBytes, 0);
    }
    for (const auto *group : {&replay.metrics.selectedRepairRpc, &replay.metrics.healthyCopyRpc}) {
      EXPECT_FALSE(group->overflow);
      EXPECT_FALSE(group->clockAnomaly);
      for (const auto &method : group->methods) {
        EXPECT_EQ(method.entered, 0);
        EXPECT_EQ(method.requestFrameBytes, 0);
        EXPECT_EQ(method.responseFrameBytes, 0);
      }
    }
    EXPECT_EQ(serde::serialize(replay.progress.record->child.publishedRoot), serde::serialize(child.publishedRoot));
    auto acquire = request<AcquireEcTreeReadReq>();
    acquire.intent.session = open.session;
    acquire.intent.request = Uuid::random();
    acquire.intent.range = Uuid::random();
    acquire.intent.selection.object = opened->object.object;
    acquire.intent.selection.length = expected.size();
    acquire.intent.selection.pinCount = 1;
    acquire.intent.selection.pins[0].pin = Uuid::random();
    auto pinned = blockingWait(metaClient_->acquireEcTreeRead(acquire));
    ASSERT_OK(pinned);
    acquire.stripeIndex = 0;
    auto readable = blockingWait(metaClient_->acquireEcTreeRead(acquire));
    ASSERT_OK(readable);
    ASSERT_TRUE(readable->read);
    EXPECT_EQ(readable->read->manifest.revision, child.targetRevision);
    storage::EcCodec::Shards shards;
    std::array<storage::EcCodecShardView, 12> views;
    for (size_t n = 0; n < 12; ++n) {
      auto value = readOne(*readable->read, n);
      ASSERT_OK(value);
      shards[n] = std::move(value->payload.data);
      views[n] = {uint16_t(n), shards[n]};
      EXPECT_EQ(readable->read->manifest.fragments[n].identity.allocation,
                access->access->targets[n].fragment.identity.allocation);
    }
    ASSERT_OK(storage::EcCodec::verify(views, expected.size(), kShardBytes));
    std::string actual;
    for (size_t n = 0; n < 10 && actual.size() < expected.size(); ++n)
      actual.append(shards[n].data(), std::min(shards[n].size(), expected.size() - actual.size()));
    EXPECT_EQ(actual, expected);
    auto release = request<ReleaseEcTreeReadReq>();
    release.intent = acquire.intent;
    release.revocations[0] = Uuid::random();
    ASSERT_OK(blockingWait(metaClient_->releaseEcTreeRead(release)));
    auto closed = client->closeDebt(*journal, ctl(), true);
    ASSERT_FALSE(closed.failure);
    EXPECT_TRUE(closed.progress.outputDrained);
    EXPECT_TRUE(closed.progress.sourceReleased);
    EXPECT_TRUE(closed.metrics.available);
    EXPECT_EQ(closed.metrics.action, 2);
    EXPECT_EQ(closed.metrics.at(EcRepairPoint::CloseDebt).succeeded, 1);
    EXPECT_EQ(closed.metrics.at(EcRepairPoint::SelectedRepair).entered, 0);
    for (const auto &method : closed.metrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
    for (const auto &method : closed.metrics.selectedRepairRpc.methods) EXPECT_EQ(method.entered, 0);
    for (const auto &method : closed.metrics.healthyCopyRpc.methods) EXPECT_EQ(method.entered, 0);
    auto historical = client->query(*journal, ctl());
    ASSERT_FALSE(historical.failure);
    EXPECT_FALSE(historical.metrics.available); // Default remains opt-out, including replay.
    EXPECT_TRUE(historical.progress.sourceReleased);
    auto end = request<CloseEcFileSessionReq>();
    end.object = opened->object.object;
    end.session = open.session;
    auto ended = blockingWait(metaClient_->closeEcFileSession(end));
    ASSERT_OK(ended);
    EXPECT_EQ(ended->session.state, EcFileSessionState::Closed);
  }
  RecordProperty(
      "scope",
      "three real repair strategies; one process TCP fixture; controlled mask, not a machine-loss experiment");
}

TEST_F(TestEcFileNativeRepair, UnreservedRepairRequiresAbortedParentReleasedSourceAndMissingExecution) {
  using namespace hf3fs::client::ec;
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "unreserved-repair");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = 3;
  open.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(opened);
  AdvanceEcFilePwriteReq write;
  ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, bytes(kShardBytes + 7, 92), false, write));

  std::optional<EcUnreservedRepair> original;
  QueryEcUnreservedRepairReq historical;
  for (bool reserved : {false, true}) {
    SCOPED_TRACE(reserved ? "bound output" : "never reserved");
    opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    const std::array<uint8_t, 10> sources{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    auto run = prepareEcTreeRepair(opened->session, opened->root, "unreserved-repair", 0, 3,
                                   EcFileRepairMode::CentralSerial, sources);
    ASSERT_OK(run);
    const auto &i = run->intent;
    auto begin = request<BeginEcFileRepairReq>();
    begin.intent = i;
    begin.uuid = i.request;
    ASSERT_OK(blockingWait(metaClient_->beginEcFileRepair(begin)));

    EcFileOutputIdentity identity;
    identity.object = i.object;
    identity.owner = i.owner;
    identity.parent = i.operation;
    identity.child = i.child;
    identity.ownerKind = EcFileOutputOwner::Repair;
    auto observer = fileOutputRequest(identity);
    ASSERT_OK(observer);
    ConfirmEcUnreservedRepairReq confirm;
    static_cast<ReqBase &>(confirm) = static_cast<const ReqBase &>(*observer);
    confirm.identity = identity;
    confirm.resolutionId = Uuid::random();
    auto query = request<QueryEcUnreservedRepairReq>();
    query.user = confirm.user;
    query.identity = identity;
    query.resolutionId = confirm.resolutionId;
    ASSERT_ERROR(blockingWait(metaClient_->queryEcUnreservedRepair(query)), MetaCode::kNotFound);
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(confirm)), StatusCode::kTokenStale);

    auto prepare = request<AdvanceEcFileRepairReq>();
    prepare.intent = i;
    prepare.uuid = run->prepareRequest;
    prepare.action = EcFileRepairAdvance::Prepare;
    if (reserved) {
      auto prepared = blockingWait(metaClient_->advanceEcFileRepair(prepare));
      ASSERT_OK(prepared);
      ASSERT_TRUE(prepared->access);
    } else {
      // Interrupt closing at the real parent-fence transaction. The accepted
      // child is terminal, but its source pin still needs authenticated release.
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      ASSERT_OK(blockingWait(EcFileRepairCatalog::abort(tx, i.owner, i.object, i.operation)));
      ASSERT_OK(blockingWait(tx.commit()));
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(confirm)), StatusCode::kTokenStale);
      ASSERT_ERROR(blockingWait(metaClient_->advanceEcFileRepair(prepare)), StatusCode::kTokenStale);
    }
    auto close = request<CloseEcFileRepairDebtReq>();
    close.intent = i;
    close.outputRevocation = run->outputRevocation;
    close.sourceRevocation = run->sourceRevocation;
    auto closed = blockingWait(metaClient_->closeEcFileRepairDebt(close));
    ASSERT_OK(closed);
    ASSERT_TRUE(closed->progress.sourceReleased);
    ASSERT_TRUE(closed->progress.outputDrained);
    if (reserved) {
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(confirm)), StatusCode::kTokenStale);
      auto reused = confirm;
      reused.resolutionId = original->resolutionId;
      ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(reused)), StatusCode::kTokenMismatch);
      ASSERT_ERROR(blockingWait(metaClient_->queryEcUnreservedRepair(query)), MetaCode::kNotFound);
      continue;
    }
    auto mismatch = confirm;
    mismatch.identity.parent = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(mismatch)), StatusCode::kTokenMismatch);
    mismatch = confirm;
    mismatch.identity.owner.client = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(mismatch)), MetaCode::kNoPermission);
    mismatch = confirm;
    mismatch.user = user_;
    ASSERT_ERROR(blockingWait(metaClient_->confirmEcUnreservedRepair(mismatch)), MetaCode::kNoPermission);

    auto result = blockingWait(metaClient_->confirmEcUnreservedRepair(confirm));
    ASSERT_OK(result);
    original = result->resolution;
    ASSERT_OK(original->valid());
    EXPECT_EQ(serde::serialize(original->identity), serde::serialize(identity));
    EXPECT_EQ(original->confirmingClientNamespace, metaClientId_.uuid);
    EXPECT_EQ(original->resolutionId, confirm.resolutionId);
    EXPECT_EQ(original->sourcePin, i.sourcePin);
    auto replay = blockingWait(metaClient_->confirmEcUnreservedRepair(confirm));
    ASSERT_OK(replay);
    EXPECT_EQ(serde::serialize(replay->resolution), serde::serialize(*original));
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(*observer)), MetaCode::kNotFound);
    ASSERT_ERROR(blockingWait(metaClient_->advanceEcFileRepair(prepare)), StatusCode::kTokenStale);
    {
      const ClientId otherId(Uuid::random());
      auto factory = std::make_unique<meta::client::MetaClient::StubFactory>(
          [this](net::Address address) { return metaNet_->serdeCtx(address); });
      meta::client::MetaClient other(otherId, metaClientConfig_, std::move(factory), mgmtd_, storageClient_, false);
      SCOPE_EXIT { other.stop(); };
      ASSERT_ERROR(blockingWait(other.confirmEcUnreservedRepair(confirm)), StatusCode::kTokenMismatch);
      auto read = blockingWait(other.queryEcUnreservedRepair(query));
      ASSERT_OK(read);
      EXPECT_EQ(read->clientNamespace, otherId.uuid);
      EXPECT_EQ(serde::serialize(read->resolution), serde::serialize(*original));
    }
    historical = query;
  }
  auto close = request<CloseEcFileSessionReq>();
  close.object = opened->object.object;
  close.session = open.session;
  ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  auto past = blockingWait(metaClient_->queryEcUnreservedRepair(historical));
  ASSERT_OK(past);
  EXPECT_EQ(serde::serialize(past->resolution), serde::serialize(*original));
}
