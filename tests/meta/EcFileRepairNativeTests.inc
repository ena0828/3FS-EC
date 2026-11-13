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
    auto completed = client->repair(*journal, ctl(), true);
    ASSERT_FALSE(completed.failure);
    ASSERT_TRUE(completed.revalidated);
    ASSERT_TRUE(completed.progress.record);
    EXPECT_EQ(completed.progress.record->state, EcFileRepairState::Published);
    EXPECT_TRUE(completed.progress.outputDrained);
    EXPECT_FALSE(completed.progress.sourceReleased);
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
    for (size_t i = 0; i != rpc.methods.size(); ++i) {
      const auto &method = rpc.methods[i];
      EXPECT_EQ(method.active, 0);
      EXPECT_EQ(method.finished, method.entered);
      EXPECT_EQ(method.outerOk, method.entered);
      EXPECT_EQ(method.outerError, 0);
      EXPECT_EQ(method.withoutResult, 0);
      EXPECT_EQ(method.client.valid, method.entered);
      EXPECT_EQ(method.server.valid, method.entered);
      EXPECT_EQ(method.client.missing + method.client.reversed + method.client.outOfRange, 0);
      EXPECT_EQ(method.server.missing + method.server.reversed + method.server.outOfRange, 0);
      RecordProperty(fmt::format("repair_rpc_{}_{}", uint8_t(mode), storage::client::kEcRpcMethodNames[i]),
                     fmt::format("frames={},client_valid={},server_valid={},active={}", method.entered,
                                 method.client.valid, method.server.valid, method.active));
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
    for (const auto &method : replay.metrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
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
