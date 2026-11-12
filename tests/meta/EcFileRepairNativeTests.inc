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
    auto completed = client->repair(*journal, ctl());
    ASSERT_FALSE(completed.failure);
    ASSERT_TRUE(completed.revalidated);
    ASSERT_TRUE(completed.progress.record);
    EXPECT_EQ(completed.progress.record->state, EcFileRepairState::Published);
    EXPECT_TRUE(completed.progress.outputDrained);
    EXPECT_FALSE(completed.progress.sourceReleased);
    const auto &child = completed.progress.record->child;
    EXPECT_EQ(child.targetGeneration, child.source.generation);
    EXPECT_GT(child.targetRevision, child.source.revision);
    auto replay = client->repair(*journal, ctl());
    ASSERT_FALSE(replay.failure);
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
    auto closed = client->closeDebt(*journal, ctl());
    ASSERT_FALSE(closed.failure);
    EXPECT_TRUE(closed.progress.outputDrained);
    EXPECT_TRUE(closed.progress.sourceReleased);
    auto historical = client->query(*journal, ctl());
    ASSERT_FALSE(historical.failure);
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
