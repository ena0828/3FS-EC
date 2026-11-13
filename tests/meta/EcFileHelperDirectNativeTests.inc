// Real FDB issuance, real Meta70 response loss, ten TCP helpers and twelve
// Engine outputs. This is a file-mode4 integration test, not an external fence.
TEST_F(TestEcFileNativeRepair, HelperDirectCommittedIssuanceLostReplyAndFreshTwelvePublication) {
  using namespace hf3fs::client::ec;
  using storage::client::EcRpcMethod;
  constexpr uint32_t shardBytes = 3 * storage::kEcIntegrityBlockBytes + 4096;
  const auto ctl = [] { return EcStripeControl{SteadyClock::now() + std::chrono::seconds(120), {}}; };
  auto helperKey = storage::EcHelperKey::loadFile(std::filesystem::path(helperKeyPath_.string()));
  ASSERT_OK(helperKey);
  const std::array<std::pair<uint16_t, uint16_t>, 3> cases{{{1, 1}, {3, 2}, {3, 4}}};
  for (const auto [mask, window] : cases) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, fmt::format("native-direct-{}-{}", mask, window));
    open.shardBytes = shardBytes;
    open.session = Uuid::random();
    open.rights = 3;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    const auto expected = bytes(3 * shardBytes - 37, 181 + mask + window);
    auto encoded = storage::EcCodec::encode(expected, shardBytes);
    ASSERT_OK(encoded);
    AdvanceEcFilePwriteReq written;
    ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, expected, false, written));
    opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    std::array<uint8_t, 10> selected{};
    size_t selectedCount = 0;
    for (uint8_t n = 0; n < 12 && selectedCount < 10; ++n)
      if (!(mask & (1u << n))) selected[selectedCount++] = n;
    auto run = prepareEcTreeRepair(opened->session, opened->root, "native-helper-direct", 0, mask,
                                  EcFileRepairMode::HelperChainDirect, selected, window);
    ASSERT_OK(run);
    const auto path = std::filesystem::path(traces_.path().string()) / fmt::format("direct-{}-{}", mask, window);
    auto made = EcTreeRepairJournal::create(path, *run);
    ASSERT_OK(made);
    auto journal = std::move(*made);
    EcTreeRepairState pending;
    pending.issued = true;
    ASSERT_OK(journal->append(pending));
    auto prepare = request<PrepareEcFileRepairDirectReq>();
    prepare.uuid = run->prepareRequest;
    prepare.intent = run->intent;
    ASSERT_ERROR(blockingWait(metaClient_->prepareEcFileRepairDirect(prepare)), MetaCode::kNotFound);
    auto begin = request<BeginEcFileRepairReq>();
    begin.uuid = run->intent.request;
    begin.intent = run->intent;
    ASSERT_OK(blockingWait(metaClient_->beginEcFileRepair(begin)));
    auto changed = begin;
    changed.intent.mode = EcFileRepairMode::HelperChain;
    ASSERT_ERROR(blockingWait(metaClient_->beginEcFileRepair(changed)), StatusCode::kTokenMismatch);
    auto oldPrepare = request<AdvanceEcFileRepairReq>();
    oldPrepare.uuid = run->prepareRequest;
    oldPrepare.intent = run->intent;
    oldPrepare.action = EcFileRepairAdvance::Prepare;
    ASSERT_ERROR(blockingWait(metaClient_->advanceEcFileRepair(oldPrepare)), StatusCode::kInvalidArg);
    auto wrongMode = prepare;
    wrongMode.intent.mode = EcFileRepairMode::HelperChain;
    ASSERT_ERROR(blockingWait(metaClient_->prepareEcFileRepairDirect(wrongMode)), StatusCode::kInvalidArg);
    // Failed protocol/mode choices cannot reserve an execution or issue grants.
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto absent = blockingWait(tx.get(ec_tree_detail::idKey(kv::KeyPrefix::EcFileExecution,
                                                             run->intent.object, run->intent.child)));
      ASSERT_OK(absent);
      ASSERT_FALSE(*absent);
    }
    size_t droppedBefore = 0;
    {
      std::lock_guard lock(replyDrop_.mutex);
      droppedBefore = replyDrop_.directPrepareRepliesDropped;
      replyDrop_.directPrepareDropOperation = run->intent.operation;
      replyDrop_.directShutdownObserved = false;
      replyDrop_.directShutdownResult = -1;
      replyDrop_.directPrepared.reset();
    }
    auto lost = blockingWait(metaClient_->prepareEcFileRepairDirect(prepare));
    ASSERT_FALSE(lost);
    EcFileRepairDirectRsp committed;
    {
      std::unique_lock lock(replyDrop_.mutex);
      ASSERT_TRUE(replyDrop_.directChanged.wait_for(lock, std::chrono::seconds(5),
                                                  [&] { return replyDrop_.directShutdownObserved; }));
      ASSERT_EQ(replyDrop_.directPrepareRepliesDropped, droppedBefore + 1);
      ASSERT_EQ(replyDrop_.directShutdownResult, 0);
      ASSERT_TRUE(replyDrop_.directPrepared);
      committed = *replyDrop_.directPrepared;
    }
    ASSERT_TRUE(committed.access);
    ASSERT_TRUE(committed.progress.record);
    // Observe real persisted ECFE/ECSP issuance after the reply was actually lost.
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto execution = blockingWait(EcFileExecutionCatalog::get(tx, run->intent.owner, run->intent.object,
                                                               run->intent.child));
      ASSERT_OK(execution);
      ASSERT_TRUE(execution->record.allocations);
      EXPECT_GT(execution->record.issuanceSequence, 0);
      EXPECT_EQ(serde::serialize(*execution->record.allocations), serde::serialize(committed.access->base.targets));
      auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, sourceIntentFor(committed.progress.record->child)));
      ASSERT_OK(source);
      EXPECT_GT(source->issuanceSequence, 0);
      EXPECT_FALSE(source->drain);
    }
    journal.reset();
    ASSERT_NO_FATAL_FAILURE(restartCoordinator());
    auto resumed = EcTreeRepairJournal::resume(path);
    ASSERT_OK(resumed);
    journal = std::move(*resumed);
    EXPECT_EQ(serde::serialize(journal->record()), serde::serialize(*run));
    auto query = request<QueryEcFileRepairReq>();
    query.uuid = run->queryRequest;
    query.intent = run->intent;
    auto observed = blockingWait(metaClient_->queryEcFileRepair(query));
    ASSERT_OK(observed);
    ASSERT_TRUE(observed->progress.record);
    EXPECT_EQ(observed->progress.record->state, EcFileRepairState::Planned);
    EXPECT_FALSE(observed->progress.outputClosing);
    auto issued = blockingWait(metaClient_->prepareEcFileRepairDirect(prepare));
    ASSERT_OK(issued);
    ASSERT_TRUE(issued->access);
    const auto &a = *issued->access;
    EXPECT_EQ(serde::serialize(a.base.plan), serde::serialize(committed.access->base.plan));
    EXPECT_EQ(serde::serialize(a.base.targets), serde::serialize(committed.access->base.targets));
    auto plan = storage::EcRepairPlan::create(a.base.plan);
    ASSERT_OK(plan);
    ASSERT_EQ((*plan)->blockCount(), 4);
    for (uint32_t b = 0; b < (*plan)->blockCount(); ++b) {
      ASSERT_OK(storage::validateEcHelperDirectDelegation(**plan, a.delegation, b));
      const auto now = uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
      ASSERT_OK(storage::verifyEcHelperDirectDelegation(**helperKey, **plan, a.delegation, b, now));
    }
    for (size_t n = 0; n < 2; ++n) {
      if (n < a.base.plan.targetCount) {
        EXPECT_EQ(a.delegation.appendGrants[n].claims.rights, uint16_t(storage::EcGrantRightV2::Append));
        EXPECT_EQ(a.delegation.queryGrants[n].claims.rights, uint16_t(storage::EcGrantRightV2::Query));
        EXPECT_EQ(a.delegation.appendGrants[n].claims.scopeId, run->intent.child);
        EXPECT_EQ(serde::serialize(a.delegation.appendGrants[n].claims.identity),
                  serde::serialize(a.base.plan.targets[n].identity));
      } else {
        EXPECT_EQ(serde::serialize(a.delegation.appendGrants[n]), serde::serialize(storage::EcCapabilityV2{}));
        EXPECT_EQ(serde::serialize(a.delegation.queryGrants[n]), serde::serialize(storage::EcCapabilityV2{}));
      }
    }
    auto broadened = a.delegation;
    broadened.appendGrants[0].claims.rights |= uint16_t(storage::EcGrantRightV2::Seal);
    EXPECT_FALSE(storage::validateEcHelperDirectDelegation(**plan, broadened, 0));
    auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
    auto connected = EcFileRepairClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid);
    ASSERT_OK(connected);
    auto client = std::move(*connected);
    auto complete = client->repair(*journal, ctl(), true);
    ASSERT_FALSE(complete.failure);
    ASSERT_TRUE(complete.progress.record);
    EXPECT_EQ(complete.progress.record->state, EcFileRepairState::Published);
    EXPECT_TRUE(complete.progress.outputDrained);
    EXPECT_FALSE(complete.progress.sourceReleased);
    ASSERT_TRUE(journal->latest());
    EXPECT_TRUE(journal->latest()->dataComplete);
    EXPECT_EQ(complete.metrics.selectedRepairRpc.at(EcRpcMethod::Append).entered, 0);
    EXPECT_EQ(complete.metrics.selectedRepairRpc.at(EcRpcMethod::Helper).entered, 0);
    EXPECT_EQ(complete.metrics.selectedRepairRpc.at(EcRpcMethod::HelperDirect).entered, 4);
    EXPECT_EQ(complete.metrics.healthyCopyRpc.at(EcRpcMethod::Append).entered,
              uint64_t(12 - std::popcount(mask)) * 4);
    for (const auto &method : complete.metrics.storageRpc.methods) {
      EXPECT_EQ(method.active, 0);
      EXPECT_EQ(method.finished, method.entered);
    }
    auto acquire = request<AcquireEcTreeReadReq>();
    acquire.intent.session = open.session;
    acquire.intent.request = Uuid::random();
    acquire.intent.range = Uuid::random();
    acquire.intent.selection.object = opened->object.object;
    acquire.intent.selection.length = expected.size();
    acquire.intent.selection.pinCount = 1;
    acquire.intent.selection.pins[0].pin = Uuid::random();
    ASSERT_OK(blockingWait(metaClient_->acquireEcTreeRead(acquire)));
    acquire.stripeIndex = 0;
    auto readable = blockingWait(metaClient_->acquireEcTreeRead(acquire));
    ASSERT_OK(readable);
    ASSERT_TRUE(readable->read);
    storage::EcCodec::Shards shards;
    std::array<storage::EcCodecShardView, 12> views;
    for (size_t n = 0; n < 12; ++n) {
      ASSERT_TRUE(readable->read->readGrants[n]);
      EcV2AllocationBinding allocation;
      allocation.fragment = readable->read->manifest.fragments[n];
      EXPECT_EQ(allocation.fragment.identity.allocation, a.base.targets[n].fragment.identity.allocation);
      for (uint32_t b = 0; b < 4; ++b) {
        storage::EcReadBlockV2Req read;
        read.request = access(allocation);
        read.grant = *readable->read->readGrants[n];
        read.blockIndex = b;
        auto value = blockingWait(storageClient_->readEcBlockV2Controlled(read, control()));
        ASSERT_OK(value);
        shards[n] += value->payload.data;
      }
      EXPECT_EQ(shards[n], (*encoded)[n]);
      views[n] = {uint16_t(n), shards[n]};
    }
    ASSERT_OK(storage::EcCodec::verify(views, expected.size(), shardBytes));
    auto release = request<ReleaseEcTreeReadReq>();
    release.intent = acquire.intent;
    release.revocations[0] = Uuid::random();
    ASSERT_OK(blockingWait(metaClient_->releaseEcTreeRead(release)));
    auto replay = client->repair(*journal, ctl(), true);
    ASSERT_FALSE(replay.failure);
    for (const auto &method : replay.metrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
    auto closed = client->closeDebt(*journal, ctl(), true);
    ASSERT_FALSE(closed.failure);
    EXPECT_TRUE(closed.progress.sourceReleased);
    auto late = blockingWait(metaClient_->prepareEcFileRepairDirect(prepare));
    ASSERT_OK(late);
    EXPECT_FALSE(late->access); // A terminal record never signs fresh delegation.
    auto end = request<CloseEcFileSessionReq>();
    end.object = opened->object.object;
    end.session = open.session;
    ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(end)));
    RecordProperty(fmt::format("helper_direct_file_{}_{}", mask, window),
                   "four_blocks_short_tail;lost_committed_prepare_tcp;fixed_targets;12_exact_shards;source_T2");
  }
}
