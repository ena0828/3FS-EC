// Real Intent WAL write followed by a single test-executable-only data pwrite
// refusal. No fabricated stage response, metadata edit, or production hook.
TEST_F(TestEcFileNativeRepair, HealthyCopyPendingIntentResumesSameJournalAfterEngineReopen) {
  using namespace hf3fs::client::ec;
  namespace fault = hf3fs::test::ec_pending;
  constexpr uint32_t blockBytes = storage::kEcIntegrityBlockBytes;
  constexpr uint32_t shardBytes = 2 * blockBytes;
  constexpr size_t healthy = 2;  // The selected erasures are exactly shards 0 and 1.
  const auto ctl = [] { return EcStripeControl{SteadyClock::now() + std::chrono::seconds(120), {}}; };
  const auto classDirectory = std::filesystem::canonical(data_.path().string()) / "engine-ec-v2" / "128KiB";
  static_assert(shardBytes == 128 * 1024);
  SCOPE_EXIT { fault::reset(); };

  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "native-repair-pending-healthy-copy");
  open.shardBytes = shardBytes;
  open.session = Uuid::random();
  open.rights = 3;
  open.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(opened);
  // Avoid the small fixture generator's periodic blocks: every tested block
  // must identify these exact bytes independently of another shard's writes.
  std::string expected(3 * shardBytes - 37, '\0');
  uint32_t random = 0x739a42d1;
  for (auto &byte : expected) {
    random ^= random << 13;
    random ^= random >> 17;
    random ^= random << 5;
    byte = static_cast<char>(random & 255);
  }
  auto encoded = storage::EcCodec::encode(expected, shardBytes);
  ASSERT_OK(encoded);
  const auto firstBytes = (*encoded)[healthy].substr(0, blockBytes);
  const auto pendingBytes = (*encoded)[healthy].substr(blockBytes, blockBytes);
  for (size_t n = 0; n < 12; ++n)
    for (size_t b = 0; b < 2; ++b)
      if (n != healthy || b != 1)
        ASSERT_NE((*encoded)[n].substr(b * blockBytes, blockBytes), pendingBytes);
  AdvanceEcFilePwriteReq written;
  ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, expected, false, written));
  opened = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(opened);
  ASSERT_EQ(opened->object.shardBytes, shardBytes);

  const std::array<uint8_t, 10> selected{2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  auto run = prepareEcTreeRepair(opened->session, opened->root, "native-pending-copy", 0, 3,
                                EcFileRepairMode::ClientPipeline, selected);
  ASSERT_OK(run);
  const auto journalPath = std::filesystem::path(traces_.path().string()) / "repair-pending-copy";
  auto made = EcTreeRepairJournal::create(journalPath, *run);
  ASSERT_OK(made);
  auto journal = std::move(*made);
  const auto runBytes = serde::serialize(journal->record());
  EcTreeRepairState issued;
  issued.issued = true;
  ASSERT_OK(journal->append(issued));
  auto begin = request<BeginEcFileRepairReq>();
  begin.uuid = run->intent.request;
  begin.intent = run->intent;
  ASSERT_OK(blockingWait(metaClient_->beginEcFileRepair(begin)));
  auto prepare = request<AdvanceEcFileRepairReq>();
  prepare.uuid = run->prepareRequest;
  prepare.intent = run->intent;
  prepare.action = EcFileRepairAdvance::Prepare;
  auto prepared = blockingWait(metaClient_->advanceEcFileRepair(prepare));
  ASSERT_OK(prepared);
  ASSERT_TRUE(prepared->access);
  const auto fixed = *prepared->access;
  const auto targetsBytes = serde::serialize(fixed.targets);
  const auto target = access(fixed.targets[healthy]);
  ASSERT_EQ(target.integrity.wholeLength, shardBytes);
  ASSERT_EQ(target.integrity.blockCount, 2);
  const auto accounting = [&]() -> Result<uint64_t> {
    CHECK_RESULT(found, components_->targetMap.getByTargetId(target.targetId));
    return found->storageTarget->usedSize();
  };
  auto initialUsed = accounting();
  ASSERT_OK(initialUsed);

  // First observe one actual, successful write to this very allocation. The
  // wrapper only records its call-site dev/ino/offset; the real Append response
  // below, not the wrapper, proves the completed prefix before arming EIO.
  ASSERT_OK(blockingWait(storageClient_->beginEcStageV2Controlled({target, fixed.writes[healthy]}, control())));
  fault::captureNext(classDirectory, firstBytes);
  storage::EcAppendStageV2Req append{target, 0, {}, fixed.writes[healthy]};
  append.payload.data = firstBytes;
  auto prefix = blockingWait(storageClient_->appendEcStageV2Controlled(std::move(append), control()));
  ASSERT_OK(prefix);
  ASSERT_OK(storage::validateEcStageStateV2(*prefix, target, fixed.writes[healthy].claims));
  ASSERT_EQ(prefix->prefixBytes, blockBytes);
  ASSERT_FALSE(prefix->pendingBlock);
  ASSERT_FALSE(prefix->needsReconcile);
  const auto captured = fault::observation();
  ASSERT_EQ(captured.captures, 1);
  ASSERT_EQ(captured.failures, 0);
  ASSERT_EQ(captured.interceptionErrors, 0);
  fault::failNext(captured, blockBytes, pendingBytes);

  auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected = EcFileRepairClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid);
  ASSERT_OK(connected);
  auto client = std::move(*connected);
  auto interrupted = client->repair(*journal, ctl());
  ASSERT_TRUE(interrupted.failure);
  const auto refused = fault::observation();
  ASSERT_EQ(refused.captures, 1);
  ASSERT_EQ(refused.failures, 1);  // No hit, wrong symbol, or other failure is not coverage.
  ASSERT_EQ(refused.interceptionErrors, 0);
  ASSERT_EQ(refused.device, captured.device);
  ASSERT_EQ(refused.inode, captured.inode);
  ASSERT_EQ(refused.offset, captured.offset + blockBytes);
  auto pending = blockingWait(storageClient_->queryEcStageV2Controlled({target, fixed.writes[healthy]}, control()));
  ASSERT_OK(pending);
  ASSERT_OK(storage::validateEcStageStateV2(*pending, target, fixed.writes[healthy].claims));
  ASSERT_EQ(pending->state, 1);
  ASSERT_EQ(pending->prefixBytes, blockBytes);
  ASSERT_TRUE(pending->pendingBlock);
  ASSERT_TRUE(pending->needsReconcile);
  auto confirmed =
      blockingWait(storageClient_->reconcileEcStageV2Controlled({target, fixed.writes[healthy]}, control()));
  ASSERT_OK(confirmed);
  ASSERT_FALSE(confirmed->needsReconcile);
  ASSERT_TRUE(confirmed->pendingBlock);  // Reconcile must not invent completed bytes.
  ASSERT_EQ(confirmed->prefixBytes, blockBytes);
  ASSERT_EQ(confirmed->revision, pending->revision);
  auto observed = client->query(*journal, ctl());
  ASSERT_FALSE(observed.failure);
  ASSERT_TRUE(observed.progress.record);
  EXPECT_EQ(observed.progress.record->state, EcFileRepairState::Planned);
  EXPECT_FALSE(observed.progress.outputDrained);
  EXPECT_FALSE(observed.progress.sourceReleased);
  ASSERT_TRUE(journal->latest());
  EXPECT_FALSE(journal->latest()->dataComplete);
  const auto sequence = journal->latest()->sequence;
  auto pendingUsed = accounting();
  ASSERT_OK(pendingUsed);
  EXPECT_EQ(*pendingUsed, *initialUsed);  // This healthy stage has not been sealed.

  // No client coroutine or Engine/fd lease survives this boundary. The fixture
  // stops/joins the real service and StorageOperator, closes the real Engine,
  // and reloads all twelve identical instance identities with the same Meta/FDB.
  fault::reset();
  client.reset();
  journal.reset();
  ASSERT_NO_FATAL_FAILURE(reopenStorageKeepingMeta());
  auto resumed = EcTreeRepairJournal::resume(journalPath);
  ASSERT_OK(resumed);
  journal = std::move(*resumed);
  EXPECT_EQ(serde::serialize(journal->record()), runBytes);
  ASSERT_TRUE(journal->latest());
  EXPECT_EQ(journal->latest()->sequence, sequence);
  prepared = blockingWait(metaClient_->advanceEcFileRepair(prepare));
  ASSERT_OK(prepared);
  ASSERT_TRUE(prepared->access);
  EXPECT_EQ(serde::serialize(prepared->access->targets), targetsBytes);
  const auto recoveredWrite = prepared->access->writes[healthy];
  auto reopened = blockingWait(storageClient_->queryEcStageV2Controlled({target, recoveredWrite}, control()));
  ASSERT_OK(reopened);
  ASSERT_EQ(reopened->state, 1);
  ASSERT_TRUE(reopened->pendingBlock);
  ASSERT_TRUE(reopened->needsReconcile);
  ASSERT_EQ(reopened->prefixBytes, blockBytes);
  ASSERT_EQ(reopened->revision, confirmed->revision);

  // Observe the successful replay's physical location as well: logical UUID
  // equality alone would not prove the retained allocation position is reused.
  fault::captureNext(classDirectory, pendingBytes);
  connected = EcFileRepairClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid);
  ASSERT_OK(connected);
  client = std::move(*connected);
  auto completed = client->repair(*journal, ctl());
  ASSERT_FALSE(completed.failure) << completed.failure->describe();
  const auto replayed = fault::observation();
  ASSERT_EQ(replayed.captures, 1);
  ASSERT_EQ(replayed.failures, 0);
  ASSERT_EQ(replayed.interceptionErrors, 0);
  EXPECT_EQ(replayed.device, refused.device);
  EXPECT_EQ(replayed.inode, refused.inode);
  EXPECT_EQ(replayed.offset, refused.offset);
  fault::reset();
  ASSERT_TRUE(completed.progress.record);
  EXPECT_EQ(completed.progress.record->state, EcFileRepairState::Published);
  EXPECT_TRUE(completed.progress.outputDrained);
  EXPECT_FALSE(completed.progress.sourceReleased);
  auto finalUsed = accounting();
  ASSERT_OK(finalUsed);
  EXPECT_EQ(*finalUsed, *initialUsed + shardBytes);  // Exactly one 128 KiB allocation class.

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
  storage::EcCodec::Shards actual;
  std::array<storage::EcCodecShardView, 12> views;
  for (size_t n = 0; n < 12; ++n) {
    ASSERT_TRUE(readable->read->readGrants[n]);
    EXPECT_EQ(readable->read->manifest.fragments[n].identity.allocation,
              fixed.targets[n].fragment.identity.allocation);
    for (uint32_t b = 0; b < 2; ++b) {
      storage::EcReadBlockV2Req read;
      read.request = access(fixed.targets[n]);
      read.blockIndex = b;
      read.grant = *readable->read->readGrants[n];
      auto block = blockingWait(storageClient_->readEcBlockV2Controlled(read, control()));
      ASSERT_OK(block);
      ASSERT_OK(storage::validateEcReadBlockV2(*block, read));
      actual[n] += block->payload.data;
    }
    EXPECT_EQ(actual[n], (*encoded)[n]);
    views[n] = {uint16_t(n), actual[n]};
  }
  ASSERT_OK(storage::EcCodec::verify(views, expected.size(), shardBytes));
  std::string logical;
  for (size_t n = 0; n < 10 && logical.size() < expected.size(); ++n)
    logical.append(actual[n], 0, std::min(actual[n].size(), expected.size() - logical.size()));
  EXPECT_EQ(logical, expected);
  auto release = request<ReleaseEcTreeReadReq>();
  release.intent = acquire.intent;
  release.revocations[0] = Uuid::random();
  ASSERT_OK(blockingWait(metaClient_->releaseEcTreeRead(release)));
  auto closed = client->closeDebt(*journal, ctl());
  ASSERT_FALSE(closed.failure);
  EXPECT_TRUE(closed.progress.outputDrained);
  EXPECT_TRUE(closed.progress.sourceReleased);
  auto replay = client->repair(*journal, ctl());
  ASSERT_FALSE(replay.failure);
  EXPECT_EQ(serde::serialize(replay.progress.record), serde::serialize(closed.progress.record));
  auto replayUsed = accounting();
  ASSERT_OK(replayUsed);
  EXPECT_EQ(*replayUsed, *finalUsed);
  auto end = request<CloseEcFileSessionReq>();
  end.object = opened->object.object;
  end.session = open.session;
  ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(end)));
  RecordProperty("pending_fault", "one exact-inode/offset/payload pwrite EIO after actual Intent WAL; not power loss");
  RecordProperty("pending_recovery",
                 "same journal, allocation UUID, inode/offset and Engine identity; twelve actual reads");
}
