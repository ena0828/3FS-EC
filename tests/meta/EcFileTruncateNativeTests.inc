// Extends the existing private-FDB/real-TCP W2 fixture. No metadata installer
// test seam is used: source Data comes from actual W1/W2 service publication.
TEST_F(TestEcFileNativeWrite, TruncateTailLostReplyAndExtensionDoNotResurrectBytes) {
  using namespace hf3fs::client::ec;
  auto opening = request<OpenEcFileSessionReq>();
  opening.createNew = true;
  opening.path = PathAt(parent_, "native-truncate-file");
  opening.shardBytes = kShardBytes;
  opening.session = Uuid::random();
  opening.rights = kEcSessionWrite;
  opening.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(opened);
  const auto original = bytes(2 * kShardBytes + 7, 77);
  AdvanceEcFilePwriteReq write;
  ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, original, false, write));
  auto current = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(current);
  ASSERT_EQ(current->root.visibleLength, original.size());
  auto run = prepareEcFileTruncate(current->session, current->root, "native-truncate", kShardBytes + 7);
  ASSERT_OK(run);
  const auto path = std::filesystem::path(traces_.path().string()) / "truncate-range";
  auto created = EcTruncateJournal::create(path, *run);
  ASSERT_OK(created);
  auto journal = std::shared_ptr<EcTruncateJournal>(std::move(*created));
  folly::CPUThreadPoolExecutor executor(2);
  auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected =
      blockingWait(EcFileClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid, executor));
  ASSERT_OK(connected);
  auto client = std::move(*connected);
  auto closeManager = folly::makeGuard([&] {
    if (client) blockingWait(client->close());
  });
  const auto deadline = [] {
    return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}};
  };
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.truncateDropOperation = run->intent.operation;
  }
  bool lost = false;
  uint64_t transactionConflicts = 0;
  const auto until = SteadyClock::now() + 60_s;
  while (SteadyClock::now() < until) {
    auto advanced = blockingWait(client->truncate(journal, deadline()));
    if (!advanced) {
      size_t dropped;
      {
        std::lock_guard lock(replyDrop_.mutex);
        dropped = replyDrop_.truncateRepliesDropped;
      }
      if (dropped == 0 && advanced.error().code() == TransactionCode::kConflict) {
        // Advance may conflict with the worker's own issuance/Bind transaction
        // before any Published reply reaches the fault seam. This definite
        // conflict is not the lost reply under test. Keep all original IDs and
        // query before another finite attempt; no other error is retried here.
        ++transactionConflicts;
        auto queried = blockingWait(client->queryTruncate(journal, deadline()));
        ASSERT_OK(queried);
        ASSERT_EQ(serde::serialize(queried->intent), serde::serialize(run->intent));
        ASSERT_EQ(serde::serialize(journal->record()), serde::serialize(*run));
        // A conflict may also precede Begin. Missing permits only the same
        // Begin CAS; Published without the actual drop does not satisfy this test.
        if (queried->observed) ASSERT_EQ(queried->observed->state, EcFileTruncateState::Planned);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        continue;
      }
      ASSERT_EQ(dropped, 1) << advanced.error().describe();
      lost = true;
      break;
    }
    ASSERT_TRUE(advanced->observed);
    ASSERT_EQ(advanced->observed->state, EcFileTruncateState::Planned);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_TRUE(lost);
  RecordProperty("same_identity_transaction_conflicts", std::to_string(transactionConflicts));
  blockingWait(client->close());
  client.reset();
  journal.reset();
  auto resumed = EcTruncateJournal::resume(path);
  ASSERT_OK(resumed);
  journal = std::shared_ptr<EcTruncateJournal>(std::move(*resumed));
  connected =
      blockingWait(EcFileClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid, executor));
  ASSERT_OK(connected);
  client = std::move(*connected);
  auto observed = blockingWait(client->queryTruncate(journal, deadline()));
  ASSERT_OK(observed);
  ASSERT_TRUE(observed->observed);
  ASSERT_EQ(observed->observed->state, EcFileTruncateState::Published);
  ASSERT_TRUE(observed->observed->publishedRoot);
  ASSERT_TRUE(observed->observed->tailRequired);
  EXPECT_TRUE(observed->observed->outputDrained);
  EXPECT_FALSE(observed->observed->sourceReleased);
  EXPECT_EQ(serde::serialize(journal->record()), serde::serialize(*run));
  const auto published = *observed->observed->publishedRoot;
  auto replay = blockingWait(client->truncate(journal, deadline()));
  ASSERT_OK(replay);
  EXPECT_EQ(serde::serialize(*replay), serde::serialize(*observed));
  auto debt = blockingWait(client->closeTruncateDebt(journal, deadline()));
  ASSERT_OK(debt);
  ASSERT_TRUE(debt->observed->outputDrained);
  ASSERT_TRUE(debt->observed->sourceReleased);
  // White-box checks only observe actual service-created durable records;
  // no scope state or ACK is manufactured by this fixture.
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    const EcOwner owner{user_.uid, metaClientId_.uuid};
    auto record = blockingWait(EcFileTruncateCatalog::query(tx, owner, run->intent.object, run->intent.operation));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    ASSERT_TRUE((**record).tail);
    auto execution = blockingWait(EcFileExecutionCatalog::get(tx, owner, run->intent.object, run->intent.child));
    ASSERT_OK(execution);
    ASSERT_EQ(execution->record.state, EcFileExecutionState::Published);
    ASSERT_TRUE(execution->record.drain);
    const auto &child = *(**record).tail;
    EcTreeSourcePinIntent pin;
    pin.object = child.intent.object;
    pin.owner = child.owner;
    pin.session = child.session;
    pin.parent = child.intent.parent;
    pin.child = child.intent.child;
    pin.pin = child.intent.sourcePin;
    pin.root = child.sourceRoot;
    pin.sequence = child.sourceSequence;
    pin.epoch = child.epoch;
    pin.lengthAtPlan = child.lengthAtPlan;
    pin.slot = child.source;
    auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, pin));
    ASSERT_OK(source);
    ASSERT_EQ(source->state, EcTreeSourcePinState::Released);
    ASSERT_TRUE(source->drain);
    auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
    ASSERT_OK(key);
    for (const auto *drain : {&*execution->record.drain, &*source->drain}) {
      ASSERT_EQ(drain->identity.endpoints.count, 12);
      for (size_t n = 0; n < 12; ++n) {
        ASSERT_TRUE(drain->observations[n]);
        const auto &ack = *drain->observations[n];
        ASSERT_OK(EcVerifiedDrainAck::verify(**key, *drain, n, ack.request, ack.ack));
      }
    }
  }
  auto extension = prepareEcFileTruncate(current->session, published, "native-truncate", original.size());
  ASSERT_OK(extension);
  auto extending =
      EcTruncateJournal::create(std::filesystem::path(traces_.path().string()) / "truncate-extension", *extension);
  ASSERT_OK(extending);
  auto extensionJournal = std::shared_ptr<EcTruncateJournal>(std::move(*extending));
  auto extended = blockingWait(client->truncate(extensionJournal, deadline()));
  ASSERT_OK(extended);
  ASSERT_TRUE(extended->observed);
  ASSERT_EQ(extended->observed->state, EcFileTruncateState::Published);
  EXPECT_FALSE(extended->observed->tailRequired);
  auto readOpen = request<OpenEcFileSessionReq>();
  readOpen.object = run->intent.object;
  readOpen.birth = current->root.birth;
  readOpen.session = Uuid::random();
  readOpen.rights = kEcSessionRead;
  auto reader = blockingWait(metaClient_->openEcFileSession(readOpen));
  ASSERT_OK(reader);
  auto range = prepareEcTreeRead(reader->session, "native-truncate", kShardBytes, 0, original.size());
  ASSERT_OK(range);
  auto rangeMade = EcTreeReadJournal::create(std::filesystem::path(traces_.path().string()) / "truncate-read", *range);
  ASSERT_OK(rangeMade);
  auto rangeJournal = std::shared_ptr<EcTreeReadJournal>(std::move(*rangeMade));
  auto output = blockingWait(client->readTree(rangeJournal, deadline()));
  ASSERT_OK(output);
  auto expected = original.substr(0, kShardBytes + 7);
  expected.resize(original.size(), '\0');
  EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(output->data.bytes().data()), output->data.size()),
            expected);
  auto released = blockingWait(client->releaseTree(rangeJournal, deadline()));
  ASSERT_OK(released);
  EXPECT_EQ(released->state, EcTreeReadState::Released);
  for (const auto &session : {readOpen.session, opening.session}) {
    auto close = request<CloseEcFileSessionReq>();
    close.object = run->intent.object;
    close.session = session;
    auto closed = blockingWait(metaClient_->closeEcFileSession(close));
    ASSERT_OK(closed);
    EXPECT_EQ(closed->session.state, EcFileSessionState::Closed);
  }
  RecordProperty("coverage",
                 "private FDB + actual Meta56-59/W1 Data TruncateTail + lost committed reply + native tree read; not "
                 "crash/power-loss proof");
}

TEST_F(TestEcFileNativeWrite, TruncatePublicationSurvivesClosingLastUnlinkedSession) {
  using namespace hf3fs::client::ec;
  using namespace ec_tree_detail;
  auto opening = request<OpenEcFileSessionReq>();
  opening.createNew = true;
  opening.path = PathAt(parent_, "native-truncate-closing-session");
  opening.shardBytes = kShardBytes;
  opening.session = Uuid::random();
  opening.rights = kEcSessionWrite;
  opening.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(opened);
  AdvanceEcFilePwriteReq initial;
  ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, bytes(2 * kShardBytes + 7, 91), false, initial));
  auto current = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(current);
  auto run = prepareEcFileTruncate(current->session, current->root, "native-retired-tail", kShardBytes + 7);
  ASSERT_OK(run);
  auto begin = request<BeginEcFileTruncateReq>();
  begin.uuid = run->beginRequest;
  begin.intent = run->intent;
  auto begun = blockingWait(metaClient_->beginEcFileTruncate(begin));
  ASSERT_OK(begun);
  ASSERT_TRUE(begun->progress.observed);
  ASSERT_EQ(begun->progress.observed->state, EcFileTruncateState::Planned);
  ASSERT_TRUE(begun->progress.observed->tailRequired);
  const auto fencedRoot = begun->progress.observed->fencedRoot;

  // B0 and the exact source pin have actually committed before the final
  // namespace link disappears and Close marks this sole session Closing.
  auto remove = request<RemoveReq>();
  remove.path = opening.path;
  remove.inodeId = run->intent.object.inode;
  ASSERT_OK(blockingWait(metaClient_->unlinkWithIdentity(remove)));
  auto close = request<CloseEcFileSessionReq>();
  close.object = run->intent.object;
  close.session = opening.session;
  auto closing = blockingWait(metaClient_->closeEcFileSession(close));
  ASSERT_OK(closing);
  ASSERT_EQ(closing->session.state, EcFileSessionState::Closing);
  ASSERT_EQ(closing->session.activeStructural, run->intent.operation);

  auto advance = request<AdvanceEcFileTruncateReq>();
  advance.uuid = run->advanceRequest;
  advance.intent = run->intent;
  auto query = request<QueryEcFileTruncateReq>();
  query.uuid = run->queryRequest;
  query.intent = run->intent;
  uint64_t transactionConflicts = 0;
  std::optional<EcFileTruncateRsp> published;
  const auto until = SteadyClock::now() + 60_s;
  while (SteadyClock::now() < until) {
    auto result = blockingWait(metaClient_->advanceEcFileTruncate(advance));
    if (!result && result.error().code() == TransactionCode::kConflict) {
      // Worker Bind52 may commit against this Advance's issuance transaction.
      // Query the fixed intent before retrying only this definite conflict;
      // neither a different error nor a missing observation proves progress.
      ++transactionConflicts;
      auto observed = blockingWait(metaClient_->queryEcFileTruncate(query));
      ASSERT_OK(observed);
      ASSERT_EQ(observed->requestId, query.uuid);
      ASSERT_EQ(serde::serialize(observed->progress.intent), serde::serialize(run->intent));
      ASSERT_TRUE(observed->progress.observed);
      if (observed->progress.observed->state == EcFileTruncateState::Published) {
        published = std::move(*observed);
        break;
      }
      ASSERT_EQ(observed->progress.observed->state, EcFileTruncateState::Planned);
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }
    ASSERT_OK(result);
    ASSERT_TRUE(result->progress.observed);
    if (result->progress.observed->state == EcFileTruncateState::Published) {
      published = std::move(*result);
      break;
    }
    ASSERT_EQ(result->progress.observed->state, EcFileTruncateState::Planned);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_TRUE(published);
  ASSERT_TRUE(published->progress.observed->publishedRoot);
  const auto publishedRoot = *published->progress.observed->publishedRoot;
  EXPECT_EQ(publishedRoot.visibleLength, run->intent.length);
  EXPECT_EQ(publishedRoot.sequence, fencedRoot.sequence + 1);
  EXPECT_TRUE(published->progress.observed->outputDrained);
  EXPECT_FALSE(published->progress.observed->sourceReleased);
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  EcTreeSourcePinIntent sourceIntent;
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto record = blockingWait(EcFileTruncateCatalog::query(tx, owner, run->intent.object, run->intent.operation));
    ASSERT_OK(record);
    ASSERT_TRUE(*record);
    ASSERT_TRUE((**record).tail);
    ASSERT_TRUE((**record).tail->publishedRoot);
    EXPECT_EQ((**record).tail->state, EcFileChildState::Published);
    EXPECT_EQ(serde::serialize(*(**record).tail->publishedRoot), serde::serialize(publishedRoot));
    auto execution = blockingWait(EcFileExecutionCatalog::get(tx, owner, run->intent.object, run->intent.child));
    ASSERT_OK(execution);
    EXPECT_EQ(execution->record.state, EcFileExecutionState::Published);
    ASSERT_TRUE(execution->record.drain);
    EXPECT_EQ(execution->record.drain->state, EcV2DrainState::Published);
    auto session = blockingWait(EcFileSessionCatalog::get(tx, run->intent.object, opening.session, owner));
    ASSERT_OK(session);
    EXPECT_EQ(session->state, EcFileSessionState::Closed);
    auto object = blockingWait(EcCatalog::getObject(tx, run->intent.object));
    ASSERT_OK(object);
    EXPECT_TRUE(object->deleting);
    // Read the persistent root directly: opening a live tree after retirement
    // is intentionally not a precondition for observing this publication.
    auto live = blockingWait(require<EcTreeRoot>(tx, objectKey(kv::KeyPrefix::EcTreeRoot, run->intent.object)));
    ASSERT_OK(live);
    EXPECT_TRUE(live->root.is_nil());
    EXPECT_EQ(live->sequence, publishedRoot.sequence + 1);
    const auto &child = *(**record).tail;
    sourceIntent.object = child.intent.object;
    sourceIntent.owner = child.owner;
    sourceIntent.session = child.session;
    sourceIntent.parent = child.intent.parent;
    sourceIntent.child = child.intent.child;
    sourceIntent.pin = child.intent.sourcePin;
    sourceIntent.root = child.sourceRoot;
    sourceIntent.sequence = child.sourceSequence;
    sourceIntent.epoch = child.epoch;
    sourceIntent.lengthAtPlan = child.lengthAtPlan;
    sourceIntent.slot = child.source;
    auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, sourceIntent));
    ASSERT_OK(source);
    EXPECT_EQ(source->state, EcTreeSourcePinState::Active);
  }
  RecordProperty("same_identity_transaction_conflicts", std::to_string(transactionConflicts));
  auto observed = blockingWait(metaClient_->queryEcFileTruncate(query));
  ASSERT_OK(observed);
  EXPECT_EQ(serde::serialize(observed->progress), serde::serialize(published->progress));
  auto replay = blockingWait(metaClient_->advanceEcFileTruncate(advance));
  ASSERT_OK(replay);
  EXPECT_EQ(serde::serialize(replay->progress), serde::serialize(published->progress));

  auto debt = request<CloseEcFileTruncateDebtReq>();
  debt.uuid = run->closeRequest;
  debt.intent = run->intent;
  debt.outputRevocation = run->outputRevocation;
  debt.sourceRevocation = run->sourceRevocation;
  auto released = blockingWait(metaClient_->closeEcFileTruncateDebt(debt));
  ASSERT_OK(released);
  ASSERT_TRUE(released->progress.observed);
  EXPECT_TRUE(released->progress.observed->outputDrained);
  EXPECT_TRUE(released->progress.observed->sourceReleased);
  ASSERT_TRUE(released->progress.observed->publishedRoot);
  EXPECT_EQ(serde::serialize(*released->progress.observed->publishedRoot), serde::serialize(publishedRoot));
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, sourceIntent));
    ASSERT_OK(source);
    ASSERT_EQ(source->state, EcTreeSourcePinState::Released);
    ASSERT_TRUE(source->drain);
    ASSERT_EQ(source->drain->identity.endpoints.count, 12);
    auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
    ASSERT_OK(key);
    for (size_t n = 0; n < 12; ++n) {
      ASSERT_TRUE(source->drain->observations[n]);
      const auto &ack = *source->drain->observations[n];
      ASSERT_OK(EcVerifiedDrainAck::verify(**key, *source->drain, n, ack.request, ack.ack));
    }
  }
  auto final = blockingWait(metaClient_->queryEcFileTruncate(query));
  ASSERT_OK(final);
  EXPECT_EQ(serde::serialize(final->progress), serde::serialize(released->progress));
  RecordProperty("coverage",
                 "real Data tail + committed B0 + last unlink/Closing session + same-txn root retirement; source T2 "
                 "remains separate");
}
