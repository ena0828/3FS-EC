// Real FDB/Meta/worker/12 Storage fragments. The acceptance acknowledgement is
// deliberately discarded only after the actual service has committed it.
TEST_F(TestEcFileNativeWrite, AppendLostAcceptanceUsesSameEofAndFsyncRequiresPublishedData) {
  using namespace hf3fs::client::ec;
  auto opening = request<OpenEcFileSessionReq>();
  opening.createNew = true;
  opening.path = PathAt(parent_, "native-append-file");
  opening.shardBytes = kShardBytes;
  opening.session = Uuid::random();
  opening.rights = kEcSessionWrite;
  opening.perm = Permission{0600};
  auto opened = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(opened);
  const auto original = bytes(kShardBytes + 17, 121);
  AdvanceEcFilePwriteReq first;
  ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, original, false, first));
  opened = blockingWait(metaClient_->openEcFileSession(opening));
  ASSERT_OK(opened);
  const auto suffix = bytes(257, 209);
  const auto directory = std::filesystem::path(traces_.path().string());
  const auto input = directory / "append-input";
  {
    std::ofstream f(input, std::ios::binary);
    f.write(suffix.data(), suffix.size());
    ASSERT_TRUE(f.good());
  }
  net::Client::Config config;
  smallClient(config);
  auto transport = std::make_shared<storage::client::EcRmwTransport>(config);
  ASSERT_OK(transport->start());
  auto stop = folly::makeGuard([&] { transport->stopAndJoin(); });
  auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto w = EcFilePwriteClient::connect(borrowed, transport, mgmtd_, user_, metaClientId_.uuid);
  ASSERT_OK(w);
  auto writer = std::move(*w);
  auto connected = EcFileAppendClient::connect(borrowed, *writer, user_, metaClientId_.uuid);
  ASSERT_OK(connected);
  auto app = std::move(*connected);
  auto payload = writer->readInput(input);
  ASSERT_OK(payload);
  auto run = prepareEcAppend(opened->session,
                             kShardBytes,
                             "native-append",
                             input.string(),
                             (directory / "append-children").string(),
                             payload->bytes());
  ASSERT_OK(run);
  auto made = EcAppendJournal::create(directory / "append", *run);
  ASSERT_OK(made);
  auto journal = std::move(*made);
  EcAppendJournalState issued;
  issued.issued = true;
  ASSERT_OK(journal->append(issued));
  auto begin = request<BeginEcFileAppendReq>();
  begin.uuid = run->appendIntent.request;
  begin.intent = run->appendIntent;
  {
    auto committed = blockingWait(metaClient_->beginEcFileAppend(begin));
    ASSERT_OK(committed);
    ASSERT_TRUE(committed->record);
    EXPECT_EQ(committed->record->parent.intent.offset, original.size());
  }  // discard actual committed reply
  auto syncRun = prepareEcSync(opened->session, "native-append");
  ASSERT_OK(syncRun);
  auto sync = EcAppendJournal::create(directory / "sync", *syncRun);
  ASSERT_OK(sync);
  const auto ctl = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}}; };
  ASSERT_ERROR(app->fsync(**sync, ctl()), StorageClientCode::kResourceBusy);
  journal.reset();
  auto resumed = EcAppendJournal::resume(directory / "append");
  ASSERT_OK(resumed);
  journal = std::move(*resumed);
  auto completed = app->append(*journal, std::move(*payload), ctl());
  ASSERT_OK(completed);
  EXPECT_EQ(completed->acceptedOffset, original.size());
  ASSERT_FALSE(completed->write.failure) << (completed->write.failure ? completed->write.failure->describe()
                                                                      : "no write failure");
  ASSERT_TRUE(completed->write.logicalComplete);
  ASSERT_TRUE(completed->write.allCleanupComplete);
  EXPECT_EQ(completed->write.revalidatedPrefix, suffix.size());
  auto durable = app->fsync(**sync, ctl());
  ASSERT_OK(durable);
  EXPECT_EQ(durable->durabilityContract, 1);
  EXPECT_EQ(durable->root.visibleLength, original.size() + suffix.size());
  auto replay = app->fsync(**sync, ctl());
  ASSERT_OK(replay);
  EXPECT_EQ(serde::serialize(*durable), serde::serialize(*replay));
  auto readOpen = request<OpenEcFileSessionReq>();
  readOpen.object = opened->object.object;
  readOpen.birth = opened->root.birth;
  readOpen.session = Uuid::random();
  readOpen.rights = kEcSessionRead;
  auto reader = blockingWait(metaClient_->openEcFileSession(readOpen));
  ASSERT_OK(reader);
  auto acquire = request<AcquireEcTreeReadReq>();
  acquire.intent.session = readOpen.session;
  acquire.intent.request = Uuid::random();
  acquire.intent.range = Uuid::random();
  acquire.intent.selection.object = opened->object.object;
  acquire.intent.selection.length = original.size() + suffix.size();
  acquire.intent.selection.pinCount = 1;
  acquire.intent.selection.pins[0].pin = Uuid::random();
  auto pinned = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_OK(pinned);
  acquire.stripeIndex = 0;
  auto credentials = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_OK(credentials);
  ASSERT_TRUE(credentials->read);
  storage::EcCodec::Shards shards;
  std::array<storage::EcCodecShardView, 12> views;
  for (size_t n = 0; n < 12; ++n) {
    auto block = readOne(*credentials->read, n);
    ASSERT_OK(block);
    shards[n] = std::move(block->payload.data);
    views[n] = {uint16_t(n), shards[n]};
  }
  const auto expected = original + suffix;
  ASSERT_OK(storage::EcCodec::verify(views, expected.size(), kShardBytes));
  std::string actual;
  for (size_t n = 0; n < 10 && actual.size() < expected.size(); ++n)
    actual.append(shards[n].data(), std::min(shards[n].size(), expected.size() - actual.size()));
  EXPECT_EQ(actual, expected);
  auto release = request<ReleaseEcTreeReadReq>();
  release.intent = acquire.intent;
  release.revocations[0] = Uuid::random();
  auto released = blockingWait(metaClient_->releaseEcTreeRead(release));
  ASSERT_OK(released);
  EXPECT_EQ(released->record.state, EcTreeReadState::Released);
  for (const auto &session : {opening.session, readOpen.session}) {
    auto close = request<CloseEcFileSessionReq>();
    close.object = opened->object.object;
    close.session = session;
    auto closed = blockingWait(metaClient_->closeEcFileSession(close));
    ASSERT_OK(closed);
    EXPECT_EQ(closed->session.state, EcFileSessionState::Closed);
  }
  RecordProperty("coverage",
                 "actual eager durable Seal/FDB publication path; not hardware power-loss or faulty-device proof");
}
