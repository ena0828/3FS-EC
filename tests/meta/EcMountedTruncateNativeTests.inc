// Actual Mount-core -> Meta TCP -> private FDB/Storage integration. This does
// not mount a kernel FUSE filesystem; the hosted POSIX probe remains separate.
class TestEcMountedTruncateRecovery : public TestEcFileNativeWrite {
 protected:
  using Fault = detail::EcMountedTruncateFault;
  using Method = Fault::Method;
  bool enableMountedTruncateFault() const override { return true; }

  void TearDown() override {
    // All assertions use pre-cleanup snapshots. Ordinary stop may attempt the
    // original debt recovery; it must not be mistaken for the tested syscall.
    if (mount_) {
      EXPECT_OK(mount_->stop());
      mount_.reset();
    }
    if (rmw_) rmw_->stopAndJoin();
    rmw_.reset();
    state_.reset();
    TestEcFileNativeWrite::TearDown();
  }
  void startMount(std::chrono::seconds limit = std::chrono::seconds(120)) {
    ASSERT_EQ(::chmod(traces_.path().c_str(), 0700), 0);
    smallClient(rmwConfig_);
    rmw_ = std::make_shared<storage::client::EcRmwTransport>(rmwConfig_);
    ASSERT_OK(rmw_->start());
    auto state = hf3fs::fuse::EcFileMountState::open(
        {std::filesystem::path(traces_.path().string()) / "mount", "mounted-truncate", true, 8, metaClientId_.uuid});
    ASSERT_OK(state);
    state_ = *state;
    hf3fs::fuse::EcFileMount::Dependencies dependencies;
    dependencies.meta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
    dependencies.storage = storageClient_;
    dependencies.mgmtd = mgmtd_;
    dependencies.rmw = rmw_;
    auto mount = hf3fs::fuse::EcFileMount::start(state_, std::move(dependencies), user_.token, limit);
    ASSERT_OK(mount);
    mount_ = *mount;
    auto opened = blockingWait(mount_->create(PathAt(parent_, "mounted-file"), user_, O_RDWR, 0600, kShardBytes));
    ASSERT_OK(opened);
    handle_ = opened->handle;
    ASSERT_NE(replyDrop_.mountedTruncate, nullptr);
  }
  Result<std::unique_ptr<hf3fs::client::ec::EcTruncateJournal>> journal() {
    CHECK_RESULT(dirs, state_->sessions());
    std::optional<std::filesystem::path> found;
    for (const auto &dir : dirs) {
      for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.path().filename().string().starts_with("truncate-")) continue;
        if (found) return makeError(StatusCode::kTokenDuplicated, "more than one truncate identity");
        found = entry.path();
      }
    }
    if (!found) return makeError(MetaCode::kNotFound);
    return hf3fs::client::ec::EcTruncateJournal::resume(*found);
  }
  void checkTrace(const Fault::Snapshot &trace, const hf3fs::client::ec::EcTruncateJournal &j) {
    ASSERT_TRUE(trace.intent);
    ASSERT_FALSE(trace.changed);
    ASSERT_FALSE(trace.overflow);
    ASSERT_EQ(trace.setupErrors, 0u);
    EXPECT_EQ(trace.injections, trace.competingCommits);
    EXPECT_EQ(trace.injections, trace.originalCommits);
    EXPECT_EQ(trace.injections, trace.conflicts);
    EXPECT_EQ(serde::serialize(*trace.intent), serde::serialize(j.record().intent));
    const std::array requests{j.record().queryRequest, j.record().beginRequest,
                              j.record().advanceRequest, j.record().closeRequest};
    for (size_t m = 0; m < requests.size(); ++m)
      if (!trace.requests[m].is_nil()) EXPECT_EQ(trace.requests[m], requests[m]);
    ASSERT_GT(trace.count, 0u);
    EXPECT_EQ(trace.events[0].method, Method::Query);
    for (size_t n = 0; n < trace.count; ++n) {
      EXPECT_TRUE(trace.events[n].finished);
      // Each retry must issue its real Query before any further mutation.
      if (trace.events[n].status == TransactionCode::kConflict && n + 1 < trace.count)
        EXPECT_EQ(trace.events[n + 1].method, Method::Query);
    }
    EXPECT_FALSE(j.poisoned());
    EXPECT_GE(j.remainingStates(), 8u);
    RecordProperty("injected_real_fdb_conflicts", std::to_string(trace.conflicts));
    RecordProperty("truncate_rpc_frames", std::to_string(trace.count));
    RecordProperty("remaining_journal_states", std::to_string(j.remainingStates()));
  }
  static size_t calls(const Fault::Snapshot &trace, Method method) {
    size_t count = 0;
    for (size_t n = 0; n < trace.count; ++n) count += trace.events[n].method == method;
    return count;
  }
  void checkDebt() {
    auto dirs = state_->sessions();
    ASSERT_OK(dirs);
    ASSERT_EQ(dirs->size(), 1u);
    auto operations = state_->operations(dirs->front());
    ASSERT_OK(operations);
    ASSERT_EQ(operations->size(), 1u);
    EXPECT_TRUE(operations->front().name.starts_with("truncate-"));
    const std::array<uint8_t, 1> byte{17};
    auto blocked = blockingWait(mount_->write(handle_, user_, 0, byte));
    ASSERT_ERROR(blocked, StorageClientCode::kResourceBusy);
  }
  void checkPublished(const hf3fs::client::ec::EcTruncateJournal &j, bool tail) {
    ASSERT_TRUE(j.latest());
    ASSERT_TRUE(j.latest()->progress);
    ASSERT_TRUE(j.latest()->progress->observed);
    const auto &observed = *j.latest()->progress->observed;
    EXPECT_EQ(observed.state, EcFileTruncateState::Published);
    EXPECT_TRUE(observed.outputDrained);
    EXPECT_TRUE(observed.sourceReleased);
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Rmw);
    auto actual = blockingWait(EcFileTruncateCatalog::query(tx, j.record().intent.owner,
                                                          j.record().intent.object, j.record().intent.operation));
    ASSERT_OK(actual);
    ASSERT_TRUE(*actual);
    EXPECT_EQ(serde::serialize((**actual).intent), serde::serialize(j.record().intent));
    EXPECT_EQ((**actual).state, EcFileTruncateState::Published);
    ASSERT_TRUE((**actual).publishedRoot);
    EXPECT_EQ((**actual).publishedRoot->sequence, (**actual).fencedRoot.sequence + 1);
    EXPECT_EQ((**actual).tail.has_value(), tail);
    if (tail) {
      auto execution = blockingWait(EcFileExecutionCatalog::get(tx, j.record().intent.owner,
                                                               j.record().intent.object, j.record().intent.child));
      ASSERT_OK(execution);
      EXPECT_EQ(execution->record.state, EcFileExecutionState::Published);
      ASSERT_TRUE(execution->record.allocations);
      EXPECT_EQ(execution->record.allocations->size(), 12u);
      ASSERT_TRUE(execution->record.drain);
      for (size_t n = 0; n < execution->record.drain->identity.endpoints.count; ++n)
        EXPECT_TRUE(ecTerminalAt(*execution->record.drain, n));
    }
  }
  void checkBytes(std::string_view expected) {
    auto read = blockingWait(mount_->read(handle_, user_, 0, expected.size(), false));
    ASSERT_OK(read);
    EXPECT_EQ(read->length, expected.size());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(read->data.bytes().data()), read->data.size()), expected);
  }
  net::Client::Config rmwConfig_;
  std::shared_ptr<storage::client::EcRmwTransport> rmw_;
  std::shared_ptr<hf3fs::fuse::EcFileMountState> state_;
  std::shared_ptr<hf3fs::fuse::EcFileMount> mount_;
  hf3fs::fuse::EcMountHandle handle_;
};

TEST_F(TestEcMountedTruncateRecovery, BeginConflictReplaysOriginalIntent) {
  ASSERT_NO_FATAL_FAILURE(startMount());
  replyDrop_.mountedTruncate->arm(handle_.object, EcFileTruncateState::Planned, 1);
  auto result = blockingWait(mount_->truncate(handle_, user_, 257));
  ASSERT_OK(result);
  EXPECT_EQ(*result, 257u);
  const auto trace = replyDrop_.mountedTruncate->snapshot();
  auto saved = journal();
  ASSERT_OK(saved);
  ASSERT_NO_FATAL_FAILURE(checkTrace(trace, **saved));
  EXPECT_EQ(trace.conflicts, 1u);
  EXPECT_EQ(calls(trace, Method::Begin), 2u);
  ASSERT_GE(trace.count, 4u);
  EXPECT_EQ(trace.events[1].method, Method::Begin);
  EXPECT_EQ(trace.events[1].status, TransactionCode::kConflict);
  EXPECT_EQ(trace.events[2].method, Method::Query);
  EXPECT_EQ(trace.events[3].method, Method::Begin);
  ASSERT_NO_FATAL_FAILURE(checkPublished(**saved, false));
  ASSERT_NO_FATAL_FAILURE(checkBytes(std::string(257, '\0')));
}

TEST_F(TestEcMountedTruncateRecovery, PublishedConflictAfterDataTailReplaysOriginalIntent) {
  ASSERT_NO_FATAL_FAILURE(startMount());
  const auto original = bytes(2 * kShardBytes + 7, 109);
  auto written = blockingWait(mount_->write(handle_, user_, 0,
      std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(original.data()), original.size())));
  ASSERT_OK(written);
  ASSERT_EQ(*written, original.size());
  replyDrop_.mountedTruncate->arm(handle_.object, EcFileTruncateState::Published, 1);
  auto result = blockingWait(mount_->truncate(handle_, user_, kShardBytes + 7));
  ASSERT_OK(result);
  const auto trace = replyDrop_.mountedTruncate->snapshot();
  auto saved = journal();
  ASSERT_OK(saved);
  ASSERT_NO_FATAL_FAILURE(checkTrace(trace, **saved));
  EXPECT_EQ(trace.conflicts, 1u);
  EXPECT_GE(calls(trace, Method::Advance), 2u);
  // The selected Published set is reached only after the real worker has
  // computed/written/sealed all twelve targets and the verifier has read them.
  ASSERT_NO_FATAL_FAILURE(checkPublished(**saved, true));
  ASSERT_NO_FATAL_FAILURE(checkBytes(std::string_view(original).substr(0, kShardBytes + 7)));
}

TEST_F(TestEcMountedTruncateRecovery, EightConflictsKeepDebtAndRecoveryCapacity) {
  ASSERT_NO_FATAL_FAILURE(startMount());
  replyDrop_.mountedTruncate->arm(handle_.object, EcFileTruncateState::Planned, 8);
  auto result = blockingWait(mount_->truncate(handle_, user_, 257));
  ASSERT_ERROR(result, TransactionCode::kConflict);
  const auto trace = replyDrop_.mountedTruncate->snapshot();
  auto saved = journal();
  ASSERT_OK(saved);
  ASSERT_NO_FATAL_FAILURE(checkTrace(trace, **saved));
  EXPECT_EQ(trace.conflicts, 8u);
  EXPECT_EQ(calls(trace, Method::Query), 8u);
  EXPECT_EQ(calls(trace, Method::Begin), 8u);
  EXPECT_EQ(calls(trace, Method::Advance), 0u);
  EXPECT_EQ(calls(trace, Method::Close), 0u);
  ASSERT_TRUE((*saved)->latest());
  EXPECT_EQ((*saved)->latest()->sequence + 1, 32u);  // Four actual appends per failed Begin attempt.
  saved->reset();
  ASSERT_NO_FATAL_FAILURE(checkDebt());
  EXPECT_EQ(replyDrop_.mountedTruncate->snapshot().count, trace.count);
}

TEST_F(TestEcMountedTruncateRecovery, FixedDeadlineStopsConflictRecovery) {
  ASSERT_NO_FATAL_FAILURE(startMount(std::chrono::seconds(1)));
  // Delay a selected real committing transaction beyond the original Mount
  // deadline. This wait tests time, not a probabilistic scheduling race.
  replyDrop_.mountedTruncate->arm(handle_.object, EcFileTruncateState::Planned, 1, std::chrono::milliseconds(1500));
  auto result = blockingWait(mount_->truncate(handle_, user_, 257));
  ASSERT_ERROR(result, StorageClientCode::kTimeout);
  const auto trace = replyDrop_.mountedTruncate->snapshot();
  auto saved = journal();
  ASSERT_OK(saved);
  ASSERT_NO_FATAL_FAILURE(checkTrace(trace, **saved));
  EXPECT_EQ(trace.conflicts, 1u);
  EXPECT_EQ(calls(trace, Method::Query), 1u);
  EXPECT_EQ(calls(trace, Method::Begin), 1u);
  EXPECT_EQ(calls(trace, Method::Advance), 0u);
  saved->reset();
  ASSERT_NO_FATAL_FAILURE(checkDebt());
}

TEST_F(TestEcMountedTruncateRecovery, LostCommittedBeginReplyIsNotRetried) {
  ASSERT_NO_FATAL_FAILURE(startMount());
  replyDrop_.mountedTruncate->arm(handle_.object, EcFileTruncateState::Planned, 0);
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.mountedDropBegin = true;
  }
  auto result = blockingWait(mount_->truncate(handle_, user_, 257));
  ASSERT_FALSE(result);
  EXPECT_NE(result.error().code(), TransactionCode::kConflict);
  const auto trace = replyDrop_.mountedTruncate->snapshot();
  auto saved = journal();
  ASSERT_OK(saved);
  ASSERT_NO_FATAL_FAILURE(checkTrace(trace, **saved));
  EXPECT_EQ(trace.conflicts, 0u);
  EXPECT_EQ(calls(trace, Method::Query), 1u);
  EXPECT_EQ(calls(trace, Method::Begin), 1u);
  EXPECT_EQ(calls(trace, Method::Advance), 0u);
  EXPECT_EQ(calls(trace, Method::Close), 0u);
  {
    std::unique_lock lock(replyDrop_.mutex);
    ASSERT_TRUE(replyDrop_.mountedChanged.wait_for(lock, std::chrono::seconds(5),
                                                  [&] { return replyDrop_.mountedShutdownFinished; }));
    EXPECT_EQ(replyDrop_.mountedBeginDrops, 1u);
    EXPECT_EQ(replyDrop_.mountedShutdownResult, 0);
  }
  auto raw = kv_->createReadWriteTransaction();
  EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Rmw);
  auto persisted = blockingWait(EcFileTruncateCatalog::query(tx, (*saved)->record().intent.owner,
                                                           handle_.object, (*saved)->record().intent.operation));
  ASSERT_OK(persisted);
  ASSERT_TRUE(*persisted);
  EXPECT_EQ((**persisted).state, EcFileTruncateState::Planned);
  EXPECT_EQ(serde::serialize((**persisted).intent), serde::serialize((*saved)->record().intent));
  saved->reset();
  ASSERT_NO_FATAL_FAILURE(checkDebt());
}
