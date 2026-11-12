// Included inside TestEcV2NativeLifecycle.cc's existing anonymous namespace.
// Reuses its actual private FDB, authenticated Meta/Storage TCP services and
// twelve logical targets; this is one Engine and one physical failure domain.
namespace file_client_native {
using namespace hf3fs::client::ec;

class TestEcFileClientNative : public TestEcV2NativeFileRange {
 protected:
  void TearDown() override {
    closeFileClient();
    TestEcV2NativeFileRange::TearDown();
  }
  void openFileClient() {
    ASSERT_FALSE(fileClient_);
    auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
    auto connected =
        blockingWait(EcFileClient::connect(borrowed, storageClient_, mgmtd_, user_, metaClientId_.uuid, fileExecutor_));
    ASSERT_OK(connected);
    fileClient_ = std::move(*connected);
  }
  void closeFileClient() {
    if (fileClient_) blockingWait(fileClient_->close());
    fileClient_.reset();
  }
  static EcStripeControl fileControl() { return {std::chrono::steady_clock::now() + std::chrono::seconds(120), {}}; }
  static std::span<const uint8_t> byteView(std::string_view value) {
    return {reinterpret_cast<const uint8_t *>(value.data()), value.size()};
  }
  static Result<storage::EcSha256> sha(std::string_view value) {
    std::array<std::string_view, 10> parts{};
    parts[0] = value;
    return computeEcLogicalSha256(parts, value.size());
  }
  std::filesystem::path runPath(std::string_view name) const {
    return std::filesystem::path(traces_.path().string()) / std::string(name);
  }
  void newRead(const EcObjectRef &object,
               uint64_t offset,
               uint64_t length,
               std::string_view name,
               std::shared_ptr<EcFileRunJournal> &journal) {
    const auto id = Uuid::random();
    auto described = blockingWait(fileClient_->describe(object, id, AccessType::READ, fileControl()));
    ASSERT_OK(described);
    auto prepared = prepareEcFileRead(*described, fileClient_->owner(), "native-file-fixture", offset, length, id);
    ASSERT_OK(prepared);
    auto created = EcFileRunJournal::create(runPath(name), *prepared);
    ASSERT_OK(created);
    journal = std::shared_ptr<EcFileRunJournal>(std::move(*created));
  }
  QueryEcRangeV2Req queryRun(const EcFileRunRecord &record) const {
    auto query = request<QueryEcRangeV2Req>();
    query.uuid = record.rangeRequest;
    query.rangeId = record.rangeId;
    query.selection.object = record.object;
    query.selection.offset = record.offset;
    query.selection.length = record.length;
    query.selection.pinCount = record.count;
    for (size_t i = 0; i != record.count; ++i)
      query.selection.pins[i] = EcRangePin{record.slots[i].stripe, record.slots[i].pin};
    return query;
  }
  void verifyAllReleased(const EcFileRunRecord &record, uint16_t count) {
    auto observed = blockingWait(metaClient_->queryEcRangeV2(queryRun(record)));
    ASSERT_OK(observed);
    ASSERT_EQ(observed->snapshot.stripeCount, count);
    for (size_t i = 0; i != count; ++i) {
      const auto &entry = observed->snapshot.stripes[i];
      ASSERT_EQ(entry.state, EcRangePinState::Released);
      auto release = request<ReleaseEcReadV2Req>();
      release.uuid = record.slots[i].releaseRequest;
      release.object = record.object;
      release.stripe = record.slots[i].stripe;
      release.pin = record.slots[i].pin;
      auto confirmed = blockingWait(metaClient_->releaseEcReadV2(release));
      ASSERT_OK(confirmed);
      ASSERT_NO_FATAL_FAILURE(verifyDrain(record.object,
                                          storage::EcGrantScope::ReadPin,
                                          release.pin,
                                          confirmed->drain,
                                          EcV2DrainState::ReadReleased));
      auto txn = kv_->createReadWriteTransaction();
      auto manifest =
          blockingWait(EcCatalog::getManifest(*txn, record.object, release.stripe, entry.snapshot.revision));
      ASSERT_OK(manifest);
      ASSERT_EQ(manifest->pins, 0);
    }
  }
  folly::CPUThreadPoolExecutor fileExecutor_{4};
  std::shared_ptr<EcFileClient> fileClient_;
};

TEST_F(TestEcFileClientNative, CrossStripeClippedReadVerifiesBytesShaAndEveryActualPinT2) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "file-client-clipped"));
  Mutation first, second, tail;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 1, second));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 2, tail, 137));
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  std::shared_ptr<EcFileRunJournal> journal;
  ASSERT_NO_FATAL_FAILURE(newRead(object, kStripeBytes - 31, kStripeBytes + 500, "clipped-run", journal));
  auto read = blockingWait(fileClient_->read(journal, fileControl()));
  ASSERT_OK(read);
  const auto expected = (first.logical + second.logical + tail.logical).substr(kStripeBytes - 31);
  const std::string_view actual(reinterpret_cast<const char *>(read->data.bytes().data()), read->data.size());
  ASSERT_EQ(actual, expected);
  auto actualSha = sha(actual), expectedSha = sha(expected);
  ASSERT_OK(actualSha);
  ASSERT_OK(expectedSha);
  ASSERT_EQ(*actualSha, *expectedSha);
  ASSERT_EQ(read->snapshot.stripeCount, 3);
  ASSERT_EQ(read->snapshot.readableLength, kStripeBytes + 168);
  ASSERT_TRUE(journal->latest()->dataReady);
  ASSERT_TRUE(journal->latest()->localComplete);
  ASSERT_FALSE(journal->latest()->allPinsReleased());
  ASSERT_EQ(fileClient_->payloadBytes(), expected.size());
  auto beforeRelease = blockingWait(metaClient_->queryEcRangeV2(queryRun(journal->record())));
  ASSERT_OK(beforeRelease);
  for (size_t i = 0; i != 3; ++i) ASSERT_EQ(beforeRelease->snapshot.stripes[i].state, EcRangePinState::Active);
  const auto output = runPath("clipped-output.bin");
  ASSERT_OK(saveEcFileReadOutput(output, read->data.bytes()));
  std::ifstream input(output, std::ios::binary);
  ASSERT_TRUE(input.is_open());
  const std::string persisted((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  ASSERT_EQ(persisted, expected);
  auto released = blockingWait(fileClient_->releaseRead(journal, fileControl()));
  ASSERT_FALSE(released.failure);
  ASSERT_TRUE(released.allReleased);
  ASSERT_EQ(released.expectedPins, 3);
  ASSERT_EQ(released.releasedMask, 7);
  ASSERT_NO_FATAL_FAILURE(verifyAllReleased(journal->record(), 3));
  read = makeError(StatusCode::kInterrupted);
  ASSERT_EQ(fileClient_->payloadBytes(), 0);
  RecordProperty("file_read_release", "real range43/44, native block reads, all three signed12-endpoint T2 proofs");
}

TEST_F(TestEcFileClientNative, FullStripeAppendConfirmsContinuousPrefixAndRevalidatesSameJournalAfterRestart) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "file-client-append"));
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  const auto expected = bytes(2 * kStripeBytes, 1901);
  const auto inputPath = runPath("append-input.bin");
  ASSERT_OK(saveEcFileReadOutput(inputPath, byteView(expected)));
  const auto describeId = Uuid::random();
  auto described = blockingWait(fileClient_->describe(object, describeId, AccessType::WRITE, fileControl()));
  ASSERT_OK(described);
  ASSERT_EQ(described->length, 0);
  auto payload = readEcFileInput(*fileClient_, inputPath);
  ASSERT_OK(payload);
  auto prepared = prepareEcFileAppend(*described,
                                      fileClient_->owner(),
                                      "native-file-fixture",
                                      0,
                                      inputPath.string(),
                                      payload->bytes(),
                                      describeId);
  ASSERT_OK(prepared);
  const auto original = *prepared;
  const auto path = runPath("append-run");
  auto created = EcFileRunJournal::create(path, original);
  ASSERT_OK(created);
  auto journal = std::shared_ptr<EcFileRunJournal>(std::move(*created));
  auto result = blockingWait(fileClient_->appendAt(journal, std::move(*payload), fileControl()));
  ASSERT_FALSE(result.failure) << (result.failure ? result.failure->describe() : "");
  ASSERT_TRUE(result.complete);
  ASSERT_EQ(result.confirmedStripes, 2);
  ASSERT_EQ(result.firstUnconfirmedIndex, 2);
  ASSERT_EQ(result.confirmedPrefixBytes, expected.size());
  ASSERT_EQ(result.revalidatedPrefixBytes, expected.size());
  ASSERT_EQ(fileClient_->payloadBytes(), 0);
  std::array<EcManifest, 2> originals;
  for (size_t i = 0; i != 2; ++i) {
    auto req = request<GetEcOperationV2Req>();
    req.uuid = original.slots[i].mutation.getRequest;
    req.object = object;
    req.operation = original.slots[i].mutation.operation;
    auto published = blockingWait(metaClient_->getEcOperationV2(req));
    ASSERT_OK(published);
    ASSERT_EQ(published->record.state, EcOperationState::Published);
    ASSERT_TRUE(published->drain);
    ASSERT_TRUE(published->reservation);
    ASSERT_EQ(published->reservation->contentSha256, original.slots[i].contentSha256);
    ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                        storage::EcGrantScope::WriteOperation,
                                        req.operation,
                                        *published->drain,
                                        EcV2DrainState::Published));
    originals[i] = published->record.candidate;
  }
  // Real Meta/MetaClient teardown and disk journal reopen. This is normal
  // restart, not a process-kill or power-loss durability experiment.
  closeFileClient();
  journal.reset();
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  auto resumed = EcFileRunJournal::resume(path);
  ASSERT_OK(resumed);
  journal = std::shared_ptr<EcFileRunJournal>(std::move(*resumed));
  auto encodedOriginal = encodeEcFileRunRecord(original), encodedResumed = encodeEcFileRunRecord(journal->record());
  ASSERT_OK(encodedOriginal);
  ASSERT_OK(encodedResumed);
  ASSERT_EQ(*encodedOriginal, *encodedResumed);
  payload = readEcFileInput(*fileClient_, inputPath);
  ASSERT_OK(payload);
  auto replay = blockingWait(fileClient_->appendAt(journal, std::move(*payload), fileControl()));
  ASSERT_FALSE(replay.failure);
  ASSERT_TRUE(replay.complete);
  ASSERT_EQ(replay.revalidatedPrefixBytes, expected.size());
  for (size_t i = 0; i != 2; ++i) {
    auto req = request<GetEcOperationV2Req>();
    req.uuid = original.slots[i].mutation.getRequest;
    req.object = object;
    req.operation = original.slots[i].mutation.operation;
    auto observed = blockingWait(metaClient_->getEcOperationV2(req));
    ASSERT_OK(observed);
    ASSERT_TRUE(serde::equals(observed->record.candidate, originals[i]));
  }
  std::shared_ptr<EcFileRunJournal> readJournal;
  ASSERT_NO_FATAL_FAILURE(newRead(object, 0, expected.size(), "append-readback", readJournal));
  auto read = blockingWait(fileClient_->read(readJournal, fileControl()));
  ASSERT_OK(read);
  ASSERT_EQ(read->snapshot.file.length, expected.size());
  ASSERT_EQ(std::string_view(reinterpret_cast<const char *>(read->data.bytes().data()), read->data.size()), expected);
  auto released = blockingWait(fileClient_->releaseRead(readJournal, fileControl()));
  ASSERT_FALSE(released.failure);
  ASSERT_TRUE(released.allReleased);
  ASSERT_NO_FATAL_FAILURE(verifyAllReleased(readJournal->record(), 2));
  RecordProperty("append_prefix",
                 "two full stripes sequentially Published with real T2; same IDs and manifests after normal restart");
}

TEST_F(TestEcFileClientNative, LostAcquireReplyResumesCommittedRangeAndOriginalPinsFromDiskJournal) {
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "file-client-acquire-recovery"));
  Mutation first, second;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 1, second));
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  std::shared_ptr<EcFileRunJournal> journal;
  ASSERT_NO_FATAL_FAILURE(newRead(object, kStripeBytes - 19, 97, "lost-range", journal));
  const auto original = journal->record();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.rangeArmed = original.rangeRequest;
    replyDrop_.rangeCalls = 0;
  }
  auto lost = blockingWait(fileClient_->read(journal, fileControl()));
  ASSERT_FALSE(lost);
  ASSERT_TRUE(journal->latest()->acquisitionIssued);
  ASSERT_FALSE(journal->latest()->snapshotObserved);
  EcRangeSnapshot committed;
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.rangeCalls, 1);
    ASSERT_TRUE(replyDrop_.rangeCommitted);
    committed = replyDrop_.rangeCommitted->snapshot;
  }
  closeFileClient();
  journal.reset();
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  auto resumed = EcFileRunJournal::resume(runPath("lost-range"));
  ASSERT_OK(resumed);
  journal = std::shared_ptr<EcFileRunJournal>(std::move(*resumed));
  ASSERT_EQ(journal->record().rangeId, original.rangeId);
  auto recovered = blockingWait(fileClient_->read(journal, fileControl()));
  ASSERT_OK(recovered);
  ASSERT_TRUE(serde::equals(recovered->snapshot, committed));
  const auto expected = (first.logical + second.logical).substr(kStripeBytes - 19, 97);
  ASSERT_EQ(std::string_view(reinterpret_cast<const char *>(recovered->data.bytes().data()), recovered->data.size()),
            expected);
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.rangeCalls, 1);  // Query44 recovered; no second Acquire43.
  }
  for (size_t i = 0; i != 2; ++i) {
    auto txn = kv_->createReadWriteTransaction();
    auto manifest = blockingWait(
        EcCatalog::getManifest(*txn, object, original.slots[i].stripe, committed.stripes[i].snapshot.revision));
    ASSERT_OK(manifest);
    ASSERT_EQ(manifest->pins, 1);  // Original permanent pin is not duplicated.
  }
  auto released = blockingWait(fileClient_->releaseRead(journal, fileControl()));
  ASSERT_FALSE(released.failure);
  ASSERT_TRUE(released.allReleased);
  ASSERT_NO_FATAL_FAILURE(verifyAllReleased(original, 2));
  RecordProperty("unknown_range_recovery",
                 "actual successful FDB Acquire43 then one-shot TCP reply invalidation; same journal and pins");
}

TEST_F(TestEcFileClientNative, WriteOnlyLostBeginAndPublishRepliesRecoverSameJournalThroughOwnedQuery) {
  // Two dropped replies must reach the two StripeClient recovery attempts,
  // not be consumed by MetaClient's independent inner RPC retry loop.
  const auto retryWait = metaClientConfig_.retry_default().retry_init_wait();
  auto restoreRetry = folly::makeGuard([&] { metaClientConfig_.retry_default().set_retry_init_wait(retryWait); });
  metaClientConfig_.retry_default().set_retry_init_wait(0_ms);
  for (unsigned phase = 0; phase != 2; ++phase) {
    SCOPED_TRACE(phase);
    EcObjectRef object;
    ASSERT_NO_FATAL_FAILURE(createFile(object, "file-owner-lost-" + std::to_string(phase)));
    ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &inode) { inode.acl.perm = Permission{0200}; }));
    ASSERT_NO_FATAL_FAILURE(openFileClient());
    const auto data = bytes(kStripeBytes, 2200 + phase);
    const auto inputPath = runPath("owner-lost-input-" + std::to_string(phase));
    ASSERT_OK(saveEcFileReadOutput(inputPath, byteView(data)));
    const auto describeId = Uuid::random();
    auto described = blockingWait(fileClient_->describe(object, describeId, AccessType::WRITE, fileControl()));
    ASSERT_OK(described);
    ASSERT_ERROR(blockingWait(fileClient_->describe(object, Uuid::random(), AccessType::READ, fileControl())),
                 MetaCode::kNoPermission);
    auto input = readEcFileInput(*fileClient_, inputPath);
    ASSERT_OK(input);
    auto prepared = prepareEcFileAppend(*described,
                                        fileClient_->owner(),
                                        "native-file-fixture",
                                        0,
                                        inputPath.string(),
                                        input->bytes(),
                                        describeId);
    ASSERT_OK(prepared);
    const auto original = *prepared;
    const auto run = runPath("owner-lost-run-" + std::to_string(phase));
    auto created = EcFileRunJournal::create(run, original);
    ASSERT_OK(created);
    auto journal = std::shared_ptr<EcFileRunJournal>(std::move(*created));
    size_t callsBefore;
    {
      std::lock_guard lock(replyDrop_.mutex);
      callsBefore = phase == 0 ? replyDrop_.ownerBeginCalls : replyDrop_.state.calls;
      if (phase == 0) {
        replyDrop_.fileBeginDropOperation = original.slots[0].mutation.operation;
        replyDrop_.fileBeginRepliesToDrop = 2;  // two manager attempts, one RPC attempt each
      } else {
        replyDrop_.filePublishDropOperation = original.slots[0].mutation.operation;
        replyDrop_.filePublishRepliesToDrop = 2;
      }
    }
    auto lost = blockingWait(fileClient_->appendAt(journal, std::move(*input), fileControl()));
    ASSERT_TRUE(lost.failure);
    ASSERT_FALSE(lost.complete);
    ASSERT_EQ(lost.confirmedPrefixBytes, 0);
    ASSERT_EQ(journal->latest()->appendStates[0], EcFileAppendState::Issued);
    ASSERT_TRUE(journal->latest()->localComplete);
    auto ordinary = request<GetEcOperationV2Req>();
    ordinary.uuid = original.slots[0].mutation.getRequest;
    ordinary.object = object;
    ordinary.operation = original.slots[0].mutation.operation;
    ASSERT_ERROR(blockingWait(metaClient_->getEcOperationV2(ordinary)), MetaCode::kNoPermission);
    auto query = request<QueryEcOwnedMutationV2Req>();
    query.uuid = ordinary.uuid;
    query.object = object;
    query.operation = ordinary.operation;
    auto committed = blockingWait(metaClient_->queryEcOwnedMutationV2(query));
    ASSERT_OK(committed);
    ASSERT_EQ(committed->record.state, phase == 0 ? EcOperationState::Preparing : EcOperationState::Published);
    ASSERT_EQ(committed->publishedContentConfirmed, phase != 0);
    ASSERT_EQ(committed->contentSha256, original.slots[0].contentSha256);
    const auto firstCandidate = committed->record.candidate;
    size_t beginCalls;
    {
      std::lock_guard lock(replyDrop_.mutex);
      ASSERT_EQ(replyDrop_.fileBeginRepliesToDrop, 0);
      ASSERT_EQ(replyDrop_.filePublishRepliesToDrop, 0);
      ASSERT_EQ((phase == 0 ? replyDrop_.ownerBeginCalls : replyDrop_.state.calls) - callsBefore, 2);
      beginCalls = replyDrop_.ownerBeginCalls;
    }
    closeFileClient();
    journal.reset();
    ASSERT_NO_FATAL_FAILURE(restartCoordinator());
    ASSERT_NO_FATAL_FAILURE(openFileClient());
    auto resumed = EcFileRunJournal::resume(run);
    ASSERT_OK(resumed);
    journal = std::shared_ptr<EcFileRunJournal>(std::move(*resumed));
    auto before = encodeEcFileRunRecord(original), after = encodeEcFileRunRecord(journal->record());
    ASSERT_OK(before);
    ASSERT_OK(after);
    ASSERT_EQ(*before, *after);
    input = readEcFileInput(*fileClient_, inputPath);
    ASSERT_OK(input);
    auto recovered = blockingWait(fileClient_->appendAt(journal, std::move(*input), fileControl()));
    ASSERT_FALSE(recovered.failure) << (recovered.failure ? recovered.failure->describe() : "");
    ASSERT_TRUE(recovered.complete);
    ASSERT_EQ(recovered.revalidatedPrefixBytes, kStripeBytes);
    auto terminal = blockingWait(metaClient_->queryEcOwnedMutationV2(query));
    ASSERT_OK(terminal);
    ASSERT_TRUE(terminal->publishedContentConfirmed);
    ASSERT_TRUE(terminal->drain);
    ASSERT_EQ(terminal->record.candidate.generation, firstCandidate.generation);
    ASSERT_EQ(terminal->record.candidate.revision, firstCandidate.revision);
    for (size_t i = 0; i != 12; ++i)
      ASSERT_TRUE(
          serde::equals(terminal->record.candidate.fragments[i].identity, firstCandidate.fragments[i].identity));
    ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                        storage::EcGrantScope::WriteOperation,
                                        query.operation,
                                        *terminal->drain,
                                        EcV2DrainState::Published));
    {
      std::lock_guard lock(replyDrop_.mutex);
      // Published recovery observes only. Preparing recovery still needs a
      // same-operation Begin under the currently allowed WRITE permission.
      ASSERT_EQ(replyDrop_.ownerBeginCalls - beginCalls, phase == 0 ? 1 : 0);
    }
    closeFileClient();
    journal.reset();
  }
  RecordProperty(
      "owner_recovery",
      "real committed Begin/Publish replies lost; WRITE-only rejects33; fixed journal45 after normal restart");
}

TEST_F(TestEcFileClientNative, RevokedAclAllowsPublishedObservationButDoesNotAuthorizeUnfinishedTail) {
  // Two dropped replies must reach the two StripeClient recovery attempts,
  // not be consumed by MetaClient's independent inner RPC retry loop.
  const auto retryWait = metaClientConfig_.retry_default().retry_init_wait();
  auto restoreRetry = folly::makeGuard([&] { metaClientConfig_.retry_default().set_retry_init_wait(retryWait); });
  metaClientConfig_.retry_default().set_retry_init_wait(0_ms);
  EcObjectRef object;
  ASSERT_NO_FATAL_FAILURE(createFile(object, "file-owner-revoked"));
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &inode) { inode.acl.perm = Permission{0200}; }));
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  const auto data = bytes(2 * kStripeBytes, 2301);
  const auto inputPath = runPath("revoked-input");
  ASSERT_OK(saveEcFileReadOutput(inputPath, byteView(data)));
  const auto describeId = Uuid::random();
  auto described = blockingWait(fileClient_->describe(object, describeId, AccessType::WRITE, fileControl()));
  ASSERT_OK(described);
  auto input = readEcFileInput(*fileClient_, inputPath);
  ASSERT_OK(input);
  auto prepared = prepareEcFileAppend(*described,
                                      fileClient_->owner(),
                                      "native-file-fixture",
                                      0,
                                      inputPath.string(),
                                      input->bytes(),
                                      describeId);
  ASSERT_OK(prepared);
  const auto original = *prepared;
  const auto path = runPath("revoked-run");
  auto created = EcFileRunJournal::create(path, original);
  ASSERT_OK(created);
  auto journal = std::shared_ptr<EcFileRunJournal>(std::move(*created));
  size_t callsBefore;
  {
    std::lock_guard lock(replyDrop_.mutex);
    callsBefore = replyDrop_.state.calls;
    replyDrop_.filePublishDropOperation = original.slots[0].mutation.operation;
    replyDrop_.filePublishRepliesToDrop = 2;
  }
  auto lost = blockingWait(fileClient_->appendAt(journal, std::move(*input), fileControl()));
  ASSERT_TRUE(lost.failure);
  ASSERT_EQ(lost.confirmedPrefixBytes, 0);
  ASSERT_EQ(journal->latest()->appendStates[0], EcFileAppendState::Issued);
  ASSERT_EQ(journal->latest()->appendStates[1], EcFileAppendState::NotStarted);
  {
    std::lock_guard lock(replyDrop_.mutex);
    ASSERT_EQ(replyDrop_.filePublishRepliesToDrop, 0);
    ASSERT_EQ(replyDrop_.state.calls - callsBefore, 2);
  }
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &inode) { inode.acl.perm = Permission{0000}; }));
  closeFileClient();
  journal.reset();
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  ASSERT_NO_FATAL_FAILURE(openFileClient());
  ASSERT_ERROR(blockingWait(fileClient_->describe(object, Uuid::random(), AccessType::WRITE, fileControl())),
               MetaCode::kNoPermission);
  auto reopened = EcFileRunJournal::resume(path);
  ASSERT_OK(reopened);
  journal = std::shared_ptr<EcFileRunJournal>(std::move(*reopened));
  input = readEcFileInput(*fileClient_, inputPath);
  ASSERT_OK(input);
  auto recovered = blockingWait(fileClient_->appendAt(journal, std::move(*input), fileControl()));
  ASSERT_TRUE(recovered.failure);
  ASSERT_EQ(recovered.failure->code(), MetaCode::kNoPermission);
  ASSERT_FALSE(recovered.complete);
  ASSERT_EQ(recovered.confirmedStripes, 1);
  ASSERT_EQ(recovered.confirmedPrefixBytes, kStripeBytes);
  ASSERT_EQ(recovered.revalidatedPrefixBytes, kStripeBytes);
  ASSERT_EQ(recovered.firstUnconfirmedIndex, 1);
  ASSERT_EQ(journal->latest()->appendStates[1], EcFileAppendState::Issued);
  auto query = request<QueryEcOwnedMutationV2Req>();
  query.uuid = original.slots[0].mutation.getRequest;
  query.object = object;
  query.operation = original.slots[0].mutation.operation;
  auto published = blockingWait(metaClient_->queryEcOwnedMutationV2(query));
  ASSERT_OK(published);
  ASSERT_TRUE(published->publishedContentConfirmed);
  ASSERT_TRUE(published->drain);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(object,
                                      storage::EcGrantScope::WriteOperation,
                                      query.operation,
                                      *published->drain,
                                      EcV2DrainState::Published));
  query.uuid = original.slots[1].mutation.getRequest;
  query.operation = original.slots[1].mutation.operation;
  ASSERT_ERROR(blockingWait(metaClient_->queryEcOwnedMutationV2(query)), StatusCode::kKVStoreNotFound);
  // Direct FDB evidence complements the negative RPC: no new tail allocation
  // or file-length advance was granted after ACL revocation.
  auto txn = kv_->createReadWriteTransaction();
  auto stored = blockingWait(EcCatalog::getObject(*txn, object));
  ASSERT_OK(stored);
  ASSERT_EQ(stored->length, kStripeBytes);
  ASSERT_ERROR(blockingWait(EcCatalog::getOperation(*txn, object, query.operation)), StatusCode::kKVStoreNotFound);
  auto before = encodeEcFileRunRecord(original), after = encodeEcFileRunRecord(journal->record());
  ASSERT_OK(before);
  ASSERT_OK(after);
  ASSERT_EQ(*before, *after);
  RecordProperty("revoked_acl",
                 "Published45 observation confirms original prefix; tail Begin remains current-WRITE denied and same "
                 "journal retained");
}
}  // namespace file_client_native
