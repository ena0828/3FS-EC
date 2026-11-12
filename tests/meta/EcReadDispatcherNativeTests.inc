// Included after EcFileClientNativeTests.inc in the existing private-FDB/TCP
// fixture. No FUSE, USRBIO or operating-system process failure is simulated.
namespace read_dispatcher_native {
using namespace hf3fs::client::ec;
class TestEcReadDispatcherNative : public file_client_native::TestEcFileClientNative {
 protected:
  void TearDown() override {
    if (dispatcher_) blockingWait(dispatcher_->stop()); dispatcher_.reset(); spool_.reset();
    dispatchPool_.reset();
    TestEcFileClientNative::TearDown();
  }
  void openDispatcher(bool create = true) {
    ASSERT_FALSE(fileClient_); ASSERT_FALSE(dispatcher_);
    if (!dispatchPool_) dispatchPool_ = std::make_unique<folly::CPUThreadPoolExecutor>(4);
    auto opened = create ? EcReadSpool::create(runPath("read-spool"), "native-dispatcher", {2, 1, 6u << 20})
                         : EcReadSpool::open(runPath("read-spool"), "native-dispatcher", {2, 1, 6u << 20});
    ASSERT_OK(opened); spool_ = std::move(*opened);
    // Stable namespace is read from the private spool before constructing the
    // real MetaClient. The fixture's old client.uuid is intentionally not used.
    metaClient_->stop(); metaClient_.reset(); metaNet_->stopAndJoin(); metaNet_.reset();
    ASSERT_NO_FATAL_FAILURE(startMetaClient(ClientId(spool_->clientNamespace())));
    auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
    auto connected = EcReadDispatcher::connect(spool_, borrowed, storageClient_, mgmtd_, *dispatchPool_, {});
    ASSERT_OK(connected); dispatcher_ = std::move(*connected);
  }
  void verifyRetainedT2(const EcReadReceipt &receipt, size_t expected) {
    const auto directory = spool_->directory() / fmt::format("run-{:020}", receipt.sequence);
    auto journal = EcFileRunJournal::resume(directory); ASSERT_OK(journal);
    const auto &record = (*journal)->record();
    auto observed = blockingWait(metaClient_->queryEcRangeV2(queryRun(record))); ASSERT_OK(observed);
    ASSERT_EQ(observed->snapshot.stripeCount, expected);
    auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string())); ASSERT_OK(key);
    for (size_t i = 0; i != expected; ++i) {
      ASSERT_EQ(observed->snapshot.stripes[i].state, EcRangePinState::Released);
      auto txn = kv_->createReadWriteTransaction();
      auto drain = blockingWait(EcV2DrainCatalog::get(*txn, record.object, storage::EcGrantScope::ReadPin,
          record.slots[i].pin, EcOwner{user_.uid, spool_->clientNamespace()}));
      ASSERT_OK(drain); ASSERT_TRUE(*drain);
      ASSERT_EQ((**drain).state, EcV2DrainState::ReadReleased); ASSERT_EQ((**drain).identity.endpoints.count, 12);
      for (size_t endpoint = 0; endpoint != 12; ++endpoint) {
        ASSERT_TRUE((**drain).observations[endpoint]);
        const auto &ack = *(**drain).observations[endpoint];
        ASSERT_OK(EcVerifiedDrainAck::verify(**key, **drain, endpoint, ack.request, ack.ack));
      }
      auto pin = blockingWait(EcCatalog::getPin(*txn, record.object, record.slots[i].pin)); ASSERT_OK(pin);
      ASSERT_TRUE(pin->released); ASSERT_EQ(pin->owner.client, spool_->clientNamespace());
    }
  }
  std::shared_ptr<EcReadSpool> spool_;
  std::shared_ptr<EcReadDispatcher> dispatcher_;
  std::unique_ptr<folly::CPUThreadPoolExecutor> dispatchPool_;
};
TEST_F(TestEcReadDispatcherNative, RealCrossStripeBytesAllSignedT2AndRestartedExplicitRetirement) {
  EcObjectRef object; ASSERT_NO_FATAL_FAILURE(createFile(object, "dispatcher-real-read"));
  Mutation first, second, tail;
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 1, second));
  ASSERT_NO_FATAL_FAILURE(appendStripe(object, 2, tail, 137));
  ASSERT_NO_FATAL_FAILURE(openDispatcher());
  auto opened = blockingWait(dispatcher_->openRead(object, user_, fileControl())); ASSERT_OK(opened);
  auto read = blockingWait(dispatcher_->read(*opened, user_, kStripeBytes - 31, kStripeBytes + 500, fileControl()));
  ASSERT_OK(read); ASSERT_FALSE(read->readFailure); ASSERT_TRUE(read->data);
  ASSERT_TRUE(read->localJoined); ASSERT_TRUE(read->cleanup.localJoined);
  const auto expected = (first.logical + second.logical + tail.logical).substr(kStripeBytes - 31);
  const auto view = read->data->bytes();
  const std::string_view actual(reinterpret_cast<const char *>(view.data()), view.size());
  ASSERT_EQ(actual, expected); ASSERT_EQ(read->data->snapshot().stripeCount, 3);
  ASSERT_TRUE(read->cleanup.allReleased); ASSERT_EQ(read->cleanup.releasedMask, 7);
  ASSERT_NO_FATAL_FAILURE(verifyRetainedT2(read->receipt, 3));
  auto oldReceipt = read->receipt;
  ASSERT_ERROR(blockingWait(dispatcher_->retire(oldReceipt, user_, runPath("read-summary.json"), fileControl())),
               StorageClientCode::kResourceBusy);
  auto stopped = blockingWait(dispatcher_->stop()); ASSERT_TRUE(stopped.localJoined);
  ASSERT_EQ(stopped.retainedOutputLeases, 1);
  dispatcher_.reset(); spool_.reset();
  // The still-held payload must not keep an executor KeepAlive after stop.
  dispatchPool_.reset();
  // Output still owns the core/spool after stop and dispatcher destruction.
  ASSERT_ERROR(EcReadSpool::open(runPath("read-spool"), "native-dispatcher", {}), StorageClientCode::kResourceBusy);
  read->data.reset(); spool_.reset();
  ASSERT_NO_FATAL_FAILURE(openDispatcher(false));
  ASSERT_EQ(metaClient_->clientId().uuid, oldReceipt.clientNamespace);
  auto original = blockingWait(dispatcher_->inspectReceipt(oldReceipt)); ASSERT_OK(original);
  ASSERT_EQ(original->evidence, EcReadLocalEvidence::Retained); ASSERT_TRUE(original->record->allPinsReleased);
  auto retired = blockingWait(dispatcher_->retire(oldReceipt, user_, runPath("read-summary.json"), fileControl()));
  ASSERT_OK(retired); ASSERT_TRUE(retired->localFilesRemoved);
  auto absent = blockingWait(dispatcher_->inspectReceipt(oldReceipt)); ASSERT_OK(absent);
  ASSERT_EQ(absent->evidence, EcReadLocalEvidence::NotRetained);
  ASSERT_ERROR(blockingWait(dispatcher_->resumeRead(oldReceipt, user_, fileControl())), StatusCode::kKVStoreNotFound);
  RecordProperty("dispatcher_scope", "real FDB/TCP 3-stripe read, all12 signed ACK per pin, local namespace reopen; no process kill");
}
TEST_F(TestEcReadDispatcherNative, RealAuthenticationRootDelegationAndRevokedAclDoNotCreateNewRanges) {
  EcObjectRef object; ASSERT_NO_FATAL_FAILURE(createFile(object, "dispatcher-auth"));
  Mutation first; ASSERT_NO_FATAL_FAILURE(appendStripe(object, 0, first));
  ASSERT_NO_FATAL_FAILURE(openDispatcher());
  auto claimedRoot = user_; claimedRoot.uid = flat::Uid{0};
  ASSERT_ERROR(blockingWait(dispatcher_->openRead(object, claimedRoot, fileControl())), StatusCode::kAuthenticationFail);
  auto administrator = rootUser(); ASSERT_OK(administrator);
  administrator->uid = user_.uid; administrator->gid = user_.gid;
  auto opened = blockingWait(dispatcher_->openRead(object, *administrator, fileControl())); ASSERT_OK(opened);
  auto result = blockingWait(dispatcher_->read(*opened, *administrator, 3, 29, fileControl())); ASSERT_OK(result);
  ASSERT_FALSE(result->readFailure); ASSERT_TRUE(result->data); ASSERT_TRUE(result->cleanup.allReleased);
  ASSERT_EQ(result->receipt.ownerUid, user_.uid.toUnderType()); result->data.reset();
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &inode) { inode.acl.perm = Permission{0}; }));
  // Retire is owner-bound cleanup observation; current READ ACL is not needed.
  ASSERT_OK(blockingWait(dispatcher_->retire(result->receipt, *administrator, runPath("auth-summary.json"), fileControl())));
  auto denied = blockingWait(dispatcher_->read(*opened, user_, 0, 1, fileControl())); ASSERT_OK(denied);
  ASSERT_TRUE(denied->readFailure); ASSERT_EQ(denied->readFailure->code(), MetaCode::kNoPermission);
  ASSERT_FALSE(denied->cleanup.allReleased);
  auto debt = blockingWait(dispatcher_->inspectReceipt(denied->receipt)); ASSERT_OK(debt);
  ASSERT_TRUE(debt->record->acquisitionIssued); ASSERT_FALSE(debt->record->snapshotObserved);
  ASSERT_FALSE(blockingWait(dispatcher_->retire(denied->receipt, user_, runPath("denied-summary.json"), fileControl())));
  RecordProperty("dispatcher_auth", "actual UserStore root delegation retained; UID claim alone rejected; ACL denial preserves uncertain identity");
}
}  // namespace read_dispatcher_native
