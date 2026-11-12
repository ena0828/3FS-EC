// Included after the private-FDB/real-TCP fixture definition. Only routing is
// fake; worker compute, Meta52, twelve Engine fragments, candidate/source drain
// and mode4 root publication execute their actual service implementations.
class TestEcFileNativeWrite : public TestEcV2NativeLifecycle {
 protected:
  bool enableFileRmw() const override { return true; }
  bool enableMetaGcAdmin() const override { return true; }
  bool enableExactGc() const override { return true; }
  uint32_t ecAdmissionLimit() const override { return 4; }
  net::Address workerAddressFor(const EcV2PhysicalEndpoint &worker) {
    const auto *node = routing_->getNode(worker.placement.node);
    if (!node) throw std::runtime_error("fixture worker is absent");
    for (const auto &group : node->app.serviceGroups)
      if (group.services.contains("StorageSerde"))
        for (const auto &address : group.endpoints)
          if (address.type == net::Address::TCP) return address;
    throw std::runtime_error("fixture worker has no actual listener");
  }
  void acceptPatch(const OpenEcFileSessionRsp &opened,
                   uint64_t offset,
                   const std::string &bytes,
                   AdvanceEcFilePwriteReq &accepted) {
    auto sha = storage::ec_rmw_detail::sha256(bytes);
    ASSERT_OK(sha);
    auto begin = request<BeginEcFilePwriteReq>();
    begin.object = opened.object.object;
    begin.session = opened.session.intent.session;
    begin.operation = Uuid::random();
    begin.offset = offset;
    begin.length = bytes.size();
    begin.inputSha256 = *sha;
    auto begun = blockingWait(metaClient_->beginEcFilePwrite(begin));
    ASSERT_OK(begun);
    ASSERT_TRUE(begun->progress.parent);
    ASSERT_EQ(begun->progress.parent->confirmedPrefix, 0);
    auto changed = begin;
    changed.inputSha256[0] ^= 1;
    auto rejected = blockingWait(metaClient_->beginEcFilePwrite(changed));
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), StatusCode::kTokenMismatch);

    accepted = request<AdvanceEcFilePwriteReq>();
    accepted.object = begin.object;
    accepted.session = begin.session;
    accepted.operation = begin.operation;
    accepted.action = EcFileAdvanceAction::Plan;
    accepted.child = Uuid::random();
    accepted.intent.object = begin.object;
    accepted.intent.parent = begin.operation;
    accepted.intent.child = accepted.child;
    accepted.intent.plan = Uuid::random();
    accepted.intent.sourcePin = Uuid::random();
    accepted.intent.expectedPrefix = 0;
    accepted.intent.patchSha256 = *sha;
    for (auto &id : accepted.intent.nodeIds) id = Uuid::random();
  }
  static EcTreeSourcePinIntent sourceIntentFor(const EcFileChildRecord &child) {
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
    return pin;
  }
  void commitDataChildBeforeExecution(const AdvanceEcFilePwriteReq &accepted, EcFileChildRecord &committed) {
    const EcOwner owner{user_.uid, metaClientId_.uuid};
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw);
      auto child = blockingWait(EcFileMutationCatalog::planChild(tx, owner, accepted.intent));
      ASSERT_OK(child);
      ASSERT_EQ(child->source.kind, EcTreeSlotKind::Data);
      ASSERT_EQ(child->state, EcFileChildState::Planned);
      EXPECT_EQ(serde::serialize(child->intent), serde::serialize(accepted.intent));
      committed = *child;
      ASSERT_OK(blockingWait(tx.commit()));
      RecordProperty("committed_child_phase_bytes", std::to_string(tx.usage().totalBytes()));
      RecordProperty("committed_child_phase_key_operations", std::to_string(tx.usage().keyOperations));
    }
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw);
      auto execution =
          blockingWait(tx.get(ec_tree_detail::idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child)));
      ASSERT_OK(execution);
      ASSERT_FALSE(*execution);
      auto child = blockingWait(EcFileMutationCatalog::queryChild(tx, accepted.object, accepted.child, owner));
      ASSERT_OK(child);
      ASSERT_TRUE(*child);
      EXPECT_EQ(serde::serialize(**child), serde::serialize(committed));
      auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, sourceIntentFor(committed)));
      ASSERT_OK(source);
      EXPECT_EQ(source->state, EcTreeSourcePinState::Active);
      EXPECT_EQ(source->issuanceSequence, 0);
      EXPECT_FALSE(source->drain);
    }
    auto query = request<QueryEcFilePwriteReq>();
    query.object = accepted.object;
    query.session = accepted.session;
    query.operation = accepted.operation;
    query.child = accepted.child;
    auto observed = blockingWait(metaClient_->queryEcFilePwrite(query));
    ASSERT_OK(observed);
    ASSERT_TRUE(observed->progress.parent);
    ASSERT_TRUE(observed->progress.child);
    EXPECT_EQ(observed->progress.parent->state, EcFileMutationState::Open);
    EXPECT_EQ(observed->progress.parent->activeChild, accepted.child);
    EXPECT_EQ(observed->progress.child->state, EcFileChildState::Planned);
    EXPECT_FALSE(observed->progress.outputDrained);
    EXPECT_FALSE(observed->progress.sourceReleased);
    EXPECT_FALSE(observed->progress.worker);
  }
  void writePatch(const OpenEcFileSessionRsp &opened,
                  uint64_t offset,
                  const std::string &bytes,
                  bool losePublishReply,
                  AdvanceEcFilePwriteReq &accepted,
                  bool stopBeforePublication = false,
                  bool resumeCommittedChild = false) {
    ASSERT_NO_FATAL_FAILURE(acceptPatch(opened, offset, bytes, accepted));
    std::optional<EcFileChildRecord> committed;
    if (resumeCommittedChild) {
      committed.emplace();
      ASSERT_NO_FATAL_FAILURE(commitDataChildBeforeExecution(accepted, *committed));
    }
    // The optional boundary commits real child/source metadata but deliberately
    // stops before ECFE reservation or signing. It does not simulate a kill.
    auto planned = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
    ASSERT_OK(planned);
    ASSERT_TRUE(planned->progress.worker);
    ASSERT_TRUE(planned->progress.child);
    ASSERT_EQ(planned->progress.child->patchLength, bytes.size());
    if (committed) {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw);
      auto resumed = blockingWait(
          EcFileExecutionCatalog::get(tx, EcOwner{user_.uid, metaClientId_.uuid}, accepted.object, accepted.child));
      ASSERT_OK(resumed);
      EXPECT_EQ(serde::serialize(resumed->record.child), serde::serialize(*committed));
      EXPECT_EQ(resumed->record.planDigest, planned->progress.worker->planDigest);
      EXPECT_GT(resumed->record.issuanceSequence, 0);
    }
    const auto access = *planned->progress.worker;
    EXPECT_EQ(access.grant.claims.rights & uint16_t(storage::EcRmwRight::Install), 0);
    EXPECT_EQ(access.grant.claims.rights,
              uint16_t(storage::EcRmwRight::Upload) | uint16_t(storage::EcRmwRight::Execute) |
                  uint16_t(storage::EcRmwRight::Observe));
    net::Client::Config config;
    smallClient(config);
    auto transport = std::make_shared<storage::client::EcRmwTransport>(config);
    ASSERT_OK(transport->start());
    auto stopped = folly::makeGuard([&] { transport->stopAndJoin(); });
    const auto address = workerAddressFor(access.worker);
    for (size_t offset = 0, block = 0; offset < bytes.size(); offset += storage::kEcIntegrityBlockBytes, ++block) {
      storage::EcRmwPutReq put;
      put.planId = accepted.intent.plan;
      put.grant = access.grant;
      put.blockIndex = block;
      put.payload.data = bytes.substr(offset, std::min<size_t>(storage::kEcIntegrityBlockBytes, bytes.size() - offset));
      ASSERT_OK(blockingWait(transport->put(address, std::move(put), control())));
    }
    storage::EcRmwActionReq action;
    action.planId = accepted.intent.plan;
    action.grant = access.grant;
    action.action = storage::EcRmwActionRequest::Submit;
    auto submitted = blockingWait(transport->action(address, action, control()));
    ASSERT_OK(submitted);
    action.action = storage::EcRmwActionRequest::Query;
    const auto until = SteadyClock::now() + 30_s;
    while (submitted->state != 4 && SteadyClock::now() < until) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      submitted = blockingWait(transport->action(address, action, control()));
      ASSERT_OK(submitted);
    }
    ASSERT_EQ(submitted->state, 4);
    ASSERT_EQ(submitted->executionError, StatusCode::kOK);
    if (stopBeforePublication) return;
    if (losePublishReply) {
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.fileTreePublishDropChild = accepted.child;
    }
    accepted.action = EcFileAdvanceAction::Publish;
    auto first = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
    if (losePublishReply) {
      ASSERT_FALSE(first);
      std::lock_guard lock(replyDrop_.mutex);
      ASSERT_EQ(replyDrop_.fileTreeRepliesDropped, 1);
    } else
      ASSERT_OK(first);
    auto query = request<QueryEcFilePwriteReq>();
    query.object = accepted.object;
    query.session = accepted.session;
    query.operation = accepted.operation;
    query.child = accepted.child;
    auto observed = blockingWait(metaClient_->queryEcFilePwrite(query));
    ASSERT_OK(observed);
    ASSERT_TRUE(observed->progress.parent);
    ASSERT_EQ(observed->progress.parent->confirmedPrefix, bytes.size());
    ASSERT_EQ(observed->progress.child->state, EcFileChildState::Published);
    auto replay = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
    ASSERT_OK(replay);
    EXPECT_EQ(replay->progress.parent->confirmedPrefix, bytes.size());
    accepted.action = EcFileAdvanceAction::CleanupChild;
    accepted.outputRevocation = Uuid::random();
    accepted.sourceRevocation = Uuid::random();
    auto cleaned = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
    ASSERT_OK(cleaned);
    EXPECT_TRUE(cleaned->progress.outputDrained);
    EXPECT_TRUE(cleaned->progress.sourceReleased);
  }
};

TEST_F(TestEcFileNativeWrite, CommittedSourceChildWithoutExecutionCanBeFencedAndReleased) {
  using namespace ec_tree_detail;
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "native-mode4-child-stage");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = kEcSessionWrite;
  open.perm = Permission{0600};
  auto created = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(created);
  AdvanceEcFilePwriteReq initial;
  ASSERT_NO_FATAL_FAILURE(writePatch(*created, 0, bytes(2 * kShardBytes + 7, 57), false, initial));
  auto current = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(current);
  AdvanceEcFilePwriteReq accepted;
  ASSERT_NO_FATAL_FAILURE(acceptPatch(*current, 17, bytes(257, 61), accepted));
  EcFileChildRecord committed;
  ASSERT_NO_FATAL_FAILURE(commitDataChildBeforeExecution(accepted, committed));
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  const auto pin = sourceIntentFor(committed);

  auto cleanup = accepted;
  cleanup.action = EcFileAdvanceAction::CleanupChild;
  cleanup.outputRevocation = Uuid::random();
  cleanup.sourceRevocation = Uuid::random();
  auto cleaned = blockingWait(metaClient_->advanceEcFilePwrite(cleanup));
  ASSERT_OK(cleaned);
  ASSERT_TRUE(cleaned->progress.parent);
  ASSERT_TRUE(cleaned->progress.child);
  EXPECT_EQ(cleaned->progress.parent->state, EcFileMutationState::ClosedLogical);
  EXPECT_EQ(cleaned->progress.parent->fencedChild, accepted.child);
  EXPECT_EQ(cleaned->progress.parent->confirmedPrefix, 0);
  EXPECT_EQ(cleaned->progress.child->state, EcFileChildState::Fenced);
  EXPECT_TRUE(cleaned->progress.outputDrained);
  EXPECT_TRUE(cleaned->progress.sourceReleased);
  EXPECT_FALSE(cleaned->progress.worker);
  auto sealed = accepted;
  sealed.action = EcFileAdvanceAction::SealPrefix;
  auto sealedAgain = blockingWait(metaClient_->advanceEcFilePwrite(sealed));
  ASSERT_OK(sealedAgain);
  EXPECT_EQ(serde::serialize(sealedAgain->progress), serde::serialize(cleaned->progress));
  auto repeated = blockingWait(metaClient_->advanceEcFilePwrite(cleanup));
  ASSERT_OK(repeated);
  EXPECT_EQ(serde::serialize(repeated->progress), serde::serialize(cleaned->progress));
  ASSERT_ERROR(blockingWait(metaClient_->advanceEcFilePwrite(accepted)), StatusCode::kTokenStale);

  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto execution = blockingWait(tx.get(idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child)));
    ASSERT_OK(execution);
    EXPECT_FALSE(*execution);
    auto child = blockingWait(EcFileMutationCatalog::queryChild(tx, accepted.object, accepted.child, owner));
    ASSERT_OK(child);
    ASSERT_TRUE(*child);
    auto expected = committed;
    expected.state = EcFileChildState::Fenced;
    EXPECT_EQ(serde::serialize(**child), serde::serialize(expected));
    auto source = blockingWait(EcTreeSourcePinCatalog::query(tx, pin));
    ASSERT_OK(source);
    EXPECT_EQ(source->state, EcTreeSourcePinState::Released);
    EXPECT_EQ(source->issuanceSequence, 0);
    ASSERT_TRUE(source->drain);
    ASSERT_EQ(source->drain->identity.endpoints.count, 12);
    EXPECT_EQ(source->drain->identity.revocationId, cleanup.sourceRevocation);
    auto controlKey = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
    ASSERT_OK(controlKey);
    for (size_t n = 0; n < 12; ++n) {
      ASSERT_TRUE(source->drain->observations[n]);
      const auto &ack = *source->drain->observations[n];
      ASSERT_OK(EcVerifiedDrainAck::verify(**controlKey, *source->drain, n, ack.request, ack.ack));
      auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, source->allocations[n].fragment.identity);
      ASSERT_OK(key);
      auto accounting = blockingWait(require<EcTreeSourceAllocationRecord>(tx, *key));
      ASSERT_OK(accounting);
      EXPECT_EQ(accounting->registered, 1);
      EXPECT_EQ(accounting->released, 1);
      EXPECT_EQ(accounting->active, 0);
    }
    auto manifest = blockingWait(EcCatalog::getManifest(tx, accepted.object, pin.slot.stripe, pin.slot.revision));
    ASSERT_OK(manifest);
    EXPECT_EQ(manifest->pins, 0);
    auto context = blockingWait(EcFileTreeCatalog::open(tx, accepted.object));
    ASSERT_OK(context);
    auto root = blockingWait(EcFileTreeCatalog::getRoot(*context));
    ASSERT_OK(root);
    EXPECT_EQ(serde::serialize(*root), serde::serialize(current->root));
  }
  auto close = request<CloseEcFileSessionReq>();
  close.object = accepted.object;
  close.session = accepted.session;
  auto closed = blockingWait(metaClient_->closeEcFileSession(close));
  ASSERT_OK(closed);
  EXPECT_EQ(closed->session.state, EcFileSessionState::Closed);
  ASSERT_ERROR(blockingWait(metaClient_->advanceEcFilePwrite(accepted)), StatusCode::kTokenStale);
  auto query = request<QueryEcFilePwriteReq>();
  query.object = accepted.object;
  query.session = accepted.session;
  query.operation = accepted.operation;
  query.child = accepted.child;
  auto observed = blockingWait(metaClient_->queryEcFilePwrite(query));
  ASSERT_OK(observed);
  EXPECT_EQ(serde::serialize(observed->progress), serde::serialize(cleaned->progress));
  {
    auto raw = kv_->createReadWriteTransaction();
    auto execution = blockingWait(raw->get(idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child)));
    ASSERT_OK(execution);
    EXPECT_FALSE(*execution);
  }
  RecordProperty("coverage", "real committed child/source-pin boundary before ECFE or signing; not a process kill");
}

TEST_F(TestEcFileNativeWrite, FreshPublicationRejectsOrphanedPermanentEditBeforeInstallingManifest) {
  using namespace ec_tree_detail;
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "native-mode4-orphaned-edit");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = kEcSessionWrite;
  open.perm = Permission{0600};
  auto created = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(created);
  const auto payload = bytes(2 * kShardBytes + 7, 93);
  AdvanceEcFilePwriteReq accepted;
  ASSERT_NO_FATAL_FAILURE(writePatch(*created, 0, payload, false, accepted, true));
  const auto object = accepted.object;
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  EcTreeRoot beforeRoot;
  EcFileExecutionRecord beforeExecution;
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto context = blockingWait(EcFileTreeCatalog::open(tx, object));
    ASSERT_OK(context);
    auto root = blockingWait(EcFileTreeCatalog::getRoot(*context));
    ASSERT_OK(root);
    beforeRoot = *root;
    auto execution = blockingWait(EcFileExecutionCatalog::get(tx, owner, object, accepted.child));
    ASSERT_OK(execution);
    ASSERT_EQ(execution->record.state, EcFileExecutionState::Bound);
    beforeExecution = execution->record;
  }
  ASSERT_TRUE(beforeExecution.allocations);
  const auto &child = beforeExecution.child;
  EcTreeEditResult orphan;
  auto &edit = orphan.intent;
  edit.object = object;
  edit.operation = accepted.child;
  edit.expectedRoot = beforeRoot.root;
  edit.expectedSequence = beforeRoot.sequence;
  edit.expectedEpoch = child.epoch;
  edit.stripe = child.stripe;
  edit.visibleLength = payload.size();
  edit.nodeIds = accepted.intent.nodeIds;
  edit.replacement.kind = EcTreeSlotKind::Data;
  edit.replacement.stripe = child.stripe;
  edit.replacement.revision = child.targetRevision;
  edit.replacement.generation = child.targetGeneration;
  edit.replacement.logicalLength = child.targetLogicalLength;
  edit.replacement.contentSha256 = beforeExecution.contentSha256;
  orphan.root = beforeRoot;
  orphan.root.root = edit.nodeIds[15];
  ++orphan.root.sequence;
  orphan.root.visibleLength = edit.visibleLength;
  const auto editKey = idKey(kv::KeyPrefix::EcTreeEdit, object, accepted.child);
  {
    auto raw = kv_->createReadWriteTransaction();
    // Deliberate persistent inconsistency: a structurally valid replay result
    // without its manifest or tree. This is not a publication proof.
    ASSERT_OK(blockingWait(store(*raw, editKey, orphan)));
    ASSERT_OK(blockingWait(raw->commit()));
  }
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto context = blockingWait(EcFileTreeCatalog::open(tx, object));
    ASSERT_OK(context);
    auto replay = blockingWait(EcFileTreeCatalog::queryEdit(*context, accepted.child));
    ASSERT_OK(replay);
    ASSERT_TRUE(*replay);
    EXPECT_EQ(serde::serialize(**replay), serde::serialize(orphan));
  }
  accepted.action = EcFileAdvanceAction::Publish;
  auto rejected = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
  ASSERT_ERROR(rejected, StatusCode::kDataCorruption);
  EXPECT_NE(rejected.error().describe().find("installation collides with permanent publication metadata"),
            std::string::npos);
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto context = blockingWait(EcFileTreeCatalog::open(tx, object));
    ASSERT_OK(context);
    auto root = blockingWait(EcFileTreeCatalog::getRoot(*context));
    ASSERT_OK(root);
    EXPECT_EQ(serde::serialize(*root), serde::serialize(beforeRoot));
    auto execution = blockingWait(EcFileExecutionCatalog::get(tx, owner, object, accepted.child));
    ASSERT_OK(execution);
    EXPECT_EQ(execution->record.state, EcFileExecutionState::Drained);
    auto logical = blockingWait(EcFileMutationCatalog::queryChild(tx, object, accepted.child, owner));
    ASSERT_OK(logical);
    ASSERT_TRUE(*logical);
    EXPECT_EQ((**logical).state, EcFileChildState::Planned);
    auto parent = blockingWait(EcFileMutationCatalog::query(tx, object, accepted.operation, owner));
    ASSERT_OK(parent);
    ASSERT_TRUE(*parent);
    EXPECT_EQ((**parent).confirmedPrefix, 0);
    for (const auto prefix : {kv::KeyPrefix::EcManifest, kv::KeyPrefix::EcTreeManifest}) {
      auto absent = blockingWait(tx.get(manifestKey(prefix, object, child.stripe, child.targetRevision)));
      ASSERT_OK(absent);
      EXPECT_FALSE(*absent);
    }
    for (const auto &allocation : beforeExecution.candidates) {
      auto key = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, allocation.identity);
      ASSERT_OK(key);
      auto held = blockingWait(require<EcFileExecutionAllocation>(tx, *key));
      ASSERT_OK(held);
      EXPECT_TRUE(held->active);
      for (const auto prefix : {kv::KeyPrefix::EcFragmentRef, kv::KeyPrefix::EcTreeAllocationHold}) {
        auto absentKey = allocationKey(prefix, allocation.identity);
        ASSERT_OK(absentKey);
        auto absent = blockingWait(tx.get(*absentKey));
        ASSERT_OK(absent);
        EXPECT_FALSE(*absent);
      }
    }
  }
  {
    auto raw = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(raw->clear(editKey)));
    ASSERT_OK(blockingWait(raw->commit()));
  }
  // Restore only the injected damage. The same permanent child and real
  // verifier evidence must now publish and activate all twelve allocations.
  auto published = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
  ASSERT_OK(published);
  ASSERT_TRUE(published->progress.child);
  ASSERT_TRUE(published->progress.parent);
  EXPECT_EQ(published->progress.child->state, EcFileChildState::Published);
  EXPECT_EQ(published->progress.parent->confirmedPrefix, payload.size());
  auto replay = blockingWait(metaClient_->advanceEcFilePwrite(accepted));
  ASSERT_OK(replay);
  {
    auto raw = kv_->createReadWriteTransaction();
    EcFileTreeTxnBudget tx(*raw);
    auto execution = blockingWait(EcFileExecutionCatalog::get(tx, owner, object, accepted.child));
    ASSERT_OK(execution);
    EXPECT_EQ(execution->record.state, EcFileExecutionState::Published);
    auto compact = blockingWait(require<EcTreeManifestHolds>(
        tx,
        manifestKey(kv::KeyPrefix::EcTreeManifest, object, child.stripe, child.targetRevision)));
    ASSERT_OK(compact);
    EXPECT_EQ(compact->treeHolds, 1);
    for (const auto &allocation : beforeExecution.candidates) {
      auto key = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, allocation.identity);
      ASSERT_OK(key);
      auto held = blockingWait(require<EcFileExecutionAllocation>(tx, *key));
      ASSERT_OK(held);
      EXPECT_FALSE(held->active);
      auto treeKey = allocationKey(kv::KeyPrefix::EcTreeAllocationHold, allocation.identity);
      ASSERT_OK(treeKey);
      auto treeHeld = blockingWait(require<EcTreeAllocationHolds>(tx, *treeKey));
      ASSERT_OK(treeHeld);
      EXPECT_EQ(treeHeld->holds, 1);
    }
  }
}

TEST_F(TestEcFileNativeWrite, WriteOnlyZeroThenDataPatchPublishesAndReadsThroughTreeSession) {
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(parent_, "native-mode4-file");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = kEcSessionWrite;
  open.perm = Permission{0600};
  auto created = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(created);
  auto retry = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(retry);
  ASSERT_EQ(retry->object.object, created->object.object);
  ASSERT_EQ(retry->session.intent.session, open.session);
  auto changed = open;
  changed.rights = kEcSessionRead;
  auto badRetry = blockingWait(metaClient_->openEcFileSession(changed));
  ASSERT_FALSE(badRetry);
  EXPECT_EQ(badRetry.error().code(), StatusCode::kTokenMismatch);

  auto link = request<HardLinkReq>();
  link.oldPath = open.path;
  link.newPath = PathAt(parent_, "native-mode4-alias");
  auto linked = blockingWait(metaClient_->hardLinkWithIdentity(link));
  ASSERT_OK(linked);
  EXPECT_EQ(linked->stat.nlink, 2);
  auto expected = bytes(2 * kShardBytes + 7, 91);
  AdvanceEcFilePwriteReq first, second;
  ASSERT_NO_FATAL_FAILURE(writePatch(*created, 0, expected, true, first));
  auto readOpen = request<OpenEcFileSessionReq>();
  readOpen.object = created->object.object;
  readOpen.birth = created->root.birth;
  readOpen.session = Uuid::random();
  readOpen.rights = kEcSessionRead;
  auto reader = blockingWait(metaClient_->openEcFileSession(readOpen));
  ASSERT_OK(reader);
  auto removeOriginal = request<RemoveReq>();
  removeOriginal.path = open.path;
  removeOriginal.inodeId = created->object.object.inode;
  auto removeAlias = request<RemoveReq>();
  removeAlias.path = link.newPath;
  removeAlias.inodeId = created->object.object.inode;
  ASSERT_OK(blockingWait(metaClient_->unlinkWithIdentity(removeOriginal)));
  ASSERT_OK(blockingWait(metaClient_->unlinkWithIdentity(removeAlias)));
  // Preserve the same UUID: the generic remove cache must not bypass the
  // permanent mode-4 request comparison on this deliberately changed path.
  auto changedRemove = removeAlias;
  changedRemove.path = PathAt(parent_, "unrelated");
  auto wrongReplay = blockingWait(metaClient_->unlinkWithIdentity(changedRemove));
  ASSERT_FALSE(wrongReplay);
  EXPECT_EQ(wrongReplay.error().code(), StatusCode::kTokenMismatch);
  auto newReader = readOpen;
  newReader.uuid = Uuid::random();
  newReader.session = Uuid::random();
  auto rejectedOpen = blockingWait(metaClient_->openEcFileSession(newReader));
  ASSERT_FALSE(rejectedOpen);
  EXPECT_EQ(rejectedOpen.error().code(), MetaCode::kNotFound);
  // Actual Data-source RMW through the already-open WRITE-only session after
  // the last name was unlinked; no path or new session is silently created.
  const auto patch = bytes(257, 203);
  expected.replace(17, patch.size(), patch);
  ASSERT_NO_FATAL_FAILURE(writePatch(*created, 17, patch, false, second, false, true));
  auto acquire = request<AcquireEcTreeReadReq>();
  acquire.intent.session = open.session;
  acquire.intent.request = Uuid::random();
  acquire.intent.range = Uuid::random();
  acquire.intent.selection.object = created->object.object;
  acquire.intent.selection.length = expected.size();
  acquire.intent.selection.pinCount = 1;
  acquire.intent.selection.pins[0].stripe = 0;
  acquire.intent.selection.pins[0].pin = Uuid::random();
  auto denied = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_FALSE(denied);
  EXPECT_EQ(denied.error().code(), MetaCode::kNoPermission);

  EXPECT_EQ(reader->root.visibleLength, expected.size());
  acquire.uuid = Uuid::random();
  acquire.intent.session = readOpen.session;
  auto pinned = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_OK(pinned);
  ASSERT_EQ(pinned->record.stripeCount, 1);
  ASSERT_EQ(pinned->record.stripes[0].slot.kind, EcTreeSlotKind::Data);
  acquire.stripeIndex = 0;
  auto credentials = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_OK(credentials);
  ASSERT_TRUE(credentials->read);
  storage::EcCodec::Shards data;
  std::array<storage::EcCodecShardView, 12> views;
  for (size_t i = 0; i < 12; ++i) {
    auto read = readOne(*credentials->read, i);
    ASSERT_OK(read);
    data[i] = std::move(read->payload.data);
    auto integrity = storage::computeEcIntegrity(credentials->read->manifest.fragments[i].identity, data[i]);
    ASSERT_OK(integrity);
    EXPECT_EQ(*integrity, credentials->read->manifest.fragments[i].integrity);
    views[i] = {uint16_t(i), data[i]};
  }
  ASSERT_OK(storage::EcCodec::verify(views, expected.size(), kShardBytes));
  std::string logical;
  for (size_t i = 0; i < 10 && logical.size() < expected.size(); ++i)
    logical.append(data[i].data(), std::min<size_t>(data[i].size(), expected.size() - logical.size()));
  EXPECT_EQ(logical, expected);
  auto close = request<CloseEcFileSessionReq>();
  close.object = created->object.object;
  close.session = readOpen.session;
  auto closing = blockingWait(metaClient_->closeEcFileSession(close));
  ASSERT_OK(closing);
  EXPECT_EQ(closing->session.state, EcFileSessionState::Closing);
  EXPECT_EQ(closing->session.activeReadRanges, 1);
  auto release = request<ReleaseEcTreeReadReq>();
  release.intent = acquire.intent;
  release.revocations[0] = Uuid::random();
  auto released = blockingWait(metaClient_->releaseEcTreeRead(release));
  ASSERT_OK(released);
  EXPECT_EQ(released->record.state, EcTreeReadState::Released);
  auto closed = blockingWait(metaClient_->closeEcFileSession(close));
  ASSERT_OK(closed);
  EXPECT_EQ(closed->session.state, EcFileSessionState::Closed);
  EXPECT_EQ(closed->session.activeReadRanges, 0);
  close.uuid = Uuid::random();
  close.session = open.session;
  auto writerClosed = blockingWait(metaClient_->closeEcFileSession(close));
  ASSERT_OK(writerClosed);
  EXPECT_EQ(writerClosed->session.state, EcFileSessionState::Closed);
  auto afterClose = request<QueryEcFilePwriteReq>();
  afterClose.object = second.object;
  afterClose.session = second.session;
  afterClose.operation = second.operation;
  afterClose.child = second.child;
  auto historical = blockingWait(metaClient_->queryEcFilePwrite(afterClose));
  ASSERT_OK(historical);
  ASSERT_TRUE(historical->progress.parent);
  EXPECT_EQ(historical->progress.parent->confirmedPrefix, patch.size());
  EXPECT_TRUE(historical->progress.outputDrained);
  EXPECT_TRUE(historical->progress.sourceReleased);
  auto oldOpen = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(oldOpen);
  EXPECT_EQ(oldOpen->session.state, EcFileSessionState::Closed);
  EXPECT_TRUE(oldOpen->object.deleting);
  ASSERT_OK(blockingWait(metaClient_->unlinkWithIdentity(removeAlias)));
  auto oldLink = blockingWait(metaClient_->hardLinkWithIdentity(link));
  ASSERT_OK(oldLink);
  EXPECT_EQ(oldLink->stat.nlink, 2);
  // Continue this same real Engine/FDB fixture through typed tree retirement
  // and G2. No metadata-only Data seam or caller receipt creates the claim.
  metaConfig_.set_enable_ec_revision_retirement(true);
  auto rootTxn = kv_->createReadWriteTransaction();
  core::UserStore users;
  auto rootAccount = blockingWait(users.getUser(*rootTxn, flat::Uid{0}));
  ASSERT_OK(rootAccount);
  ASSERT_TRUE(*rootAccount);
  UserInfo admin{(**rootAccount).uid, (**rootAccount).gid, (**rootAccount).token};
  rootTxn.reset();
  auto currentManifest = credentials->read->manifest;
  auto gc = request<CollectEcFragmentV2Req>();
  gc.user = admin;
  gc.object = created->object.object;
  gc.identity = currentManifest.fragments[0].identity;
  gc.claimId = Uuid::random();
  auto tooSoon = blockingWait(metaClient_->collectEcFragmentV2(gc));
  ASSERT_FALSE(tooSoon);
  auto step = request<AdvanceEcTreeReclaimReq>();
  step.user = admin;
  step.object = created->object.object;
  auto inspected = blockingWait(metaClient_->advanceEcTreeReclaim(step));
  ASSERT_OK(inspected);
  size_t reclaimedNodes = 0;
  while (!inspected->progress.next.is_nil() && reclaimedNodes < 64) {
    step.uuid = Uuid::random();
    step.node = inspected->progress.next;
    auto advanced = blockingWait(metaClient_->advanceEcTreeReclaim(step));
    ASSERT_OK(advanced);
    ASSERT_TRUE(advanced->progress.reclaimed);
    if (!reclaimedNodes) metaConfig_.set_readonly(true);
    auto repeated = blockingWait(metaClient_->advanceEcTreeReclaim(step));
    if (!reclaimedNodes) metaConfig_.set_readonly(false);
    ASSERT_OK(repeated);
    EXPECT_EQ(serde::serialize(advanced->progress), serde::serialize(repeated->progress));
    inspected = std::move(advanced);
    ++reclaimedNodes;
  }
  ASSERT_TRUE(inspected->progress.next.is_nil());
  EXPECT_GE(reclaimedNodes, 32);
  // Both revisions were actually published by the same accepted WRITE owner.
  for (const auto &child : {first, second}) {
    EcFileExecutionRecord original;
    {
      auto txn = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget t(*txn);
      auto execution = blockingWait(
          EcFileExecutionCatalog::get(t, EcOwner{user_.uid, metaClientId_.uuid}, created->object.object, child.child));
      ASSERT_OK(execution);
      original = execution->record;
    }
    ASSERT_TRUE(original.allocations);
    const auto revision = original.child.targetRevision;
    auto retire = request<RetireEcRevisionV2Req>();
    retire.user = admin;
    retire.object = created->object.object;
    retire.stripe = 0;
    retire.revision = revision;
    auto retired = blockingWait(metaClient_->retireEcRevisionV2(retire));
    ASSERT_OK(retired);
    EXPECT_TRUE(retired->referencesReleased);
    ASSERT_OK(blockingWait(metaClient_->retireEcRevisionV2(retire)));
    auto collect = request<CollectEcFragmentV2Req>();
    collect.user = admin;
    collect.object = created->object.object;
    collect.identity = (*original.allocations)[0].fragment.identity;
    collect.claimId = Uuid::random();
    auto result = blockingWait(metaClient_->collectEcFragmentV2(collect));
    ASSERT_OK(result);
    auto query = request<QueryEcFragmentGcV2Req>();
    query.user = admin;
    query.object = collect.object;
    query.identity = collect.identity;
    query.claimId = collect.claimId;
    auto confirmed = blockingWait(metaClient_->queryEcFragmentGcV2(query));
    ASSERT_OK(confirmed);
    EXPECT_EQ(confirmed->ledgerSha256, result->ledgerSha256);
    EXPECT_EQ(confirmed->terminalRevision, result->terminalRevision);
    auto wrong = collect;
    wrong.claimId = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->collectEcFragmentV2(wrong)), StatusCode::kTokenMismatch);
  }
  oldOpen = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(oldOpen);
  EXPECT_EQ(oldOpen->session.state, EcFileSessionState::Closed);
  EXPECT_TRUE(oldOpen->object.deleting);
  RecordProperty(
      "coverage",
      "private FDB + real Meta38-40/46-49/51-55/60 + Storage25/28-29/40-45/47-49; normal operation, not power loss");
}

TEST_F(TestEcFileNativeWrite, RenameMovesReplacesAndKeepsOpenObjectsWithPermanentReplay) {
  // The usual UUID-only cache is enabled deliberately: the mode4 permanent
  // request check must run before it, including after both old names disappear.
  metaConfig_.set_idempotent_rename(true);
  auto a = blockingWait(metaClient_->mkdirs(user_, parent_, Path("rename-a"), Permission{0700}, false));
  auto b = blockingWait(metaClient_->mkdirs(user_, parent_, Path("rename-b"), Permission{0700}, false));
  ASSERT_OK(a);
  ASSERT_OK(b);
  const auto count = [&](InodeId directory) {
    auto txn = kv_->createReadWriteTransaction();
    return blockingWait(EcNamespaceGuard::subtreeCount(*txn, directory));
  };
  const auto expectCounts = [&](uint64_t left, uint64_t right) {
    auto ca = count(a->id), cb = count(b->id), total = count(parent_);
    ASSERT_OK(ca);
    ASSERT_OK(cb);
    ASSERT_OK(total);
    EXPECT_EQ(*ca, left);
    EXPECT_EQ(*cb, right);
    EXPECT_EQ(*total, left + right);
  };
  auto open = request<OpenEcFileSessionReq>();
  open.createNew = true;
  open.path = PathAt(a->id, "source");
  open.shardBytes = kShardBytes;
  open.session = Uuid::random();
  open.rights = kEcSessionRead | kEcSessionWrite;
  open.perm = Permission{0600};
  auto source = blockingWait(metaClient_->openEcFileSession(open));
  ASSERT_OK(source);
  auto targetOpen = open;
  targetOpen.uuid = Uuid::random();
  targetOpen.session = Uuid::random();
  targetOpen.path = PathAt(b->id, "target");
  auto target = blockingWait(metaClient_->openEcFileSession(targetOpen));
  ASSERT_OK(target);
  AdvanceEcFilePwriteReq sourceWrite, targetWrite;
  const auto data = bytes(37, 23);
  ASSERT_NO_FATAL_FAILURE(writePatch(*source, 0, data, false, sourceWrite));
  ASSERT_NO_FATAL_FAILURE(expectCounts(1, 1));

  auto sameDirectory = request<RenameReq>();
  sameDirectory.src = open.path;
  sameDirectory.dest = PathAt(a->id, "renamed");
  sameDirectory.inodeId = source->object.object.inode;
  auto renamed = blockingWait(metaClient_->renameWithIdentity(sameDirectory));
  ASSERT_OK(renamed);
  ASSERT_TRUE(renamed->stat);
  EXPECT_EQ(renamed->stat->id, source->object.object.inode);
  EXPECT_EQ(renamed->stat->asFile().length, data.size());
  ASSERT_NO_FATAL_FAILURE(expectCounts(1, 1));
  auto crossDirectory = request<RenameReq>();
  crossDirectory.src = sameDirectory.dest;
  crossDirectory.dest = PathAt(b->id, "moved");
  crossDirectory.inodeId = source->object.object.inode;
  ASSERT_OK(blockingWait(metaClient_->renameWithIdentity(crossDirectory)));
  ASSERT_NO_FATAL_FAILURE(expectCounts(0, 2));
  auto replay = blockingWait(metaClient_->renameWithIdentity(sameDirectory));
  ASSERT_OK(replay);
  ASSERT_TRUE(replay->stat);
  EXPECT_EQ(replay->stat->id, source->object.object.inode);
  for (unsigned field = 0; field != 4; ++field) {
    auto changed = sameDirectory;
    if (field == 0) changed.src = PathAt(b->id, "moved");
    if (field == 1) changed.dest = PathAt(b->id, "different");
    if (field == 2) changed.moveToTrash = true;
    if (field == 3) changed.inodeId = target->object.object.inode;
    auto mismatch = blockingWait(metaClient_->renameWithIdentity(changed));
    ASSERT_FALSE(mismatch);
    EXPECT_EQ(mismatch.error().code(), StatusCode::kTokenMismatch);
  }
  auto link = request<HardLinkReq>();
  link.oldPath = crossDirectory.dest;
  link.newPath = PathAt(b->id, "alias");
  ASSERT_OK(blockingWait(metaClient_->hardLinkWithIdentity(link)));
  auto sameInode = request<RenameReq>();
  sameInode.src = link.oldPath;
  sameInode.dest = link.newPath;
  ASSERT_OK(blockingWait(metaClient_->renameWithIdentity(sameInode)));
  for (const auto *name : {"moved", "alias"}) {
    auto inode = blockingWait(metaClient_->stat(user_, b->id, Path(name), false));
    ASSERT_OK(inode);
    EXPECT_EQ(inode->id, source->object.object.inode);
    EXPECT_EQ(inode->nlink, 2);
  }
  ASSERT_NO_FATAL_FAILURE(expectCounts(0, 3));

  auto replace = request<RenameReq>();
  replace.src = crossDirectory.dest;
  replace.dest = targetOpen.path;
  replace.inodeId = source->object.object.inode;
  auto noReplace = replace;
  noReplace.uuid = Uuid::random();
  noReplace.moveToTrash = true;
  auto exists = blockingWait(metaClient_->renameWithIdentity(noReplace));
  ASSERT_FALSE(exists);
  EXPECT_EQ(exists.error().code(), MetaCode::kExists);
  ASSERT_NO_FATAL_FAILURE(alterInode(target->object.object, [](Inode &inode) { inode.acl.iflags |= FS_IMMUTABLE_FL; }));
  auto immutable = blockingWait(metaClient_->renameWithIdentity(replace));
  ASSERT_FALSE(immutable);
  EXPECT_EQ(immutable.error().code(), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(expectCounts(0, 3));
  ASSERT_NO_FATAL_FAILURE(
      alterInode(target->object.object, [](Inode &inode) { inode.acl.iflags &= ~FS_IMMUTABLE_FL; }));
  replace.uuid = Uuid::random();
  auto replaced = blockingWait(metaClient_->renameWithIdentity(replace));
  ASSERT_OK(replaced);
  ASSERT_TRUE(replaced->stat);
  EXPECT_EQ(replaced->stat->id, source->object.object.inode);
  EXPECT_EQ(replaced->stat->nlink, 2);
  ASSERT_NO_FATAL_FAILURE(expectCounts(0, 2));
  auto missing = blockingWait(metaClient_->stat(user_, b->id, Path("moved"), false));
  ASSERT_FALSE(missing);
  EXPECT_EQ(missing.error().code(), MetaCode::kNotFound);

  // The surviving name still resolves to the original published bytes.
  auto acquire = request<AcquireEcTreeReadReq>();
  acquire.intent.session = open.session;
  acquire.intent.request = Uuid::random();
  acquire.intent.range = Uuid::random();
  acquire.intent.selection.object = source->object.object;
  acquire.intent.selection.length = data.size();
  acquire.intent.selection.pinCount = 1;
  acquire.intent.selection.pins[0].stripe = 0;
  acquire.intent.selection.pins[0].pin = Uuid::random();
  ASSERT_OK(blockingWait(metaClient_->acquireEcTreeRead(acquire)));
  acquire.stripeIndex = 0;
  auto readable = blockingWait(metaClient_->acquireEcTreeRead(acquire));
  ASSERT_OK(readable);
  ASSERT_TRUE(readable->read);
  auto shard = readOne(*readable->read, 0);
  ASSERT_OK(shard);
  ASSERT_GE(shard->payload.data.size(), data.size());
  EXPECT_EQ(shard->payload.data.substr(0, data.size()), data);
  auto release = request<ReleaseEcTreeReadReq>();
  release.intent = acquire.intent;
  release.revocations[0] = Uuid::random();
  auto released = blockingWait(metaClient_->releaseEcTreeRead(release));
  ASSERT_OK(released);
  EXPECT_EQ(released->record.state, EcTreeReadState::Released);

  // Replacing the last target name does not invalidate its accepted session.
  // This is real worker compute/Seal/publication, not a metadata Data seam.
  ASSERT_NO_FATAL_FAILURE(writePatch(*target, 0, bytes(19, 51), false, targetWrite));
  auto closeTarget = request<CloseEcFileSessionReq>();
  closeTarget.object = target->object.object;
  closeTarget.session = targetOpen.session;
  auto targetClosed = blockingWait(metaClient_->closeEcFileSession(closeTarget));
  ASSERT_OK(targetClosed);
  EXPECT_EQ(targetClosed->session.state, EcFileSessionState::Closed);
  auto historicalOpen = blockingWait(metaClient_->openEcFileSession(targetOpen));
  ASSERT_OK(historicalOpen);
  EXPECT_TRUE(historicalOpen->object.deleting);
  EXPECT_EQ(historicalOpen->session.state, EcFileSessionState::Closed);
  auto replacementReplay = blockingWait(metaClient_->renameWithIdentity(replace));
  ASSERT_OK(replacementReplay);
  ASSERT_TRUE(replacementReplay->stat);
  EXPECT_EQ(replacementReplay->stat->id, source->object.object.inode);

  auto stolenId = request<RemoveReq>();
  stolenId.uuid = replace.uuid;
  stolenId.path = replace.dest;
  auto wrongAction = blockingWait(metaClient_->unlinkWithIdentity(stolenId));
  ASSERT_FALSE(wrongAction);
  EXPECT_EQ(wrongAction.error().code(), StatusCode::kTokenMismatch);
  for (const auto *name : {"target", "alias"}) {
    auto remove = request<RemoveReq>();
    remove.path = PathAt(b->id, name);
    remove.inodeId = source->object.object.inode;
    ASSERT_OK(blockingWait(metaClient_->unlinkWithIdentity(remove)));
  }
  auto closeSource = request<CloseEcFileSessionReq>();
  closeSource.object = source->object.object;
  closeSource.session = open.session;
  auto sourceClosed = blockingWait(metaClient_->closeEcFileSession(closeSource));
  ASSERT_OK(sourceClosed);
  EXPECT_EQ(sourceClosed->session.state, EcFileSessionState::Closed);
  ASSERT_NO_FATAL_FAILURE(expectCounts(0, 0));
  auto afterRetirement = blockingWait(metaClient_->renameWithIdentity(replace));
  ASSERT_OK(afterRetirement);
  ASSERT_TRUE(afterRetirement->stat);
  EXPECT_EQ(afterRetirement->stat->id, source->object.object.inode);
  EXPECT_EQ(afterRetirement->stat->nlink, 2);  // original result, not a resurrection
}
