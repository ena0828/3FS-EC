// Reuses W0's explicitly metadata-only seam. Real FDB and local persistent
// target scope controls below do not claim a production mode4 Data publication.
using SourcePins = EcTreeSourcePinCatalog;
static_assert(!std::is_default_constructible_v<EcTreeSourcePinEvidence>);
static_assert(!std::is_constructible_v<EcTreeSourcePinEvidence, EcTreeSourcePinRecord>);
EcTreeSourcePinIntent sourceIntent(const Fixture &f, const EcTreeRoot &root, const EcTreeSlot &slot) {
  EcTreeSourcePinIntent i;
  i.object = f.birth.object;
  i.owner = f.birth.creator;
  i.session = Uuid::random();
  i.parent = Uuid::random();
  i.child = Uuid::random();
  i.pin = Uuid::random();
  i.root = root.root;
  i.sequence = root.sequence;
  i.epoch = root.epoch;
  i.lengthAtPlan = root.visibleLength;
  i.slot = slot;
  return i;
}
TEST_F(TestEcFileTree, RealFdbSourcePinKeepsExactHistoryAndConflictsWithClosing) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = slot->logicalLength;
  ASSERT_OK(f.apply(edit, true));
  root = f.root();
  ASSERT_OK(root);
  const auto intent = sourceIntent(f, *root, *slot);
  auto pin = f.run([&](Tx &t) { return SourcePins::pinExactSource(t, intent); });
  ASSERT_OK(pin);
  ASSERT_OK(f.run([&](Tx &t) { return SourcePins::pinExactSource(t, intent); }));
  auto historical = f.run([&](Tx &t) { return EcCatalog::getManifest(t, f.birth.object, 0, slot->revision); });
  ASSERT_OK(historical);
  EXPECT_EQ(historical->pins, 1);
  auto changed = intent;
  changed.owner.client = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::query(t, changed); }), MetaCode::kNoPermission);
  changed = intent;
  changed.child = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::pinExactSource(t, changed); }), StatusCode::kTokenMismatch);
  auto zero = f.edit(*root);
  ASSERT_OK(f.apply(zero));
  for (int level = 15; level >= 0; --level) ASSERT_OK(f.reclaim(edit.nodeIds[level]));
  ASSERT_OK(f.run([&](Tx &t) { return SourcePins::query(t, intent); }));
  const auto identity = metadata->manifest.fragments[0].identity;
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileTreeGcGuard::requireUnheld(t, f.birth.object, identity); }),
               StatusCode::kTokenStale);
  auto ia = f.engine->createReadWriteTransaction(), ib = f.engine->createReadWriteTransaction();
  Tx issue(*ia), close(*ib);
  ASSERT_OK(blockingWait(SourcePins::reserveIssuance(issue, intent)));
  const auto authority = Uuid::random(), revocation = Uuid::random();
  ASSERT_OK(blockingWait(SourcePins::startClosing(close, intent, authority, revocation)));
  ASSERT_OK(blockingWait(close.commit()));
  ASSERT_ERROR(blockingWait(issue.commit()), TransactionCode::kConflict);
  ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::reserveIssuance(t, intent); }), StatusCode::kTokenStale);
  ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::pinExactSource(t, intent); }), StatusCode::kTokenStale);
  // Cleanup observation remains available after the object becomes deleting.
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto object = co_await EcCatalog::getObject(t, f.birth.object);
    CO_RETURN_ON_ERROR(object);
    object->deleting = true;
    co_return co_await store(t, objectKey(kv::KeyPrefix::EcObject, f.birth.object), *object);
  }));
  auto closed = f.run([&](Tx &t) { return SourcePins::query(t, intent); });
  ASSERT_OK(closed);
  EXPECT_EQ(closed->state, EcTreeSourcePinState::Closing);
  EXPECT_EQ(closed->issuanceSequence, 0);
}

struct SourcePinTargetFixture {
  folly::test::TemporaryDirectory disk, keys;
  storage::StorageTargets::Config config;
  storage::AtomicallyTargetMap map;
  CPUExecutorGroup cpu{1, "TreeSourcePinTest"};
  std::unique_ptr<storage::StorageTargets> targets;
  std::array<std::shared_ptr<storage::StorageTarget>, 12> physical;
  std::shared_ptr<const storage::EcScopeControlKey> key;
  std::unique_ptr<storage::EcScopeControlExecutor> control;
  Uuid authority = Uuid::random();
  ~SourcePinTargetFixture() {
    control.reset();
    for (auto &p : physical) p.reset();
    map.release().reset();
    targets.reset();
  }
  void initialize(detail::EcTreeTestMetadata &metadata) {
    const auto path = keys.path() / "control.key";
    std::ofstream file(path.string(), std::ios::binary);
    const std::string raw(32, 'k');
    file.write(raw.data(), raw.size());
    file.close();
    ASSERT_TRUE(file.good());
    ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
    auto loaded = storage::EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
    ASSERT_OK(loaded);
    key = std::shared_ptr<const storage::EcScopeControlKey>(std::move(*loaded));
    config.set_target_paths({disk.path()});
    config.set_allow_disk_without_uuid(true);
    config.set_ec_only(true);
    config.set_ec_staging_v2(true);
    targets = std::make_unique<storage::StorageTargets>(config, map);
    ASSERT_OK(targets->load(cpu));
    for (size_t i = 0; i < 12; ++i) {
      storage::CreateTargetReq request;
      request.chainId = storage::ChainId(100 + i);
      request.targetId = storage::TargetId(200 + i);
      request.onlyChunkEngine = true;
      ASSERT_OK(targets->create(request, true));
      auto found = map.getByTargetId(request.targetId);
      ASSERT_OK(found);
      physical[i] = (*found)->storageTarget;
      auto state = physical[i]->ecScopeState();
      ASSERT_OK(state);
      std::copy(state->second.engine.begin(),
                state->second.engine.end(),
                std::begin(metadata.allocations[i].engineUuid.data));
      std::copy(state->second.incarnation.begin(),
                state->second.incarnation.end(),
                std::begin(metadata.allocations[i].targetIncarnation.data));
    }
    auto executor =
        storage::EcScopeControlExecutor::create(key, authority, flat::NodeId(9), [] { return uint64_t{1700000001}; });
    ASSERT_OK(executor);
    control = std::move(*executor);
  }
};
TEST_F(TestEcFileTree, RealFdbSourcePinT2RequiresTwelveRealLocalAcksAndReplaysOnce) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  SourcePinTargetFixture targetFixture;
  ASSERT_NO_FATAL_FAILURE(targetFixture.initialize(*metadata));
  auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = slot->logicalLength;
  ASSERT_OK(f.apply(edit, true));
  root = f.root();
  ASSERT_OK(root);
  const auto intent = sourceIntent(f, *root, *slot);
  ASSERT_OK(f.run([&](Tx &t) { return SourcePins::pinExactSource(t, intent); }));
  const auto revocation = Uuid::random();
  auto closing = f.run([&](Tx &t) { return SourcePins::startClosing(t, intent, targetFixture.authority, revocation); });
  ASSERT_OK(closing);
  for (size_t i = 0; i < 12; ++i) {
    if (i == 11)
      ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::finishRelease(t, intent, *targetFixture.key); }),
                   StatusCode::kTokenStale);
    auto request = EcV2DrainCatalog::makeRequest(*closing,
                                                 i,
                                                 storage::EcScopeControlAction::Revoke,
                                                 *targetFixture.key,
                                                 1700000000);
    ASSERT_OK(request);
    auto ack = blockingWait(
        targetFixture.control->execute(storage::EcScopeControlAction::Revoke, *request, targetFixture.physical[i]));
    ASSERT_OK(ack);
    ASSERT_OK(f.run([&](Tx &t) { return SourcePins::recordAck(t, intent, i, *targetFixture.key, *request, *ack); }));
  }
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner);
  auto terminal = blockingWait(SourcePins::finishRelease(txn, intent, *targetFixture.key));
  ASSERT_OK(terminal);
  auto lost = [&]() -> CoTryTask<Void> {
    CO_RETURN_ON_ERROR(co_await txn.commit());
    co_return makeError(TransactionCode::kMaybeCommitted, "discard actual source T2 acknowledgement");
  };
  ASSERT_ERROR(blockingWait(lost()), TransactionCode::kMaybeCommitted);
  auto repeated = f.run([&](Tx &t) { return SourcePins::finishRelease(t, intent, *targetFixture.key); });
  ASSERT_OK(repeated);
  EXPECT_TRUE(same(*terminal, *repeated));
  EXPECT_EQ(repeated->state, EcTreeSourcePinState::Released);
  ASSERT_ERROR(f.run([&](Tx &t) { return SourcePins::reserveIssuance(t, intent); }), StatusCode::kTokenStale);
  auto m = f.run([&](Tx &t) { return EcCatalog::getManifest(t, f.birth.object, 0, slot->revision); });
  ASSERT_OK(m);
  EXPECT_EQ(m->pins, 0);
  EXPECT_FALSE(m->referencesReleased);
  for (const auto &a : metadata->allocations) {
    auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, a.fragment.identity);
    ASSERT_OK(key);
    auto count = f.run([&](Tx &t) { return require<EcTreeSourceAllocationRecord>(t, *key); });
    ASSERT_OK(count);
    EXPECT_EQ(count->registered, 1);
    EXPECT_EQ(count->released, 1);
    EXPECT_EQ(count->active, 0);
    ASSERT_OK(f.run([&](Tx &t) { return SourcePins::requireUnheld(t, f.birth.object, a.fragment.identity); }));
    // Live Data leaf still retains its independent tree hold after source T2.
    ASSERT_ERROR(f.run([&](Tx &t) { return EcFileTreeGcGuard::requireUnheld(t, f.birth.object, a.fragment.identity); }),
                 StatusCode::kTokenStale);
  }
}
