// Real FDB transaction tests. Data fixtures assemble metadata through W0's
// existing private seam; they are not a production Data publication test.
using TreeReads = EcFileTreeReadCatalog;

// Match the production outer transaction: one Range ledger from the first
// catalog read through commit. Fixture::run remains W0 for tree-only work.
auto runTreeRead(Fixture &f, auto fn) {
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner, TreeReads::transactionProfile());
  auto result = blockingWait(fn(txn));
  f.lastUsage = txn.usage();
  if (result) {
    auto committed = blockingWait(txn.commit());
    if (!committed) return decltype(result)(makeError(std::move(committed.error())));
  }
  return result;
}

void uniqueTreeReadInode(Fixture &f) {
  uint64_t number = 0;
  for (size_t n = 0; n < 8; ++n) number = (number << 8) | f.birth.object.incarnation.data[n];
  f.birth.object.inode = InodeId((number & InodeId::normalMax().u64()) | 0x101);
}

Result<EcFileOpenIntent> openTreeRead(Fixture &f, uint8_t rights = kEcSessionRead) {
  EcFileOpenIntent opening;
  opening.object = f.birth.object;
  opening.birth = f.birth.createRequest;
  opening.owner = f.birth.creator;
  opening.session = Uuid::random();
  opening.openRequest = Uuid::random();
  opening.rights = rights;
  auto saved = f.run([&](Tx &txn) -> CoTryTask<Void> {
    auto prior = co_await Inode::load(txn, f.birth.object.inode);
    CO_RETURN_ON_ERROR(prior);
    if (!*prior) {
      auto ctx = co_await Tree::open(txn, f.birth.object);
      CO_RETURN_ON_ERROR(ctx);
      auto root = co_await Tree::getRoot(*ctx);
      CO_RETURN_ON_ERROR(root);
      EcManifestLayoutV1 ec;
      ec.incarnation = f.birth.object.incarnation;
      ec.shardBytes = f.birth.shardBytes;
      Layout layout{ChainTableId(0), ChainTableVersion(0), ec.shardBytes, 10, ec};
      auto inode = Inode::newFile(f.birth.object.inode,
                                  Acl(f.birth.creator.uid, flat::Gid(103), Permission(0600)),
                                  layout,
                                  UtcClock::now());
      inode.asFile().length = root->visibleLength;
      CO_RETURN_ON_ERROR(co_await inode.store(txn));
    } else if (!(**prior).isFile() || !(**prior).asFile().layout.ecLayout() ||
               (**prior).asFile().layout.ecLayout()->incarnation != f.birth.object.incarnation) {
      co_return makeError(StatusCode::kTokenDuplicated, "private test inode collided");
    }
    flat::UserInfo user(f.birth.creator.uid, flat::Gid(103));
    auto session = co_await EcFileSessionCatalog::open(txn, user, opening);
    CO_RETURN_ON_ERROR(session);
    co_return Void{};
  });
  RETURN_ON_ERROR(saved);
  return opening;
}

EcTreeReadIntent treeReadIntent(const Fixture &f, const EcFileOpenIntent &opening, uint64_t offset, uint64_t length) {
  EcTreeReadIntent i;
  i.owner = opening.owner;
  i.session = opening.session;
  i.request = Uuid::random();
  i.range = Uuid::random();
  i.selection.object = f.birth.object;
  i.selection.offset = offset;
  i.selection.length = length;
  const uint64_t stripeBytes = uint64_t(f.birth.shardBytes) * 10;
  i.selection.pinCount = length ? (offset + length - 1) / stripeBytes - offset / stripeBytes + 1 : 0;
  for (size_t n = 0; n < i.selection.pinCount; ++n)
    i.selection.pins[n] = EcRangePin{offset / stripeBytes + n, Uuid::random()};
  return i;
}

TEST_F(TestEcFileTree, RealFdbTreeReadRetainsZeroSnapshotAndSessionAfterLostAcquireReply) {
  Fixture f;
  uniqueTreeReadInode(f);
  ASSERT_OK(f.initialize(true));
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root, 2);
  edit.visibleLength = 1287;
  ASSERT_OK(f.apply(edit));
  auto opening = openTreeRead(f);
  ASSERT_OK(opening);
  const auto intent = treeReadIntent(f, *opening, 639, 700);
  auto inner = f.engine->createReadWriteTransaction();
  Tx txn(*inner, TreeReads::transactionProfile());
  auto acquired = blockingWait(TreeReads::acquire(txn, intent));
  ASSERT_OK(acquired);
  ASSERT_OK(blockingWait(txn.commit()));  // The test deliberately discards the application acknowledgement.
  EXPECT_EQ(acquired->readableLength, 648u);
  ASSERT_EQ(acquired->stripeCount, 3u);
  for (size_t n = 0; n < 3; ++n) {
    EXPECT_EQ(acquired->stripes[n].slot.kind, EcTreeSlotKind::Zero);
    EXPECT_EQ(acquired->stripes[n].slot.stripe, n);
    EXPECT_FALSE(acquired->stripes[n].snapshot);
  }
  auto replay = runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, intent); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*acquired, *replay));
  auto changed = intent;
  ++changed.selection.length;
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, changed); }), StatusCode::kTokenMismatch);
  auto writer = openTreeRead(f, kEcSessionWrite);
  ASSERT_OK(writer);
  auto forbidden = treeReadIntent(f, *writer, 0, 1);
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, forbidden); }), MetaCode::kNoPermission);
  auto closed =
      f.run([&](Tx &t) { return EcFileSessionCatalog::close(t, f.birth.object, opening->session, opening->owner); });
  ASSERT_OK(closed);
  EXPECT_EQ(closed->state, EcFileSessionState::Closing);
  EXPECT_EQ(closed->activeReadRanges, 1u);
  auto next = treeReadIntent(f, *opening, 0, 1);
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, next); }), StatusCode::kTokenStale);
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }));
  folly::test::TemporaryDirectory keys;
  const auto path = keys.path() / "control.key";
  {
    std::ofstream file(path.string(), std::ios::binary);
    file << std::string(32, 'r');
    ASSERT_TRUE(file.good());
  }
  ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
  auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(path.string()));
  ASSERT_OK(key);
  const auto authority = Uuid::random();
  const std::array<Uuid, 8> revocations{};
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::startClosing(t, intent, authority, revocations); }));
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, **key); }));
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, **key); }));
  closed = f.run([&](Tx &t) { return EcFileSessionCatalog::get(t, f.birth.object, opening->session, opening->owner); });
  ASSERT_OK(closed);
  EXPECT_EQ(closed->state, EcFileSessionState::Closed);
  EXPECT_EQ(closed->activeReadRanges, 0u);
}

TEST_F(TestEcFileTree, RealFdbTreeRangeClosingFencesIssuanceAndWaitsForAllActualStorageAcks) {
  Fixture f;
  uniqueTreeReadInode(f);
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  SourcePinTargetFixture target;
  ASSERT_NO_FATAL_FAILURE(target.initialize(*metadata));
  auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(slot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *slot;
  edit.visibleLength = 641;
  ASSERT_OK(f.apply(edit, true));
  auto opening = openTreeRead(f);
  ASSERT_OK(opening);
  auto intent = treeReadIntent(f, *opening, 0, 641);
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, intent); }));
  auto session =
      f.run([&](Tx &t) { return EcFileSessionCatalog::close(t, f.birth.object, opening->session, opening->owner); });
  ASSERT_OK(session);
  EXPECT_EQ(session->state, EcFileSessionState::Closing);
  auto inner = f.engine->createReadWriteTransaction();
  Tx issuing(*inner, TreeReads::transactionProfile());
  ASSERT_OK(blockingWait(TreeReads::reserveRead(issuing, intent, 0)));
  std::array<Uuid, 8> revocations{};
  revocations[0] = Uuid::random();
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::startClosing(t, intent, target.authority, revocations); }));
  ASSERT_ERROR(blockingWait(issuing.commit()), TransactionCode::kConflict);
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::reserveRead(t, intent, 0); }), StatusCode::kTokenStale);
  auto drain = runTreeRead(f, [&](Tx &t) { return TreeReads::closingSource(t, intent, 0); });
  ASSERT_OK(drain);
  for (size_t n = 0; n < 12; ++n) {
    if (n == 11)
      ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }),
                   StatusCode::kTokenStale);
    auto request =
        EcV2DrainCatalog::makeRequest(*drain, n, storage::EcScopeControlAction::Revoke, *target.key, 1700000000);
    ASSERT_OK(request);
    auto ack =
        blockingWait(target.control->execute(storage::EcScopeControlAction::Revoke, *request, target.physical[n]));
    ASSERT_OK(ack);
    auto evidence = EcVerifiedDrainAck::verify(*target.key, *drain, n, *request, *ack);
    ASSERT_OK(evidence);
    ASSERT_OK(
        runTreeRead(f, [&](Tx &t) { return TreeReads::recordVerifiedAck(t, intent, 0, *target.key, *evidence); }));
  }
  auto released = runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); });
  ASSERT_OK(released);
  EXPECT_EQ(released->state, EcTreeReadState::Released);
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }));
  session =
      f.run([&](Tx &t) { return EcFileSessionCatalog::get(t, f.birth.object, opening->session, opening->owner); });
  ASSERT_OK(session);
  EXPECT_EQ(session->state, EcFileSessionState::Closed);
  EXPECT_EQ(session->activeReadRanges, 0u);
  auto history = f.run([&](Tx &t) { return EcCatalog::getManifest(t, f.birth.object, 0, slot->revision); });
  ASSERT_OK(history);
  EXPECT_EQ(history->pins, 0u);
}

TEST_F(TestEcFileTree, RealFdbEightDataRangeFitsExplicitMeasuredTransactionBudget) {
  struct Shape {
    uint32_t shardBytes;
    uint16_t stripes;
    uint64_t offset;
    uint64_t length;
  };
  // Eight fixed descriptor tables are the maximum record count. At 1 MiB
  // shards, a legal 32 MiB window can intersect at most five Data stripes.
  const std::array<Shape, 2> shapes{{
      {384u << 10, 8, 0, uint64_t(384u << 10) * 10 * 8},
      {1u << 20, 5, 9u << 20, 32u << 20},
  }};
  for (const auto &shape : shapes) {
    SCOPED_TRACE(fmt::format("shardBytes={} stripes={}", shape.shardBytes, shape.stripes));
    Fixture f;
    uniqueTreeReadInode(f);
    f.birth.shardBytes = shape.shardBytes;
    ASSERT_OK(f.initialize(true));
    SourcePinTargetFixture target;
    EcV2AllocationBindings physical;
    for (size_t n = 0; n < shape.stripes; ++n) {
      auto metadata = f.metadata(n);
      ASSERT_OK(metadata);
      ASSERT_EQ(metadata->manifest.fragments[0].integrity.blockCount,
                shape.shardBytes / storage::kEcIntegrityBlockBytes);
      if (!n) {
        ASSERT_NO_FATAL_FAILURE(target.initialize(*metadata));
        physical = metadata->allocations;
      } else {
        for (size_t shard = 0; shard < 12; ++shard) {
          metadata->allocations[shard].engineUuid = physical[shard].engineUuid;
          metadata->allocations[shard].targetIncarnation = physical[shard].targetIncarnation;
        }
      }
      auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
      ASSERT_OK(slot);
      auto root = f.root();
      ASSERT_OK(root);
      auto edit = f.edit(*root, n);
      edit.replacement = *slot;
      edit.visibleLength = uint64_t(n) * f.birth.shardBytes * 10 + slot->logicalLength;
      ASSERT_OK(f.apply(edit, true));
    }
    auto opening = openTreeRead(f);
    ASSERT_OK(opening);
    auto intent = treeReadIntent(f, *opening, shape.offset, shape.length);
    size_t maximumBytes = 0, maximumKeys = 0, maximumMutationAndConflictBytes = 0;
    auto remember = [&] {
      maximumBytes = std::max(maximumBytes, f.lastUsage.totalBytes());
      maximumKeys = std::max(maximumKeys, f.lastUsage.keyOperations);
      maximumMutationAndConflictBytes =
          std::max(maximumMutationAndConflictBytes, f.lastUsage.mutationAndConflictBytes());
      EXPECT_LE(f.lastUsage.totalBytes(), 2u << 20);
      EXPECT_LE(f.lastUsage.keyOperations, 8192u);
    };

    if (shape.stripes == 8) {
      // Real reads spend the ledger before Acquire; no hidden smaller profile
      // or counter reset. Failure occurs after actual pin mutations were staged.
      const auto paddingKey = std::string("EC-TREE-READ-BUDGET-TEST/") + Uuid::random().toHexString();
      const std::string padding(64u << 10, 'b');
      ASSERT_OK(f.run([&](Tx &t) { return t.set(paddingKey, padding); }));
      {
        auto inner = f.engine->createReadWriteTransaction();
        Tx txn(*inner, TreeReads::transactionProfile());
        for (size_t n = 0; n < 29; ++n) ASSERT_OK(blockingWait(txn.get(paddingKey)));
        auto exhausted = blockingWait(TreeReads::acquire(txn, intent));
        ASSERT_ERROR(exhausted, StatusCode::kInvalidArg);
        EXPECT_TRUE(txn.poisoned());
        EXPECT_GT(txn.usage().mutationBytes, 0u);
        // Test-only raw read inspects uncommitted RYW after the ledger is
        // poisoned. It never commits or bypasses a production budget gate.
        const auto firstPin = idKey(kv::KeyPrefix::EcTreeSourcePin, f.birth.object, intent.selection.pins[0].pin);
        auto staged = blockingWait(inner->get(firstPin));
        ASSERT_OK(staged);
        ASSERT_TRUE(*staged);
        ASSERT_ERROR(blockingWait(txn.commit()), StatusCode::kInvalidArg);
      }
      ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
        auto range = co_await t.get(idKey(kv::KeyPrefix::EcFileTreeReadRange, f.birth.object, intent.range));
        CO_RETURN_ON_ERROR(range);
        auto request = co_await t.get(idKey(kv::KeyPrefix::EcFileTreeReadRequest, f.birth.object, intent.request));
        CO_RETURN_ON_ERROR(request);
        if (*range || *request) co_return makeError(StatusCode::kDataCorruption);
        for (size_t n = 0; n < intent.selection.pinCount; ++n) {
          auto source =
              co_await t.get(idKey(kv::KeyPrefix::EcTreeSourcePin, f.birth.object, intent.selection.pins[n].pin));
          CO_RETURN_ON_ERROR(source);
          if (*source) co_return makeError(StatusCode::kDataCorruption);
          auto m = co_await EcCatalog::getManifest(t, f.birth.object, n, 1);
          CO_RETURN_ON_ERROR(m);
          if (m->pins) co_return makeError(StatusCode::kDataCorruption);
          for (const auto &fragment : m->manifest.fragments) {
            auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, fragment.identity);
            CO_RETURN_ON_ERROR(key);
            auto allocation = co_await t.get(*key);
            CO_RETURN_ON_ERROR(allocation);
            if (*allocation) co_return makeError(StatusCode::kDataCorruption);
          }
        }
        auto session = co_await EcFileSessionCatalog::get(t, f.birth.object, opening->session, opening->owner);
        CO_RETURN_ON_ERROR(session);
        if (session->activeReadRanges) co_return makeError(StatusCode::kDataCorruption);
        co_return Void{};
      }));
    }

    auto acquired = runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, intent); });
    ASSERT_OK(acquired);
    ASSERT_EQ(acquired->stripeCount, shape.stripes);
    remember();
    EXPECT_GT(f.lastUsage.totalBytes(), 256u << 10);
    auto replay = runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, intent); });
    ASSERT_OK(replay);
    EXPECT_TRUE(same(*acquired, *replay));
    remember();
    ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }));
    remember();
    // Match RPC53's query + issuance in a single outer transaction.
    ASSERT_OK(runTreeRead(f, [&](Tx &t) -> CoTryTask<Void> {
      CO_RETURN_ON_ERROR(co_await TreeReads::query(t, intent));
      CO_RETURN_ON_ERROR(co_await TreeReads::reserveRead(t, intent, 0));
      co_return Void{};
    }));
    remember();
    std::array<Uuid, 8> revocations{};
    for (size_t n = 0; n < shape.stripes; ++n) revocations[n] = Uuid::random();
    ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::startClosing(t, intent, target.authority, revocations); }));
    remember();
    for (size_t n = 0; n < shape.stripes; ++n) {
      auto drain = runTreeRead(f, [&](Tx &t) { return TreeReads::closingSource(t, intent, n); });
      ASSERT_OK(drain);
      remember();
      for (size_t endpoint = 0; endpoint < 12; ++endpoint) {
        if (n + 1 == shape.stripes && endpoint == 11)
          ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }),
                       StatusCode::kTokenStale);
        auto request = EcV2DrainCatalog::makeRequest(*drain,
                                                     endpoint,
                                                     storage::EcScopeControlAction::Revoke,
                                                     *target.key,
                                                     1700000000);
        ASSERT_OK(request);
        auto ack = blockingWait(
            target.control->execute(storage::EcScopeControlAction::Revoke, *request, target.physical[endpoint]));
        ASSERT_OK(ack);
        auto evidence = EcVerifiedDrainAck::verify(*target.key, *drain, endpoint, *request, *ack);
        ASSERT_OK(evidence);
        ASSERT_OK(
            runTreeRead(f, [&](Tx &t) { return TreeReads::recordVerifiedAck(t, intent, n, *target.key, *evidence); }));
        remember();
      }
    }
    auto released = runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); });
    ASSERT_OK(released);
    EXPECT_EQ(released->state, EcTreeReadState::Released);
    remember();
    ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }));
    remember();
    ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }));
    remember();
    for (const auto &entry : acquired->stripes) {
      if (entry.slot.kind != EcTreeSlotKind::Data) continue;
      auto manifest = f.run(
          [&](Tx &t) { return EcCatalog::getManifest(t, f.birth.object, entry.slot.stripe, entry.slot.revision); });
      ASSERT_OK(manifest);
      EXPECT_EQ(manifest->pins, 0u);
      for (const auto &fragment : manifest->manifest.fragments) {
        auto count = f.run([&](Tx &t) -> CoTryTask<EcTreeSourceAllocationRecord> {
          auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, fragment.identity);
          CO_RETURN_ON_ERROR(key);
          co_return co_await require<EcTreeSourceAllocationRecord>(t, *key);
        });
        ASSERT_OK(count);
        EXPECT_EQ(count->registered, 1u);
        EXPECT_EQ(count->released, 1u);
        EXPECT_EQ(count->active, 0u);
      }
    }
    const auto label = std::to_string(shape.stripes);
    RecordProperty("tree_read_" + label + "_data_max_key_value_conflict_bytes", std::to_string(maximumBytes));
    RecordProperty("tree_read_" + label + "_data_max_key_operations", std::to_string(maximumKeys));
    RecordProperty("tree_read_" + label + "_data_max_mutation_and_conflict_bytes",
                   std::to_string(maximumMutationAndConflictBytes));
  }
}
