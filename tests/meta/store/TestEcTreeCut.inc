// Tree-layer fixtures only. Their metadata-only Data seam does not construct
// EcRmwPublicationProof and cannot substitute for the real W1/W2 verifier.
EcTreeCut cutIntent(const Fixture &f, const EcTreeRoot &root, uint64_t length) {
  EcTreeCut cut;
  cut.object = f.birth.object;
  cut.operation = Uuid::random();
  cut.expected = root;
  cut.length = length;
  for (auto &id : cut.nodeIds) id = Uuid::random();
  return cut;
}
Result<EcTreeRoot> applyCut(Fixture &f, const EcTreeCut &cut) {
  return f.run([&](Tx &t) -> CoTryTask<EcTreeRoot> {
    auto c = co_await Tree::open(t, f.birth.object);
    CO_RETURN_ON_ERROR(c);
    co_return co_await detail::EcFileTreeTestAccess::cut(*c, cut);
  });
}
Result<EcTreeSlot> cutLookup(Fixture &f, uint64_t stripe) {
  return f.run([&](Tx &t) -> CoTryTask<EcTreeSlot> {
    auto c = co_await Tree::open(t, f.birth.object);
    CO_RETURN_ON_ERROR(c);
    co_return co_await Tree::lookup(*c, stripe);
  });
}
TEST_F(TestEcFileTree, RealFdbCutPrunesWholeSuffixAndExtensionCannotResurrectIt) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  const uint64_t far = uint64_t{1} << 40;
  for (uint64_t stripe : {uint64_t{0}, uint64_t{15}, uint64_t{16}, far}) {
    auto metadata = f.metadata(stripe);
    ASSERT_OK(metadata);
    auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
    ASSERT_OK(slot);
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root, stripe);
    edit.replacement = *slot;
    edit.visibleLength = stripe * 640 + slot->logicalLength;
    ASSERT_OK(f.apply(edit, true));
  }
  auto old = f.root();
  ASSERT_OK(old);
  auto cut = cutIntent(f, *old, 16 * 640);
  auto result = applyCut(f, cut);
  ASSERT_OK(result);
  EXPECT_EQ(result->visibleLength, 16 * 640);
  for (uint64_t stripe : {uint64_t{0}, uint64_t{15}}) {
    auto value = cutLookup(f, stripe);
    ASSERT_OK(value);
    EXPECT_EQ(value->kind, EcTreeSlotKind::Data);
  }
  for (uint64_t stripe : {uint64_t{16}, far}) {
    auto value = cutLookup(f, stripe);
    ASSERT_OK(value);
    EXPECT_EQ(value->kind, EcTreeSlotKind::Zero);
  }
  auto extended = applyCut(f, cutIntent(f, *result, old->visibleLength));
  ASSERT_OK(extended);
  EXPECT_EQ(extended->root, result->root);
  for (uint64_t stripe : {uint64_t{16}, far}) {
    auto value = cutLookup(f, stripe);
    ASSERT_OK(value);
    EXPECT_EQ(value->kind, EcTreeSlotKind::Zero);
  }
  // Existing reclamation consumes one <=16-edge node at a time. Removed
  // subtree holds survive until those actual queue entries are processed.
  bool empty = false;
  for (size_t step = 0; step < 256; ++step) {
    auto work = f.run([&](Tx &t) -> CoTryTask<std::optional<EcTreeReclaimWork>> {
      const auto first = objectKey(kv::KeyPrefix::EcTreeReclaim, f.birth.object);
      auto rows = co_await t.getRange({first, true}, {kv::TransactionHelper::prefixListEndKey(first), false}, 1);
      CO_RETURN_ON_ERROR(rows);
      if (rows->kvs.empty()) co_return std::nullopt;
      EcTreeReclaimWork w;
      CO_RETURN_ON_ERROR(serde::deserialize(w, rows->kvs.front().value));
      co_return w;
    });
    ASSERT_OK(work);
    if (!*work) {
      empty = true;
      break;
    }
    ASSERT_OK(f.reclaim((**work).node));
  }
  ASSERT_TRUE(empty);
  for (uint64_t stripe : {uint64_t{16}, far}) {
    auto hold = f.run([&](Tx &t) {
      return require<EcTreeManifestHolds>(t, manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, stripe, 1));
    });
    ASSERT_OK(hold);
    EXPECT_EQ(hold->treeHolds, 0);
  }
}
TEST_F(TestEcFileTree, RealFdbCutPartialTailRequiresNewContentAndConflictsWithWrite) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  auto oldSlot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
  ASSERT_OK(oldSlot);
  auto root = f.root();
  ASSERT_OK(root);
  auto edit = f.edit(*root);
  edit.replacement = *oldSlot;
  edit.visibleLength = 37;
  ASSERT_OK(f.apply(edit, true));
  root = f.root();
  ASSERT_OK(root);
  auto cut = cutIntent(f, *root, 10);
  ASSERT_ERROR(applyCut(f, cut), StatusCode::kInvalidArg);
  auto unchanged = f.root();
  ASSERT_OK(unchanged);
  EXPECT_TRUE(same(*root, *unchanged));
  auto next = *metadata;
  next.manifest.revision = 2;
  next.manifest.generation = 2;
  next.manifest.logicalLength = 10;
  auto shards = storage::EcCodec::encode(std::string(10, 'k'), 64);
  ASSERT_OK(shards);
  std::array<std::string_view, 10> views;
  for (size_t i = 0; i < 10; ++i) views[i] = (*shards)[i];
  auto hash = computeEcLogicalSha256(views, 10);
  ASSERT_OK(hash);
  next.contentSha256 = *hash;
  for (size_t i = 0; i < 12; ++i) {
    auto &fragment = next.manifest.fragments[i];
    fragment.identity.generation = 2;
    fragment.identity.allocation = Uuid::random();
    fragment.operation = Uuid::random();
    auto integrity = storage::computeEcIntegrity(fragment.identity, (*shards)[i]);
    ASSERT_OK(integrity);
    fragment.integrity = *integrity;
    next.allocations[i].fragment = fragment;
  }
  auto newSlot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, next); });
  ASSERT_OK(newSlot);
  cut.tail = *newSlot;
  auto inner = f.engine->createReadWriteTransaction();
  Tx pending(*inner);
  auto context = blockingWait(Tree::open(pending, f.birth.object));
  ASSERT_OK(context);
  ASSERT_OK(blockingWait(detail::EcFileTreeTestAccess::cut(*context, cut)));
  auto competing = f.edit(*root, 1);
  competing.visibleLength = 700;
  ASSERT_OK(f.apply(competing));
  ASSERT_ERROR(blockingWait(pending.commit()), TransactionCode::kConflict);
  root = f.root();
  ASSERT_OK(root);
  cut = cutIntent(f, *root, 10);
  cut.tail = *newSlot;
  auto shortened = applyCut(f, cut);
  ASSERT_OK(shortened);
  auto extended = applyCut(f, cutIntent(f, *shortened, 700));
  ASSERT_OK(extended);
  auto value = cutLookup(f, 0);
  ASSERT_OK(value);
  EXPECT_EQ(value->logicalLength, 10);
  EXPECT_EQ(value->contentSha256, *hash);
  value = cutLookup(f, 1);
  ASSERT_OK(value);
  EXPECT_EQ(value->kind, EcTreeSlotKind::Zero);

  // This prior tail remains held by its historical leaf. Replacing it with
  // the longer old revision makes a positive-hold tail valid for a new cut.
  root = f.root();
  ASSERT_OK(root);
  auto restore = f.edit(*root);
  restore.replacement = *oldSlot;
  ASSERT_OK(f.apply(restore, true));
  root = f.root();
  ASSERT_OK(root);
  const auto holdsKey = manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, 0, newSlot->revision);
  auto held = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, holdsKey); });
  ASSERT_OK(held);
  ASSERT_GT(held->treeHolds, 0);
  const auto bindingKey = allocationKey(kv::KeyPrefix::EcV2Allocation, next.allocations[0].fragment.identity);
  ASSERT_OK(bindingKey);
  auto changedBinding = next.allocations[0];
  changedBinding.writer.client = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return store(t, *bindingKey, changedBinding); }));
  auto heldCut = cutIntent(f, *root, 10);
  heldCut.tail = *newSlot;
  ASSERT_ERROR(applyCut(f, heldCut), StatusCode::kDataCorruption);
  auto rejectedRoot = f.root();
  ASSERT_OK(rejectedRoot);
  EXPECT_TRUE(same(*root, *rejectedRoot));
  auto rejectedHolds = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, holdsKey); });
  ASSERT_OK(rejectedHolds);
  EXPECT_TRUE(same(*held, *rejectedHolds));
  ASSERT_OK(f.run([&](Tx &t) { return store(t, *bindingKey, next.allocations[0]); }));
  ASSERT_OK(applyCut(f, heldCut));
}

TEST_F(TestEcFileTree, RealFdbFreshTailFailureDoesNotCommitEarlierCopiedSlotHolds) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB required";
  Fixture f;
  ASSERT_OK(f.initialize(true));
  for (uint64_t stripe : {uint64_t{0}, uint64_t{1}}) {
    auto metadata = f.metadata(stripe);
    ASSERT_OK(metadata);
    auto slot = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *metadata); });
    ASSERT_OK(slot);
    auto root = f.root();
    ASSERT_OK(root);
    auto edit = f.edit(*root, stripe);
    edit.replacement = *slot;
    edit.visibleLength = stripe * 640 + 37;
    ASSERT_OK(f.apply(edit, true));
  }
  auto next = f.metadata(1);
  ASSERT_OK(next);
  next->manifest.revision = 2;
  next->manifest.generation = 2;
  next->manifest.logicalLength = 10;
  auto shards = storage::EcCodec::encode(std::string(10, 'k'), 64);
  ASSERT_OK(shards);
  std::array<std::string_view, 10> views;
  for (size_t i = 0; i < 10; ++i) views[i] = (*shards)[i];
  auto hash = computeEcLogicalSha256(views, 10);
  ASSERT_OK(hash);
  next->contentSha256 = *hash;
  for (size_t i = 0; i < 12; ++i) {
    auto &fragment = next->manifest.fragments[i];
    fragment.identity.generation = 2;
    auto integrity = storage::computeEcIntegrity(fragment.identity, (*shards)[i]);
    ASSERT_OK(integrity);
    fragment.integrity = *integrity;
    next->allocations[i].fragment = fragment;
  }
  auto tail = f.run([&](Tx &t) { return detail::EcFileTreeTestAccess::assemble(t, f.birth, *next); });
  ASSERT_OK(tail);
  auto root = f.root();
  ASSERT_OK(root);
  const auto firstKey = manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, 0, 1);
  const auto tailKey = manifestKey(kv::KeyPrefix::EcTreeManifest, f.birth.object, 1, 2);
  auto first = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, firstKey); });
  auto fresh = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, tailKey); });
  ASSERT_OK(first);
  ASSERT_OK(fresh);
  ASSERT_GT(first->treeHolds, 0);
  ASSERT_EQ(fresh->treeHolds, 0);
  const auto bindingKey = allocationKey(kv::KeyPrefix::EcV2Allocation, next->allocations[0].fragment.identity);
  ASSERT_OK(bindingKey);
  auto changedBinding = next->allocations[0];
  changedBinding.writer.client = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return store(t, *bindingKey, changedBinding); }));
  auto cut = cutIntent(f, *root, 640 + 10);
  cut.tail = *tail;
  {
    auto raw = f.engine->createReadWriteTransaction();
    Tx pending(*raw);
    auto context = blockingWait(Tree::open(pending, f.birth.object));
    ASSERT_OK(context);
    ASSERT_ERROR(blockingWait(detail::EcFileTreeTestAccess::cut(*context, cut)), StatusCode::kDataCorruption);
    auto stagedFirst = blockingWait(require<EcTreeManifestHolds>(pending, firstKey));
    ASSERT_OK(stagedFirst);
    EXPECT_EQ(stagedFirst->treeHolds, first->treeHolds + 1);
    // A semantic error does not itself poison the transaction. Deliberately
    // discard it without commit, including slot zero's actual staged hold.
  }
  auto afterRoot = f.root();
  auto afterFirst = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, firstKey); });
  auto afterTail = f.run([&](Tx &t) { return require<EcTreeManifestHolds>(t, tailKey); });
  ASSERT_OK(afterRoot);
  ASSERT_OK(afterFirst);
  ASSERT_OK(afterTail);
  EXPECT_TRUE(same(*root, *afterRoot));
  EXPECT_TRUE(same(*first, *afterFirst));
  EXPECT_TRUE(same(*fresh, *afterTail));
  ASSERT_OK(f.run([&](Tx &t) { return store(t, *bindingKey, next->allocations[0]); }));
  ASSERT_OK(applyCut(f, cut));
}
