// Uses the original typed catalog fixture; only this test asks for its private
// FDB. The conflict is a real database transaction, not an in-memory ordering.
TEST_F(TestEcFileMutation, AppendEofGateConflictsAndAbortDoesNotReserveHole) {
  Fixture f;
  ASSERT_OK(f.initialize(true));
  ASSERT_OK(f.open());
  auto firstRoot = f.root();
  ASSERT_OK(firstRoot);
  ASSERT_OK(f.zero(f.edit(*firstRoot, 0, 63)));
  auto session2 = f.opening;
  session2.session = Uuid::random();
  session2.openRequest = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return Sessions::open(t, f.user, session2); }));
  auto normal = f.write(3, 10);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::begin(t, normal); }));
  auto child = f.child(normal);
  ASSERT_OK(f.run([&](Tx &t) { return Mutations::planChild(t, f.opening.owner, child); }));
  auto raw = f.engine->createReadWriteTransaction();
  Tx stale(*raw);
  ASSERT_OK(blockingWait(Mutations::preparePublication(stale, f.birth.object, child.child, f.opening.owner)));
  EcFileAppendIntent a;
  a.object = f.birth.object;
  a.owner = f.opening.owner;
  a.session = session2.session;
  a.request = Uuid::random();
  a.operation = Uuid::random();
  a.length = 5;
  a.inputSha256.back() = 17;
  auto accepted = f.run([&](Tx &t) { return EcFileAppendCatalog::begin(t, a); });
  ASSERT_OK(accepted);
  EXPECT_EQ(accepted->parent.intent.offset, 63u);
  auto unchanged = f.root();
  ASSERT_OK(unchanged);
  EXPECT_EQ(unchanged->visibleLength, 63u);
  auto probe = objectKey(KeyPrefix::EcFileAppend, f.birth.object);
  probe += "-conflict";
  ASSERT_OK(blockingWait(stale.set(probe, "not-a-publication")));
  ASSERT_ERROR(blockingWait(stale.commit()), TransactionCode::kConflict);
  ASSERT_ERROR(
      f.run([&](Tx &t) { return Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner); }),
      StorageClientCode::kResourceBusy);
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileAppendCatalog::requireMutationOpen(t, f.birth.object, Uuid::zero()); }),
               StorageClientCode::kResourceBusy);
  auto replay = f.run([&](Tx &t) { return EcFileAppendCatalog::begin(t, a); });
  ASSERT_OK(replay);
  EXPECT_TRUE(same(*accepted, *replay));
  auto changed = a;
  changed.length++;
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileAppendCatalog::begin(t, changed); }), StatusCode::kTokenMismatch);
  changed = a;
  changed.operation = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileAppendCatalog::begin(t, changed); }), StatusCode::kTokenMismatch);
  EcFileSyncIntent sync;
  sync.object = f.birth.object;
  sync.owner = a.owner;
  sync.session = a.session;
  sync.request = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileAppendCatalog::sync(t, sync); }), StorageClientCode::kResourceBusy);
  auto stopped = f.run([&](Tx &t) { return Mutations::sealPrefix(t, a.object, a.operation, a.owner); });
  ASSERT_OK(stopped);
  EXPECT_EQ(stopped->confirmedPrefix, 0u);
  unchanged = f.root();
  ASSERT_OK(unchanged);
  EXPECT_EQ(unchanged->visibleLength, 63u);
  auto barrier = f.run([&](Tx &t) { return EcFileAppendCatalog::sync(t, sync); });
  ASSERT_OK(barrier);
  // An old accepted pwrite remains a real debt/operation, not implicitly ACKed
  // or destroyed by append. With unchanged length its original CAS is valid.
  ASSERT_OK(
      f.run([&](Tx &t) { return Mutations::preparePublication(t, f.birth.object, child.child, f.opening.owner); }));
  a.request = Uuid::random();
  a.operation = Uuid::random();
  auto next = f.run([&](Tx &t) { return EcFileAppendCatalog::begin(t, a); });
  ASSERT_OK(next);
  EXPECT_EQ(next->parent.intent.offset, 63u);
  auto oldBarrier = f.run([&](Tx &t) { return EcFileAppendCatalog::sync(t, sync); });
  ASSERT_OK(oldBarrier);
  EXPECT_TRUE(same(*barrier, *oldBarrier));  // fixed historical receipt, not a new flush
  sync.request = Uuid::random();
  ASSERT_ERROR(f.run([&](Tx &t) { return EcFileAppendCatalog::sync(t, sync); }), StorageClientCode::kResourceBusy);
}
