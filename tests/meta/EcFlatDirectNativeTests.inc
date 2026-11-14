// Included by the real FDB + TCP Storage/Meta fixture, not a mock Meta service.
TEST_F(TestEcV2NativeHelperPlan, FlatDirectSingleAndDoubleTargetsKeepPermanentDelivery) {
  using namespace hf3fs::client::ec;
  folly::CPUThreadPoolExecutor pool(4);
  auto borrowedMeta = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto connected = blockingWait(
      EcStripeClient::connect(borrowedMeta, storageClient_, mgmtd_, user_, metaClientId_.uuid, pool, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT { blockingWait(manager->close()); };
  auto control = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(120), {}}; };
  auto ids = [] {
    return EcStripeMutationIds{Uuid::random(), Uuid::random(), Uuid::random(),
                               Uuid::random(), Uuid::random(), Uuid::random()};
  };
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "flat-direct-windows");
  create.shardBytes = 3 * storage::kEcIntegrityBlockBytes + 7;  // Four real blocks, including the tail.
  auto created = blockingWait(manager->createFile(create, control()));
  ASSERT_OK(created);
  EcStripeWrite write;
  write.object = created->object;
  write.ids = ids();
  write.logicalData = bytes(10 * create.shardBytes - 37, 901);
  auto written = blockingWait(manager->write(write, control()));
  ASSERT_TRUE(written.published()) << (written.failure ? written.failure->describe() : "not published");
  auto object = written.observation->object;
  auto previous = written.observation->record.candidate;
  for (uint16_t mask : {uint16_t{1}, uint16_t{3}}) {
    for (uint8_t window : {uint8_t{1}, uint8_t{2}, uint8_t{4}}) {
      EcStripeRepair repair;
      repair.object = object;
      repair.expectedRevision = previous.revision;
      repair.ids = ids();
      repair.baseRead = {object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
      repair.planId = Uuid::random();
      repair.replacementMask = mask;
      repair.blockWindow = window;
      repair.mode = EcRepairMode::HelperChain;
      repair.delivery = EcRepairDelivery::HelperDirect;
      // Keep one real data execution at the API's default-off setting. All
      // remaining windows/target counts exercise the same opt-in observer.
      EXPECT_FALSE(repair.collectMetrics);
      repair.collectMetrics = mask != 1 || window != 1;
      size_t source = 0;
      for (uint16_t shard = 0; shard != 12 && source != repair.sources.size(); ++shard)
        if (!(mask & (uint16_t{1} << shard))) repair.sources[source++] = shard;
      auto repaired = blockingWait(manager->repair(repair, control()));
      ASSERT_TRUE(repaired.published()) << (repaired.failure ? repaired.failure->describe() : "not published");
      EXPECT_TRUE(repaired.repairDataPhaseEntered);
      if (repair.collectMetrics) {
        const uint64_t targets = std::popcount(mask);
        ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(
            repaired.repairMetrics, {0, targets, 0, targets, targets, targets, 0, 4}));
        EXPECT_EQ(repaired.repairMetrics.configuredWindow, window);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::SelectedRepair).succeeded, 1);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::NativeBegin).apiInvocations, 3 * targets);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::NativeHelper).succeeded, 4);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::NativeHelper).validatedReturnedPayloadBytes, 0);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::NativeAppend).entered, 0);
        EXPECT_EQ(repaired.repairMetrics.at(EcRepairPoint::NativeSeal).succeeded, targets);
        EXPECT_LE(repaired.repairMetrics.at(EcRepairPoint::BlockActor).peakActive, window);
      } else {
        EXPECT_FALSE(repaired.repairMetrics.available);
        EXPECT_EQ(repaired.repairMetrics.elapsedNs, 0);
        for (const auto &point : repaired.repairMetrics.points) EXPECT_EQ(point.entered, 0);
        for (const auto &method : repaired.repairMetrics.storageRpc.methods) EXPECT_EQ(method.entered, 0);
      }
      ASSERT_TRUE(repaired.observation->drain);
      EXPECT_EQ(repaired.observation->drain->state, EcV2DrainState::Published);
      EXPECT_EQ(repaired.observation->drain->expectedEndpoints,
                repaired.observation->drain->acknowledgedEndpoints);
      const auto &candidate = repaired.observation->record.candidate;
      for (size_t i = 0; i != 12; ++i) {
        if (mask & (uint16_t{1} << i)) {
          EXPECT_NE(candidate.fragments[i].identity.allocation, previous.fragments[i].identity.allocation);
          EXPECT_EQ(candidate.fragments[i].operation, repair.ids.operation);
        } else {
          EXPECT_TRUE(serde::equals(candidate.fragments[i], previous.fragments[i]));
        }
      }
      object = repaired.observation->object;
      EcStripePinIds pin{object.object, 0, Uuid::random(), Uuid::random(), Uuid::random()};
      auto reading = manager->startRead(pin, control());
      ASSERT_OK(reading);
      auto output = blockingWait(reading->takeReady());
      ASSERT_OK(output);
      EXPECT_EQ(output->logicalData, write.logicalData);
      EXPECT_EQ(output->pinned.manifest.revision, candidate.revision);
      // The public read output carries only the fixed pin/manifest, not bearer grants.
      // Replay its original Acquire request; do not create another pin or request identity.
      auto acquire = request<AcquireEcReadV2Req>();
      acquire.uuid = pin.acquireRequest;
      acquire.object = pin.object;
      acquire.stripe = pin.stripe;
      acquire.pin = pin.pin;
      auto granted = blockingWait(metaClient_->acquireEcReadV2(acquire));
      ASSERT_OK(granted);
      ASSERT_EQ(serde::serialize(granted->manifest), serde::serialize(output->pinned.manifest));
      ASSERT_EQ(serde::serialize(granted->snapshot), serde::serialize(output->pinned.snapshot));
      // Read every actual target, rather than accepting only the ten-shard logical decode.
      auto encoded = storage::EcCodec::encode(write.logicalData, create.shardBytes);
      ASSERT_OK(encoded);
      for (uint16_t shard = 0; shard != 12; ++shard) {
        ASSERT_TRUE(granted->readGrants[shard]);
        EcV2AllocationBinding allocation;
        allocation.fragment = output->pinned.manifest.fragments[shard];
        storage::EcReadBlockV2Req read;
        read.request = access(allocation);
        read.grant = *granted->readGrants[shard];
        std::string allBytes;
        for (uint32_t block = 0; block != 4; ++block) {
          read.blockIndex = block;
          auto actual = blockingWait(storageClient_->readEcBlockV2Controlled(read, this->control()));
          ASSERT_OK(actual);
          EXPECT_EQ(actual->blockIndex, block);
          allBytes += actual->payload.data;
        }
        EXPECT_EQ(allBytes, (*encoded)[shard]);
      }
      blockingWait(reading->waitLocalCleanup());
      ASSERT_OK(blockingWait(manager->release(*reading, control())));
      auto releasedBase = blockingWait(manager->release(repair.baseRead, control()));
      ASSERT_OK(releasedBase);
      EXPECT_EQ(releasedBase->drain.state, EcV2DrainState::ReadReleased);
      auto seq = [&] {
        auto txn = kv_->createReadWriteTransaction();
        return blockingWait(ec_v2_lifecycle::readIssuanceSequence(
            *txn, object.object, storage::EcGrantScope::WriteOperation, repair.ids.operation));
      };
      auto before = seq();
      ASSERT_OK(before);
      repair.collectMetrics = true;
      auto replay = blockingWait(manager->repair(repair, control()));
      EXPECT_FALSE(replay.repairDataPhaseEntered);
      ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(replay.repairMetrics, {}));
      EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Query).succeeded, 1);
      EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Prepare).succeeded, 1);
      EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::SelectedRepair).entered, 0);
      EXPECT_EQ(replay.repairMetrics.at(EcRepairPoint::Publish).entered, 0);
      ASSERT_TRUE(replay.published()) << (replay.failure ? replay.failure->describe() : "not published");
      EXPECT_EQ(serde::serialize(replay.observation->record), serde::serialize(repaired.observation->record));
      auto after = seq();
      ASSERT_OK(after);
      EXPECT_EQ(*before, *after);
      auto wrong = repair;
      wrong.delivery = EcRepairDelivery::ClientAppend;
      auto rejected = blockingWait(manager->repair(wrong, control()));
      ASSERT_TRUE(rejected.failure);
      EXPECT_EQ(rejected.failure->code(), StatusCode::kTokenMismatch);
      EXPECT_FALSE(rejected.repairDataPhaseEntered);
      ASSERT_NO_FATAL_FAILURE(expectFlatRepairMetrics(rejected.repairMetrics, {}));
      EXPECT_EQ(rejected.repairMetrics.at(EcRepairPoint::Query).succeeded, 1);
      EXPECT_EQ(rejected.repairMetrics.at(EcRepairPoint::Prepare).entered, 1);
      EXPECT_EQ(rejected.repairMetrics.at(EcRepairPoint::Prepare).succeeded, 0);
      EXPECT_EQ(rejected.repairMetrics.at(EcRepairPoint::SelectedRepair).entered, 0);
      EXPECT_EQ(rejected.repairMetrics.at(EcRepairPoint::Publish).entered, 0);
      auto observed = request<PrepareEcRepairDirectV2Req>();
      observed.object = object.object;
      observed.operation = repair.ids.operation;
      observed.planId = repair.planId;
      observed.maxBlocksInFlight = window;
      for (size_t i = 0; i != repair.sources.size(); ++i) observed.sourceOrder[i] = repair.sources[i];
      auto history = blockingWait(metaClient_->prepareEcRepairDirectV2(observed));
      ASSERT_OK(history);
      EXPECT_FALSE(history->delegation);
      EXPECT_FALSE(history->base.helpers);
      for (const auto &grant : history->base.mutation.grants) EXPECT_FALSE(grant);
      ASSERT_TRUE(history->base.mutation.reservation);
      ASSERT_TRUE(history->base.mutation.allocations);
      EXPECT_EQ(history->base.plan.operationEndpointCount,
                history->base.mutation.reservation->operationEndpoints.count);
      previous = candidate;
    }
  }
  blockingWait(manager->close());
  EXPECT_EQ(manager->snapshot().activeOperations, 0);
  EXPECT_EQ(manager->snapshot().reservedApplicationBytes, 0);
  RecordProperty("flat_direct_targets_windows", "1,2 targets x 1,2,4 blocks in flight; four blocks per shard");
  RecordProperty("flat_direct_metrics", "default off plus first-hop-only frames; no client Append or validated output bytes");
  RecordProperty("authority", "Meta71 committed ECRP2/ECVI; independent Append and Query; Storage50 TCP");
}

TEST_F(TestEcV2NativeHelperPlan, FlatDirectCommittedReplyLossAndClosingOnlyObserve) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "flat-direct-lost-prepare");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 907));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto base = blockingWait(metaClient_->acquireEcReadV2(readRequest(object)));
  ASSERT_OK(base);
  Mutation replacement;
  ASSERT_NO_FATAL_FAILURE(prepareRepairMetadata(replacement, *base, 3));
  auto legacy = planRequest(replacement);
  PrepareEcRepairDirectV2Req req;
  static_cast<PrepareEcRepairV2Req &>(req) = legacy;
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.flatDirectDropOperation = req.operation;
  }
  auto lost = blockingWait(metaClient_->prepareEcRepairDirectV2(req));
  ASSERT_FALSE(lost);  // Actual TCP shutdown after commit, not a fabricated error response.
  std::optional<PrepareEcRepairDirectV2Rsp> committed;
  {
    std::unique_lock lock(replyDrop_.mutex);
    ASSERT_TRUE(replyDrop_.directChanged.wait_for(lock, std::chrono::seconds(10),
                                                [&] { return replyDrop_.flatDirectFinished; }));
    EXPECT_EQ(replyDrop_.flatDirectDrops, 1);
    EXPECT_EQ(replyDrop_.flatDirectShutdown, 0);
    committed = replyDrop_.flatDirectPrepared;
  }
  ASSERT_TRUE(committed);
  auto replay = blockingWait(metaClient_->prepareEcRepairDirectV2(req));
  ASSERT_OK(replay);
  ASSERT_TRUE(replay->delegation);
  ASSERT_TRUE(replay->base.helpers);
  EXPECT_EQ(serde::serialize(replay->base.plan), serde::serialize(committed->base.plan));
  EXPECT_EQ(serde::serialize(replay->base.mutation.record), serde::serialize(committed->base.mutation.record));
  for (size_t i = 0; i != replay->base.plan.targetCount; ++i) {
    EXPECT_EQ(replay->delegation->appendGrants[i].claims.rights, uint16_t(storage::EcGrantRightV2::Append));
    EXPECT_EQ(replay->delegation->queryGrants[i].claims.rights, uint16_t(storage::EcGrantRightV2::Query));
    EXPECT_EQ(replay->delegation->appendGrants[i].claims.scopeId, req.operation);
    EXPECT_EQ(replay->delegation->queryGrants[i].claims.scopeId, req.operation);
  }
  std::string key(kv::toStr(kv::KeyPrefix::EcV2RepairPlan));
  key.append(object.incarnation.asStringView());
  key.append(req.operation.asStringView());
  auto txn = kv_->createReadWriteTransaction();
  auto raw = blockingWait(txn->get(key));
  ASSERT_OK(raw);
  ASSERT_TRUE(*raw);
  EcV2RepairPlanRecord record;
  ASSERT_OK(serde::deserialize(record, **raw));
  EXPECT_EQ(record.version, 2);
  // The original global-v1 loader remains unchanged and refuses ECRP2.
  ASSERT_ERROR(blockingWait(ec_v2_lifecycle::load<EcV2RepairPlanRecord>(*txn, key)), StatusCode::kDataCorruption);
  txn.reset();
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(legacy)), StatusCode::kTokenMismatch);
  auto changed = req;
  changed.maxBlocksInFlight = 2;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(changed)), StatusCode::kTokenMismatch);
  changed = req;
  std::swap(changed.sourceOrder[0], changed.sourceOrder[1]);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(changed)), StatusCode::kTokenMismatch);
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = req.operation;
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.scope = req.operation;
    controlFault_.fail = true;
  }
  ASSERT_ERROR(blockingWait(metaClient_->cancelEcMutationV2(cancel)), StatusCode::kNotImplemented);
  auto sequence = [&] {
    auto transaction = kv_->createReadWriteTransaction();
    return blockingWait(ec_v2_lifecycle::readIssuanceSequence(
        *transaction, object, storage::EcGrantScope::WriteOperation, req.operation));
  };
  auto before = sequence();
  ASSERT_OK(before);
  auto history = blockingWait(metaClient_->prepareEcRepairDirectV2(req));
  ASSERT_OK(history);
  ASSERT_TRUE(history->base.mutation.drain);
  EXPECT_EQ(history->base.mutation.drain->state, EcV2DrainState::Closing);
  EXPECT_FALSE(history->delegation);
  EXPECT_FALSE(history->base.helpers);
  for (const auto &grant : history->base.mutation.grants) EXPECT_FALSE(grant);
  auto after = sequence();
  ASSERT_OK(after);
  EXPECT_EQ(*before, *after);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairV2(legacy)), StatusCode::kTokenMismatch);
  // History cannot silently recreate a missing ECRP or use a new delivery.
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->clear(key)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(req)), StatusCode::kTokenStale);
  txn = kv_->createReadWriteTransaction();
  auto stillMissing = blockingWait(txn->get(key));
  ASSERT_OK(stillMissing);
  EXPECT_FALSE(*stillMissing);
  ASSERT_OK(blockingWait(txn->set(key, **raw)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn.reset();
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0400}; }));
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(req)), MetaCode::kNoPermission);
  ASSERT_NO_FATAL_FAILURE(alterInode(object, [](Inode &value) { value.acl.perm = Permission{0600}; }));
  {
    std::lock_guard lock(controlFault_.mutex);
    controlFault_.fail = false;
  }
  ASSERT_OK(blockingWait(metaClient_->cancelEcMutationV2(cancel)));
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcRepairDirectV2(req)), StatusCode::kTokenStale);
  auto actual = readOne(*base, 0);
  ASSERT_OK(actual);
  EXPECT_EQ(actual->payload.data, original.shards[0]);
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = base->snapshot.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(released);
  EXPECT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
  EXPECT_EQ(released->drain.expectedEndpoints, 12);
  EXPECT_EQ(released->drain.acknowledgedEndpoints, 12);
  ASSERT_NO_FATAL_FAILURE(checkPin(object, base->snapshot.pin, true));
  RecordProperty("prepare_reply_loss", "actual committed Meta71 response followed by TCP shutdown; same operation replay");
}
