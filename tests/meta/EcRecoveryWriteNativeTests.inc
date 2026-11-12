// Included inside TestEcV2NativeLifecycle.cc's existing anonymous namespace.
// Separate TCP/Components/Engine instances, still one OS process and one host.
class TestEcV2NativeRecoveryWrite : public TestEcV2NativeExactGc {
 protected:
  void TearDown() override {
    closeExtra();
    TestEcV2NativeExactGc::TearDown();
  }

  void closeExtra() {
    if (extraServer_) extraServer_->stopAndJoin();
    extraServer_.reset();
    if (!extra_) return;
    if (extraInitialized_) {
      auto stopped = extra_->storageOperator.stopAndJoin();
      EXPECT_TRUE(stopped) << stopped.error().describe();
      extraInitialized_ = false;
    }
    {
      auto map = extra_->targetMap.release();
      if (map) for (const auto &[id, target] : map->getTargets()) {
        if (target.storageTarget) {
          auto released = target.storageTarget->release();
          EXPECT_TRUE(released) << released.error().describe();
        }
      }
    }
    auto cleared = extra_->storageTargets.globalFileStore().clear(loader_);
    EXPECT_TRUE(cleared) << cleared.error().describe();
    extra_.reset();
    extraConfig_.reset();
  }

  void addExtra(const Path &root, flat::NodeId node, storage::ChainId chainId, storage::TargetId targetId) {
    ASSERT_FALSE(extra_);
    struct rlimit limit {};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limit), 0);
    ASSERT_GE(limit.rlim_cur, openFds() + 8192u) << "Insufficient descriptor headroom for the additional Engine";
    extraConfig_ = std::make_unique<storage::Components::Config>(storageConfig_.clone());
    extraConfig_->targets().set_target_paths({root});
    extra_ = std::make_unique<storage::Components>(*extraConfig_);
    extra_->appInfo.nodeId = node;
    ASSERT_OK(extra_->storageTargets.load(loader_));
    extra_->mgmtdClient.store(std::shared_ptr<hf3fs::client::IMgmtdClientForServer>(fakeMgmtd_));
    ASSERT_OK(extra_->storageOperator.init(1));
    extraInitialized_ = true;
    routing_ = std::make_shared<flat::RoutingInfo>(*routing_);
    ASSERT_NO_FATAL_FAILURE(startServer(extraServerConfig_, extraServer_,
        std::make_unique<ControlFailureStorageService>(extra_->storageOperator, extraFault_),
        node, flat::NodeType::STORAGE, "StorageSerde"));
    routing_->routingInfoVersion = flat::RoutingInfoVersion(routing_->routingInfoVersion.toUnderType() + 1);
    fakeMgmtd_->setRoutingInfo(routing_);
    storage::EcCreateTargetReq create;
    create.settings.targetId = targetId;
    create.settings.chainId = chainId;
    create.settings.diskIndex = 0;
    create.settings.onlyChunkEngine = true;
    create.settings.allowExistingTarget = false;
    ASSERT_OK(blockingWait(storageClient_->createEcTarget(node, create)));
    auto next = std::make_shared<flat::RoutingInfo>(*routing_);
    flat::TargetInfo target;
    target.targetId = targetId;
    target.chainId = chainId;
    target.nodeId = node;
    target.diskIndex = 0;
    target.publicState = flat::PublicTargetState::SERVING;
    target.localState = flat::LocalTargetState::UPTODATE;
    next->targets[targetId] = target;
    flat::ChainInfo chain;
    chain.chainId = chainId;
    chain.chainVersion = storage::ChainVer{1};
    flat::ChainTargetInfo member;
    member.targetId = targetId;
    member.publicState = flat::PublicTargetState::SERVING;
    chain.targets.push_back(member);
    next->chains[chainId] = std::move(chain);
    next->routingInfoVersion = flat::RoutingInfoVersion(next->routingInfoVersion.toUnderType() + 1);
    routing_ = std::move(next);
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_OK(extra_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
    ASSERT_OK(components_->targetMap.updateRouting(fakeMgmtd_->getRoutingInfo()));
  }

  Result<storage::EcTargetDiscoveryObservation> discover(flat::NodeId node,
      storage::ChainId chain, storage::TargetId target, std::chrono::seconds timeout = std::chrono::seconds(20)) {
    CHECK_RESULT(key, storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string())));
    std::shared_ptr<const storage::EcScopeControlKey> shared(std::move(key));
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    storage::EcTargetDiscoveryClaims claims;
    claims.clusterAuthority = authority_;
    claims.nodeId = node;
    claims.chainId = chain;
    claims.targetId = target;
    claims.nonce = Uuid::random();
    claims.issuedAtSeconds = now;
    claims.expiresAtSeconds = now + 30;
    CHECK_RESULT(signedRequest, storage::signEcTargetDiscovery(*shared, claims, now));
    auto deadline = control();
    deadline.deadline = std::chrono::steady_clock::now() + timeout;
    return blockingWait(storageClient_->getEcTargetIdentityControlled(std::move(signedRequest), shared, deadline));
  }

  void selectPoolZero(flat::NodeId node, storage::ChainId chain, storage::TargetId target) {
    auto observed = discover(node, chain, target);
    ASSERT_OK(observed);
    const auto &endpoint = observed->claims.endpoint;
    ASSERT_EQ(endpoint.nodeId, node);
    ASSERT_EQ(endpoint.chainId, chain);
    ASSERT_EQ(endpoint.targetId, target);
    auto &fixed = metaConfig_.ec_targets(0);
    fixed.set_node(node.toUnderType());
    fixed.set_chain(chain.toUnderType());
    fixed.set_target(target.toUnderType());
    fixed.set_engine_uuid(endpoint.engineUuid.toHexString());
    fixed.set_target_incarnation(endpoint.targetIncarnation.toHexString());
    // Verify the other eleven actual currently loaded instances as well.
    for (size_t i = 1; i != 12; ++i) {
      const auto &existing = metaConfig_.ec_targets(i);
      auto healthy = discover(flat::NodeId(existing.node()), storage::ChainId(existing.chain()),
                              storage::TargetId(existing.target()));
      ASSERT_OK(healthy);
      ASSERT_EQ(healthy->claims.endpoint.engineUuid.toHexString(), existing.engine_uuid());
      ASSERT_EQ(healthy->claims.endpoint.targetIncarnation.toHexString(), existing.target_incarnation());
    }
  }

  hf3fs::client::ec::EcStripeRunRecord freshRun() {
    hf3fs::client::ec::EcStripeRunRecord run;
    run.action = "write";
    run.cluster = "native-recovery-private-fdb";
    run.clientNamespace = metaClientId_.uuid;
    run.inputPath = "/private-test-input";
    run.remotePath = "/private-test-source";
    run.shardBytes = kShardBytes;
    run.createRequest = Uuid::random();
    run.operation = Uuid::random();
    run.beginRequest = Uuid::random();
    run.bindRequest = Uuid::random();
    run.publishRequest = Uuid::random();
    run.getRequest = Uuid::random();
    run.prepareRepairRequest = Uuid::random();
    run.pin = Uuid::random();
    run.acquireRequest = Uuid::random();
    run.releaseRequest = Uuid::random();
    run.planId = Uuid::random();
    return run;
  }

  folly::test::TemporaryDirectory lostRoot_, spareRoot_;
  std::unique_ptr<storage::Components::Config> extraConfig_;
  std::unique_ptr<storage::Components> extra_;
  bool extraInitialized_ = false;
  net::Server::Config extraServerConfig_;
  std::unique_ptr<net::Server> extraServer_;
  ControlFailure extraFault_;
};

TEST_F(TestEcV2NativeRecoveryWrite, OfflineInstanceSameObjectRecoveryPreservesOldDebtAndFixedReplay) {
  using namespace hf3fs::client::ec;
  const flat::NodeId lostNode{63}, spareNode{64};
  const storage::ChainId lostChain{3000}, spareChain{4000};
  const storage::TargetId lostTarget{3000}, spareTarget{4000};
  ASSERT_NO_FATAL_FAILURE(addExtra(lostRoot_.path(), lostNode, lostChain, lostTarget));
  ASSERT_NO_FATAL_FAILURE(selectPoolZero(lostNode, lostChain, lostTarget));
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "recovery-original-object");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, created->object.object, 0, 57));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  auto published = blockingWait(metaClient_->publishEcMutationV2(original.publish));
  ASSERT_OK(published);
  ASSERT_TRUE(published->drain);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(created->object.object, storage::EcGrantScope::WriteOperation,
      original.begin.operation, *published->drain, EcV2DrainState::Published));
  auto heldRequest = readRequest(created->object.object);
  auto held = blockingWait(metaClient_->acquireEcReadV2(heldRequest));
  ASSERT_OK(held);
  Mutation unfinishedRepair;
  ASSERT_NO_FATAL_FAILURE(prepareRepairMetadata(unfinishedRepair, *held, 2));
  const auto repairBefore = serde::serialize(unfinishedRepair.reservation.record);
  const auto oldEndpoint = held->snapshot.endpoints[0].endpoint;

  auto source = freshRun();
  source.createRequest = create.uuid;
  source.operation = original.begin.operation;
  source.beginRequest = original.begin.uuid;
  source.bindRequest = original.bind.uuid;
  source.publishRequest = original.publish.uuid;
  source.inputBytes = original.logical.size();
  source.inputSha256 = original.begin.contentSha256;
  EcStripeRunObservation observed;
  observed.state = "Published";
  observed.ownerUid = user_.uid.toUnderType();
  observed.object = published->object;
  observed.revision = published->record.candidate.revision;
  observed.mutationPublished = true;
  const auto sourcePath = std::filesystem::path(traces_.path().string()) / "source-run";
  auto sourceJournal = EcStripeRunJournal::create(sourcePath, source);
  ASSERT_OK(sourceJournal);
  ASSERT_OK((*sourceJournal)->append(observed));
  sourceJournal->reset();
  auto recordBytes = readEcStripeInput(sourcePath / "record.json", 65536);
  auto observationBytes = readEcStripeInput(sourcePath / "state-00000000000000000000.json", 65536);
  ASSERT_OK(recordBytes);
  ASSERT_OK(observationBytes);
  std::array<std::string_view, 10> hashParts{};
  hashParts[0] = *recordBytes;
  auto recordHash = computeEcLogicalSha256(hashParts, recordBytes->size());
  ASSERT_OK(recordHash);
  hashParts[0] = *observationBytes;
  auto observationHash = computeEcLogicalSha256(hashParts, observationBytes->size());
  ASSERT_OK(observationHash);
  // Actual listener/worker/Engine close. Its historical route and files remain;
  // failure is not manufactured by deleting a target from the routing table.
  ASSERT_NO_FATAL_FAILURE(closeExtra());
  ASSERT_TRUE(routing_->nodes.contains(lostNode));
  ASSERT_TRUE(routing_->targets.contains(lostTarget));
  auto unavailable = discover(lostNode, lostChain, lostTarget, std::chrono::seconds(2));
  ASSERT_FALSE(unavailable);
  // Read real surviving fragments only after the original Engine/listener
  // are closed. The old twelve-endpoint pin remains held; no all-ACK Release
  // is attempted. Index 10 is parity, so this is an actual degraded decode.
  storage::EcCodec::Shards surviving;
  std::array<storage::EcCodecShardView, 10> survivingViews;
  for (size_t i = 1; i != 11; ++i) {
    auto read = readOne(*held, i);
    ASSERT_OK(read);
    surviving[i] = std::move(read->payload.data);
    survivingViews[i - 1] = {static_cast<uint16_t>(i), surviving[i]};
  }
  auto decoded = storage::EcCodec::recover(survivingViews, held->manifest.logicalLength, kShardBytes);
  ASSERT_OK(decoded);
  std::string restoredLogical;
  std::array<std::string_view, 10> logicalParts;
  for (size_t i = 0; i != 10; ++i) {
    logicalParts[i] = (*decoded)[i];
    restoredLogical += (*decoded)[i];
  }
  restoredLogical.resize(held->manifest.logicalLength);
  ASSERT_EQ(restoredLogical, original.logical);
  auto restoredHash = computeEcLogicalSha256(logicalParts, restoredLogical.size());
  ASSERT_OK(restoredHash);
  ASSERT_EQ(*restoredHash, held->contentSha256);
  ASSERT_EQ(*restoredHash, source.inputSha256);
  const auto restoredInputPath = std::filesystem::path(traces_.path().string()) / "restored-input";
  {
    std::ofstream output(restoredInputPath, std::ios::binary);
    ASSERT_TRUE(output.is_open());
    output.write(restoredLogical.data(), restoredLogical.size());
    output.close();
    ASSERT_TRUE(output.good());
    ASSERT_EQ(::chmod(restoredInputPath.c_str(), 0600), 0);
  }
  auto restoredInput = readEcStripeInput(restoredInputPath, size_t(kShardBytes) * 10);
  ASSERT_OK(restoredInput);
  auto recovery = prepareEcRecoveryWrite(freshRun(), source, observed, sourcePath.string(),
      *recordHash, *observationHash, restoredInputPath.string(), *restoredInput);
  ASSERT_OK(recovery);
  const auto recoveryPath = std::filesystem::path(traces_.path().string()) / "recovery-run";
  auto recoveryJournal = EcStripeRunJournal::create(recoveryPath, *recovery);
  ASSERT_OK(recoveryJournal);
  ASSERT_NO_FATAL_FAILURE(addExtra(spareRoot_.path(), spareNode, spareChain, spareTarget));
  ASSERT_NO_FATAL_FAILURE(selectPoolZero(spareNode, spareChain, spareTarget));
  auto borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto operationControl = [] { return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(90), {}}; };
  auto actualSource = blockingWait(verifyEcRecoveryWriteSource(borrowed, *recovery, user_, operationControl()));
  ASSERT_OK(actualSource);  // Actual RPC33 with old instance offline and a new configured pool.
  ASSERT_EQ(actualSource->record.candidate.revision, observed.revision);
  ASSERT_EQ(serde::serialize((*actualSource->allocations)[0].endpoint()), serde::serialize(oldEndpoint));
  ASSERT_NE(metaConfig_.ec_targets(0).engine_uuid(), oldEndpoint.engineUuid.toHexString());
  auto wrongOwner = *recovery;
  ++*wrongOwner.expectedOwnerUid;
  ASSERT_ERROR(blockingWait(verifyEcRecoveryWriteSource(borrowed, wrongOwner, user_, operationControl())),
               StatusCode::kAuthenticationFail);
  auto wrongNamespace = *recovery;
  wrongNamespace.clientNamespace = Uuid::random();
  ASSERT_ERROR(blockingWait(verifyEcRecoveryWriteSource(borrowed, wrongNamespace, user_, operationControl())),
               StatusCode::kTokenMismatch);
  auto missingSource = *recovery;
  missingSource.recoverySource->operation = Uuid::random();
  const auto missingIdentity = serde::serialize(missingSource);
  ASSERT_FALSE(blockingWait(verifyEcRecoveryWriteSource(borrowed, missingSource, user_, operationControl())));
  ASSERT_EQ(serde::serialize(missingSource), missingIdentity);
  // A missing source observation never issues the new operation or replaces
  // any caller identity. The same persisted request remains recoverable.
  {
    auto txn = kv_->createReadWriteTransaction();
    ASSERT_FALSE(blockingWait(EcCatalog::getOperation(*txn, created->object.object, recovery->operation)));
  }

  folly::CPUThreadPoolExecutor executor(2);
  auto connected = blockingWait(EcStripeClient::connect(borrowed, storageClient_, mgmtd_, user_,
      metaClientId_.uuid, executor, {}));
  ASSERT_OK(connected);
  auto manager = *connected;
  SCOPE_EXIT { if (manager) blockingWait(manager->close()); };
  EcStripeWrite write;
  write.object = *recovery->object;
  write.expectedRevision = recovery->expectedRevision;
  write.ids = recovery->mutationIds();
  write.logicalData = *restoredInput;
  replyDrop_.arm(write.ids.operation);
  auto replaced = blockingWait(manager->write(write, operationControl()));
  ASSERT_TRUE(replaced.published()) << (replaced.failure ? replaced.failure->describe() : "not published");
  ASSERT_TRUE(replyDrop_.snapshot().committed);  // Service really committed, then lost a TCP response.
  ASSERT_OK(validateEcRecoveryWritePublication(*recovery, *actualSource, *replaced.observation));
  const auto replacementRevision = replaced.observation->record.candidate.revision;
  ASSERT_EQ(replaced.observation->object.object, created->object.object);
  // Emulate a process stopping before its local success record was durable.
  EcStripeRunObservation unknown;
  unknown.state = "Indeterminate";
  unknown.ownerUid = user_.uid.toUnderType();
  unknown.object = recovery->object;
  unknown.errorCode = TransactionCode::kMaybeCommitted;
  ASSERT_OK((*recoveryJournal)->append(unknown));
  recoveryJournal->reset();
  blockingWait(manager->close());
  manager.reset();
  connected->reset();
  borrowed.reset();
  ASSERT_NO_FATAL_FAILURE(reconstructMetaClient());
  auto reopened = EcStripeRunJournal::resume(recoveryPath);
  ASSERT_OK(reopened);
  ASSERT_EQ(serde::serialize((*reopened)->record()), serde::serialize(*recovery));
  auto restoredAgain = readEcStripeInput((*reopened)->record().inputPath, size_t(kShardBytes) * 10);
  ASSERT_OK(restoredAgain);
  ASSERT_EQ(*restoredAgain, *restoredInput);
  write.logicalData = *restoredAgain;
  borrowed = std::shared_ptr<meta::client::MetaClient>(metaClient_.get(), [](auto *) {});
  auto sourceAgain = blockingWait(verifyEcRecoveryWriteSource(borrowed, (*reopened)->record(), user_, operationControl()));
  ASSERT_OK(sourceAgain);
  connected = blockingWait(EcStripeClient::connect(borrowed, storageClient_, mgmtd_, user_,
      metaClientId_.uuid, executor, {}));
  ASSERT_OK(connected);
  manager = *connected;
  auto replayed = blockingWait(manager->write(write, operationControl()));
  ASSERT_TRUE(replayed.published());
  ASSERT_EQ(replayed.observation->record.candidate.revision, replacementRevision);
  ASSERT_EQ(serde::serialize(replayed.observation->record), serde::serialize(replaced.observation->record));
  ASSERT_OK(validateEcRecoveryWritePublication((*reopened)->record(), *sourceAgain, *replayed.observation));
  auto current = blockingWait(metaClient_->acquireEcReadV2(readRequest(created->object.object)));
  ASSERT_OK(current);
  ASSERT_EQ(current->manifest.revision, replacementRevision);
  ASSERT_NO_FATAL_FAILURE(verifyCurrent(*current, original));
  auto releaseCurrent = request<ReleaseEcReadV2Req>();
  releaseCurrent.object = created->object.object;
  releaseCurrent.pin = current->snapshot.pin;
  auto currentReleased = blockingWait(metaClient_->releaseEcReadV2(releaseCurrent));
  ASSERT_OK(currentReleased);
  ASSERT_EQ(currentReleased->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_EQ(currentReleased->drain.expectedEndpoints, 12);
  ASSERT_EQ(currentReleased->drain.acknowledgedEndpoints, 12);
  ASSERT_NO_FATAL_FAILURE(verifyDrain(created->object.object, storage::EcGrantScope::ReadPin,
      current->snapshot.pin, currentReleased->drain, EcV2DrainState::ReadReleased));

  // Old repair and pin retain their exact unreachable historical endpoint;
  // no cancellation, explicit retirement/reference release, replacement ACK
  // or physical GC occurs. Publish itself marks the previous manifest retired.
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  auto controlKey = storage::EcScopeControlKey::loadFile(std::filesystem::path(controlKeyPath_.string()));
  ASSERT_OK(controlKey);
  {
    auto txn = kv_->createReadWriteTransaction();
    auto repairRecord = blockingWait(EcCatalog::getOperation(*txn, created->object.object, unfinishedRepair.begin.operation));
    ASSERT_OK(repairRecord);
    ASSERT_EQ(serde::serialize(*repairRecord), repairBefore);
    auto originalPin = blockingWait(EcV2BindingCatalog::getPinSnapshot(*txn, created->object.object, heldRequest.pin, owner));
    ASSERT_OK(originalPin);
    ASSERT_EQ(serde::serialize(*originalPin), serde::serialize(held->snapshot));
    ASSERT_OK(blockingWait(EcV2GcCatalog::requireProtectedScope(*txn, created->object.object,
        storage::EcGrantScope::ReadPin, heldRequest.pin, owner)));
    ASSERT_OK(blockingWait(EcV2GcCatalog::requireProtectedScope(*txn, created->object.object,
        storage::EcGrantScope::WriteOperation, unfinishedRepair.begin.operation, owner)));
    auto debt = blockingWait(EcV2GcCatalog::getAllocation(*txn, created->object.object,
        original.reservation.record.candidate.fragments[0].identity));
    ASSERT_OK(debt);
    ASSERT_GT(debt->active, 0);
    ASSERT_TRUE(debt->claimId.is_nil());
    ASSERT_ERROR(blockingWait(EcCatalog::retireRevision(*txn, created->object.object, 0, observed.revision)),
                 StatusCode::kTokenStale);
    ASSERT_ERROR(blockingWait(EcV2GcCatalog::claim(*txn, created->object.object,
        original.reservation.record.candidate.fragments[0].identity, Uuid::random(), **controlKey)),
        StatusCode::kTokenStale);
  }
  auto stale = prepareEcRecoveryWrite(freshRun(), source, observed, sourcePath.string(),
      *recordHash, *observationHash, (traces_.path() / "restored-input").string(), original.logical);
  ASSERT_OK(stale);
  const auto stalePath = std::filesystem::path(traces_.path().string()) / "stale-cas-run";
  auto staleJournal = EcStripeRunJournal::create(stalePath, *stale);
  ASSERT_OK(staleJournal);
  write.ids = stale->mutationIds();
  auto denied = blockingWait(manager->write(write, operationControl()));
  ASSERT_TRUE(denied.failure);
  ASSERT_EQ(denied.failure->code(), StatusCode::kTokenStale);
  ASSERT_EQ(denied.operation, stale->operation);
  ASSERT_EQ((*staleJournal)->record().expectedRevision, observed.revision);
  ASSERT_EQ((*staleJournal)->record().operation, stale->operation);
  RecordProperty("recovery_failure_domain", "one host/process; actual independent TCP service and Engine closed");
  RecordProperty("recovery_pool", "11 retained healthy endpoints plus one discovered spare; all 12 allocations new");
  RecordProperty("recovery_debt", "old repair and pin remain active; retirement/GC rejected; offline route and data retained");
}
