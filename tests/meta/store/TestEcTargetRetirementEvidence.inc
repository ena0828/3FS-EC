// Real FDB metadata plus actual persistent Storage target control. The W0
// metadata seam does not claim data writes, publication seals or physical GC.
using Retirements = EcTargetRetirementCatalog;

std::string retirementRecordKey(const EcV2PhysicalEndpoint &ep) {
  return Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirement,
                                ep.placement.node.toUnderType(),
                                ep.placement.chain.toUnderType(),
                                ep.placement.target.toUnderType(),
                                ep.engineUuid,
                                ep.targetIncarnation);
}
Result<EcTargetRetirementRecord> retireTestTarget(Fixture &f,
                                                  SourcePinTargetFixture &physical,
                                                  const EcV2PhysicalEndpoint &ep) {
  EcTargetRetirementIntent intent;
  intent.endpoint = ep;
  intent.authority = physical.authority;
  intent.retirementId = Uuid::random();
  intent.owner = {flat::Uid(0), Uuid::random()};
  intent.requestId = Uuid::random();
  RETURN_ON_ERROR(f.run([&](Tx &t) { return Retirements::prepare(t, intent); }));
  CHECK_RESULT(executor, storage::EcTargetRetirementExecutor::create(
      physical.key, physical.authority, ep.placement.node, [] { return uint64_t{1700000001}; }));
  storage::EcTargetRetirementClaims claims;
  claims.clusterAuthority = physical.authority;
  claims.nodeId = ep.placement.node;
  claims.chainId = ep.placement.chain;
  claims.targetId = ep.placement.target;
  claims.engineUuid = ep.engineUuid;
  claims.targetIncarnation = ep.targetIncarnation;
  claims.retirementId = intent.retirementId;
  claims.nonce = Uuid::random();
  claims.issuedAtSeconds = 1700000000;
  claims.expiresAtSeconds = 1700000060;
  CHECK_RESULT(request, storage::signEcTargetRetirement(*physical.key, claims, 1700000000));
  CHECK_RESULT(found, physical.map.getByTargetId(ep.placement.target));
  CHECK_RESULT(observed, blockingWait(executor->execute(claims.action, request, found->storageTarget)));
  CHECK_RESULT(record, f.run([&](Tx &t) {
    return Retirements::recordCompletion(t, intent, request, observed, *physical.key);
  }));
  RETURN_ON_ERROR(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto changed = co_await Retirements::recordCompletion(t, intent, request, observed, *physical.key);
    CO_RETURN_ON_ERROR(changed);
    if (serde::serialize(*changed) != serde::serialize(record)) co_return makeError(StatusCode::kDataCorruption);
    co_return Void{};
  }));
  return record;
}

TEST_F(TestEcFileTree, DrainEvidenceVersionsPreserveV1BytesAndRejectPublication) {
  EcV2DrainProgressV1 oldProgress;
  oldProgress.state = EcV2DrainState::ReadReleased;
  oldProgress.revocation = Uuid::random();
  oldProgress.expectedEndpoints = oldProgress.acknowledgedEndpoints = 12;
  EcV2DrainProgress progress;
  ASSERT_OK(serde::deserialize(progress, serde::serialize(oldProgress)));
  EXPECT_EQ(serde::serialize(progress), serde::serialize(oldProgress));
  EXPECT_EQ(serde::toJsonString(progress), serde::toJsonString(oldProgress));
  EXPECT_EQ(progress.terminalEndpoints(), 12u);
  progress.acknowledgedEndpoints = 11;
  progress.retiredEndpoints = 1;
  EcV2DrainProgress restored;
  ASSERT_OK(serde::deserialize(restored, serde::serialize(progress)));
  EXPECT_EQ(restored.acknowledgedEndpoints, 11);
  EXPECT_EQ(restored.retiredEndpoints, 1);
  EXPECT_EQ(restored.terminalEndpoints(), 12u);
  EcV2DrainV1 old;
  old.identity.object = {InodeId(17), Uuid::random()};
  old.identity.owner = {flat::Uid(11), Uuid::random()};
  old.identity.scopeId = Uuid::random();
  old.identity.objectEpoch = old.identity.generation = old.identity.revision = 1;
  old.identity.clusterAuthority = Uuid::random();
  old.identity.revocationId = Uuid::random();
  old.identity.endpoints.count = 24;
  for (size_t i = 0; i < 24; ++i)
    old.identity.endpoints.endpoints[i] = {{storage::ChainId(100 + i), storage::TargetId(200 + i), flat::NodeId(9)},
                                          Uuid::random(), Uuid::random()};
  auto digest = ec_v2_lifecycle::setDigest(old.identity.endpoints);
  ASSERT_OK(digest);
  old.identity.endpoints.digest = *digest;
  const auto oldBytes = serde::serialize(old);
  EcV2DrainRecord decoded;
  ASSERT_OK(serde::deserialize(decoded, oldBytes));
  EXPECT_EQ(serde::serialize(decoded), oldBytes);
  EXPECT_EQ(decoded.terminalUse, EcV2DrainUse::AckOnly);
  ASSERT_OK(ec_v2_lifecycle::drainValid(decoded));
  decoded.version = kEcV2RetirementDrainVersion;
  decoded.terminalUse = EcV2DrainUse::ReadRelease;
  for (auto &slot : decoded.retirements) {
    slot.emplace();
    slot->retirementId = Uuid::random();
    slot->completionDigest.fill(0x31);
  }
  ASSERT_OK(ec_v2_lifecycle::drainValid(decoded));
  const auto bytes = serde::serialize(decoded);
  EXPECT_LT(bytes.size() - oldBytes.size(), 1600u);
  EXPECT_LT(bytes.size(), 64u << 10);
  EcV2DrainV1 oldReader;
  ASSERT_OK(serde::deserialize(oldReader, bytes));
  EXPECT_NE(oldReader.version, kEcV2LifecycleVersion);  // The old catalog's explicit version gate refuses it.
  EcV2DrainRecord roundtrip;
  ASSERT_OK(serde::deserialize(roundtrip, bytes));
  EXPECT_EQ(serde::serialize(roundtrip), bytes);
  auto invalid = decoded;
  invalid.observations[0].emplace();
  ASSERT_ERROR(ec_v2_lifecycle::drainValid(invalid), StatusCode::kDataCorruption);
  invalid = decoded;
  invalid.state = EcV2DrainState::Published;
  ASSERT_ERROR(ec_v2_lifecycle::drainValid(invalid), StatusCode::kDataCorruption);
  invalid = decoded;
  invalid.identity.endpoints.count = 23;
  ASSERT_ERROR(ec_v2_lifecycle::drainValid(invalid), StatusCode::kDataCorruption);
  invalid.identity.endpoints.count = 25;
  ASSERT_ERROR(ec_v2_lifecycle::drainValid(invalid), StatusCode::kDataCorruption);
  // Fixed array decoder rejects shortened/extended wire arrays independently
  // of the record's endpoint count. Build their array prefix through Serde.
  for (uint64_t count : {23, 25}) {
    serde::Out<DownwardBytes<net::Allocator<>>> out;
    out.arrayBegin();
    for (uint64_t n = 0; n < count; ++n) serde::serialize(std::optional<EcTargetRetirementRef>{}, out);
    out.arrayEnd(count);
    std::array<std::optional<EcTargetRetirementRef>, 24> slots;
    ASSERT_ERROR(serde::deserialize(slots, out.bytes().toString()), StatusCode::kInvalidFormat);
  }
}

TEST_F(TestEcFileTree, RealFdbEightDataRetirementRangeRevalidatesAndFitsSingleBudget) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  uniqueTreeReadInode(f);
  f.birth.shardBytes = 384u << 10;
  ASSERT_OK(f.initialize(true));
  SourcePinTargetFixture target;
  EcV2AllocationBindings physical;
  for (size_t n = 0; n < 8; ++n) {
    auto metadata = f.metadata(n);
    ASSERT_OK(metadata);
    if (!n) {
      ASSERT_NO_FATAL_FAILURE(target.initialize(*metadata));
      physical = metadata->allocations;
    } else {
      for (size_t i = 0; i < 12; ++i) {
        metadata->allocations[i].engineUuid = physical[i].engineUuid;
        metadata->allocations[i].targetIncarnation = physical[i].targetIncarnation;
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
  auto intent = treeReadIntent(f, *opening, 0, uint64_t(f.birth.shardBytes) * 10 * 8);
  auto acquired = runTreeRead(f, [&](Tx &t) { return TreeReads::acquire(t, intent); });
  ASSERT_OK(acquired);
  ASSERT_EQ(acquired->stripeCount, 8);
  std::array<Uuid, 8> revocations;
  for (auto &id : revocations) id = Uuid::random();
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::startClosing(t, intent, target.authority, revocations); }));
  std::array<EcTargetRetirementRecord, 12> retirements;
  for (size_t i = 0; i < 12; ++i) {
    auto retired = retireTestTarget(f, target, physical[i].endpoint());
    ASSERT_OK(retired);
    ASSERT_TRUE(retired->completion);
    EXPECT_LE(serde::serialize(*retired).size(), Retirements::kMaximumRecordBytes);
    retirements[i] = *retired;
  }
  for (size_t n = 0; n < 8; ++n) {
    for (size_t i = 0; i < 12; ++i) {
      if (n == 7 && i == 11)
        ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }),
                     StatusCode::kTokenStale);
      auto attached = runTreeRead(f, [&](Tx &t) { return TreeReads::recordRetirement(t, intent, n, i, *target.key); });
      ASSERT_OK(attached);
      ASSERT_TRUE(attached->retirements[i]);
      EXPECT_FALSE(attached->observations[i]);
      EXPECT_LT(serde::serialize(*attached).size(), 64u << 10);
    }
  }
  auto finish = runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); });
  ASSERT_OK(finish);
  EXPECT_EQ(finish->state, EcTreeReadState::Released);
  EXPECT_LE(f.lastUsage.totalBytes(), 2u << 20);
  EXPECT_LE(f.lastUsage.keyOperations, 8192u);
  RecordProperty("retirement_range_finish_bytes", std::to_string(f.lastUsage.totalBytes()));
  RecordProperty("retirement_range_finish_operations", std::to_string(f.lastUsage.keyOperations));
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }));
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }));
  for (size_t n = 0; n < 8; ++n) {
    auto manifest = f.run([&](Tx &t) { return EcCatalog::getManifest(t, f.birth.object, n, 1); });
    ASSERT_OK(manifest);
    EXPECT_EQ(manifest->pins, 0);
    for (const auto &fragment : manifest->manifest.fragments) {
      auto count = f.run([&](Tx &t) -> CoTryTask<EcTreeSourceAllocationRecord> {
        auto key = allocationKey(kv::KeyPrefix::EcTreeSourceAllocation, fragment.identity);
        CO_RETURN_ON_ERROR(key);
        co_return co_await require<EcTreeSourceAllocationRecord>(t, *key);
      });
      ASSERT_OK(count);
      EXPECT_EQ(count->registered, 1);
      EXPECT_EQ(count->released, 1);
      EXPECT_EQ(count->active, 0);
    }
  }
  const auto key = retirementRecordKey(physical[11].endpoint());
  ASSERT_OK(f.run([&](Tx &t) { return t.clear(key); }));
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }), StatusCode::kDataCorruption);
  ASSERT_OK(f.run([&](Tx &t) { return store(t, key, retirements[11]); }));
  auto corrupt = retirements[11];
  corrupt.completion->observation.claims.bootNonce = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return store(t, key, corrupt); }));
  ASSERT_ERROR(runTreeRead(f, [&](Tx &t) { return TreeReads::query(t, intent); }), StatusCode::kDataCorruption);
  ASSERT_OK(f.run([&](Tx &t) { return store(t, key, retirements[11]); }));
  ASSERT_OK(runTreeRead(f, [&](Tx &t) { return TreeReads::finishRelease(t, intent, *target.key); }));
}

TEST_F(TestEcFileTree, RealFdbRepairTwentyTwoRetirementsFencePublicationAndRevalidateGc) {
  if (!std::getenv("EC_CATALOG_TEST_CLUSTER")) GTEST_SKIP() << "private FDB is required";
  Fixture f;
  f.birth.shardBytes = storage::kEcFragmentRpcMaxBytes;
  uint64_t randomInode = 0;
  const auto randomId = Uuid::random();
  std::memcpy(&randomInode, randomId.data, sizeof(randomInode));
  f.birth.object.inode = InodeId((randomInode & InodeId::normalMax().u64()) | 0x101);
  ASSERT_OK(f.initialize(true));
  auto metadata = f.metadata();
  ASSERT_OK(metadata);
  SourcePinTargetFixture targets;
  ASSERT_NO_FATAL_FAILURE(targets.initialize(*metadata));
  for (const auto &fragment : metadata->manifest.fragments) EXPECT_EQ(fragment.integrity.blockCount, 16);
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
  flat::UserInfo user(f.birth.creator.uid, flat::Gid(103));
  EcFileOpenIntent opening;
  opening.object = f.birth.object;
  opening.birth = f.birth.createRequest;
  opening.owner = f.birth.creator;
  opening.session = Uuid::random();
  opening.openRequest = Uuid::random();
  opening.rights = kEcSessionRead | kEcSessionWrite;
  ASSERT_OK(f.run([&](Tx &t) -> CoTryTask<Void> {
    auto old = co_await Inode::load(t, f.birth.object.inode);
    CO_RETURN_ON_ERROR(old);
    if (*old) co_return makeError(StatusCode::kTokenDuplicated);
    EcManifestLayoutV1 ec;
    ec.incarnation = f.birth.object.incarnation;
    ec.shardBytes = f.birth.shardBytes;
    Layout layout{ChainTableId(0), ChainTableVersion(0), 0, 0, ec};
    auto inode =
        Inode::newFile(f.birth.object.inode, Acl(user.uid, user.gid, Permission(0600)), layout, UtcClock::now());
    inode.asFile().length = root->visibleLength;
    CO_RETURN_ON_ERROR(co_await inode.store(t));
    auto object = co_await EcCatalog::getObject(t, f.birth.object);
    CO_RETURN_ON_ERROR(object);
    object->nextGeneration = object->nextRevision = 2;
    CO_RETURN_ON_ERROR(co_await store(t, objectKey(kv::KeyPrefix::EcObject, f.birth.object), *object));
    auto opened = co_await EcFileSessionCatalog::open(t, user, opening);
    CO_RETURN_ON_ERROR(opened);
    co_return Void{};
  }));
  EcFileRepairIntent intent;
  intent.object = f.birth.object;
  intent.owner = f.birth.creator;
  intent.session = opening.session;
  intent.request = Uuid::random();
  intent.operation = Uuid::random();
  intent.child = Uuid::random();
  intent.sourcePin = Uuid::random();
  intent.expectedRoot = root->root;
  intent.expectedSequence = root->sequence;
  intent.expectedEpoch = root->epoch;
  intent.replacementMask = 3;
  intent.selection.planId = Uuid::random();
  intent.selection.maxBlocksInFlight = 4;
  for (size_t n = 0; n < 10; ++n) intent.selection.sourceOrder[n] = uint8_t(n + 2);
  for (auto &id : intent.nodeIds) id = Uuid::random();
  size_t maximumBytes = 0, maximumKeys = 0, maximumMutationConflict = 0;
  const auto measured = [&] {
    maximumBytes = std::max(maximumBytes, f.lastUsage.totalBytes());
    maximumKeys = std::max(maximumKeys, f.lastUsage.keyOperations);
    maximumMutationConflict = std::max(maximumMutationConflict, f.lastUsage.mutationAndConflictBytes());
    EXPECT_LE(f.lastUsage.totalBytes(), 2u << 20);
    EXPECT_LE(f.lastUsage.keyOperations, 8192);
  };
  auto accepted = f.runProfile([&](Tx &t) { return EcFileRepairCatalog::begin(t, intent); }, Tx::Profile::Repair);
  ASSERT_OK(accepted);
  measured();
  EcFileExecutionCatalog::TrustedPool fresh;
  for (size_t n = 0; n < 12; ++n) {
    storage::CreateTargetReq create;
    create.chainId = storage::ChainId(300 + n);
    create.targetId = storage::TargetId(400 + n);
    create.onlyChunkEngine = true;
    ASSERT_OK(targets.targets->create(create, true));
    auto found = targets.map.getByTargetId(create.targetId);
    ASSERT_OK(found);
    auto state = (*found)->storageTarget->ecScopeState();
    ASSERT_OK(state);
    fresh[n].placement = {create.chainId, create.targetId, flat::NodeId(9)};
    std::copy(state->second.engine.begin(), state->second.engine.end(), std::begin(fresh[n].engineUuid.data));
    std::copy(state->second.incarnation.begin(), state->second.incarnation.end(),
              std::begin(fresh[n].targetIncarnation.data));
  }
  auto bound = f.runProfile(
      [&](Tx &t) -> CoTryTask<EcFileExecutionObservation> {
        auto reserved = co_await EcFileExecutionCatalog::reserveExecution(t,
                                                                          intent.owner,
                                                                          intent.object,
                                                                          intent.child,
                                                                          fresh,
                                                                          0,
                                                                          EcFileExecutionOwner::Repair);
        CO_RETURN_ON_ERROR(reserved);
        co_return co_await EcFileExecutionCatalog::bindRepairOutput(t, intent.owner, intent.object, intent.child);
      },
      Tx::Profile::Repair);
  ASSERT_OK(bound);
  measured();
  ASSERT_EQ(bound->record.endpoints.count, 22);
  ASSERT_TRUE(bound->record.allocations);
  for (const auto &allocation : *bound->record.allocations) EXPECT_EQ(allocation.fragment.integrity.blockCount, 16);

  // The target proof may exist while the child is still Planned; it must not
  // acquire a scope reference until the actual typed fence commits.
  auto first = retireTestTarget(f, targets, fresh[0]);
  ASSERT_OK(first);
  ASSERT_ERROR(f.runProfile([&](Tx &t) {
    return EcFileExecutionCatalog::recordRetirement(t, intent.owner, intent.object, intent.child, 0, *targets.key);
  }, Tx::Profile::Repair), StatusCode::kTokenStale);
  const auto revoke = Uuid::random();
  auto closing = f.runProfile([&](Tx &t) {
    return EcFileExecutionCatalog::startCancelClosing(t, intent.owner, intent.object, intent.child,
                                                      targets.authority, revoke);
  }, Tx::Profile::Repair);
  ASSERT_OK(closing);
  std::array<EcTargetRetirementRecord, 22> completed;
  completed[0] = *first;
  for (size_t n = 0; n < 22; ++n) {
    if (n) {
      auto done = retireTestTarget(f, targets, closing->identity.endpoints.endpoints[n]);
      ASSERT_OK(done);
      completed[n] = *done;
    }
    if (n == 21)
      ASSERT_ERROR(f.runProfile([&](Tx &t) {
        return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, *targets.key);
      }, Tx::Profile::Repair), StatusCode::kTokenStale);
    auto saved = f.runProfile([&](Tx &t) {
      return EcFileExecutionCatalog::recordRetirement(t, intent.owner, intent.object, intent.child, n, *targets.key);
    }, Tx::Profile::Repair);
    ASSERT_OK(saved);
    measured();
    EXPECT_TRUE(saved->retirements[n]);
    EXPECT_FALSE(saved->observations[n]);
  }
  auto finished = f.runProfile([&](Tx &t) {
    return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, *targets.key);
  }, Tx::Profile::Repair);
  ASSERT_OK(finished);
  measured();
  ASSERT_EQ(finished->record.state, EcFileExecutionState::Aborted);
  ASSERT_EQ(finished->record.drain->terminalUse, EcV2DrainUse::AbortOnly);
  EXPECT_LT(serde::serialize(finished->record).size(), 64u << 10);
  // Publication uses an independent purpose gate, even with all 22 valid
  // retirement observations and a bound full descriptor array.
  ASSERT_ERROR(f.runProfile([&](Tx &t) {
    return verifyEcTerminalEvidence(t, *finished->record.drain, *targets.key, EcTerminalPurpose::Publication);
  }, Tx::Profile::Repair), StatusCode::kTokenStale);
  ASSERT_ERROR(f.runProfile([&](Tx &t) {
    return EcFileRepairCatalog::requireExecutable(t, intent.owner, intent.object, intent.child);
  }, Tx::Profile::Repair), StatusCode::kTokenStale);
  auto replay = f.runProfile([&](Tx &t) {
    return EcFileExecutionCatalog::finishDrain(t, intent.owner, intent.object, intent.child, *targets.key);
  }, Tx::Profile::Repair);
  ASSERT_OK(replay);
  measured();
  EXPECT_EQ(serde::serialize(replay->record), serde::serialize(finished->record));
  const auto &child = accepted->child;
  EcTreeSourcePinIntent source;
  source.object = child.intent.object;
  source.owner = child.owner;
  source.session = child.session;
  source.parent = child.intent.parent;
  source.child = child.intent.child;
  source.pin = child.intent.sourcePin;
  source.root = child.sourceRoot;
  source.sequence = child.sourceSequence;
  source.epoch = child.epoch;
  source.lengthAtPlan = child.lengthAtPlan;
  source.slot = child.source;
  auto pinned = f.runProfile([&](Tx &t) { return SourcePins::query(t, source); }, Tx::Profile::Repair);
  ASSERT_OK(pinned);
  ASSERT_EQ(pinned->state, EcTreeSourcePinState::Active);  // Independent original twelve are not released.
  const auto identity = (*finished->record.allocations)[0].fragment.identity;
  const auto claimId = Uuid::random();
  auto claim = f.runProfile([&](Tx &t) { return EcExactGcCatalog::claim(t, intent.object, identity, claimId, *targets.key); });
  ASSERT_OK(claim);
  measured();
  const auto lostKey = retirementRecordKey(closing->identity.endpoints.endpoints[21]);
  ASSERT_OK(f.run([&](Tx &t) { return t.clear(lostKey); }));
  ASSERT_ERROR(f.runProfile([&](Tx &t) { return EcExactGcCatalog::getClaim(t, intent.object, identity); }),
               StatusCode::kDataCorruption);
  ASSERT_OK(f.run([&](Tx &t) { return store(t, lostKey, completed[21]); }));
  auto changed = completed[21];
  changed.completion->observation.claims.bootNonce = Uuid::random();
  ASSERT_OK(f.run([&](Tx &t) { return store(t, lostKey, changed); }));
  ASSERT_ERROR(f.runProfile([&](Tx &t) { return EcExactGcCatalog::claim(t, intent.object, identity, claimId, *targets.key); }),
               StatusCode::kDataCorruption);
  ASSERT_OK(f.run([&](Tx &t) { return store(t, lostKey, completed[21]); }));
  auto again = f.runProfile([&](Tx &t) { return EcExactGcCatalog::getClaim(t, intent.object, identity); });
  ASSERT_OK(again);
  ASSERT_TRUE(*again);
  EXPECT_EQ(serde::serialize(**again), serde::serialize(*claim));
  measured();
  // Source T0/T2 is separate. Only the two unselected source targets still need
  // their own completed observation; the ten prior completions are immutable.
  for (size_t n = 0; n < 2; ++n) ASSERT_OK(retireTestTarget(f, targets, metadata->allocations[n].endpoint()));
  const auto sourceRevoke = Uuid::random();
  ASSERT_OK(f.runProfile([&](Tx &t) {
    return SourcePins::startClosing(t, source, targets.authority, sourceRevoke);
  }, Tx::Profile::Repair));
  for (size_t n = 0; n < 12; ++n)
    ASSERT_OK(f.runProfile([&](Tx &t) { return SourcePins::recordRetirement(t, source, n, *targets.key); },
                          Tx::Profile::Repair));
  auto released = f.runProfile([&](Tx &t) { return SourcePins::finishRelease(t, source, *targets.key); },
                               Tx::Profile::Repair);
  ASSERT_OK(released);
  measured();
  EXPECT_EQ(released->state, EcTreeSourcePinState::Released);
  // Releasing a source later must not change the fixed output origin claim.
  auto afterSource = f.runProfile([&](Tx &t) { return EcExactGcCatalog::getClaim(t, intent.object, identity); });
  ASSERT_OK(afterSource);
  ASSERT_TRUE(*afterSource);
  EXPECT_EQ(serde::serialize(**afterSource), serde::serialize(*claim));
  RecordProperty("retirement_repair_22_max_bytes", std::to_string(maximumBytes));
  RecordProperty("retirement_repair_22_max_operations", std::to_string(maximumKeys));
  RecordProperty("scope", "real FDB and persistent target observations; metadata-only assembled Data; no physical GC");
}
