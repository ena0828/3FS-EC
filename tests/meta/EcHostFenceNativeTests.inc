// Real FDB and authenticated Meta RPC; the independent F signer below is a
// test-only oracle. OS/cgroup isolation is separately exercised by the hosted
// provider acceptance and is not inferred from these protocol tests.
class TestEcHostFenceNative : public TestEcTargetRetirementNative {
 protected:
  void SetUp() override {
    TestEcTargetRetirementNative::SetUp();
    if (HasFatalFailure() || IsSkipped()) return;
    std::array<uint8_t, 32> seed{};
    seed.fill(0x71);  // Public test material; never a deployed provider key.
    signer_.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    ASSERT_NE(signer_, nullptr);
    size_t size = publicKey_.size();
    ASSERT_EQ(EVP_PKEY_get_raw_public_key(signer_.get(), publicKey_.data(), &size), 1);
    ASSERT_EQ(size, publicKey_.size());
    const auto path = traces_.path() / "host-fence-test.pub";
    {
      std::ofstream file(path.string(), std::ios::binary | std::ios::trunc);
      file.write(reinterpret_cast<const char *>(publicKey_.data()), publicKey_.size());
      ASSERT_TRUE(file.good());
    }
    metaConfig_.set_enable_ec_host_fence(true);
    metaConfig_.set_ec_host_fence_provider_id(provider_.toHexString());
    metaConfig_.set_ec_host_fence_public_key_file(path);
    ASSERT_NO_FATAL_FAILURE(restartCoordinator());
    RecordProperty("external_fence_scope", "real Meta/FDB; Ed25519 test oracle, not OS isolation proof");
  }
  Result<PrepareEcTargetRetirementReq> external(size_t slot = 0) {
    CHECK_RESULT(req, retirement(slot));
    req.mode = EcTargetRetirementMode::HostExecutionFence;
    req.externalBinding.emplace();
    req.externalBinding->providerId = provider_;
    req.externalBinding->enrollmentId = Uuid::random();
    req.externalBinding->resourceGeneration = Uuid::random();
    req.externalBinding->bindingDigest.fill(0x34);
    return req;
  }
  EcTargetRetirementIntent externalIntent(const PrepareEcTargetRetirementReq &req) {
    auto value = intent(req);
    value.version = 2;
    return value;
  }
  QueryEcTargetRetirementReq externalQuery(const PrepareEcTargetRetirementReq &req) {
    auto value = query(req);
    value.externalEvidence.clear();
    return value;
  }
  Result<String> proof(const PrepareEcTargetRetirementReq &req, uint8_t denyByte = 0x56) {
    storage::EcSha256 deny{};
    deny.fill(denyByte);
    CHECK_RESULT(claims, EcHostFence::claims(externalIntent(req), *req.externalBinding, deny, 1));
    String result(reinterpret_cast<const char *>(claims.data()), claims.size());
    result.resize(kEcHostFenceCertificateBytes);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t size = 64;
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, signer_.get()) != 1 ||
        EVP_DigestSign(ctx.get(), reinterpret_cast<uint8_t *>(result.data()) + claims.size(), &size,
                       claims.data(), claims.size()) != 1 || size != 64)
      return makeError(StatusCode::kIOError);
    return result;
  }
  Uuid provider_ = Uuid::random();
  EcHostFencePublicKey publicKey_{};
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> signer_{nullptr, EVP_PKEY_free};
};

TEST_F(TestEcHostFenceNative, ProofIdentityReplayAndRestartRemainImmutable) {
  auto req = external();
  ASSERT_OK(req);
  auto evidence = proof(*req);
  ASSERT_OK(evidence);
  ASSERT_EQ(evidence->size(), 312u);
  // Missing is never a completion; importing cannot silently prepare either.
  ASSERT_ERROR(blockingWait(metaClient_->queryEcTargetRetirement(externalQuery(*req))), StatusCode::kTokenStale);
  auto importRequest = *req;
  importRequest.externalEvidence = *evidence;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(importRequest)), StatusCode::kTokenStale);
  auto accepted = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
  ASSERT_OK(accepted);
  ASSERT_EQ(accepted->mode, EcTargetRetirementMode::HostExecutionFence);
  ASSERT_EQ(accepted->stage, EcTargetRetirementStage::Prepared);
  ASSERT_EQ(accepted->intent.version, 2);
  ASSERT_FALSE(accepted->external);
  ASSERT_EQ(accepted->completionDigest, storage::EcSha256{});
  ASSERT_TRUE(serde::equals(*accepted->externalBinding, *req->externalBinding));
  auto key = controlKey();
  ASSERT_OK(key);
  auto txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(EcTargetRetirementCatalog::requireAssignable(*txn, req->endpoint)), StatusCode::kTokenStale);
  auto incomplete = blockingWait(EcTargetRetirementCatalog::findCompleted(*txn, req->endpoint, authority_, **key));
  ASSERT_OK(incomplete);
  ASSERT_FALSE(*incomplete);
  auto pending = blockingWait(metaClient_->queryEcTargetRetirement(externalQuery(*req)));
  ASSERT_OK(pending);
  ASSERT_TRUE(serde::equals(*accepted, *pending));

  auto damaged = importRequest;
  damaged.externalEvidence.back() ^= 1;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(damaged)), StatusCode::kAuthenticationFail);
  // Each signed field is checked against the immutable original, not accepted
  // merely because some independent provider signed a different resource.
  for (size_t field = 0; field != 7; ++field) {
    SCOPED_TRACE(field);
    auto changed = *req;
    if (field == 0) changed.externalBinding->providerId = Uuid::random();
    if (field == 1) changed.externalBinding->enrollmentId = Uuid::random();
    if (field == 2) changed.externalBinding->resourceGeneration = Uuid::random();
    if (field == 3) changed.externalBinding->bindingDigest[0] ^= 1;
    if (field == 4) changed.endpoint.targetIncarnation = Uuid::random();
    if (field == 5) changed.retirementId = Uuid::random();
    if (field == 6) changed.uuid = Uuid::random();
    auto otherProof = proof(changed);
    ASSERT_OK(otherProof);
    ASSERT_TRUE(EcHostFence::verify(*otherProof, externalIntent(*req), *req->externalBinding, publicKey_).hasError());
    changed.externalEvidence = *otherProof;
    ASSERT_TRUE(blockingWait(metaClient_->prepareEcTargetRetirement(changed)).hasError());
  }
  auto otherKey = publicKey_;
  otherKey[0] ^= 1;
  ASSERT_TRUE(EcHostFence::verify(*evidence, externalIntent(*req), *req->externalBinding, otherKey).hasError());
  auto wrongOwner = externalIntent(*req);
  wrongOwner.owner.client = Uuid::random();
  ASSERT_ERROR(EcHostFence::verify(*evidence, wrongOwner, *req->externalBinding, publicKey_), StatusCode::kTokenMismatch);
  wrongOwner = externalIntent(*req);
  wrongOwner.owner.uid = flat::Uid(1);
  ASSERT_TRUE(EcHostFence::verify(*evidence, wrongOwner, *req->externalBinding, publicKey_).hasError());
  metaConfig_.set_enable_ec_host_fence(false);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(importRequest)), StatusCode::kNotImplemented);
  metaConfig_.set_enable_ec_host_fence(true);

  // Actual committed Meta response loss, then Query with the original IDs.
  ASSERT_NO_FATAL_FAILURE(installDropService());
  {
    std::lock_guard lock(fault.mutex);
    fault.armed = req->uuid;
  }
  ASSERT_TRUE(blockingWait(metaClient_->prepareEcTargetRetirement(importRequest)).hasError());
  {
    std::lock_guard lock(fault.mutex);
    ASSERT_EQ(fault.calls, 1u);
    ASSERT_EQ(fault.dropped, 1u);
  }
  auto completed = blockingWait(metaClient_->queryEcTargetRetirement(externalQuery(*req)));
  ASSERT_OK(completed);
  ASSERT_EQ(completed->stage, EcTargetRetirementStage::HostExecutionFenced);
  ASSERT_TRUE(completed->external && completed->external->valid());
  ASSERT_NE(completed->completionDigest, storage::EcSha256{});
  txn = kv_->createReadWriteTransaction();
  auto stored = blockingWait(EcTargetRetirementCatalog::get(*txn, externalIntent(*req)));
  ASSERT_OK(stored);
  ASSERT_TRUE(stored->hostFence);
  ASSERT_FALSE(stored->completion);
  const auto bytes = serde::serialize(*stored->hostFence);
  ASSERT_LT(bytes.size(), EcTargetRetirementCatalog::kMaximumRecordBytes);
  EcTargetRetirementRecord oldReader;
  const auto decoded = serde::deserialize(oldReader, bytes);
  ASSERT_TRUE(!decoded || oldReader.version != 1 || serde::serialize(oldReader) != bytes);
  const EcTargetRetirementRef ref{req->retirementId, completed->completionDigest};
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::verifyStoredReference(*txn, req->endpoint, authority_, ref)));
  ASSERT_ERROR(blockingWait(EcTargetRetirementCatalog::getVerifiedCompletion(*txn, req->endpoint, authority_, ref, **key)),
               StatusCode::kNotImplemented);  // Never a disk absence/Collected witness.
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  metaConfig_.set_readonly(true);
  auto replay = blockingWait(metaClient_->queryEcTargetRetirement(externalQuery(*req)));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*completed, *replay));
  metaConfig_.set_readonly(false);
  auto repeated = blockingWait(metaClient_->prepareEcTargetRetirement(importRequest));
  ASSERT_OK(repeated);
  ASSERT_TRUE(serde::equals(*completed, *repeated));
  auto changedProof = proof(*req, 0x57);
  ASSERT_OK(changedProof);
  importRequest.externalEvidence = *changedProof;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(importRequest)), StatusCode::kTokenMismatch);
  auto wrongMode = query(*req);
  wrongMode.mode = EcTargetRetirementMode::Cooperative;
  wrongMode.externalBinding.reset();
  ASSERT_ERROR(blockingWait(metaClient_->queryEcTargetRetirement(wrongMode)), StatusCode::kTokenMismatch);
  txn = kv_->createReadWriteTransaction();
  auto after = blockingWait(EcTargetRetirementCatalog::get(*txn, externalIntent(*req)));
  ASSERT_OK(after);
  ASSERT_EQ(bytes, serde::serialize(*after->hostFence));
}

TEST_F(TestEcHostFenceNative, ClosedUnavailableTargetsReleaseReadAndAbortButNeverPublish) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "external-retirement-terminal-union");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 451));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  ASSERT_OK(blockingWait(metaClient_->publishEcMutationV2(original.publish)));
  auto read = readRequest(object);
  auto pinned = blockingWait(metaClient_->acquireEcReadV2(read));
  ASSERT_OK(pinned);
  Mutation unfinished;
  ASSERT_NO_FATAL_FAILURE(prepare(unfinished, object, 1, 453));
  ASSERT_NO_FATAL_FAILURE(writeFragments(unfinished));
  // Eleven genuine cooperative completions and one independent evidence type.
  // The final close must not need the now unavailable old Storage TCP service.
  for (size_t slot = 1; slot != 12; ++slot) {
    auto req = retirement(slot);
    ASSERT_OK(req);
    auto done = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
    ASSERT_OK(done);
    ASSERT_EQ(done->stage, EcTargetRetirementStage::Completed);
  }
  auto req = external();
  ASSERT_OK(req);
  ASSERT_OK(blockingWait(metaClient_->prepareEcTargetRetirement(*req)));
  auto evidence = proof(*req);
  ASSERT_OK(evidence);
  storageServer_->stopAndJoin();
  storageServer_.reset();
  req->externalEvidence = *evidence;
  auto fenced = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
  ASSERT_OK(fenced);
  ASSERT_EQ(fenced->stage, EcTargetRetirementStage::HostExecutionFenced);
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = unfinished.begin.operation;
  auto aborted = blockingWait(metaClient_->cancelEcMutationV2(cancel));
  ASSERT_OK(aborted);
  ASSERT_EQ(aborted->record.state, EcOperationState::Aborted);
  ASSERT_TRUE(aborted->drain);
  ASSERT_EQ(aborted->drain->acknowledgedEndpoints, 0);
  ASSERT_EQ(aborted->drain->retiredEndpoints, 12);
  ASSERT_TRUE(blockingWait(metaClient_->publishEcMutationV2(unfinished.publish)).hasError());
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = read.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(released);
  ASSERT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_EQ(released->drain.acknowledgedEndpoints, 0);
  ASSERT_EQ(released->drain.retiredEndpoints, 12);
  ASSERT_NO_FATAL_FAILURE(checkPin(object, read.pin, true));
  auto key = controlKey();
  ASSERT_OK(key);
  auto txn = kv_->createReadWriteTransaction();
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  auto drain = blockingWait(EcV2DrainCatalog::get(*txn, object, storage::EcGrantScope::WriteOperation,
                                               unfinished.begin.operation, owner));
  ASSERT_OK(drain);
  ASSERT_TRUE(*drain);
  ASSERT_OK(blockingWait(verifyEcTerminalEvidence(*txn, **drain, **key, EcTerminalPurpose::FencedAbort)));
  ASSERT_ERROR(blockingWait(verifyEcTerminalEvidence(*txn, **drain, **key, EcTerminalPurpose::Publication)),
               StatusCode::kTokenStale);
  size_t externalCount = 0, cooperativeCount = 0;
  for (size_t i = 0; i != (**drain).identity.endpoints.count; ++i) {
    ASSERT_TRUE((**drain).retirements[i]);
    ASSERT_FALSE((**drain).observations[i]);
    const auto &ep = (**drain).identity.endpoints.endpoints[i];
    const auto &ref = *(**drain).retirements[i];
    ASSERT_OK(blockingWait(EcTargetRetirementCatalog::verifyStoredReference(*txn, ep, authority_, ref)));
    if (ep == req->endpoint) ++externalCount; else ++cooperativeCount;
  }
  ASSERT_EQ(externalCount, 1u);
  ASSERT_EQ(cooperativeCount, 11u);
  auto history = blockingWait(EcV2GcCatalog::getAllocation(*txn, object, pinned->manifest.fragments[0].identity));
  ASSERT_OK(history);
  ASSERT_EQ(history->active, 0);
  ASSERT_EQ(history->registered, history->released);
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  auto replay = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*released, *replay));
}
