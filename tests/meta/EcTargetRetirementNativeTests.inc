// Included in the existing real FDB / Meta TCP / Storage TCP fixture TU.
struct TargetRetirementReplyDrop {
  std::mutex mutex;
  Uuid armed = Uuid::zero();
  size_t calls = 0;
  size_t dropped = 0;
  std::optional<EcTargetRetirementRsp> accepted;
};
class DropTargetRetirementMetaService : public MetaSerdeService {
 public:
  DropTargetRetirementMetaService(MetaOperator &meta, TargetRetirementReplyDrop &fault)
      : MetaSerdeService(meta), fault_(fault) {}
  CoTryTask<EcTargetRetirementRsp> prepareEcTargetRetirement(serde::CallContext &ctx,
                                                            const PrepareEcTargetRetirementReq &req) {
    {
      std::lock_guard lock(fault_.mutex);
      ++fault_.calls;
    }
    auto result = co_await MetaSerdeService::prepareEcTargetRetirement(ctx, req);
    bool drop = false;
    if (result) {
      std::lock_guard lock(fault_.mutex);
      if (fault_.armed == req.uuid) {
        fault_.armed = Uuid::zero();
        fault_.accepted = *result;
        ++fault_.dropped;
        drop = true;
      }
    }
    // Real Meta intent commit and actual Storage control exchange finished.
    // Invalidate the transport before serializing the successful response.
    if (drop) ctx.transport()->invalidate(false);
    co_return result;
  }

 protected:
  friend struct ::hf3fs::refl::Helper;
  template <class U = DropTargetRetirementMetaService>
  static auto CollectField(::hf3fs::refl::Rank<>) -> refl::Helper::FieldInfoList<MetaSerde<U>>;

 private:
  TargetRetirementReplyDrop &fault_;
};

class TestEcTargetRetirementNative : public TestEcV2NativeLifecycle {
 protected:
  bool enableTargetRetirement() const override { return true; }
  Result<PrepareEcTargetRetirementReq> retirement(size_t slot = 0) {
    auto txn = kv_->createReadWriteTransaction();
    core::UserStore store;
    auto root = blockingWait(store.getUser(*txn, flat::Uid{0}));
    RETURN_ON_ERROR(root);
    if (!*root) return makeError(StatusCode::kAuthenticationFail);
    auto req = request<PrepareEcTargetRetirementReq>();
    req.user = UserInfo{(**root).uid, (**root).gid, (**root).token};
    const auto &cfg = metaConfig_.ec_targets(slot);
    auto engine = Uuid::fromHexString(cfg.engine_uuid());
    auto incarnation = Uuid::fromHexString(cfg.target_incarnation());
    RETURN_ON_ERROR(engine);
    RETURN_ON_ERROR(incarnation);
    req.endpoint = {cfg.placement(), *engine, *incarnation};
    req.retirementId = Uuid::random();
    return req;
  }
  QueryEcTargetRetirementReq query(const PrepareEcTargetRetirementReq &req) {
    QueryEcTargetRetirementReq q;
    static_cast<EcTargetRetirementReq &>(q) = req;
    return q;
  }
  EcTargetRetirementIntent intent(const PrepareEcTargetRetirementReq &req) {
    EcTargetRetirementIntent value;
    value.endpoint = req.endpoint;
    value.authority = authority_;
    value.retirementId = req.retirementId;
    value.owner = {req.user.uid, metaClientId_.uuid};
    value.requestId = req.uuid;
    return value;
  }
  Result<std::shared_ptr<const storage::EcScopeControlKey>> controlKey() {
    auto loaded = storage::EcScopeControlKey::loadFile(controlKeyPath_.string());
    RETURN_ON_ERROR(loaded);
    return std::shared_ptr<const storage::EcScopeControlKey>(std::move(*loaded));
  }
  void installDropService() {
    metaClient_->stop();
    metaClient_.reset();
    metaNet_->stopAndJoin();
    metaNet_.reset();
    metaServer_->stopAndJoin();
    metaServer_.reset();
    routing_ = std::make_shared<flat::RoutingInfo>(*routing_);
    ASSERT_NO_FATAL_FAILURE(startServer(metaServerConfig_,
                                        metaServer_,
                                        std::make_unique<DropTargetRetirementMetaService>(*meta_, fault),
                                        metaNode_, flat::NodeType::META, "MetaSerde"));
    routing_->routingInfoVersion = flat::RoutingInfoVersion(routing_->routingInfoVersion.toUnderType() + 1);
    fakeMgmtd_->setRoutingInfo(routing_);
    ASSERT_NO_FATAL_FAILURE(startMetaClient(metaClientId_));
  }
  TargetRetirementReplyDrop fault;
};

TEST_F(TestEcTargetRetirementNative, LostPrepareReplySameIdQueryAndFirstCompletionSurviveRestart) {
  auto req = retirement();
  ASSERT_OK(req);
  auto key = controlKey();
  ASSERT_OK(key);
  metaNetConfig_.set_default_send_retry_times(3);
  ASSERT_NO_FATAL_FAILURE(installDropService());
  auto target = components_->targetMap.getByTargetId(req->endpoint.placement.target);
  ASSERT_OK(target);
  auto scope = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(scope);
  storage::EcScopeBinding binding{};
  binding.target = scope->second;
  binding.kind = static_cast<uint8_t>(storage::EcGrantScope::ReadPin);
  binding.object.fill(7);
  binding.scope.fill(8);
  binding.owner_uid = user_.uid.toUnderType();
  std::copy(std::begin(metaClientId_.uuid.data), std::end(metaClientId_.uuid.data), binding.client_namespace.begin());
  ASSERT_OK(scope->first->prepare(binding));
  {
    auto held = scope->first->tryAdmit(binding);
    ASSERT_OK(held);
    {
      std::lock_guard lock(fault.mutex);
      fault.armed = req->uuid;
    }
    auto lost = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
    ASSERT_TRUE(lost.hasError());
    {
      std::lock_guard lock(fault.mutex);
      ASSERT_EQ(fault.calls, 1);  // one-attempt client, no invisible Prepare retry
      ASSERT_EQ(fault.dropped, 1);
      ASSERT_TRUE(fault.accepted);
      ASSERT_EQ(fault.accepted->stage, EcTargetRetirementStage::Prepared);
    }
    ASSERT_ERROR(scope->first->tryAdmit(binding), StatusCode::kTokenStale);
    auto pending = blockingWait(metaClient_->queryEcTargetRetirement(query(*req)));
    ASSERT_OK(pending);
    ASSERT_EQ(pending->stage, EcTargetRetirementStage::Prepared);
    ASSERT_EQ(pending->completionDigest, storage::EcSha256{});
    auto txn = kv_->createReadWriteTransaction();
    auto absent = blockingWait(EcTargetRetirementCatalog::findCompleted(*txn, req->endpoint, authority_, **key));
    ASSERT_OK(absent);
    ASSERT_FALSE(*absent);
    ASSERT_ERROR(blockingWait(EcTargetRetirementCatalog::requireAssignable(*txn, req->endpoint)), StatusCode::kTokenStale);
  }
  auto completed = blockingWait(metaClient_->queryEcTargetRetirement(query(*req)));
  ASSERT_OK(completed);
  ASSERT_EQ(completed->stage, EcTargetRetirementStage::Completed);
  ASSERT_NE(completed->completionDigest, storage::EcSha256{});
  auto txn = kv_->createReadWriteTransaction();
  auto first = blockingWait(EcTargetRetirementCatalog::get(*txn, intent(*req)));
  ASSERT_OK(first);
  ASSERT_TRUE(first->completion);
  ASSERT_TRUE(first->completion->observation.claims.durable);
  ASSERT_EQ(first->completion->observation.claims.inflight, 0);
  ASSERT_EQ(first->completion->observation.claims.state, storage::EcTargetRetirementState::LocalDataDrained);
  ASSERT_OK(storage::verifyEcTargetRetirementObservation(**key, first->completion->observation, first->completion->request));
  ASSERT_LT(serde::serialize(*first).size(), EcTargetRetirementCatalog::kMaximumRecordBytes);
  RecordProperty("target_retirement_record_bytes", std::to_string(serde::serialize(*first).size()));
  const EcTargetRetirementRef ref{req->retirementId, completed->completionDigest};
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::verifyReference(*txn, req->endpoint, authority_, ref, **key)));
  auto badRef = ref;
  badRef.completionDigest[0] ^= 1;
  ASSERT_ERROR(blockingWait(EcTargetRetirementCatalog::verifyReference(*txn, req->endpoint, authority_, badRef, **key)),
               StatusCode::kTokenMismatch);
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::verifyStoredReference(*txn, req->endpoint, authority_, ref)));
  // A later, independently signed real Query exchange cannot replace the first
  // immutable completion, even though its nonce and authenticated bytes differ.
  auto laterClaims = first->completion->request.claims;
  laterClaims.action = storage::EcTargetRetirementAction::Query;
  laterClaims.nonce = Uuid::random();
  laterClaims.issuedAtSeconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  laterClaims.expiresAtSeconds = laterClaims.issuedAtSeconds + 60;
  auto laterRequest = storage::signEcTargetRetirement(**key, laterClaims, laterClaims.issuedAtSeconds);
  ASSERT_OK(laterRequest);
  storage::client::EcRequestControl control;
  control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
  control.deadline = SteadyClock::now() + 20_s;
  auto laterObservation = blockingWait(storageClient_->queryEcTargetRetirement(*laterRequest, *key, control));
  ASSERT_OK(laterObservation);
  txn = kv_->createReadWriteTransaction();
  auto retained = blockingWait(EcTargetRetirementCatalog::recordCompletion(
      *txn, intent(*req), *laterRequest, *laterObservation, **key));
  ASSERT_OK(retained);
  ASSERT_EQ(serde::serialize(*first), serde::serialize(*retained));
  ASSERT_OK(blockingWait(txn->commit()));
  const auto targetKey = Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirement,
                                               req->endpoint.placement.node.toUnderType(),
                                               req->endpoint.placement.chain.toUnderType(),
                                               req->endpoint.placement.target.toUnderType(),
                                               req->endpoint.engineUuid,
                                               req->endpoint.targetIncarnation);
  auto damaged = *first;
  damaged.completion->observation.claims.requestDigest[0] ^= 1;
  const auto damagedBytes = serde::serialize(damaged);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(targetKey, damagedBytes)));
  ASSERT_OK(blockingWait(txn->commit()));
  txn = kv_->createReadWriteTransaction();
  ASSERT_ERROR(blockingWait(EcTargetRetirementCatalog::verifyStoredReference(*txn, req->endpoint, authority_, ref)),
               StatusCode::kDataCorruption);
  ASSERT_TRUE(blockingWait(EcTargetRetirementCatalog::verifyReference(*txn, req->endpoint, authority_, ref, **key)).hasError());
  ASSERT_TRUE(blockingWait(metaClient_->queryEcTargetRetirement(query(*req))).hasError());
  const auto firstBytes = serde::serialize(*first);
  txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(txn->set(targetKey, firstBytes)));
  ASSERT_OK(blockingWait(txn->commit()));
  // Release every borrowed engine handle before the real Storage close/reopen.
  scope = makeError(StatusCode::kIOError);
  target = makeError(StatusCode::kIOError);
  ASSERT_NO_FATAL_FAILURE(reopenStorageKeepingMeta());
  ASSERT_NO_FATAL_FAILURE(restartCoordinator());
  metaConfig_.set_readonly(true);
  auto replay = blockingWait(metaClient_->queryEcTargetRetirement(query(*req)));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*completed, *replay));
  metaConfig_.set_readonly(false);
  auto preparedAgain = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
  ASSERT_OK(preparedAgain);
  ASSERT_TRUE(serde::equals(*completed, *preparedAgain));
  txn = kv_->createReadWriteTransaction();
  auto after = blockingWait(EcTargetRetirementCatalog::get(*txn, intent(*req)));
  ASSERT_OK(after);
  ASSERT_EQ(serde::serialize(*first), serde::serialize(*after));
  auto changed = *req;
  changed.retirementId = Uuid::random();
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(changed)), StatusCode::kTokenMismatch);
  ASSERT_ERROR(blockingWait(metaClient_->queryEcTargetRetirement(query(changed))), StatusCode::kTokenMismatch);
}

TEST_F(TestEcTargetRetirementNative, AcceptedButUnsentIntentQueryCannotPrepareAndRootAuthenticationIsMandatory) {
  auto req = retirement();
  ASSERT_OK(req);
  auto changed = *req;
  changed.user = user_;
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(changed)), MetaCode::kNoPermission);
  changed = *req;
  changed.user.token = "invalid-root-token";
  ASSERT_TRUE(blockingWait(metaClient_->prepareEcTargetRetirement(changed)).hasError());
  metaConfig_.set_authenticate(false);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(*req)), StatusCode::kAuthenticationFail);
  metaConfig_.set_authenticate(true);
  metaConfig_.set_enable_ec_target_retirement(false);
  ASSERT_ERROR(blockingWait(metaClient_->prepareEcTargetRetirement(*req)), StatusCode::kNotImplemented);
  metaConfig_.set_enable_ec_target_retirement(true);
  auto txn = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::requireAssignable(*txn, req->endpoint)));
  ASSERT_ERROR(blockingWait(metaClient_->queryEcTargetRetirement(query(*req))), StatusCode::kTokenStale);
  // Model a real crash boundary: commit only the immutable acceptance, with no
  // Storage command issued. An active Query must not silently turn into Prepare.
  ASSERT_OK(blockingWait(EcTargetRetirementCatalog::prepare(*txn, intent(*req))));
  ASSERT_OK(blockingWait(txn->commit()));
  ASSERT_TRUE(blockingWait(metaClient_->queryEcTargetRetirement(query(*req))).hasError());
  auto target = components_->targetMap.getByTargetId(req->endpoint.placement.target);
  ASSERT_OK(target);
  auto scope = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(scope);
  storage::EcScopeBinding binding{};
  binding.target = scope->second;
  binding.kind = static_cast<uint8_t>(storage::EcGrantScope::ReadPin);
  binding.object.fill(9);
  binding.scope.fill(10);
  binding.owner_uid = user_.uid.toUnderType();
  binding.client_namespace.fill(11);
  ASSERT_OK(scope->first->prepare(binding));
  {
    auto stillServing = scope->first->tryAdmit(binding);
    ASSERT_OK(stillServing);
  }
  // Explicit same-ID Prepare is the only action that resumes the unsent stage.
  auto completed = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
  ASSERT_OK(completed);
  ASSERT_EQ(completed->stage, EcTargetRetirementStage::Completed);
  ASSERT_ERROR(scope->first->tryAdmit(binding), StatusCode::kTokenStale);
}

TEST_F(TestEcTargetRetirementNative, FlatReadAndFencedAbortUseOneRetirementButNeverPublish) {
  auto create = request<CreateEcFileV2Req>();
  create.path = PathAt(parent_, "retirement-terminal-union");
  create.shardBytes = kShardBytes;
  auto created = blockingWait(metaClient_->createEcFileV2(create));
  ASSERT_OK(created);
  const auto object = created->object.object;
  Mutation original;
  ASSERT_NO_FATAL_FAILURE(prepare(original, object, 0, 291));
  ASSERT_NO_FATAL_FAILURE(writeFragments(original));
  auto published = blockingWait(metaClient_->publishEcMutationV2(original.publish));
  ASSERT_OK(published);
  ASSERT_TRUE(published->drain);
  ASSERT_EQ(published->drain->acknowledgedEndpoints, 12);
  ASSERT_EQ(published->drain->retiredEndpoints, 0);
  auto read = readRequest(object);
  auto pinned = blockingWait(metaClient_->acquireEcReadV2(read));
  ASSERT_OK(pinned);
  Mutation unfinished;
  ASSERT_NO_FATAL_FAILURE(prepare(unfinished, object, 1, 293));
  ASSERT_NO_FATAL_FAILURE(writeFragments(unfinished));
  auto req = retirement();
  ASSERT_OK(req);
  auto complete = blockingWait(metaClient_->prepareEcTargetRetirement(*req));
  ASSERT_OK(complete);
  ASSERT_EQ(complete->stage, EcTargetRetirementStage::Completed);
  // Every candidate payload was written, but retired admission cannot supply
  // the required fresh publication verification/Seal/scope-ACK proof.
  ASSERT_TRUE(blockingWait(metaClient_->publishEcMutationV2(unfinished.publish)).hasError());
  // The same normal ECVD conflict read used by PreparePublish/issuance is
  // taken before the real Cancel commits T0 and its retirement union. A writer
  // with that stale read version must not commit across the terminal fence.
  auto publishing = kv_->createReadWriteTransaction();
  ASSERT_OK(blockingWait(EcV2ReservationCatalog::checkIssuanceOpen(
      *publishing, object, storage::EcGrantScope::WriteOperation, unfinished.begin.operation,
      EcOwner{user_.uid, metaClientId_.uuid})));
  auto cancel = request<CancelEcMutationV2Req>();
  cancel.object = object;
  cancel.operation = unfinished.begin.operation;
  auto aborted = blockingWait(metaClient_->cancelEcMutationV2(cancel));
  ASSERT_OK(aborted);
  ASSERT_EQ(aborted->record.state, EcOperationState::Aborted);
  ASSERT_TRUE(aborted->drain);
  ASSERT_EQ(aborted->drain->expectedEndpoints, 12);
  ASSERT_EQ(aborted->drain->acknowledgedEndpoints, 11);
  ASSERT_EQ(aborted->drain->retiredEndpoints, 1);
  const auto staleMarker = Serializer::serRawArgs(kv::KeyPrefix::EcTargetRetirementRequest, Uuid::random());
  const std::string staleValue = "stale publication admission";
  ASSERT_OK(blockingWait(publishing->set(staleMarker, staleValue)));
  ASSERT_ERROR(blockingWait(publishing->commit()), TransactionCode::kConflict);
  auto checkStale = kv_->createReadWriteTransaction();
  auto absentMarker = blockingWait(checkStale->get(staleMarker));
  ASSERT_OK(absentMarker);
  ASSERT_FALSE(*absentMarker);
  ASSERT_TRUE(blockingWait(metaClient_->publishEcMutationV2(unfinished.publish)).hasError());
  auto release = request<ReleaseEcReadV2Req>();
  release.object = object;
  release.pin = read.pin;
  auto released = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(released);
  ASSERT_EQ(released->drain.state, EcV2DrainState::ReadReleased);
  ASSERT_EQ(released->drain.expectedEndpoints, 12);
  ASSERT_EQ(released->drain.acknowledgedEndpoints, 11);
  ASSERT_EQ(released->drain.retiredEndpoints, 1);
  ASSERT_NO_FATAL_FAILURE(checkPin(object, read.pin, true));
  auto replay = blockingWait(metaClient_->releaseEcReadV2(release));
  ASSERT_OK(replay);
  ASSERT_TRUE(serde::equals(*released, *replay));
  auto key = controlKey();
  ASSERT_OK(key);
  auto txn = kv_->createReadWriteTransaction();
  const EcOwner owner{user_.uid, metaClientId_.uuid};
  auto drain = blockingWait(EcV2DrainCatalog::get(*txn, object, storage::EcGrantScope::ReadPin, read.pin, owner));
  ASSERT_OK(drain);
  ASSERT_TRUE(*drain);
  ASSERT_EQ((**drain).version, kEcV2RetirementDrainVersion);
  size_t acknowledgements = 0, retired = 0;
  for (size_t i = 0; i != (**drain).identity.endpoints.count; ++i) {
    if ((**drain).observations[i]) {
      ++acknowledgements;
      auto verified = EcVerifiedDrainAck::verify(**key, **drain, i,
                                                 (**drain).observations[i]->request,
                                                 (**drain).observations[i]->ack);
      ASSERT_OK(verified);
    }
    if ((**drain).retirements[i]) {
      ++retired;
      ASSERT_FALSE((**drain).observations[i]);
      ASSERT_EQ((**drain).identity.endpoints.endpoints[i], req->endpoint);
      ASSERT_OK(blockingWait(EcTargetRetirementCatalog::verifyReference(
          *txn, req->endpoint, authority_, *(**drain).retirements[i], **key)));
    }
  }
  ASSERT_EQ(acknowledgements, 11);
  ASSERT_EQ(retired, 1);
  auto history = blockingWait(EcV2GcCatalog::getAllocation(*txn, object, pinned->manifest.fragments[0].identity));
  ASSERT_OK(history);
  ASSERT_EQ(history->active, 0);
  ASSERT_EQ(history->registered, history->released);
}
