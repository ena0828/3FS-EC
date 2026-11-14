// Included inside TestEcStageService.cc's existing anonymous namespace.
// This is actual TCP/Engine I/O with a PRIVATE fixture binder. It does not
// claim a mode4 birth/WRITE ACL/Meta issuance or root-publication end-to-end test.
class RmwFixtureBinder final : public EcRmwOutputBinder {
 public:
  RmwFixtureBinder(std::shared_ptr<const EcCapabilityKey> key, std::shared_ptr<const EcRmwKey> rmw)
      : key_(std::move(key)),
        rmw_(std::move(rmw)) {}
  CoTryTask<std::array<EcCapabilityV2, 12>> bind(const EcRmwPlan &plan,
                                                 const EcRmwComputedCommitment &computed,
                                                 client::EcRequestControl) override {
    auto checkedPlan = EcRmwPlan::create(plan.input());
    CO_RETURN_ON_ERROR(checkedPlan);
    auto verified = EcRmwComputationAuthorization::verify(*rmw_, *checkedPlan, computed);
    CO_RETURN_ON_ERROR(verified);
    const auto &output = computed.output;
    if (first_ && (first_->planDigest != output.planDigest || first_->logicalSha256 != output.logicalSha256 ||
                   first_->descriptors != output.descriptors))
      co_return makeError(StatusCode::kTokenMismatch);
    first_ = output;
    std::array<EcCapabilityV2, 12> grants;
    for (size_t i = 0; i < 12; ++i) {
      auto token = credential(plan, i, output.descriptors[i]);
      if (!token) co_return makeError(std::move(token.error()));
      grants[i] = std::move(*token);
    }
    co_return grants;
  }
  Result<EcCapabilityV2> credential(const EcRmwPlan &plan, size_t i, const EcIntegrityDescriptor &d) const {
    const auto &p = plan.input();
    const auto &t = p.targets[i];
    EcGrantClaimsV2 c;
    c.engineUuid = t.endpoint.engineUuid;
    c.targetIncarnation = t.endpoint.targetIncarnation;
    c.identity = t.identity;
    c.fragmentOperationId = p.operationId;
    c.chainId = t.endpoint.chainId;
    c.targetId = t.endpoint.targetId;
    c.nodeId = t.endpoint.nodeId;
    c.expectedLength = d.wholeLength;
    c.expectedCrc32c = d.wholeCrc32c;
    CHECK_RESULT(hash, digestEcIntegrityV2(t.identity, d));
    c.integrityDigest = hash;
    c.ownerUid = p.ownerUid;
    c.clientNamespace = p.clientNamespace;
    c.scopeObject = p.object;
    c.scopeKind = EcGrantScope::WriteOperation;
    c.scopeId = p.operationId;
    c.rights = kEcGrantAllRightsV2;
    c.grantId = Uuid::random();
    c.issuedAtSeconds = 1000;
    c.expiresAtSeconds = 1100;
    return signEcGrantV2(*key_, c, 1000);
  }

 private:
  std::shared_ptr<const EcCapabilityKey> key_;
  std::shared_ptr<const EcRmwKey> rmw_;
  std::optional<EcRmwOutputCommitment> first_;
};
class TestEcRmwNative : public TestEcNativeRepairService {
 protected:
  Result<std::shared_ptr<NativeEcRmwIo>> makeIo(std::shared_ptr<const EcRmwPlan> plan,
                                                const EcRmwGrant &grant,
                                                std::shared_ptr<const EcRmwKey> key,
                                                std::shared_ptr<const EcCapabilityKey> data,
                                                std::shared_ptr<RmwFixtureBinder> binder,
                                                std::shared_ptr<EcRmwResources> resources,
                                                std::array<EcCapabilityV2, 12> reads = {},
                                                client::EcRequestControl::TransportPolicy transport =
                                                    client::EcRequestControl::TransportPolicy::TcpOnly) {
    CHECK_RESULT(loaded, components_->targetMap.getByTargetId(plan->worker().targetId));
    auto target = loaded->storageTarget;
    CHECK_RESULT(state, target->ecScopeState());
    EcScopeBinding binding{};
    binding.target = state.second;
    binding.kind = 2;
    const auto &p = plan->input();
    std::copy(std::begin(p.object.data), std::end(p.object.data), binding.object.begin());
    std::copy(std::begin(p.operationId.data), std::end(p.operationId.data), binding.scope.begin());
    std::copy(std::begin(p.clientNamespace.data), std::end(p.clientNamespace.data), binding.client_namespace.begin());
    binding.owner_uid = p.ownerUid.toUnderType();
    RETURN_ON_ERROR(state.first->prepare(binding));
    auto ticket = state.first->tryAdmit(binding);
    RETURN_ON_ERROR(ticket);
    auto lease = resources->acquire();
    RETURN_ON_ERROR(lease);
    const auto actual = state.second;
    const auto targetId = plan->worker().targetId;
    auto requestControl = control();
    requestControl.transport = transport;
    return NativeEcRmwIo::create(
        plan,
        grant,
        std::move(key),
        std::move(data),
        Uuid::from(91, 92),
        plan->worker(),
        target,
        std::move(*ticket),
        std::move(*lease),
        client_,
        std::move(reads),
        std::move(binder),
        [](const EcScopeEndpoint &e) -> Result<VersionedChainId> {
          return VersionedChainId{e.chainId, ChainVer(1)};
        },
        [] { return uint64_t(1000); },
        [this, target, targetId, actual]() -> Result<Void> {
          CHECK_RESULT(current, components_->targetMap.getByTargetId(targetId));
          if (current->storageTarget != target) return makeError(StorageCode::kTargetStateInvalid);
          return target->checkEcScopeTarget(actual);
        },
        requestControl);
  }
};
TEST_F(TestEcRmwNative, LostSealReplyReopensSamePlanAndVerifiesAllTwelveActualOutputs) {
  using namespace ec_rmw_detail;
  const std::string patch(65536 + 17, 'w');
  auto input = zeroPlan(patch, 65536 + 31);
  input.lengthAtPlan = 10ull * input.shardBytes;
  input.targetLogicalLength = input.lengthAtPlan;
  for (size_t i = 0; i < 12; ++i) input.targets[i].endpoint = endpoints_[i];
  auto plan = EcRmwPlan::create(input);
  ASSERT_OK(plan);
  auto key = AuthorizationTestAccess::key();
  auto grant = AuthorizationTestAccess::grant(*key, **plan);
  ASSERT_OK(grant);
  // Real 47 receiver and fixed codec reject a disabled production runtime;
  // the private NativeIo fixture below cannot implicitly enable that service.
  auto network = std::make_shared<client::EcRmwTransport>(messengerConfig_);
  ASSERT_OK(network->start());
  auto stopNetwork = folly::makeGuard([&] { network->stopAndJoin(); });
  EcRmwInstallReq install;
  install.plan.input = input;
  install.grant = *grant;
  install.deadlineUnixMillis = uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count()) +
                               10000;
  auto blocked = blockingWait(network->install(address_, std::move(install), control()));
  ASSERT_FALSE(blocked);
  EXPECT_EQ(blocked.error().code(), StatusCode::kAuthenticationFail);
  network->stopAndJoin();
  stopNetwork.dismiss();
  network.reset();

  auto data = std::make_shared<EcCapabilityKey>(std::span<const uint8_t, 32>(keyBytes_));
  auto binder = std::make_shared<RmwFixtureBinder>(data, key);
  auto resources = EcRmwResources::create();
  auto authority =
      EcRmwAuthorization::verify(*key, *grant, *plan, (*plan)->worker(), Uuid::from(91, 92), EcRmwRight::Execute, 1000);
  ASSERT_OK(authority);
  auto io = makeIo(*plan, *grant, key, data, binder, resources);
  ASSERT_OK(io);
  replyDrop_.arm();
  auto failed = blockingWait(EcRmwExecution::run(*authority, patch, *io));
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error().code(), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.snapshot().droppedReceipt);
  // Drop the actual ticket/target references only AFTER the owned execution
  // has completed, then reopen the same physical root/target incarnations.
  io->reset();
  resources->closeAndWait();
  resources.reset();
  ASSERT_NO_FATAL_FAILURE(reopenStorage());
  resources = EcRmwResources::create();
  io = makeIo(*plan, *grant, key, data, binder, resources);
  ASSERT_OK(io);
  auto result = blockingWait(EcRmwExecution::run(*authority, patch, *io));
  ASSERT_OK(result);
  io->reset();
  resources->closeAndWait();
  resources.reset();
  std::string logical(input.targetLogicalLength, '\0');
  logical.replace(input.patchOffset, patch.size(), patch);
  auto expected = EcCodec::encode(logical, input.shardBytes);
  ASSERT_OK(expected);
  EcCodec::Shards actual;
  std::array<EcCodecShardView, 12> views;
  for (size_t i = 0; i < 12; ++i) {
    const auto &descriptor = result->commitment.descriptors[i];
    auto token = binder->credential(**plan, i, descriptor);
    ASSERT_OK(token);
    EcFragmentAccessV2 access;
    access.identity = input.targets[i].identity;
    access.operationId = input.operationId;
    access.vChainId = {endpoints_[i].chainId, ChainVer(1)};
    access.targetId = endpoints_[i].targetId;
    access.integrity = descriptor;
    for (uint32_t block = 0; block < descriptor.blockCount; ++block) {
      EcReadBlockV2Req request;
      request.request = access;
      request.grant = *token;
      request.blockIndex = block;
      auto read = blockingWait(client_->readEcBlockV2Controlled(request, control()));
      ASSERT_OK(read);
      ASSERT_OK(validateEcReadBlockV2(*read, request));
      actual[i] += read->payload.data;
    }
    EXPECT_EQ(actual[i], (*expected)[i]);
    views[i] = {uint16_t(i), actual[i]};
  }
  ASSERT_OK(EcCodec::verify(views, input.targetLogicalLength, input.shardBytes));
  EXPECT_EQ(result->commitment.logicalSha256, *sha256(logical));
  // Same real old bytes now feed a distinct TruncateTail execution. Its new
  // twelve identities cannot alias the original candidate; full old SHA is
  // verified before taking the prefix and encoding zero-padded new shards.
  auto tail = input;
  tail.action = EcRmwAction::TruncateTail;
  tail.planId = Uuid::from(8100, 1);
  tail.parentId = Uuid::from(8101, 1);
  tail.operationId = Uuid::from(8102, 1);
  tail.sourceKind = EcRmwSourceKind::Data;
  tail.sourceRoot = Uuid::from(8103, 1);
  tail.sourcePin = Uuid::from(8104, 1);
  tail.sourceRevision = input.targetRevision;
  tail.sourceGeneration = input.targetGeneration;
  tail.sourceLogicalLength = input.targetLogicalLength;
  tail.sourceLogicalSha256 = result->commitment.logicalSha256;
  tail.patchOffset = 0;
  tail.patchLength = 0;
  tail.patchSha256 = *sha256({});
  tail.targetLogicalLength = 65536 + 7;
  tail.targetRevision = input.targetRevision + 1;
  tail.targetGeneration = input.targetGeneration + 1;
  std::array<EcCapabilityV2, 12> reads;
  for (size_t i = 0; i < 12; ++i) {
    auto &source = tail.sources[i];
    source.identity = input.targets[i].identity;
    source.endpoint = endpoints_[i];
    source.operationId = input.operationId;
    source.writerNamespace = input.clientNamespace;
    source.integrity = result->commitment.descriptors[i];
    tail.targets[i].identity.generation = tail.targetGeneration;
    tail.targets[i].identity.allocation = Uuid::from(8200 + i, 1);
    auto sourceGrant = binder->credential(**plan, i, source.integrity);
    ASSERT_OK(sourceGrant);
    auto claims = sourceGrant->claims;
    claims.scopeKind = EcGrantScope::ReadPin;
    claims.scopeId = tail.sourcePin;
    claims.rights = uint16_t(EcGrantRightV2::ReadBlock);
    claims.grantId = Uuid::from(8300 + i, 1);
    auto signedRead = signEcGrantV2(*data, claims, 1000);
    ASSERT_OK(signedRead);
    reads[i] = std::move(*signedRead);
  }
  auto tailPlan = EcRmwPlan::create(tail);
  ASSERT_OK(tailPlan);
  auto tailGrant = AuthorizationTestAccess::grant(*key, **tailPlan);
  ASSERT_OK(tailGrant);
  auto tailAuth = EcRmwAuthorization::verify(*key,
                                             *tailGrant,
                                             *tailPlan,
                                             (*tailPlan)->worker(),
                                             Uuid::from(91, 92),
                                             EcRmwRight::Execute,
                                             1000);
  ASSERT_OK(tailAuth);
  auto tailBinder = std::make_shared<RmwFixtureBinder>(data, key);
  resources = EcRmwResources::create();
  io = makeIo(*tailPlan, *tailGrant, key, data, tailBinder, resources, std::move(reads));
  ASSERT_OK(io);
  auto shortened = blockingWait(EcRmwExecution::run(*tailAuth, {}, *io));
  ASSERT_OK(shortened);
  io->reset();
  resources->closeAndWait();
  resources.reset();
  const auto prefix = logical.substr(0, tail.targetLogicalLength);
  auto tailExpected = EcCodec::encode(prefix, tail.shardBytes);
  ASSERT_OK(tailExpected);
  EcCodec::Shards tailActual;
  for (size_t i = 0; i < 12; ++i) {
    const auto &descriptor = shortened->commitment.descriptors[i];
    auto token = tailBinder->credential(**tailPlan, i, descriptor);
    ASSERT_OK(token);
    EcReadBlockV2Req request;
    request.request.identity = tail.targets[i].identity;
    request.request.operationId = tail.operationId;
    request.request.vChainId = {endpoints_[i].chainId, ChainVer(1)};
    request.request.targetId = endpoints_[i].targetId;
    request.request.integrity = descriptor;
    request.grant = *token;
    for (uint32_t block = 0; block < descriptor.blockCount; ++block) {
      request.blockIndex = block;
      auto read = blockingWait(client_->readEcBlockV2Controlled(request, control()));
      ASSERT_OK(read);
      ASSERT_OK(validateEcReadBlockV2(*read, request));
      tailActual[i] += read->payload.data;
    }
    EXPECT_EQ(tailActual[i], (*tailExpected)[i]);
    views[i] = {uint16_t(i), tailActual[i]};
  }
  ASSERT_OK(EcCodec::verify(views, tail.targetLogicalLength, tail.shardBytes));
  EXPECT_EQ(shortened->commitment.logicalSha256, *sha256(prefix));
}


TEST_F(TestEcRmwNative, ExplicitRdmaNativeIoRejectsTcpOnlyTargetsBeforeBegin) {
  using namespace ec_rmw_detail;
  using Policy = client::EcRequestControl::TransportPolicy;
  const std::string patch = "strict-rdma";
  auto input = zeroPlan(patch, 31);
  for (size_t i = 0; i != 12; ++i) input.targets[i].endpoint = endpoints_[i];
  auto plan = EcRmwPlan::create(input);
  ASSERT_OK(plan);
  auto key = AuthorizationTestAccess::key();
  auto grant = AuthorizationTestAccess::grant(*key, **plan);
  ASSERT_OK(grant);
  auto authority = EcRmwAuthorization::verify(*key, *grant, *plan, (*plan)->worker(),
                                              Uuid::from(91, 92), EcRmwRight::Execute, 1000);
  ASSERT_OK(authority);
  auto data = std::make_shared<EcCapabilityKey>(std::span<const uint8_t, 32>(keyBytes_));
  auto binder = std::make_shared<RmwFixtureBinder>(data, key);
  auto resources = EcRmwResources::create();
  auto io = makeIo(*plan, *grant, key, data, binder, resources, {}, Policy::RdmaOnly);
  auto cleanup = folly::makeGuard([&] {
    if (io) io->reset();
    resources->closeAndWait();
  });
  ASSERT_OK(io);
  EXPECT_EQ((*io)->transportPolicy(), Policy::RdmaOnly);
  size_t begins, queries;
  {
    std::lock_guard lock(replyDrop_.mutex);
    begins = replyDrop_.beginCalls;
    queries = replyDrop_.queryCalls;
  }
  const auto before = replyDrop_.snapshot();
  auto result = blockingWait(EcRmwExecution::run(*authority, patch, *io));
  ASSERT_ERROR(result, StorageClientCode::kRoutingError);
  {
    std::lock_guard lock(replyDrop_.mutex);
    EXPECT_EQ(replyDrop_.beginCalls, begins);
    EXPECT_EQ(replyDrop_.queryCalls, queries);
  }
  EXPECT_EQ(replyDrop_.snapshot().appendCalls, before.appendCalls);
  net::Client::Config networkConfig;
  smallClient(networkConfig);
  networkConfig.set_force_use_tcp(true);
  auto network = std::make_shared<client::EcRmwTransport>(networkConfig);
  ASSERT_OK(network->start());
  auto stopNetwork = folly::makeGuard([&] { network->stopAndJoin(); });
  auto selected = address_;
  selected.type = net::Address::RDMA;
  auto requestControl = control();
  requestControl.transport = Policy::RdmaOnly;
  EcRmwInstallReq install;
  install.plan.input = input;
  install.grant = *grant;
  install.deadlineUnixMillis = uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count()) + 10000;
  // Without requireRdma propagation, force_use_tcp would reach the live TCP
  // receiver and report its disabled-runtime AuthenticationFail instead.
  ASSERT_ERROR(blockingWait(network->install(selected, install, requestControl)), StatusCode::kInvalidArg);
  EcRmwActionReq action;
  action.planId = input.planId;
  action.grant = *grant;
  action.action = EcRmwActionRequest::Query;
  ASSERT_ERROR(blockingWait(network->action(selected, action, requestControl)), StatusCode::kInvalidArg);
  action.action = EcRmwActionRequest::Submit;
  ASSERT_ERROR(blockingWait(network->action(selected, action, requestControl)), StorageCode::kEcSealOutcomeUnknown);
  RecordProperty("transport_coverage", "real target ticket and NativeEcRmwIo with RDMA policy; TCP-only route "
                                      "rejected before Begin; fixture binder is not Meta; no RDMA hardware run");
}
