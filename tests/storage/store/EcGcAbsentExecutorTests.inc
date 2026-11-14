// Actual same-handle Rust persistence/target lifecycle. The G2 issuer below
// is synthetic test evidence; real distributed T2 is covered by Meta tests.
class TestEcGcAbsentExecutor : public TestEcGcExecutor {
 protected:
  void SetUp() override {
    TestEcGcExecutor::SetUp();
    if (HasFatalFailure()) return;
    auto started=EcGcAbsentExecutor::create(key,authority,node,[]{return 1000;},[this]{return readOnly;});
    ASSERT_OK(started);
    absent=std::move(*started);
  }
  void TearDown() override {
    if (absent) EXPECT_TRUE(absent->stopAndJoin());
    absent.reset();
    TestEcGcExecutor::TearDown();
  }
  EcScopeRevocation closure() const {
    EcScopeRevocation r{};
    r.binding.target=actual;
    std::copy(std::begin(request.identity.object.data),std::end(request.identity.object.data),r.binding.object.begin());
    r.binding.kind=static_cast<uint8_t>(EcGrantScope::WriteOperation);
    std::copy(std::begin(request.operationId.data),std::end(request.operationId.data),r.binding.scope.begin());
    r.binding.owner_uid=1000;
    std::copy(std::begin(request.writerNamespace.data),std::end(request.writerNamespace.data),r.binding.client_namespace.begin());
    r.id.fill(31); r.endpoint_set_digest.fill(32);
    return r;
  }
  EcGcAbsentRequest token(EcGcAbsentAction action) const {
    EcGcAbsentRequestClaims c;
    c.action=action; c.keyId=keyId; c.authority=authority; c.nonce=Uuid::random();
    c.issuedAtSeconds=1000;c.expiresAtSeconds=1100;
    c.certificate=claims(EcGcAction::Collect).certificate;
    c.certificate.version=2;c.certificate.metaMode=4;c.certificate.catalogVersion=2;
    c.certificate.enrollmentVersion=2;c.certificate.gcProtocol=2;
    auto &w=c.closure;
    const auto local=closure();
    w.scopeId=request.operationId;w.ownerUid=flat::Uid{1000};w.clientNamespace=request.writerNamespace;
    w.objectEpoch=1;w.generation=request.identity.generation;w.revision=1;
    w.endpointSetDigest=local.endpoint_set_digest;
    std::copy(local.id.begin(),local.id.end(),std::begin(w.revocationId.data));
    w.originDrainEvidence=c.certificate.originDrainEvidence;
    w.scopeRequest.emplace();w.scopeAck.emplace();
    auto &r=w.scopeRequest->claims;const auto &e=c.certificate.endpoint;
    r.clusterAuthority=authority;r.nodeId=e.nodeId;r.chainId=e.chainId;r.targetId=e.targetId;
    r.engineUuid=e.engineUuid;r.targetIncarnation=e.targetIncarnation;r.object=request.identity.object;
    r.scopeKind=w.scopeKind;r.scopeId=w.scopeId;r.ownerUid=w.ownerUid;r.clientNamespace=w.clientNamespace;
    r.endpointSetDigest=w.endpointSetDigest;r.revocationId=w.revocationId;
    r.nonce=Uuid::from(901,902);r.issuedAtSeconds=900;r.expiresAtSeconds=1100;
    // Complete canonical synthetic C envelope; this fixture does not claim
    // to exercise Meta's verification of a distributed signed C exchange.
    w.scopeAck->claims.requestDigest.fill(41);w.scopeAck->claims.revocationDigest.fill(42);
    w.scopeAck->claims.bootNonce=Uuid::from(903,904);w.scopeAck->claims.observedAtSeconds=950;
    w.scopeAck->claims.state=EcScopeControlState::Drained;w.scopeAck->claims.durable=true;
    const auto body=ec_gc_absent_detail::Codec::encode(c);
    EcSha256 mac{};unsigned size=0;
    if (!HMAC(EVP_sha256(),keyBytes.data(),keyBytes.size(),reinterpret_cast<const uint8_t *>(body.data()),body.size(),mac.data(),&size)||size!=32)
      throw std::runtime_error("absence fixture HMAC");
    auto result=ec_gc_absent_detail::Codec::decodeRequest(body,{reinterpret_cast<const char *>(mac.data()),mac.size()});
    if (!result) throw std::runtime_error("absence fixture shape");
    return std::move(*result);
  }
  Result<EcGcAbsentAck> exchange(EcGcAbsentAction action) {
    return folly::coro::blockingWait(absent->execute(action,token(action),target));
  }
  std::unique_ptr<EcGcAbsentExecutor> absent;
  bool readOnly=false;
};

TEST_F(TestEcGcAbsentExecutor, MissingRequiresOriginalDurableCloseAndQueryNeverCreatesLedger) {
  const auto before=used();
  EXPECT_FALSE(exchange(EcGcAbsentAction::ConfirmAbsent));
  auto scope=target->ecScopeState();ASSERT_OK(scope);
  ASSERT_OK(scope->first->revoke(closure()));
  EXPECT_FALSE(exchange(EcGcAbsentAction::QueryAbsent));
  EXPECT_EQ(used(),before);
  auto issued=token(EcGcAbsentAction::ConfirmAbsent);
  auto confirmed=folly::coro::blockingWait(absent->execute(EcGcAbsentAction::ConfirmAbsent,issued,target));ASSERT_OK(confirmed);
  EXPECT_EQ(confirmed->claims.state,EcGcAbsentState::AbsentAfterClose);
  EXPECT_EQ(confirmed->claims.recordRevision,1u);
  using AbsentCodec=ec_gc_absent_detail::Codec;
  ASSERT_OK(AbsentCodec::verifyAck(*key,*confirmed,issued));
  // Actual G verification and independent old-protocol rejection. Mutation of
  // any original closure/claim/action never selects Collect as a fallback.
  EcGcLocalTarget local{issued.claims.certificate.endpoint,2,3,2,true};
  auto changed=issued;changed.claims.authority=Uuid::random();
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,changed,authority,local,1000));
  changed=issued;changed.claims.closure.revocationId=Uuid::random();
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,changed,authority,local,1000));
  changed=issued;changed.claims.action=static_cast<EcGcAbsentAction>(3);
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,changed,authority,local,1000));
  changed=issued;changed.claims.expiresAtSeconds=1301;
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,changed,authority,local,1000));
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,issued,authority,local,1100));
  local.enabled=false;
  EXPECT_FALSE(AbsentCodec::verifyRequest(*key,issued,authority,local,1000));
  local.enabled=true;
  EXPECT_FALSE(AbsentCodec::verifyAck(*key,*confirmed,token(EcGcAbsentAction::QueryAbsent)));
  const auto legacy=Codec::encode(claims(EcGcAction::Collect));
  EXPECT_FALSE(AbsentCodec::decodeRequest({reinterpret_cast<const char *>(legacy.data()),legacy.size()},std::string(32,'x')));
  std::array<uint8_t,32> otherBytes{};otherBytes.fill(0x73);
  writeFile(directory.path()/"other-g.key",{reinterpret_cast<const char *>(otherBytes.data()),otherBytes.size()});
  auto otherKey=EcGcKey::loadFile(std::filesystem::path((directory.path()/"other-g.key").string()),keyId,{});ASSERT_OK(otherKey);
  EXPECT_FALSE(AbsentCodec::verifyRequest(**otherKey,issued,authority,local,1000));
  EXPECT_FALSE(AbsentCodec::verifyAck(**otherKey,*confirmed,issued));
  // Re-MAC a structurally valid ACK with the fixture oracle. The verifier must
  // compare identities/digests in addition to authenticating the envelope.
  for (int field=0;field!=3;++field) {
    auto a=confirmed->claims;
    if (field==0) a.claimDigest[0]^=1;
    if (field==1) a.closureDigest[0]^=1;
    if (field==2) a.requestDigest[0]^=1;
    const auto body=AbsentCodec::encode(a);EcSha256 mac{};unsigned size=0;
    ASSERT_NE(HMAC(EVP_sha256(),keyBytes.data(),keyBytes.size(),reinterpret_cast<const uint8_t *>(body.data()),body.size(),mac.data(),&size),nullptr);
    ASSERT_EQ(size,32u);
    auto mismatch=AbsentCodec::decodeAck(body,{reinterpret_cast<const char *>(mac.data()),mac.size()});ASSERT_OK(mismatch);
    EXPECT_FALSE(AbsentCodec::verifyAck(*key,*mismatch,issued));
  }
  EcGcAbsentDiscoveryClaims dc;
  dc.keyId=keyId;dc.authority=authority;dc.nodeId=node;dc.chainId=ChainId{actual.chain};dc.targetId=TargetId{actual.target};
  dc.nonce=Uuid::random();dc.issuedAtSeconds=1000;dc.expiresAtSeconds=1050;
  auto discovery=signEcGcAbsentDiscovery(*key,dc,1000);ASSERT_OK(discovery);
  auto capability=absent->observeCapabilities(*discovery,target,[]{return Result<Void>(Void{});});ASSERT_OK(capability);
  EXPECT_EQ(capability->claims.capabilities,kEcGcAbsentDiscoveryConfirmQuery);
  readOnly=true;
  auto queryOnly=absent->observeCapabilities(*discovery,target,[]{return Result<Void>(Void{});});ASSERT_OK(queryOnly);
  EXPECT_EQ(queryOnly->claims.capabilities,kEcGcAbsentDiscoveryQueryOnly);
  readOnly=false;
  auto queried=exchange(EcGcAbsentAction::QueryAbsent);ASSERT_OK(queried);
  EXPECT_EQ(queried->claims.ledgerSha256,confirmed->claims.ledgerSha256);
  EXPECT_FALSE(target->executeEcStage(request));
  ASSERT_OK(absent->stopAndJoin());absent.reset();
  ASSERT_OK(executor->stopAndJoin());executor.reset();
  scope=makeError(StatusCode::kInvalidArg);target.reset();engine.reset();
  ASSERT_NO_FATAL_FAILURE(open(false));
  auto started=EcGcAbsentExecutor::create(key,authority,node,[]{return 1000;});ASSERT_OK(started);
  absent=std::move(*started);
  auto reopened=exchange(EcGcAbsentAction::QueryAbsent);ASSERT_OK(reopened);
  EXPECT_EQ(reopened->claims.ledgerSha256,confirmed->claims.ledgerSha256);
  EXPECT_EQ(used(),before);
}

TEST_F(TestEcGcAbsentExecutor, OriginalInFlightTicketBlocksAbsenceUntilItsOwnedRelease) {
  auto scope=target->ecScopeState();ASSERT_OK(scope);
  const auto close=closure();
  ASSERT_OK(scope->first->prepare(close.binding));
  auto admitted=scope->first->tryAdmit(close.binding);ASSERT_OK(admitted);
  std::optional<EcScopeTicket> ticket(std::move(*admitted));
  auto revoked=scope->first->revoke(close);ASSERT_OK(revoked);
  EXPECT_EQ(revoked->inflight,1u);EXPECT_FALSE(revoked->drained);
  EXPECT_FALSE(exchange(EcGcAbsentAction::ConfirmAbsent));
  EXPECT_FALSE(exchange(EcGcAbsentAction::QueryAbsent));
  ticket.reset();
  auto result=exchange(EcGcAbsentAction::ConfirmAbsent);ASSERT_OK(result);
  EXPECT_EQ(result->claims.recordRevision,1u);
  auto changed=token(EcGcAbsentAction::QueryAbsent);changed.claims.closure.revocationId=Uuid::random();
  EXPECT_FALSE(folly::coro::blockingWait(absent->execute(EcGcAbsentAction::QueryAbsent,changed,target)));
}

TEST_F(TestEcGcAbsentExecutor, ExistingStageAndCollectedLedgerCannotBecomeAbsentAndReadOnlyBlocksConfirm) {
  readOnly=true;
  auto denied=exchange(EcGcAbsentAction::ConfirmAbsent);ASSERT_FALSE(denied);
  EXPECT_EQ(denied.error().code(),StatusCode::kReadOnlyMode);
  readOnly=false;
  ASSERT_NO_FATAL_FAILURE(seal());
  auto scope=target->ecScopeState();ASSERT_OK(scope);ASSERT_OK(scope->first->revoke(closure()));
  EXPECT_FALSE(exchange(EcGcAbsentAction::ConfirmAbsent));
  auto c=claims(EcGcAction::Collect);
  c.certificate=token(EcGcAbsentAction::ConfirmAbsent).claims.certificate;
  auto collected=run(EcGcAction::Collect,sign(c));ASSERT_OK(collected);
  EXPECT_FALSE(exchange(EcGcAbsentAction::ConfirmAbsent));
  EXPECT_FALSE(exchange(EcGcAbsentAction::QueryAbsent));
  EXPECT_EQ(used(),0u);
}
