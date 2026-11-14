// Actual Meta72, private FDB and original Storage scopes. No synthetic terminal
// record is installed. The first case never uploads a byte to its candidates.
TEST_F(TestEcFileNativeWrite, OutputObservationAuthenticatesExactOwnerAndRetainsCandidateDebt) {
  using namespace ec_tree_detail;
  for (unsigned scenario = 0; scenario < 3; ++scenario) {
    auto open = request<OpenEcFileSessionReq>();
    open.createNew = true;
    open.path = PathAt(parent_, fmt::format("observe-output-{}", scenario));
    open.shardBytes = kShardBytes;
    open.session = Uuid::random();
    open.rights = kEcSessionWrite;
    open.perm = Permission{0600};
    auto opened = blockingWait(metaClient_->openEcFileSession(open));
    ASSERT_OK(opened);
    AdvanceEcFilePwriteReq accepted;
    const auto input = bytes(kShardBytes + 7, 183 + scenario);
    if (scenario == 0) {
      ASSERT_NO_FATAL_FAILURE(acceptPatch(*opened, 0, input, accepted));
      ASSERT_ERROR(observeFileOutput(accepted.object, accepted.operation, accepted.child, EcFileOutputOwner::Pwrite),
                   MetaCode::kNotFound);
      ASSERT_OK(blockingWait(metaClient_->advanceEcFilePwrite(accepted)));
    } else {
      ASSERT_NO_FATAL_FAILURE(writePatch(*opened, 0, input, false, accepted, scenario == 1));
    }
    auto initial = observeFileOutput(accepted.object, accepted.operation, accepted.child, EcFileOutputOwner::Pwrite);
    ASSERT_OK(initial);
    const auto &before = initial->observation;
    EXPECT_EQ(before.state, scenario == 0 ? EcFileOutputState::Reserved
                          : scenario == 1 ? EcFileOutputState::Bound : EcFileOutputState::Published);
    EXPECT_EQ(before.allocations.has_value(), scenario != 0);
    EXPECT_EQ(before.outputT2Confirmed, scenario == 2);
    EXPECT_FALSE(before.physicalReclamationConfirmed);
    EXPECT_EQ(before.session, open.session);
    EXPECT_EQ(before.plan, accepted.intent.plan);
    EXPECT_EQ(before.sourcePin, accepted.intent.sourcePin);
    EXPECT_EQ(before.candidates.size(), 12);
    EXPECT_NE(before.recordDigest, storage::EcSha256{});
    for (size_t n = 0; n < 12; ++n) {
      EXPECT_EQ(before.candidates[n].identity.shard, n);
      EXPECT_EQ(before.candidates[n].operation, accepted.child);
      EXPECT_EQ(before.candidates[n].writer.client, metaClientId_.uuid);
    }
    auto req = fileOutputRequest(before.identity);
    ASSERT_OK(req);
    if (scenario == 0) {
      metaConfig_.set_authenticate(false);
      auto disabled = blockingWait(metaClient_->queryEcFileOutput(*req));
      metaConfig_.set_authenticate(true);
      ASSERT_ERROR(disabled, StatusCode::kAuthenticationFail);
    }
    auto repeated = blockingWait(metaClient_->queryEcFileOutput(*req));
    ASSERT_OK(repeated);
    EXPECT_EQ(repeated->requestId, req->uuid);
    EXPECT_EQ(repeated->clientNamespace, metaClientId_.uuid);
    EXPECT_EQ(serde::serialize(repeated->observation), serde::serialize(before));
    // Reading through the catalog consumes the same budget and cannot issue,
    // create, close, clear or commit anything, even for nonterminal candidates.
    {
      auto raw = kv_->createReadWriteTransaction();
      EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Repair);
      auto recordBefore = blockingWait(tx.get(idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child)));
      ASSERT_OK(recordBefore);
      ASSERT_TRUE(*recordBefore);
      auto projected = blockingWait(EcFileExecutionCatalog::observeOutput(tx, before.identity));
      ASSERT_OK(projected);
      auto recordAfter = blockingWait(tx.get(idKey(kv::KeyPrefix::EcFileExecution, accepted.object, accepted.child)));
      ASSERT_OK(recordAfter);
      EXPECT_EQ(*recordAfter, *recordBefore);
      EXPECT_EQ(tx.usage().mutationBytes, 0);
      EXPECT_LE(tx.usage().totalBytes(), tx.limits().bytes);
      EXPECT_LE(tx.usage().keyOperations, tx.limits().keyOperations);
      RecordProperty(fmt::format("output_query_budget_bytes_{}", scenario), std::to_string(tx.usage().totalBytes()));
      EXPECT_EQ(serde::serialize(*projected), serde::serialize(before));
    }
    auto wrong = *req;
    wrong.user = user_;
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), MetaCode::kNoPermission);
    wrong.user.uid = flat::Uid{0}; // A claimed root UID with the nonroot token is not authorization.
    ASSERT_FALSE(blockingWait(metaClient_->queryEcFileOutput(wrong)));
    wrong = *req;
    wrong.identity.owner.client = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), MetaCode::kNoPermission);
    wrong = *req;
    wrong.identity.owner.uid = flat::Uid{987654};
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), MetaCode::kNoPermission);
    wrong = *req;
    wrong.identity.parent = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), StatusCode::kTokenMismatch);
    wrong = *req;
    wrong.identity.ownerKind = EcFileOutputOwner::Repair;
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), StatusCode::kTokenMismatch);
    wrong = *req;
    wrong.identity.ownerKind = static_cast<EcFileOutputOwner>(0);
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), StatusCode::kInvalidArg);
    wrong = *req;
    wrong.identity.object.inode = InodeId(accepted.object.inode.u64() + 1);
    ASSERT_FALSE(blockingWait(metaClient_->queryEcFileOutput(wrong)));
    wrong = *req;
    wrong.identity.child = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), MetaCode::kNotFound);
    wrong = *req;
    wrong.identity.object.incarnation = Uuid::random();
    ASSERT_ERROR(blockingWait(metaClient_->queryEcFileOutput(wrong)), MetaCode::kNotFound);
    if (scenario != 2) {
      auto cleanup = accepted;
      cleanup.action = EcFileAdvanceAction::CleanupChild;
      cleanup.outputRevocation = Uuid::random();
      cleanup.sourceRevocation = Uuid::random();
      ASSERT_OK(blockingWait(metaClient_->advanceEcFilePwrite(cleanup)));
    }
    auto terminal = blockingWait(metaClient_->queryEcFileOutput(*req));
    ASSERT_OK(terminal);
    const auto &out = terminal->observation;
    EXPECT_EQ(out.state, scenario == 2 ? EcFileOutputState::Published : EcFileOutputState::Aborted);
    EXPECT_TRUE(out.outputT2Confirmed);
    EXPECT_FALSE(out.physicalReclamationConfirmed);
    EXPECT_EQ(out.allocations.has_value(), scenario != 0);
    EXPECT_EQ(serde::serialize(out.candidates), serde::serialize(before.candidates));
    ASSERT_TRUE(out.drain);
    EXPECT_EQ(out.drain->identity.scopeId, accepted.child);
    EXPECT_EQ(out.drain->ackMask, (uint32_t{1} << out.endpoints.count) - 1);
    const auto json = serde::toJsonString(out);
    for (const auto *secret : {"\"grant\"", "\"capability\"", "\"observations\"", "\"ack\"", "\"key\""})
      EXPECT_EQ(json.find(secret), std::string::npos);
    // A lost permanent candidate is corruption, not an empty success. Restore
    // the exact bytes before checking the result so normal fixture cleanup runs.
    auto candidateKey = allocationKey(kv::KeyPrefix::EcFileExecutionAllocation, out.candidates[0].identity);
    ASSERT_OK(candidateKey);
    auto tx = kv_->createReadWriteTransaction();
    auto saved = blockingWait(tx->get(*candidateKey));
    ASSERT_OK(saved);
    ASSERT_TRUE(*saved);
    ASSERT_OK(blockingWait(tx->clear(*candidateKey)));
    ASSERT_OK(blockingWait(tx->commit()));
    auto corrupt = blockingWait(metaClient_->queryEcFileOutput(*req));
    tx = kv_->createReadWriteTransaction();
    ASSERT_OK(blockingWait(tx->set(*candidateKey, **saved)));
    ASSERT_OK(blockingWait(tx->commit()));
    ASSERT_ERROR(corrupt, StatusCode::kDataCorruption);
    auto close = request<CloseEcFileSessionReq>();
    close.object = accepted.object;
    close.session = open.session;
    ASSERT_OK(blockingWait(metaClient_->closeEcFileSession(close)));
    auto closedHistory = blockingWait(metaClient_->queryEcFileOutput(*req));
    ASSERT_OK(closedHistory);
    EXPECT_EQ(serde::serialize(closedHistory->observation), serde::serialize(out));
  }
  RecordProperty("scope", "actual authenticated Meta72 metadata observation; no physical reclamation proof");
}
