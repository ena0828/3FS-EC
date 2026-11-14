// Included in the real TCP/Rust Engine fixture. No transport or disk result is
// synthesized; faults wrap actual handlers, replies or a matched data syscall.
TEST_F(TestEcNativeRepairService, HelperDirectPendingWriteEioReopensAndReplaysSameAllocation) {
  namespace fault = hf3fs::test::ec_pending;
  constexpr uint32_t blockBytes = kEcIntegrityBlockBytes;
  SCOPE_EXIT { fault::reset(); };
  auto value = prepare({0, 11}, 2 * blockBytes, 2);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  armDirect(*value);
  std::array<uint64_t, 2> initialUsed{};
  for (uint8_t i = 0; i != 2; ++i) {
    auto used = committedBytes(value->plan->input().targets[i]);
    ASSERT_OK(used);
    initialUsed[i] = *used;
  }
  const auto firstBytes = repair_test::blockBytes(value->data, value->plan->input().targets[1], 0);
  const auto pendingBytes = repair_test::blockBytes(value->data, value->plan->input().targets[1], 1);
  const auto classDirectory = std::filesystem::canonical(directory_.path().string()) / "engine-ec-v2" / "128KiB";

  // Only target one is written while capturing: equal bytes on target zero
  // cannot select a different allocation. Both writes still come from the
  // real last helper's reconstruction and authenticated Append RPC.
  fault::captureNext(classDirectory, firstBytes);
  auto first = directRequest(*value, 0, 2);
  ASSERT_OK(first);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*first, control())));
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  const auto captured = fault::observation();
  ASSERT_EQ(captured.captures, 1);
  ASSERT_EQ(captured.failures, 0);
  ASSERT_EQ(captured.interceptionErrors, 0);
  auto other = directRequest(*value, 0, 1);
  ASSERT_OK(other);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*other, control())));
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  for (const auto &fixed : value->bindings.targets) {
    auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(state);
    ASSERT_EQ(state->prefixBytes, blockBytes);
    ASSERT_FALSE(state->pendingBlock);
    ASSERT_FALSE(state->needsReconcile);
  }
  fault::failNext(captured, blockBytes, pendingBytes);
  auto both = directRequest(*value, 1);
  ASSERT_OK(both);
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*both, control())), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  const auto failed = fault::observation();
  ASSERT_EQ(failed.captures, 1);
  ASSERT_EQ(failed.failures, 1);
  ASSERT_EQ(failed.interceptionErrors, 0);
  ASSERT_EQ(failed.device, captured.device);
  ASSERT_EQ(failed.inode, captured.inode);
  ASSERT_EQ(failed.offset, captured.offset + blockBytes);
  ASSERT_EQ(directTrace().appends.size(), 3);  // Target zero's second block completed before the EIO.
  ASSERT_EQ(directTrace().appendAttempts.size(), 4);
  std::array<EcStageStateV2, 2> reconciled{};
  for (uint8_t i = 0; i != 2; ++i) {
    const auto &fixed = value->bindings.targets[i];
    auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(state);
    ASSERT_OK(validateEcStageStateV2(*state, fixed.request, fixed.grant.claims));
    EXPECT_EQ(state->state, 1);
    EXPECT_EQ(state->prefixBytes, i == 0 ? 2 * blockBytes : blockBytes);
    EXPECT_EQ(state->pendingBlock, i == 1);
    if (i == 1) ASSERT_TRUE(state->needsReconcile);
    auto barrier = blockingWait(client_->reconcileEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(barrier);
    ASSERT_FALSE(barrier->needsReconcile);
    ASSERT_EQ(barrier->pendingBlock, i == 1);
    ASSERT_EQ(barrier->prefixBytes, state->prefixBytes);
    ASSERT_EQ(barrier->revision, state->revision);
    reconciled[i] = *barrier;
    auto used = committedBytes(value->plan->input().targets[i]);
    ASSERT_OK(used);
    EXPECT_EQ(*used, initialUsed[i]);  // Neither unsealed stage can count as committed data.
  }

  // Only scalar observations and immutable request identities cross this
  // boundary. No Engine/target/fd lease survives the actual stop/join/reopen.
  fault::reset();
  ASSERT_NO_FATAL_FAILURE(reopenStorage());
  for (uint8_t i = 0; i != 2; ++i) {
    const auto &fixed = value->bindings.targets[i];
    auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(state);
    ASSERT_OK(validateEcStageStateV2(*state, fixed.request, fixed.grant.claims));
    ASSERT_EQ(state->state, 1);
    ASSERT_TRUE(state->needsReconcile);
    EXPECT_EQ(state->pendingBlock, i == 1);
    EXPECT_EQ(state->prefixBytes, reconciled[i].prefixBytes);
    EXPECT_EQ(state->revision, reconciled[i].revision);
    auto barrier = blockingWait(client_->reconcileEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(barrier);
    ASSERT_FALSE(barrier->needsReconcile);
    ASSERT_EQ(barrier->pendingBlock, i == 1);
    ASSERT_EQ(barrier->prefixBytes, reconciled[i].prefixBytes);
  }
  fault::captureNext(classDirectory, pendingBytes);
  auto replay = directRequest(*value, 1);
  ASSERT_OK(replay);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*replay, control())));
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  const auto resumed = fault::observation();
  ASSERT_EQ(resumed.captures, 1);
  ASSERT_EQ(resumed.failures, 0);
  ASSERT_EQ(resumed.interceptionErrors, 0);
  EXPECT_EQ(resumed.device, captured.device);
  EXPECT_EQ(resumed.inode, captured.inode);
  EXPECT_EQ(resumed.offset, captured.offset + blockBytes);
  EXPECT_EQ(directTrace().appends.size(), 5);  // The already-complete target still receives real duplicate Append.
  EXPECT_EQ(directTrace().appendAttempts.size(), 6);
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
  for (uint8_t i = 0; i != 2; ++i) {
    auto used = committedBytes(value->plan->input().targets[i]);
    ASSERT_OK(used);
    EXPECT_EQ(*used, initialUsed[i] + 2 * blockBytes);
  }
  RecordProperty("coverage", "Storage50 direct reconstruction; real target-one pending pwrite EIO after target-zero "
                             "success; original allocation dev/ino/offset after orderly Engine reopen; real duplicate "
                             "Append/Seal/readback; not Meta publication or power-failure recovery");
}

TEST_F(TestEcNativeRepairService, HelperDirectGlobalBudgetSaturationKeepsControlResponsive) {
  // Only this case enables the real control executor. Reopen before starting
  // requests so its key/authority and system clock are initialized normally;
  // the fixture's later data/helper clock=1000 does not replace that clock.
  const auto controlPath = traces_.path() / "direct-budget-control.key";
  std::array<uint8_t, 32> controlBytes{};
  for (size_t i = 0; i != controlBytes.size(); ++i) controlBytes[i] = uint8_t(i + 151);
  const int fd = ::open(controlPath.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT_GE(fd, 0);
  const auto written = ::write(fd, controlBytes.data(), controlBytes.size());
  const auto closed = ::close(fd);
  ASSERT_EQ(written, ssize_t(controlBytes.size()));
  ASSERT_EQ(closed, 0);
  auto key = EcScopeControlKey::loadFile(std::filesystem::path(controlPath.string()));
  ASSERT_OK(key);
  const auto authority = Uuid::random();
  config_.storage().set_enable_ec_scope_control(true);
  config_.storage().set_ec_scope_control_key_file(controlPath);
  config_.storage().set_ec_scope_control_authority(fmt::to_string(authority));
  ASSERT_NO_FATAL_FAILURE(reopenStorage());
  ASSERT_EQ(config_.coroutines_pool_default().coroutines_num(), 128);

  constexpr size_t heldPlans = 16;
  std::vector<Case> values;
  values.reserve(heldPlans + 1);
  auto hold = std::make_shared<StageReplyDropState::DirectBudgetHold>();
  // Prepare the seventeenth plan before saturation as well. Every plan has
  // independent real source stages and operation scopes; no admission token
  // or private semaphore is synthesized to fill the budget.
  for (size_t i = 0; i != heldPlans + 1; ++i) {
    auto value = prepare({0}, 31, 1);
    ASSERT_OK(value);
    ASSERT_OK(beginDirect(*value));
    for (const auto &existing : values)
      ASSERT_NE(existing.plan->input().operationId, value->plan->input().operationId);
    if (i != heldPlans) ASSERT_TRUE(hold->allowed.insert(value->plan->digest()).second);
    values.push_back(std::move(*value));
  }
  ASSERT_EQ(hold->allowed.size(), heldPlans);
  ASSERT_FALSE(hold->allowed.contains(values.back().plan->digest()));
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.directBudget = hold;
  }
  std::vector<std::future<Result<EcHelperDirectHopResult>>> calls;
  calls.reserve(heldPlans);
  SCOPE_EXIT {
    hold->unblock();
    for (auto &call : calls) if (call.valid()) call.wait();
    // A timed-out client does not prove remote completion. The shared tracker
    // remains in the service fixture through its normal stop/join teardown.
  };
  for (size_t i = 0; i != heldPlans; ++i) {
    auto wire = directRequest(values[i]);
    ASSERT_OK(wire);
    wire->deadlineUnixMillis =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() + 30000;
    calls.push_back(std::async(std::launch::async, [this, request = std::move(*wire)]() mutable {
      auto ctl = control();
      ctl.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(40);
      return blockingWait(client_->executeEcHelperDirect(std::move(request), ctl));
    }));
  }
  ASSERT_TRUE(hold->waitFor([](const auto &state) { return state.held == heldPlans; }));
  const auto expectHeld = [&] {
    const auto snapshot = hold->snapshot();
    ASSERT_EQ(snapshot.held, heldPlans);
    ASSERT_EQ(snapshot.duplicatePositionFour, 0);
    ASSERT_EQ(snapshot.entered, heldPlans * 5);  // 64 upstream permits + 16 pre-Operator barriers.
    ASSERT_EQ(snapshot.finished, 0);
    for (auto &call : calls) ASSERT_EQ(call.wait_for(std::chrono::seconds(0)), std::future_status::timeout);
  };
  ASSERT_NO_FATAL_FAILURE(expectHeld());
  net::UserRequestOptions options;
  options.timeout = 2_s;
  options.sendRetryTimes = 0;
  auto extra = directRequest(values.back());
  ASSERT_OK(extra);
  auto rejected = blockingWait(messenger_->executeEcHelperDirect(address_, *extra, &options));
  ASSERT_OK(rejected);  // Actual RPC50 response, not the SDK's own helper limit or a network timeout.
  ASSERT_ERROR(rejected->result, StorageClientCode::kResourceBusy);
  ASSERT_NO_FATAL_FAILURE(expectHeld());

  const auto &plan = values.front().plan->input();
  const auto &source = plan.sources[0];
  EcScopeControlClaims claims;
  claims.clusterAuthority = authority;
  claims.nodeId = source.endpoint.nodeId;
  claims.chainId = source.endpoint.chainId;
  claims.targetId = source.endpoint.targetId;
  claims.engineUuid = source.endpoint.engineUuid;
  claims.targetIncarnation = source.endpoint.targetIncarnation;
  claims.object = source.identity.object;
  claims.scopeKind = EcGrantScope::WriteOperation;
  claims.scopeId = plan.operationId;
  claims.ownerUid = plan.ownerUid;
  claims.clientNamespace = plan.clientNamespace;
  claims.revocationId = Uuid::random();
  claims.nonce = Uuid::random();
  claims.endpointSetDigest = values.front().plan->endpointSetDigest();
  claims.issuedAtSeconds =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  claims.expiresAtSeconds = claims.issuedAtSeconds + 120;
  auto revoke = signEcScopeControl(**key, claims, claims.issuedAtSeconds);
  ASSERT_OK(revoke);
  auto pending = blockingWait(messenger_->revokeEcScope(address_, *revoke, &options));
  ASSERT_OK(pending);
  ASSERT_OK(pending->result);
  ASSERT_OK(verifyEcScopeControlAck(**key, *pending->result, *revoke));
  EXPECT_EQ(pending->result->claims.state, EcScopeControlState::Pending);
  EXPECT_TRUE(pending->result->claims.durable);
  EXPECT_GE(pending->result->claims.inflight, 1u);
  ASSERT_NO_FATAL_FAILURE(expectHeld());
  claims.action = EcScopeControlAction::Query;
  claims.nonce = Uuid::random();
  auto query = signEcScopeControl(**key, claims, claims.issuedAtSeconds);
  ASSERT_OK(query);
  auto stillPending = blockingWait(messenger_->queryEcScopeDrain(address_, *query, &options));
  ASSERT_OK(stillPending);
  ASSERT_OK(stillPending->result);
  ASSERT_OK(verifyEcScopeControlAck(**key, *stillPending->result, *query));
  EXPECT_EQ(stillPending->result->claims.state, EcScopeControlState::Pending);
  EXPECT_TRUE(stillPending->result->claims.durable);
  EXPECT_GE(stillPending->result->claims.inflight, 1u);
  ASSERT_NO_FATAL_FAILURE(expectHeld());

  hold->unblock();
  for (size_t i = 0; i != calls.size(); ++i) {
    auto result = calls[i].get();
    if (i == 0 || !result) {
      ASSERT_ERROR(result, StorageCode::kEcSealOutcomeUnknown);
    } else {
      EXPECT_EQ(result->appendedTargetMask, 1);
      EXPECT_EQ(result->planDigest, values[i].plan->digest());
    }
  }
  // Released children can race for admission and fail conservatively. Joining
  // frontend calls alone is insufficient; observe the actual tracked bodies.
  ASSERT_TRUE(hold->waitFor([](const auto &state) { return state.entered == state.finished; }));
  EXPECT_EQ(hold->snapshot().duplicatePositionFour, 0);
  claims.nonce = Uuid::random();
  auto finalQuery = signEcScopeControl(**key, claims, claims.issuedAtSeconds);
  ASSERT_OK(finalQuery);
  auto drained = blockingWait(messenger_->queryEcScopeDrain(address_, *finalQuery, &options));
  ASSERT_OK(drained);
  ASSERT_OK(drained->result);
  ASSERT_OK(verifyEcScopeControlAck(**key, *drained->result, *finalQuery));
  EXPECT_EQ(drained->result->claims.state, EcScopeControlState::Drained);
  EXPECT_TRUE(drained->result->claims.durable);
  EXPECT_EQ(drained->result->claims.inflight, 0);
  // Same seventeenth plan/allocation, now with a fresh finite call deadline.
  // Its earlier refusal was before dispatch; it is outside the revoked scope.
  auto admitted = directRequest(values.back());
  ASSERT_OK(admitted);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*admitted, control())));
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(values.back()));
  RecordProperty("coverage", "16 independent Storage50 chains hold 64 real upstream permits and 80 defaultPool128 "
                             "frames; real RPC50 ResourceBusy; signed TCP control25/26 Pending then locally Drained; "
                             "permit reuse; one Engine and twelve logical targets, not distributed T2");
}

TEST_F(TestEcNativeRepairService, HelperDirectW1W2W4WriteOriginalTargetsWithSmallReplies) {
  for (uint8_t window : {1, 2, 4}) {
    auto value = prepare(window == 1 ? std::vector<uint16_t>{0} : std::vector<uint16_t>{0, 11},
                         window == 4 ? 16 * kEcIntegrityBlockBytes : kEcIntegrityBlockBytes + 7, window);
    ASSERT_OK(value);
    ASSERT_OK(beginDirect(*value));
    armDirect(*value);
    client::EcRpcObservation observation;
    for (uint32_t base = 0; base < value->plan->blockCount(); base += window) {
      std::vector<std::future<Result<EcHelperDirectHopResult>>> calls;
      for (uint32_t block = base; block < std::min<uint32_t>(base + window, value->plan->blockCount()); ++block) {
        auto wire = directRequest(*value, block);
        ASSERT_OK(wire);
        calls.push_back(std::async(std::launch::async, [this, wire = std::move(*wire), &observation]() mutable {
          auto ctl = control();
          ctl.observation = &observation;
          return blockingWait(client_->executeEcHelperDirect(std::move(wire), ctl));
        }));
      }
      for (auto &call : calls) {
        auto result = call.get();
        ASSERT_OK(result);
        EXPECT_EQ(result->appendedTargetMask, (1u << value->plan->input().targetCount) - 1);
        EXPECT_LE(serde::serialize(*result).size(), 8192u);
      }
    }
    ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
    const auto trace = directTrace();
    ASSERT_EQ(trace.successfulResponseBytes.size(), 10u * value->plan->blockCount());
    for (const auto size : trace.successfulResponseBytes) EXPECT_LE(size, 8192u);
    EXPECT_EQ(trace.appends.size(), size_t(value->plan->blockCount()) * value->plan->input().targetCount);
    const auto metrics = observation.snapshot();
    const auto &direct = metrics.at(client::EcRpcMethod::HelperDirect);
    EXPECT_EQ(direct.messengerInvocations, value->plan->blockCount());
    EXPECT_EQ(direct.observedEncodedResponseFrames, value->plan->blockCount());
    EXPECT_LT(direct.responseFrameBytes, uint64_t(value->plan->blockCount()) * 16384);
    EXPECT_EQ(metrics.at(client::EcRpcMethod::Append).messengerInvocations, 0u);
    EXPECT_EQ(metrics.at(client::EcRpcMethod::Helper).messengerInvocations, 0u);
    for (const auto &limiter : direct.limiters) EXPECT_EQ(limiter.entered, 0u);
    EXPECT_FALSE(metrics.overflow);
    ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
  }
  RecordProperty("coverage", "real TCP ten-hop Storage50 W1/W2/W4 and Append42; 16 blocks; first-hop encoded frames; "
                              "each handler small response; original target Seal/readback; not full-wire accounting");
}

TEST_F(TestEcNativeRepairService, HelperDirectReverseArrivalWaitsForDurablePrefixAcrossWindows) {
  for (uint8_t window : {2, 4}) {
    auto value = prepare({0, 11}, window * kEcIntegrityBlockBytes + 7, window);
    ASSERT_OK(value);
    ASSERT_OK(beginDirect(*value));
    armDirect(*value);
    std::vector<std::future<Result<EcHelperDirectHopResult>>> calls;
    SCOPE_EXIT { for (auto &call : calls) if (call.valid()) call.wait(); };
    // Force every high block to reach the real last-hop Query while block zero
    // has not been dispatched. Lower block still has a legal window slot.
    for (uint32_t block = 1; block != window; ++block) {
      auto wire = directRequest(*value, block);
      ASSERT_OK(wire);
      calls.push_back(std::async(std::launch::async, [this, wire = std::move(*wire)]() mutable {
        return blockingWait(client_->executeEcHelperDirect(std::move(wire), control()));
      }));
    }
    const auto highMask = uint16_t((1u << window) - 2);
    ASSERT_TRUE(replyDrop_.waitDirect([&](const auto &t) {
      return (t.enteredBlocks[9] & highMask) == highMask && t.zeroPrefixQueries >= window - 1;
    }));
    EXPECT_TRUE(directTrace().appends.empty());
    auto first = directRequest(*value, 0);
    ASSERT_OK(first);
    ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*first, control())));
    for (auto &call : calls) ASSERT_OK(call.get());
    ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
    // Empty activeBlocks_ is not loss of ordering state: a new batch observes
    // the target's real prefix and proceeds without an in-memory nextIndex.
    auto tail = directRequest(*value, window);
    ASSERT_OK(tail);
    ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*tail, control())));
    ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
    const auto trace = directTrace();
    for (uint8_t target = 0; target != 2; ++target) {
      std::vector<uint32_t> order;
      for (const auto &[id, block] : trace.appendAttempts)
        if (id == value->plan->input().targets[target].endpoint.targetId) order.push_back(block);
      std::vector<uint32_t> expected;
      for (uint32_t block = 0; block <= window; ++block) expected.push_back(block);
      EXPECT_EQ(order, expected);
    }
    ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
  }
}

TEST_F(TestEcNativeRepairService, HelperDirectLostSecondAppendReplyReconcilesOriginalAllocations) {
  auto value = prepare({0, 11});
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  armDirect(*value);
  replyDrop_.armAppend(value->bindings.targets[1].request, 0);
  auto wire = directRequest(*value);
  ASSERT_OK(wire);
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*wire, control())), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  auto trace = directTrace();
  ASSERT_EQ(trace.shutdownCalls, 1);
  ASSERT_TRUE(trace.tcp);
  ASSERT_EQ(trace.shutdownResult, 0) << trace.shutdownErrno;
  ASSERT_EQ(trace.appends.size(), 2);
  ASSERT_TRUE(replyDrop_.snapshot().droppedAppend);
  std::array<uint64_t, 2> before{};
  for (uint8_t i = 0; i != 2; ++i) {
    const auto &fixed = value->bindings.targets[i];
    auto queried = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(queried);
    EXPECT_EQ(queried->prefixBytes, kEcIntegrityBlockBytes);
    auto barrier = blockingWait(client_->reconcileEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(barrier);
    EXPECT_EQ(barrier->prefixBytes, kEcIntegrityBlockBytes);
    EXPECT_FALSE(barrier->needsReconcile);
    auto size = committedBytes(value->plan->input().targets[i]);
    ASSERT_OK(size);
    before[i] = *size;
  }
  // A renewed delegation still names the same plan/stage. Both block-zero
  // Appends really execute again, rather than accepting Query as a substitute.
  auto replay = directRequest(*value);
  ASSERT_OK(replay);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*replay, control())));
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  EXPECT_EQ(directTrace().appends.size(), 4);
  for (uint8_t i = 0; i != 2; ++i) {
    auto size = committedBytes(value->plan->input().targets[i]);
    ASSERT_OK(size);
    EXPECT_EQ(*size, before[i]);
  }
  auto tail = directRequest(*value, 1);
  ASSERT_OK(tail);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*tail, control())));
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
}

TEST_F(TestEcNativeRepairService, HelperDirectLostFinalAndIntermediateSmallRepliesRemainUnknown) {
  for (uint8_t dropPosition : {9, 4}) {
    auto value = prepare({0, 11}, 31);
    ASSERT_OK(value);
    ASSERT_OK(beginDirect(*value));
    armDirect(*value);
    {
      std::lock_guard lock(replyDrop_.mutex);
      replyDrop_.direct.dropResultPosition = dropPosition;
    }
    auto wire = directRequest(*value);
    ASSERT_OK(wire);
    ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*wire, control())), StorageCode::kEcSealOutcomeUnknown);
    ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
    const auto trace = directTrace();
    EXPECT_EQ(trace.appends.size(), 2);
    ASSERT_EQ(trace.shutdownCalls, 1);
    ASSERT_TRUE(trace.tcp);
    ASSERT_EQ(trace.shutdownResult, 0) << trace.shutdownErrno;
    for (uint8_t i = 0; i != 2; ++i) {
      const auto &fixed = value->bindings.targets[i];
      ASSERT_OK(blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control())));
      ASSERT_OK(blockingWait(client_->reconcileEcStageV2Controlled({fixed.request, fixed.grant}, control())));
    }
    auto replay = directRequest(*value);
    ASSERT_OK(replay);
    ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*replay, control())));
    ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
  }
}

TEST_F(TestEcNativeRepairService, HelperDirectMissingPredecessorAndDuplicateHaveFiniteOwnedLifetime) {
  auto value = prepare({0}, kEcIntegrityBlockBytes + 7, 2);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  armDirect(*value);
  auto wire = directRequest(*value, 1);
  ASSERT_OK(wire);
  wire->deadlineUnixMillis -= 2000;  // Eight seconds, fixed across every hop/query; no renewed poll deadline.
  auto future = std::async(std::launch::async, [&, request = *wire] {
    return blockingWait(client_->executeEcHelperDirect(request, control()));
  });
  SCOPE_EXIT { if (future.valid()) future.wait(); };
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.zeroPrefixQueries > 0; }));
  auto duplicate = directRequest(*value, 1);  // Different grant IDs cannot escape the live plan/hop/block key.
  ASSERT_OK(duplicate);
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*duplicate, control())), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_EQ(future.wait_for(std::chrono::seconds(12)), std::future_status::ready);
  ASSERT_ERROR(future.get(), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  EXPECT_TRUE(directTrace().appends.empty());
  auto zero = directRequest(*value, 0);
  ASSERT_OK(zero);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*zero, control())));
  auto one = directRequest(*value, 1);
  ASSERT_OK(one);
  ASSERT_OK(blockingWait(client_->executeEcHelperDirect(*one, control())));
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
}

TEST_F(TestEcNativeRepairService, HelperDirectMaskSkipsSealedTargetAndBadDataMacCannotAppend) {
  auto value = prepare({0, 11}, 31);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  armDirect(*value);
  auto bad = directRequest(*value);
  ASSERT_OK(bad);
  // The trusted helper authenticates this delegation's digest. Only the real
  // destination's data-key check can reject the empty opaque Append signature.
  auto damaged = bad->delegation.appendGrants;
  const auto claims = damaged[1].claims;
  damaged[1] = EcCapabilityV2{};
  damaged[1].claims = claims;
  auto resigned = issueEcHelperDirectDelegation(*helperKey_, *value->plan, damaged,
                                                bad->delegation.queryGrants, 1, 1000, 100);
  ASSERT_OK(resigned);
  bad->delegation = *resigned;
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*bad, control())), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  EXPECT_EQ(directTrace().appends.size(), 1);  // target zero committed; target one's real auth denied.
  for (uint8_t i = 0; i != 2; ++i) {
    const auto &fixed = value->bindings.targets[i];
    auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(state);
    EXPECT_EQ(state->prefixBytes, i == 0 ? 31 : 0);
    ASSERT_OK(blockingWait(client_->reconcileEcStageV2Controlled({fixed.request, fixed.grant}, control())));
  }
  const auto &first = value->bindings.targets[0];
  ASSERT_OK(blockingWait(client_->sealEcStageV2Controlled({first.request, first.grant}, control())));
  auto secondOnly = directRequest(*value, 0, 2);
  ASSERT_OK(secondOnly);
  auto result = blockingWait(client_->executeEcHelperDirect(*secondOnly, control()));
  ASSERT_OK(result);
  EXPECT_EQ(result->appendedTargetMask, 2);
  EXPECT_TRUE(serde::equals(result->states[0], EcStageStateV2{}));
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
}

TEST_F(TestEcNativeRepairService, HelperDirectCancellationAndSourceFenceKeepRealDownstreamJoined) {
  auto value = prepare({0}, 31, 1);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  armDirect(*value);
  auto delay = std::make_shared<StageReplyDropState::ReadDelay>();
  auto entered = delay->entered.get_future();
  {
    std::lock_guard lock(replyDrop_.mutex);
    replyDrop_.directDelay = delay;
  }
  auto wire = directRequest(*value);
  ASSERT_OK(wire);
  CancellationSource cancel;
  auto ctl = control();
  ctl.cancellation = cancel.getToken();
  auto future = std::async(std::launch::async, [&] {
    return blockingWait(client_->executeEcHelperDirect(*wire, ctl));
  });
  SCOPE_EXIT { delay->unblock(); if (future.valid()) future.wait(); };
  ASSERT_EQ(entered.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  cancel.requestCancellation();
  auto target = components_->targetMap.getByTargetId(value->plan->input().sources[0].endpoint.targetId);
  ASSERT_OK(target);
  auto scope = (*target)->storageTarget->ecScopeState();
  ASSERT_OK(scope);
  EcScopeRevocation revoke{};
  revoke.binding.target = scope->second;
  revoke.binding.kind = 2;
  const auto copyUuid = [](auto &to, const Uuid &from) {
    std::copy(std::begin(from.data), std::end(from.data), to.begin());
  };
  copyUuid(revoke.binding.object, value->plan->input().sources[0].identity.object);
  copyUuid(revoke.binding.scope, value->plan->input().operationId);
  copyUuid(revoke.binding.client_namespace, value->plan->input().clientNamespace);
  revoke.binding.owner_uid = value->plan->input().ownerUid.toUnderType();
  copyUuid(revoke.id, Uuid::random());
  revoke.endpoint_set_digest = value->plan->endpointSetDigest();
  auto pending = scope->first->revoke(revoke);
  ASSERT_OK(pending);
  EXPECT_TRUE(pending->durable);
  EXPECT_FALSE(pending->drained);
  EXPECT_GE(pending->inflight, 1);
  delay->unblock();
  ASSERT_ERROR(future.get(), StorageCode::kEcSealOutcomeUnknown);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &t) { return t.entered == t.finished; }));
  auto drained = scope->first->drainStatus(revoke);
  ASSERT_OK(drained);
  EXPECT_TRUE(drained->drained);
  auto late = directRequest(*value);
  ASSERT_OK(late);
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*late, control())), StorageCode::kEcSealOutcomeUnknown);
  // Downstream effects may have finished after upstream cancellation. They are
  // intentionally not promoted into a successful repair or Meta publication.
}
