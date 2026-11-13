// Included in the real TCP/Rust Engine fixture. No transport or disk result is
// synthesized; faults occur only around an actual handler or its successful reply.
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
