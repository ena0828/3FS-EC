// These tests use the real TCP service/Engine fixture. Explicit RDMA calls
// exercise only missing-endpoint rejection; no RDMA socket or hardware is faked.
TEST_F(TestEcNativeRepairService, HelperTransportRejectsUnknownIngressBeforeOwnedWork) {
  auto value = prepare({0}, 31, 1);
  ASSERT_OK(value);
  const auto wire = request(*value);
  auto direct = directRequest(*value);
  ASSERT_OK(direct);
  const auto before = replyDrop_.snapshot();
  StorageService service(components_->storageOperator);
  // The real Service copies its scalar before returning the task. Both contexts
  // have already died when the tasks are awaited; neither may be borrowed.
  auto missingHelper = [&] {
    serde::MessagePacket<> packet;
    serde::CallContext::ServiceWrapper registration;
    serde::CallContext ctx(packet, nullptr, registration);
    return service.executeEcHelper(ctx, wire);
  }();
  auto missingDirect = [&] {
    serde::MessagePacket<> packet;
    serde::CallContext::ServiceWrapper registration;
    serde::CallContext ctx(packet, nullptr, registration);
    return service.executeEcHelperDirect(ctx, *direct);
  }();
  auto helper = blockingWait(std::move(missingHelper));
  ASSERT_OK(helper);
  ASSERT_ERROR(helper->result, StatusCode::kInvalidArg);
  auto result = blockingWait(std::move(missingDirect));
  ASSERT_OK(result);
  ASSERT_ERROR(result->result, StatusCode::kInvalidArg);
  for (auto type : {net::Address::LOCAL, net::Address::UNIX, net::Address::IPoIB,
                    static_cast<net::Address::Type>(65535)}) {
    auto rejected = blockingWait(components_->storageOperator.executeEcHelper(wire, type));
    ASSERT_OK(rejected);
    ASSERT_ERROR(rejected->result, StatusCode::kInvalidArg);
    auto rejectedDirect = blockingWait(components_->storageOperator.executeEcHelperDirect(*direct, type));
    ASSERT_OK(rejectedDirect);
    ASSERT_ERROR(rejectedDirect->result, StatusCode::kInvalidArg);
  }
  EcRmwInstallReq install;
  EcRmwPutReq put;
  EcRmwActionReq action;
  const auto withoutContext = [&](auto invoke) {
    serde::MessagePacket<> packet;
    serde::CallContext::ServiceWrapper registration;
    serde::CallContext ctx(packet, nullptr, registration);
    return invoke(ctx);
  };
  auto missingInstall = withoutContext([&](auto &ctx) { return service.installEcRmw(ctx, install); });
  auto missingPut = withoutContext([&](auto &ctx) { return service.putEcRmw(ctx, put); });
  auto missingAction = withoutContext([&](auto &ctx) { return service.actionEcRmw(ctx, action); });
  auto installed = blockingWait(std::move(missingInstall));
  auto uploaded = blockingWait(std::move(missingPut));
  auto observed = blockingWait(std::move(missingAction));
  ASSERT_OK(installed);
  ASSERT_OK(uploaded);
  ASSERT_OK(observed);
  ASSERT_ERROR(installed->result, StatusCode::kInvalidArg);
  ASSERT_ERROR(uploaded->result, StatusCode::kInvalidArg);
  ASSERT_ERROR(observed->result, StatusCode::kInvalidArg);
  EXPECT_EQ(replyDrop_.snapshot().appendCalls, before.appendCalls);
  std::lock_guard lock(replyDrop_.mutex);
  for (auto calls : replyDrop_.helperHopCalls) EXPECT_EQ(calls, 0);
  EXPECT_EQ(replyDrop_.direct.entered, 0);
}

TEST_F(TestEcNativeRepairService, HelperTransportTcpIngressSelectsOnlyTcpAtEveryHop) {
  auto value = prepare({0, 11}, 31, 1);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  const auto wire = request(*value);
  auto direct = directRequest(*value);
  ASSERT_OK(direct);
  armDirect(*value);
  const auto original = routing_;
  SCOPE_EXIT {
    routing_ = original;
    mgmtd_->setRoutingInfo(original);
  };
  const auto advertise = [&](bool withTcp) {
    auto next = std::make_shared<flat::RoutingInfo>(*original);
    next->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
    size_t storageGroups = 0;
    for (auto &group : next->nodes.at(nodeId_).app.serviceGroups) {
      if (!group.services.contains("StorageSerde")) continue;
      ++storageGroups;
      auto rdma = address_;
      rdma.type = net::Address::RDMA;
      group.endpoints = {rdma};  // A different advertised type must never be selected.
      if (withTcp) group.endpoints.push_back(address_);
    }
    ASSERT_EQ(storageGroups, 1);
    routing_ = next;
    mgmtd_->setRoutingInfo(next);
  };
  ASSERT_NO_FATAL_FAILURE(advertise(true));
  auto recovered = blockingWait(messenger_->executeEcHelper(address_, wire, &options_));
  ASSERT_OK(recovered);
  ASSERT_OK(recovered->result);
  ASSERT_OK(verifyEcHelperFinal(*helperKey_, *value->plan, *recovered->result, 1000));
  for (uint8_t i = 0; i != 2; ++i)
    EXPECT_EQ(recovered->result->packet.outputs[i].data,
              repair_test::blockBytes(value->data, value->plan->input().targets[i], 0));
  auto written = blockingWait(messenger_->executeEcHelperDirect(address_, *direct, &options_));
  ASSERT_OK(written);
  ASSERT_OK(written->result);
  ASSERT_OK(verifyEcHelperDirectResult(*helperKey_, *value->plan, *direct, *written->result, 1000));
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &trace) { return trace.entered == trace.finished; }));
  auto trace = directTrace();
  EXPECT_EQ(trace.entered, 10);
  EXPECT_EQ(trace.zeroPrefixQueries, 2);
  EXPECT_EQ(trace.appends.size(), 2);
  {
    std::lock_guard lock(replyDrop_.mutex);
    for (auto calls : replyDrop_.helperHopCalls) EXPECT_EQ(calls, 1);
  }
  ASSERT_NO_FATAL_FAILURE(advertise(false));
  // Still enter the first real TCP listener explicitly. That listener must not
  // fall back to the only advertised RDMA next-hop address.
  auto unavailable = blockingWait(messenger_->executeEcHelper(address_, wire, &options_));
  ASSERT_OK(unavailable);
  ASSERT_ERROR(unavailable->result, StorageClientCode::kRoutingError);
  auto unavailableDirect = blockingWait(messenger_->executeEcHelperDirect(address_, *direct, &options_));
  ASSERT_OK(unavailableDirect);
  ASSERT_ERROR(unavailableDirect->result, StorageClientCode::kRoutingError);
  ASSERT_TRUE(replyDrop_.waitDirect([](const auto &state) { return state.entered == state.finished; }));
  trace = directTrace();
  EXPECT_EQ(trace.entered, 11);  // Only the new first-hop handler entered.
  EXPECT_EQ(trace.appends.size(), 2);
  EXPECT_EQ(trace.zeroPrefixQueries, 2);
  routing_ = original;
  mgmtd_->setRoutingInfo(original);
  ASSERT_NO_FATAL_FAILURE(expectDirectSealedBytes(*value));
  RecordProperty("transport_coverage", "real TCP ingress, ten return/direct hops and direct Query/Append; "
                                      "RDMA-first advertisements ignored; missing TCP rejected; not RDMA execution");
}

TEST_F(TestEcNativeRepairService, HelperTransportRdmaPolicyNeverFallsBackToTcp) {
  auto value = prepare({0, 11}, 31, 1);
  ASSERT_OK(value);
  ASSERT_OK(beginDirect(*value));
  const auto wire = request(*value);
  auto direct = directRequest(*value);
  ASSERT_OK(direct);
  armDirect(*value);
  size_t queries;
  {
    std::lock_guard lock(replyDrop_.mutex);
    queries = replyDrop_.queryCalls;
  }
  auto rdmaControl = control();
  rdmaControl.transport = client::EcRequestControl::TransportPolicy::RdmaOnly;
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*direct, rdmaControl)),
               StorageClientCode::kRoutingError);
  CancellationSource canceled;
  canceled.requestCancellation();
  auto canceledControl = control();
  canceledControl.cancellation = canceled.getToken();
  ASSERT_ERROR(blockingWait(client_->executeEcHelperDirect(*direct, canceledControl)),
               StorageClientCode::kRequestCanceled);
  EXPECT_EQ(directTrace().entered, 0);  // Pre-dispatch errors are not Unknown.
  // Explicit Operator calls reach the actual owned executor and authenticated
  // source read. No RDMA endpoint exists, so they cannot delegate to TCP.
  auto helper = blockingWait(components_->storageOperator.executeEcHelper(wire, net::Address::RDMA));
  ASSERT_OK(helper);
  ASSERT_ERROR(helper->result, StorageClientCode::kRoutingError);
  auto first = blockingWait(components_->storageOperator.executeEcHelperDirect(*direct, net::Address::RDMA));
  ASSERT_OK(first);
  ASSERT_ERROR(first->result, StorageClientCode::kRoutingError);
  // Independently construct a valid predecessor chain to reach the real final
  // helper's target Query boundary without claiming nine RDMA network hops.
  auto tail = *direct;
  for (uint8_t position = 0; position != 9; ++position) {
    auto computed = EcRepairBlockCore::advance(*value->plan, position, repairBlock(tail.packet),
        repair_test::blockBytes(value->data, value->plan->input().sources[position], 0));
    ASSERT_OK(computed);
    auto packet = helperPacket(std::move(*computed));
    auto stamp = ec_helper_direct_detail::stamp(*helperKey_, *value->plan, tail, packet, 1000);
    ASSERT_OK(stamp);
    tail.packet = std::move(packet);
    tail.predecessor = std::move(*stamp);
  }
  ASSERT_EQ(tail.packet.nextHelper, 9);
  auto last = blockingWait(components_->storageOperator.executeEcHelperDirect(tail, net::Address::RDMA));
  ASSERT_OK(last);
  ASSERT_ERROR(last->result, StorageClientCode::kRoutingError);
  // A local hot force_use_tcp setting must not silently turn an explicitly
  // selected RDMA hop into a TCP call. The actual ClientContext rejects before
  // encoding/Waiter/send; the Direct forwarding path still preserves Unknown.
  const auto original = routing_;
  const auto originalForce = config_.forward_client().force_use_tcp();
  SCOPE_EXIT {
    config_.forward_client().set_force_use_tcp(originalForce);
    routing_ = original;
    mgmtd_->setRoutingInfo(original);
  };
  auto next = std::make_shared<flat::RoutingInfo>(*original);
  next->routingInfoVersion = flat::RoutingInfoVersion{++routingVersion_};
  for (auto &group : next->nodes.at(nodeId_).app.serviceGroups) {
    if (!group.services.contains("StorageSerde")) continue;
    auto advertisedRdma = address_;
    advertisedRdma.type = net::Address::RDMA;
    group.endpoints = {advertisedRdma};
  }
  routing_ = next;
  mgmtd_->setRoutingInfo(next);
  config_.forward_client().set_force_use_tcp(true);
  auto forcedHelper = blockingWait(components_->storageOperator.executeEcHelper(wire, net::Address::RDMA));
  ASSERT_OK(forcedHelper);
  ASSERT_ERROR(forcedHelper->result, StatusCode::kInvalidArg);
  auto forcedFirst = blockingWait(components_->storageOperator.executeEcHelperDirect(*direct, net::Address::RDMA));
  ASSERT_OK(forcedFirst);
  ASSERT_ERROR(forcedFirst->result, StorageCode::kEcSealOutcomeUnknown);
  auto forcedLast = blockingWait(components_->storageOperator.executeEcHelperDirect(tail, net::Address::RDMA));
  ASSERT_OK(forcedLast);
  ASSERT_ERROR(forcedLast->result, StatusCode::kInvalidArg);
  routing_ = original;
  mgmtd_->setRoutingInfo(original);
  config_.forward_client().set_force_use_tcp(originalForce);
  EXPECT_TRUE(directTrace().appendAttempts.empty());
  {
    std::lock_guard lock(replyDrop_.mutex);
    EXPECT_EQ(replyDrop_.queryCalls, queries);
    for (auto calls : replyDrop_.helperHopCalls) EXPECT_EQ(calls, 0);
  }
  for (const auto &fixed : value->bindings.targets) {
    auto state = blockingWait(client_->queryEcStageV2Controlled({fixed.request, fixed.grant}, control()));
    ASSERT_OK(state);
    EXPECT_EQ(state->prefixBytes, 0);
    EXPECT_FALSE(state->pendingBlock);
  }
  RecordProperty("transport_coverage", "owned RDMA policy rejects TCP-only next hop and direct final target; "
                                      "no RDMA connection attempted or hardware result claimed");
}
