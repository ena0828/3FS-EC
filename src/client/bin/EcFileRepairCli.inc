// Included after Config and the shared CLI parsers. Existing mode4 command
// dispatch stays unchanged; this facade owns only explicit repair commands.
bool isMode4RepairCommand(std::string_view command) {
  return command == "mode4-repair" || command == "mode4-resume-repair" || command == "mode4-query-repair" ||
         command == "mode4-close-repair-debt";
}
Result<std::array<uint8_t, 10>> repairSources(std::string_view text, uint16_t mask) {
  std::array<uint8_t, 10> out{};
  uint16_t seen = 0;
  for (size_t n = 0; n < out.size(); ++n) {
    const auto comma = text.find(',');
    if ((n == 9) != (comma == std::string_view::npos))
      return makeError(StatusCode::kInvalidArg, "repair_source_order requires exactly ten comma-separated indices");
    auto value = decimal(text.substr(0, comma));
    if (!value || *value >= 12)
      return makeError(StatusCode::kInvalidArg, "source index must be canonical decimal 0..11");
    const auto bit = uint16_t{1} << *value;
    if ((seen & bit) || (mask & bit))
      return makeError(StatusCode::kInvalidArg, "repair sources must be unique and outside the replacement mask");
    seen |= bit;
    out[n] = static_cast<uint8_t>(*value);
    if (comma != std::string_view::npos) text.remove_prefix(comma + 1);
  }
  return out;
}
const char *repairModeName(meta::EcFileRepairMode mode) {
  switch (mode) {
    case meta::EcFileRepairMode::CentralSerial:
      return "central";
    case meta::EcFileRepairMode::ClientPipeline:
      return "pipeline";
    case meta::EcFileRepairMode::HelperChain:
    case meta::EcFileRepairMode::HelperChainDirect:
      return "helper";
  }
  return "invalid";
}
int executeMode4Repair(const Config &cfg, const std::string &command) {
  const bool fresh = command == "mode4-repair";
  std::unique_ptr<EcTreeRepairJournal> journal;
  std::unique_ptr<EcFilePwriteJournal> session;
  EcTreeRepairOutcome result;
  auto emit = [&] {
    const bool observed = result.progress.record.has_value();
    const auto state = observed ? result.progress.record->state : meta::EcFileRepairState::Planned;
    const bool published = observed && state == meta::EcFileRepairState::Published;
    const bool aborted = observed && state == meta::EcFileRepairState::Aborted;
    folly::dynamic out = folly::dynamic::object("schema", 1)("command", command)("observed", observed)(
        "state",
        !observed   ? "Missing"
        : published ? "Published"
        : aborted   ? "Aborted"
                    : "Planned")("published", published)("output_drained", result.progress.outputDrained)(
        "source_released",
        result.progress.sourceReleased)("output_closing", result.progress.outputClosing)("revalidated",
                                                                                         result.revalidated)(
        "all_cleanup_complete",
        observed && result.progress.outputDrained && result.progress.sourceReleased)("failure", nullptr);
    if (result.failure)
      out["failure"] = folly::dynamic::object("code", result.failure->code())("message", result.failure->describe());
    if (journal) {
      const auto &r = journal->record();
      const auto &i = r.intent;
      out["cluster"] = r.cluster;
      out["client_namespace"] = i.owner.client.toHexString();
      out["inode_decimal"] = std::to_string(i.object.inode.u64());
      out["incarnation"] = i.object.incarnation.toHexString();
      out["session"] = i.session.toHexString();
      out["operation"] = i.operation.toHexString();
      out["child"] = i.child.toHexString();
      out["plan"] = i.selection.planId.toHexString();
      out["source_pin"] = i.sourcePin.toHexString();
      out["captured_root"] = i.expectedRoot.toHexString();
      out["captured_sequence_decimal"] = std::to_string(i.expectedSequence);
      out["captured_epoch_decimal"] = std::to_string(i.expectedEpoch);
      out["stripe_decimal"] = std::to_string(i.stripe);
      out["replacement_mask_decimal"] = std::to_string(i.replacementMask);
      out["strategy"] = repairModeName(i.mode);
      out["delivery"] = i.mode == meta::EcFileRepairMode::HelperChainDirect ? "direct" : "return";
      out["window"] = unsigned(i.selection.maxBlocksInFlight);
      out["source_order"] = folly::dynamic::array();
      for (auto index : i.selection.sourceOrder) out["source_order"].push_back(unsigned(index));
    }
    const auto business = folly::toJson(out);
    if (!cfg.repair_metrics()) {
      std::cout << business << '\n';
      return;
    }
    std::string metrics;
    bool available = false;
    try {
      if (result.metrics.available) {
        metrics = repairMetricsJson(result.metrics);
        available = true;
      }
    } catch (...) {
      // No telemetry failure becomes a business failure/unknown commit.
    }
    std::cout.write(business.data(), business.size() - 1);
    std::cout << ",\"metrics\":";
    if (available) std::cout << metrics;
    else std::cout << "null";
    std::cout << ",\"telemetry_unavailable\":" << (available ? "false" : "true") << "}\n";
  };
  auto fail = [&](Status error, int code = 1) {
    if (journal && journal->latest()) result.progress = journal->latest()->progress;
    result.failure = std::move(error);
    result.revalidated = false;
    emit();
    std::cerr << "repair unconfirmed: " << result.failure->describe() << "; retain the original run and IDs\n";
    return code;
  };
  try {
    if (!isMode4RepairCommand(command)) return fail(Status(StatusCode::kInvalidArg), 2);
    if (cfg.run_dir().empty() || !std::filesystem::path(cfg.run_dir()).is_absolute())
      return fail(Status(StatusCode::kInvalidArg, "repair requires an explicit absolute run_dir"), 2);
    if (!cfg.inode_decimal().empty() || !cfg.incarnation().empty() || !cfg.birth().empty() ||
        !cfg.file_path().empty() || !cfg.offset_decimal().empty() || !cfg.length_decimal().empty() ||
        !cfg.input_file().empty() || !cfg.output_file().empty())
      return fail(Status(StatusCode::kInvalidArg,
                         "repair uses the session/run object and does not accept file, extent or payload overrides"),
                  2);
    std::string cluster = cfg.cluster_id();
    Uuid ns = Uuid::zero();
    uint64_t stripe = 0;
    uint16_t mask = 0, window = 2;
    meta::EcFileRepairMode mode = meta::EcFileRepairMode::CentralSerial;
    std::array<uint8_t, 10> sources{};
    if (fresh) {
      auto parsedStripe = decimal(cfg.repair_stripe_decimal());
      auto parsedMask = decimal(cfg.repair_mask_decimal());
      auto parsedWindow =
          cfg.repair_window_decimal().empty() ? Result<uint64_t>(uint64_t{2}) : decimal(cfg.repair_window_decimal());
      if (!parsedStripe || !parsedMask || !*parsedMask || *parsedMask > 4095 ||
          std::popcount(static_cast<uint16_t>(*parsedMask)) > 2 || !parsedWindow || !*parsedWindow || *parsedWindow > 4)
        return fail(Status(StatusCode::kInvalidArg, "repair needs stripe, a one/two-bit 12-shard mask and window 1..4"),
                    2);
      stripe = *parsedStripe;
      mask = static_cast<uint16_t>(*parsedMask);
      window = static_cast<uint16_t>(*parsedWindow);
      if (cfg.repair_mode() == "central")
        mode = meta::EcFileRepairMode::CentralSerial;
      else if (cfg.repair_mode() == "pipeline")
        mode = meta::EcFileRepairMode::ClientPipeline;
      else if (cfg.repair_mode() == "helper")
        mode = meta::EcFileRepairMode::HelperChain;
      else
        return fail(Status(StatusCode::kInvalidArg, "repair_mode must be central, pipeline or helper"), 2);
      if (!cfg.repair_delivery().empty() && cfg.repair_delivery() != "return" && cfg.repair_delivery() != "direct")
        return fail(Status(StatusCode::kInvalidArg, "repair_delivery must be return or direct"), 2);
      if (!cfg.repair_delivery().empty() && mode != meta::EcFileRepairMode::HelperChain)
        return fail(Status(StatusCode::kInvalidArg, "repair_delivery requires helper strategy"), 2);
      if (cfg.repair_delivery() == "direct") {
        mode = meta::EcFileRepairMode::HelperChainDirect;
      }
      auto order = repairSources(cfg.repair_source_order(), mask);
      if (!order) return fail(std::move(order.error()), 2);
      sources = *order;
      auto old = EcFilePwriteJournal::resume(cfg.session_run_dir());
      if (!old) return fail(std::move(old.error()));
      session = std::move(*old);
      if (session->record().kind != EcPwriteRunKind::Session || !session->latest() || !session->latest()->session ||
          session->latest()->session->state != meta::EcFileSessionState::Open ||
          session->latest()->session->intent.rights != 3)
        return fail(Status(MetaCode::kNoPermission, "an accepted, open READ|WRITE session journal is required"), 2);
      ns = session->record().owner.client;
      if (!cluster.empty() && cluster != session->record().cluster) return fail(Status(StatusCode::kTokenMismatch), 2);
      cluster = session->record().cluster;
    } else {
      // Even an equal-looking override is forbidden: resume consumes the
      // original immutable body, never a partially reconstructed request.
      if (!cfg.session_run_dir().empty() || !cfg.repair_stripe_decimal().empty() ||
          !cfg.repair_mask_decimal().empty() || !cfg.repair_mode().empty() || !cfg.repair_source_order().empty() ||
          !cfg.repair_window_decimal().empty() || !cfg.repair_delivery().empty())
        return fail(Status(StatusCode::kInvalidArg, "resume/query/close-debt accept only the original repair run"), 2);
      auto old = EcTreeRepairJournal::resume(cfg.run_dir());
      if (!old) return fail(std::move(old.error()));
      journal = std::move(*old);
      if (journal->latest()) result.progress = journal->latest()->progress;
      ns = journal->record().intent.owner.client;
      if (!cluster.empty() && cluster != journal->record().cluster) return fail(Status(StatusCode::kTokenMismatch), 2);
      cluster = journal->record().cluster;
    }
    if (cluster.empty() || (!cfg.client_namespace().empty() && cfg.client_namespace() != ns.toHexString()))
      return fail(Status(StatusCode::kTokenMismatch, "cluster and namespace must match the persistent run"), 2);
    auto token = tokenFile(cfg.user_info().token_file());
    if (!token) return fail(std::move(token.error()));
    logging::initOrDie(cfg.log());
    auto monitored = monitor::Monitor::start(cfg.monitor());
    if (!monitored) return fail(std::move(monitored.error()));
    SCOPE_EXIT { monitor::Monitor::stop(); };
    auto network = std::make_shared<net::Client>(cfg.client());
    auto started = network->start("EcFileRepairCli");
    if (!started) return fail(std::move(started.error()));
    SCOPE_EXIT { network->stopAndJoin(); };
    auto mgmtd = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
        cluster,
        std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
            [network](net::Address a) { return network->serdeCtx(a); }),
        cfg.mgmtd_client());
    blockingWait(mgmtd->start(&network->tpg().bgThreadPool().randomPick()));
    SCOPE_EXIT { blockingWait(mgmtd->stop()); };
    auto refreshedRouting = blockingWait(mgmtd->refreshRoutingInfo(true));
    if (!refreshedRouting) return fail(std::move(refreshedRouting.error()));
    auto storage = storage::client::StorageClient::create(ClientId(ns), cfg.storage_client(), *mgmtd);
    if (!storage) return fail(Status(StorageClientCode::kNotInitialized));
    SCOPE_EXIT { storage->stop(); };
    auto metadata =
        std::make_shared<meta::client::MetaClient>(ClientId(ns),
                                                   cfg.meta_client(),
                                                   std::make_unique<meta::client::MetaClient::StubFactory>(
                                                       [network](net::Address a) { return network->serdeCtx(a); }),
                                                   mgmtd,
                                                   storage,
                                                   false);
    SCOPE_EXIT { metadata->stop(); };
    flat::UserInfo credentials{flat::Uid(cfg.user_info().uid()), flat::Gid(cfg.user_info().gid()), std::move(*token)};
    if (fresh) {
      // The only request before creating the repair run replays an already
      // durable session Open identity to capture current root/sequence/epoch.
      auto rmw = std::make_shared<storage::client::EcRmwTransport>(cfg.client());
      auto startedRmw = rmw->start();
      if (!startedRmw) return fail(std::move(startedRmw.error()));
      SCOPE_EXIT { rmw->stopAndJoin(); };
      auto writer = EcFilePwriteClient::connect(metadata, rmw, mgmtd, credentials, ns);
      if (!writer) return fail(std::move(writer.error()));
      if (session->record().owner.uid != (*writer)->owner().uid) return fail(Status(MetaCode::kNoPermission));
      auto accepted = (*writer)->open(*session, control(cfg));
      if (!accepted) return fail(std::move(accepted.error()));
      if (!session->latest()->root) return fail(Status(StatusCode::kDataCorruption));
      auto record =
          prepareEcTreeRepair(*accepted, *session->latest()->root, cluster, stripe, mask, mode, sources, window);
      if (!record) return fail(std::move(record.error()));
      auto created = EcTreeRepairJournal::create(cfg.run_dir(), std::move(*record));
      if (!created) return fail(std::move(created.error()));
      journal = std::move(*created);
      session.reset();
    }
    auto connected = EcFileRepairClient::connect(metadata, storage, mgmtd, credentials, ns);
    if (!connected) return fail(std::move(connected.error()));
    auto client = std::move(*connected);
    result = command == "mode4-query-repair"        ? client->query(*journal, control(cfg), cfg.repair_metrics())
             : command == "mode4-close-repair-debt" ? client->closeDebt(*journal, control(cfg), cfg.repair_metrics())
                                                    : client->repair(*journal, control(cfg), cfg.repair_metrics());
    emit();
    if (result.failure) {
      std::cerr << "repair unconfirmed: " << result.failure->describe() << "; retain the original run and IDs\n";
      return 1;
    }
    if (!result.revalidated) return 1;
    if (command == "mode4-query-repair") return 0;  // Missing remains explicitly nonterminal.
    if (!result.progress.record) return 1;
    const auto state = result.progress.record->state;
    if (command == "mode4-close-repair-debt")
      return (state == meta::EcFileRepairState::Published || state == meta::EcFileRepairState::Aborted) &&
                     result.progress.outputDrained && result.progress.sourceReleased
                 ? 0
                 : 1;
    // Publication does not pretend that old source debt has been cleared.
    return state == meta::EcFileRepairState::Published && result.progress.outputDrained ? 0 : 1;
  } catch (...) {
    return fail(Status(TransactionCode::kMaybeCommitted,
                       "repair CLI interrupted after possible dispatch; resume original run"));
  }
}
