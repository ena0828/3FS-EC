// Included inside ec_file_cli's anonymous namespace. Mode 4 is deliberately
// separate from legacy mode-3 append-at/range run formats and permissions.
int executeMode4(const Config &cfg, const std::string &command) {
  if (command == "mode4-export-output-identities") {
    auto exported = exportEcFileOutputIdentities(cfg.run_dir(), cfg.output_kind(), cfg.output_file());
    if (!exported) {
      std::cerr << "unconfirmed local identity export: " << exported.error().describe() << '\n';
      return 1;
    }
    std::cout << "{\"kind\":\"ec_file_output_identities_exported\",\"candidate_identities_only\":true,"
                 "\"network_io_performed\":false}\n";
    return 0;
  }
  // No token, RPC client, worker or IB device is needed for this local archive.
  if (command == "mode4-export-read-allocations") {
    auto exported = exportEcTreeReadAllocations(cfg.run_dir(), cfg.output_file());
    if (!exported) {
      std::cerr << "unconfirmed local snapshot export: " << exported.error().describe() << '\n';
      return 1;
    }
    std::cout << "{\"kind\":\"ec_tree_read_allocations_exported\",\"network_io_performed\":false}\n";
    return 0;
  }
  const bool freshSession = command == "mode4-create" || command == "mode4-open";
  const bool freshWrite = command == "mode4-pwrite";
  const bool freshRead = command == "mode4-read";
  const bool freshAppend = command == "mode4-append";
  const bool freshSync = command == "mode4-fsync";
  const bool oldAppend =
      command == "mode4-resume-append" || command == "mode4-query-append" || command == "mode4-seal-append";
  const bool oldSync = command == "mode4-resume-fsync";
  const bool freshTruncate = command == "mode4-truncate";
  const bool oldTruncate =
      command == "mode4-resume-truncate" || command == "mode4-query-truncate" || command == "mode4-close-truncate-debt";
  const bool treeExisting = command == "mode4-resume-read" || command == "mode4-release-read";
  const bool pwriteExisting = command == "mode4-resume" || command == "mode4-query" || command == "mode4-seal";
  if (!freshSession && !freshWrite && !freshRead && !freshTruncate && !oldTruncate && !freshAppend && !freshSync &&
      !oldAppend && !oldSync && !treeExisting && !pwriteExisting && command != "mode4-close" &&
      command != "mode4-resume-open" && command != "mode4-inspect") {
    std::cerr << "unknown mode4 command\n";
    return 2;
  }
  std::shared_ptr<EcFilePwriteJournal> run, sessionRun;
  std::shared_ptr<EcTreeReadJournal> tree;
  std::shared_ptr<EcTruncateJournal> truncation;
  std::shared_ptr<EcAppendJournal> appendRun;
  std::string cluster = cfg.cluster_id();
  Uuid ns = Uuid::zero();
  auto fail = [](const Status &s) {
    std::cerr << "unconfirmed: " << s.describe() << "; retain original run and IDs\n";
    return 1;
  };
  if (freshWrite || freshRead || freshTruncate || freshAppend || freshSync) {
    auto old = EcFilePwriteJournal::resume(cfg.session_run_dir());
    if (!old) return fail(old.error());
    sessionRun = std::shared_ptr<EcFilePwriteJournal>(std::move(*old));
    if (sessionRun->record().kind != EcPwriteRunKind::Session || !sessionRun->latest() ||
        !sessionRun->latest()->session) {
      std::cerr << "accepted session run required\n";
      return 2;
    }
    ns = sessionRun->record().owner.client;
    if (!cluster.empty() && cluster != sessionRun->record().cluster) {
      std::cerr << "cluster differs\n";
      return 2;
    }
    cluster = sessionRun->record().cluster;
  } else if (oldAppend || oldSync) {
    auto old = EcAppendJournal::resume(cfg.run_dir());
    if (!old) return fail(old.error());
    appendRun = std::shared_ptr<EcAppendJournal>(std::move(*old));
    ns = appendRun->record().session.intent.owner.client;
    if ((!cluster.empty() && cluster != appendRun->record().cluster) || !cfg.offset_decimal().empty() ||
        !cfg.length_decimal().empty() || !cfg.inode_decimal().empty() || !cfg.incarnation().empty() ||
        !cfg.file_path().empty() || !cfg.birth().empty() ||
        (!cfg.input_file().empty() &&
         std::filesystem::absolute(cfg.input_file()).string() != appendRun->record().inputPath))
      return fail(Status(StatusCode::kTokenMismatch));
    if ((oldSync && appendRun->record().kind != EcAppendRunKind::Sync) ||
        (oldAppend && appendRun->record().kind != EcAppendRunKind::Append))
      return fail(Status(StatusCode::kTokenMismatch));
    cluster = appendRun->record().cluster;
  } else if (oldTruncate) {
    auto old = EcTruncateJournal::resume(cfg.run_dir());
    if (!old) return fail(old.error());
    truncation = std::shared_ptr<EcTruncateJournal>(std::move(*old));
    ns = truncation->record().session.owner.client;
    if ((!cluster.empty() && cluster != truncation->record().cluster) || !cfg.length_decimal().empty() ||
        !cfg.offset_decimal().empty() || !cfg.input_file().empty() || !cfg.inode_decimal().empty() ||
        !cfg.incarnation().empty() || !cfg.birth().empty() || !cfg.file_path().empty())
      return fail(Status(StatusCode::kTokenMismatch));
    cluster = truncation->record().cluster;
  } else if (treeExisting) {
    auto old = EcTreeReadJournal::resume(cfg.run_dir());
    if (!old) return fail(old.error());
    tree = std::shared_ptr<EcTreeReadJournal>(std::move(*old));
    ns = tree->record().session.owner.client;
    if (!cluster.empty() && cluster != tree->record().cluster) {
      std::cerr << "cluster differs\n";
      return 2;
    }
    cluster = tree->record().cluster;
  } else if (!freshSession) {
    auto old = EcFilePwriteJournal::resume(cfg.run_dir());
    if (!old) return fail(old.error());
    run = std::shared_ptr<EcFilePwriteJournal>(std::move(*old));
    ns = run->record().owner.client;
    if (!cluster.empty() && cluster != run->record().cluster) {
      std::cerr << "cluster differs\n";
      return 2;
    }
    cluster = run->record().cluster;
    if (!cfg.input_file().empty() && std::filesystem::absolute(cfg.input_file()).string() != run->record().inputPath) {
      std::cerr << "input path differs\n";
      return 2;
    }
    if (!cfg.inode_decimal().empty() || !cfg.incarnation().empty() || !cfg.birth().empty() ||
        !cfg.file_path().empty() || !cfg.offset_decimal().empty() || !cfg.length_decimal().empty()) {
      std::cerr << "resume uses original identity and extent\n";
      return 2;
    }
  } else {
    auto parsed = cfg.client_namespace().empty() ? Result<Uuid>(Uuid::random()) : nonzeroUuid(cfg.client_namespace());
    if (!parsed) return fail(parsed.error());
    ns = *parsed;
  }
  if (cluster.empty() || (!cfg.client_namespace().empty() && cfg.client_namespace() != ns.toHexString())) {
    std::cerr << "explicit cluster and matching persistent namespace required\n";
    return 2;
  }
  auto show = [&](const EcFilePwriteJournal &j) {
    folly::dynamic o =
        folly::dynamic::object("schema", 1)("kind", unsigned(j.record().kind))("client_namespace",
                                                                               j.record().owner.client.toHexString())(
            "session",
            j.record().session.toHexString())("operation", j.record().operation.toHexString())(
            "offset_decimal",
            std::to_string(j.record().offset))("length_decimal", std::to_string(j.record().length));
    if (j.latest()) {
      const auto &p = *j.latest();
      o["sequence_decimal"] = std::to_string(p.sequence);
      o["error_code"] = p.errorCode;
      o["cleaned_mask_decimal"] = std::to_string(p.cleanedMask);
      if (p.session) {
        const auto &s = *p.session;
        o["inode_decimal"] = std::to_string(s.intent.object.inode.u64());
        o["incarnation"] = s.intent.object.incarnation.toHexString();
        o["birth"] = s.intent.birth.toHexString();
        o["session_state"] = unsigned(s.state);
        o["shard_bytes"] = p.shardBytes;
      }
      if (p.parent) {
        o["confirmed_prefix_decimal"] = std::to_string(p.parent->confirmedPrefix);
        o["parent_state"] = unsigned(p.parent->state);
      }
    }
    std::cout << folly::toJson(o) << '\n';
  };
  if (command == "mode4-inspect") {
    show(*run);
    return 0;
  }
  auto token = tokenFile(cfg.user_info().token_file());
  if (!token) return fail(token.error());
  logging::initOrDie(cfg.log());
  auto monitored = monitor::Monitor::start(cfg.monitor());
  if (!monitored) return fail(monitored.error());
  SCOPE_EXIT { monitor::Monitor::stop(); };
  auto network = std::make_shared<net::Client>(cfg.client());
  auto started = network->start("EcFileMode4Cli");
  if (!started) return fail(started.error());
  SCOPE_EXIT { network->stopAndJoin(); };
  auto mgmtd = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
      cluster,
      std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
          [network](net::Address a) { return network->serdeCtx(a); }),
      cfg.mgmtd_client());
  blockingWait(mgmtd->start(&network->tpg().bgThreadPool().randomPick()));
  SCOPE_EXIT { blockingWait(mgmtd->stop()); };
  auto routing = blockingWait(mgmtd->refreshRoutingInfo(true));
  if (!routing) return fail(routing.error());
  auto storage = storage::client::StorageClient::create(ClientId(ns), cfg.storage_client(), *mgmtd);
  if (!storage) {
    std::cerr << "storage client unavailable\n";
    return 2;
  }
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
  auto rmw = std::make_shared<storage::client::EcRmwTransport>(cfg.client());
  auto rstart = rmw->start();
  if (!rstart) return fail(rstart.error());
  SCOPE_EXIT { rmw->stopAndJoin(); };
  flat::UserInfo credentials{flat::Uid(cfg.user_info().uid()), flat::Gid(cfg.user_info().gid()), std::move(*token)};
  auto client = EcFilePwriteClient::connect(metadata, rmw, mgmtd, credentials, ns);
  if (!client) return fail(client.error());
  if (sessionRun && (sessionRun->record().owner.uid != (*client)->owner().uid ||
                     sessionRun->record().owner.client != (*client)->owner().client))
    return fail(Status(StatusCode::kTokenMismatch));
  if (freshSession) {
    meta::EcObjectRef object;
    Uuid birth = Uuid::zero();
    if (command == "mode4-open") {
      auto inode = decimal(cfg.inode_decimal());
      auto incarnation = nonzeroUuid(cfg.incarnation());
      auto b = nonzeroUuid(cfg.birth());
      if (!inode || !incarnation || !b || !cfg.file_path().empty()) {
        std::cerr << "open requires exact inode/incarnation/birth\n";
        return 2;
      }
      object = {meta::InodeId(*inode), *incarnation};
      birth = *b;
    } else if (!cfg.inode_decimal().empty() || !cfg.incarnation().empty() || !cfg.birth().empty()) {
      std::cerr << "create cannot select old object identity\n";
      return 2;
    }
    if (cfg.session_rights() < 1 || cfg.session_rights() > 3) return 2;
    auto record = prepareEcPwriteSession((*client)->owner(),
                                         cluster,
                                         command == "mode4-create",
                                         cfg.file_path(),
                                         object,
                                         birth,
                                         cfg.shard_bytes(),
                                         uint8_t(cfg.session_rights()),
                                         cfg.permission());
    if (!record) return fail(record.error());
    auto j = EcFilePwriteJournal::create(cfg.run_dir(), std::move(*record));
    if (!j) return fail(j.error());
    run = std::shared_ptr<EcFilePwriteJournal>(std::move(*j));
  }
  if (freshSession || command == "mode4-resume-open") {
    auto opened = (*client)->open(*run, control(cfg));
    show(*run);
    return opened ? 0 : fail(opened.error());
  }
  if (command == "mode4-close") {
    auto closed = (*client)->closeSession(*run, control(cfg));
    show(*run);
    return closed && closed->state == meta::EcFileSessionState::Closed ? 0 : closed ? 1 : fail(closed.error());
  }
  if (freshAppend || freshSync || oldAppend || oldSync) {
    if (!cfg.offset_decimal().empty() || !cfg.length_decimal().empty()) return fail(Status(StatusCode::kInvalidArg));
    auto appender = EcFileAppendClient::connect(metadata, **client, credentials, ns);
    if (!appender) return fail(appender.error());
    std::optional<EcFilePayload> input;
    if (freshAppend || freshSync) {
      Result<EcAppendRun> record = makeError(StatusCode::kInvalidArg);
      if (freshAppend) {
        if (cfg.input_file().empty()) return 2;
        const auto path = std::filesystem::absolute(cfg.input_file());
        auto data = (*client)->readInput(path);
        if (!data) return fail(data.error());
        record = prepareEcAppend(*sessionRun->latest()->session,
                                 sessionRun->latest()->shardBytes,
                                 cluster,
                                 path.string(),
                                 (std::filesystem::absolute(cfg.run_dir()) / "pwrite").string(),
                                 data->bytes());
        input.emplace(std::move(*data));
      } else {
        if (!cfg.input_file().empty()) return 2;
        record = prepareEcSync(*sessionRun->latest()->session, cluster);
      }
      if (!record) return fail(record.error());
      auto created = EcAppendJournal::create(cfg.run_dir(), std::move(*record));
      if (!created) return fail(created.error());
      appendRun = std::shared_ptr<EcAppendJournal>(std::move(*created));
    }
    if (freshSync || oldSync) {
      auto done = (*appender)->fsync(*appendRun, control(cfg));
      if (!done) return fail(done.error());
      folly::dynamic out = folly::dynamic::object("synced", true)("request", done->intent.request.toHexString())(
          "durability_contract",
          done->durabilityContract)("root_sequence_decimal", std::to_string(done->root.sequence))(
          "length_decimal",
          std::to_string(done->root.visibleLength))("error_code", 0);
      std::cout << folly::toJson(out) << '\n';
      return 0;
    }
    Result<EcAppendOutcome> result = makeError(StatusCode::kInvalidArg);
    if (command == "mode4-query-append")
      result = (*appender)->query(*appendRun, control(cfg));
    else if (command == "mode4-seal-append")
      result = (*appender)->sealAndCleanup(*appendRun, control(cfg));
    else {
      if (!input) {
        auto data = (*client)->readInput(appendRun->record().inputPath);
        if (!data) return fail(data.error());
        input.emplace(std::move(*data));
      }
      result = (*appender)->append(*appendRun, std::move(*input), control(cfg));
    }
    if (!result) return fail(result.error());
    const auto &w = result->write;
    folly::dynamic out = folly::dynamic::object("accepted_offset_decimal", std::to_string(result->acceptedOffset))(
        "confirmed_prefix_decimal",
        std::to_string(w.confirmedPrefix))("revalidated_prefix_decimal", std::to_string(w.revalidatedPrefix))(
        "logical_closed",
        w.logicalClosed)("logical_complete", w.logicalComplete)("all_cleanup_complete", w.allCleanupComplete)(
        "error_code",
        w.failure ? w.failure->code() : 0);
    std::cout << folly::toJson(out) << '\n';
    if (w.failure) return fail(*w.failure);
    return command == "mode4-query-append"                                                   ? 0
           : (w.allCleanupComplete && (command == "mode4-seal-append" || w.logicalComplete)) ? 0
                                                                                             : 1;
  }
  if (freshTruncate || oldTruncate) {
    if (freshTruncate) {
      auto length = decimal(cfg.length_decimal());
      if (!length || !cfg.offset_decimal().empty() || !cfg.input_file().empty()) return 2;
      // Replay the original accepted Open. It captures a current root without
      // inventing another birth/session; the truncate run fixes that CAS forever.
      auto refreshed = (*client)->open(*sessionRun, control(cfg));
      if (!refreshed || !sessionRun->latest()->root) return refreshed ? 1 : fail(refreshed.error());
      auto record = prepareEcFileTruncate(*refreshed, *sessionRun->latest()->root, cluster, *length);
      if (!record) return fail(record.error());
      auto created = EcTruncateJournal::create(cfg.run_dir(), std::move(*record));
      if (!created) return fail(created.error());
      truncation = std::shared_ptr<EcTruncateJournal>(std::move(*created));
    }
    if (truncation->record().intent.owner.uid != (*client)->owner().uid ||
        truncation->record().intent.owner.client != ns)
      return fail(Status(StatusCode::kTokenMismatch));
    folly::CPUThreadPoolExecutor executor(cfg.worker_threads());
    auto connected = blockingWait(EcFileClient::connect(metadata,
                                                        storage,
                                                        mgmtd,
                                                        credentials,
                                                        ns,
                                                        executor,
                                                        std::chrono::seconds(cfg.deadline_seconds())));
    if (!connected) return fail(connected.error());
    auto client = std::move(*connected);
    SCOPE_EXIT { blockingWait(client->close()); };
    auto progress = command == "mode4-query-truncate" ? blockingWait(client->queryTruncate(truncation, control(cfg)))
                    : command == "mode4-close-truncate-debt"
                        ? blockingWait(client->closeTruncateDebt(truncation, control(cfg)))
                        : blockingWait(client->truncate(truncation, control(cfg)));
    if (!progress) return fail(progress.error());
    const bool observed = progress->observed.has_value();
    const bool published = observed && progress->observed->state == meta::EcFileTruncateState::Published;
    const bool aborted = observed && progress->observed->state == meta::EcFileTruncateState::Aborted;
    const bool cleaned = observed && progress->observed->outputDrained && progress->observed->sourceReleased;
    folly::dynamic out = folly::dynamic::object("operation", progress->intent.operation.toHexString())(
        "length_decimal",
        std::to_string(progress->intent.length))("observed", observed)("published", published)("aborted", aborted)(
        "all_cleanup_complete",
        cleaned)("error_code", 0);
    std::cout << folly::toJson(out) << '\n';
    // One bounded advance. Planned requires another SAME-run resume; never
    // hide a pending operation behind exit 0 or automatically abandon it.
    return command == "mode4-query-truncate"        ? 0
           : command == "mode4-close-truncate-debt" ? ((published || aborted) && cleaned ? 0 : 1)
           : published                              ? 0
                                                    : 1;
  }
  if (freshRead || treeExisting) {
    if (freshRead) {
      auto offset = decimal(cfg.offset_decimal()), length = decimal(cfg.length_decimal());
      if (!offset || !length) return 2;
      auto record = prepareEcTreeRead(*sessionRun->latest()->session,
                                      cluster,
                                      sessionRun->latest()->shardBytes,
                                      *offset,
                                      *length);
      if (!record) return fail(record.error());
      auto j = EcTreeReadJournal::create(cfg.run_dir(), std::move(*record));
      if (!j) return fail(j.error());
      tree = std::shared_ptr<EcTreeReadJournal>(std::move(*j));
    }
    folly::CPUThreadPoolExecutor executor(cfg.worker_threads());
    auto c = blockingWait(EcFileClient::connect(metadata,
                                                storage,
                                                mgmtd,
                                                credentials,
                                                ns,
                                                executor,
                                                std::chrono::seconds(cfg.deadline_seconds())));
    if (!c) return fail(c.error());
    auto reader = std::move(*c);
    SCOPE_EXIT { blockingWait(reader->close()); };
    if (command == "mode4-release-read") {
      auto released = blockingWait(reader->releaseTree(tree, control(cfg)));
      if (!released) return fail(released.error());
      const bool done = released->state == meta::EcTreeReadState::Released;
      folly::dynamic o =
          folly::dynamic::object("all_cleanup_complete",
                                 done)("range", tree->record().intent.range.toHexString())("error_code", 0);
      std::cout << folly::toJson(o) << '\n';
      return done ? 0 : 1;
    }
    auto data = blockingWait(reader->readTree(tree, control(cfg)));
    if (!data) return fail(data.error());
    auto saved = saveEcFileReadOutput(cfg.output_file(), data->data.bytes());
    if (!saved) return fail(saved.error());
    folly::dynamic o =
        folly::dynamic::object("data_ready", true)("readable_length_decimal", std::to_string(data->data.size()))(
            "all_cleanup_complete",
            false)("range", tree->record().intent.range.toHexString())("error_code", 0);
    std::cout << folly::toJson(o) << '\n';
    // Explicit separate release command: output failure never discards pin IDs.
    return 0;
  }
  std::optional<EcFilePayload> input;
  if (freshWrite) {
    auto offset = decimal(cfg.offset_decimal());
    if (!offset || cfg.input_file().empty()) return 2;
    const auto path = std::filesystem::absolute(cfg.input_file());
    auto data = (*client)->readInput(path);
    if (!data) return fail(data.error());
    auto record = prepareEcPwrite(*sessionRun, *offset, path.string(), data->bytes());
    if (!record) return fail(record.error());
    auto created = EcFilePwriteJournal::create(cfg.run_dir(), std::move(*record));
    if (!created) return fail(created.error());
    run = std::shared_ptr<EcFilePwriteJournal>(std::move(*created));
    input.emplace(std::move(*data));
  }
  EcPwriteOutcome result;
  if (command == "mode4-query")
    result = (*client)->query(*run, control(cfg));
  else if (command == "mode4-seal")
    result = (*client)->sealAndCleanup(*run, control(cfg));
  else {
    if (!input) {
      auto data = (*client)->readInput(run->record().inputPath);
      if (!data) return fail(data.error());
      input.emplace(std::move(*data));
    }
    result = (*client)->pwrite(*run, std::move(*input), control(cfg));
  }
  show(*run);
  folly::dynamic o = folly::dynamic::object("observed", result.observed)("confirmed_prefix_decimal",
                                                                         std::to_string(result.confirmedPrefix))(
      "revalidated_prefix_decimal",
      std::to_string(result.revalidatedPrefix))("logical_closed", result.logicalClosed)("logical_complete",
                                                                                        result.logicalComplete)(
      "all_cleanup_complete",
      result.allCleanupComplete)("error_code", result.failure ? result.failure->code() : 0);
  std::cout << folly::toJson(o) << '\n';
  if (result.failure) return fail(*result.failure);
  return command == "mode4-query"                                                             ? 0
         : (result.allCleanupComplete && (command == "mode4-seal" || result.logicalComplete)) ? 0
                                                                                              : 1;
}
