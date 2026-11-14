// Meta-only namespace operations use a durable original request. No RMW
// worker or IB device is needed to acknowledge one unlink. MetaClient's
// StorageClient dependency still owns its normal messenger lifecycle.
bool isMode4NamespaceCommand(std::string_view command) {
  return command == "mode4-unlink" || command == "mode4-resume-unlink" || command == "mode4-inspect-unlink";
}
int executeMode4Namespace(const Config &cfg, const std::string &command) {
  const bool fresh = command == "mode4-unlink";
  const bool inspect = command == "mode4-inspect-unlink";
  std::unique_ptr<EcNamespaceJournal> journal;
  EcNamespaceOutcome result;
  bool networkPerformed = false;
  auto emit = [&] {
    folly::dynamic out = folly::dynamic::object("schema", 1)("kind", "ec_file_namespace_unlink")(
        "command", command)("namespace_unlink_acknowledged", result.acknowledged)("revalidated", result.revalidated)(
        "network_io_performed", networkPerformed)("physical_capacity_returned", false)("namespace_deleted", false)(
        "failure", nullptr);
    if (journal) {
      const auto &r = journal->record();
      const auto &i = r.session.intent;
      out["cluster"] = r.cluster;
      out["client_namespace"] = i.owner.client.toHexString();
      out["inode_decimal"] = std::to_string(i.object.inode.u64());
      out["incarnation"] = i.object.incarnation.toHexString();
      out["birth"] = i.birth.toHexString();
      out["path"] = r.path;
      out["request"] = r.request.toHexString();
    }
    if (result.failure)
      out["failure"] = folly::dynamic::object("code", result.failure->code())("message", result.failure->describe());
    std::cout << folly::toJson(out) << '\n';
  };
  auto fail = [&](Status error, int code = 1) {
    if (journal && journal->latest()) result.acknowledged = journal->latest()->acknowledged;
    result.revalidated = false;
    result.failure = std::move(error);
    emit();
    std::cerr << "namespace unlink unconfirmed: " << result.failure->describe()
              << "; retain original run and request identity\n";
    return code;
  };
  try {
    if (!isMode4NamespaceCommand(command) || cfg.run_dir().empty() ||
        !std::filesystem::path(cfg.run_dir()).is_absolute())
      return fail(Status(StatusCode::kInvalidArg, "namespace operation requires an absolute run_dir"), 2);
    if (!cfg.inode_decimal().empty() || !cfg.incarnation().empty() || !cfg.birth().empty() ||
        !cfg.offset_decimal().empty() || !cfg.length_decimal().empty() || !cfg.input_file().empty() ||
        !cfg.output_file().empty() || !cfg.repair_stripe_decimal().empty() || !cfg.repair_mask_decimal().empty() ||
        !cfg.repair_mode().empty() || !cfg.repair_delivery().empty() || !cfg.repair_source_order().empty() ||
        !cfg.repair_window_decimal().empty() || cfg.repair_metrics())
      return fail(Status(StatusCode::kInvalidArg, "unlink accepts no data, extent or object identity overrides"), 2);
    std::string cluster = cfg.cluster_id();
    if (fresh) {
      if (cfg.session_run_dir().empty() || !std::filesystem::path(cfg.session_run_dir()).is_absolute())
        return fail(Status(StatusCode::kInvalidArg, "unlink requires the accepted original session journal"), 2);
      auto session = EcFilePwriteJournal::resume(cfg.session_run_dir());
      if (!session) return fail(std::move(session.error()), 2);
      auto record = prepareEcUnlink(**session, cfg.file_path());
      if (!record) return fail(std::move(record.error()), 2);
      if ((!cluster.empty() && cluster != record->cluster) ||
          (!cfg.client_namespace().empty() && cfg.client_namespace() != record->session.intent.owner.client.toHexString()))
        return fail(Status(StatusCode::kTokenMismatch, "unlink cluster/namespace differs from the accepted session"), 2);
      // The immutable request is fsynced before any
      // authentication or removal RPC. A failed call never authorizes new IDs.
      auto created = EcNamespaceJournal::create(cfg.run_dir(), std::move(*record));
      if (!created) return fail(std::move(created.error()));
      journal = std::move(*created);
    } else {
      if (!cfg.session_run_dir().empty() || !cfg.file_path().empty())
        return fail(Status(StatusCode::kInvalidArg, "resume/inspect use only the original namespace run"), 2);
      auto old = EcNamespaceJournal::resume(cfg.run_dir());
      if (!old) return fail(std::move(old.error()));
      journal = std::move(*old);
    }
    const auto ns = journal->record().session.intent.owner.client;
    if ((!cluster.empty() && cluster != journal->record().cluster) ||
        (!cfg.client_namespace().empty() && cfg.client_namespace() != ns.toHexString()))
      return fail(Status(StatusCode::kTokenMismatch, "namespace run identity differs"), 2);
    cluster = journal->record().cluster;
    if (journal->latest()) result.acknowledged = journal->latest()->acknowledged;
    if (inspect) {
      emit();  // Local acknowledgement history, never a remote query.
      return 0;
    }
    auto token = tokenFile(cfg.user_info().token_file());
    if (!token) return fail(std::move(token.error()));
    logging::initOrDie(cfg.log());
    auto monitored = monitor::Monitor::start(cfg.monitor());
    if (!monitored) return fail(std::move(monitored.error()));
    SCOPE_EXIT { monitor::Monitor::stop(); };
    auto network = std::make_shared<net::Client>(cfg.client());
    auto started = network->start("EcNamespaceCli");
    if (!started) return fail(std::move(started.error()));
    SCOPE_EXIT { network->stopAndJoin(); };
    auto mgmtd = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
        cluster,
        std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
            [network](net::Address a) { return network->serdeCtx(a); }),
        cfg.mgmtd_client());
    networkPerformed = true;
    blockingWait(mgmtd->start(&network->tpg().bgThreadPool().randomPick()));
    SCOPE_EXIT { blockingWait(mgmtd->stop()); };
    auto refreshed = blockingWait(mgmtd->refreshRoutingInfo(true));
    if (!refreshed) return fail(std::move(refreshed.error()));
    // MetaClient needs this dependency, but namespace unlink never dispatches
    // a Storage request or creates an RMW worker.
    auto storage = storage::client::StorageClient::create(ClientId(ns), cfg.storage_client(), *mgmtd);
    if (!storage) return fail(Status(StorageClientCode::kNotInitialized));
    SCOPE_EXIT { storage->stop(); };
    auto metadata = std::make_shared<meta::client::MetaClient>(
        ClientId(ns), cfg.meta_client(),
        std::make_unique<meta::client::MetaClient::StubFactory>(
            [network](net::Address a) { return network->serdeCtx(a); }),
        mgmtd, storage, false);
    SCOPE_EXIT { metadata->stop(); };
    flat::UserInfo credentials{flat::Uid(cfg.user_info().uid()), flat::Gid(cfg.user_info().gid()), std::move(*token)};
    auto connected = EcNamespaceClient::connect(metadata, std::move(credentials), ns);
    if (!connected) return fail(std::move(connected.error()));
    result = (*connected)->unlink(*journal, control(cfg));
    emit();
    return !result.failure && result.acknowledged && result.revalidated ? 0 : 1;
  } catch (...) {
    return fail(Status(TransactionCode::kMaybeCommitted,
                       "namespace CLI interrupted after possible dispatch; resume the original request"));
  }
}
