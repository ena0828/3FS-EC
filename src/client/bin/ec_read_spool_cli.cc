#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/json.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

#include "client/ec/EcFileRunFactory.h"
#include "client/ec/EcReadDispatcher.h"
#include "client/mgmtd/MgmtdClientForAdmin.h"
#include "common/logging/LogInit.h"
#include "common/monitor/Monitor.h"
#include "common/net/Client.h"
#include "stubs/common/RealStubFactory.h"
#include "stubs/mgmtd/MgmtdServiceStub.h"
using namespace hf3fs;
using namespace hf3fs::client::ec;
using folly::coro::blockingWait;
namespace {
void configureThreads(net::Client::Config &c) {
  c.thread_pool().set_num_proc_threads(2);
  c.thread_pool().set_num_io_threads(1);
  c.thread_pool().set_num_bg_threads(1);
  c.thread_pool().set_num_connect_threads(1);
}
class UserConfig : public ConfigBase<UserConfig> {
  CONFIG_ITEM(uid, uint32_t{0});
  CONFIG_ITEM(gid, uint32_t{0});
  CONFIG_ITEM(token_file, "");
};
class Config : public ConfigBase<Config> {
  CONFIG_OBJ(client, net::Client::Config, [](auto &c) { configureThreads(c); });
  CONFIG_OBJ(mgmtd_client, hf3fs::client::MgmtdClientForAdmin::Config, [](auto &c) {
    c.set_enable_auto_refresh(true);
    c.set_enable_auto_heartbeat(false);
    c.set_enable_auto_extend_client_session(false);
    c.set_accept_incomplete_routing_info_during_mgmtd_bootstrapping(false);
    c.set_network_type(net::Address::TCP);
  });
  CONFIG_OBJ(meta_client, meta::client::MetaClient::Config, [](auto &c) { c.set_network_type(net::Address::TCP); });
  CONFIG_OBJ(storage_client, storage::client::StorageClient::Config, [](auto &c) {
    c.set_implementation_type(storage::client::StorageClient::ImplementationType::RPC);
    configureThreads(c.net_client());
    configureThreads(c.net_client_for_updates());
  });
  CONFIG_OBJ(monitor, monitor::Monitor::Config);
  CONFIG_OBJ(user_info, UserConfig);
  CONFIG_ITEM(cluster_id, "");
  CONFIG_ITEM(state_directory, "");
  CONFIG_ITEM(sequence_decimal, "");
  CONFIG_ITEM(range_id, "");
  CONFIG_ITEM(owner_decimal, "");
  CONFIG_ITEM(archive_file, "");
  CONFIG_ITEM(output_file, "");
  CONFIG_ITEM(deadline_seconds, uint32_t{300});
  CONFIG_ITEM(worker_threads, uint32_t{2});
  CONFIG_ITEM(retained_runs, uint32_t{64});
  CONFIG_ITEM(outstanding_runs, uint32_t{32});
  CONFIG_ITEM(logical_spool_bytes, uint64_t{256} << 20);
  CONFIG_ITEM(log, "INFO:normal; normal=file:path=ec-read-spool.log,async=true,sync_level=ERR");
};
Result<uint64_t> decimal(std::string_view text) {
  if (text.empty() || text.size() > 20 || (text.size() > 1 && text.front() == '0'))
    return makeError(StatusCode::kInvalidArg);
  for (char c : text)
    if (c < '0' || c > '9') return makeError(StatusCode::kInvalidArg);
  uint64_t result = 0;
  auto p = std::from_chars(text.data(), text.data() + text.size(), result);
  if (p.ec != std::errc{} || p.ptr != text.data() + text.size()) return makeError(StatusCode::kInvalidArg);
  return result;
}
Result<Uuid> nonzeroUuid(std::string_view text) {
  CHECK_RESULT(id, Uuid::fromHexString(text));
  if (id.is_nil() || id.toHexString() != text) return makeError(StatusCode::kInvalidArg);
  return id;
}
Result<std::string> tokenFile(const std::string &path) {
  if (path.empty() || path.find('\0') != std::string::npos) return makeError(StatusCode::kInvalidConfig);
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return makeError(StatusCode::kInvalidConfig, "cannot open explicit user token file");
  SCOPE_EXIT { ::close(fd); };
  struct stat value {};
  if (::fstat(fd, &value) != 0 || !S_ISREG(value.st_mode) || (value.st_mode & 0077) ||
      (value.st_uid != ::geteuid() && value.st_uid != 0) || value.st_size <= 0 || value.st_size > 4096)
    return makeError(StatusCode::kInvalidConfig,
                     "token file must be owner-only, regular, owned by user/root and <=4096 bytes");
  std::string token(static_cast<size_t>(value.st_size), '\0');
  size_t offset = 0;
  while (offset != token.size()) {
    auto bytes = ::read(fd, token.data() + offset, token.size() - offset);
    if (bytes < 0 && errno == EINTR) continue;
    if (bytes <= 0) return makeError(StatusCode::kIOError, "cannot read complete token file");
    offset += static_cast<size_t>(bytes);
  }
  char extra;
  if (::read(fd, &extra, 1) != 0) return makeError(StatusCode::kInvalidConfig, "token file changed during read");
  if (!token.empty() && token.back() == '\n') token.pop_back();
  if (!token.empty() && token.back() == '\r') token.pop_back();
  if (token.empty()) return makeError(StatusCode::kInvalidConfig, "empty user token");
  return token;
}

EcStripeControl control(const Config &cfg) {
  return {std::chrono::steady_clock::now() + std::chrono::seconds(cfg.deadline_seconds()), {}};
}
[[noreturn]] void failStopMaintenance() noexcept {
  constexpr char message[] =
      "EC spool maintenance cannot confirm local join; retaining original spool and terminating before runtime "
      "teardown.\n";
  (void)::write(STDERR_FILENO, message, sizeof(message) - 1);
  std::_Exit(EXIT_FAILURE);
}
void printLocalInventory(const EcReadSpool &spool, const EcReadSpoolSnapshot &snapshot) {
  folly::dynamic records = folly::dynamic::array;
  for (const auto &r : snapshot.records) {
    folly::dynamic row = folly::dynamic::object("sequence_decimal", std::to_string(r.receipt.sequence))(
        "range_id",
        r.receipt.rangeId.toHexString())("owner_decimal", std::to_string(r.receipt.ownerUid))(
        "inode_decimal",
        std::to_string(r.object.inode.u64()))("incarnation", r.object.incarnation.toHexString())(
        "acquisition_issued",
        r.acquisitionIssued)("snapshot_observed", r.snapshotObserved)("local_complete_observed", r.localComplete)(
        "all_pins_released_observed",
        r.allPinsReleased)("actual_pins", r.actualPins)("released_mask", r.releasedMask)(
        "retirement_pending",
        r.retirementPending)("last_error_code", r.lastErrorCode);
    records.push_back(std::move(row));
  }
  folly::dynamic output = folly::dynamic::object("local_evidence_only", true)("remote_revalidated", false)(
      "client_namespace",
      spool.clientNamespace().toHexString())("cluster", spool.cluster())("retained_runs", snapshot.retainedRuns)(
      "outstanding_runs",
      snapshot.outstandingRuns)("logical_file_bytes", std::to_string(snapshot.logicalFileBytes))("records",
                                                                                                 std::move(records));
  std::cout << folly::toJson(output) << '\n';
}
int execute(int argc, char **argv) {
  if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
    std::cout
        << "ec_read_spool_cli --cfg=FILE [--config.FIELD=VALUE] COMMAND\n"
           "Commands: create-state, inspect, cleanup, retire, resume-read\n"
           "Unmount first. Every command obtains the original private spool's exclusive flock.\n"
           "inspect is local-only and does not require a reachable cluster or token.\n"
           "cleanup/retire/resume-read require exact sequence_decimal/range_id/owner_decimal and real user "
           "credentials.\n"
           "retire requires a new absolute archive_file outside spool; resume-read requires exclusive output_file.\n"
           "Missing/unknown/Closing retain original IDs and never authorize deletion or a replacement Acquire.\n";
    return 0;
  }
  Config cfg;
  auto configured = cfg.init(&argc, &argv);
  if (!configured || argc != 2 || cfg.cluster_id().empty()) {
    std::cerr << "invalid explicit configuration/command\n";
    return 2;
  }
  const std::string command = argv[1];
  if (command != "create-state" && command != "inspect" && command != "cleanup" && command != "retire" &&
      command != "resume-read") {
    std::cerr << "unknown command\n";
    return 2;
  }
  EcReadSpool::Limits spoolLimits{cfg.retained_runs(), cfg.outstanding_runs(), cfg.logical_spool_bytes()};
  auto opened = command == "create-state" ? EcReadSpool::create(cfg.state_directory(), cfg.cluster_id(), spoolLimits)
                                          : EcReadSpool::open(cfg.state_directory(), cfg.cluster_id(), spoolLimits);
  if (!opened) {
    std::cerr << opened.error().describe() << '\n';
    return 2;
  }
  auto spool = std::move(*opened);
  if (command == "create-state" || command == "inspect") {
    auto inventory = spool->inspectExclusive();
    if (!inventory) {
      std::cerr << inventory.error().describe() << '\n';
      return 2;
    }
    printLocalInventory(*spool, *inventory);
    return 0;
  }
  auto sequence = decimal(cfg.sequence_decimal());
  auto range = nonzeroUuid(cfg.range_id());
  auto owner = decimal(cfg.owner_decimal());
  if (!sequence || !*sequence || !range || !owner || *owner > UINT32_MAX || !cfg.deadline_seconds() ||
      cfg.deadline_seconds() > 3600 || !cfg.worker_threads() || cfg.worker_threads() > 8 ||
      cfg.meta_client().network_type() != net::Address::TCP || cfg.mgmtd_client().network_type() != net::Address::TCP) {
    std::cerr << "exact receipt, finite deadline, 1..8 worker threads and TCP are required\n";
    return 2;
  }
  EcReadReceipt receipt{spool->clientNamespace(), *sequence, static_cast<uint32_t>(*owner), *range};
  auto token = tokenFile(cfg.user_info().token_file());
  if (!token) {
    std::cerr << token.error().describe() << '\n';
    return 2;
  }
  flat::UserInfo user{flat::Uid(cfg.user_info().uid()), flat::Gid(cfg.user_info().gid()), std::move(*token)};
  logging::initOrDie(cfg.log());
  auto monitored = monitor::Monitor::start(cfg.monitor());
  if (!monitored) return 2;
  SCOPE_EXIT { monitor::Monitor::stop(); };
  auto network = std::make_shared<net::Client>(cfg.client());
  auto networkStop = folly::makeGuard([&]() noexcept {
    try {
      network->stopAndJoin();
    } catch (...) {
      failStopMaintenance();
    }
  });
  auto started = network->start("EcSpoolCli");
  if (!started) return 2;
  auto mgmtd = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
      cfg.cluster_id(),
      std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
          [network](net::Address a) { return network->serdeCtx(a); }),
      cfg.mgmtd_client());
  auto mgmtdStop = folly::makeGuard([&]() noexcept {
    try {
      blockingWait(mgmtd->stop());
    } catch (...) {
      failStopMaintenance();
    }
  });
  blockingWait(mgmtd->start(&network->tpg().bgThreadPool().randomPick()));
  auto routing = blockingWait(mgmtd->refreshRoutingInfo(true));
  if (!routing) {
    std::cerr << routing.error().describe() << '\n';
    return 2;
  }
  const ClientId clientId(spool->clientNamespace());
  auto storage = storage::client::StorageClient::create(clientId, cfg.storage_client(), *mgmtd);
  if (!storage) return 2;
  auto storageStop = folly::makeGuard([&]() noexcept {
    try {
      storage->stop();
    } catch (...) {
      failStopMaintenance();
    }
  });
  auto metadata =
      std::make_shared<meta::client::MetaClient>(clientId,
                                                 cfg.meta_client(),
                                                 std::make_unique<meta::client::MetaClient::StubFactory>(
                                                     [network](net::Address a) { return network->serdeCtx(a); }),
                                                 mgmtd,
                                                 storage,
                                                 false);
  auto metadataStop = folly::makeGuard([&]() noexcept {
    try {
      metadata->stop();
    } catch (...) {
      failStopMaintenance();
    }
  });
  folly::CPUThreadPoolExecutor executor(cfg.worker_threads());
  std::shared_ptr<EcReadDispatcher> dispatcher;
  // This application guard precedes all external runtime destructors. It is
  // installed before connect, and never treats a failed join as normal return.
  auto checkedStop = folly::makeGuard([&]() noexcept {
    if (!dispatcher) return;
    try {
      const auto report = blockingWait(dispatcher->stop());
      if (report.localJoined && report.lowerJoinConfirmed) return;
    } catch (...) {
    }
    failStopMaintenance();
  });
  auto connected = EcReadDispatcher::connect(spool,
                                             metadata,
                                             storage,
                                             mgmtd,
                                             executor,
                                             {std::chrono::seconds(cfg.deadline_seconds()),
                                              std::chrono::seconds(std::min(cfg.deadline_seconds(), uint32_t{5}))});
  if (!connected) {
    std::cerr << connected.error().describe() << '\n';
    return 2;
  }
  dispatcher = std::move(*connected);
  if (command == "cleanup") {
    const auto result = blockingWait(dispatcher->retryCleanup(receipt, user, control(cfg)));
    folly::dynamic output =
        folly::dynamic::object("local_joined", result.localJoined)("all_released", result.allReleased)(
            "expected_pins",
            result.expectedPins)("released_mask", result.releasedMask)("error_code",
                                                                       result.failure ? result.failure->code() : 0);
    std::cout << folly::toJson(output) << '\n';
    return result.localJoined && result.allReleased && !result.failure ? 0 : 1;
  }
  if (command == "retire") {
    auto result = blockingWait(dispatcher->retire(receipt, user, cfg.archive_file(), control(cfg)));
    if (!result) {
      std::cerr << result.error().describe() << '\n';
      return 1;
    }
    folly::dynamic output = folly::dynamic::object("local_files_removed", result->localFilesRemoved)(
        "archive",
        result->archive.string())("sequence_decimal", std::to_string(receipt.sequence));
    std::cout << folly::toJson(output) << '\n';
    return result->localFilesRemoved ? 0 : 1;
  }
  if (!std::filesystem::path(cfg.output_file()).is_absolute()) {
    std::cerr << "explicit absolute output_file required\n";
    return 2;
  }
  auto result = blockingWait(dispatcher->resumeRead(receipt, user, control(cfg)));
  if (!result) {
    std::cerr << result.error().describe() << '\n';
    return 1;
  }
  bool saved = false;
  if (result->localJoined && result->data) {
    auto output = saveEcFileReadOutput(cfg.output_file(), result->data->bytes());
    saved = bool(output);
    if (!output) std::cerr << output.error().describe() << '\n';
  }
  folly::dynamic output = folly::dynamic::object("local_joined", result->localJoined)("output_saved", saved)(
      "all_released",
      result->cleanup.allReleased)("retained_identity", true);
  std::cout << folly::toJson(output) << '\n';
  return saved && result->cleanup.localJoined && result->cleanup.allReleased ? 0 : 1;
}
}  // namespace
int main(int argc, char **argv) {
  try {
    return execute(argc, argv);
  } catch (...) {
    std::cerr << "EC spool maintenance failed; preserve original spool and receipt\n";
    return 2;
  }
}
