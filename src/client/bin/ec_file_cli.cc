#include <bit>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <folly/json.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

#include "client/ec/EcFileAppendClient.h"
#include "client/ec/EcFilePwriteClient.h"
#include "client/ec/EcFileRepairClient.h"
#include "client/ec/EcFileRunFactory.h"
#include "client/ec/EcTreeReadJournal.h"
#include "client/ec/EcTruncateJournal.h"
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
  CONFIG_ITEM(run_dir, "");
  CONFIG_ITEM(session_run_dir, "");
  CONFIG_ITEM(file_path, "");
  CONFIG_ITEM(birth, "");
  CONFIG_ITEM(shard_bytes, uint32_t{1u << 20});
  CONFIG_ITEM(session_rights, uint32_t{3});
  CONFIG_ITEM(permission, uint32_t{0600});
  CONFIG_ITEM(client_namespace, "");
  CONFIG_ITEM(inode_decimal, "");
  CONFIG_ITEM(incarnation, "");
  CONFIG_ITEM(offset_decimal, "");
  CONFIG_ITEM(length_decimal, "");
  CONFIG_ITEM(input_file, "");
  CONFIG_ITEM(output_file, "");
  CONFIG_ITEM(repair_stripe_decimal, "");
  CONFIG_ITEM(repair_mask_decimal, "");
  CONFIG_ITEM(repair_mode, "");
  CONFIG_ITEM(repair_delivery, "");
  CONFIG_ITEM(repair_source_order, "");
  CONFIG_ITEM(repair_window_decimal, "");
  CONFIG_ITEM(repair_metrics, false);
  CONFIG_ITEM(deadline_seconds, uint32_t{300});
  CONFIG_ITEM(worker_threads, uint32_t{4});
  CONFIG_ITEM(log, "INFO:normal; normal=file:path=ec-file.log,async=true,sync_level=ERR");
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

EcStripeControl control(const Config &c) {
  return {std::chrono::steady_clock::now() + std::chrono::seconds(c.deadline_seconds()), {}};
}
void printProgress(const EcFileRunJournal &j) {
  if (j.latest()) {
    auto text = encodeEcFileRunProgress(*j.latest());
    if (text) std::cout << *text << '\n';
  }
}
#include "EcFileMode4Cli.inc"
#include "EcFileRepairCli.inc"
int execute(int argc, char **argv) {
  if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
    std::cout << "ec_file_cli --cfg=FILE [--config.FIELD=VALUE] COMMAND\n"
                 "Commands: describe, new-range-read, new-append-at, resume, release, inspect\n"
                 "One command only. New commands require explicit inode_decimal/incarnation; read requires "
                 "offset_decimal/length_decimal.\n"
                 "Append uses aligned expected EOF in offset_decimal and complete stripes from input_file.\n"
                 "read/resume-read writes output_file exclusively and then attempts all fixed pin releases.\n"
                 "resume/release preserve every ID in run_dir; errors never authorize a replacement run.\n"
                 "Local journal fsync is not remote file fsync.\n"
                 "Mode4: mode4-create/open/resume-open/close/inspect; mode4-pwrite/resume/query/seal.\n"
                 "Mode4 reads: mode4-read/resume-read/release-read; release is explicit and separate.\n"
                 "Mode4 append: mode4-append/resume-append/query-append/seal-append (no offset input).\n"
                 "Mode4 sync: mode4-fsync uses accepted session + new run; resume-fsync preserves that barrier.\n"
                 "Resolve all prior write/truncate runs before sync; sync never executes prepared input journals.\n"
                 "Mode4 repair: mode4-repair/resume-repair/query-repair/close-repair-debt.\n"
                 "New repair: accepted READ|WRITE session_run_dir + new run_dir + repair_stripe_decimal,\n"
                 "repair_mask_decimal, repair_mode=central|pipeline|helper and ten repair_source_order indices.\n"
                 "Optional repair_metrics=true observes this call only; default false, journal format unchanged.\n"
                 "Optional repair_window_decimal=1..4 (default 2); helper repair_delivery=return|direct.\n"
                 "Resume/query/close use only original run_dir; no repair_delivery override.\n"
                 "Published and source-released are separate; close-repair-debt cancels an unfinished repair.\n"
                 "Mode4 truncate: mode4-truncate/resume-truncate/query-truncate/close-truncate-debt.\n"
                 "New truncate: session_run_dir + new run_dir + length_decimal; resume keeps original CAS/IDs.\n"
                 "close-truncate-debt abandons unfinished truncation; it is an explicit cancellation.\n"
                 "Create: file_path + new run_dir. Open: inode_decimal/incarnation/birth + new run_dir.\n"
                 "Pwrite/read: accepted session_run_dir + new run_dir + offset_decimal + input_file/length_decimal.\n"
                 "Resume/query/close use original run_dir, original namespace and fixed IDs.\n";
    return 0;
  }
  Config cfg;
  auto configured = cfg.init(&argc, &argv);
  if (!configured) {
    std::cerr << configured.error().describe() << '\n';
    return 2;
  }
  if (argc != 2 || !cfg.deadline_seconds() || cfg.deadline_seconds() > 3600 || !cfg.worker_threads() ||
      cfg.worker_threads() > 32 || cfg.meta_client().network_type() != net::Address::TCP ||
      cfg.mgmtd_client().network_type() != net::Address::TCP) {
    std::cerr << "require one command, finite 1..3600s deadline, 1..32 threads and TCP\n";
    return 2;
  }
  const std::string command = argv[1];
  if (isMode4RepairCommand(command)) return executeMode4Repair(cfg, command);
  if (command.starts_with("mode4-")) return executeMode4(cfg, command);
  const bool existing = command == "resume" || command == "release" || command == "inspect";
  const bool newRead = command == "new-range-read", newAppend = command == "new-append-at";
  if (!existing && !newRead && !newAppend && command != "describe") {
    std::cerr << "unknown command\n";
    return 2;
  }
  std::shared_ptr<EcFileRunJournal> journal;
  std::string cluster = cfg.cluster_id();
  Uuid namespaceId = Uuid::zero();
  meta::EcObjectRef object;
  if (existing) {
    auto opened = EcFileRunJournal::resume(cfg.run_dir());
    if (!opened) {
      std::cerr << opened.error().describe() << '\n';
      return 2;
    }
    journal = std::shared_ptr<EcFileRunJournal>(std::move(*opened));
    const auto &r = journal->record();
    namespaceId = r.owner.client;
    object = r.object;
    if ((!cluster.empty() && cluster != r.cluster) ||
        (!cfg.client_namespace().empty() && cfg.client_namespace() != namespaceId.toHexString()) ||
        (!cfg.input_file().empty() && std::filesystem::absolute(cfg.input_file()).string() != r.inputPath)) {
      std::cerr << "resume parameters differ from original file run\n";
      return 2;
    }
    // Extents and object cannot be overridden by a resumed invocation.
    if (!cfg.inode_decimal().empty() || !cfg.incarnation().empty() || !cfg.offset_decimal().empty() ||
        !cfg.length_decimal().empty()) {
      std::cerr << "resume uses the stored object/extent; omit new-run parameters\n";
      return 2;
    }
    cluster = r.cluster;
    if (command == "inspect") {
      auto text = encodeEcFileRunRecord(r);
      if (!text) return 2;
      std::cout << *text << '\n';
      printProgress(*journal);
      return 0;
    }
  } else {
    auto inode = decimal(cfg.inode_decimal());
    auto incarnation = nonzeroUuid(cfg.incarnation());
    auto client = cfg.client_namespace().empty() ? Result<Uuid>(Uuid::random()) : nonzeroUuid(cfg.client_namespace());
    if (cluster.empty() || !inode || !incarnation || !client) {
      std::cerr << "invalid explicit cluster/object/client identity\n";
      return 2;
    }
    object = {meta::InodeId(*inode), *incarnation};
    namespaceId = *client;
  }
  const bool readAction =
      newRead || (journal && journal->record().kind == EcFileRunKind::RangeRead && command == "resume");
  if (readAction && (!std::filesystem::path(cfg.output_file()).is_absolute() || cfg.output_file().empty())) {
    std::cerr << "read requires a new absolute output_file\n";
    return 2;
  }
  auto token = tokenFile(cfg.user_info().token_file());
  if (!token) {
    std::cerr << token.error().describe() << '\n';
    return 2;
  }
  logging::initOrDie(cfg.log());
  auto monitored = monitor::Monitor::start(cfg.monitor());
  if (!monitored) {
    std::cerr << monitored.error().describe() << '\n';
    return 2;
  }
  SCOPE_EXIT { monitor::Monitor::stop(); };
  auto network = std::make_shared<net::Client>(cfg.client());
  auto started = network->start("EcFileCli");
  if (!started) {
    std::cerr << started.error().describe() << '\n';
    return 2;
  }
  SCOPE_EXIT { network->stopAndJoin(); };
  auto mgmtd = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
      cluster,
      std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
          [network](net::Address a) { return network->serdeCtx(a); }),
      cfg.mgmtd_client());
  blockingWait(mgmtd->start(&network->tpg().bgThreadPool().randomPick()));
  SCOPE_EXIT { blockingWait(mgmtd->stop()); };
  auto routing = blockingWait(mgmtd->refreshRoutingInfo(true));
  if (!routing) {
    std::cerr << routing.error().describe() << '\n';
    return 2;
  }
  auto storage = storage::client::StorageClient::create(ClientId::random(), cfg.storage_client(), *mgmtd);
  if (!storage) {
    std::cerr << "cannot create data transport\n";
    return 2;
  }
  SCOPE_EXIT { storage->stop(); };
  auto metadata =
      std::make_shared<meta::client::MetaClient>(ClientId(namespaceId),
                                                 cfg.meta_client(),
                                                 std::make_unique<meta::client::MetaClient::StubFactory>(
                                                     [network](net::Address a) { return network->serdeCtx(a); }),
                                                 mgmtd,
                                                 storage,
                                                 false);
  SCOPE_EXIT { metadata->stop(); };
  folly::CPUThreadPoolExecutor executor(cfg.worker_threads());
  auto connected = blockingWait(EcFileClient::connect(
      metadata,
      storage,
      mgmtd,
      flat::UserInfo{flat::Uid(cfg.user_info().uid()), flat::Gid(cfg.user_info().gid()), std::move(*token)},
      namespaceId,
      executor,
      std::chrono::seconds(cfg.deadline_seconds())));
  if (!connected) {
    std::cerr << connected.error().describe() << '\n';
    return 2;
  }
  auto manager = std::move(*connected);
  SCOPE_EXIT { blockingWait(manager->close()); };
  if (journal && (journal->record().owner.uid != manager->owner().uid ||
                  journal->record().owner.client != manager->owner().client)) {
    std::cerr << "authenticated effective owner differs from original run\n";
    return 2;
  }
  std::optional<EcFilePayload> preparedInput;
  if (!existing) {
    const auto describeId = Uuid::random();
    auto described = blockingWait(manager->describe(object,
                                                    describeId,
                                                    newAppend ? meta::AccessType::WRITE : meta::AccessType::READ,
                                                    control(cfg)));
    if (!described) {
      std::cerr << described.error().describe() << '\n';
      return 2;
    }
    if (command == "describe") {
      folly::dynamic output = folly::dynamic::object("inode_decimal", std::to_string(object.inode.u64()))(
          "incarnation",
          object.incarnation.toHexString())("length_decimal", std::to_string(described->length))(
          "epoch_decimal",
          std::to_string(described->epoch))("shard_bytes", described->layout.shardBytes)("client_namespace",
                                                                                         namespaceId.toHexString());
      std::cout << folly::toJson(output) << '\n';
      return 0;
    }
    auto offset = decimal(cfg.offset_decimal());
    if (!offset) {
      std::cerr << "explicit exact offset_decimal required\n";
      return 2;
    }
    Result<EcFileRunRecord> record = makeError(StatusCode::kInvalidArg);
    if (newRead) {
      auto length = decimal(cfg.length_decimal());
      if (!length) {
        std::cerr << "exact length_decimal required\n";
        return 2;
      }
      record = prepareEcFileRead(*described, manager->owner(), cluster, *offset, *length, describeId);
    } else {
      if (cfg.input_file().empty()) {
        std::cerr << "input_file required\n";
        return 2;
      }
      auto inputPath = std::filesystem::absolute(cfg.input_file());
      auto input = readEcFileInput(*manager, inputPath);
      if (!input) {
        std::cerr << input.error().describe() << '\n';
        return 2;
      }
      if (!cfg.length_decimal().empty()) {
        auto length = decimal(cfg.length_decimal());
        if (!length || *length != input->size()) {
          std::cerr << "input length differs\n";
          return 2;
        }
      }
      record = prepareEcFileAppend(*described,
                                   manager->owner(),
                                   cluster,
                                   *offset,
                                   inputPath.string(),
                                   input->bytes(),
                                   describeId);
      preparedInput.emplace(std::move(*input));
    }
    if (!record) {
      std::cerr << record.error().describe() << '\n';
      return 2;
    }
    auto created = EcFileRunJournal::create(cfg.run_dir(), std::move(*record));
    if (!created) {
      std::cerr << created.error().describe() << '\n';
      return 2;
    }
    journal = std::shared_ptr<EcFileRunJournal>(std::move(*created));
  }
  if (command == "release") {
    auto result = blockingWait(manager->releaseRead(journal, control(cfg)));
    printProgress(*journal);
    if (result.failure) std::cerr << result.failure->describe() << '\n';
    return result.allReleased ? 0 : 1;
  }
  if (journal->record().kind == EcFileRunKind::RangeRead) {
    auto read = blockingWait(manager->read(journal, control(cfg)));
    std::optional<Status> error;
    if (!read)
      error = std::move(read.error());
    else {
      auto saved = saveEcFileReadOutput(cfg.output_file(), read->data.bytes());
      if (!saved) error = std::move(saved.error());
    }
    // Even failed output writes and never-read stripes retain the fixed range
    // and pass through explicit all-pin cleanup using a fresh finite budget.
    auto released = blockingWait(manager->releaseRead(journal, control(cfg)));
    printProgress(*journal);
    if (error) std::cerr << error->describe() << '\n';
    if (released.failure) std::cerr << released.failure->describe() << '\n';
    return !error && released.allReleased ? 0 : 1;
  }
  if (!preparedInput) {
    auto input = readEcFileInput(*manager, journal->record().inputPath);
    if (!input) {
      std::cerr << input.error().describe() << '\n';
      return 1;
    }
    preparedInput.emplace(std::move(*input));
  }
  auto outcome = blockingWait(manager->appendAt(journal, std::move(*preparedInput), control(cfg)));
  folly::dynamic output =
      folly::dynamic::object("confirmed_prefix_bytes", std::to_string(outcome.confirmedPrefixBytes))(
          "revalidated_prefix_bytes",
          std::to_string(outcome.revalidatedPrefixBytes))("confirmed_stripes", outcome.confirmedStripes)(
          "first_unconfirmed_index",
          outcome.firstUnconfirmedIndex)("first_unconfirmed_state", unsigned(outcome.firstUnconfirmedState))(
          "complete",
          outcome.complete)("error_code", outcome.failure ? outcome.failure->code() : 0);
  std::cout << folly::toJson(output) << '\n';
  printProgress(*journal);
  if (outcome.failure) std::cerr << outcome.failure->describe() << '\n';
  return outcome.complete ? 0 : 1;
}
}  // namespace
int main(int argc, char **argv) {
  try {
    return execute(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << "ec_file_cli unconfirmed failure: " << e.what() << "; retain original run and IDs\n";
    return 2;
  } catch (...) {
    std::cerr << "ec_file_cli unconfirmed failure; retain original run and IDs\n";
    return 2;
  }
}
