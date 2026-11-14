#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fmt/ranges.h>
#include <folly/ScopeGuard.h>
#include <folly/experimental/coro/BlockingWait.h>
#include <gflags/gflags.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

#include "client/bin/EcRepairMetricsJson.h"
#include "client/ec/EcAllocationExport.h"
#include "client/ec/EcStripeRecoveryWrite.h"
#include "client/ec/EcStripeRunRecord.h"
#include "client/meta/MetaClient.h"
#include "client/mgmtd/MgmtdClientForAdmin.h"
#include "common/logging/LogInit.h"
#include "common/monitor/Monitor.h"
#include "common/net/Client.h"
#include "common/net/ib/IBDevice.h"
#include "fbs/meta/EcRequestDigest.h"
#include "stubs/common/RealStubFactory.h"
#include "stubs/mgmtd/MgmtdServiceStub.h"

DECLARE_string(cfg);

using namespace hf3fs;
using namespace hf3fs::client::ec;
using folly::coro::blockingWait;
namespace {
void configureThreads(net::Client::Config &config) {
  config.thread_pool().set_num_proc_threads(2);
  config.thread_pool().set_num_io_threads(1);
  config.thread_pool().set_num_bg_threads(1);
  config.thread_pool().set_num_connect_threads(1);
}
class UserConfig : public ConfigBase<UserConfig> {
  CONFIG_ITEM(uid, uint32_t{0});
  CONFIG_ITEM(gid, uint32_t{0});
  CONFIG_ITEM(token_file, "");
};
class Config : public ConfigBase<Config> {
  CONFIG_OBJ(client, net::Client::Config, [](auto &cfg) { configureThreads(cfg); });
  CONFIG_OBJ(mgmtd_client, hf3fs::client::MgmtdClientForAdmin::Config, [](auto &cfg) {
    cfg.set_enable_auto_refresh(true);
    cfg.set_enable_auto_heartbeat(false);
    cfg.set_enable_auto_extend_client_session(false);
    cfg.set_accept_incomplete_routing_info_during_mgmtd_bootstrapping(false);
    cfg.set_network_type(net::Address::TCP);
  });
  CONFIG_OBJ(meta_client, meta::client::MetaClient::Config, [](auto &cfg) { cfg.set_network_type(net::Address::TCP); });
  CONFIG_OBJ(storage_client, storage::client::StorageClient::Config, [](auto &cfg) {
    cfg.set_implementation_type(storage::client::StorageClient::ImplementationType::RPC);
    configureThreads(cfg.net_client());
    configureThreads(cfg.net_client_for_updates());
  });
  CONFIG_OBJ(monitor, monitor::Monitor::Config);
  CONFIG_OBJ(user_info, UserConfig);
  CONFIG_ITEM(cluster_id, "");
  CONFIG_ITEM(run_dir, "");
  CONFIG_ITEM(source_run, "");
  CONFIG_ITEM(allocation_output, "");
  CONFIG_ITEM(input_file, "");
  CONFIG_ITEM(remote_path, "");
  CONFIG_ITEM(shard_bytes, uint32_t{0});
  CONFIG_ITEM(strategy, "");
  CONFIG_ITEM(delivery, "");
  CONFIG_ITEM(replacement_mask, uint16_t{0});
  CONFIG_ITEM(source_order, std::vector<uint16_t>{});
  CONFIG_ITEM(block_window, uint8_t{0});
  CONFIG_ITEM(repair_metrics, false);
  CONFIG_ITEM(storage_transport, "tcp");
  CONFIG_OBJ(ib_devices, net::IBDevice::Config);
  CONFIG_ITEM(deadline_seconds, uint32_t{300});
  CONFIG_ITEM(worker_threads, uint32_t{4});
  CONFIG_ITEM(max_operations, uint32_t{2});
  CONFIG_ITEM(max_application_bytes, uint64_t{64u << 20});
  CONFIG_ITEM(write_fragments, uint8_t{2});
  CONFIG_ITEM(read_blocks, uint8_t{2});
  CONFIG_ITEM(log, "INFO:normal; normal=file:path=ec-stripe.log,async=true,sync_level=ERR");
};

std::string quote(std::string_view value) {
  std::string result("'");
  for (char byte : value) result += byte == '\'' ? "'\\''" : std::string(1, byte);
  return result + "'";
}
EcStripeRunRecord identities() {
  EcStripeRunRecord record;
  record.clientNamespace = Uuid::random();
  record.createRequest = Uuid::random();
  record.operation = Uuid::random();
  record.beginRequest = Uuid::random();
  record.bindRequest = Uuid::random();
  record.publishRequest = Uuid::random();
  record.getRequest = Uuid::random();
  record.prepareRepairRequest = Uuid::random();
  record.pin = Uuid::random();
  record.acquireRequest = Uuid::random();
  record.releaseRequest = Uuid::random();
  record.planId = Uuid::random();
  return record;
}
Result<storage::EcSha256> contentDigest(std::string_view bytes) {
  std::array<std::string_view, 10> data{};
  data[0] = bytes;
  return meta::computeEcLogicalSha256(data, bytes.size());
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
Result<std::unique_ptr<EcStripeRunJournal>> journal(const Config &config,
                                                    std::string_view command,
                                                    std::string_view executable) {
  if ((!config.delivery().empty() && command != "new-repair") ||
      (!config.delivery().empty() && config.delivery() != "return" && config.delivery() != "direct") ||
      (config.delivery() == "direct" && config.strategy() != "helper"))
    return makeError(StatusCode::kInvalidArg,
                     "delivery is new-repair-only; direct requires helper; resume uses the persisted delivery");
  if (command == "resume" || command == "release" || command == "inspect" || command == "export-allocations") {
    CHECK_RESULT(value, EcStripeRunJournal::resume(config.run_dir()));
    const auto &record = value->record();
    if ((!config.cluster_id().empty() && config.cluster_id() != record.cluster) ||
        (!config.input_file().empty() && std::filesystem::absolute(config.input_file()).string() != record.inputPath) ||
        (!config.remote_path().empty() && config.remote_path() != record.remotePath) ||
        (config.shard_bytes() && config.shard_bytes() != record.shardBytes) ||
        (!config.strategy().empty() && config.strategy() != record.strategy) ||
        (config.replacement_mask() && config.replacement_mask() != record.replacementMask) ||
        (!config.source_order().empty() && config.source_order() != record.sourceOrder) ||
        (config.block_window() && config.block_window() != record.blockWindow) ||
        (record.recoverySource && !config.source_run().empty() &&
         std::filesystem::absolute(config.source_run()).string() != record.recoverySource->runPath))
      return makeError(StatusCode::kTokenMismatch, "resume parameters differ from immutable run record");
    return std::move(value);
  }
  auto record = identities();
  record.cluster = config.cluster_id();
  record.blockWindow = config.block_window() ? config.block_window() : 1;
  record.resumeCommand = fmt::format("{} --cfg={} --config.run_dir={} resume",
                                     quote(executable),
                                     quote(FLAGS_cfg),
                                     quote(config.run_dir()));
  if (command == "new-write") {
    record.action = "write";
    record.inputPath = std::filesystem::absolute(config.input_file()).string();
    record.remotePath = config.remote_path();
    record.shardBytes = config.shard_bytes();
    if (!record.shardBytes || record.shardBytes > (1u << 20))
      return makeError(StatusCode::kInvalidArg, "new-write requires explicit shard_bytes in 1..1048576");
    CHECK_RESULT(bytes, readEcStripeInput(record.inputPath, size_t(record.shardBytes) * 10));
    CHECK_RESULT(hash, contentDigest(bytes));
    record.inputSha256 = hash;
    record.inputBytes = bytes.size();
  } else if (command == "new-recovery-write") {
    if (config.source_run().empty() || config.input_file().empty() || !config.remote_path().empty() ||
        !config.strategy().empty() || config.replacement_mask() || !config.source_order().empty())
      return makeError(StatusCode::kInvalidArg,
                       "recovery requires explicit source_run/input_file and no create/repair parameters");
    const auto sourcePath = std::filesystem::absolute(config.source_run());
    CHECK_RESULT(source, EcStripeRunJournal::resume(sourcePath));
    if (!source->latest()) return makeError(StatusCode::kInvalidArg, "source has no confirmed publication observation");
    CHECK_RESULT(recordText, readEcStripeInput(sourcePath / "record.json", 65536));
    CHECK_RESULT(observationText,
                 readEcStripeInput(sourcePath / fmt::format("state-{:020}.json", source->latest()->sequence), 65536));
    CHECK_RESULT(recordHash, contentDigest(recordText));
    CHECK_RESULT(observationHash, contentDigest(observationText));
    const auto input = std::filesystem::absolute(config.input_file());
    CHECK_RESULT(bytes, readEcStripeInput(input, size_t(source->record().shardBytes) * 10));
    CHECK_RESULT(prepared,
                 prepareEcRecoveryWrite(std::move(record),
                                        source->record(),
                                        *source->latest(),
                                        sourcePath.string(),
                                        recordHash,
                                        observationHash,
                                        input.string(),
                                        bytes));
    record = std::move(prepared);
    if (config.shard_bytes() && config.shard_bytes() != record.shardBytes)
      return makeError(StatusCode::kTokenMismatch, "recovery cannot change the recorded shard layout");
  } else if (command == "new-read" || command == "new-repair") {
    CHECK_RESULT(source, EcStripeRunJournal::resume(config.source_run()));
    if (!source->latest() || !source->latest()->mutationPublished || !source->latest()->object ||
        !source->latest()->revision || source->record().cluster != record.cluster)
      return makeError(StatusCode::kInvalidArg, "source_run must contain an observed Published result in this cluster");
    record.action = command == "new-read" ? "read" : "repair";
    record.clientNamespace = source->record().clientNamespace;
    record.expectedOwnerUid = source->latest()->ownerUid;
    record.object = source->latest()->object;
    record.expectedRevision = source->latest()->revision;
    record.inputBytes = source->record().inputBytes;
    record.inputSha256 = source->record().inputSha256;
    record.shardBytes = record.object->shardBytes;
    if (record.action == "repair") {
      record.strategy = config.strategy();
      if (config.delivery() == "direct") {
        record.version = 3;
        record.delivery = "direct";
      }
      record.replacementMask = config.replacement_mask();
      record.sourceOrder = config.source_order();
      // The resulting fixed order is persisted before Begin. It will not be
      // adaptively changed per block or replaced after a source failure.
      if (record.sourceOrder.empty())
        for (uint16_t i = 0; i != 12 && record.sourceOrder.size() != 10; ++i)
          if (!(record.replacementMask & (1u << i))) record.sourceOrder.push_back(i);
    }
  } else
    return makeError(StatusCode::kInvalidArg, "unknown command");
  record.command = fmt::format("{} --cfg={} --config.run_dir={} {}",
                               quote(executable),
                               quote(FLAGS_cfg),
                               quote(config.run_dir()),
                               command);
  if (record.action == "write") {
    record.command += fmt::format(" --config.input_file={} --config.remote_path={} --config.shard_bytes={}",
                                  quote(record.inputPath),
                                  quote(record.remotePath),
                                  record.shardBytes);
  } else if (record.action == "recovery-write") {
    record.command += fmt::format(" --config.source_run={} --config.input_file={}",
                                  quote(record.recoverySource->runPath),
                                  quote(record.inputPath));
  } else {
    record.command += fmt::format(" --config.source_run={}", quote(config.source_run()));
    if (record.action == "repair")
      record.command += fmt::format(
          " --config.strategy={} --config.replacement_mask={} --config.source_order='[{}]' --config.block_window={}",
          record.strategy,
          record.replacementMask,
          fmt::join(record.sourceOrder, ","),
          record.blockWindow);
    if (record.action == "repair" && record.delivery == "direct") record.command += " --config.delivery=direct";
  }
  return EcStripeRunJournal::create(config.run_dir(), std::move(record));
}

EcStripeRunObservation observation(const EcStripeRunJournal &journal, const EcStripeClient &manager) {
  EcStripeRunObservation result = journal.latest().value_or(EcStripeRunObservation{});
  result.ownerUid = manager.owner().uid.toUnderType();
  result.logicalBytes = journal.record().inputBytes;
  result.shardBytes = journal.record().shardBytes;
  result.blocksPerShard = (result.shardBytes + storage::kEcIntegrityBlockBytes - 1) / storage::kEcIntegrityBlockBytes;
  result.errorCode = 0;
  result.error.clear();
  result.coreElapsedNanoseconds = 0;
  result.dataPhaseElapsedNanoseconds.reset();
  return result;
}
struct FlatRepairMetrics {
  EcRepairSample sample;
  bool invoked = false, dataPhaseEntered = false, published = false;
};

// The CLI journal and manager shutdown are outside the owned repair sample.
// Emit only after close(), separately from business records. Rendering failure
// must not replace the operation's result or create a journal observation.
void emitFlatRepairMetrics(const FlatRepairMetrics &metrics,
                           const EcStripeRunRecord &record,
                           std::string_view command) noexcept {
  try {
    folly::dynamic out = folly::dynamic::object("schema", 1)("kind", "ec_flat_repair_metrics")(
        "command", std::string(command))("operation", record.operation.toHexString())(
        "plan", record.planId.toHexString())("strategy", record.strategy)("delivery", record.delivery)(
        "observation_boundary", "owned_flat_repair; excludes public admission, CLI journal and shutdown")(
        "repair_scope", "selected_replacement_shards; unchanged shards are not copied")(
        "meta_invocation_scope", "orchestration method entries; internal retries and recovery queries are not separate samples")(
        "repair_invoked", metrics.invoked)("data_phase_entered", metrics.dataPhaseEntered)(
        "owned_repair_published", metrics.published)("local_manager_joined", true)(
        "telemetry_unavailable", !metrics.sample.available);
    auto line = folly::toJson(out);
    line.pop_back();
    line += ",\"metrics\":";
    line += metrics.sample.available ? repairMetricsJson(metrics.sample) : "null";
    line += "}\n";
    std::fwrite(line.data(), 1, line.size(), stdout);
  } catch (...) {
    std::fputs("{\"schema\":1,\"kind\":\"ec_flat_repair_metrics\",\"metrics\":null,"
               "\"telemetry_unavailable\":true}\n", stdout);
  }
}

Result<Void> run(EcStripeRunJournal &journal,
                 EcStripeClient &manager,
                 const Config &config,
                 std::string_view command,
                 std::shared_ptr<meta::client::MetaClient> metadata,
                 const flat::UserInfo &credentials,
                 FlatRepairMetrics *metrics) {
  const auto &record = journal.record();
  if (record.expectedOwnerUid && *record.expectedOwnerUid != manager.owner().uid.toUnderType())
    return makeError(StatusCode::kTokenMismatch, "authenticated user differs from source run owner");
  if (journal.latest() && journal.latest()->ownerUid != manager.owner().uid.toUnderType())
    return makeError(StatusCode::kTokenMismatch, "authenticated user differs from recorded run owner");
  auto state = observation(journal, manager);
  state.maxOperations = config.max_operations();
  state.applicationByteBudget = config.max_application_bytes();
  state.writeFragmentWindow = config.write_fragments();
  state.readBlockWindow = config.read_blocks();
  state.workerThreads = config.worker_threads();
  state.deadlineSeconds = config.deadline_seconds();
  state.metaRpcTimeoutMillis = config.meta_client().retry_default().rpc_timeout().asMs().count();
  state.metaRetryTotalMillis = config.meta_client().retry_default().retry_total_time().asMs().count();
  if (!journal.latest()) {
    state.state = "Authenticated";
    RETURN_ON_ERROR(journal.append(state));
  }
  auto control = [&] {
    return EcStripeControl{std::chrono::steady_clock::now() + std::chrono::seconds(config.deadline_seconds()),
                           {}, *parseEcStorageTransport(config.storage_transport())};
  };
  auto recordFailure = [&](Status error) -> Result<Void> {
    state.errorCode = error.code();
    state.error = std::string(error.message());
    RETURN_ON_ERROR(journal.append(state));
    return makeError(std::move(error));
  };
  auto object = state.object ? state.object : record.object;
  if (record.action == "recovery-write")
    object = record.object;  // Never rebase the fixed epoch or CAS from a later observation.
  if (command == "release") {
    if (!object || record.action == "write" || record.action == "recovery-write")
      return makeError(StatusCode::kInvalidArg, "this run owns no read pin; old cleanup remains separate");
    auto released = blockingWait(manager.release(record.pinIds(object->object), control()));
    if (!released) return recordFailure(released.error());
    state.state = released->drain.state == meta::EcV2DrainState::ReadReleased ? "ReadReleased" : "Closing";
    state.acknowledgedEndpoints = released->drain.acknowledgedEndpoints;
    state.expectedEndpoints = released->drain.expectedEndpoints;
    RETURN_ON_ERROR(journal.append(state));
    if (state.state != "ReadReleased")
      return makeError(StorageCode::kEcSealOutcomeUnknown, "remote pin drain remains pending");
    return Void{};
  }
  if (record.action == "write" || record.action == "recovery-write") {
    CHECK_RESULT(bytes, readEcStripeInput(record.inputPath, size_t(record.shardBytes) * 10));
    CHECK_RESULT(hash, contentDigest(bytes));
    if (bytes.size() != record.inputBytes || hash != record.inputSha256)
      return makeError(StatusCode::kTokenMismatch, "input bytes/SHA differ from fixed record");
    std::optional<meta::EcV2MutationRsp> recoverySource;
    if (record.action == "recovery-write") {
      auto verified = blockingWait(verifyEcRecoveryWriteSource(metadata, record, credentials, control()));
      if (!verified) return recordFailure(verified.error());
      recoverySource = std::move(*verified);
      if (!object) return makeError(StatusCode::kDataCorruption, "recovery lost its fixed existing object");
    }
    if (!object) {
      meta::CreateEcFileV2Req create;
      create.uuid = record.createRequest;
      create.path = meta::PathAt(meta::InodeId::root(), Path(record.remotePath));
      create.shardBytes = record.shardBytes;
      auto created = blockingWait(manager.createFile(std::move(create), control()));
      if (!created) return recordFailure(created.error());
      object = created->object;
      state.object = object;
      state.state = "Created";
      RETURN_ON_ERROR(journal.append(state));
    }
    EcStripeWrite request;
    request.object = *object;
    request.expectedRevision = record.expectedRevision;
    request.ids = record.mutationIds();
    request.logicalData = std::move(bytes);
    auto result = blockingWait(manager.write(std::move(request), control()));
    if (recoverySource && result.published()) {
      auto verified = validateEcRecoveryWritePublication(record, *recoverySource, *result.observation);
      if (!verified) result.failure = verified.error();
    }
    state.coreElapsedNanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(result.elapsed).count();
    if (result.dataPhaseElapsed)
      state.dataPhaseElapsedNanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(*result.dataPhaseElapsed).count();
    if (result.observation) {
      state.object = result.observation->object;
      state.revision = result.observation->record.candidate.revision;
    }
    state.state = result.published() ? "Published" : "MutationPending";
    state.mutationPublished = state.mutationPublished || result.published();
    if (result.failure) return recordFailure(*result.failure);
    RETURN_ON_ERROR(journal.append(state));
    if (recoverySource)
      fmt::print("Recovery Write observed separately. No old operation, read pin or GC protection was released.\n");
  } else if (record.action == "repair") {
    if (!object) return makeError(StatusCode::kInvalidArg);
    EcStripeRepair request;
    request.object = *object;
    request.expectedRevision = record.expectedRevision;
    request.ids = record.mutationIds();
    request.baseRead = record.pinIds(object->object);
    request.planId = record.planId;
    std::copy(record.sourceOrder.begin(), record.sourceOrder.end(), request.sources.begin());
    request.replacementMask = record.replacementMask;
    request.blockWindow = record.blockWindow;
    request.mode = record.strategy == "central"    ? EcRepairMode::CentralSerial
                   : record.strategy == "pipeline" ? EcRepairMode::ClientPipeline
                                                   : EcRepairMode::HelperChain;
    request.delivery = record.delivery == "direct" ? EcRepairDelivery::HelperDirect : EcRepairDelivery::ClientAppend;
    request.collectMetrics = metrics != nullptr;
    auto result = blockingWait(manager.repair(std::move(request), control()));
    if (metrics) {
      metrics->invoked = true;
      metrics->sample = result.repairMetrics;
      metrics->dataPhaseEntered = result.repairDataPhaseEntered;
      metrics->published = result.published();
    }
    state.coreElapsedNanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(result.elapsed).count();
    if (result.dataPhaseElapsed)
      state.dataPhaseElapsedNanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(*result.dataPhaseElapsed).count();
    if (result.observation) {
      state.object = result.observation->object;
      state.revision = result.observation->record.candidate.revision;
    }
    state.state = result.published() ? "Published" : "MutationPending";
    state.mutationPublished = state.mutationPublished || result.published();
    if (result.failure) return recordFailure(*result.failure);
    RETURN_ON_ERROR(journal.append(state));
    fmt::print("Repair joined locally. Its base read pin is retained; use the explicit release command.\n");
  } else {
    if (!object) return makeError(StatusCode::kInvalidArg);
    auto started = manager.startRead(record.pinIds(object->object), control());
    if (!started) return recordFailure(started.error());
    auto output = blockingWait(started->takeReady());
    // Even an error or caller deadline cannot discard outstanding requests.
    blockingWait(started->waitLocalCleanup());
    if (!output) return recordFailure(output.error());
    if (output->pinned.manifest.revision != record.expectedRevision || output->contentSha256 != record.inputSha256 ||
        output->logicalData.size() != record.inputBytes)
      return recordFailure(Status(StatusCode::kTokenMismatch, "pinned result differs from fixed source record"));
    state.coreElapsedNanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(output->readyElapsed).count();
    CHECK_RESULT(filename, journal.saveReadOutput(output->logicalData));
    state.readOutput = filename;
    state.object = object;
    state.revision = output->pinned.manifest.revision;
    state.state = "ReadReadyLocalCleaned";
    RETURN_ON_ERROR(journal.append(state));
    fmt::print("Read output: {}. Local cleanup complete; remote pin remains held until explicit release.\n", filename);
  }
  return Void{};
}

int execute(int argc, char **argv) {
  if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
    std::cout
        << "ec_stripe_cli --cfg=client.toml --config.run_dir=/absolute/new-run new-write|new-read|new-repair\n"
           "Client Storage EC: --config.storage_transport=tcp|rdma (default tcp; no fallback).\n"
           "Select it per invocation, including resume; Meta-owned data configuration is independent.\n"
           "ec_stripe_cli --cfg=client.toml --config.run_dir=/absolute/new-run "
           "--config.source_run=/absolute/published-run --config.input_file=/absolute/restored-data "
           "new-recovery-write\n"
           "ec_stripe_cli --cfg=client.toml --config.run_dir=/absolute/run resume|release|inspect\n"
           "ec_stripe_cli --cfg=client.toml --config.run_dir=/absolute/published-run "
           "--config.allocation_output=/absolute/new.json export-allocations\n"
           "new-write: --config.input_file=... --config.remote_path=/... --config.shard_bytes=...\n"
           "new-read: --config.source_run=/absolute/published-run\n"
           "new-repair: source_run plus --config.strategy=central|pipeline|helper, replacement_mask, optional "
           "source_order and block_window; helper accepts --config.delivery=return|direct (default return)\n"
           "resume/release/inspect/export-allocations reject delivery overrides and use the immutable run record.\n"
           "Optional --config.repair_metrics=true for new-repair/resume emits this-call observations after local "
           "join; default false, journal and durable IDs unchanged. It excludes CLI journal and admission.\n"
           "Uses actual mgmtd/Meta/Storage clients and a real user token_file (owner-only). No signing keys are "
           "accepted.\n"
           "Single stripe only; no FUSE, multi-stripe mapping or physical GC. Input preparation, output files "
           "and UI are excluded from core timing.\n"
           "recovery-write replaces the same stripe-zero object with fixed expectedRevision and identical SHA/length; "
           "requires READ+WRITE and an explicitly prepared healthy twelve-endpoint Meta pool. Old cleanup is "
           "retained.\n"
           "112KiB logical data with ~11KiB shards has one block; cross 640KiB logical and use multi-block "
           "shards to exercise slice overlap.\n";
    return 0;
  }
  const std::string executable = argv[0];
  Config config;
  auto configured = config.init(&argc, &argv);
  if (!configured) {
    std::cerr << configured.error().describe() << '\n';
    return 2;
  }
  if (argc != 2 || !config.deadline_seconds() || config.deadline_seconds() > 3600 || !config.worker_threads() ||
      config.worker_threads() > 32) {
    std::cerr << "one command, a 1..3600-second deadline and 1..32 worker threads are required\n";
    return 2;
  }
  auto storageTransport = parseEcStorageTransport(config.storage_transport());
  if (!storageTransport) {
    std::cerr << storageTransport.error().describe() << '\n';
    return 2;
  }
  std::cerr << "CLIENT_ORIGINATED_STORAGE_TRANSPORT=" << config.storage_transport()
            << "; Meta/Mgmtd control plane remains TCP; Meta-owned data uses independent configuration; "
               "selection is not RDMA success or a comparable performance sample\n";
  const std::string command = argv[1];
  if (config.meta_client().network_type() != net::Address::TCP ||
      config.mgmtd_client().network_type() != net::Address::TCP) {
    std::cerr << "this bounded V2 CLI requires TCP Meta/mgmtd routing\n";
    return 2;
  }
  auto journalResult = journal(config, command, executable);
  if (!journalResult) {
    std::cerr << journalResult.error().describe() << '\n';
    return 2;
  }
  auto &record = **journalResult;
  fmt::print("{}\n", serde::toJsonString(record.record(), true, true));
  if (command == "inspect") {
    if (record.latest()) fmt::print("{}\n", serde::toJsonString(*record.latest(), true, true));
    return 0;
  }
  auto token = tokenFile(config.user_info().token_file());
  if (!token) {
    std::cerr << token.error().describe() << '\n';
    return 2;
  }
  // This outer guard outlives every command's manager, worker and network.
  // Arm it before start so a partial IB initialization is also cleaned up.
  const bool useRdma = *storageTransport == EcStorageTransportPolicy::RdmaOnly;
  SCOPE_EXIT {
    if (useRdma) net::IBManager::stop();
  };
  if (useRdma) {
    auto ibStarted = net::IBManager::start(config.ib_devices());
    if (!ibStarted) {
      std::cerr << "cannot initialize requested RDMA devices: " << ibStarted.error().describe() << '\n';
      return 2;
    }
  }
  logging::initOrDie(config.log());
  auto monitorStarted = monitor::Monitor::start(config.monitor());
  if (!monitorStarted) {
    std::cerr << monitorStarted.error().describe() << '\n';
    return 2;
  }
  SCOPE_EXIT { monitor::Monitor::stop(); };
  auto network = std::make_shared<net::Client>(config.client());
  auto started = network->start("EcStripeCli");
  if (!started) {
    std::cerr << started.error().describe() << '\n';
    return 2;
  }
  SCOPE_EXIT { network->stopAndJoin(); };
  auto mgmtdClient = std::make_shared<hf3fs::client::MgmtdClientForAdmin>(
      record.record().cluster,
      std::make_unique<stubs::RealStubFactory<mgmtd::MgmtdServiceStub>>(
          [network](net::Address address) { return network->serdeCtx(address); }),
      config.mgmtd_client());
  blockingWait(mgmtdClient->start(&network->tpg().bgThreadPool().randomPick()));
  SCOPE_EXIT { blockingWait(mgmtdClient->stop()); };
  auto routing = blockingWait(mgmtdClient->refreshRoutingInfo(true));
  if (!routing) {
    std::cerr << routing.error().describe() << '\n';
    return 2;
  }
  const ClientId namespaceId(record.record().clientNamespace);
  std::shared_ptr<storage::client::StorageClient> dataClient;
  if (command != "export-allocations")
    dataClient = storage::client::StorageClient::create(ClientId::random(), config.storage_client(), *mgmtdClient);
  if (command != "export-allocations" && !dataClient) {
    std::cerr << "cannot start StorageClient\n";
    return 2;
  }
  SCOPE_EXIT {
    if (dataClient) dataClient->stop();
  };
  // A fresh transport process reuses the persisted namespace, not a new UUID.
  auto metadata = std::make_shared<meta::client::MetaClient>(
      namespaceId,
      config.meta_client(),
      std::make_unique<meta::client::MetaClient::StubFactory>(
          [network](net::Address address) { return network->serdeCtx(address); }),
      mgmtdClient,
      dataClient,
      false);
  SCOPE_EXIT { metadata->stop(); };
  if (command == "export-allocations") {
    const EcStripeControl control{std::chrono::steady_clock::now() + std::chrono::seconds(config.deadline_seconds()),
                                  {}, *storageTransport};
    auto exported = blockingWait(exportEcAllocations(
        metadata,
        record,
        flat::UserInfo{flat::Uid(config.user_info().uid()), flat::Gid(config.user_info().gid()), std::move(*token)},
        config.allocation_output(),
        control));
    if (!exported) {
      std::cerr << exported.error().describe() << '\n';
      return 1;
    }
    fmt::print("Allocation metadata archived at {}; this is not GC authorization.\n", config.allocation_output());
    return 0;
  }
  folly::CPUThreadPoolExecutor executor(config.worker_threads());
  const flat::UserInfo credentials{flat::Uid(config.user_info().uid()),
                                   flat::Gid(config.user_info().gid()),
                                   std::move(*token)};
  EcStripeClient::Limits limits;
  limits.maxOperations = config.max_operations();
  limits.maxApplicationBytes = config.max_application_bytes();
  limits.writeFragments = config.write_fragments();
  limits.readBlocks = config.read_blocks();
  limits.maxOperationTime = std::chrono::seconds(config.deadline_seconds());
  auto manager = blockingWait(
      EcStripeClient::connect(metadata, dataClient, mgmtdClient, credentials, namespaceId.uuid, executor, limits));
  if (!manager) {
    std::cerr << manager.error().describe() << '\n';
    return 2;
  }
  SCOPE_EXIT { blockingWait((*manager)->close()); };
  std::optional<FlatRepairMetrics> repairMetrics;
  if (config.repair_metrics() && record.record().action == "repair" &&
      (command == "new-repair" || command == "resume"))
    repairMetrics.emplace();
  auto result = run(record, **manager, config, command, metadata, credentials,
                    repairMetrics ? &*repairMetrics : nullptr);
  blockingWait((*manager)->close());
  if (repairMetrics) emitFlatRepairMetrics(*repairMetrics, record.record(), command);
  if (record.latest()) fmt::print("{}\n", serde::toJsonString(*record.latest(), true, true));
  fmt::print("Local manager joined; active_operations={} reserved_application_bytes={}.\n",
             (*manager)->snapshot().activeOperations,
             (*manager)->snapshot().reservedApplicationBytes);
  if (!result) {
    std::cerr << result.error().describe() << '\n';
    return 1;
  }
  return 0;
}
}  // namespace

int main(int argc, char **argv) {
  try {
    return execute(argc, argv);
  } catch (const std::exception &error) {
    std::cerr << "ec_stripe_cli failed: " << error.what() << '\n';
    return 2;
  } catch (...) {
    std::cerr << "ec_stripe_cli failed with an unknown exception\n";
    return 2;
  }
}
