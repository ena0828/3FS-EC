#include "EcTargets.h"

#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <unistd.h>

#include "AdminEnv.h"
#include "client/cli/common/Utils.h"
#include "fbs/storage/EcTargetDiscovery.h"

namespace hf3fs::client::cli {
namespace {
uint64_t nowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
struct DiscoveryExport {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(authority, std::string{});
  SERDE_STRUCT_FIELD(node, uint32_t{});
  SERDE_STRUCT_FIELD(chain, uint32_t{});
  SERDE_STRUCT_FIELD(target, uint64_t{});
  SERDE_STRUCT_FIELD(engine_uuid, std::string{});
  SERDE_STRUCT_FIELD(target_incarnation, std::string{});
  SERDE_STRUCT_FIELD(protocol, uint16_t{2});
  SERDE_STRUCT_FIELD(observed_at_seconds, uint64_t{});
  SERDE_STRUCT_FIELD(verified_at_seconds, uint64_t{});
  SERDE_STRUCT_FIELD(verification, std::string{"control_mac_verified"});
};
Result<Void> writeNewExport(const Path &path, std::string_view contents) {
  // Explicit output only; never replace an existing manifest or follow a final
  // symlink. An interrupted partial file must be removed by its administrator.
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return makeError(StatusCode::kIOError, "cannot exclusively create EC discovery export");
  SCOPE_EXIT { ::close(fd); };
  size_t offset = 0;
  while (offset < contents.size()) {
    const auto written = ::write(fd, contents.data() + offset, contents.size() - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return makeError(StatusCode::kIOError, "EC discovery export write failed");
    offset += static_cast<size_t>(written);
  }
  if (::fsync(fd) != 0) return makeError(StatusCode::kIOError, "EC discovery export sync failed");
  return Void{};
}
auto discoveryParser() {
  argparse::ArgumentParser parser("discover-ec-target");
  parser.add_argument("--node-id").scan<'u', uint32_t>().required();
  parser.add_argument("--chain-id").scan<'u', uint32_t>().required();
  parser.add_argument("--target-id").scan<'u', uint64_t>().required();
  parser.add_argument("--authority").required();
  parser.add_argument("--control-key-file").required();
  parser.add_argument("--output").required();
  return parser;
}
CoTryTask<Dispatcher::OutputTable> discover(IEnv &ienv,
                                            const argparse::ArgumentParser &parser,
                                            const Dispatcher::Args &args) {
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  ENSURE_USAGE(args.empty());
  auto authority = Uuid::fromHexString(parser.get<std::string>("--authority"));
  CO_RETURN_ON_ERROR(authority);
  auto key = storage::EcScopeControlKey::loadFile(std::filesystem::path(parser.get<std::string>("--control-key-file")));
  CO_RETURN_ON_ERROR(key);
  std::shared_ptr<const storage::EcScopeControlKey> shared(std::move(*key));
  storage::EcTargetDiscoveryClaims claims;
  claims.clusterAuthority = *authority;
  claims.nodeId = flat::NodeId(parser.get<uint32_t>("--node-id"));
  claims.chainId = storage::ChainId(parser.get<uint32_t>("--chain-id"));
  claims.targetId = storage::TargetId(parser.get<uint64_t>("--target-id"));
  claims.nonce = Uuid::random();
  claims.issuedAtSeconds = nowSeconds();
  claims.expiresAtSeconds = claims.issuedAtSeconds + 30;
  auto request = storage::signEcTargetDiscovery(*shared, claims, claims.issuedAtSeconds);
  CO_RETURN_ON_ERROR(request);
  CO_RETURN_ON_ERROR(co_await env.mgmtdClientGetter()->refreshRoutingInfo(true));
  storage::client::EcRequestControl control;
  control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
  control.transport = storage::client::EcRequestControl::TransportPolicy::TcpOnly;
  auto observed = co_await env.storageClientGetter()->getEcTargetIdentityControlled(*request, shared, control);
  CO_RETURN_ON_ERROR(observed);
  // Client verified the MAC, live nonce and complete logical binding. Export
  // only normalized observations, never a signing key or bearer request.
  const auto &endpoint = observed->claims.endpoint;
  DiscoveryExport out;
  out.authority = authority->toHexString();
  out.node = endpoint.nodeId.toUnderType();
  out.chain = endpoint.chainId.toUnderType();
  out.target = endpoint.targetId.toUnderType();
  out.engine_uuid = endpoint.engineUuid.toHexString();
  out.target_incarnation = endpoint.targetIncarnation.toHexString();
  out.observed_at_seconds = observed->claims.observedAtSeconds;
  out.verified_at_seconds = nowSeconds();
  CO_RETURN_ON_ERROR(writeNewExport(Path(parser.get<std::string>("--output")), serde::toJsonString(out) + "\n"));
  co_return Dispatcher::OutputTable{{"Verified loaded V2 target; wrote explicit instance export"}};
}
auto createParser() {
  argparse::ArgumentParser parser("create-ec-target");
  parser.add_argument("--node-id").scan<'u', uint32_t>().required();
  parser.add_argument("--disk-index").scan<'u', uint32_t>().required();
  parser.add_argument("--chain-id").scan<'u', uint32_t>().required();
  parser.add_argument("--target-id").scan<'u', uint64_t>().required();
  parser.add_argument("--allow-existing").default_value(false).implicit_value(true);
  return parser;
}
CoTryTask<Dispatcher::OutputTable> create(IEnv &ienv,
                                          const argparse::ArgumentParser &parser,
                                          const Dispatcher::Args &args) {
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  ENSURE_USAGE(args.empty());
  storage::EcCreateTargetReq request;
  request.settings.targetId = storage::TargetId(parser.get<uint64_t>("--target-id"));
  request.settings.chainId = storage::ChainId(parser.get<uint32_t>("--chain-id"));
  request.settings.diskIndex = parser.get<uint32_t>("--disk-index");
  request.settings.onlyChunkEngine = true;
  request.settings.allowExistingTarget = parser.get<bool>("--allow-existing");
  CO_RETURN_ON_ERROR(co_await env.mgmtdClientGetter()->refreshRoutingInfo(true));
  auto result =
      co_await env.storageClientGetter()->createEcTarget(flat::NodeId(parser.get<uint32_t>("--node-id")), request);
  CO_RETURN_ON_ERROR(result);
  if (result->targetId != request.settings.targetId) co_return makeError(StorageClientCode::kProtocolMismatch);
  // Method 18 retains the existing trusted cluster-management boundary. This
  // command does not imply that legacy target administration gained MAC auth.
  co_return Dispatcher::OutputTable{{"Created EC target through explicit immutable-target method 18"}};
}
}  // namespace
CoTryTask<void> registerEcTargetsHandlers(Dispatcher &dispatcher) {
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(discoveryParser, discover));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(createParser, create));
  co_return Void{};
}
}  // namespace hf3fs::client::cli
