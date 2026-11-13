#include "EcTargetRetirementCommands.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

#include "AdminClientIdentity.h"
#include "AdminEnv.h"
#include "client/cli/common/Utils.h"
#include "fbs/meta/EcTargetRetirement.h"

namespace hf3fs::client::cli {
namespace {
// This is an operator archive, not a signed Storage observation or a GC proof.
// Preserve every caller-chosen identity before any potentially committing RPC.
struct Observation {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{});
  SERDE_STRUCT_FIELD(phase, std::string{"prepared"});
  SERDE_STRUCT_FIELD(outcome, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(client_namespace, Uuid::zero());
  SERDE_STRUCT_FIELD(request_id, Uuid::zero());
  SERDE_STRUCT_FIELD(retirement_id, Uuid::zero());
  SERDE_STRUCT_FIELD(node_decimal, std::string{});
  SERDE_STRUCT_FIELD(chain_decimal, std::string{});
  SERDE_STRUCT_FIELD(target_decimal, std::string{});
  SERDE_STRUCT_FIELD(engine_uuid, Uuid::zero());
  SERDE_STRUCT_FIELD(target_incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(authority, Uuid::zero());
  SERDE_STRUCT_FIELD(meta_intent_confirmed, false);
  SERDE_STRUCT_FIELD(cooperative_data_drained, false);
  SERDE_STRUCT_FIELD(completion_sha256, std::string{});
  SERDE_STRUCT_FIELD(status_code, uint32_t{});
};

Result<uint64_t> unsignedDecimal(std::string_view text) {
  if (text.empty() || text.size() > 20 ||
      !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
    return makeError(StatusCode::kInvalidArg, "target retirement integers require unsigned decimal digits");
  uint64_t value = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || !value)
    return makeError(StatusCode::kInvalidArg, "target retirement identity integer is zero or out of range");
  return value;
}

auto parserFor(std::string name) {
  argparse::ArgumentParser parser(std::move(name));
  for (const auto *option : {"--node-id", "--chain-id", "--target-id", "--engine-uuid", "--target-incarnation",
                            "--retirement-id", "--client-namespace", "--request-id", "--output"})
    parser.add_argument(option).required();
  return parser;
}

Result<meta::EcTargetRetirementReq> requestFor(const argparse::ArgumentParser &parser, const flat::UserInfo &user) {
  // Only an early usage check: the real Meta server authenticates the token.
  if (!user.isRoot() || user.token.empty()) return makeError(StatusCode::kAuthenticationFail);
  CHECK_RESULT(node, unsignedDecimal(parser.get<std::string>("--node-id")));
  CHECK_RESULT(chain, unsignedDecimal(parser.get<std::string>("--chain-id")));
  CHECK_RESULT(target, unsignedDecimal(parser.get<std::string>("--target-id")));
  if (node > std::numeric_limits<uint32_t>::max() || chain > std::numeric_limits<uint32_t>::max())
    return makeError(StatusCode::kInvalidArg, "target retirement node or chain exceeds uint32");
  CHECK_RESULT(engine, parseAdminNonNilUuid(parser.get<std::string>("--engine-uuid")));
  CHECK_RESULT(incarnation, parseAdminNonNilUuid(parser.get<std::string>("--target-incarnation")));
  CHECK_RESULT(retirement, parseAdminNonNilUuid(parser.get<std::string>("--retirement-id")));
  CHECK_RESULT(client, parseAdminNonNilUuid(parser.get<std::string>("--client-namespace")));
  CHECK_RESULT(request, parseAdminNonNilUuid(parser.get<std::string>("--request-id")));
  meta::EcTargetRetirementReq req;
  req.user = user;
  req.uuid = request;
  req.client = ClientId(client);
  req.endpoint.placement.node = flat::NodeId(static_cast<uint32_t>(node));
  req.endpoint.placement.chain = storage::ChainId(static_cast<uint32_t>(chain));
  req.endpoint.placement.target = storage::TargetId(target);
  req.endpoint.engineUuid = engine;
  req.endpoint.targetIncarnation = incarnation;
  req.retirementId = retirement;
  RETURN_ON_ERROR(req.valid());
  return req;
}

Observation prepared(const meta::EcTargetRetirementReq &req, bool prepare) {
  Observation out;
  out.action = prepare ? "prepare_target_retirement" : "query_target_retirement";
  out.client_namespace = req.client.uuid;
  out.request_id = req.uuid;
  out.retirement_id = req.retirementId;
  out.node_decimal = std::to_string(req.endpoint.placement.node.toUnderType());
  out.chain_decimal = std::to_string(req.endpoint.placement.chain.toUnderType());
  out.target_decimal = std::to_string(req.endpoint.placement.target.toUnderType());
  out.engine_uuid = req.endpoint.engineUuid;
  out.target_incarnation = req.endpoint.targetIncarnation;
  return out;
}

class Archive {
 public:
  explicit Archive(int fd)
      : fd_(fd) {}
  ~Archive() { ::close(fd_); }
  Archive(const Archive &) = delete;
  Archive &operator=(const Archive &) = delete;

  static Result<std::unique_ptr<Archive>> create(const Path &path, const Observation &observation) {
    if (path.empty()) return makeError(StatusCode::kInvalidArg);
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return makeError(StatusCode::kIOError, "target retirement archive must be a new exclusive file");
    auto closeFd = folly::makeGuard([fd] { ::close(fd); });
    if (::fchmod(fd, 0600) != 0) return makeError(StatusCode::kIOError);
    RETURN_ON_ERROR(appendFd(fd, observation));
    const auto parent = path.parent_path().empty() ? Path(".") : path.parent_path();
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return makeError(StatusCode::kIOError, "cannot open target retirement archive directory");
    SCOPE_EXIT { ::close(directory); };
    if (::fsync(directory) != 0) return makeError(StatusCode::kIOError, "target retirement archive sync failed");
    auto archive = std::make_unique<Archive>(fd);
    closeFd.dismiss();
    return Result<std::unique_ptr<Archive>>(std::move(archive));
  }
  Result<Void> append(const Observation &value) { return appendFd(fd_, value); }

 private:
  static Result<Void> appendFd(int fd, const Observation &value) {
    const auto text = serde::toJsonString(value) + "\n";
    size_t offset = 0;
    while (offset < text.size()) {
      const auto written = ::write(fd, text.data() + offset, text.size() - offset);
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) return makeError(StatusCode::kIOError, "target retirement archive append failed");
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) return makeError(StatusCode::kIOError, "target retirement archive sync failed");
    return Void{};
  }
  int fd_;
};

bool matches(const meta::EcTargetRetirementRsp &rsp, const meta::EcTargetRetirementReq &req) {
  const auto &intent = rsp.intent;
  if (intent.version != meta::kEcTargetRetirementCatalogVersion || intent.endpoint != req.endpoint ||
      intent.retirementId != req.retirementId ||
      intent.authority.is_nil() || intent.owner.uid != req.user.uid || intent.owner.client != req.client.uuid ||
      intent.requestId != req.uuid)
    return false;
  const bool zero = std::all_of(rsp.completionDigest.begin(), rsp.completionDigest.end(), [](auto byte) { return !byte; });
  return (rsp.stage == meta::EcTargetRetirementStage::Prepared && zero) ||
         (rsp.stage == meta::EcTargetRetirementStage::Completed && !zero);
}

std::string hex(const storage::EcSha256 &bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(64);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

CoTryTask<Dispatcher::OutputTable> handle(IEnv &ienv,
                                        const argparse::ArgumentParser &parser,
                                        const Dispatcher::Args &args,
                                        bool prepare) {
  ENSURE_USAGE(args.empty());
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  auto request = requestFor(parser, env.userInfo);
  CO_RETURN_ON_ERROR(request);
  auto observation = prepared(*request, prepare);
  auto archive = Archive::create(Path(parser.get<std::string>("--output")), observation);
  CO_RETURN_ON_ERROR(archive);
  bool invoked = false;
  try {
    auto client = env.metaClientGetter();
    if (!client) co_return makeError(StatusCode::kInvalidConfig, "Meta client unavailable; prepared archive retained");
    // MetaClient sets req.client from its real namespace. A matching command
    // argument alone cannot make recovery across process restarts durable.
    if (client->clientId().uuid != request->client.uuid)
      co_return makeError(StatusCode::kInvalidArg, "set config.client_uuid to the archived client namespace");
    invoked = true;
    Result<meta::EcTargetRetirementRsp> result = makeError(StatusCode::kNotImplemented);
    if (prepare) {
      meta::PrepareEcTargetRetirementReq req;
      static_cast<meta::EcTargetRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->prepareEcTargetRetirement(std::move(req)));
    } else {
      meta::QueryEcTargetRetirementReq req;
      static_cast<meta::EcTargetRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->queryEcTargetRetirement(std::move(req)));
    }
    observation.phase = "result";
    if (result && !matches(*result, *request)) result = makeError(StorageClientCode::kProtocolMismatch);
    if (result) {
      observation.meta_intent_confirmed = true;
      observation.authority = result->intent.authority;
      observation.cooperative_data_drained = result->stage == meta::EcTargetRetirementStage::Completed;
      observation.outcome = observation.cooperative_data_drained ? "cooperative_data_drained" : "intent_accepted";
      if (observation.cooperative_data_drained) observation.completion_sha256 = hex(result->completionDigest);
    } else {
      observation.status_code = result.error().code();
      observation.outcome = result.error().code() == StorageCode::kEcSealOutcomeUnknown ||
                                    result.error().code() == TransactionCode::kMaybeCommitted
                                ? "unknown"
                                : "not_confirmed";
    }
    auto saved = (*archive)->append(observation);
    if (!saved)
      co_return makeError(StorageCode::kEcSealOutcomeUnknown, "archive sync failed; query the same target and intent IDs");
    if (!result)
      co_return makeError(result.error().code(), "target retirement unconfirmed; retain original IDs and use a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
}  // namespace

CoTryTask<void> registerEcTargetRetirementHandlers(Dispatcher &dispatcher) {
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-prepare-target-retirement"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, true); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-query-target-retirement"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, false); }));
  co_return Void{};
}
}  // namespace hf3fs::client::cli
