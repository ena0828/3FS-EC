#include "EcExternalFenceCommands.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <limits>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include "AdminClientIdentity.h"
#include "AdminEnv.h"
#include "client/cli/common/Utils.h"
#include "fbs/meta/EcTargetRetirement.h"

namespace hf3fs::client::cli {
namespace {
// Administrative observation only. Signed provider evidence is never printed.
// This does not establish physical deletion, scope drain or publication rights.
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
  SERDE_STRUCT_FIELD(host_execution_fenced, false);
  SERDE_STRUCT_FIELD(physical_capacity_returned, false);
  SERDE_STRUCT_FIELD(provider_id, Uuid::zero());
  SERDE_STRUCT_FIELD(enrollment_id, Uuid::zero());
  SERDE_STRUCT_FIELD(resource_generation, Uuid::zero());
  SERDE_STRUCT_FIELD(binding_sha256, std::string{});
  SERDE_STRUCT_FIELD(evidence_sha256, std::string{});
  SERDE_STRUCT_FIELD(deny_sha256, std::string{});
  SERDE_STRUCT_FIELD(proof_sha256, std::string{});
  SERDE_STRUCT_FIELD(sequence_decimal, std::string{});
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

enum class Action { Prepare, Import, Query };

std::string hex(const storage::EcSha256 &);

auto parserFor(std::string name, Action action) {
  argparse::ArgumentParser parser(std::move(name));
  for (const auto *option : {"--node-id", "--chain-id", "--target-id", "--engine-uuid", "--target-incarnation",
                            "--retirement-id", "--client-namespace", "--request-id", "--output",
                            "--provider-id", "--enrollment-id", "--resource-generation", "--binding-sha256"})
    parser.add_argument(option).required();
  if (action == Action::Import) parser.add_argument("--evidence").required();
  return parser;
}

Result<storage::EcSha256> digestArgument(std::string_view text) {
  if (text.size() != 64) return makeError(StatusCode::kInvalidArg);
  storage::EcSha256 out{};
  auto digit = [](char c) -> int {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
  };
  bool nonzero = false;
  for (size_t i = 0; i < out.size(); ++i) {
    const int high = digit(text[2 * i]), low = digit(text[2 * i + 1]);
    if (high < 0 || low < 0) return makeError(StatusCode::kInvalidArg);
    out[i] = static_cast<uint8_t>((high << 4) | low);
    nonzero = nonzero || out[i] != 0;
  }
  if (!nonzero) return makeError(StatusCode::kInvalidArg);
  return out;
}

Result<std::string> evidenceFile(const Path &path) {
  // O_NONBLOCK avoids blocking on a FIFO before fstat rejects its type.
  const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return makeError(StatusCode::kIOError);
  SCOPE_EXIT { ::close(fd); };
  struct stat before{}, after{};
  constexpr size_t bytes = meta::kEcHostFenceCertificateBytes;  // Version 1: fixed 248-byte claims + 64-byte Ed25519 signature.
  if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
      before.st_size != static_cast<off_t>(bytes))
    return makeError(StatusCode::kInvalidArg, "external fence evidence must be one fixed 312-byte regular file");
  std::string out(bytes, '\0');
  size_t offset = 0;
  while (offset < out.size()) {
    const auto count = ::read(fd, out.data() + offset, out.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return makeError(StatusCode::kIOError);
    offset += static_cast<size_t>(count);
  }
  char extra;
  ssize_t count;
  do { count = ::read(fd, &extra, 1); } while (count < 0 && errno == EINTR);
  if (count != 0 || ::fstat(fd, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
    return makeError(StatusCode::kIOError, "external fence evidence changed while reading");
  return out;
}

Result<std::string> evidenceDigest(std::string_view bytes) {
  if (bytes.empty()) return std::string{};
  storage::EcSha256 value{};
  unsigned length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), value.data(), &length, EVP_sha256(), nullptr) != 1 || length != value.size())
    return makeError(StatusCode::kIOError);
  return hex(value);
}

Result<meta::EcTargetRetirementReq> requestFor(const argparse::ArgumentParser &parser,
                                              const flat::UserInfo &user, Action action) {
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
  req.mode = meta::EcTargetRetirementMode::HostExecutionFence;
  meta::EcHostFenceBinding binding;
  CHECK_RESULT(provider, parseAdminNonNilUuid(parser.get<std::string>("--provider-id")));
  CHECK_RESULT(enrollment, parseAdminNonNilUuid(parser.get<std::string>("--enrollment-id")));
  CHECK_RESULT(generation, parseAdminNonNilUuid(parser.get<std::string>("--resource-generation")));
  CHECK_RESULT(digest, digestArgument(parser.get<std::string>("--binding-sha256")));
  binding.providerId = provider;
  binding.enrollmentId = enrollment;
  binding.resourceGeneration = generation;
  binding.bindingDigest = digest;
  if (!binding.valid()) return makeError(StatusCode::kInvalidArg);
  req.externalBinding = binding;
  if (action == Action::Import) {
    CHECK_RESULT(bytes, evidenceFile(Path(parser.get<std::string>("--evidence"))));
    req.externalEvidence = std::move(bytes);
  }
  RETURN_ON_ERROR(req.valid());
  return req;
}

Observation prepared(const meta::EcTargetRetirementReq &req, Action action, std::string evidenceSha) {
  Observation out;
  out.action = action == Action::Prepare ? "prepare_external_fence"
               : action == Action::Import ? "import_external_fence" : "query_external_fence";
  out.provider_id = req.externalBinding->providerId;
  out.enrollment_id = req.externalBinding->enrollmentId;
  out.resource_generation = req.externalBinding->resourceGeneration;
  out.binding_sha256 = hex(req.externalBinding->bindingDigest);
  out.evidence_sha256 = std::move(evidenceSha);
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
    if (fd < 0) return makeError(StatusCode::kIOError, "external fence archive must be a new exclusive file");
    auto closeFd = folly::makeGuard([fd] { ::close(fd); });
    if (::fchmod(fd, 0600) != 0) return makeError(StatusCode::kIOError);
    RETURN_ON_ERROR(appendFd(fd, observation));
    const auto parent = path.parent_path().empty() ? Path(".") : path.parent_path();
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return makeError(StatusCode::kIOError, "cannot open external fence archive directory");
    SCOPE_EXIT { ::close(directory); };
    if (::fsync(directory) != 0) return makeError(StatusCode::kIOError, "external fence archive sync failed");
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
      if (written <= 0) return makeError(StatusCode::kIOError, "external fence archive append failed");
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) return makeError(StatusCode::kIOError, "external fence archive sync failed");
    return Void{};
  }
  int fd_;
};

bool matches(const meta::EcTargetRetirementRsp &rsp, const meta::EcTargetRetirementReq &req) {
  const auto &intent = rsp.intent;
  if (rsp.mode != meta::EcTargetRetirementMode::HostExecutionFence || intent.version != 2 ||
      intent.endpoint != req.endpoint || intent.retirementId != req.retirementId || intent.authority.is_nil() ||
      intent.owner.uid != req.user.uid || intent.owner.client != req.client.uuid || intent.requestId != req.uuid ||
      !req.externalBinding || !rsp.externalBinding || !rsp.externalBinding->valid())
    return false;
  const auto &binding = *req.externalBinding;
  const auto &observed = *rsp.externalBinding;
  if (observed.providerId != binding.providerId || observed.enrollmentId != binding.enrollmentId ||
      observed.resourceGeneration != binding.resourceGeneration || observed.bindingDigest != binding.bindingDigest)
    return false;
  const bool zero = std::all_of(rsp.completionDigest.begin(), rsp.completionDigest.end(), [](auto b) { return !b; });
  if (rsp.stage == meta::EcTargetRetirementStage::Prepared) return zero && !rsp.external;
  if (rsp.stage != meta::EcTargetRetirementStage::HostExecutionFenced || zero || !rsp.external || !rsp.external->valid())
    return false;
  const auto &x = *rsp.external;
  const auto &b = *req.externalBinding;
  return x.providerId == b.providerId && x.enrollmentId == b.enrollmentId &&
         x.resourceGeneration == b.resourceGeneration && x.bindingDigest == b.bindingDigest && x.sequence == 1;
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
                                        Action action) {
  ENSURE_USAGE(args.empty());
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  auto request = requestFor(parser, env.userInfo, action);
  CO_RETURN_ON_ERROR(request);
  auto evidenceSha = evidenceDigest(request->externalEvidence);
  CO_RETURN_ON_ERROR(evidenceSha);
  auto observation = prepared(*request, action, std::move(*evidenceSha));
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
    if (action != Action::Query) {
      meta::PrepareEcTargetRetirementReq req;
      static_cast<meta::EcTargetRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->prepareEcTargetRetirement(std::move(req)));
    } else {
      meta::QueryEcTargetRetirementReq req;
      static_cast<meta::EcTargetRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->queryEcTargetRetirement(std::move(req)));
    }
    observation.phase = "result";
    if (result && (!matches(*result, *request) ||
                   (action == Action::Import &&
                    (result->stage != meta::EcTargetRetirementStage::HostExecutionFenced ||
                     hex(result->external->proofDigest) != observation.evidence_sha256))))
      result = makeError(StorageClientCode::kProtocolMismatch);
    if (result) {
      observation.meta_intent_confirmed = true;
      observation.authority = result->intent.authority;
      observation.host_execution_fenced = result->stage == meta::EcTargetRetirementStage::HostExecutionFenced;
      observation.outcome = observation.host_execution_fenced ? "host_execution_fenced" : "intent_accepted";
      if (observation.host_execution_fenced) {
        observation.completion_sha256 = hex(result->completionDigest);
        observation.deny_sha256 = hex(result->external->denyDigest);
        observation.proof_sha256 = hex(result->external->proofDigest);
        observation.sequence_decimal = std::to_string(result->external->sequence);
      }
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
      co_return makeError(result.error().code(), "external fence unconfirmed; retain original IDs and use a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
}  // namespace

CoTryTask<void> registerEcExternalFenceHandlers(Dispatcher &dispatcher) {
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-prepare-external-fence", Action::Prepare); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, Action::Prepare); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-import-external-fence", Action::Import); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, Action::Import); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-query-external-fence", Action::Query); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, Action::Query); }));
  co_return Void{};
}
}  // namespace hf3fs::client::cli
