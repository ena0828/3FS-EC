#include "EcRevisionRetirementCommands.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <sys/stat.h>
#include <unistd.h>

#include "AdminClientIdentity.h"
#include "AdminEnv.h"
#include "client/cli/common/Utils.h"

namespace hf3fs::client::cli {
namespace {
// Full-width integers remain decimal strings in JSON; neither JSON floating
// point nor InodeId's diagnostic hexadecimal form is an archive identity.
struct Observation {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{});
  SERDE_STRUCT_FIELD(phase, std::string{"prepared"});
  SERDE_STRUCT_FIELD(outcome, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(client_namespace, Uuid::zero());
  SERDE_STRUCT_FIELD(request_id, Uuid::zero());
  SERDE_STRUCT_FIELD(inode_decimal, std::string{});
  SERDE_STRUCT_FIELD(object_incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe_decimal, std::string{});
  SERDE_STRUCT_FIELD(revision_decimal, std::string{});
  SERDE_STRUCT_FIELD(generation_decimal, std::string{});
  SERDE_STRUCT_FIELD(references_released, false);
  SERDE_STRUCT_FIELD(status_code, uint32_t{});
};

Result<uint64_t> unsignedDecimal(std::string_view text) {
  if (text.empty() || text.size() > 20 ||
      !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
    return makeError(StatusCode::kInvalidArg, "retirement integers require unsigned decimal digits");
  uint64_t value = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    return makeError(StatusCode::kInvalidArg, "retirement unsigned integer is out of range");
  return value;
}

auto parserFor(std::string name) {
  argparse::ArgumentParser parser(std::move(name));
  for (const auto *option :
       {"--inode", "--object-incarnation", "--stripe", "--revision", "--client-namespace", "--request-id", "--output"})
    parser.add_argument(option).required();
  return parser;
}

Result<meta::EcRevisionRetirementReq> requestFor(const argparse::ArgumentParser &parser, const flat::UserInfo &user) {
  // Early usage validation only. Authentication is the real server's token
  // check followed by its effective UID0 check, never this local field.
  if (!user.isRoot() || user.token.empty())
    return makeError(StatusCode::kAuthenticationFail, "retirement requires configured root UID and a token");
  CHECK_RESULT(inode, unsignedDecimal(parser.get<std::string>("--inode")));
  CHECK_RESULT(stripe, unsignedDecimal(parser.get<std::string>("--stripe")));
  CHECK_RESULT(revision, unsignedDecimal(parser.get<std::string>("--revision")));
  CHECK_RESULT(object, parseAdminNonNilUuid(parser.get<std::string>("--object-incarnation")));
  CHECK_RESULT(client, parseAdminNonNilUuid(parser.get<std::string>("--client-namespace")));
  CHECK_RESULT(request, parseAdminNonNilUuid(parser.get<std::string>("--request-id")));
  if (!inode || meta::InodeId(inode).isTreeRoot() || inode > meta::InodeId::normalMax().u64() || !revision)
    return makeError(StatusCode::kInvalidArg, "invalid fixed historical revision identity");
  meta::EcRevisionRetirementReq req;
  req.user = user;
  req.uuid = request;
  req.client = ClientId(client);
  req.object = {meta::InodeId(inode), object};
  req.stripe = stripe;
  req.revision = revision;
  RETURN_ON_ERROR(req.valid());
  return req;
}

Observation prepared(const meta::EcRevisionRetirementReq &req, bool retire) {
  Observation value;
  value.action = retire ? "retire_revision" : "query_revision_retirement";
  value.client_namespace = req.client.uuid;
  value.request_id = req.uuid;
  value.inode_decimal = std::to_string(req.object.inode.u64());
  value.object_incarnation = req.object.incarnation;
  value.stripe_decimal = std::to_string(req.stripe);
  value.revision_decimal = std::to_string(req.revision);
  return value;
}

class Journal {
 public:
  explicit Journal(int fd)
      : fd_(fd) {}
  ~Journal() {
    if (fd_ >= 0) ::close(fd_);
  }
  Journal(const Journal &) = delete;
  Journal &operator=(const Journal &) = delete;

  static Result<std::unique_ptr<Journal>> create(const Path &path, const auto &observation) {
    if (path.empty()) return makeError(StatusCode::kInvalidArg);
    const auto text = serde::toJsonString(observation) + "\n";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return makeError(StatusCode::kIOError, "retirement archive must be a new exclusive file");
    SCOPE_EXIT { ::close(fd); };
    if (::fchmod(fd, 0600) != 0) return makeError(StatusCode::kIOError, "cannot set private retirement archive mode");
    RETURN_ON_ERROR(appendFd(fd, text));
    const auto parent = path.parent_path().empty() ? Path(".") : path.parent_path();
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return makeError(StatusCode::kIOError, "cannot open retirement archive directory");
    SCOPE_EXIT { ::close(directory); };
    if (::fsync(directory) != 0) return makeError(StatusCode::kIOError, "retirement archive directory sync failed");
    // Prepared identity is durable before this ownership transfer. The original
    // fd remains guarded if duplicating ownership or allocating the object fails.
    const int held = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (held < 0) return makeError(StatusCode::kIOError, "cannot retain retirement archive fd");
    auto guard = folly::makeGuard([&] { ::close(held); });
    auto result = std::make_unique<Journal>(held);
    guard.dismiss();
    return Result<std::unique_ptr<Journal>>(std::move(result));
  }
  Result<Void> append(const auto &value) { return appendFd(fd_, serde::toJsonString(value) + "\n"); }

 private:
  static Result<Void> appendFd(int fd, std::string_view text) {
    size_t offset = 0;
    while (offset != text.size()) {
      const auto written = ::write(fd, text.data() + offset, text.size() - offset);
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) return makeError(StatusCode::kIOError, "retirement archive append failed");
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) return makeError(StatusCode::kIOError, "retirement archive sync failed");
    return Void{};
  }
  int fd_;
};

CoTryTask<Dispatcher::OutputTable> handle(IEnv &ienv,
                                          const argparse::ArgumentParser &parser,
                                          const Dispatcher::Args &args,
                                          bool retire) {
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  ENSURE_USAGE(args.empty());
  auto request = requestFor(parser, env.userInfo);
  CO_RETURN_ON_ERROR(request);
  auto observation = prepared(*request, retire);
  auto journal = Journal::create(Path(parser.get<std::string>("--output")), observation);
  CO_RETURN_ON_ERROR(journal);
  bool invoked = false;
  try {
    auto client = env.metaClientGetter();
    if (!client) co_return makeError(StatusCode::kInvalidConfig, "Meta client unavailable; prepared archive retained");
    // MetaClient::retry overwrites req.client. Checking only the request field
    // would falsely promise cross-process recovery under a random namespace.
    if (client->clientId().uuid != request->client.uuid)
      co_return makeError(
          StatusCode::kInvalidArg,
          "client-namespace differs from actual MetaClient; set --config.client_uuid to the same persisted UUID");
    invoked = true;
    Result<meta::EcRevisionRetirementRsp> result = makeError(StatusCode::kNotImplemented);
    if (retire) {
      meta::RetireEcRevisionV2Req req;
      static_cast<meta::EcRevisionRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->retireEcRevisionV2(std::move(req)));
    } else {
      meta::QueryEcRevisionRetirementV2Req req;
      static_cast<meta::EcRevisionRetirementReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->queryEcRevisionRetirementV2(std::move(req)));
    }
    observation.phase = "result";
    if (result && (result->object != request->object || result->stripe != request->stripe ||
                   result->revision != request->revision || !result->generation ||
                   result->clientNamespace != request->client.uuid || result->requestId != request->uuid ||
                   !result->referencesReleased))
      result = makeError(StorageClientCode::kProtocolMismatch);
    if (result) {
      observation.outcome = "confirmed";
      observation.generation_decimal = std::to_string(result->generation);
      observation.references_released = true;
    } else {
      observation.status_code = result.error().code();
      const auto code = result.error().code();
      observation.outcome = code == StorageCode::kEcSealOutcomeUnknown || code == TransactionCode::kMaybeCommitted
                                ? "unknown"
                                : "not_confirmed";
    }
    auto saved = (*journal)->append(observation);
    if (!saved)
      co_return makeError(StorageCode::kEcSealOutcomeUnknown,
                          "retirement final archive sync failed; query the same namespace, request and payload");
    if (!result)
      co_return makeError(result.error().code(),
                          "retirement not confirmed; retain the original identity and query using a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    // Query errors are also inconclusive: a prior retirement may have committed.
    // Neither exceptions nor missing observations authorize a new identity.
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}

struct TreeGcCandidate {
  SERDE_STRUCT_FIELD(stripe_decimal, std::string{});
  SERDE_STRUCT_FIELD(revision_decimal, std::string{});
  SERDE_STRUCT_FIELD(generation_decimal, std::string{});
  SERDE_STRUCT_FIELD(shard, uint16_t{});
  SERDE_STRUCT_FIELD(allocation, Uuid::zero());
};
struct TreeObservation {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{"tree_reclaim"});
  SERDE_STRUCT_FIELD(phase, std::string{"prepared"});
  SERDE_STRUCT_FIELD(outcome, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(inode_decimal, std::string{});
  SERDE_STRUCT_FIELD(object_incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(client_namespace, Uuid::zero());
  SERDE_STRUCT_FIELD(request_id, Uuid::zero());
  SERDE_STRUCT_FIELD(node, Uuid::zero());
  SERDE_STRUCT_FIELD(next_node, Uuid::zero());
  SERDE_STRUCT_FIELD(reclaimed, false);
  // Each string is "stripe:revision" in unsigned decimal. No logical content
  // or capability is printed; the root administrator already owns this scope.
  SERDE_STRUCT_FIELD(retire_candidates, std::vector<std::string>{});
  SERDE_STRUCT_FIELD(gc_candidates, std::vector<TreeGcCandidate>{});
  SERDE_STRUCT_FIELD(status_code, uint32_t{});
};
auto treeParser() {
  argparse::ArgumentParser p("ec-advance-tree-reclaim");
  for (const auto *arg :
       {"--inode", "--object-incarnation", "--node", "--client-namespace", "--request-id", "--output"})
    p.add_argument(arg).required();
  return p;
}
CoTryTask<Dispatcher::OutputTable> handleTree(IEnv &ienv,
                                              const argparse::ArgumentParser &p,
                                              const Dispatcher::Args &args) {
  ENSURE_USAGE(args.empty());
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  if (!env.userInfo.isRoot() || env.userInfo.token.empty()) co_return makeError(StatusCode::kAuthenticationFail);
  auto inode = unsignedDecimal(p.get<std::string>("--inode"));
  CO_RETURN_ON_ERROR(inode);
  auto object = parseAdminNonNilUuid(p.get<std::string>("--object-incarnation"));
  CO_RETURN_ON_ERROR(object);
  auto client = parseAdminNonNilUuid(p.get<std::string>("--client-namespace"));
  CO_RETURN_ON_ERROR(client);
  auto id = parseAdminNonNilUuid(p.get<std::string>("--request-id"));
  CO_RETURN_ON_ERROR(id);
  const auto nodeText = p.get<std::string>("--node");
  Uuid node{};
  if (nodeText != "inspect") {
    auto n = parseAdminNonNilUuid(nodeText);
    CO_RETURN_ON_ERROR(n);
    node = *n;
  }
  meta::AdvanceEcTreeReclaimReq req;
  req.user = env.userInfo;
  req.client.uuid = *client;
  req.uuid = *id;
  req.object = {meta::InodeId(*inode), *object};
  req.node = node;
  CO_RETURN_ON_ERROR(req.valid());
  TreeObservation observation;
  observation.inode_decimal = std::to_string(*inode);
  observation.object_incarnation = *object;
  observation.client_namespace = *client;
  observation.request_id = *id;
  observation.node = node;
  if (node.is_nil()) observation.action = "tree_reclaim_inspect";
  auto journal = Journal::create(Path(p.get<std::string>("--output")), observation);
  CO_RETURN_ON_ERROR(journal);
  bool invoked = false;
  try {
    auto remote = env.metaClientGetter();
    if (!remote) co_return makeError(StatusCode::kInvalidConfig);
    if (remote->clientId().uuid != *client)
      co_return makeError(StatusCode::kInvalidArg, "actual MetaClient namespace differs from prepared archive");
    invoked = true;
    auto result = co_await folly::coro::co_withCancellation({}, remote->advanceEcTreeReclaim(req));
    if (result && (result->requestId != req.uuid || result->clientNamespace != req.client.uuid ||
                   result->progress.object != req.object || result->progress.node != node ||
                   result->progress.reclaimed != !node.is_nil() ||
                   (!node.is_nil() && (!result->progress.refs || result->progress.refs->object != req.object ||
                                       result->progress.refs->node != node ||
                                       result->progress.refs->state != meta::EcTreeRefState::Reclaimed ||
                                       result->progress.refs->references))))
      result = makeError(StorageClientCode::kProtocolMismatch);
    observation.phase = "result";
    if (result) {
      observation.outcome = "confirmed";
      observation.reclaimed = result->progress.reclaimed;
      observation.next_node = result->progress.next;
      for (size_t n = 0; n < 16; ++n) {
        const auto &slot = result->progress.revisions[n];
        if (slot.kind != meta::EcTreeSlotKind::Data) continue;
        observation.retire_candidates.push_back(std::to_string(slot.stripe) + ":" + std::to_string(slot.revision));
        for (size_t shard = 0; shard < 12; ++shard) {
          const auto &identity = result->progress.identities[n].fragments[shard];
          if (!identity.validate() || identity.object != req.object.incarnation || identity.stripe != slot.stripe ||
              identity.generation != slot.generation || identity.shard != shard) {
            observation.outcome = "not_confirmed";
            observation.status_code = StorageClientCode::kProtocolMismatch;
            CO_RETURN_ON_ERROR((*journal)->append(observation));
            co_return makeError(StorageClientCode::kProtocolMismatch);
          }
          TreeGcCandidate candidate;
          candidate.stripe_decimal = std::to_string(slot.stripe);
          candidate.revision_decimal = std::to_string(slot.revision);
          candidate.generation_decimal = std::to_string(identity.generation);
          candidate.shard = identity.shard;
          candidate.allocation = identity.allocation;
          observation.gc_candidates.push_back(std::move(candidate));
        }
      }
    } else {
      observation.status_code = result.error().code();
      observation.outcome = (result.error().code() == TransactionCode::kMaybeCommitted ||
                             result.error().code() == StorageCode::kEcSealOutcomeUnknown)
                                ? "unknown"
                                : "not_confirmed";
    }
    auto saved = (*journal)->append(observation);
    if (!saved) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
    if (!result)
      co_return makeError(result.error().code(),
                          "tree reclaim not confirmed; retry exact original IDs and node with a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
}  // namespace

CoTryTask<void> registerEcRevisionRetirementHandlers(Dispatcher &dispatcher) {
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return treeParser(); },
      [](IEnv &env, const auto &p, const auto &a) { return handleTree(env, p, a); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-retire-revision"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, true); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-query-revision-retirement"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, false); }));
  co_return Void{};
}
}  // namespace hf3fs::client::cli
