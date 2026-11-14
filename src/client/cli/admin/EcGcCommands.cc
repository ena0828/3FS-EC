#include "EcGcCommands.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <folly/ScopeGuard.h>
#include <limits>
#include <unistd.h>

#include "AdminEnv.h"
#include "client/cli/common/Utils.h"

namespace hf3fs::client::cli {
namespace {
// uint64 values are decimal strings in the archive, never JSON doubles or
// diagnostic InodeId hexadecimal strings. No token, key or signed G request.
struct Observation {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{});
  SERDE_STRUCT_FIELD(phase, std::string{"prepared"});
  SERDE_STRUCT_FIELD(outcome, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(request_id, Uuid::zero());
  SERDE_STRUCT_FIELD(claim_id, Uuid::zero());
  SERDE_STRUCT_FIELD(inode_decimal, std::string{});
  SERDE_STRUCT_FIELD(object_incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe_decimal, std::string{});
  SERDE_STRUCT_FIELD(generation_decimal, std::string{});
  SERDE_STRUCT_FIELD(shard, uint16_t{});
  SERDE_STRUCT_FIELD(allocation, Uuid::zero());
  SERDE_STRUCT_FIELD(status_code, uint32_t{});
  SERDE_STRUCT_FIELD(claim_sha256, std::string{});
  SERDE_STRUCT_FIELD(ledger_sha256, std::string{});
  SERDE_STRUCT_FIELD(terminal_revision_decimal, std::string{});
};
Result<uint64_t> unsignedDecimal(std::string_view text) {
  if (text.empty() || text.size() > 20 ||
      !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
    return makeError(StatusCode::kInvalidArg, "GC integer arguments require unsigned decimal digits");
  uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size())
    return makeError(StatusCode::kInvalidArg, "GC unsigned integer is out of range");
  return value;
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
auto parserFor(std::string name, bool absence = false) {
  argparse::ArgumentParser parser(std::move(name));
  for (const auto *name : {"--inode",
                           "--object-incarnation",
                           "--stripe",
                           "--generation",
                           "--shard",
                           "--allocation",
                           "--claim-id",
                           "--request-id",
                           "--output"})
    parser.add_argument(name).required();
  if (absence) parser.add_argument("--client-namespace").required();
  return parser;
}
Result<meta::EcGcAdminReq> requestFor(const argparse::ArgumentParser &parser,
                                     const flat::UserInfo &user,
                                     bool absence = false) {
  // This is an early usage check, not token authentication. The real Meta
  // service authenticates the supplied token before checking effective UID 0.
  if (!user.isRoot() || user.token.empty())
    return makeError(StatusCode::kAuthenticationFail, "GC requires configured root UID and a token");
  CHECK_RESULT(inode, unsignedDecimal(parser.get<std::string>("--inode")));
  CHECK_RESULT(stripe, unsignedDecimal(parser.get<std::string>("--stripe")));
  CHECK_RESULT(generation, unsignedDecimal(parser.get<std::string>("--generation")));
  CHECK_RESULT(shard, unsignedDecimal(parser.get<std::string>("--shard")));
  CHECK_RESULT(object, Uuid::fromHexString(parser.get<std::string>("--object-incarnation")));
  CHECK_RESULT(allocation, Uuid::fromHexString(parser.get<std::string>("--allocation")));
  CHECK_RESULT(claim, Uuid::fromHexString(parser.get<std::string>("--claim-id")));
  CHECK_RESULT(requestId, Uuid::fromHexString(parser.get<std::string>("--request-id")));
  if (object.is_nil() || allocation.is_nil() || claim.is_nil() || requestId.is_nil() || !generation || !inode ||
      meta::InodeId(inode).isTreeRoot() || inode > meta::InodeId::normalMax().u64() || shard >= 12)
    return makeError(StatusCode::kInvalidArg, "invalid fixed object/fragment/claim/request identity");
  meta::EcGcAdminReq req;
  req.user = user;
  req.uuid = requestId;  // ReqBase.uuid, not a G exchange nonce or claim ID.
  req.object = {meta::InodeId(inode), object};
  req.identity.object = object;
  req.identity.stripe = stripe;
  req.identity.generation = generation;
  req.identity.shard = static_cast<uint16_t>(shard);
  req.identity.allocation = allocation;
  req.claimId = claim;
  if (absence) {
    CHECK_RESULT(client, Uuid::fromHexString(parser.get<std::string>("--client-namespace")));
    if (client.is_nil()) return makeError(StatusCode::kInvalidArg, "fixed administrative namespace required");
    req.client.uuid = client;
  }
  return req;  // MetaClient supplies its own client UUID before req.valid().
}
Observation prepared(const meta::EcGcAdminReq &req, bool collect) {
  Observation value;
  value.action = collect ? "collect" : "query";
  value.request_id = req.uuid;
  value.claim_id = req.claimId;
  value.inode_decimal = std::to_string(req.object.inode.u64());
  value.object_incarnation = req.object.incarnation;
  value.stripe_decimal = std::to_string(req.identity.stripe);
  value.generation_decimal = std::to_string(req.identity.generation);
  value.shard = req.identity.shard;
  value.allocation = req.identity.allocation;
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
  template <typename Value>
  static Result<std::unique_ptr<Journal>> create(const Path &path, const Value &observation) {
    if (path.empty() || path.native().find('\0') != std::string::npos) return makeError(StatusCode::kInvalidArg);
    const auto text = serde::toJsonString(observation) + "\n";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return makeError(StatusCode::kIOError, "GC archive must be a new exclusive file");
    // Acquire ownership without an allocation window after open().
    SCOPE_EXIT { ::close(fd); };
    RETURN_ON_ERROR(appendFd(fd, text));
    const auto parent = path.parent_path().empty() ? Path(".") : path.parent_path();
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return makeError(StatusCode::kIOError, "cannot open GC archive directory");
    SCOPE_EXIT { ::close(directory); };
    if (::fsync(directory) != 0) return makeError(StatusCode::kIOError, "GC archive directory sync failed");
    // Duplicate ownership only after all pre-dispatch durability checks. The
    // original is closed by its guard even if allocating the Journal throws.
    const int held = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (held < 0) return makeError(StatusCode::kIOError, "cannot retain GC archive fd");
    auto closeHeld = folly::makeGuard([&] { ::close(held); });
    auto result = std::make_unique<Journal>(held);
    closeHeld.dismiss();
    return Result<std::unique_ptr<Journal>>(std::move(result));
  }
  template <typename Value>
  Result<Void> append(const Value &value) { return appendFd(fd_, serde::toJsonString(value) + "\n"); }

 private:
  static Result<Void> appendFd(int fd, std::string_view text) {
    size_t offset = 0;
    while (offset != text.size()) {
      const auto written = ::write(fd, text.data() + offset, text.size() - offset);
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) return makeError(StatusCode::kIOError, "GC archive append failed");
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) return makeError(StatusCode::kIOError, "GC archive sync failed");
    return Void{};
  }
  int fd_;
};
CoTryTask<Dispatcher::OutputTable> handle(IEnv &ienv,
                                          const argparse::ArgumentParser &parser,
                                          const Dispatcher::Args &args,
                                          bool collect) {
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  ENSURE_USAGE(args.empty());
  auto request = requestFor(parser, env.userInfo);
  CO_RETURN_ON_ERROR(request);
  auto observation = prepared(*request, collect);
  auto journal = Journal::create(Path(parser.get<std::string>("--output")), observation);
  CO_RETURN_ON_ERROR(journal);
  bool invoked = false;
  try {
    auto client = env.metaClientGetter();
    if (!client)
      co_return makeError(StatusCode::kInvalidConfig, "Meta client is unavailable; prepared archive retained");
    invoked = true;
    Result<meta::EcGcAdminRsp> result = makeError(StatusCode::kNotImplemented);
    if (collect) {
      meta::CollectEcFragmentV2Req req;
      static_cast<meta::EcGcAdminReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->collectEcFragmentV2(std::move(req)));
    } else {
      meta::QueryEcFragmentGcV2Req req;
      static_cast<meta::EcGcAdminReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->queryEcFragmentGcV2(std::move(req)));
    }
    observation.phase = "result";
    if (result) {
      if (result->object != request->object || !serde::equals(result->identity, request->identity) ||
          result->claimId != request->claimId || !result->terminalRevision ||
          result->claimDigest == storage::EcSha256{} || result->ledgerSha256 == storage::EcSha256{})
        result = makeError(StorageClientCode::kProtocolMismatch);
    }
    if (result) {
      observation.outcome = "confirmed";
      observation.claim_sha256 = hex(result->claimDigest);
      observation.ledger_sha256 = hex(result->ledgerSha256);
      observation.terminal_revision_decimal = std::to_string(result->terminalRevision);
    } else {
      observation.status_code = result.error().code();
      observation.outcome = result.error().code() == StorageCode::kEcSealOutcomeUnknown ? "unknown" : "not_confirmed";
    }
    auto saved = (*journal)->append(observation);
    if (!saved)
      co_return makeError(StorageCode::kEcSealOutcomeUnknown,
                          "GC archive final sync failed; retain identities and query the same claim");
    if (!result)
      co_return makeError(result.error().code(), "GC not confirmed; query the same claim using a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    // Prepared identity is already fsync'ed. Do not erase it, detach the native
    // request, or claim that an ordinary exception proves no deletion occurred.
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
// This separate archive never represents an absent candidate as a Collected
// stage. Its revision belongs to the dedicated absence ledger, not a stage.
struct AbsenceObservation {
  SERDE_STRUCT_FIELD(schema, uint16_t{1});
  SERDE_STRUCT_FIELD(kind, std::string{"ec_fragment_absence"});
  SERDE_STRUCT_FIELD(absence_protocol, uint16_t{1});
  SERDE_STRUCT_FIELD(action, std::string{});
  SERDE_STRUCT_FIELD(phase, std::string{"prepared"});
  SERDE_STRUCT_FIELD(outcome, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(state, std::string{"not_confirmed"});
  SERDE_STRUCT_FIELD(client_namespace, Uuid::zero());
  SERDE_STRUCT_FIELD(request_id, Uuid::zero());
  SERDE_STRUCT_FIELD(claim_id, Uuid::zero());
  SERDE_STRUCT_FIELD(inode_decimal, std::string{});
  SERDE_STRUCT_FIELD(object_incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(stripe_decimal, std::string{});
  SERDE_STRUCT_FIELD(generation_decimal, std::string{});
  SERDE_STRUCT_FIELD(shard, uint16_t{});
  SERDE_STRUCT_FIELD(allocation, Uuid::zero());
  SERDE_STRUCT_FIELD(status_code, uint32_t{});
  SERDE_STRUCT_FIELD(claim_sha256, std::string{});
  SERDE_STRUCT_FIELD(closure_sha256, std::string{});
  SERDE_STRUCT_FIELD(ledger_sha256, std::string{});
  SERDE_STRUCT_FIELD(absence_record_revision_decimal, std::string{});
  SERDE_STRUCT_FIELD(candidate_reservation_release_eligible, false);
  SERDE_STRUCT_FIELD(storage_absence_observed, false);
  SERDE_STRUCT_FIELD(collected, false);
  SERDE_STRUCT_FIELD(physical_reclamation_confirmed, false);
};

AbsenceObservation preparedAbsence(const meta::EcGcAdminReq &req, bool confirm) {
  AbsenceObservation value;
  value.action = confirm ? "confirm_absent" : "query_absent";
  value.client_namespace = req.client.uuid;
  value.request_id = req.uuid;
  value.claim_id = req.claimId;
  value.inode_decimal = std::to_string(req.object.inode.u64());
  value.object_incarnation = req.object.incarnation;
  value.stripe_decimal = std::to_string(req.identity.stripe);
  value.generation_decimal = std::to_string(req.identity.generation);
  value.shard = req.identity.shard;
  value.allocation = req.identity.allocation;
  return value;
}

CoTryTask<Dispatcher::OutputTable> handleAbsent(IEnv &ienv,
                                               const argparse::ArgumentParser &parser,
                                               const Dispatcher::Args &args,
                                               bool confirm) {
  auto &env = dynamic_cast<AdminEnv &>(ienv);
  ENSURE_USAGE(args.empty());
  auto request = requestFor(parser, env.userInfo, true);
  CO_RETURN_ON_ERROR(request);
  auto observation = preparedAbsence(*request, confirm);
  auto journal = Journal::create(Path(parser.get<std::string>("--output")), observation);
  CO_RETURN_ON_ERROR(journal);
  bool invoked = false;
  try {
    auto client = env.metaClientGetter();
    if (!client || client->clientId().uuid != request->client.uuid)
      co_return makeError(StatusCode::kInvalidConfig, "actual Meta namespace differs; prepared archive retained");
    invoked = true;
    Result<meta::EcAbsentAdminRsp> result = makeError(StatusCode::kNotImplemented);
    if (confirm) {
      meta::ConfirmEcFragmentAbsentReq req;
      static_cast<meta::EcGcAdminReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->confirmEcFragmentAbsent(std::move(req)));
    } else {
      meta::QueryEcFragmentAbsentReq req;
      static_cast<meta::EcGcAdminReq &>(req) = *request;
      result = co_await folly::coro::co_withCancellation({}, client->queryEcFragmentAbsent(std::move(req)));
    }
    observation.phase = "result";
    if (result) {
      auto valid = result->valid();
      if (!valid || result->object != request->object || !serde::equals(result->identity, request->identity) ||
          result->claimId != request->claimId || result->requestId != request->uuid ||
          result->clientNamespace != request->client.uuid)
        result = makeError(StorageClientCode::kProtocolMismatch);
    }
    if (result) {
      observation.outcome = confirm ? "confirmed" : "observed";
      observation.state = "absent_after_close";
      observation.claim_sha256 = hex(result->claimDigest);
      observation.closure_sha256 = hex(result->closureDigest);
      observation.ledger_sha256 = hex(result->ledgerSha256);
      observation.absence_record_revision_decimal = std::to_string(result->recordRevision);
      observation.candidate_reservation_release_eligible = true;
      observation.storage_absence_observed = true;
    } else {
      observation.status_code = result.error().code();
      // A failed Confirm reply cannot establish that its Storage ledger was
      // never committed. Query observes the same claim; it never falls back to
      // Confirm or to the old Collect operation.
      observation.outcome = confirm ? "unknown" : "not_observed";
    }
    auto saved = (*journal)->append(observation);
    if (!saved)
      co_return makeError(StorageCode::kEcSealOutcomeUnknown,
                          "absence archive final sync failed; retain identities and query the same claim");
    if (!result)
      co_return makeError(result.error().code(), "absence not confirmed; preserve the same claim and use a new archive");
    co_return Dispatcher::OutputTable{{serde::toJsonString(observation)}};
  } catch (...) {
    co_return makeError(invoked ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
}  // namespace
CoTryTask<void> registerEcGcHandlers(Dispatcher &dispatcher) {
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-gc-collect"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, true); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-gc-query"); },
      [](IEnv &env, const auto &parser, const auto &args) { return handle(env, parser, args, false); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-gc-confirm-absent", true); },
      [](IEnv &env, const auto &parser, const auto &args) { return handleAbsent(env, parser, args, true); }));
  CO_RETURN_ON_ERROR(co_await dispatcher.registerHandler(
      [] { return parserFor("ec-gc-query-absent", true); },
      [](IEnv &env, const auto &parser, const auto &args) { return handleAbsent(env, parser, args, false); }));
  co_return Void{};
}
}  // namespace hf3fs::client::cli
