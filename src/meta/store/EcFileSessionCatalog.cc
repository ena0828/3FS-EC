#include "EcFileSessionCatalog.h"

#include <limits>
#include <linux/fs.h>

#include "EcFileLifecycleCatalog.h"
#include "Inode.h"
#include "common/kv/ITransaction.h"
#include "detail/EcFileMutationKeys.h"
#include "fbs/meta/Service.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_file_mutation_detail;
using kv::KeyPrefix;
using Tx = EcFileTreeTxnBudget;
struct ExistingOpenRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  // Binary serialization of sanitized semantic request, not a token or readable JSON.
  SERDE_STRUCT_FIELD(input, std::string{});
  SERDE_STRUCT_FIELD(resolved, EcFileOpenIntent{});
};
std::string originalOpen(const OpenEcFileSessionReq &req, const flat::UserInfo &authenticated) {
  auto input = req;
  input.user = authenticated;
  input.user.token.clear();
  input.forward = flat::NodeId{};
  // A client restart may change diagnostic hostname, but not its namespace.
  input.client.hostname.clear();
  const auto bytes = serde::serialize(input);
  return std::string(std::string_view(bytes));
}
CoTryTask<Inode> inodeFor(Tx &txn,
                          const EcTreeBirth &birth,
                          const EcTreeRoot &root,
                          uint8_t rights,
                          bool acceptedSession = false) {
  auto found = co_await Inode::load(txn, birth.object.inode);
  CO_RETURN_ON_ERROR(found);
  if (!*found) co_return makeError(MetaCode::kNotFound);
  if (!(**found).nlink) {
    if (!acceptedSession) co_return makeError(MetaCode::kNotFound);
    CO_RETURN_ON_ERROR(co_await EcFileLifecycleCatalog::requireUnlinkedSession(txn, birth.object));
  }
  auto inode = std::move(**found);
  if (!inode.isFile()) co_return makeError(MetaCode::kNotFile);
  const auto *layout = inode.asFile().layout.ecLayout();
  if (!layout || layout->incarnation != birth.object.incarnation || layout->shardBytes != birth.shardBytes ||
      inode.asFile().length != root.visibleLength)
    co_return makeError(StatusCode::kDataCorruption, "mode-4 inode/tree identity or length differs");
  CO_RETURN_ON_ERROR(layout->valid());
  if ((rights & kEcSessionWrite) && (inode.acl.iflags & FS_IMMUTABLE_FL))
    co_return makeError(MetaCode::kNoPermission, "immutable file cannot accept writes");
  co_return inode;
}
CoTryTask<EcFileSessionIndex> index(Tx &txn, const EcTreeBirth &birth, bool initialize) {
  const auto key = objectKey(KeyPrefix::EcFileSessionIndex, birth.object);
  auto old = co_await load<EcFileSessionIndex>(txn, key);
  CO_RETURN_ON_ERROR(old);
  if (*old) {
    if ((**old).object != birth.object || (**old).birth != birth.createRequest)
      co_return makeError(StatusCode::kDataCorruption, "file-session index changed birth");
    co_return **old;
  }
  if (!initialize) co_return makeError(StatusCode::kDataCorruption, "missing file-session index");
  // A lost index cannot be reconstructed as zero from a cache miss. Conflict-
  // read each complete namespace before initializing a previously unused birth.
  for (auto prefix : {KeyPrefix::EcFileOpenRequest,
                      KeyPrefix::EcFileSession,
                      KeyPrefix::EcFileMutation,
                      KeyPrefix::EcFileMutationChild}) {
    auto first = objectKey(prefix, birth.object);
    auto rows = co_await txn.getRange({first, true}, {kv::TransactionHelper::prefixListEndKey(first), false}, 1);
    CO_RETURN_ON_ERROR(rows);
    if (!rows->kvs.empty() || rows->hasMore)
      co_return makeError(StatusCode::kDataCorruption, "session index missing beneath permanent history");
  }
  EcFileSessionIndex result;
  result.object = birth.object;
  result.birth = birth.createRequest;
  co_return result;
}
}  // namespace

CoTryTask<EcFileSessionRecord> EcFileSessionCatalog::openExisting(Tx &txn,
                                                                  const flat::UserInfo &authenticated,
                                                                  const OpenEcFileSessionReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  if (req.createNew || authenticated.uid != req.user.uid) co_return makeError(MetaCode::kNoPermission);
  const auto input = originalOpen(req, authenticated);
  std::string key(kv::toStr(KeyPrefix::EcFileOriginalOpen));
  key.append(req.client.uuid.asStringView());
  key.append(req.uuid.asStringView());
  auto old = co_await load<ExistingOpenRecord>(txn, key);
  CO_RETURN_ON_ERROR(old);
  EcFileOpenIntent intent;
  intent.object = req.object;
  intent.birth = req.birth;
  intent.owner = {authenticated.uid, req.client.uuid};
  intent.session = req.session;
  intent.openRequest = req.uuid;
  intent.rights = req.rights;
  if (*old) {
    if ((**old).input != input)
      co_return makeError(StatusCode::kTokenMismatch, "existing-open original request changed");
    intent.birth = (**old).resolved.birth;
    if (!same(intent, (**old).resolved))
      co_return makeError(StatusCode::kDataCorruption, "existing-open resolved intent changed");
    auto historical = co_await get(txn, intent.object, intent.session, intent.owner);
    CO_RETURN_ON_ERROR(historical);
    if (!same(historical->intent, intent))
      co_return makeError(StatusCode::kDataCorruption, "original open lost matching session history");
    co_return historical;
  }
  if (req.resolveBirth) {
    // Do not reconstruct a missing original request from a surviving session.
    auto prior = co_await load<EcFileSessionRecord>(txn, idKey(KeyPrefix::EcFileSession, req.object, req.session));
    CO_RETURN_ON_ERROR(prior);
    auto request = co_await load<EcFileOpenIntent>(txn, idKey(KeyPrefix::EcFileOpenRequest, req.object, req.uuid));
    CO_RETURN_ON_ERROR(request);
    if (*prior || *request)
      co_return makeError(StatusCode::kTokenMismatch, "birth resolution lacks original request history");
    auto birth = co_await EcFileTreeCatalog::getBirth(txn, req.object);
    CO_RETURN_ON_ERROR(birth);
    intent.birth = birth->createRequest;
  }
  auto result = co_await open(txn, authenticated, intent);
  CO_RETURN_ON_ERROR(result);
  ExistingOpenRecord record;
  record.input = input;
  record.resolved = intent;
  CO_RETURN_ON_ERROR(co_await store(txn, key, record));
  co_return result;
}

CoTryTask<EcFileSessionRecord> EcFileSessionCatalog::open(Tx &txn,
                                                          const flat::UserInfo &authenticated,
                                                          const EcFileOpenIntent &intent) {
  CO_RETURN_ON_ERROR(valid(intent));
  if (authenticated.uid != intent.owner.uid) co_return makeError(MetaCode::kNoPermission);
  auto birth = co_await EcFileTreeCatalog::getBirth(txn, intent.object);
  CO_RETURN_ON_ERROR(birth);
  if (birth->createRequest != intent.birth) co_return makeError(StatusCode::kTokenMismatch, "open birth changed");
  const auto key = idKey(KeyPrefix::EcFileSession, intent.object, intent.session);
  const auto requestKey = idKey(KeyPrefix::EcFileOpenRequest, intent.object, intent.openRequest);
  auto request = co_await load<EcFileOpenIntent>(txn, requestKey);
  CO_RETURN_ON_ERROR(request);
  if (*request && !same(**request, intent))
    co_return makeError(StatusCode::kTokenMismatch, "open request changed session or rights");
  auto prior = co_await load<EcFileSessionRecord>(txn, key);
  CO_RETURN_ON_ERROR(prior);
  if (*prior) {
    CO_RETURN_ON_ERROR(valid(**prior));
    if (!same((**prior).intent, intent))
      co_return makeError(StatusCode::kTokenMismatch, "session retry changed intent");
    if (!*request) co_return makeError(StatusCode::kDataCorruption, "session lost its permanent open request");
    auto count = co_await index(txn, *birth, false);
    CO_RETURN_ON_ERROR(count);
    if ((**prior).state != EcFileSessionState::Closed && !count->openCount)
      co_return makeError(StatusCode::kDataCorruption, "live session lost its count");
    co_return **prior;
  }
  if (*request) co_return makeError(StatusCode::kDataCorruption, "open request lost its session");
  auto context = co_await EcFileTreeCatalog::open(txn, intent.object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  auto inode = co_await inodeFor(txn, context->birth(), *root, intent.rights);
  CO_RETURN_ON_ERROR(inode);
  if (intent.rights & kEcSessionRead) CO_RETURN_ON_ERROR(inode->acl.checkPermission(authenticated, AccessType::READ));
  if (intent.rights & kEcSessionWrite) CO_RETURN_ON_ERROR(inode->acl.checkPermission(authenticated, AccessType::WRITE));
  auto count = co_await index(txn, context->birth(), true);
  CO_RETURN_ON_ERROR(count);
  if (count->openCount == std::numeric_limits<uint64_t>::max()) co_return makeError(StorageClientCode::kResourceBusy);
  ++count->openCount;
  EcFileSessionRecord result;
  result.intent = intent;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileSessionIndex, intent.object), *count));
  CO_RETURN_ON_ERROR(co_await store(txn, requestKey, intent));
  CO_RETURN_ON_ERROR(co_await store(txn, key, result));
  co_return result;
}

CoTryTask<EcFileSessionRecord> EcFileSessionCatalog::get(Tx &txn,
                                                         const EcObjectRef &object,
                                                         const Uuid &session,
                                                         const EcOwner &actual) {
  if (session.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto birth = co_await EcFileTreeCatalog::getBirth(txn, object);
  CO_RETURN_ON_ERROR(birth);
  auto r = co_await load<EcFileSessionRecord>(txn, idKey(KeyPrefix::EcFileSession, object, session));
  CO_RETURN_ON_ERROR(r);
  if (!*r) co_return makeError(MetaCode::kNotFound, "file session missing; not a completion proof");
  CO_RETURN_ON_ERROR(valid(**r));
  CO_RETURN_ON_ERROR(owner((**r).intent.owner, actual));
  if ((**r).intent.object != object || (**r).intent.session != session || (**r).intent.birth != birth->createRequest)
    co_return makeError(StatusCode::kDataCorruption, "file session key/birth mismatch");
  auto request =
      co_await load<EcFileOpenIntent>(txn, idKey(KeyPrefix::EcFileOpenRequest, object, (**r).intent.openRequest));
  CO_RETURN_ON_ERROR(request);
  if (!*request || !same(**request, (**r).intent))
    co_return makeError(StatusCode::kDataCorruption, "file session lost open request");
  auto count = co_await index(txn, *birth, false);
  CO_RETURN_ON_ERROR(count);
  if ((**r).state != EcFileSessionState::Closed && !count->openCount)
    co_return makeError(StatusCode::kDataCorruption, "live session count is zero");
  co_return std::move(**r);
}

CoTryTask<EcFileSessionRecord> EcFileSessionCatalog::require(Tx &txn,
                                                             const EcObjectRef &object,
                                                             const Uuid &session,
                                                             const EcOwner &actual,
                                                             uint8_t rights,
                                                             bool allowClosing) {
  auto r = co_await get(txn, object, session, actual);
  CO_RETURN_ON_ERROR(r);
  if (r->state == EcFileSessionState::Closed || (!allowClosing && r->state != EcFileSessionState::Open))
    co_return makeError(StatusCode::kTokenStale, "session is closing or closed");
  if ((r->intent.rights & rights) != rights)
    co_return makeError(MetaCode::kNoPermission, "session lacks accepted rights");
  auto context = co_await EcFileTreeCatalog::open(txn, object);
  CO_RETURN_ON_ERROR(context);
  auto root = co_await EcFileTreeCatalog::getRoot(*context);
  CO_RETURN_ON_ERROR(root);
  auto inode = co_await inodeFor(txn, context->birth(), *root, rights, true);
  CO_RETURN_ON_ERROR(inode);
  // chmod does not rewrite already-open rights. Immutable and incarnation are
  // still enforced, and authenticated ownership is checked on every request.
  co_return r;
}

CoTryTask<EcFileSessionRecord> EcFileSessionCatalog::close(Tx &txn,
                                                           const EcObjectRef &object,
                                                           const Uuid &session,
                                                           const EcOwner &actual) {
  auto r = co_await get(txn, object, session, actual);
  CO_RETURN_ON_ERROR(r);
  if (r->state == EcFileSessionState::Closed) co_return r;
  r->state = EcFileSessionState::Closing;
  if (r->activeParent.is_nil() && !r->activeReadRanges && r->activeStructural.is_nil()) {
    auto birth = co_await EcFileTreeCatalog::getBirth(txn, object);
    CO_RETURN_ON_ERROR(birth);
    auto count = co_await index(txn, *birth, false);
    CO_RETURN_ON_ERROR(count);
    if (!count->openCount) co_return makeError(StatusCode::kDataCorruption);
    --count->openCount;
    r->state = EcFileSessionState::Closed;
    CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcFileSessionIndex, object), *count));
  }
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileSession, object, session), *r));
  if (r->state == EcFileSessionState::Closed)
    CO_RETURN_ON_ERROR(co_await EcFileLifecycleCatalog::retireIfUnreferenced(txn, object));
  co_return r;
}

CoTryTask<Void> EcFileSessionCatalog::retainReadRange(Tx &txn,
                                                      const EcObjectRef &object,
                                                      const Uuid &session,
                                                      const EcOwner &actual) {
  auto r = co_await require(txn, object, session, actual, kEcSessionRead, false);
  CO_RETURN_ON_ERROR(r);
  if (r->activeReadRanges == std::numeric_limits<uint64_t>::max())
    co_return makeError(StorageClientCode::kResourceBusy);
  ++r->activeReadRanges;
  co_return co_await store(txn, idKey(KeyPrefix::EcFileSession, object, session), *r);
}
CoTryTask<Void> EcFileSessionCatalog::releaseReadRange(Tx &txn,
                                                       const EcObjectRef &object,
                                                       const Uuid &session,
                                                       const EcOwner &actual) {
  auto r = co_await get(txn, object, session, actual);
  CO_RETURN_ON_ERROR(r);
  if (!r->activeReadRanges || r->state == EcFileSessionState::Closed)
    co_return makeError(StatusCode::kDataCorruption, "session read-range accounting underflow");
  --r->activeReadRanges;
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileSession, object, session), *r));
  if (r->state == EcFileSessionState::Closing && r->activeParent.is_nil() && !r->activeReadRanges &&
      r->activeStructural.is_nil())
    CO_RETURN_ON_ERROR(co_await close(txn, object, session, actual));
  co_return Void{};
}
CoTryTask<Void> EcFileSessionCatalog::retainStructural(Tx &txn,
                                                       const EcObjectRef &object,
                                                       const Uuid &session,
                                                       const EcOwner &actual,
                                                       const Uuid &operation) {
  if (operation.is_nil()) co_return makeError(StatusCode::kInvalidArg);
  auto r = co_await require(txn, object, session, actual, kEcSessionWrite, false);
  CO_RETURN_ON_ERROR(r);
  if (!r->activeStructural.is_nil())
    co_return makeError(StorageClientCode::kResourceBusy, "session already owns a structural operation");
  r->activeStructural = operation;
  co_return co_await store(txn, idKey(KeyPrefix::EcFileSession, object, session), *r);
}
CoTryTask<Void> EcFileSessionCatalog::releaseStructural(Tx &txn,
                                                        const EcObjectRef &object,
                                                        const Uuid &session,
                                                        const EcOwner &actual,
                                                        const Uuid &operation) {
  auto r = co_await get(txn, object, session, actual);
  CO_RETURN_ON_ERROR(r);
  if (operation.is_nil() || r->activeStructural != operation || r->state == EcFileSessionState::Closed)
    co_return makeError(StatusCode::kDataCorruption, "structural session ownership differs");
  r->activeStructural = Uuid::zero();
  CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcFileSession, object, session), *r));
  if (r->state == EcFileSessionState::Closing && r->activeParent.is_nil() && !r->activeReadRanges)
    CO_RETURN_ON_ERROR(co_await close(txn, object, session, actual));
  co_return Void{};
}
}  // namespace hf3fs::meta::server
