#include "EcRmwPublicationVerifier.h"

#include <folly/ScopeGuard.h>

#include "fbs/storage/EcStageValidationV2.h"
#include "storage/ec_codec/EcCodec.h"

namespace hf3fs::meta::server {
namespace {
using namespace storage;
using Control = storage::client::EcRequestControl;
Result<Void> ready(const Control &c) {
  if (c.transport != Control::TransportPolicy::TcpOnly || c.deadline == std::chrono::steady_clock::time_point::max())
    return makeError(StatusCode::kInvalidArg);
  if (c.cancellation.isCancellationRequested()) return makeError(StorageClientCode::kRequestCanceled);
  if (std::chrono::steady_clock::now() >= c.deadline) return makeError(StorageClientCode::kTimeout);
  return Void{};
}
EcFragmentAccessV2 access(const EcV2AllocationBinding &a, VersionedChainId route) {
  EcFragmentAccessV2 r;
  r.identity = a.fragment.identity;
  r.operationId = a.fragment.operation;
  r.integrity = a.fragment.integrity;
  r.targetId = a.fragment.placement.target;
  r.vChainId = route;
  return r;
}
}  // namespace
struct EcRmwPublicationVerifier::State {
  Config config;
  std::shared_ptr<kv::IKVEngine> db;
  std::shared_ptr<EcRmwPlanIssuer> issuer;
  std::shared_ptr<storage::client::StorageClient> storage;
  std::shared_ptr<const storage::EcScopeControlKey> controlKey;
  // One verification, charged as a whole 64MiB application reservation.
  // Before logical allocation: 12*S C++ bytes + bridge/Rust input and
  // verification codeword copies (at most 3 additional 12*S buffers).
  // After verify returns: 12*S bytes + <=10*S logical. S<=1MiB; requests
  // are sequential <=64KiB blocks. This is not an allocator/RSS guarantee.
  std::atomic_flag active{};
};
Result<std::shared_ptr<EcRmwPublicationVerifier>> EcRmwPublicationVerifier::create(
    Config c,
    std::shared_ptr<kv::IKVEngine> db,
    std::shared_ptr<EcRmwPlanIssuer> issuer,
    std::shared_ptr<storage::client::StorageClient> storage,
    std::shared_ptr<const EcScopeControlKey> key) {
  if (!db || !issuer || !storage || !key || !key->fileIdentity() || c.authority.is_nil() || !c.now || !c.route)
    return makeError(StatusCode::kInvalidConfig);
  auto s = std::make_shared<State>();
  s->config = std::move(c);
  s->db = std::move(db);
  s->issuer = std::move(issuer);
  s->storage = std::move(storage);
  s->controlKey = std::move(key);
  return std::shared_ptr<EcRmwPublicationVerifier>(new EcRmwPublicationVerifier(std::move(s)));
}
CoTryTask<std::shared_ptr<const EcRmwPublicationProof>> EcRmwPublicationVerifier::verify(EcObjectRef object,
                                                                                         EcOwner owner,
                                                                                         Uuid child,
                                                                                         Control control) const {
  return run(state_, object, owner, child, std::move(control));
}
// Direct propagation avoids formatting a code-only unknown/OOM result.
#define RMW_TRY(expr)                                    \
  do {                                                   \
    auto &&r_ = (expr);                                  \
    if (!r_) co_return makeError(std::move(r_.error())); \
  } while (false)
CoTryTask<std::shared_ptr<const EcRmwPublicationProof>> EcRmwPublicationVerifier::run(std::shared_ptr<State> s,
                                                                                      EcObjectRef object,
                                                                                      EcOwner owner,
                                                                                      Uuid child,
                                                                                      Control control) {
  RMW_TRY(ready(control));
  if (s->active.test_and_set()) co_return makeError(StorageClientCode::kResourceBusy);
  auto release = folly::makeGuard([&] { s->active.clear(); });
  bool irreversible = false;
  try {
    auto raw = s->db->createReadWriteTransaction();
    if (!raw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget tx(*raw, EcFileTreeTxnBudget::Profile::Rmw);
    auto initial = co_await EcFileExecutionCatalog::get(tx, owner, object, child);
    RMW_TRY(initial);
    RMW_TRY(co_await tx.commit());
    auto observed = std::move(*initial);
    if (observed.record.state == EcFileExecutionState::Bound) {
      auto issued = co_await s->issuer->issue(object, owner, child);
      RMW_TRY(issued);
      observed = std::move(issued->observed);
      if (!observed.record.allocations || !issued->writes) co_return makeError(StatusCode::kDataCorruption);
      const auto &p = observed.plan->input();
      EcManifest manifest;
      manifest.object = object;
      manifest.stripe = p.stripe;
      manifest.generation = p.targetGeneration;
      manifest.revision = p.targetRevision;
      manifest.logicalLength = p.targetLogicalLength;
      EcCodec::Shards bytes;
      std::array<EcCodecShardView, 12> views;
      for (size_t i = 0; i < 12; ++i) {
        const auto &a = (*observed.record.allocations)[i];
        manifest.fragments[i] = a.fragment;
        bytes[i].reserve(p.shardBytes);
        for (uint32_t block = 0; block < a.fragment.integrity.blockCount; ++block) {
          RMW_TRY(ready(control));
          auto route = s->config.route(a.endpoint());
          RMW_TRY(route);
          EcReadBlockV2Req req;
          req.request = access(a, *route);
          req.grant = (*issued->writes)[i];
          req.blockIndex = block;
          auto read = co_await s->storage->readEcBlockV2Controlled(req, control);
          RMW_TRY(read);
          RMW_TRY(validateEcReadBlockV2(*read, req));
          bytes[i] += read->payload.data;
        }
        auto integrity = computeEcIntegrity(a.fragment.identity, bytes[i]);
        RMW_TRY(integrity);
        if (*integrity != a.fragment.integrity) co_return makeError(StatusCode::kDataCorruption);
        views[i] = {uint16_t(i), bytes[i]};
      }
      RMW_TRY(EcCodec::verify(views, p.targetLogicalLength, p.shardBytes));
      std::string logical;
      logical.reserve(p.targetLogicalLength);
      for (size_t i = 0; i < 10 && logical.size() < p.targetLogicalLength; ++i)
        logical.append(bytes[i].data(), std::min<size_t>(bytes[i].size(), p.targetLogicalLength - logical.size()));
      auto hash = ec_rmw_detail::sha256(logical);
      RMW_TRY(hash);
      if (*hash != observed.record.contentSha256) co_return makeError(StatusCode::kDataCorruption);
      // Seal actual twelve immutable bindings, never trust the worker receipts.
      for (size_t i = 0; i < 12; ++i) {
        RMW_TRY(ready(control));
        const auto &a = (*observed.record.allocations)[i];
        auto route = s->config.route(a.endpoint());
        RMW_TRY(route);
        EcSealStageV2Req req;
        req.request = access(a, *route);
        req.grant = (*issued->writes)[i];
        irreversible = true;
        auto sealed = co_await s->storage->sealEcStageV2Controlled(req, control);
        RMW_TRY(sealed);
        RMW_TRY(validateEcReceiptV2(*sealed, req.request, req.grant.claims));
      }
      RMW_TRY(ready(control));
      auto closingRaw = s->db->createReadWriteTransaction();
      if (!closingRaw) co_return makeError(StatusCode::kKVStoreNotFound);
      EcFileTreeTxnBudget closing(*closingRaw, EcFileTreeTxnBudget::Profile::Rmw);
      // The private catalog entry rechecks live child/root/epoch and immutable
      // binding in this transaction before permanently closing issuance.
      auto drain = co_await EcFileExecutionCatalog::startPublishClosing(closing,
                                                                        owner,
                                                                        object,
                                                                        child,
                                                                        manifest,
                                                                        *hash,
                                                                        s->config.authority,
                                                                        Uuid::random());
      RMW_TRY(drain);
      RMW_TRY(co_await closing.commit());
      observed.record.drain = std::move(*drain);
      observed.record.state = EcFileExecutionState::Closing;
    }
    if (!observed.record.drain || observed.record.drain->version != kEcV2LifecycleVersion ||
        !observed.record.drain->verifiedManifest || !observed.record.allocations)
      co_return makeError(StatusCode::kTokenStale);
    irreversible = true;
    if (observed.record.state == EcFileExecutionState::Closing) {
      const auto record = *observed.record.drain;
      if (observed.record.ownerKind == EcFileExecutionOwner::Repair
              ? (record.identity.endpoints.count < 12 || record.identity.endpoints.count > 22)
              : record.identity.endpoints.count != 12)
        co_return makeError(StatusCode::kDataCorruption);
      for (size_t i = 0; i < record.identity.endpoints.count; ++i) {
        if (record.observations[i]) continue;
        RMW_TRY(ready(control));
        auto request =
            EcV2DrainCatalog::makeRequest(record, i, EcScopeControlAction::Revoke, *s->controlKey, s->config.now());
        RMW_TRY(request);
        // Existing control transport has its own finite TCP timer. Its owned
        // request must complete even when the outer caller cancels/expires.
        auto ack = co_await s->storage->revokeEcScope(*request);
        RMW_TRY(ack);
        RMW_TRY(verifyEcScopeControlAck(*s->controlKey, *ack, *request));
        if (ack->claims.state != EcScopeControlState::Drained) co_return makeError(StorageClientCode::kResourceBusy);
        auto ackRaw = s->db->createReadWriteTransaction();
        if (!ackRaw) co_return makeError(StatusCode::kKVStoreNotFound);
        EcFileTreeTxnBudget ackTx(*ackRaw, EcFileTreeTxnBudget::Profile::Rmw);
        auto persisted =
            co_await EcFileExecutionCatalog::recordAck(ackTx, owner, object, child, i, *s->controlKey, *request, *ack);
        RMW_TRY(persisted);
        RMW_TRY(co_await ackTx.commit());
      }
    }
    RMW_TRY(ready(control));
    auto finalRaw = s->db->createReadWriteTransaction();
    if (!finalRaw) co_return makeError(StatusCode::kKVStoreNotFound);
    EcFileTreeTxnBudget finalTx(*finalRaw, EcFileTreeTxnBudget::Profile::Rmw);
    auto finished = co_await EcFileExecutionCatalog::finishDrain(finalTx, owner, object, child, *s->controlKey);
    RMW_TRY(finished);
    RMW_TRY(co_await finalTx.commit());
    const auto &record = finished->record;
    if ((record.state != EcFileExecutionState::Drained && record.state != EcFileExecutionState::Published) ||
        !record.drain || record.drain->version != kEcV2LifecycleVersion ||
        !record.allocations || !record.drain->verifiedManifest ||
        (record.state == EcFileExecutionState::Drained && record.drain->state != EcV2DrainState::Closing) ||
        (record.state == EcFileExecutionState::Published && record.drain->state != EcV2DrainState::Published) ||
        record.drain->verifiedContentSha256 != record.contentSha256)
      co_return makeError(StatusCode::kDataCorruption);
    co_return std::shared_ptr<const EcRmwPublicationProof>(
        new EcRmwPublicationProof(finished->plan, *record.drain->verifiedManifest, *record.allocations, *record.drain));
  } catch (const std::bad_alloc &) {
    co_return makeError(irreversible ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(irreversible ? StorageCode::kEcSealOutcomeUnknown : StatusCode::kIOError);
  }
}
#undef RMW_TRY
}  // namespace hf3fs::meta::server
