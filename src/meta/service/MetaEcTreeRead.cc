#include "meta/store/EcTerminalEvidence.h"
#include <algorithm>
#include <folly/experimental/coro/Sleep.h>
#include <new>

#include "meta/service/MetaOperator.h"
#include "meta/store/EcFileTreeReadCatalog.h"

namespace hf3fs::meta::server {
namespace {
using Catalog = EcFileTreeReadCatalog;
template <typename R, typename Fn>
CoTryTask<R> treeReadTransaction(std::shared_ptr<kv::IKVEngine> engine, Fn fn, bool commit = true) {
  bool commitStarted = false;
  try {
    auto inner = engine->createReadWriteTransaction();
    if (!inner) co_return makeError(StatusCode::kKVStoreNotFound);
    Catalog::Tx txn(*inner, Catalog::transactionProfile());
    auto value = co_await fn(txn);
    CO_RETURN_ON_ERROR(value);
    if (commit) {
      commitStarted = true;
      CO_RETURN_ON_ERROR(co_await txn.commit());
    }
    co_return std::move(*value);
  } catch (const std::bad_alloc &) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kNotEnoughMemory);
  } catch (...) {
    co_return makeError(commitStarted ? TransactionCode::kMaybeCommitted : StatusCode::kIOError);
  }
}
EcTreeReadRsp response(EcTreeReadRecord record) {
  EcTreeReadRsp rsp;
  rsp.record = std::move(record);
  return rsp;
}
}  // namespace

CoTryTask<EcTreeReadRsp> MetaOperator::acquireEcTreeRead(AcquireEcTreeReadReq req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  CO_RETURN_ON_ERROR(ecV2Coordinator_->checkEnabled());
  // The wire owner is informational. Bind the actual effective authenticated
  // UID and client namespace exactly as the permanent file-session service.
  req.intent.owner = EcOwner{req.user.uid, req.client.uuid};
  auto work = [request = req](Catalog::Tx &txn) -> CoTryTask<EcTreeReadRsp> {
    if (!request.stripeIndex) {
      auto record = co_await Catalog::acquire(txn, request.intent);
      CO_RETURN_ON_ERROR(record);
      co_return response(std::move(*record));
    }
    auto record = co_await Catalog::query(txn, request.intent);
    CO_RETURN_ON_ERROR(record);
    auto evidence = co_await Catalog::reserveRead(txn, request.intent, *request.stripeIndex);
    CO_RETURN_ON_ERROR(evidence);
    const auto &source = evidence->record();
    auto rsp = response(std::move(*record));
    rsp.read.emplace();
    rsp.read->manifest = source.manifest;
    rsp.read->contentSha256 = source.intent.slot.contentSha256;
    rsp.read->snapshot = *rsp.record.stripes[*request.stripeIndex].snapshot;
    co_return rsp;
  };
  auto result =
      co_await folly::coro::co_withCancellation({}, treeReadTransaction<EcTreeReadRsp>(kvEngine_, std::move(work)));
  CO_RETURN_ON_ERROR(result);
  // Only successful durable issuance reservation can produce a bearer. A
  // delayed grant after T0 still meets the irreversible Storage scope deny.
  if (result->read) CO_RETURN_ON_ERROR(ecV2Coordinator_->addReadGrants(*result->read));
  co_return std::move(*result);
}

CoTryTask<EcTreeReadRsp> MetaOperator::queryEcTreeRead(QueryEcTreeReadReq req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  req.intent.owner = EcOwner{req.user.uid, req.client.uuid};
  auto value = co_await treeReadTransaction<EcTreeReadRecord>(
      kvEngine_,
      [intent = req.intent](Catalog::Tx &txn) { return Catalog::query(txn, intent); },
      false);
  CO_RETURN_ON_ERROR(value);
  co_return response(std::move(*value));
}

CoTryTask<EcTreeReadRsp> MetaOperator::releaseEcTreeRead(ReleaseEcTreeReadReq req) {
  CO_RETURN_ON_ERROR(req.valid());
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  CO_RETURN_ON_ERROR(ecV2Coordinator_->checkEnabled());
  req.intent.owner = EcOwner{req.user.uid, req.client.uuid};
  const auto authority = ecV2Coordinator_->authority();
  auto started = co_await folly::coro::co_withCancellation(
      {},
      treeReadTransaction<EcTreeReadRecord>(
          kvEngine_,
          [intent = req.intent, revocations = req.revocations, authority](Catalog::Tx &txn) {
            return Catalog::startClosing(txn, intent, authority, revocations);
          }));
  CO_RETURN_ON_ERROR(started);
  if (started->state == EcTreeReadState::Released) co_return response(std::move(*started));
  const auto deadline = SteadyClock::now() + config_.ec_v2_drain_timeout();
  for (size_t stripe = 0; stripe < started->stripeCount; ++stripe) {
    if (started->stripes[stripe].slot.kind == EcTreeSlotKind::Zero) continue;
    auto current = co_await treeReadTransaction<EcV2DrainRecord>(
        kvEngine_,
        [intent = req.intent, stripe](Catalog::Tx &txn) { return Catalog::closingSource(txn, intent, stripe); },
        false);
    CO_RETURN_ON_ERROR(current);
    std::array<bool, 24> revokeSent{};
    while (true) {
      for (size_t endpoint = 0; endpoint < current->identity.endpoints.count; ++endpoint) {
        if (ecTerminalAt(*current, endpoint)) continue;
        auto retired = co_await treeReadTransaction<EcV2DrainRecord>(kvEngine_,
            [intent = req.intent, stripe, endpoint, key = ecV2Coordinator_->sharedControlKey()](Catalog::Tx &txn) {
              return Catalog::recordRetirement(txn, intent, stripe, endpoint, *key);
            });
        CO_RETURN_ON_ERROR(retired);
        current = std::move(retired);
        if (ecTerminalAt(*current, endpoint)) continue;
        if (SteadyClock::now() >= deadline)
          co_return makeError(MetaCode::kOperationTimeout, "tree range remains Closing; retry its original identities");
        CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
        auto observed = co_await ecV2Coordinator_->observeDrain(
            *current,
            endpoint,
            revokeSent[endpoint] ? storage::EcScopeControlAction::Query : storage::EcScopeControlAction::Revoke);
        CO_RETURN_ON_ERROR(observed);
        revokeSent[endpoint] = true;
        if (!*observed) continue;
        CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
        const auto key = ecV2Coordinator_->sharedControlKey();
        auto saved = co_await folly::coro::co_withCancellation(
            {},
            treeReadTransaction<EcV2DrainRecord>(
                kvEngine_,
                [intent = req.intent, stripe, key, evidence = std::move(**observed)](Catalog::Tx &txn) {
                  return Catalog::recordVerifiedAck(txn, intent, stripe, *key, evidence);
                }));
        CO_RETURN_ON_ERROR(saved);
        current = std::move(saved);
      }
      if (ecAllTerminal(*current))
        break;
      if (SteadyClock::now() >= deadline)
        co_return makeError(MetaCode::kOperationTimeout, "tree source has pending storage readers");
      co_await folly::coro::sleep(config_.ec_v2_drain_poll_interval());
    }
  }
  CO_RETURN_ON_ERROR(co_await authenticateEcFileRange(req));
  auto key = ecV2Coordinator_->sharedControlKey();
  auto result = co_await folly::coro::co_withCancellation(
      {},
      treeReadTransaction<EcTreeReadRecord>(kvEngine_, [intent = req.intent, key](Catalog::Tx &txn) {
        return Catalog::finishRelease(txn, intent, *key);
      }));
  CO_RETURN_ON_ERROR(result);
  co_return response(std::move(*result));
}
}  // namespace hf3fs::meta::server
