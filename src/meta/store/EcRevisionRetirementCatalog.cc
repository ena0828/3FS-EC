#include "EcRevisionRetirementCatalog.h"

#include "common/kv/KeyPrefix.h"
#include "common/utils/SerDeser.h"
#include "meta/store/EcCatalog.h"
#include "meta/store/EcV2GcCatalog.h"

namespace hf3fs::meta::server {
namespace {
struct RetirementRecord {
  SERDE_STRUCT_FIELD(version, uint16_t{1});
  SERDE_STRUCT_FIELD(result, EcRevisionRetirementRsp{});
};

std::string key(const EcRevisionRetirementReq &req) {
  // No object in this key: reusing the same namespace/request ID for another
  // object must conflict instead of silently creating an independent record.
  return Serializer::serRawArgs(kv::KeyPrefix::EcRevisionRetirement, req.uuid, req.client.uuid);
}

CoTryTask<EcManifestRecord> loadHistorical(kv::IReadWriteTransaction &txn, const EcRevisionRetirementReq &req) {
  auto mode = co_await EcV2BindingCatalog::requireV2Mode(txn, req.object);
  CO_RETURN_ON_ERROR(mode);
  if (mode->mode != kEcGcTrackedObjectMode)
    co_return makeError(StatusCode::kNotImplemented, "retirement requires GC tracking since object creation");
  // requireV2Mode also checks the object creator and permanent enrollment.
  CO_RETURN_ON_ERROR(co_await EcV2GcCatalog::validateEnrollment(txn, *mode));
  auto record = co_await EcCatalog::getManifest(txn, req.object, req.stripe, req.revision);
  CO_RETURN_ON_ERROR(record);
  if (record->manifest.object != req.object || record->manifest.stripe != req.stripe ||
      record->manifest.revision != req.revision || !record->manifest.generation)
    co_return makeError(StatusCode::kDataCorruption, "retirement manifest identity differs");
  co_return *record;
}

CoTryTask<std::optional<EcRevisionRetirementRsp>> previous(kv::IReadWriteTransaction &txn,
                                                           const EcRevisionRetirementReq &req) {
  auto bytes = co_await txn.get(key(req));
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  RetirementRecord record;
  CO_RETURN_ON_ERROR(serde::deserialize(record, **bytes));
  const auto &rsp = record.result;
  if (record.version != 1 || !rsp.referencesReleased || !rsp.generation || !rsp.revision ||
      rsp.clientNamespace != req.client.uuid || rsp.requestId != req.uuid)
    co_return makeError(StatusCode::kDataCorruption, "invalid permanent retirement completion");
  if (rsp.object != req.object || rsp.stripe != req.stripe || rsp.revision != req.revision)
    co_return makeError(StatusCode::kTokenMismatch, "retirement request ID reused with different revision identity");
  auto manifest = co_await loadHistorical(txn, req);
  CO_RETURN_ON_ERROR(manifest);
  if (!manifest->retired || !manifest->referencesReleased || manifest->pins ||
      manifest->manifest.generation != rsp.generation)
    co_return makeError(StatusCode::kDataCorruption, "retirement completion disagrees with historical manifest");
  co_return std::optional<EcRevisionRetirementRsp>{rsp};
}
}  // namespace

CoTryTask<EcRevisionRetirementRsp> EcRevisionRetirementCatalog::retire(kv::IReadWriteTransaction &txn,
                                                                       const EcRevisionRetirementReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  auto old = co_await previous(txn, req);
  CO_RETURN_ON_ERROR(old);
  if (*old) co_return **old;
  auto historical = co_await loadHistorical(txn, req);
  CO_RETURN_ON_ERROR(historical);
  // The existing core rejects current heads and nonzero pins and decrements
  // each shared fragment reference exactly once in this same transaction.
  CO_RETURN_ON_ERROR(co_await EcCatalog::retireRevision(txn, req.object, req.stripe, req.revision));
  auto observed = co_await EcCatalog::getManifest(txn, req.object, req.stripe, req.revision);
  CO_RETURN_ON_ERROR(observed);
  if (!observed->referencesReleased || !observed->retired || observed->pins)
    co_return makeError(StatusCode::kDataCorruption, "retirement did not produce a terminal manifest");
  RetirementRecord record;
  auto &rsp = record.result;
  rsp.object = req.object;
  rsp.stripe = req.stripe;
  rsp.revision = req.revision;
  rsp.generation = historical->manifest.generation;
  rsp.clientNamespace = req.client.uuid;
  rsp.requestId = req.uuid;
  rsp.referencesReleased = true;
  CO_RETURN_ON_ERROR(co_await txn.set(key(req), serde::serialize(record)));
  co_return rsp;
}

CoTryTask<EcRevisionRetirementRsp> EcRevisionRetirementCatalog::query(kv::IReadWriteTransaction &txn,
                                                                      const EcRevisionRetirementReq &req) {
  CO_RETURN_ON_ERROR(req.valid());
  auto old = co_await previous(txn, req);
  CO_RETURN_ON_ERROR(old);
  if (!*old) {
    auto historical = co_await loadHistorical(txn, req);
    CO_RETURN_ON_ERROR(historical);
    co_return makeError(StatusCode::kKVStoreNotFound, "no retirement completion observed for this identity");
  }
  co_return **old;
}

}  // namespace hf3fs::meta::server
