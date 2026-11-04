#include "meta/store/EcV2PublishedCatalog.h"

#include "meta/store/EcV2LifecycleUtils.h"

namespace hf3fs::meta::server {
namespace {
using namespace ec_v2_lifecycle;
std::string contentKey(const EcObjectRef &object, uint64_t stripe, uint64_t revision) {
  std::string key(kv::toStr(kv::KeyPrefix::EcV2PublishedContent));
  key.append(object.incarnation.asStringView());
  for (auto number : {stripe, revision})
    for (int shift = 56; shift >= 0; shift -= 8) key.push_back(static_cast<char>(number >> shift));
  return key;
}
CoTryTask<EcV2PublishedContent> completed(kv::IReadWriteTransaction &txn,
                                          const EcObjectRef &object,
                                          const Uuid &operation,
                                          const EcOwner &owner) {
  auto op = co_await EcCatalog::getOperation(txn, object, operation);
  CO_RETURN_ON_ERROR(op);
  CO_RETURN_ON_ERROR(ownerMatches(op->owner, owner));
  auto drain = co_await EcV2DrainCatalog::get(txn, object, storage::EcGrantScope::WriteOperation, operation, owner);
  CO_RETURN_ON_ERROR(drain);
  if (!*drain || (**drain).state != EcV2DrainState::Published || !(**drain).verifiedManifest ||
      op->state != EcOperationState::Published || op->candidate != *(**drain).verifiedManifest)
    co_return makeError(StatusCode::kTokenStale, "V2 publication provenance requires a completed T2");
  auto reservation = co_await EcV2ReservationCatalog::get(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(reservation);
  if ((**drain).verifiedContentSha256 != reservation->contentSha256)
    co_return makeError(StatusCode::kDataCorruption, "V2 publication SHA differs from its durable proof");
  auto manifest = co_await EcCatalog::getManifest(txn, object, op->candidate.stripe, op->candidate.revision);
  CO_RETURN_ON_ERROR(manifest);
  if (manifest->manifest != op->candidate) co_return makeError(StatusCode::kDataCorruption);
  EcV2PublishedContent out;
  out.object = object;
  out.stripe = op->candidate.stripe;
  out.revision = op->candidate.revision;
  out.generation = op->candidate.generation;
  out.logicalLength = op->candidate.logicalLength;
  out.operation = operation;
  out.owner = owner;
  out.contentSha256 = reservation->contentSha256;
  co_return out;
}
}  // namespace
CoTryTask<EcV2PublishedContent> EcV2PublishedCatalog::get(Transaction &txn,
                                                          const EcObjectRef &object,
                                                          uint64_t stripe,
                                                          uint64_t revision) {
  CO_RETURN_ON_ERROR(co_await EcV2BindingCatalog::requireV2Mode(txn, object));
  auto stored = co_await load<EcV2PublishedContent>(txn, contentKey(object, stripe, revision));
  CO_RETURN_ON_ERROR(stored);
  if (!*stored)
    co_return makeError(StatusCode::kNotImplemented, "V2 historical revision has no publication provenance");
  const auto &value = **stored;
  if (value.object != object || value.stripe != stripe || value.revision != revision || !revision ||
      !value.generation || !value.logicalLength || value.operation.is_nil() ||
      value.contentSha256 == storage::EcSha256{})
    co_return makeError(StatusCode::kDataCorruption, "invalid V2 historical content key or record");
  auto expected = co_await completed(txn, object, value.operation, value.owner);
  CO_RETURN_ON_ERROR(expected);
  if (!same(*expected, value))
    co_return makeError(StatusCode::kDataCorruption, "V2 historical content provenance changed");
  co_return value;
}
CoTryTask<EcV2PublishedContent> EcV2PublishedCatalog::record(Transaction &txn,
                                                             const EcObjectRef &object,
                                                             const Uuid &operation,
                                                             const EcOwner &owner) {
  auto expected = co_await completed(txn, object, operation, owner);
  CO_RETURN_ON_ERROR(expected);
  auto key = contentKey(object, expected->stripe, expected->revision);
  auto previous = co_await load<EcV2PublishedContent>(txn, key);
  CO_RETURN_ON_ERROR(previous);
  if (*previous) {
    if (!same(**previous, *expected))
      co_return makeError(StatusCode::kDataCorruption, "V2 historical SHA cannot change");
    co_return **previous;
  }
  CO_RETURN_ON_ERROR(co_await save(txn, key, *expected));
  co_return expected;
}
}  // namespace hf3fs::meta::server
