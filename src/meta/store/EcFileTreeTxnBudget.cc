#include "EcFileTreeTxnBudget.h"

#include <fmt/format.h>
#include <limits>
#include <optional>
#include <string>

namespace hf3fs::meta::server {
namespace {
auto budgetError(const EcFileTreeTxnBudget &budget,
                 const Status &error,
                 std::string_view operation,
                 std::string_view phase,
                 std::string_view key,
                 std::optional<size_t> valueBytes) {
  using Profile = EcFileTreeTxnBudget::Profile;
  std::string_view profile = "unknown";
  switch (budget.profile()) {
    case Profile::W0:
      profile = "W0";
      break;
    case Profile::Range:
      profile = "Range";
      break;
    case Profile::Gc:
      profile = "Gc";
      break;
    case Profile::Repair:
      profile = "Repair";
      break;
    case Profile::Rmw:
      profile = "Rmw";
      break;
  }
  // Prefix bytes identify the record family without logging key IDs or values.
  constexpr char hex[] = "0123456789abcdef";
  std::string prefix;
  for (size_t i = 0; i < key.size() && i < 4; ++i) {
    const auto byte = static_cast<unsigned char>(key[i]);
    prefix.push_back(hex[byte >> 4]);
    prefix.push_back(hex[byte & 15]);
  }
  const auto &limits = budget.limits();
  const auto &usage = budget.usage();
  return makeError(
      error.code(),
      fmt::format("EC tree budget rejected: operation={} phase={} profile={} limits_bytes={} limits_ops={} "
                  "used_read={} used_mutation={} used_conflict={} used_ops={} key_prefix_hex={} "
                  "key_bytes={} value_bytes={} cause={}",
                  operation,
                  phase,
                  profile,
                  limits.bytes,
                  limits.keyOperations,
                  usage.readBytes,
                  usage.mutationBytes,
                  usage.conflictBytes,
                  usage.keyOperations,
                  prefix,
                  key.size(),
                  valueBytes ? std::to_string(*valueBytes) : "unknown",
                  error.message()));
}
}  // namespace
EcFileTreeTxnBudget::EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner)
    : EcFileTreeTxnBudget(inner, Limits{}) {}
EcFileTreeTxnBudget::EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner, Limits limits)
    : inner_(inner),
      limits_(limits) {
  poisoned_ = !validLimits();
}
EcFileTreeTxnBudget::EcFileTreeTxnBudget(kv::IReadWriteTransaction &inner, Profile profile)
    : inner_(inner),
      limits_(profileLimits(profile)),
      profile_(profile) {
  poisoned_ = !validLimits();
}
EcFileTreeTxnBudget::~EcFileTreeTxnBudget() { observe(ObservationPoint::Destroy); }
void EcFileTreeTxnBudget::observe(ObservationPoint point) noexcept {
  // inner_ already must outlive this borrowed wrapper. Publication's private
  // validation is gone before the outer wrapper is destroyed; never invoke an
  // observer from charge(), reads, writes or commit's critical body.
  if (auto *observer = dynamic_cast<SnapshotObserver *>(&inner_))
    observer->observeEcTreeBudget(
        Snapshot{profile_, limits_, usage_, attempt_, poisoned_, commitOutcome_, commitError_, point});
}
EcFileTreeTxnBudget::Limits EcFileTreeTxnBudget::profileLimits(Profile profile) noexcept {
  switch (profile) {
    case Profile::W0:
      return {};
    case Profile::Range:
    case Profile::Gc:
    case Profile::Repair:
    case Profile::Rmw:
      return {2u << 20, 8192};
  }
  return {0, 0};
}
bool EcFileTreeTxnBudget::validLimits() const noexcept {
  const auto maximum = profileLimits(profile_);
  return limits_.bytes && limits_.bytes <= maximum.bytes && limits_.keyOperations &&
         limits_.keyOperations <= maximum.keyOperations;
}
Status EcFileTreeTxnBudget::unavailable() {
  poisoned_ = true;
  return Status(StatusCode::kInvalidArg);
}
Result<Void> EcFileTreeTxnBudget::charge(size_t operations, size_t read, size_t mutation, size_t conflict) {
  if (poisoned_) return makeError(StatusCode::kInvalidArg, "EC tree transaction is poisoned");
  size_t left = limits_.bytes - usage_.totalBytes();
  if (operations > limits_.keyOperations - usage_.keyOperations || read > left) return makeError(unavailable());
  left -= read;
  if (mutation > left) return makeError(unavailable());
  left -= mutation;
  if (conflict > left) return makeError(unavailable());
  usage_.keyOperations += operations;
  usage_.readBytes += read;
  usage_.mutationBytes += mutation;
  usage_.conflictBytes += conflict;
  return Void{};
}
void EcFileTreeTxnBudget::setReadVersion(int64_t version) {
  if (!poisoned_) inner_.setReadVersion(version);
}
CoTryTask<std::optional<String>> EcFileTreeTxnBudget::snapshotGet(std::string_view) {
  co_return makeError(unavailable());
}
CoTryTask<std::optional<String>> EcFileTreeTxnBudget::get(std::string_view key) {
  auto keyCharge = charge(1, key.size(), 0, key.size());
  if (!keyCharge) co_return budgetError(*this, keyCharge.error(), "get", "key", key, std::nullopt);
  auto result = co_await inner_.get(key);
  if (!result) {
    poisoned_ = true;
    co_return makeError(std::move(result.error()));
  }
  if (*result) {
    auto valueCharge = charge(0, (**result).size(), 0, 0);
    if (!valueCharge) co_return budgetError(*this, valueCharge.error(), "get", "value", key, (**result).size());
  }
  co_return std::move(*result);
}
CoTryTask<kv::IReadOnlyTransaction::GetRangeResult> EcFileTreeTxnBudget::snapshotGetRange(const KeySelector &,
                                                                                          const KeySelector &,
                                                                                          int32_t) {
  co_return makeError(unavailable());
}
CoTryTask<kv::IReadOnlyTransaction::GetRangeResult> EcFileTreeTxnBudget::getRange(const KeySelector &begin,
                                                                                  const KeySelector &end,
                                                                                  int32_t limit) {
  if (limit <= 0 || size_t(limit) > limits_.keyOperations) co_return makeError(unavailable());
  CO_RETURN_ON_ERROR(charge(1, begin.key.size(), 0, begin.key.size()));
  CO_RETURN_ON_ERROR(charge(1, end.key.size(), 0, end.key.size()));
  auto result = co_await inner_.getRange(begin, end, limit);
  if (!result) {
    poisoned_ = true;
    co_return makeError(std::move(result.error()));
  }
  for (const auto &entry : result->kvs) {
    CO_RETURN_ON_ERROR(charge(1, entry.key.size(), 0, entry.key.size()));
    CO_RETURN_ON_ERROR(charge(0, entry.value.size(), 0, 0));
  }
  co_return std::move(*result);
}
CoTryTask<void> EcFileTreeTxnBudget::cancel() {
  poisoned_ = true;
  co_return co_await inner_.cancel();
}
void EcFileTreeTxnBudget::reset() {
  observe(ObservationPoint::BeforeReset);
  inner_.reset();
  usage_ = {};
  commitOutcome_ = CommitOutcome::NotCalled;
  commitError_ = StatusCode::kOK;
  ++attempt_;
  poisoned_ = !attempt_ || !validLimits();
}
CoTryTask<void> EcFileTreeTxnBudget::addReadConflict(std::string_view key) {
  CO_RETURN_ON_ERROR(charge(1, 0, 0, key.size()));
  auto result = co_await inner_.addReadConflict(key);
  if (!result) poisoned_ = true;
  co_return result;
}
CoTryTask<void> EcFileTreeTxnBudget::addReadConflictRange(std::string_view begin, std::string_view end) {
  CO_RETURN_ON_ERROR(charge(1, 0, 0, begin.size()));
  CO_RETURN_ON_ERROR(charge(1, 0, 0, end.size()));
  auto result = co_await inner_.addReadConflictRange(begin, end);
  if (!result) poisoned_ = true;
  co_return result;
}
CoTryTask<void> EcFileTreeTxnBudget::set(std::string_view key, std::string_view value) {
  auto keyCharge = charge(1, 0, key.size(), key.size());
  if (!keyCharge) co_return budgetError(*this, keyCharge.error(), "set", "key", key, value.size());
  auto valueCharge = charge(0, 0, value.size(), 0);
  if (!valueCharge) co_return budgetError(*this, valueCharge.error(), "set", "value", key, value.size());
  auto result = co_await inner_.set(key, value);
  if (!result) poisoned_ = true;
  co_return result;
}
CoTryTask<void> EcFileTreeTxnBudget::clear(std::string_view key) {
  CO_RETURN_ON_ERROR(charge(1, 0, key.size(), key.size()));
  auto result = co_await inner_.clear(key);
  if (!result) poisoned_ = true;
  co_return result;
}
CoTryTask<void> EcFileTreeTxnBudget::setVersionstampedKey(std::string_view, uint32_t, std::string_view) {
  co_return makeError(unavailable());
}
CoTryTask<void> EcFileTreeTxnBudget::setVersionstampedValue(std::string_view, std::string_view, uint32_t) {
  co_return makeError(unavailable());
}
CoTryTask<void> EcFileTreeTxnBudget::commit() {
  auto admitted = charge(0, 0, 0, 0);
  if (!admitted) {
    commitOutcome_ = CommitOutcome::Rejected;
    commitError_ = admitted.error().code();
    co_return makeError(std::move(admitted.error()));
  }
  // An exception or cancellation after dispatch cannot be reported as success.
  commitOutcome_ = CommitOutcome::Unconfirmed;
  commitError_ = StatusCode::kOK;
  auto result = co_await inner_.commit();
  commitOutcome_ = result ? CommitOutcome::Succeeded : CommitOutcome::Failed;
  if (!result) {
    poisoned_ = true;
    commitError_ = result.error().code();
  }
  co_return result;
}
int64_t EcFileTreeTxnBudget::getCommittedVersion() { return inner_.getCommittedVersion(); }
}  // namespace hf3fs::meta::server
