#include "EcFilePayload.h"

#include <atomic>
#include <new>
#include <utility>

namespace hf3fs::client::ec {
namespace detail {
struct EcFilePayloadCounter {
  std::atomic<size_t> bytes{0};
};
struct EcFilePayloadCharge {
  std::shared_ptr<EcFilePayloadCounter> counter;
  size_t bytes;
  EcFilePayloadCharge(std::shared_ptr<EcFilePayloadCounter> value, size_t size)
      : counter(std::move(value)),
        bytes(size) {}
  ~EcFilePayloadCharge() { counter->bytes.fetch_sub(bytes); }
};
}  // namespace detail

EcFilePayload::EcFilePayload(EcFilePayload &&other) noexcept
    : charge_(std::move(other.charge_)),
      data_(std::move(other.data_)),
      size_(std::exchange(other.size_, 0)) {}

EcFilePayload &EcFilePayload::operator=(EcFilePayload &&other) noexcept {
  if (this != &other) {
    data_.reset();
    charge_.reset();
    charge_ = std::move(other.charge_);
    data_ = std::move(other.data_);
    size_ = std::exchange(other.size_, 0);
  }
  return *this;
}
Result<std::shared_ptr<EcFilePayloadBudget>> EcFilePayloadBudget::create() {
  try {
    return std::shared_ptr<EcFilePayloadBudget>(
        new EcFilePayloadBudget(std::make_shared<detail::EcFilePayloadCounter>()));
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
Result<EcFilePayload> EcFilePayloadBudget::allocate(size_t bytes) {
  if (bytes > limitBytes()) return makeError(StatusCode::kInvalidArg, "file payload exceeds 32 MiB");
  auto used = counter_->bytes.load();
  do {
    if (used > limitBytes() - bytes)
      return makeError(StorageClientCode::kResourceBusy, "file payload budget is retained by another input/output");
  } while (!counter_->bytes.compare_exchange_weak(used, used + bytes));
  std::shared_ptr<detail::EcFilePayloadCharge> charge;
  try {
    charge = std::make_shared<detail::EcFilePayloadCharge>(counter_, bytes);
  } catch (const std::bad_alloc &) {
    counter_->bytes.fetch_sub(bytes);
    return makeError(StatusCode::kNotEnoughMemory);
  }
  try {
    // The zero-filled fixed allocation has no growing container capacity. A
    // caller fills input bytes before transferring this payload to appendAt.
    auto data = bytes ? std::make_unique<uint8_t[]>(bytes) : nullptr;
    return EcFilePayload(std::move(charge), std::move(data), bytes);
  } catch (const std::bad_alloc &) {
    return makeError(StatusCode::kNotEnoughMemory);
  }
}
bool EcFilePayloadBudget::owns(const EcFilePayload &value) const {
  return value.charge_ && value.charge_->counter == counter_;
}
size_t EcFilePayloadBudget::usedBytes() const { return counter_->bytes.load(); }
}  // namespace hf3fs::client::ec
