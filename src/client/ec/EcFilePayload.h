#pragma once

#include <memory>
#include <span>

#include "EcFilePlanning.h"

namespace hf3fs::client::ec {
namespace detail {
struct EcFilePayloadCounter;
struct EcFilePayloadCharge;
}  // namespace detail

class EcFilePayload {
 public:
  EcFilePayload() = default;
  EcFilePayload(EcFilePayload &&) noexcept;
  EcFilePayload &operator=(EcFilePayload &&) noexcept;
  EcFilePayload(const EcFilePayload &) = delete;
  EcFilePayload &operator=(const EcFilePayload &) = delete;
  size_t size() const { return size_; }
  std::span<uint8_t> bytes() { return {data_.get(), size_}; }
  std::span<const uint8_t> bytes() const { return {data_.get(), size_}; }

 private:
  friend class EcFilePayloadBudget;
  EcFilePayload(std::shared_ptr<detail::EcFilePayloadCharge> charge, std::unique_ptr<uint8_t[]> data, size_t size)
      : charge_(std::move(charge)),
        data_(std::move(data)),
        size_(size) {}
  // Destructor order is deliberate: the owned bytes disappear before their
  // charge. Move assignment explicitly preserves the same order for old data.
  std::shared_ptr<detail::EcFilePayloadCharge> charge_;
  std::unique_ptr<uint8_t[]> data_;
  size_t size_ = 0;
};

// One file manager owns this 32 MiB partition. Outputs keep it charged after
// manager shutdown; it is not a claim about the whole process's resident set.
class EcFilePayloadBudget {
 public:
  static Result<std::shared_ptr<EcFilePayloadBudget>> create();
  Result<EcFilePayload> allocate(size_t bytes);
  size_t usedBytes() const;
  bool owns(const EcFilePayload &) const;
  static constexpr size_t limitBytes() { return static_cast<size_t>(kEcFileMaxPayloadBytes); }

 private:
  explicit EcFilePayloadBudget(std::shared_ptr<detail::EcFilePayloadCounter> counter)
      : counter_(std::move(counter)) {}
  std::shared_ptr<detail::EcFilePayloadCounter> counter_;
};
}  // namespace hf3fs::client::ec
