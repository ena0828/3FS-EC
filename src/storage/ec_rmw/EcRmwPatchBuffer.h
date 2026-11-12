#pragma once

#include <bitset>

#include "EcRmwPlan.h"

namespace hf3fs::storage {
// Owns only the caller's new patch, never old source plaintext. This helper
// does not authorize upload/execute. The runtime must hold its job memory
// reservation and check the original upload capability/scope on every put.
class EcRmwPatchBuffer final {
 public:
  static Result<std::unique_ptr<EcRmwPatchBuffer>> create(std::shared_ptr<const EcRmwPlan>);
  Result<Void> put(uint32_t block, std::string_view bytes);
  // Full exact SHA is checked before ownership can leave for any execution.
  // Uploaded bits/ACKs are volatile observations, not durable recovery facts.
  Result<std::string> finish();
  const std::bitset<kEcRmwMaxPatchBlocks> &received() const noexcept { return received_; }
  size_t capacity() const noexcept { return bytes_.capacity(); }

 private:
  explicit EcRmwPatchBuffer(std::shared_ptr<const EcRmwPlan> plan)
      : plan_(std::move(plan)) {}
  std::shared_ptr<const EcRmwPlan> plan_;
  std::string bytes_;
  std::bitset<kEcRmwMaxPatchBlocks> received_;
  bool consumed_ = false;
};
}  // namespace hf3fs::storage
