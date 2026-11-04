#include "EcHelperRuntime.h"

#include <bit>

namespace hf3fs::storage {

Result<std::unique_ptr<EcHelperRuntime>> EcHelperRuntime::create(const net::Client::Config &config,
                                                                 std::unique_ptr<EcHelperKey> key) {
  if (!key) return makeError(StatusCode::kInvalidConfig, "helper key is missing");
  auto result = std::unique_ptr<EcHelperRuntime>(new EcHelperRuntime(config, std::move(key)));
  RETURN_ON_ERROR(result->messenger.start("EcHelper"));
  return result;
}
EcHelperRuntime::~EcHelperRuntime() { stopAndJoin(); }
void EcHelperRuntime::stopAndJoin() {
  if (stopped_.test_and_set()) return;
  sessions->closeAndWait();
  executor.join();
  messenger.stopAndJoin();
}
Result<Void> EcHelperRuntime::enterBlock(const std::string &key, uint16_t bit, uint8_t limit) {
  if (key.size() != 33 || std::popcount(bit) != 1 || limit == 0 || limit > 4) return makeError(StatusCode::kInvalidArg);
  std::lock_guard lock(windowMutex_);
  auto it = activeBlocks_.find(key);
  if (it != activeBlocks_.end() && ((it->second & bit) || std::popcount(it->second) >= limit)) {
    return makeError(StorageClientCode::kResourceBusy, "helper plan window or duplicate block is still active");
  }
  // Global runtime admission allows at most 64 live entries. Never wait for
  // another block while holding a helper slot or any disk-worker resource.
  if (it == activeBlocks_.end()) {
    if (activeBlocks_.size() >= 64) return makeError(StorageClientCode::kResourceBusy);
    activeBlocks_.emplace(key, bit);
  } else
    it->second |= bit;
  return Void{};
}
void EcHelperRuntime::leaveBlock(const std::string &key, uint16_t bit) noexcept {
  std::lock_guard lock(windowMutex_);
  auto it = activeBlocks_.find(key);
  if (it == activeBlocks_.end() || !(it->second & bit)) std::terminate();
  it->second &= ~bit;
  if (!it->second) activeBlocks_.erase(it);
}

}  // namespace hf3fs::storage
