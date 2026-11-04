#pragma once

#include <atomic>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <mutex>
#include <unordered_map>

#include "client/storage/StorageMessenger.h"
#include "common/utils/Semaphore.h"
#include "storage/ec_repair/EcHelperAuthorization.h"
#include "storage/update/EcWorkerSession.h"

namespace hf3fs::storage {

// Independent helper admission/CPU/transport resources. Never wait for data
// admission or drain while occupying a disk worker or the control executor.
class EcHelperRuntime {
 public:
  static Result<std::unique_ptr<EcHelperRuntime>> create(const net::Client::Config &config,
                                                         std::unique_ptr<EcHelperKey> key);
  ~EcHelperRuntime();
  void stopAndJoin();  // Call outside this executor and the network proc pool.
  Result<Void> enterBlock(const std::string &planAndHop, uint16_t blockBit, uint8_t limit);
  void leaveBlock(const std::string &planAndHop, uint16_t blockBit) noexcept;

  std::unique_ptr<EcHelperKey> key;
  Semaphore budget{64, 64};
  std::shared_ptr<EcWorkerSessions> sessions = std::make_shared<EcWorkerSessions>();
  folly::CPUThreadPoolExecutor executor{2};
  client::StorageMessenger messenger;

 private:
  explicit EcHelperRuntime(const net::Client::Config &config, std::unique_ptr<EcHelperKey> value)
      : key(std::move(value)),
        messenger(config) {}
  std::atomic_flag stopped_{};
  std::mutex windowMutex_;
  std::unordered_map<std::string, uint16_t> activeBlocks_;
};

}  // namespace hf3fs::storage
