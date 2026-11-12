#pragma once

#include <optional>

#include "meta/store/EcFileTreeTxnBudget.h"

namespace hf3fs::meta::server {
// One accounting scope per caller-owned transaction, including typed dispatch
// and permanent request/completion records. A supplied W0 budget stays W0:
// nested catalogs cannot upgrade its limit or reset its accumulated usage.
class EcGcTxnScope final {
 public:
  explicit EcGcTxnScope(kv::IReadWriteTransaction &raw) {
    budget_ = dynamic_cast<EcFileTreeTxnBudget *>(&raw);
    if (!budget_) {
      owned_.emplace(raw, EcFileTreeTxnBudget::Profile::Gc);
      budget_ = &*owned_;
    }
  }
  EcGcTxnScope(const EcGcTxnScope &) = delete;
  EcGcTxnScope &operator=(const EcGcTxnScope &) = delete;
  EcGcTxnScope(EcGcTxnScope &&) = delete;
  EcGcTxnScope &operator=(EcGcTxnScope &&) = delete;
  EcFileTreeTxnBudget &transaction() const { return *budget_; }

 private:
  std::optional<EcFileTreeTxnBudget> owned_;
  EcFileTreeTxnBudget *budget_ = nullptr;
};
}  // namespace hf3fs::meta::server
