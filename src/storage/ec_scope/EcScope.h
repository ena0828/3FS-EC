#pragma once

#include <memory>
#include <optional>

#include "chunk_engine/src/cxx.rs.h"
#include "common/utils/Result.h"

namespace hf3fs::storage {

using EcScopeTargetIdentity = chunk_engine::RawEcScopeTarget;
using EcScopeBinding = chunk_engine::RawEcScopeBinding;
using EcScopeRevocation = chunk_engine::RawEcScopeRevocation;

struct EcScopeDrainStatus {
  bool durable;
  uint64_t inflight;
  bool drained;
};

class EcScope;
class EcStagingEngine;

// A local admission count, not an authenticated capability. Move exactly once
// into the borrowed disk job and retain it through completion and postchecks.
class EcScopeTicket {
 public:
  EcScopeTicket(const EcScopeTicket &) = delete;
  EcScopeTicket &operator=(const EcScopeTicket &) = delete;
  EcScopeTicket(EcScopeTicket &&other) noexcept;
  EcScopeTicket &operator=(EcScopeTicket &&other) noexcept;
  ~EcScopeTicket() = default;

  Result<Void> checkExecution() const;
  const EcScopeBinding &binding() const { return binding_; }

 private:
  friend class EcScope;
  EcScopeTicket(rust::Box<chunk_engine::EcScopeTicketHandle> handle, EcScopeBinding binding)
      : handle_(std::move(handle)),
        binding_(binding) {}
  std::optional<rust::Box<chunk_engine::EcScopeTicketHandle>> handle_;
  EcScopeBinding binding_;
};

// Trusted process-local persistence primitive. These methods neither authenticate
// callers nor issue a Meta release proof. No current v1 RPC admits via this API.
class EcScope {
 public:
  static Result<std::shared_ptr<EcScope>> open(const chunk_engine::Engine &engine);
  Result<EcScopeTargetIdentity> registerTarget(uint32_t chain, uint64_t target) const;
  Result<EcScopeTargetIdentity> loadTarget(uint32_t chain, uint64_t target) const;
  Result<Void> prepare(const EcScopeBinding &binding) const;
  Result<EcScopeTicket> tryAdmit(const EcScopeBinding &binding) const;
  Result<EcScopeDrainStatus> revoke(const EcScopeRevocation &request) const;
  Result<EcScopeDrainStatus> drainStatus(const EcScopeRevocation &request) const;

 private:
  friend class EcStagingEngine;
  static Result<std::shared_ptr<EcScope>> fromResult(chunk_engine::RawEcScopeOpenResult result);
  explicit EcScope(rust::Box<chunk_engine::EcScopeHandle> handle)
      : handle_(std::move(handle)) {}
  rust::Box<chunk_engine::EcScopeHandle> handle_;
};

}  // namespace hf3fs::storage
