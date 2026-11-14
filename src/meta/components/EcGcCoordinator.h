#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "client/storage/EcRequestControl.h"
#include "common/kv/IKVEngine.h"
#include "meta/store/EcGcCompletionCatalog.h"

namespace hf3fs::meta::server {
// Internal dependency, not a user callback or an authorization decision. An
// implementation owns the entire request until its actual local RPC completes,
// including timeout/cancellation cleanup. NativeEcGcTransport supplies the
// production StorageClient/Messenger RPC path; test transports remain models.
class EcGcTransport {
 public:
  virtual ~EcGcTransport() = default;
  virtual CoTryTask<storage::EcGcAck> exchange(storage::EcGcRequest ownedRequest,
                                               storage::client::EcRequestControl) = 0;
};

// Cannot be constructed from a caller's in-memory claim or transaction. Only a
// fresh transaction owned by EcGcCoordinator creates this after re-reading the
// same permanent claim. This class itself cannot sign or delete anything.
class EcConfirmedGcClaim {
 public:
  const EcGcClaim &claim() const { return claim_; }
  const storage::EcGcCertificate &certificate() const { return certificate_; }

 private:
  friend class EcGcCoordinator;
  EcConfirmedGcClaim(EcGcClaim claim, storage::EcGcCertificate certificate)
      : claim_(std::move(claim)),
        certificate_(std::move(certificate)) {}
  EcGcClaim claim_;
  storage::EcGcCertificate certificate_;
};

class EcGcCoordinator {
 public:
  struct Config {
    Uuid authority = Uuid::zero();
    uint64_t requestTtlSeconds = 60;
    uint32_t maxConcurrent = 8;
    // Explicit trusted GC-capable inventory, never inferred from Meta mode3,
    // data protocol2 or current routing. No automatic instance replacement.
    std::vector<storage::EcGcLocalTarget> targets;
    std::function<uint64_t()> nowSeconds;
  };
  static Result<std::unique_ptr<EcGcCoordinator>> create(Config,
                                                         std::shared_ptr<kv::IKVEngine>,
                                                         std::shared_ptr<const storage::EcGcKey>,
                                                         std::shared_ptr<EcGcTransport>);

  // Requires G0 to have created and committed an exact claim separately.
  // No candidate scan, ordinary-user RPC, claim creation or current-head delete.
  // A failed call leaves the claim and all evidence in place for explicit Query
  // or retry. Success follows a committed G2 completion (or its verified replay).
  CoTryTask<EcGcCompletion> collect(EcObjectRef,
                                    storage::EcFragmentIdentity,
                                    Uuid claimId,
                                    storage::client::EcRequestControl) const;
  CoTryTask<EcGcCompletion> query(EcObjectRef,
                                  storage::EcFragmentIdentity,
                                  Uuid claimId,
                                  storage::client::EcRequestControl) const;
  CoTryTask<std::optional<EcGcCompletion>> getCompletion(EcObjectRef, storage::EcFragmentIdentity, Uuid claimId) const;

 private:
  struct State;
  explicit EcGcCoordinator(std::shared_ptr<State> state)
      : state_(std::move(state)) {}
  static CoTryTask<EcConfirmedGcClaim> loadCommitted(std::shared_ptr<State>,
                                                     EcObjectRef,
                                                     storage::EcFragmentIdentity,
                                                     Uuid);
  static CoTryTask<EcGcCompletion> executeOwned(std::shared_ptr<State>,
                                                EcObjectRef,
                                                storage::EcFragmentIdentity,
                                                Uuid,
                                                storage::EcGcAction,
                                                storage::client::EcRequestControl);
  static CoTryTask<std::optional<EcGcCompletion>> getOwned(std::shared_ptr<State>,
                                                           EcObjectRef,
                                                           storage::EcFragmentIdentity,
                                                           Uuid);
  std::shared_ptr<State> state_;
};
}  // namespace hf3fs::meta::server
