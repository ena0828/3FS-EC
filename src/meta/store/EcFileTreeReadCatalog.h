#pragma once

#include "EcFileSessionCatalog.h"
#include "EcTreeSourcePinCatalog.h"
#include "fbs/meta/EcFileTreeRead.h"

namespace hf3fs::meta::server {
// Each call uses one caller-owned transaction. Commit before returning an
// acquired snapshot, signing a reserved ReadBlock grant or sending T0 controls.
// Semantic failures discard the whole transaction; no implicit identity retry.
class EcFileTreeReadCatalog {
 public:
  using Tx = EcFileTreeTxnBudget;
  // Eight independent Data pins include twelve allocation protections each.
  // One named Range profile accounts for the complete outer transaction; W0
  // constructors retain their separate 256 KiB / 1024-operation hard limit.
  static constexpr Tx::Profile transactionProfile() { return Tx::Profile::Range; }
  static CoTryTask<EcTreeReadRecord> acquire(Tx &, const EcTreeReadIntent &);
  static CoTryTask<EcTreeReadRecord> query(Tx &, const EcTreeReadIntent &);
  static CoTryTask<EcTreeSourcePinEvidence> reserveRead(Tx &, const EcTreeReadIntent &, size_t stripeIndex);
  static CoTryTask<EcTreeReadRecord> startClosing(Tx &,
                                                  const EcTreeReadIntent &,
                                                  const Uuid &authority,
                                                  const std::array<Uuid, 8> &revocations);
  static CoTryTask<EcV2DrainRecord> closingSource(Tx &, const EcTreeReadIntent &, size_t stripeIndex);
  static CoTryTask<EcV2DrainRecord> recordAck(Tx &,
                                              const EcTreeReadIntent &,
                                              size_t stripeIndex,
                                              size_t endpointIndex,
                                              const storage::EcScopeControlKey &,
                                              const storage::EcScopeControlRequest &,
                                              const storage::EcScopeControlAck &);
  static CoTryTask<EcV2DrainRecord> recordVerifiedAck(Tx &,
                                                      const EcTreeReadIntent &,
                                                      size_t stripeIndex,
                                                      const storage::EcScopeControlKey &,
                                                      const EcVerifiedDrainAck &);
  static CoTryTask<EcV2DrainRecord> recordRetirement(Tx &, const EcTreeReadIntent &, size_t stripeIndex,
                                                     size_t endpointIndex, const storage::EcScopeControlKey &);
  static CoTryTask<EcTreeReadRecord> finishRelease(Tx &, const EcTreeReadIntent &, const storage::EcScopeControlKey &);
};
}  // namespace hf3fs::meta::server
