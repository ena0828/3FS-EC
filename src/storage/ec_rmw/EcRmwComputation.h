#pragma once

#include "EcRmwExecution.h"

namespace hf3fs::storage {
class NativeEcRmwIo;
class EcRmwComputationAuthorization;
// Worker-authenticated computed bytes commitment. It is neither an upload
// capability nor a durable candidate/publication proof. No readable Serde.
struct EcRmwComputedCommitment {
  EcRmwOutputCommitment output;
  EcScopeEndpoint worker;

 private:
  friend class EcRmwWireCodec;
  friend class EcRmwComputationAuthorization;
  friend struct ec_rmw_detail::AuthorizationTestAccess;
  EcSha256 signature_{};
};
class VerifiedEcRmwComputation final {
 public:
  const EcRmwPlan &plan() const noexcept { return *plan_; }
  const EcRmwOutputCommitment &commitment() const noexcept { return value_.output; }
  const EcScopeEndpoint &worker() const noexcept { return value_.worker; }

 private:
  friend class EcRmwComputationAuthorization;
  VerifiedEcRmwComputation(std::shared_ptr<const EcRmwPlan> plan, EcRmwComputedCommitment value)
      : plan_(std::move(plan)),
        value_(std::move(value)) {}
  std::shared_ptr<const EcRmwPlan> plan_;
  EcRmwComputedCommitment value_;
};
class EcRmwComputationAuthorization final {
 public:
  // Metadata must additionally fresh-read the committed child/plan, require
  // issuance still open and atomically bind the first exact result. This MAC
  // cannot authorize arbitrary metadata installation or bypass scope Closing.
  static Result<VerifiedEcRmwComputation> verify(const EcRmwKey &,
                                                 std::shared_ptr<const EcRmwPlan>,
                                                 const EcRmwComputedCommitment &);

 private:
  friend class NativeEcRmwIo;
  friend struct ec_rmw_detail::AuthorizationTestAccess;
  static Result<EcRmwComputedCommitment> sign(const EcRmwKey &, const EcRmwPlan &, const EcRmwOutputCommitment &);
};
}  // namespace hf3fs::storage
