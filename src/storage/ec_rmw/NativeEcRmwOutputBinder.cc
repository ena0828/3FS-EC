#include "NativeEcRmwOutputBinder.h"
namespace hf3fs::storage {
CoTryTask<std::array<EcCapabilityV2, 12>> NativeEcRmwOutputBinder::bind(const EcRmwPlan &plan,
                                                                        const EcRmwComputedCommitment &computed,
                                                                        client::EcRequestControl control) {
  if (!transport_ || !address_) co_return makeError(StorageClientCode::kNotInitialized);
  auto address = address_();
  if (!address) co_return makeError(std::move(address.error()));
  const auto &p = plan.input();
  meta::BindEcRmwOutputReq req;
  req.object = {meta::InodeId(p.inode), p.object};
  req.owner = {p.ownerUid, p.clientNamespace};
  req.child = p.operationId;
  req.execution = execution_;
  req.computed = computed;
  // Meta52 is a separate control plane, not a fallback for Storage data I/O.
  // Keep the original deadline/cancellation while selecting its explicit TCP endpoint.
  control.transport = client::EcRequestControl::TransportPolicy::TcpOnly;
  auto result = co_await transport_->bind(*address, std::move(req), control);
  if (!result) co_return makeError(std::move(result.error()));
  if (result->planDigest != plan.digest()) co_return makeError(StorageCode::kEcSealOutcomeUnknown);
  // NativeEcRmwIo verifies all returned D MACs against the fixed descriptor,
  // original operation, scope/owner and actual target before any Begin.
  co_return std::move(result->writes);
}
}  // namespace hf3fs::storage
