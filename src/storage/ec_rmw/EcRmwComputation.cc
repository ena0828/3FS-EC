#include "EcRmwComputation.h"

#include "fbs/storage/EcAuthorizationCrypto.h"

namespace hf3fs::storage {
namespace {
void number(std::string &out, uint64_t value, unsigned width) {
  for (unsigned i = width; i; --i) out.push_back(char(value >> ((i - 1) * 8)));
}
void hash(std::string &out, const EcSha256 &value) {
  out.append(reinterpret_cast<const char *>(value.data()), value.size());
}
Result<std::string> canonical(const EcRmwPlan &plan, const EcRmwComputedCommitment &value) {
  if (value.output.planDigest != plan.digest() || value.output.logicalSha256 == EcSha256{} ||
      !ec_rmw_detail::sameEndpoint(value.worker, plan.worker()))
    return makeError(StatusCode::kAuthenticationFail);
  std::string out = "3FS-RMW-COMPUTED-v1";
  hash(out, value.output.planDigest);
  hash(out, value.output.logicalSha256);
  number(out, value.worker.nodeId.toUnderType(), 4);
  number(out, value.worker.chainId.toUnderType(), 4);
  number(out, value.worker.targetId.toUnderType(), 8);
  out.append(value.worker.engineUuid.asStringView());
  out.append(value.worker.targetIncarnation.asStringView());
  for (size_t i = 0; i < 12; ++i) {
    const auto &d = value.output.descriptors[i];
    if (d.wholeLength != plan.input().shardBytes) return makeError(StatusCode::kInvalidArg);
    CHECK_RESULT(digest, digestEcIntegrityV2(plan.input().targets[i].identity, d));
    hash(out, digest);
  }
  return out;
}
}  // namespace
Result<EcRmwComputedCommitment> EcRmwComputationAuthorization::sign(const EcRmwKey &key,
                                                                    const EcRmwPlan &plan,
                                                                    const EcRmwOutputCommitment &output) {
  EcRmwComputedCommitment value;
  value.output = output;
  value.worker = plan.worker();
  CHECK_RESULT(bytes, canonical(plan, value));
  CHECK_RESULT(mac,
               ec_authorization_detail::Access::authenticate(
                   *key.key_,
                   std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size())));
  value.signature_ = mac;
  return value;
}
Result<VerifiedEcRmwComputation> EcRmwComputationAuthorization::verify(const EcRmwKey &key,
                                                                       std::shared_ptr<const EcRmwPlan> plan,
                                                                       const EcRmwComputedCommitment &value) {
  if (!plan) return makeError(StatusCode::kInvalidArg);
  CHECK_RESULT(bytes, canonical(*plan, value));
  CHECK_RESULT(mac,
               ec_authorization_detail::Access::authenticate(
                   *key.key_,
                   std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size())));
  if (!ec_authorization_detail::Access::constantTimeEqual(mac, value.signature_))
    return makeError(StatusCode::kAuthenticationFail);
  return VerifiedEcRmwComputation(std::move(plan), value);
}
}  // namespace hf3fs::storage
