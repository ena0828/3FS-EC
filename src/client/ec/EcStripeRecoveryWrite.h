#pragma once

#include "EcAllocationExport.h"

namespace hf3fs::client::ec {
// S0 remains a same-length stripe-zero replacement. UUIDs in fresh must be new
// and persisted in the resulting v2 journal before the first mutating RPC.
Result<EcStripeRunRecord> prepareEcRecoveryWrite(EcStripeRunRecord fresh,
                                                 const EcStripeRunRecord &source,
                                                 const EcStripeRunObservation &published,
                                                 std::string sourceRun,
                                                 storage::EcSha256 recordDigest,
                                                 storage::EcSha256 observationDigest,
                                                 std::string inputPath,
                                                 std::string_view input);
// Actual authentication plus readonly RPC33. No Storage access, source ReadPin,
// cancel, release, retirement, or GC. Missing is not permission to replace IDs.
CoTryTask<meta::EcV2MutationRsp> verifyEcRecoveryWriteSource(std::shared_ptr<meta::client::MetaClient>,
                                                             const EcStripeRunRecord &,
                                                             flat::UserInfo,
                                                             EcStripeControl);
Result<Void> validateEcRecoveryWritePublication(const EcStripeRunRecord &,
                                                const meta::EcV2MutationRsp &source,
                                                const meta::EcV2MutationRsp &replacement);
}  // namespace hf3fs::client::ec
