#pragma once
#include "client/ec/EcFileClient.h"
namespace hf3fs::client::ec::detail {
meta::EcRangeSelection fileSelection(const EcFileRunRecord &);
Result<Void> validateFileSnapshot(const EcFileRunRecord &, const meta::EcRangeSnapshot &);
Result<Void> validateSameFileSnapshot(const meta::EcRangeSnapshot &, const meta::EcRangeSnapshot &);
Result<Void> validateFileStripe(const meta::EcRangeStripe &, const EcStripeReadOutput &);
Result<Void> validateFileIntent(const EcFileRunRecord &, size_t, const meta::EcV2MutationRsp &);
// RPC45 is an authenticated observation, not a source of new grants/reservations.
Result<Void> validateFileOwnedObservation(const EcFileRunRecord &, size_t, const meta::EcOwnedMutationRsp &);
Result<Void> validateFilePublished(const EcFileRunRecord &, size_t, const meta::EcV2MutationRsp &);
Result<storage::EcSha256> fileContentSha(std::span<const uint8_t>);
Result<Void> validateFileInput(const EcFileRunRecord &, std::span<const uint8_t>);
}  // namespace hf3fs::client::ec::detail
