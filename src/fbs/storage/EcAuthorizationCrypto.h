#pragma once

#include "fbs/storage/EcAuthorization.h"

namespace hf3fs::storage::ec_authorization_detail {

// Shared private-key access for versioned EC protocols. Callers must supply
// their own fixed, versioned domain; this does not export or serialize the key.
struct Access {
  static Result<EcSha256> authenticate(const EcCapabilityKey &key, std::span<const uint8_t> bytes);
  static bool constantTimeEqual(const EcSha256 &left, const EcSha256 &right);
  static void setSignature(EcCapability &grant, const EcSha256 &signature);
  static bool matches(const EcCapability &grant, const EcSha256 &signature);
};

}  // namespace hf3fs::storage::ec_authorization_detail
