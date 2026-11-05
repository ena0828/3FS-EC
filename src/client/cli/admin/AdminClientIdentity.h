#pragma once

#include <string_view>

#include "common/app/ClientId.h"

namespace hf3fs::client::cli {
inline Result<Uuid> parseAdminNonNilUuid(std::string_view text) {
  if (text.size() != 36) return makeError(StatusCode::kInvalidArg, "expected a nonzero UUID in canonical form");
  for (size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    const bool separator = i == 8 || i == 13 || i == 18 || i == 23;
    if (separator ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
      return makeError(StatusCode::kInvalidArg, "invalid canonical UUID");
  }
  auto parsed = Uuid::fromHexString(text);
  if (!parsed || parsed->is_nil()) return makeError(StatusCode::kInvalidArg, "UUID must be valid and nonzero");
  return *parsed;
}

inline Result<ClientId> makeAdminClientId(std::string_view configuredUuid) {
  if (configuredUuid.empty()) return ClientId::random();
  CHECK_RESULT(uuid, parseAdminNonNilUuid(configuredUuid));
  return ClientId(uuid);
}
}  // namespace hf3fs::client::cli
