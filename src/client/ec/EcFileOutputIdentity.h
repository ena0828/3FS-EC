#pragma once

#include <filesystem>
#include <string_view>

#include "common/utils/Result.h"

namespace hf3fs::client::ec {
// Offline projection of fixed identities in an existing, exclusively locked
// pwrite/repair/truncate journal. This creates only a new output archive. It is
// neither an authenticated metadata observation nor a physical-reclamation proof.
Result<Void> exportEcFileOutputIdentities(const std::filesystem::path &run,
                                          std::string_view outputKind,
                                          const std::filesystem::path &output);
}  // namespace hf3fs::client::ec
